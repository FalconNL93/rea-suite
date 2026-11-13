"""ZArchive (.zar, .wua): Exzap's zstd-compressed archive, read in Python, no build needed.

  rea-suite zar info    <archive> [-o JSON]               sections, sizes, file count
  rea-suite zar list    <archive> [-o TSV]                size and path of every file
  rea-suite zar extract <archive> [path...] -o DIR        files (or folders) named, or everything

Cemu reads Wii U games packed this way (.wua); Xenia Canary reads Xbox 360 games packed this way (.zar,
made by extract-xiso + zarchive from a disc image, or by XGDTool --zar from a disc or a Games on
Demand package). For a 360 game, `rea-suite xbox360 disc` reads the same archive and names its XEX.
Creating one is upstream's tool: `zarchive <folder> <out.zar>` (component game-archives).

The format (Exzap/ZArchive, zarchivecommon.h): file data concatenated, cut into 64 KiB blocks, each
zstd-compressed alone (stored raw when it does not shrink); a table of block offsets, 16 blocks per
record; a name table; a flat file tree whose directories point at runs of child nodes; a 144-byte
big-endian footer at the end. Upstream's reader (v0.1.2 and master) misreads names of 128 bytes or
more (it takes the length's high bits from the first byte twice); this reader follows the writer.
"""

from __future__ import annotations

import argparse
import struct
from collections.abc import Iterator
from pathlib import Path

from rea_suite import containers
from rea_suite.containers import Entry, Tree
from rea_suite.text import printable

MAGIC = 0x169F52D6
VERSION1 = 0x61BF3A01
FOOTER = struct.Struct(
    ">12Q32sQII"
)  # six (offset, size) sections, hash, total size, version, magic
BLOCK = 64 * 1024
PER_RECORD = 16
RECORD = struct.Struct(">Q16H")
NODE = struct.Struct(">4I")
SECTIONS = (
    "compressed_data",
    "offset_records",
    "names",
    "file_tree",
    "meta_directory",
    "meta_data",
)
# Tables are read whole; real ones are far smaller (an 8 GB archive has ~330 KB of offset records).
MAX_TABLE = 64 * 1024 * 1024


class Zstd:
    """The block decompressor: the zstandard package (a pyproject dependency)."""

    def decompress(self, data: bytes, size: int) -> bytes:
        import zstandard

        try:
            return zstandard.ZstdDecompressor().decompress(data, max_output_size=size)
        except zstandard.ZstdError as exc:
            raise ValueError(f"zstd: {exc}") from None


def is_zar(path: Path) -> bool:
    """The footer's magic and version, the format's own signature."""
    try:
        size = path.stat().st_size
        if not path.is_file() or size < FOOTER.size:
            return False
        with path.open("rb") as f:
            f.seek(size - 8)
            version, magic = struct.unpack(">II", f.read(8))
    except OSError:
        return False
    return magic == MAGIC and version == VERSION1


class ZarArchive:
    """One archive, open for reading. Implements containers.Container."""

    format = "ZArchive"

    def __init__(self, path: Path, zstd: Zstd | None = None):
        self._zstd = zstd or Zstd()
        self._f = path.open("rb")
        try:
            self._load()
        except BaseException:
            self._f.close()
            raise
        self._block: tuple[int, bytes] | None = None
        self._tree: Tree | None = None

    def _read(self, offset: int, size: int) -> bytes:
        self._f.seek(offset)
        data = self._f.read(size)
        if len(data) != size:
            raise ValueError(f"truncated archive: {size} bytes at 0x{offset:x}")
        return data

    def _load(self) -> None:
        self._f.seek(0, 2)
        size = self._f.tell()
        if size < FOOTER.size:
            raise ValueError("not a ZArchive (too small for its footer)")
        fields = FOOTER.unpack(self._read(size - FOOTER.size, FOOTER.size))
        *pairs, self.hash, total, version, magic = fields
        if magic != MAGIC or version != VERSION1:
            raise ValueError("not a ZArchive (no footer magic)")
        if total != size:
            raise ValueError(f"footer says {total} bytes, the file has {size}")
        self.sections = {n: (pairs[2 * i], pairs[2 * i + 1]) for i, n in enumerate(SECTIONS)}
        for name, (offset, length) in self.sections.items():
            if offset + length > size:
                raise ValueError(f"section {name} lies past the end of the file")
        for name in ("offset_records", "names", "file_tree"):
            if self.sections[name][1] > MAX_TABLE:
                raise ValueError(f"section {name} is larger than {MAX_TABLE} bytes")
        raw = self._read(*self.sections["offset_records"])
        tree = self._read(*self.sections["file_tree"])
        if not raw or len(raw) % RECORD.size or not tree or len(tree) % NODE.size:
            raise ValueError("offset records or file tree of a wrong size")
        self.records = [RECORD.unpack_from(raw, o) for o in range(0, len(raw), RECORD.size)]
        self.names = self._read(*self.sections["names"])
        self.nodes = [NODE.unpack_from(tree, o) for o in range(0, len(tree), NODE.size)]
        if self.nodes[0][0] & 0x80000000:
            raise ValueError("the file tree's first node is not the root directory")
        self.data_offset, self.data_size = self.sections["compressed_data"]

    def name(self, offset: int) -> str | None:
        """A node's name: a length byte (bit 7 set: a second byte holds bits 7-14), then the bytes."""
        if offset == 0x7FFFFFFF or offset >= len(self.names):
            return None
        length, start = self.names[offset] & 0x7F, offset + 1
        if self.names[offset] & 0x80:
            if offset + 1 >= len(self.names):
                return None
            length |= self.names[offset + 1] << 7
            start += 1
        if start + length > len(self.names):
            return None
        return self.names[start : start + length].decode("utf-8", "replace")

    def tree(self) -> Tree:
        if self._tree is not None:
            return self._tree
        found = Tree()
        seen: set[int] = set()

        def walk(index: int, prefix: str, depth: int) -> None:
            if depth > containers.MAX_DEPTH:
                found.skipped.append(f"{printable(prefix)}: nested too deep")
                return
            _, start, count, _ = self.nodes[index]
            if start + count > len(self.nodes):
                found.skipped.append(f"{printable(prefix) or '/'}: children past the tree's end")
                return
            for child in range(start, start + count):
                if len(found.entries) >= containers.MAX_ENTRIES:
                    found.skipped.append(f"more than {containers.MAX_ENTRIES} entries")
                    return
                if child in seen:
                    found.skipped.append(f"{printable(prefix) or '/'}: node {child} seen twice")
                    continue
                seen.add(child)
                flags, low, size_low, high = self.nodes[child]
                name = self.name(flags & 0x7FFFFFFF)
                if name is None or not containers.safe_name(name):
                    shown = "(no name)" if name is None else printable(name)
                    found.skipped.append(f"{printable(prefix)}/{shown}: unsafe or missing name")
                    continue
                path = f"{prefix}/{name}" if prefix else name
                if flags & 0x80000000:
                    offset = low | (high & 0xFFFF) << 32
                    size = size_low | (high & 0xFFFF0000) << 16
                    found.entries.append(Entry(path, size, False, offset))
                else:
                    found.entries.append(Entry(path, 0, True, child))
                    walk(child, path, depth + 1)

        seen.add(0)
        walk(0, "", 0)
        self._tree = found
        return found

    def block(self, index: int) -> bytes:
        """One 64 KiB block of the concatenated file data, decompressed."""
        if self._block and self._block[0] == index:
            return self._block[1]
        record, sub = divmod(index, PER_RECORD)
        if record >= len(self.records):
            raise ValueError(f"block {index} is past the offset records")
        base, *sizes = self.records[record]
        offset = base + sum(sizes[:sub]) + sub
        size = sizes[sub] + 1
        if offset + size > self.data_size:
            raise ValueError(f"block {index} lies past the compressed data")
        raw = self._read(self.data_offset + offset, size)
        data = raw if size == BLOCK else self._zstd.decompress(raw, BLOCK)
        if len(data) != BLOCK:
            raise ValueError(f"block {index} decompressed to {len(data)} bytes, not {BLOCK}")
        self._block = (index, data)
        return data

    def read(self, entry: Entry) -> Iterator[bytes]:
        position, left = entry.ref, entry.size
        while left > 0:
            index, at = divmod(position, BLOCK)
            chunk = self.block(index)[at : at + min(left, BLOCK - at)]
            yield chunk
            position += len(chunk)
            left -= len(chunk)

    def describe(self) -> dict:
        return {
            "version": f"0x{VERSION1:08x}",
            "blocks": len(self.records) * PER_RECORD,
            "compressed_bytes": self.sections["compressed_data"][1],
            "sections": {n: {"offset": o, "size": s} for n, (o, s) in self.sections.items()},
        }

    def close(self) -> None:
        self._f.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite zar",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    containers.add_actions(p.add_subparsers(dest="action", required=True), "archive")
    args = p.parse_args(argv)
    try:
        archive = ZarArchive((args.caller_cwd / args.file).resolve())
        try:
            return containers.run(archive, args)
        finally:
            archive.close()
    except (OSError, ValueError, struct.error) as exc:
        p.exit(1, f"zar: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
