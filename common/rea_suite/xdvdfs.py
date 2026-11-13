"""XDVDFS, the Xbox and Xbox 360 game disc file system, read from a disc image.

A Redump image of a 360 disc (XGD2, XGD3) or an original Xbox disc (XGD1) holds a DVD video partition
first and the game partition further in; an XISO (made by extract-xiso, or a "game partition only"
dump) holds the game partition alone. The partition's volume descriptor sits in its sector 32 and
starts and ends with "MICROSOFT*XBOX*MEDIA"; this reader tries the offsets below in turn, as
extract-xiso and xdvdfs do (extract-xiso.c; xdvdfs-core blockdev/offset.rs).

Directories are binary trees of entries, 4-byte aligned: left and right child offsets in dwords (0:
none), first sector, size, attributes (0x10: directory), name length, name. Sectors are 2048 bytes
from the partition's start; all numbers little-endian.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from rea_suite import containers
from rea_suite.containers import Entry, Tree
from rea_suite.text import printable

SECTOR = 2048
MAGIC = b"MICROSOFT*XBOX*MEDIA"
DESCRIPTOR_SECTOR = 32
# The game partition's start by disc type, the XISO first. XGD3's is the one most images are cut at.
OFFSETS = {"XISO": 0, "XGD2": 0x0FD90000, "XGD3": 0x02080000, "XGD1": 0x18300000}
DIRECTORY = 0x10
HEAD = struct.Struct("<HHIIBB")
# A real directory table is a few sectors; this bounds a crafted one.
MAX_DIRECTORY = 16 * 1024 * 1024
CHUNK = 1024 * 1024


def find_partition(path: Path) -> tuple[str, int] | None:
    """The disc type and partition offset whose sector 32 holds the volume descriptor."""
    size = path.stat().st_size
    with path.open("rb") as f:
        for kind, offset in OFFSETS.items():
            at = offset + DESCRIPTOR_SECTOR * SECTOR
            if at + SECTOR > size:
                continue
            f.seek(at)
            sector = f.read(SECTOR)
            if sector[:20] == MAGIC and sector[0x7EC : 0x7EC + 20] == MAGIC:
                return kind, offset
    return None


class XdvdfsImage:
    """One disc image's game partition, open for reading. Implements containers.Container."""

    format = "XDVDFS"

    def __init__(self, path: Path):
        found = find_partition(path)
        if found is None:
            raise ValueError(
                "no XDVDFS game partition at the XISO, XGD2, XGD3 or XGD1 offset"
                " (a Games on Demand package or another container needs converting first)"
            )
        self.layout, self.offset = found
        self.size = path.stat().st_size
        self._f = path.open("rb")
        self._f.seek(self.offset + DESCRIPTOR_SECTOR * SECTOR)
        sector = self._f.read(SECTOR)
        self.root_sector, self.root_size, self.filetime = struct.unpack_from("<IIQ", sector, 20)
        self._tree: Tree | None = None

    def _read(self, offset: int, size: int) -> bytes:
        if offset + size > self.size:
            raise ValueError(f"{size} bytes at 0x{offset:x} lie past the image's end")
        self._f.seek(offset)
        return self._f.read(size)

    def _directory(self, sector: int, size: int) -> list[tuple[str, int, int, bool]]:
        """A directory's entries (name, sector, size, is_dir), walked from its tree's root."""
        if size == 0:
            return []
        if size > MAX_DIRECTORY:
            raise ValueError(f"directory at sector {sector} is {size} bytes")
        table = self._read(self.offset + sector * SECTOR, size)
        out, todo, seen = [], [0], set()
        while todo:
            at = todo.pop()
            if at in seen or at + HEAD.size > len(table):
                continue
            seen.add(at)
            left, right, start, length, attributes, count = HEAD.unpack_from(table, at)
            if left == 0xFFFF and right == 0xFFFF:  # sector padding: an empty directory
                continue
            name = table[at + HEAD.size : at + HEAD.size + count].decode("latin-1")
            out.append((name, start, length, bool(attributes & DIRECTORY)))
            todo += [4 * n for n in (right, left) if n]
        return out

    def tree(self) -> Tree:
        if self._tree is not None:
            return self._tree
        found = Tree()
        directories = {self.root_sector}

        def walk(sector: int, size: int, prefix: str, depth: int) -> None:
            if depth > containers.MAX_DEPTH:
                found.skipped.append(f"{printable(prefix)}: nested too deep")
                return
            for name, start, length, is_dir in sorted(
                self._directory(sector, size), key=lambda e: e[0].lower()
            ):
                if len(found.entries) >= containers.MAX_ENTRIES:
                    found.skipped.append(f"more than {containers.MAX_ENTRIES} entries")
                    return
                if not containers.safe_name(name):
                    found.skipped.append(f"{printable(prefix)}/{printable(name)}: unsafe name")
                    continue
                path = f"{prefix}/{name}" if prefix else name
                if is_dir:
                    if start in directories and length:
                        found.skipped.append(f"{printable(path)}: directory seen twice")
                        continue
                    directories.add(start)
                    found.entries.append(Entry(path, 0, True, start))
                    walk(start, length, path, depth + 1)
                elif self.offset + start * SECTOR + length > self.size:
                    found.skipped.append(f"{printable(path)}: lies past the image's end")
                else:
                    found.entries.append(Entry(path, length, False, start))

        walk(self.root_sector, self.root_size, "", 0)
        self._tree = found
        return found

    def read(self, entry: Entry) -> Iterator[bytes]:
        position, left = self.offset + entry.ref * SECTOR, entry.size
        while left > 0:
            chunk = self._read(position, min(left, CHUNK))
            yield chunk
            position += len(chunk)
            left -= len(chunk)

    def describe(self) -> dict:
        return {
            "layout": self.layout,
            "partition_offset": f"0x{self.offset:x}",
            "root_sector": self.root_sector,
            "root_size": self.root_size,
            "filetime": self.filetime,
            "image_bytes": self.size,
        }

    def close(self) -> None:
        self._f.close()
