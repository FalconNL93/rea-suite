"""Remedy packages (RMDP): an index (.bin) with a tree of folders and files, and a data file (.rmdp)
with their bytes, as in Alan Wake, Alan Wake Remastered, American Nightmare, Quantum Break and Control.

  rea-suite rmdp list <index.bin> [--glob PATTERN] [--json]      every file: path, size, offset, CRC-32
  rea-suite rmdp extract <index.bin> <glob>... --out DIR [--check] copies of the matching files
  rea-suite rmdp find <index.bin> (--text TEXT | --hex BYTES) [--glob PATTERN] [--inner]
                                                                   files holding the bytes, with offsets
  rea-suite rmdp inner <index.bin> <glob>... --out DIR             the entries of the matching files that
                                                                   are level containers (a name table and
                                                                   one zlib stream), extracted

--inner also looks inside those containers (Alan Wake's level .bin files; OpenAWE's binarchive).

Read only: the package is never written; extraction refuses an output inside the package's folder.
Globs match the path inside the package (folders joined by "/"), case-blind, as the engine looks names
up by their lowercase form. Written from the format's description in GrzybDev/NorthlightTools
(docs/rmdp.md) and OpenAWE-Project/OpenAWE (src/awe/rmdparchive), both GPL-3.0, read as references;
no code of theirs is used. docs/PORT-TOOLS.md has the layout.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

NULL = {4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}


@dataclass(frozen=True)
class Layout:
    """Where each field of a folder and a file record lies, for one family of games."""

    name: str
    link: int  # bytes per link: 4 or 8
    header: int  # bytes before the folder records
    folder: dict[str, int]  # field -> offset
    folder_size: int
    file: dict[str, int]
    file_size: int
    closing: bool  # one folder record after the file records


def _layouts(version: int) -> list[Layout]:
    if version == 2:
        return [
            # Alan Wake (2010): packed records, 32-bit links.
            Layout(
                "v2-packed",
                4,
                0x91,
                {"next": 0x04, "parent": 0x08, "name": 0x10, "child": 0x14, "first_file": 0x18},
                28,
                {
                    "next": 0x04,
                    "parent": 0x08,
                    "flags": 0x0C,
                    "name": 0x10,
                    "offset": 0x14,
                    "size": 0x1C,
                    "crc": 0x24,
                },
                40,
                False,
            ),
            # Alan Wake Remastered: the same fields, 64-bit links, aligned as a C compiler lays them out.
            Layout(
                "v2-aligned",
                8,
                0x91,
                {"next": 0x08, "parent": 0x10, "name": 0x20, "child": 0x28, "first_file": 0x30},
                56,
                {
                    "next": 0x08,
                    "parent": 0x10,
                    "flags": 0x18,
                    "name": 0x20,
                    "offset": 0x28,
                    "size": 0x30,
                    "crc": 0x38,
                },
                64,
                False,
            ),
        ]
    if version == 7:
        return [
            Layout(
                "v7",
                4,
                0x99,
                {"next": 0x04, "parent": 0x08, "name": 0x10, "child": 0x14, "first_file": 0x18},
                28,
                {
                    "next": 0x04,
                    "parent": 0x08,
                    "flags": 0x0C,
                    "name": 0x10,
                    "offset": 0x14,
                    "size": 0x1C,
                    "crc": 0x24,
                },
                48,
                True,
            )
        ]
    if version in (8, 9):
        return [
            Layout(
                "v8",
                8,
                0x99,
                {"next": 0x04, "parent": 0x0C, "name": 0x18, "child": 0x20, "first_file": 0x28},
                48,
                {
                    "next": 0x04,
                    "parent": 0x0C,
                    "flags": 0x14,
                    "name": 0x18,
                    "offset": 0x20,
                    "size": 0x28,
                    "crc": 0x30,
                },
                60,
                True,
            )
        ]
    return []


@dataclass
class Entry:
    path: str
    offset: int
    size: int
    crc: int
    flags: int


@dataclass
class Package:
    index: Path
    data: Path
    version: int
    layout: str
    big_endian: bool
    base_path: str
    files: list[Entry] = field(default_factory=list)
    folders: int = 0
    warnings: list[str] = field(default_factory=list)


def name_checksum(name: bytes) -> int:
    """CRC-32 of the name with ASCII A-Z lowercased (the engine looks names up in lowercase)."""
    return zlib.crc32(bytes(b + 32 if 65 <= b <= 90 else b for b in name)) & 0xFFFFFFFF


def read_package(index: Path) -> Package:
    raw = index.read_bytes()
    if len(raw) < 0x91 or raw[0] not in (0, 1):
        raise ValueError("not a Remedy package index (byte order flag)")
    big = raw[0] == 1
    order = ">" if big else "<"
    version = struct.unpack_from(order + "I", raw, 1)[0]
    layouts = _layouts(version)
    if not layouts:
        raise ValueError(f"unknown package version {version}")
    folder_count, file_count = struct.unpack_from(order + "II", raw, 5)
    names_at = 0x0D if version == 2 else 0x15
    names_size = struct.unpack_from(order + "I", raw, names_at)[0]
    base_raw = raw[names_at + 4 : names_at + 4 + 128]
    base = base_raw.split(b"\0", 1)[0].decode("utf-8", "replace")

    def link_reader(lay: Layout):
        fmt = order + ("I" if lay.link == 4 else "Q")
        return lambda at: struct.unpack_from(fmt, raw, at)[0]

    def root_fits(lay: Layout) -> bool:
        if lay.header + folder_count * lay.folder_size > len(raw):
            return False
        link = link_reader(lay)
        root = lay.header
        return (
            link(root + lay.folder["next"]) == NULL[lay.link]
            and link(root + lay.folder["parent"]) == NULL[lay.link]
        )

    fitting = [lay for lay in layouts if root_fits(lay)]
    if len(fitting) != 1:
        raise ValueError(f"version {version}: the root record fits {len(fitting)} layouts, not one")
    lay = fitting[0]
    link = link_reader(lay)
    null = NULL[lay.link]
    folders_at = lay.header
    files_at = folders_at + folder_count * lay.folder_size
    names_start = files_at + file_count * lay.file_size + (lay.folder_size if lay.closing else 0)
    names = raw[names_start : names_start + names_size]
    if len(names) != names_size:
        raise ValueError("the names block runs past the index")
    package = Package(
        index, index.with_suffix(".rmdp"), version, lay.name, big, base, folders=folder_count
    )

    def name_at(offset: int, at: int, kind: str) -> str:
        if offset == null or offset >= len(names):
            raise ValueError(f"{kind} record at {at:#x}: name offset outside the names block")
        text = names[offset : names.index(b"\0", offset)]
        stored = struct.unpack_from(order + "I", raw, at)[0]
        if stored != name_checksum(text):
            package.warnings.append(
                f"{kind} {text.decode('utf-8', 'replace')}: name checksum differs"
            )
        return text.decode("utf-8")

    seen_folders: set[int] = set()
    seen_files: set[int] = set()
    stack = [(0, "")]
    while stack:
        folder, prefix = stack.pop()
        if folder in seen_folders or folder >= folder_count:
            raise ValueError(f"folder link {folder} is repeated or out of range")
        seen_folders.add(folder)
        at = folders_at + folder * lay.folder_size
        file_index = link(at + lay.folder["first_file"])
        while file_index != null:
            if file_index in seen_files or file_index >= file_count:
                raise ValueError(f"file link {file_index} is repeated or out of range")
            seen_files.add(file_index)
            fat = files_at + file_index * lay.file_size
            f = lay.file
            name = name_at(link(fat + f["name"]), fat, "file")
            package.files.append(
                Entry(
                    path=prefix + name,
                    offset=struct.unpack_from(order + "Q", raw, fat + f["offset"])[0],
                    size=struct.unpack_from(order + "Q", raw, fat + f["size"])[0],
                    crc=struct.unpack_from("<I", raw, fat + f["crc"])[
                        0
                    ],  # little-endian in every package
                    flags=struct.unpack_from(order + "I", raw, fat + f["flags"])[0],
                )
            )
            file_index = link(fat + f["next"])
        child = link(at + lay.folder["child"])
        while child != null:
            cat = folders_at + child * lay.folder_size
            stack.append(
                (child, prefix + name_at(link(cat + lay.folder["name"]), cat, "folder") + "/")
            )
            child = link(cat + lay.folder["next"])
    if len(seen_files) != file_count:
        package.warnings.append(
            f"{file_count - len(seen_files)} file records are not reachable from the root"
        )
    package.files.sort(key=lambda e: e.path.lower())
    return package


def matching(package: Package, patterns: list[str]) -> list[Entry]:
    if not patterns:
        return package.files
    lowered = [p.lower() for p in patterns]
    return [
        e for e in package.files if any(fnmatch.fnmatchcase(e.path.lower(), p) for p in lowered)
    ]


def read_file(data, entry: Entry) -> bytes:
    data.seek(entry.offset)
    content = data.read(entry.size)
    if len(content) != entry.size:
        raise ValueError(f"{entry.path}: the data file ends inside it")
    return content


def safe_name(name: str) -> str:
    """A package name as a file name every file system takes: unsafe characters as %XX."""
    out = []
    for ch in name:
        out.append(f"%{ord(ch):02X}" if ch in '<>:"/\\|?*%' or ord(ch) < 32 else ch)
    text = "".join(out)
    if text.endswith((".", " ")):
        text = text[:-1] + f"%{ord(text[-1]):02X}"
    stem = text.split(".", 1)[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL"} or (
        stem[:3] in {"COM", "LPT"} and stem[3:] in set("123456789")
    ):
        text = f"%{ord(text[0]):02X}" + text[1:]
    return text


def inner_entries(content: bytes) -> list[tuple[str, bytes]] | None:
    """A level container's entries, or None when the bytes are not one: a little-endian count, per entry a
    name length, the name and a size, then one zlib stream holding the entries back to back. The integers
    are 32-bit in Alan Wake and 64-bit in Alan Wake Remastered."""
    for width, fmt in ((8, "<Q"), (4, "<I")):
        entries = _inner(content, width, fmt)
        if entries is not None:
            return entries
    return None


def _inner(content: bytes, width: int, fmt: str) -> list[tuple[str, bytes]] | None:
    if len(content) < 2 * width:
        return None
    count = struct.unpack_from(fmt, content, 0)[0]
    if not 0 < count < 4096:
        return None
    at = width
    table = []
    for _ in range(count):
        if at + width > len(content):
            return None
        length = struct.unpack_from(fmt, content, at)[0]
        if not 0 < length < 512 or at + 2 * width + length > len(content):
            return None
        name = content[at + width : at + width + length]
        if not all(32 <= b < 127 for b in name):
            return None
        size = struct.unpack_from(fmt, content, at + width + length)[0]
        table.append((name.decode(), size))
        at += 2 * width + length
    try:
        data = zlib.decompress(content[at:])
    except zlib.error:
        return None
    if len(data) != sum(size for _, size in table):
        return None
    out, offset = [], 0
    for name, size in table:
        out.append((name, data[offset : offset + size]))
        offset += size
    return out


def cmd_list(args, package: Package) -> int:
    rows = matching(package, [args.glob] if args.glob else [])
    if args.json:
        print(
            json.dumps(
                {
                    "version": package.version,
                    "layout": package.layout,
                    "big_endian": package.big_endian,
                    "base_path": package.base_path,
                    "folders": package.folders,
                    "files": [e.__dict__ for e in rows],
                    "warnings": package.warnings,
                },
                indent=1,
            )
        )
    else:
        for e in rows:
            print(f"{e.size:>12}  {e.offset:#014x}  {e.crc:08x}  {e.path}")
        print(
            f"{len(rows)} of {len(package.files)} files; version {package.version} ({package.layout}, "
            f"{'big' if package.big_endian else 'little'}-endian), base {package.base_path!r}",
            file=sys.stderr,
        )
    for warning in package.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 0 if rows else 1


def cmd_extract(args, package: Package) -> int:
    out = (args.caller_cwd / args.out).resolve()
    if out.is_relative_to(package.index.resolve().parent):
        print("rmdp: the output lies inside the package's folder; choose another", file=sys.stderr)
        return 2
    rows = matching(package, args.glob)
    bad = 0
    with package.data.open("rb") as data:
        for e in rows:
            content = read_file(data, e)
            if args.check and zlib.crc32(content) & 0xFFFFFFFF != e.crc:
                print(f"crc differs: {e.path}", file=sys.stderr)
                bad += 1
            target = out.joinpath(*[safe_name(part) for part in e.path.split("/")])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    print(
        f"{len(rows)} files to {out}" + (f", {bad} with another CRC-32" if args.check else ""),
        file=sys.stderr,
    )
    return 0 if rows else 1


def cmd_find(args, package: Package) -> int:
    needle = args.text.encode() if args.text is not None else bytes.fromhex(args.hex)
    if not needle:
        print("rmdp: nothing to find", file=sys.stderr)
        return 2
    rows = matching(package, [args.glob] if args.glob else [])
    hits = 0
    chunk = 1 << 24
    with package.data.open("rb") as data:
        for e in rows:
            if args.inner and e.size < (1 << 28):
                inner = inner_entries(read_file(data, e))
                if inner is not None:
                    for name, content in inner:
                        found = (
                            [i for i in range(len(content)) if content.startswith(needle, i)]
                            if needle in content
                            else []
                        )
                        if found:
                            hits += 1
                            shown = ", ".join(f"{o:#x}" for o in found[:8]) + (
                                " ..." if len(found) > 8 else ""
                            )
                            print(f"{e.path}:{name}  {len(found)}x  {shown}")
                    continue
            offsets = []
            done = 0
            tail = b""
            data.seek(e.offset)
            while done < e.size:
                block = data.read(min(chunk, e.size - done))
                if not block:
                    break
                window = tail + block
                start = 0
                while (at := window.find(needle, start)) != -1:
                    offsets.append(done - len(tail) + at)
                    start = at + 1
                tail = window[-(len(needle) - 1) :] if len(needle) > 1 else b""
                done += len(block)
            if offsets:
                hits += 1
                shown = ", ".join(f"{o:#x}" for o in offsets[:8]) + (
                    " ..." if len(offsets) > 8 else ""
                )
                print(f"{e.path}  {len(offsets)}x  {shown}")
    print(f"{hits} of {len(rows)} files hold it", file=sys.stderr)
    return 0 if hits else 1


def cmd_inner(args, package: Package) -> int:
    out = (args.caller_cwd / args.out).resolve()
    if out.is_relative_to(package.index.resolve().parent):
        print("rmdp: the output lies inside the package's folder; choose another", file=sys.stderr)
        return 2
    count = 0
    with package.data.open("rb") as data:
        for e in matching(package, args.glob):
            inner = inner_entries(read_file(data, e))
            if inner is None:
                continue
            folder = out.joinpath(*[safe_name(part) for part in e.path.split("/")])
            folder.mkdir(parents=True, exist_ok=True)
            for name, content in inner:
                (folder / safe_name(name)).write_bytes(content)
                count += 1
    print(f"{count} entries to {out}", file=sys.stderr)
    return 0 if count else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite rmdp",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("list", help="every file with its size, data offset and CRC-32")
    c.add_argument("index", type=Path)
    c.add_argument("--glob", help="only paths matching this pattern (case-blind)")
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_list)
    c = sub.add_parser("extract", help="copies of the matching files into a folder")
    c.add_argument("index", type=Path)
    c.add_argument("glob", nargs="+", help="path patterns inside the package (case-blind)")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--check", action="store_true", help="compare each file with its stored CRC-32")
    c.set_defaults(run=cmd_extract)
    c = sub.add_parser("find", help="files whose bytes hold a text or byte string")
    c.add_argument("index", type=Path)
    what = c.add_mutually_exclusive_group(required=True)
    what.add_argument("--text")
    what.add_argument("--hex")
    c.add_argument("--glob", help="only paths matching this pattern (case-blind)")
    c.add_argument("--inner", action="store_true", help="look inside level containers too")
    c.set_defaults(run=cmd_find)
    c = sub.add_parser("inner", help="the entries of level containers, extracted")
    c.add_argument("index", type=Path)
    c.add_argument("glob", nargs="+", help="path patterns inside the package (case-blind)")
    c.add_argument("--out", type=Path, required=True)
    c.set_defaults(run=cmd_inner)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        package = read_package((args.caller_cwd / args.index).resolve())
        return args.run(args, package)
    except (OSError, ValueError) as exc:
        print(f"rmdp: {args.index}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
