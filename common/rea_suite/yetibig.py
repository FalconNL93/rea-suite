"""YETI engine archives (Yeti.big): Ubisoft's YETI engine, as in Lost: Via Domus (PC and Xbox 360; checked)
and Ghost Recon Advanced Warfighter (Xbox 360; not tried). A header, a table of resources found by 32-bit
key (there are no file names), and the resources, some LZO1X-compressed, some stored several times.

  rea-suite yetibig info <Yeti.big> [--json]                   header fields, counts, classes
  rea-suite yetibig list <Yeti.big> [--class HEX] [--json]     key, class, size, flags, offset of each copy
  rea-suite yetibig blob <Yeti.big> <key>... --out DIR [--raw] resource bytes, unpacked (header stripped)
  rea-suite yetibig diff <a.big> <b.big> [--json]              keys only in A, only in B, sizes that differ
  rea-suite yetibig refs <Yeti.big> [--json]                   the reference graph of the resources' key
                                                               lists: unreferenced and absent keys
  rea-suite yetibig check <Yeti.big> [--json]                  the coverage proof: every byte of the data
                                                               read, overlaps, gaps, copies, every resource
                                                               decoded (minutes on a game's archive: run it
                                                               under `heavy run`)

Read only: the archive is never written; blob refuses an output inside the archive's folder. Offsets
printed are file offsets. LZO1X goes through liblzo2 when the system has it (much faster on a whole
archive), else a pure-Python decoder. docs/PORT-TOOLS.md has the layout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rea_suite import lzo1x
from rea_suite.text import decoded

HEADER = 0x268
VERSION = 0x57  # the loader refuses anything older
ENTRY = 12
DUP_MARK = 0xFE  # top byte of a table offset: the resource is stored several times
DUP_KEY = 0x1000  # the resource holding the duplicate-offset list
NO_KEY = 0xFFFFFFFF  # an empty slot in a key list
KNOWN_FLAGS = (0x00, 0x02, 0x08, 0x0A)
FLAG_KEYS = 0x02
FLAG_LZO = 0x08


class UnknownFlags(ValueError):
    """A resource header whose flags are not understood; reported, never guessed at."""

    def __init__(self, flags: int) -> None:
        super().__init__(f"flags {flags:#04x} not known")
        self.flags = flags


@dataclass
class Entry:
    index: int
    key: int
    type: int  # index into the header's class list
    size: int  # stored bytes
    stored: int  # the table's offset field as written
    offset: int | None  # relative to the data; None when duplicated
    dup_index: int = 0
    dup_count: int = 0


@dataclass
class Archive:
    path: Path
    file_size: int
    version: int
    short_table: int
    field08: int
    field14: int
    root: str
    classes: list[int]
    entries: list[Entry]
    _dups: list[int] | None = field(default=None, repr=False)

    @property
    def data_base(self) -> int:
        return HEADER + ENTRY * len(self.entries)

    @property
    def data_length(self) -> int:
        return self.file_size - self.data_base

    def class_of(self, e: Entry) -> int:
        return self.classes[e.type]

    def by_key(self) -> dict[int, Entry]:
        return {e.key: e for e in reversed(self.entries)}  # the first of a repeated key wins

    def duplicate_list(self) -> list[int]:
        """The data-relative offsets of every copy, from resource 0x1000; checked against the table."""
        if self._dups is None:
            self._dups = []
            if any(e.offset is None for e in self.entries):
                holder = self.by_key().get(DUP_KEY)
                if holder is None or holder.offset is None:
                    raise ValueError(
                        f"duplicated resources but no placed resource {DUP_KEY:#x} to list them"
                    )
                with self.path.open("rb") as f:
                    body = decode(read_at(f, self.data_base + holder.offset, holder.size)).body
                if len(body) < 4:
                    raise ValueError("the duplicate list is shorter than its count")
                count = struct.unpack_from("<I", body)[0]
                if len(body) < 4 + 4 * count:
                    raise ValueError(f"the duplicate list holds fewer than its {count} offsets")
                self._dups = list(struct.unpack_from(f"<{count}I", body, 4))
                for e in self.entries:
                    if e.offset is None:
                        if e.dup_count == 0 or e.dup_index + e.dup_count > count:
                            raise ValueError(f"key {e.key:08x}: copies outside the duplicate list")
                        for off in self._dups[e.dup_index : e.dup_index + e.dup_count]:
                            if off + e.size > self.data_length:
                                raise ValueError(f"key {e.key:08x}: a copy lies outside the file")
        return self._dups

    def copies(self, e: Entry) -> list[int]:
        """File offsets of the entry's stored bytes, one per copy."""
        if e.offset is not None:
            return [self.data_base + e.offset]
        dups = self.duplicate_list()
        return [self.data_base + o for o in dups[e.dup_index : e.dup_index + e.dup_count]]


def read_archive(path: Path) -> Archive:
    file_size = path.stat().st_size
    with path.open("rb") as f:
        head = f.read(HEADER)
        if len(head) < HEADER:
            raise ValueError("shorter than a Yeti.big header")
        version, short, count = struct.unpack_from("<HBxI", head)
        if version < VERSION:
            raise ValueError(
                f"version {version:#x} is older than {VERSION:#x}, which the engine refuses"
            )
        if short != 1:
            raise ValueError(f"table flag {short}: only the 12-byte table (flag 1) is handled")
        if HEADER + ENTRY * count > file_size:
            raise ValueError(f"the table of {count} entries runs past the file")
        table = f.read(ENTRY * count)
    field08, field14 = struct.unpack_from("<I8xI", head, 0x08)
    root = decoded(head[0x36:0x68].split(b"\0", 1)[0], "latin-1")
    classes = list(struct.unpack_from("<256H", head, 0x68))
    data_length = file_size - HEADER - ENTRY * count
    entries = []
    for i, (off, key, type_size) in enumerate(struct.iter_unpack("<III", table)):
        e = Entry(i, key, type_size >> 24, type_size & 0xFFFFFF, off, off)
        if off >> 24 == DUP_MARK:
            e.offset, e.dup_index, e.dup_count = None, off & 0x3FFFF, (off >> 18) & 0x3F
        elif off + e.size > data_length:
            raise ValueError(f"entry {i} (key {key:08x}) lies outside the file")
        entries.append(e)
    return Archive(path, file_size, version, short, field08, field14, root, classes, entries)


def read_at(f, at: int, size: int) -> bytes:
    f.seek(at)
    data = f.read(size)
    if len(data) != size:
        raise ValueError(f"the file ends inside the bytes at {at:#x}")
    return data


@dataclass
class Head:
    flags: int
    unpacked: int | None  # flag 0x08
    key_count: int  # flag 0x02
    keys_at: int
    body_at: int


def parse_head(prefix: bytes, size: int) -> Head:
    """A resource's header from its first bytes (8 are enough): `01 flags [u32 unpacked] [u16 n]`."""
    if size < 2 or prefix[0] != 1:
        raise ValueError(f"starts with {prefix[:1].hex() or 'nothing'}, not 01")
    flags = prefix[1]
    if flags not in KNOWN_FLAGS:
        raise UnknownFlags(flags)
    at, unpacked, count = 2, None, 0
    if flags & FLAG_LZO:
        if size < at + 4 or len(prefix) < at + 4:
            raise ValueError("ends inside the unpacked size")
        unpacked = struct.unpack_from("<I", prefix, at)[0]
        at += 4
    if flags & FLAG_KEYS:
        if size < at + 2 or len(prefix) < at + 2:
            raise ValueError("ends inside the key count")
        count = struct.unpack_from("<H", prefix, at)[0]
        at += 2
    if at + 4 * count > size:
        raise ValueError("the key list runs past the resource")
    return Head(flags, unpacked, count, at, at + 4 * count)


@dataclass
class Resource:
    flags: int
    keys: list[int]
    body: bytes  # unpacked when flag 0x08


def decode(stored: bytes) -> Resource:
    h = parse_head(stored[:8], len(stored))
    keys = list(struct.unpack_from(f"<{h.key_count}I", stored, h.keys_at))
    body = stored[h.body_at :]
    if h.unpacked is not None:
        body = lzo1x.unpack(body, h.unpacked)
    return Resource(h.flags, keys, body)


def resource_keys(f, at: int, size: int) -> list[int]:
    """The key list of the resource at a file offset, reading only its header."""
    h = parse_head(read_at(f, at, min(size, 8)), size)
    if not h.key_count:
        return []
    return list(struct.unpack(f"<{h.key_count}I", read_at(f, at + h.keys_at, 4 * h.key_count)))


def class_name(archive: Archive, e: Entry) -> str:
    return f"{archive.class_of(e):04x}"


def histogram(counter: Counter) -> str:
    return ", ".join(f"{k}:{v}" for k, v in counter.most_common()) or "none"


def emit(data: dict) -> None:
    print(json.dumps(data, indent=1))


def cmd_info(args, archive: Archive) -> int:
    used = Counter(e.type for e in archive.entries)
    dups = [e for e in archive.entries if e.offset is None]
    info = {
        "archive": str(archive.path),
        "file_size": archive.file_size,
        "version": archive.version,
        "short_table": archive.short_table,
        "entries": len(archive.entries),
        "field08": archive.field08,
        "field14": archive.field14,
        "root": archive.root,
        "data_base": archive.data_base,
        "data_length": archive.data_length,
        "placed": len(archive.entries) - len(dups),
        "duplicated": len(dups),
        "copies": sum(e.dup_count for e in dups),
        "class_slots": sum(1 for c in archive.classes if c not in (0, 0xFFFF)),
        "types": [
            {"type": t, "class": archive.classes[t], "entries": n} for t, n in used.most_common()
        ],
    }
    if args.json:
        emit(info)
        return 0
    print(f"{archive.path}: {archive.file_size} bytes")
    print(
        f"version {archive.version:#x}, table flag {archive.short_table}, {len(archive.entries)} entries,"
        f" root {archive.root!r}, field 0x08 {archive.field08:#x}, field 0x14 {archive.field14:#x} (unknown)"
    )
    print(f"data at {archive.data_base:#x}, {archive.data_length} bytes")
    print(
        f"placed {info['placed']}, duplicated {info['duplicated']} with {info['copies']} copies;"
        f" {info['class_slots']} class slots set, {len(used)} types used"
    )
    for t, n in used.most_common():
        print(f"  type {t:3d}  class {archive.classes[t]:04x}  {n}")
    return 0


def resource_flags(f, at: int, size: int) -> int | None:
    """The flag byte, or None when the resource does not start with 01."""
    head = read_at(f, at, min(size, 2))
    return head[1] if len(head) == 2 and head[0] == 1 else None


def cmd_list(args, archive: Archive) -> int:
    rows = archive.entries
    if args.class_id is not None:
        rows = [e for e in rows if archive.class_of(e) == args.class_id]
    offsets = {e.index: archive.copies(e) for e in rows}
    flags: dict[int, int | None] = {}
    with archive.path.open("rb") as f:
        for e in sorted(rows, key=lambda e: offsets[e.index][0]):
            flags[e.index] = resource_flags(f, offsets[e.index][0], e.size)
    if args.json:
        emit(
            {
                "archive": str(archive.path),
                "entries": [
                    {
                        "index": e.index,
                        "key": e.key,
                        "type": e.type,
                        "class": archive.class_of(e),
                        "size": e.size,
                        "flags": flags[e.index],
                        "table_offset": e.stored,
                        "offsets": offsets[e.index],
                    }
                    for e in rows
                ],
            }
        )
    else:
        for e in rows:
            fl = flags[e.index]
            where = ",".join(f"{o:#x}" for o in offsets[e.index])
            shown = "--" if fl is None else f"{fl:02x}"
            print(f"{e.key:08x}  {class_name(archive, e)}  {e.size:>8}  {shown}  {where}")
        print(f"{len(rows)} of {len(archive.entries)} entries", file=sys.stderr)
    return 0 if rows else 1


def cmd_blob(args, archive: Archive) -> int:
    out = (args.caller_cwd / args.out).resolve()
    if out.is_relative_to(archive.path.parent):
        print(
            "yetibig: the output lies inside the archive's folder; choose another", file=sys.stderr
        )
        return 2
    table = archive.by_key()
    missing = 0
    out.mkdir(parents=True, exist_ok=True)
    with archive.path.open("rb") as f:
        for text in args.keys:
            key = int(text, 16)
            e = table.get(key)
            if e is None:
                print(f"{key:08x}: not in the table", file=sys.stderr)
                missing += 1
                continue
            stored = read_at(f, archive.copies(e)[0], e.size)
            name = f"{key:08x}.bin"
            if args.raw:
                content, note = stored, "stored bytes"
            else:
                try:
                    res = decode(stored)
                except UnknownFlags as exc:
                    content, name, note = stored, f"{key:08x}.stored", f"{exc}: stored bytes"
                else:
                    keys = " ".join(f"{k:08x}" for k in res.keys)
                    content = res.body
                    note = f"flags {res.flags:#04x}" + (f", keys {keys}" if keys else "")
            (out / name).write_bytes(content)
            print(f"{key:08x}  {class_name(archive, e)}  {len(content):>8}  {name}  {note}")
    return 1 if missing else 0


def cmd_diff(args, a: Archive) -> int:
    b = read_archive((args.caller_cwd / args.other).resolve())
    ka, kb = a.by_key(), b.by_key()
    only_a = [e for k, e in ka.items() if k not in kb]
    only_b = [e for k, e in kb.items() if k not in ka]
    differ = [(e, kb[k]) for k, e in ka.items() if k in kb and kb[k].size != e.size]
    same = sum(1 for k, e in ka.items() if k in kb and kb[k].size == e.size)
    counts = {
        "only_a": Counter(class_name(a, e) for e in only_a),
        "only_b": Counter(class_name(b, e) for e in only_b),
        "size_differs": Counter(class_name(a, e) for e, _ in differ),
    }
    if args.json:
        emit(
            {
                "a": str(a.path),
                "b": str(b.path),
                "same_size": same,
                "only_a": [{"key": e.key, "class": a.class_of(e), "size": e.size} for e in only_a],
                "only_b": [{"key": e.key, "class": b.class_of(e), "size": e.size} for e in only_b],
                "size_differs": [
                    {"key": x.key, "class": a.class_of(x), "size_a": x.size, "size_b": y.size}
                    for x, y in differ
                ],
                "by_class": {name: dict(c.most_common()) for name, c in counts.items()},
            }
        )
        return 0
    print(f"only in A ({a.path}): {len(only_a)}")
    print(f"only in B ({b.path}): {len(only_b)}")
    print(f"in both, size differs: {len(differ)}; same size: {same}")
    for name, c in counts.items():
        print(f"{name} by class: {histogram(c)}")
    return 0


def cmd_refs(args, archive: Archive) -> int:
    keys = {e.key for e in archive.entries}
    referrers: Counter[int] = Counter()
    dangling: Counter[int] = Counter()
    dangling_by_referrer: Counter[str] = Counter()
    skipped: list[dict] = []
    with archive.path.open("rb") as f:
        for e in sorted(archive.entries, key=lambda e: archive.copies(e)[0]):
            try:
                listed = resource_keys(f, archive.copies(e)[0], e.size)
            except ValueError as exc:
                skipped.append({"key": e.key, "reason": str(exc)})
                continue
            for k in listed:
                if k == NO_KEY:
                    continue
                if k in keys:
                    referrers[k] += 1
                else:
                    dangling[k] += 1
                    dangling_by_referrer[class_name(archive, e)] += 1
    unreferenced = [e for e in archive.entries if not referrers[e.key]]
    unref_classes = Counter(class_name(archive, e) for e in unreferenced)
    if args.json:
        emit(
            {
                "archive": str(archive.path),
                "entries": len(archive.entries),
                "referenced": len(archive.entries) - len(unreferenced),
                "unreferenced": [
                    {"key": e.key, "class": archive.class_of(e), "size": e.size}
                    for e in unreferenced
                ],
                "unreferenced_by_class": dict(unref_classes.most_common()),
                "absent": [{"key": k, "uses": n} for k, n in sorted(dangling.items())],
                "absent_uses_by_referrer_class": dict(dangling_by_referrer.most_common()),
                "skipped": skipped,
            }
        )
        return 0
    print(
        f"{archive.path}: {len(archive.entries)} keys, {len(archive.entries) - len(unreferenced)} named in"
        " another resource's key list"
    )
    print(f"unreferenced: {len(unreferenced)}; by class: {histogram(unref_classes)}")
    for e in unreferenced:
        print(f"  {e.key:08x}  {class_name(archive, e)}  {e.size}")
    print(
        f"referenced but absent: {len(dangling)} keys, {sum(dangling.values())} uses;"
        f" uses by referring class: {histogram(dangling_by_referrer)}"
    )
    for s in skipped:
        print(f"key list not read: {s['key']:08x}: {s['reason']}")
    print(
        "Only the key lists in resource headers are counted, not keys inside bodies.",
        file=sys.stderr,
    )
    return 0


def zero_run(f, at: int, size: int) -> bool:
    f.seek(at)
    left = size
    while left:
        block = f.read(min(left, 1 << 24))
        if not block or block.count(0) != len(block):
            return False
        left -= len(block)
    return True


def prove(archive: Archive) -> dict:
    """Read every region of the data in file order: overlaps, gaps, copies byte-identical, decoding."""
    base = archive.data_base
    dups = archive.duplicate_list()
    regions = []  # (file offset, size, entry, copy number)
    for e in archive.entries:
        for n, at in enumerate(archive.copies(e)):
            regions.append((at, e.size, e, n))
    regions.sort(key=lambda r: (r[0], r[1]))
    slots = sorted((e.dup_index, e.dup_count) for e in archive.entries if e.offset is None)
    position = 0
    tiles = True
    for start, count in slots:
        tiles = tiles and start == position
        position = start + count
    tiles = tiles and position == len(dups)
    overlaps, gaps, failed, unknown = [], [], [], []
    differing = []
    decoded: Counter[str] = Counter()
    digests: dict[int, bytes] = {}
    end, last = base, None
    with archive.path.open("rb") as f:
        for at, size, e, _ in regions:
            if at < end:
                overlaps.append({"offset": at, "key": e.key, "previous": last})
            elif at > end:
                gaps.append(
                    {
                        "offset": end,
                        "size": at - end,
                        "zero": zero_run(f, end, at - end),
                        "after": last,
                    }
                )
            stored = read_at(f, at, size)
            digest = hashlib.blake2b(stored, digest_size=16).digest()
            if e.index in digests:
                if digests[e.index] != digest:
                    differing.append({"key": e.key, "offset": at})
            else:
                digests[e.index] = digest
                try:
                    res = decode(stored)
                    decoded[f"{res.flags:#04x}"] += 1
                except UnknownFlags as exc:
                    unknown.append({"key": e.key, "flags": exc.flags})
                except ValueError as exc:
                    failed.append({"key": e.key, "error": str(exc)})
            end, last = max(end, at + size), e.key
        if end < archive.file_size:
            gaps.append(
                {
                    "offset": end,
                    "size": archive.file_size - end,
                    "zero": zero_run(f, end, archive.file_size - end),
                    "after": last,
                }
            )
    keys_unique = len({e.key for e in archive.entries}) == len(archive.entries)
    return {
        "archive": str(archive.path),
        "entries": len(archive.entries),
        "placed": sum(1 for e in archive.entries if e.offset is not None),
        "duplicated": len(slots),
        "duplicate_list": len(dups),
        "slots_tile_list": tiles,
        "regions": len(regions),
        "overlaps": overlaps,
        "gaps": gaps,
        "keys_unique": keys_unique,
        "copies_differing": differing,
        "decoded_by_flags": dict(sorted(decoded.items())),
        "unknown_flags": unknown,
        "failed": failed,
        "ok": keys_unique and not overlaps and not differing and not failed,
    }


def cmd_check(args, archive: Archive) -> int:
    result = prove(archive)
    if args.json:
        emit(result)
        return 0 if result["ok"] else 1
    yes = {True: "yes", False: "no"}
    gaps = result["gaps"]
    print(f"{archive.path}: {result['entries']} entries")
    print(
        f"placed {result['placed']}, duplicated {result['duplicated']}; duplicate list"
        f" {result['duplicate_list']} offsets, the slots tile it: {yes[result['slots_tile_list']]}"
    )
    print(
        f"regions {result['regions']}: overlaps {len(result['overlaps'])},"
        f" gaps {len(gaps)} ({sum(g['size'] for g in gaps)} bytes)"
    )
    for g in gaps:
        after = "the table" if g["after"] is None else f"key {g['after']:08x}"
        print(
            f"  gap at {g['offset']:#x}, {g['size']} bytes, {'zero' if g['zero'] else 'not zero'}, after {after}"
        )
    for o in result["overlaps"][:20]:
        print(f"  overlap at {o['offset']:#x}: key {o['key']:08x}")
    print(
        f"keys unique: {yes[result['keys_unique']]}; copies differing: {len(result['copies_differing'])}"
    )
    print(
        f"decoded by flags: {', '.join(f'{k} {v}' for k, v in result['decoded_by_flags'].items())}"
    )
    for u in result["unknown_flags"]:
        print(f"unknown flags {u['flags']:#04x}: key {u['key']:08x} (not decoded)")
    for x in result["failed"][:20]:
        print(f"failed: key {x['key']:08x}: {x['error']}")
    print(f"failed {len(result['failed'])}; the proof {'holds' if result['ok'] else 'fails'}")
    return 0 if result["ok"] else 1


def hex_int(text: str) -> int:
    return int(text, 16)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite yetibig",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("info", help="header fields, counts and the class histogram")
    c.add_argument("archive", type=Path)
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_info)
    c = sub.add_parser(
        "list", help="every resource: key, class, size, flags, file offset of each copy"
    )
    c.add_argument("archive", type=Path)
    c.add_argument("--class", dest="class_id", type=hex_int, help="only this class id (hex)")
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_list)
    c = sub.add_parser("blob", help="resources by key into a folder, unpacked, header stripped")
    c.add_argument("archive", type=Path)
    c.add_argument("keys", nargs="+", help="resource keys (hex)")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--raw", action="store_true", help="the stored bytes as they are")
    c.set_defaults(run=cmd_blob)
    c = sub.add_parser("diff", help="two archives by key: only in A, only in B, size differs")
    c.add_argument("archive", type=Path)
    c.add_argument("other", type=Path)
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_diff)
    c = sub.add_parser("refs", help="unreferenced and referenced-but-absent keys, by class")
    c.add_argument("archive", type=Path)
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_refs)
    c = sub.add_parser(
        "check",
        help="the coverage proof; reads the whole archive, so run it under `heavy run`",
        description="Read every byte of the data in file order: no two regions overlap, gaps listed,"
        " every copy of a duplicated resource identical, every resource decoded. Reads the whole"
        " archive (gigabytes for a game's): run it under `heavy run`. Exit 1 when the proof fails;"
        " resources with unknown flags are reported, not failed.",
    )
    c.add_argument("archive", type=Path)
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_check)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        archive = read_archive((args.caller_cwd / args.archive).resolve())
        return args.run(args, archive)
    except (OSError, ValueError) as exc:
        print(f"yetibig: {args.archive}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
