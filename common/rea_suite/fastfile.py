"""IW engine fastfiles (.ff): the zone header, the zlib stream, the asset list, and the raw files,
string tables and localized strings in it, from the file alone.

  rea-suite fastfile info <file.ff> [--json]           header, sizes, blocks, assets by type
  rea-suite fastfile list <file.ff> [--json]           the assets found, by type and name
  rea-suite fastfile extract <file.ff> --out DIR [--type T]...
                                                       raw files and string tables as files,
                                                       localized strings as localize.json

A fastfile starts with an 8-byte magic and a version (12 bytes): `IWffu100` unsigned, `IWff0100`
signed, version 5 for Call of Duty 4 on the PC (IW3), little-endian; version 1, big-endian, is IW3
on the Xbox 360. After the header of an unsigned PC fastfile comes one zlib stream: the zone. The
zone opens with its sizes (`size`, `externalSize`, then one size per memory block; IW3 has nine:
temp, runtime, large runtime, physical runtime, virtual, large, physical, vertex, index), then the
asset list: the script strings (a count, a pointer, then the strings), the asset count and a
pointer to the assets, each a type and a pointer. A pointer of -1 (0xFFFFFFFF) means its data
follows in the stream, and every asset's data follows in list order.

The list gives every asset's type. Walking to one asset's data means reading every asset before it,
of every type, so this reader finds the three simple types by their shape in the stream instead,
each check strict (a -1 pointer where the data follows, a name of printable characters, a length
that ends on the terminating NUL), and says how many of each it found against the list's count:
- RawFile {name, len, buffer}: the name, then len bytes and a NUL;
- StringTable {name, columnCount, rowCount, values}: the name, rowCount x columnCount pointers,
  then the strings;
- LocalizeEntry {value, name}: the value, then the name (upper case, digits, underscores).
Images, models, materials and the rest are listed by type and count only.

Formats are behind `FORMATS` (one entry today, IW3 PC); a recognized fastfile no entry reads
(IW3 on the Xbox 360, a signed one, IW4 and later) is named and refused. The facts come from
OpenAssetTools' definitions (GPL-3.0, read as documentation, no code taken): ZoneConstantsIW3.h,
IW3.h, IW3_Assets.h. Checked on synthetic fastfiles (test_fastfile.py); not yet on the game's own
files (the opt-in test reads them, REA_FASTFILE_SAMPLE).
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import struct
import sys
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rea_suite.rmdp import safe_name
from rea_suite.text import printable

FOLLOWS = 0xFFFFFFFF
MAX_ZONE = 1 << 31  # an inflated zone larger than this is not one

IW3_ASSET_TYPES = (
    "xmodelpieces", "physpreset", "xanimparts", "xmodel", "material", "techniqueset", "image",
    "sound", "soundcurve", "loadedsound", "clipmap", "clipmap_pvs", "comworld", "gameworld_sp",
    "gameworld_mp", "map_ents", "gfxworld", "lightdef", "ui_map", "font", "menulist", "menu",
    "localize", "weapon", "snddriverglobals", "fx", "impactfx", "aitype", "mptype", "character",
    "xmodelalias", "rawfile", "stringtable",
)  # fmt: skip
IW3_BLOCKS = ("temp", "runtime", "large_runtime", "physical_runtime", "virtual", "large",
              "physical", "vertex", "index")  # fmt: skip
EXTRACTED = ("rawfile", "stringtable", "localize")


class FastfileError(ValueError):
    pass


@dataclass
class Found:
    """One asset found in the stream: its type, name and content."""

    type: str
    name: str
    offset: int  # in the inflated zone
    end: int = 0  # just past it
    data: bytes = b""  # a raw file's bytes
    rows: list[list[str]] = field(default_factory=list)  # a string table's
    value: str | None = ""  # a localized string's; None when it is a shared string (below)
    shared: int | None = None  # an encoded pointer to an earlier string, for a name or value


@dataclass
class Zone:
    game: str
    platform: str
    magic: str
    version: int
    compressed: int  # bytes of the zlib stream
    size: int
    external_size: int
    blocks: dict[str, int]
    strings: list[str]
    assets: list[str]  # the type of each, in list order
    data_offset: int  # where the assets' data starts in the zone
    found: list[Found]
    zone_bytes: int
    zone: bytes = field(default=b"", repr=False)  # the inflated zone, for --debug

    def counts(self) -> Counter:
        return Counter(self.assets)

    def found_counts(self) -> Counter:
        return Counter(f.type for f in self.found)

    def as_json(self) -> dict:
        found = self.found_counts()
        return {
            "game": self.game, "platform": self.platform, "magic": self.magic,
            "version": self.version, "compressed": self.compressed, "zone": self.zone_bytes,
            "size": self.size, "external_size": self.external_size, "blocks": self.blocks,
            "script_strings": len(self.strings), "assets": len(self.assets),
            "by_type": {t: {"listed": n, **({"found": found[t]} if t in EXTRACTED else {})}
                        for t, n in sorted(self.counts().items())},
        }  # fmt: skip


# --- the formats ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Format:
    game: str
    platform: str
    magic: bytes
    version: int
    endian: str  # "<" or ">"
    read: object | None  # (data) -> Zone; None: recognized, not read yet


def recognize(head: bytes) -> Format:
    if len(head) < 12 or not head.startswith(b"IWff"):
        raise FastfileError("not an IW fastfile (no IWff magic)")
    magic = head[:8]
    for fmt in FORMATS:
        endian = fmt.endian
        if magic == fmt.magic and struct.unpack(endian + "I", head[8:12])[0] == fmt.version:
            return fmt
    little, big = struct.unpack("<I", head[8:12])[0], struct.unpack(">I", head[8:12])[0]
    raise FastfileError(
        f"a fastfile this reader does not know: magic {magic!r}, version {little:#x} "
        f"(big-endian {big:#x}); IW3 PC is IWffu100 version 5"
    )


def read(data: bytes) -> Zone:
    fmt = recognize(data[:12])
    if fmt.read is None:
        raise FastfileError(
            f"{fmt.game} {fmt.platform} ({fmt.magic.decode()}, version {fmt.version}): not read yet"
        )
    return fmt.read(data, fmt)


def inflate(stream: bytes) -> bytes:
    d = zlib.decompressobj()
    try:
        out = d.decompress(stream, MAX_ZONE)
    except zlib.error as exc:
        raise FastfileError(f"the zone's zlib stream: {exc}") from None
    if d.unconsumed_tail:
        raise FastfileError("the zone is larger than this reader takes (2 GiB)")
    return out


def read_iw3_pc(data: bytes, fmt: Format) -> Zone:
    zone = inflate(data[12:])
    u32 = lambda at: struct.unpack_from("<I", zone, at)[0]
    head = 8 + 4 * len(IW3_BLOCKS)
    if len(zone) < head + 16:
        raise FastfileError(f"the zone is {len(zone)} bytes: too short for its header")
    size, external = u32(0), u32(4)
    blocks = {name: u32(8 + 4 * i) for i, name in enumerate(IW3_BLOCKS)}
    at = head
    string_count, strings_ptr, asset_count, assets_ptr = struct.unpack_from("<IIII", zone, at)
    at += 16
    if string_count > 1 << 20 or asset_count > 1 << 20:
        raise FastfileError(f"implausible counts: {string_count} strings, {asset_count} assets")
    strings: list[str] = []
    if string_count and strings_ptr == FOLLOWS:
        pointers = struct.unpack_from(f"<{string_count}I", zone, at)
        at += 4 * string_count
        for pointer in pointers:
            if pointer != FOLLOWS:
                strings.append("")
                continue
            end = zone.index(b"\0", at)
            strings.append(zone[at:end].decode("latin-1"))
            at = end + 1
    assets: list[str] = []
    if asset_count and assets_ptr == FOLLOWS:
        # right after the last string, unaligned (cod4's real zones, 2026-11-15)
        for i in range(asset_count):
            kind = u32(at + 8 * i)
            assets.append(IW3_ASSET_TYPES[kind] if kind < len(IW3_ASSET_TYPES) else f"type{kind}")
        at += 8 * asset_count
    wanted = Counter(assets)
    found = scan(zone, at, wanted, list(blocks.values()))
    return Zone(fmt.game, fmt.platform, fmt.magic.decode(), fmt.version, len(data) - 12, size, external,
                blocks, strings, assets, at, found, len(zone), zone)  # fmt: skip


FORMATS: tuple[Format, ...] = (
    Format("IW3", "pc", b"IWffu100", 5, "<", read_iw3_pc),
    Format("IW3", "pc (signed)", b"IWff0100", 5, "<", None),
    Format("IW3", "xbox360", b"IWffu100", 1, ">", None),
    Format("IW3", "xbox360 (signed)", b"IWff0100", 1, ">", None),
)


# --- finding the simple assets ------------------------------------------------------------------

NAME = re.compile(rb"[\x21-\x7e][\x20-\x7e]{0,254}\0")
# a raw file's name: a relative path of two characters or more (a table of {u32, -1} pairs has
# the raw file's shape with the number 47 as the name "/": cod4's zones, 2026-11-15)
RAWFILE_NAME = re.compile(rb"[A-Za-z0-9_.][A-Za-z0-9_./\-]{1,254}\0")
LOCALIZE_NAME = re.compile(rb"[A-Z0-9_]{2,128}\0")
FF4 = b"\xff\xff\xff\xff"


def cstring(zone: bytes, at: int, pattern: re.Pattern = NAME) -> tuple[str, int] | None:
    match = pattern.match(zone, at)
    if match is None:
        return None
    return zone[at : match.end() - 1].decode("latin-1"), match.end()


def text_at(zone: bytes, at: int, limit: int = 1 << 20) -> tuple[str, int] | None:
    end = zone.find(b"\0", at, at + limit)
    if end < 0:
        return None
    raw = zone[at:end]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        value = raw.decode("cp1252", errors="replace")  # the game's English text is cp1252 (©)
    if any(ord(c) < 32 and c not in "\t\n\r" for c in value):
        return None
    return value, end + 1


def encoded(pointer: int, blocks: list[int]) -> bool:
    """A pointer to data already loaded: the block in the top four bits, the offset plus one
    below, inside the block's size from the zone header (a localized value 0x4000659E: block 4)."""
    block, offset = pointer >> 28, (pointer & 0x0FFFFFFF) - 1
    return pointer != FOLLOWS and block < len(blocks) and 0 <= offset < blocks[block]


def scan(zone: bytes, start: int, wanted: Counter, blocks: list[int] | None = None) -> list[Found]:
    """The raw files, string tables and localized strings in the zone from start, by shape.
    With the zone's block sizes, also the ones whose name or value is a shared string (an
    encoded pointer where -1 would be): their -1 comes 4 or 8 bytes into the struct."""
    found: list[Found] = []
    n = len(zone)
    last = start
    at = zone.find(FF4, start)
    while 0 <= at <= n - 12:
        hit = None
        if blocks:
            hit = shared_shape(zone, at, wanted, blocks, last)
            if hit is not None:
                item, end = hit
                item.end = end
                found.append(item)
                last = end
                at = zone.find(FF4, end)
                continue
        a, b, c = struct.unpack_from("<III", zone, at)
        if wanted["rawfile"] and a == FOLLOWS and c == FOLLOWS and 0 <= b < n:
            hit = rawfile(zone, at, b)
        if hit is None and wanted["stringtable"] and a == FOLLOWS and at + 16 <= n:
            hit = stringtable(zone, at)
        if hit is None and wanted["localize"] and a == FOLLOWS and b == FOLLOWS:
            hit = localize(zone, at)
        if hit is not None:
            item, end = hit
            item.end = end
            found.append(item)
            last = end
            at = zone.find(FF4, end)
        else:
            at = zone.find(FF4, at + 1)
    return found


def shared_shape(
    zone: bytes, ff: int, wanted: Counter, blocks: list[int], last: int
) -> tuple[Found, int] | None:
    """A localized string {shared value, -1, name} whose -1 is at ff, or a raw file {shared name,
    len, -1, buffer} whose -1 is at ff; never starting before the last asset's end."""
    if wanted["localize"] and ff - 4 >= last:
        value = struct.unpack_from("<I", zone, ff - 4)[0]
        if encoded(value, blocks):
            name = cstring(zone, ff + 4, LOCALIZE_NAME)
            if name is not None:
                return Found("localize", name[0], ff - 4, value=None, shared=value), name[1]
    if wanted["rawfile"] and ff - 8 >= last:
        pointer, length = struct.unpack_from("<II", zone, ff - 8)
        end = ff + 4 + length
        if encoded(pointer, blocks) and 0 < length and end < len(zone) and zone[end] == 0:
            data = zone[ff + 4 : end]
            text = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
            if text >= 0.95 * len(data) and b"\0" not in data:
                name = f"shared-name-{ff - 8:08x}.txt"  # the name is an earlier string's
                return Found("rawfile", name, ff - 8, data=data, shared=pointer), end + 1
    return None


def rawfile(zone: bytes, at: int, length: int) -> tuple[Found, int] | None:
    name = cstring(zone, at + 12, RAWFILE_NAME)
    if name is None:
        return None
    text, data_at = name
    end = data_at + length
    if end >= len(zone) or zone[end] != 0 or "." not in text and "/" not in text:
        return None
    return Found("rawfile", text, at, data=zone[data_at:end]), end + 1


def stringtable(zone: bytes, at: int) -> tuple[Found, int] | None:
    columns, rows, values = struct.unpack_from("<III", zone, at + 4)
    if values != FOLLOWS or not 0 < columns <= 1024 or not 0 < rows <= 1 << 20:
        return None
    name = cstring(zone, at + 16)
    if name is None or not name[0].lower().endswith(".csv"):
        return None
    text, cells_at = name
    count = columns * rows
    if cells_at + 4 * count > len(zone):
        return None
    pointers = struct.unpack_from(f"<{count}I", zone, cells_at)
    if any(p != FOLLOWS for p in pointers):
        return None
    pos = cells_at + 4 * count
    cells = []
    for _ in range(count):
        cell = text_at(zone, pos, 1 << 16)
        if cell is None:
            return None
        cells.append(cell[0])
        pos = cell[1]
    table = [cells[r * columns : (r + 1) * columns] for r in range(rows)]
    return Found("stringtable", text, at, rows=table), pos


def localize(zone: bytes, at: int) -> tuple[Found, int] | None:
    value = text_at(zone, at + 8, 1 << 16)
    if value is None:
        return None
    name = cstring(zone, value[1], LOCALIZE_NAME)
    if name is None:
        return None
    return Found("localize", name[0], at, value=value[0]), name[1]


# --- extraction --------------------------------------------------------------------------------


def out_path(root: Path, name: str) -> Path:
    """A name from the fastfile as a path under root: each part made safe, `..` and empty ones
    dropped, so nothing lands outside root."""
    parts = [safe_name(p) for p in re.split(r"[\\/]+", name) if p not in ("", ".", "..")]
    path = root.joinpath(*(parts or ["unnamed"]))
    if not path.resolve().is_relative_to(root.resolve()):
        raise FastfileError(f"{printable(name)}: would land outside {root}")
    return path


def extract(zone: Zone, root: Path, types: set[str]) -> dict[str, int]:
    written: Counter = Counter()
    localized: dict[str, str | None] = {}
    for item in zone.found:
        if item.type not in types:
            continue
        if item.type == "localize":
            localized[item.name] = item.value  # None: a shared string, not resolved
            continue
        path = out_path(root, item.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if item.type == "rawfile":
            path.write_bytes(item.data)
        else:
            path.write_text(
                "".join(",".join(csv_cell(c) for c in row) + "\n" for row in item.rows),
                encoding="utf-8",
            )
        written[item.type] += 1
    if localized:
        root.mkdir(parents=True, exist_ok=True)
        (root / "localize.json").write_text(
            json.dumps(localized, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        written["localize"] = len(localized)
    return dict(written)


def runs(kinds: list[str], kind: str) -> int:
    """How many runs of consecutive entries of kind the asset list has."""
    return sum(1 for i, k in enumerate(kinds) if k == kind and (i == 0 or kinds[i - 1] != kind))


def debug_lines(zone: Zone, dump: int = 64) -> list[str]:
    """Where each found asset of the read types lies, and the gaps between consecutive ones: the
    list holds a type in `runs` runs, so a type has runs - 1 gaps where other assets lie between,
    and any more mark one it did not find; the gap's first bytes show its shape."""
    lines = []
    for kind in EXTRACTED:
        items = sorted((f for f in zone.found if f.type == kind), key=lambda f: f.offset)
        listed = zone.counts()[kind]
        if not listed:
            continue
        lines.append(
            f"{kind}: {len(items)} found of {listed} listed, in {runs(zone.assets, kind)} run(s) of the list"
        )
        for f in items:
            lines.append(f"  {f.offset:#010x}-{f.end:#010x}  {printable(f.name)}")
        gaps = [(b.offset - a.end, a, b) for a, b in itertools.pairwise(items) if b.offset > a.end]
        for size, a, b in sorted(gaps, key=lambda g: g[0]):
            lines.append(
                f"  gap of {size:#x} bytes at {a.end:#010x}, between {printable(a.name)} and {printable(b.name)}:"
            )
            lines.append("    " + zone.zone[a.end : a.end + min(size, dump)].hex(" "))
    return lines


def csv_cell(value: str) -> str:
    return '"' + value.replace('"', '""') + '"' if any(c in value for c in ',"\n') else value


# --- command line ------------------------------------------------------------------------------


def info_lines(zone: Zone) -> list[str]:
    lines = [
        f"{zone.game} {zone.platform}: {zone.magic} version {zone.version}",
        (
            f"zlib stream {zone.compressed:,} bytes -> zone {zone.zone_bytes:,} bytes "
            f"(size {zone.size:,}, external {zone.external_size:,})"
        ),
        "blocks: " + ", ".join(f"{k} {v:,}" for k, v in zone.blocks.items()),
        f"{len(zone.strings)} script strings, {len(zone.assets)} assets:",
    ]
    found = zone.found_counts()
    for kind, count in sorted(zone.counts().items(), key=lambda kv: (-kv[1], kv[0])):
        note = f" ({found[kind]} found)" if kind in EXTRACTED else ""
        lines.append(f"  {kind:18s} {count:6d}{note}")
    return lines


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rea-suite fastfile", description=__doc__.split("\n\n")[0])
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    for name, help in (("info", "header, sizes, blocks, assets by type"), ("list", "the assets found"),
                       ("extract", "raw files, string tables, localized strings")):  # fmt: skip
        c = sub.add_parser(name, help=help)
        c.add_argument("file", type=Path)
        c.add_argument("--json", action="store_true")
        if name == "list":
            c.add_argument(
                "--debug",
                action="store_true",
                help="offsets, and the gaps where an unfound asset may lie, in hex",
            )
        if name == "extract":
            c.add_argument("--out", type=Path, required=True)
            c.add_argument(
                "--type", action="append", choices=EXTRACTED, help="only these; repeatable"
            )
    args = p.parse_args(argv)
    try:
        zone = read((args.caller_cwd / args.file).read_bytes())
    except (OSError, FastfileError) as exc:
        print(f"fastfile: {exc}", file=sys.stderr)
        return 2
    if args.command == "info":
        print(json.dumps(zone.as_json(), indent=1) if args.json else "\n".join(info_lines(zone)))
    elif args.command == "list":
        rows = [
            {"type": f.type, "name": f.name, "offset": f"{f.offset:#x}", "end": f"{f.end:#x}"}
            for f in zone.found
        ]
        if args.debug:
            print("\n".join(debug_lines(zone)))
        elif args.json:
            print(json.dumps(rows, indent=1))
        else:
            for row in rows:
                print(f"{row['type']:12s} {printable(row['name'])}")
            listed, found = zone.counts(), zone.found_counts()
            for kind in EXTRACTED:
                if listed[kind] != found[kind]:
                    print(f"{kind}: {found[kind]} of {listed[kind]} found", file=sys.stderr)
    else:
        try:
            written = extract(zone, args.caller_cwd / args.out, set(args.type or EXTRACTED))
        except (OSError, FastfileError) as exc:
            print(f"fastfile: {exc}", file=sys.stderr)
            return 2
        print(
            json.dumps(written)
            if args.json
            else ", ".join(f"{n} {k}" for k, n in written.items()) or "nothing"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
