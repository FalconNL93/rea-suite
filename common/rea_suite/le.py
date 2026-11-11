"""Linear executables (LE and LX): DOS extender programs such as Watcom's DOS/4GW games, VxDs, OS/2.

  rea-suite le info <exe> [--json]           the MZ stub and its extender, the LE/LX header, the
                                             object table, fixup counts by kind, the entry point,
                                             the imported modules
  rea-suite le dump-object <exe> <n> --base ADDR --out FILE [--object-base M=ADDR ...]
                                             object n's bytes with its internal 32-bit fixups
                                             applied as if loaded at ADDR, to load raw elsewhere
  rea-suite le dump-image <exe> --out FILE [--base ADDR] [--json-map MAP]
                                             every object at its base in one flat image (gaps
                                             zeroed) with fixups applied, and a map of it

Read only: the executable is never written. Every offset the file names is checked against the file,
so a damaged one is refused with LeError rather than read past its end. Written from IBM's
"LX - Linear eXecutable Module Format Description" (1992, the EDM2 reprint) and the LE/LX structures
in Open Watcom's bld/watcom/h/exeflat.h (le_map_entry, object_record, the OSF_* constants); no code
of either is used. docs/PORT-TOOLS.md has the layout and what dump-object leaves out.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

CPU = {1: "80286", 2: "80386", 3: "80486", 4: "Pentium"}
OS = {0: "unknown", 1: "OS/2", 2: "Windows", 3: "DOS 4.x", 4: "Windows 386 (VxD)"}
OBJECT_FLAGS = [
    (0x0008, "resource"),
    (0x0010, "discardable"),
    (0x0020, "shared"),
    (0x0040, "preload"),
    (0x0080, "invalid-pages"),
    (0x0100, "zero-fill"),
    (0x1000, "alias-16:16"),
    (0x4000, "conforming"),
    (0x8000, "iopl"),
]
RESIDENT = {0x200: "resident", 0x300: "resident-contiguous", 0x400: "resident-long-lockable"}
MODULE_TYPES = {
    0x00000: "program",
    0x08000: "library",
    0x18000: "protected-memory library",
    0x20000: "physical device driver",
    0x28000: "virtual device driver",
}
SOURCE = {
    0x0: "8-bit",
    0x2: "16-bit selector",
    0x3: "16:16 pointer",
    0x5: "16-bit offset",
    0x6: "16:32 pointer",
    0x7: "32-bit offset",
    0x8: "32-bit self-relative",
}
TARGET = {0: "internal", 1: "import by ordinal", 2: "import by name", 3: "internal via entry"}
PAGE_FLAGS = {
    0: "legal",
    1: "iterated",
    2: "invalid",
    3: "zero-filled",
    4: "range",
    5: "compressed",
}
# Strings that name the extender in its stub; the first match wins.
EXTENDERS = [
    (b"DOS/32A", "DOS/32 Advanced"),
    (b"PMODE/W", "PMODE/W"),
    (b"CauseWay", "CauseWay"),
    (b"WDOSX", "WDOSX"),
    (b"Rational Systems", "DOS/4G(W), bound"),
    (b"DOS4GPATH", "DOS/4GW stub (starts DOS4GW.EXE)"),
    (b"DOS/4G", "DOS/4G(W)"),
]
MAX_OBJECTS = 4096
MAX_PAGES = 1 << 20


class LeError(ValueError):
    """Not an LE or LX executable, or one this reader cannot or will not read."""


class Reader:
    """Little-endian reads that refuse to leave the buffer."""

    def __init__(self, data: bytes):
        self.data = data

    def check(self, offset: int, size: int) -> int:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise LeError(f"offset 0x{offset:x}+{size} is outside the {len(self.data)}-byte file")
        return offset

    def u8(self, offset: int) -> int:
        return self.data[self.check(offset, 1)]

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, self.check(offset, 2))[0]

    def s16(self, offset: int) -> int:
        return struct.unpack_from("<h", self.data, self.check(offset, 2))[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, self.check(offset, 4))[0]

    def bytes(self, offset: int, size: int) -> bytes:
        return self.data[self.check(offset, size) : offset + size]

    def names(self, offset: int, limit: int | None = None) -> list[bytes]:
        """Length-prefixed names until a zero length, or `limit` of them."""
        out = []
        while limit is None or len(out) < limit:
            size = self.u8(offset)
            if size == 0 and limit is None:
                break
            out.append(self.bytes(offset + 1, size))
            offset += 1 + size
        return out


@dataclass
class Stub:
    size: int  # bytes before the LE/LX header
    image: int  # bytes of the MZ image (its pages)
    header: int  # bytes of the MZ header
    entry: str  # CS:IP
    stack: str  # SS:SP
    extender: str | None


@dataclass
class Page:
    number: int  # 1-based, as fixups and objects count them
    offset: int  # in the file
    size: int  # bytes stored in the file
    flags: int


@dataclass
class Object:
    number: int  # 1-based
    size: int
    base: int
    flags: int
    first_page: int  # 1-based index in the page table
    pages: int

    @property
    def bits(self) -> int:
        return 32 if self.flags & 0x2000 else 16

    @property
    def access(self) -> str:
        return "".join(c if self.flags & bit else "-" for bit, c in ((1, "r"), (2, "w"), (4, "x")))

    @property
    def flag_names(self) -> list[str]:
        names = [name for bit, name in OBJECT_FLAGS if self.flags & bit]
        if self.flags & 0x700 in RESIDENT:
            names.append(RESIDENT[self.flags & 0x700])
        return names


@dataclass
class Fixup:
    page: int  # 1-based page it is listed under
    offsets: list[
        int
    ]  # source offsets in that page (may be negative: it starts on the page before)
    source: int  # source type (low nibble of the first byte)
    alias: bool
    target: int  # target kind (low two bits of the flags)
    object: int = 0  # internal: target object; imports: module ordinal; via entry: unused
    offset: int = 0  # internal: target offset; import by ordinal: ordinal; by name: name offset
    entry: int = 0  # via entry: entry ordinal
    additive: int = 0

    @property
    def kind(self) -> str:
        return f"{SOURCE.get(self.source, f'type {self.source}')}, {TARGET[self.target]}"


@dataclass
class Module:
    path: Path
    data: bytes
    format: str  # "LE" or "LX"
    offset: int  # of the LE/LX header in the file
    stub: Stub
    header: dict[str, int]
    objects: list[Object]
    pages: list[Page]
    fixups: list[Fixup]
    entries: dict[int, tuple[int, int]]  # ordinal -> (object, offset)
    imports: list[str]
    name: str | None
    problems: list[str] = field(default_factory=list)

    def entry_point(self) -> dict | None:
        number, eip = self.header["eip_object"], self.header["eip"]
        if not 1 <= number <= len(self.objects):
            return None
        return {
            "object": number,
            "offset": eip,
            "address": self.objects[number - 1].base + eip,
        }


HEADER = [
    # name, offset, size
    ("byte_order", 0x02, 1),
    ("word_order", 0x03, 1),
    ("format_level", 0x04, 4),
    ("cpu", 0x08, 2),
    ("os", 0x0A, 2),
    ("module_version", 0x0C, 4),
    ("module_flags", 0x10, 4),
    ("pages", 0x14, 4),
    ("eip_object", 0x18, 4),
    ("eip", 0x1C, 4),
    ("esp_object", 0x20, 4),
    ("esp", 0x24, 4),
    ("page_size", 0x28, 4),
    ("last_page_or_shift", 0x2C, 4),  # LE: bytes on the last page; LX: page offset shift
    ("fixup_size", 0x30, 4),
    ("loader_size", 0x38, 4),
    ("object_table", 0x40, 4),
    ("objects", 0x44, 4),
    ("page_table", 0x48, 4),
    ("iterated_pages", 0x4C, 4),
    ("resource_table", 0x50, 4),
    ("resources", 0x54, 4),
    ("resident_names", 0x58, 4),
    ("entry_table", 0x5C, 4),
    ("fixup_page_table", 0x68, 4),
    ("fixup_record_table", 0x6C, 4),
    ("import_modules", 0x70, 4),
    ("import_module_count", 0x74, 4),
    ("import_procs", 0x78, 4),
    ("data_pages", 0x80, 4),  # from the start of the file, as the non-resident names
    ("preload_pages", 0x84, 4),
    ("nonresident_names", 0x88, 4),
    ("nonresident_size", 0x8C, 4),
    ("auto_data_object", 0x94, 4),
    ("heap_size", 0xA8, 4),
]


def find_header(r: Reader) -> int:
    """Where the LE/LX header starts: at the MZ header's e_lfanew (0x3C), as a 4GW stub or a VxD has
    it, or after the MZ image, as an extender bound in front of the program (DOS/4GW, PMODE/W) has it."""
    if r.bytes(0, 2) not in (b"MZ", b"ZM"):
        raise LeError("no MZ header")
    if len(r.data) >= 0x40:
        lfanew = r.u32(0x3C)
        if 0x40 <= lfanew <= len(r.data) - 0xB0 and r.bytes(lfanew, 2) in (b"LE", b"LX"):
            return lfanew
    at = 0
    for _ in range(8):  # bound extenders may chain a few MZ images
        last, pages = r.u16(at + 2), r.u16(at + 4)
        at += pages * 512 - ((512 - last) if last else 0)
        if at + 2 > len(r.data):
            break
        sig = r.bytes(at, 2)
        if sig in (b"LE", b"LX"):
            return at
        if sig not in (b"MZ", b"ZM"):
            break
    raise LeError("no LE or LX header after the MZ stub")


def read_stub(r: Reader, offset: int) -> Stub:
    last, pages, _relocs, paragraphs = struct.unpack_from("<4H", r.data, 2)
    ss, sp, _sum, ip, cs = struct.unpack_from("<5H", r.data, 0x0E)
    image = pages * 512 - ((512 - last) if last else 0)
    stub = r.data[:offset]
    extender = next((name for key, name in EXTENDERS if key in stub), None)
    return Stub(
        offset, image, paragraphs * 16, f"{cs:04x}:{ip:04x}", f"{ss:04x}:{sp:04x}", extender
    )


def read_module(path: Path) -> Module:
    r = Reader(path.read_bytes())
    at = find_header(r)
    fmt = r.bytes(at, 2).decode()
    r.check(at, 0xB0)
    h = {name: (r.u8, r.u16, None, r.u32)[size - 1](at + off) for name, off, size in HEADER}
    if h["byte_order"] or h["word_order"]:
        raise LeError("big-endian modules are not supported")
    if not 0 < h["objects"] <= MAX_OBJECTS or h["pages"] > MAX_PAGES:
        raise LeError(f"{h['objects']} objects, {h['pages']} pages: not a module this reads")
    if fmt == "LE" and h["page_size"] == 0:
        raise LeError("page size 0")
    problems: list[str] = []

    objects = []
    for i in range(h["objects"]):
        size, base, flags, first, count, _ = struct.unpack_from(
            "<6I", r.data, r.check(at + h["object_table"] + 24 * i, 24)
        )
        objects.append(Object(i + 1, size, base, flags, first, count))

    pages = []
    for i in range(h["pages"]):
        if fmt == "LE":
            e = r.bytes(at + h["page_table"] + 4 * i, 4)
            # le_map_entry: a 24-bit page number, high byte first, then the flags.
            number = (e[0] << 16) | (e[1] << 8) | e[2]
            flags = e[3]
            offset = h["data_pages"] + (number - 1) * h["page_size"] if number else 0
            size = h["page_size"]
            if i == h["pages"] - 1 and h["last_page_or_shift"]:
                size = h["last_page_or_shift"]
        else:
            data_offset, size, flags = struct.unpack_from(
                "<IHH", r.data, r.check(at + h["page_table"] + 8 * i, 8)
            )
            offset = h["data_pages"] + (data_offset << h["last_page_or_shift"])
            number = i + 1
        if flags == 0 and size and offset + size > len(r.data):
            problems.append(f"page {i + 1} lies past the end of the file")
        pages.append(Page(number, offset, size, flags))

    for o in objects:
        if o.pages and (o.first_page < 1 or o.first_page + o.pages - 1 > len(pages)):
            raise LeError(f"object {o.number} names pages outside the page table")

    fixups = read_fixups(r, at, h, problems)
    entries = read_entries(r, at + h["entry_table"]) if h["entry_table"] else {}
    imports = []
    if h["import_modules"]:
        names = r.names(at + h["import_modules"], h["import_module_count"])
        imports = [n.decode("latin-1") for n in names]
    name = None
    if h["resident_names"]:
        names = r.names(at + h["resident_names"])
        name = names[0].decode("latin-1") if names else None
    return Module(
        path,
        r.data,
        fmt,
        at,
        read_stub(r, at),
        h,
        objects,
        pages,
        fixups,
        entries,
        imports,
        name,
        problems,
    )


def read_fixups(r: Reader, at: int, h: dict[str, int], problems: list[str]) -> list[Fixup]:
    """Every fixup record, page by page. The fixup page table has one offset per page plus one more
    (the end), each into the fixup record table."""
    if not h["fixup_page_table"] or not h["fixup_record_table"]:
        return []
    table = at + h["fixup_page_table"]
    records = at + h["fixup_record_table"]
    starts = [r.u32(table + 4 * i) for i in range(h["pages"] + 1)]
    out = []
    for page in range(h["pages"]):
        p, end = records + starts[page], records + starts[page + 1]
        while p < end:
            try:
                fixup, p = read_fixup(r, p, page + 1)
            except LeError as exc:
                problems.append(f"page {page + 1}: fixup at 0x{p:x}: {exc}")
                break
            out.append(fixup)
        if p > end:
            problems.append(f"page {page + 1}: the last fixup runs past the page's records")
    return out


def read_fixup(r: Reader, p: int, page: int) -> tuple[Fixup, int]:
    src, flags = r.u8(p), r.u8(p + 1)
    p += 2
    listed = bool(src & 0x20)
    if listed:
        count, offsets = r.u8(p), []
        p += 1
    else:
        offsets, count = [r.s16(p)], 0
        p += 2
    source, target = src & 0x0F, flags & 0x03
    if source not in SOURCE:
        raise LeError(f"source type {source} is undefined")
    f = Fixup(page, offsets, source, bool(src & 0x10), target)

    def number() -> int:
        nonlocal p
        if flags & 0x40:
            value, p = r.u16(p), p + 2
        else:
            value, p = r.u8(p), p + 1
        return value

    def wide(flag: int) -> int:
        nonlocal p
        if flags & flag:
            value, p = r.u32(p), p + 4
        else:
            value, p = r.u16(p), p + 2
        return value

    if target == 0:
        f.object = number()
        if source != 0x2:  # a selector fixup has no target offset
            f.offset = wide(0x10)
    elif target == 1:
        f.object = number()
        if flags & 0x80:
            f.offset, p = r.u8(p), p + 1
        else:
            f.offset = wide(0x10)
    elif target == 2:
        f.object = number()
        f.offset = wide(0x10)
    else:
        f.entry = number()
    if flags & 0x04:
        f.additive = wide(0x20)
    if listed:
        f.offsets = [r.s16(p + 2 * i) for i in range(count)]
        p += 2 * count
    return f, p


def read_entries(r: Reader, p: int) -> dict[int, tuple[int, int]]:
    """Entry ordinals to (object, offset), from the entry table's bundles. Forwarders are left out:
    they name another module's entry, not an object here."""
    entries, ordinal = {}, 1
    sizes = {1: 3, 2: 5, 3: 5, 4: 7}
    while (count := r.u8(p)) != 0:
        kind = r.u8(p + 1) & 0x7F
        p += 2
        if kind == 0:
            ordinal += count
            continue
        if kind not in sizes:
            raise LeError(f"entry bundle type {kind} is undefined")
        obj, p = r.u16(p), p + 2
        for _ in range(count):
            if kind in (1, 2):
                entries[ordinal] = (obj, r.u16(p + 1))
            elif kind == 3:
                entries[ordinal] = (obj, r.u32(p + 1))
            p += sizes[kind]
            ordinal += 1
    return entries


# --- info -----------------------------------------------------------------------------------------


def fixup_counts(module: Module) -> dict[str, int]:
    """Fixups by kind, each record counted once per source offset it lists."""
    counts: dict[str, int] = {}
    for f in module.fixups:
        counts[f.kind] = counts.get(f.kind, 0) + len(f.offsets)
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def info(module: Module) -> dict:
    h = module.header
    flags = h["module_flags"]
    return {
        "file": str(module.path),
        "size": len(module.data),
        "stub": {
            "size": module.stub.size,
            "mz_image": module.stub.image,
            "mz_header": module.stub.header,
            "entry": module.stub.entry,
            "stack": module.stub.stack,
            "extender": module.stub.extender,
        },
        "header": {
            "format": module.format,
            "offset": module.offset,
            "cpu": CPU.get(h["cpu"], f"type {h['cpu']}"),
            "os": OS.get(h["os"], f"type {h['os']}"),
            "module_flags": flags,
            "module_type": MODULE_TYPES.get(flags & 0x38000, f"type 0x{flags & 0x38000:x}"),
            "internal_fixups_removed": bool(flags & 0x10),
            "name": module.name,
            "pages": h["pages"],
            "page_size": h["page_size"],
            **(
                {"last_page_size": h["last_page_or_shift"]}
                if module.format == "LE"
                else {"page_shift": h["last_page_or_shift"]}
            ),
            "data_pages": h["data_pages"],
            "fixup_size": h["fixup_size"],
            "loader_size": h["loader_size"],
            "stack": {"object": h["esp_object"], "offset": h["esp"]},
            "auto_data_object": h["auto_data_object"],
            "heap_size": h["heap_size"],
        },
        "objects": [
            {
                "number": o.number,
                "base": o.base,
                "size": o.size,
                "flags": o.flags,
                "bits": o.bits,
                "access": o.access,
                "flag_names": o.flag_names,
                "first_page": o.first_page,
                "pages": o.pages,
                "file_offset": module.pages[o.first_page - 1].offset if o.pages else None,
            }
            for o in module.objects
        ],
        "fixups": {"records": len(module.fixups), "by_kind": fixup_counts(module)},
        "entry_point": module.entry_point(),
        "entries": len(module.entries),
        "imports": module.imports,
        "problems": module.problems,
    }


def print_info(d: dict) -> None:
    s, h = d["stub"], d["header"]
    print(f"{d['file']}  {d['size']} bytes")
    print(
        f"MZ stub     {s['size']} bytes (image {s['mz_image']}, header {s['mz_header']}), "
        f"entry {s['entry']}, stack {s['stack']}"
    )
    print(f"extender    {s['extender'] or 'not identified'}")
    print(
        f"{h['format']} header   at 0x{h['offset']:x}: {h['cpu']}, {h['os']}, {h['module_type']}"
        + (f" '{h['name']}'" if h["name"] else "")
        + f", flags 0x{h['module_flags']:x}"
        + (", internal fixups removed" if h["internal_fixups_removed"] else "")
    )
    last = (
        f"last page {h['last_page_size']}"
        if "last_page_size" in h
        else f"page shift {h['page_shift']}"
    )
    print(
        f"pages       {h['pages']} of {h['page_size']} bytes ({last}), data at 0x{h['data_pages']:x}"
    )
    print(
        f"stack       object {h['stack']['object']} + 0x{h['stack']['offset']:x}, "
        f"auto data object {h['auto_data_object']}"
    )
    print("objects")
    print("   n  base        size        bits  rwx  pages       flags")
    for o in d["objects"]:
        pages = f"{o['first_page']}-{o['first_page'] + o['pages'] - 1}" if o["pages"] else "-"
        print(
            f"  {o['number']:2}  0x{o['base']:08x}  0x{o['size']:08x}  {o['bits']:4}  "
            f"{o['access']}  {pages:10}  0x{o['flags']:04x} {' '.join(o['flag_names'])}".rstrip()
        )
    print(f"fixups      {d['fixups']['records']} records")
    for kind, count in d["fixups"]["by_kind"].items():
        print(f"  {count:8}  {kind}")
    e = d["entry_point"]
    if e:
        print(f"entry point object {e['object']} + 0x{e['offset']:x} = 0x{e['address']:08x}")
    else:
        print("entry point none")
    print(f"entries     {d['entries']}")
    print(f"imports     {', '.join(d['imports']) if d['imports'] else 'none'}")
    for problem in d["problems"]:
        print(f"problem     {problem}")


# --- dump-object ----------------------------------------------------------------------------------


@dataclass
class Dump:
    data: bytearray
    applied: dict[str, int]
    skipped: dict[str, int]
    pages: dict[str, int]  # pages by how they were filled


def object_bytes(module: Module, obj: Object) -> tuple[bytearray, dict[str, int]]:
    """The object as loaded, before fixups: its pages, zeros for zero-filled pages and the tail."""
    page_size = module.header["page_size"]
    out = bytearray(max(obj.size, obj.pages * page_size))
    filled: dict[str, int] = {}
    for i in range(obj.pages):
        page = module.pages[obj.first_page - 1 + i]
        kind = PAGE_FLAGS.get(page.flags, f"type {page.flags}")
        filled[kind] = filled.get(kind, 0) + 1
        if page.flags != 0:
            continue  # zero-filled stays zero; iterated, compressed and invalid pages are not expanded
        size = min(page.size, page_size, max(0, len(module.data) - page.offset))
        out[i * page_size : i * page_size + size] = module.data[page.offset : page.offset + size]
    return out, filled


def dump_object(module: Module, number: int, bases: dict[int, int]) -> Dump:
    """Object `number` with its 32-bit offsets, 32-bit self-relative fixups and the offsets of 16:32
    pointers to internal targets applied, given each object's load address in `bases`."""
    if not 1 <= number <= len(module.objects):
        raise LeError(f"no object {number}; the module has {len(module.objects)}")
    obj = module.objects[number - 1]
    data, filled = object_bytes(module, obj)
    page_size = module.header["page_size"]
    first, last = obj.first_page, obj.first_page + obj.pages - 1
    applied: dict[str, int] = {}
    skipped: dict[str, int] = {}
    done: set[int] = set()

    def count(table: dict[str, int], key: str) -> None:
        table[key] = table.get(key, 0) + 1

    for f in module.fixups:
        if not first <= f.page <= last:
            continue
        target = None
        if f.target == 0:
            target = (f.object, f.offset)
        elif f.target == 3:
            target = module.entries.get(f.entry)
        for offset in f.offsets:
            at = (f.page - first) * page_size + offset
            if f.source not in (0x6, 0x7, 0x8) or f.alias:
                count(skipped, f.kind)
                continue
            if target is None or not 1 <= target[0] <= len(module.objects):
                count(skipped, f.kind)
                continue
            if at < 0:
                # A fixup that crosses a page boundary is listed under both pages, under the second
                # with a negative offset; on the object's first page that site is the object before.
                continue
            if at + 4 > len(data):
                count(skipped, f"{f.kind} (outside the object)")
                continue
            value = (bases[target[0]] + target[1] + f.additive) & 0xFFFFFFFF
            if f.source == 0x8:
                value = (value - (bases[number] + at + 4)) & 0xFFFFFFFF
            struct.pack_into("<I", data, at, value)
            if at not in done:
                done.add(at)
                count(applied, f.kind)
    return Dump(data[: obj.size], applied, skipped, filled)


def parse_address(text: str) -> int:
    return int(text, 0)


def load_bases(
    module: Module, number: int, base: int | None, overrides: list[str]
) -> dict[int, int]:
    """Each object's load address: the dumped object at `base`, the others moved by the same amount
    (so the module keeps its layout), unless --object-base names one."""
    if not 1 <= number <= len(module.objects):
        raise LeError(f"no object {number}; the module has {len(module.objects)}")
    delta = 0 if base is None else base - module.objects[number - 1].base
    bases = {o.number: (o.base + delta) & 0xFFFFFFFF for o in module.objects}
    for item in overrides:
        n, _, addr = item.partition("=")
        if not addr or not n.strip().isdigit():
            raise LeError(f"--object-base {item!r}: expected N=ADDRESS")
        if int(n) not in bases:
            raise LeError(f"--object-base {item!r}: no object {n}")
        bases[int(n)] = parse_address(addr)
    if base is not None:
        bases[number] = base
    return bases


@dataclass
class Image:
    data: bytearray
    base: int
    bases: dict[int, int]
    applied: dict[str, int]
    skipped: dict[str, int]
    pages: dict[str, int]


def dump_image(module: Module, base: int | None = None) -> Image:
    """Every object at its base in one buffer, from the lowest object base to the highest object end,
    the gaps zeros: what a loader that maps one file at one address needs to see the code and the
    data it addresses side by side. `base` moves the lowest object there and the rest with it."""
    lowest = min(module.objects, key=lambda o: o.base)
    bases = load_bases(module, lowest.number, base, [])
    start = bases[lowest.number]
    end = max(bases[o.number] + o.size for o in module.objects)
    if end - start > 1 << 30:
        raise LeError(f"the objects span 0x{end - start:x} bytes; dump them one by one")
    image = Image(bytearray(end - start), start, bases, {}, {}, {})
    for o in module.objects:
        dump = dump_object(module, o.number, bases)
        at = bases[o.number] - start
        image.data[at : at + len(dump.data)] = dump.data
        for total, part in (
            (image.applied, dump.applied),
            (image.skipped, dump.skipped),
            (image.pages, dump.pages),
        ):
            for kind, n in part.items():
                total[kind] = total.get(kind, 0) + n
    return image


def image_map(module: Module, image: Image) -> dict:
    entry = module.entry_point()
    if entry:
        entry["address"] = image.bases[entry["object"]] + entry["offset"]
    return {
        "file": str(module.path),
        "base": image.base,
        "size": len(image.data),
        "entry_point": entry,
        "objects": [
            {
                "number": o.number,
                "base": image.bases[o.number],
                "size": o.size,
                "image_offset": image.bases[o.number] - image.base,
                "bits": o.bits,
                "access": o.access,
            }
            for o in module.objects
        ],
        "fixups": {"applied": image.applied, "left": image.skipped},
        "pages": image.pages,
    }


# --- command line ---------------------------------------------------------------------------------


def cmd_info(args) -> int:
    module = read_module((args.caller_cwd / args.exe).resolve())
    d = info(module)
    if args.json:
        print(json.dumps(d, indent=1))
    else:
        print_info(d)
    return 0


def cmd_dump(args) -> int:
    exe = (args.caller_cwd / args.exe).resolve()
    out = (args.caller_cwd / args.out).resolve()
    if out == exe:
        print("le: the output would overwrite the executable; choose another", file=sys.stderr)
        return 2
    module = read_module(exe)
    bases = load_bases(module, args.object, args.base, args.object_base)
    dump = dump_object(module, args.object, bases)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dump.data)
    applied = sum(dump.applied.values())
    skipped = sum(dump.skipped.values())
    pages = ", ".join(f"{n} {kind}" for kind, n in dump.pages.items()) or "none"
    print(
        f"object {args.object}: 0x{len(dump.data):x} bytes at 0x{bases[args.object]:08x} to {out}; "
        f"pages: {pages}; {applied} fixups applied, {skipped} left",
        file=sys.stderr,
    )
    for kind, n in sorted(dump.skipped.items()):
        print(f"  left {n:6}  {kind}", file=sys.stderr)
    unexpanded = {k: n for k, n in dump.pages.items() if k not in ("legal", "zero-filled")}
    if unexpanded:
        print(f"le: pages left as zeros: {unexpanded}", file=sys.stderr)
    return 0


def cmd_image(args) -> int:
    exe = (args.caller_cwd / args.exe).resolve()
    out = (args.caller_cwd / args.out).resolve()
    json_map = (args.caller_cwd / args.json_map).resolve() if args.json_map else None
    if exe in (out, json_map):
        print("le: the output would overwrite the executable; choose another", file=sys.stderr)
        return 2
    module = read_module(exe)
    image = dump_image(module, args.base)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(image.data)
    m = image_map(module, image)
    if json_map:
        json_map.parent.mkdir(parents=True, exist_ok=True)
        json_map.write_text(json.dumps(m, indent=1) + "\n")
    print(
        f"image: 0x{len(image.data):x} bytes at 0x{image.base:08x} to {out}; "
        f"{sum(image.applied.values())} fixups applied, {sum(image.skipped.values())} left",
        file=sys.stderr,
    )
    for o in m["objects"]:
        print(
            f"  object {o['number']}  0x{o['base']:08x}  0x{o['size']:08x}  "
            f"{o['bits']}-bit {o['access']}  at +0x{o['image_offset']:x}",
            file=sys.stderr,
        )
    if m["entry_point"]:
        print(f"  entry point 0x{m['entry_point']['address']:08x}", file=sys.stderr)
    unexpanded = {k: n for k, n in image.pages.items() if k not in ("legal", "zero-filled")}
    if unexpanded:
        print(f"le: pages left as zeros: {unexpanded}", file=sys.stderr)
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite le",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("info", help="stub, header, objects, fixup counts, entry point, imports")
    c.add_argument("exe", type=Path)
    c.add_argument("--json", action="store_true")
    c.set_defaults(run=cmd_info)
    c = sub.add_parser("dump-object", help="an object's bytes with its internal fixups applied")
    c.add_argument("exe", type=Path)
    c.add_argument("object", type=int, help="object number, from 1 (as info lists them)")
    c.add_argument(
        "--base",
        type=parse_address,
        help="load address of the object (default: its relocation base from the object table)",
    )
    c.add_argument(
        "--object-base",
        action="append",
        default=[],
        metavar="N=ADDR",
        help="load address of another object its fixups point into (default: moved with --base)",
    )
    c.add_argument("--out", type=Path, required=True)
    c.set_defaults(run=cmd_dump)
    c = sub.add_parser(
        "dump-image", help="every object at its base in one flat image, fixups applied"
    )
    c.add_argument("exe", type=Path)
    c.add_argument(
        "--base",
        type=parse_address,
        help="load address of the lowest object (default: its relocation base); the rest move with it",
    )
    c.add_argument("--out", type=Path, required=True)
    c.add_argument(
        "--json-map", type=Path, help="write the map (objects, bases, entry) as JSON here"
    )
    c.set_defaults(run=cmd_image)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError) as exc:
        print(f"le: {args.exe}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
