"""PSP files from the file alone: EBOOT.PBP's sections and PARAM.SFO, a PRX's or ELF's module info
with its imported and exported NIDs, and the same from a UMD image (ISO or CSO). Ghidra analysis
is `rea-ghidra analyze` with ghidra-allegrex (component `psp`); the route is docs/PSP.md.

  rea-suite psp info  <file> [--names FILE] [--nid-source DIR] [-o JSON]
                                                        EBOOT.PBP, PRX/ELF, PARAM.SFO, ISO or CSO
  rea-suite psp nid   <name>...                         the NID of a function name
  rea-suite psp check                                   ghidra-allegrex in place for this Ghidra

An encrypted module (`~PSP`, as retail games ship) shows its outer header only: decrypt your own
copy first (docs/PSP.md, step 2). A NID is the first four bytes of the SHA-1 of the function's
name, little endian. Imports are named from PPSSPP's HLE tables (tool `ppsspp-source`, component
`psp`, pinned with PPSSPP), and from `--names`, a list of candidate names, one per line.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from rea_suite import extcheck
from rea_suite.nids import NidEntry, NidSource, NidTable

PBP_MAGIC = b"\0PBP"
PBP_SECTIONS = [
    "PARAM.SFO",
    "ICON0.PNG",
    "ICON1.PMF",
    "PIC0.PNG",
    "PIC1.PNG",
    "SND0.AT3",
    "DATA.PSP",
    "DATA.PSAR",
]
SFO_MAGIC = b"\0PSF"
PSP_MAGIC = b"~PSP"
ELF_MAGIC = b"\x7fELF"
ET_EXEC, ET_PRX = 2, 0xFFA0
EM_MIPS = 8
PT_LOAD = 1
MODULE_INFO_SECTION = ".rodata.sceModuleInfo"
MODULE_INFO = struct.Struct("<HBB28sIIIII")  # attribute, minor, major, name, gp, ent, ent_end, ...
KERNEL_MODULE = 0x1000
# The module's own exports, which every PRX has (PPSSPP's sceKernelModule.cpp names them).
SYSTEM_NIDS = {
    0xD632ACDB: "module_start",
    0xCEE8593C: "module_stop",
    0x2F064FA6: "module_reboot_before",
    0xADF12745: "module_reboot_phase",
    0xD3744BE0: "module_bootstart",
    0xF01D73A7: "module_info",
    0x0F7C276C: "module_start_thread_parameter",
    0xCF0CC697: "module_stop_thread_parameter",
    0xF4F4299D: "module_reboot_before_thread_parameter",
    0x11B97506: "module_sdk_version",
}
SECTOR = 2048
EXTENSION = "ghidra-allegrex"
# The files REA's PSP profile requires in the installed extension (GhidraPspExtension.js).
EXTENSION_FILES = [
    "Module.manifest",
    "data/languages/allegrex.ldefs",
    "data/languages/allegrex.sla",
    "data/languages/allegrex.pspec",
    "data/languages/allegrex.cspec",
]
FIX = "select component psp, then rea-suite setup"
ROOT = Path(__file__).resolve().parents[2]
MAX_ENTRIES = 4096


def hex32(value: int) -> str:
    return f"0x{value:08x}"


def nid(name: str) -> int:
    return struct.unpack("<I", hashlib.sha1(name.encode()).digest()[:4])[0]


def cstring(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


# --- PBP and PARAM.SFO -------------------------------------------------------------


def pbp_sections(data: bytes) -> list[tuple[str, int, int]]:
    """(name, offset, size) of each section of an EBOOT.PBP; empty ones included."""
    if len(data) < 0x28 or not data.startswith(PBP_MAGIC):
        raise ValueError("no \\0PBP magic: not an EBOOT.PBP")
    offsets = list(struct.unpack_from("<8I", data, 8)) + [len(data)]
    if offsets[0] < 0x28 or any(b < a for a, b in itertools.pairwise(offsets)):
        raise ValueError("PBP section offsets out of order or outside the file")
    return [(name, offsets[i], offsets[i + 1] - offsets[i]) for i, name in enumerate(PBP_SECTIONS)]


def parse_sfo(data: bytes) -> dict:
    """PARAM.SFO: keys with UTF-8 strings (format 0x0204, 0x0004) or 32-bit integers (0x0404)."""
    if len(data) < 0x14 or not data.startswith(SFO_MAGIC):
        raise ValueError("no \\0PSF magic: not a PARAM.SFO")
    _, keys, values, count = struct.unpack_from("<4I", data, 4)
    if count > MAX_ENTRIES or 0x14 + count * 16 > len(data):
        raise ValueError("PARAM.SFO entry table outside the file")
    found: dict[str, str | int] = {}
    for i in range(count):
        key_at, fmt, length, _, value_at = struct.unpack_from("<HHIII", data, 0x14 + i * 16)
        key = cstring(data[keys + key_at : keys + key_at + 128])
        raw = data[values + value_at : values + value_at + length]
        if len(raw) != length:
            raise ValueError(f"PARAM.SFO value of {key} outside the file")
        found[key] = struct.unpack("<I", raw[:4])[0] if fmt == 0x0404 else cstring(raw)
    return found


# --- modules -------------------------------------------------------------------


@dataclass
class Elf:
    data: bytes
    type: int
    flags: int
    entry: int
    segments: list[tuple[int, int, int, int, int]]  # type, offset, vaddr, paddr, filesz
    sections: dict[str, tuple[int, int, int]]  # name -> addr, offset, size

    def offset(self, address: int) -> int:
        for kind, offset, vaddr, _, filesz in self.segments:
            if kind == PT_LOAD and vaddr <= address < vaddr + filesz:
                return offset + address - vaddr
        raise ValueError(f"{hex32(address)} is in no loaded segment")

    def read(self, address: int, size: int) -> bytes:
        at = self.offset(address)
        if at + size > len(self.data):
            raise ValueError(f"{hex32(address)}+0x{size:x} lies outside the file")
        return self.data[at : at + size]

    def string(self, address: int) -> str:
        at = self.offset(address)
        return cstring(self.data[at : at + 256])


def parse_elf(data: bytes) -> Elf:
    if len(data) < 0x34 or not data.startswith(ELF_MAGIC):
        raise ValueError("no ELF magic")
    if data[4] != 1 or data[5] != 1:
        raise ValueError("not a 32-bit little-endian ELF")
    kind, machine, _, entry, phoff, shoff, flags, _, phsize, phnum, shsize, shnum, shstr = (
        struct.unpack_from("<HHIIIIIHHHHHH", data, 0x10)
    )
    if machine != EM_MIPS:
        raise ValueError(f"machine {machine} is not MIPS: not a PSP module")
    if phnum > 64 or phoff + phnum * 32 > len(data) or (phnum and phsize < 32):
        raise ValueError("program headers outside the file")
    segments = []
    for i in range(phnum):
        p_type, p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from(
            "<5I", data, phoff + i * phsize
        )
        segments.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz))
    sections: dict[str, tuple[int, int, int]] = {}
    if shnum and shoff and shoff + shnum * 40 <= len(data) and shsize >= 40 and shstr < shnum:
        heads = [struct.unpack_from("<10I", data, shoff + i * shsize) for i in range(shnum)]
        names_at = heads[shstr][4]
        for head in heads:
            name = cstring(data[names_at + head[0] : names_at + head[0] + 64])
            sections[name] = (head[3], head[4], head[5])
    return Elf(data, kind, flags, entry, segments, sections)


def module_info_offset(elf: Elf) -> int:
    """Where the module info is: its section, else the first segment's p_paddr (a file offset,
    the top bit set for kernel modules), as PPSSPP's ElfReader looks for it."""
    if MODULE_INFO_SECTION in elf.sections:
        return elf.sections[MODULE_INFO_SECTION][1]
    if elf.segments:
        return elf.segments[0][3] & 0x7FFFFFFF
    raise ValueError("no module info: neither its section nor a program header")


def tables(elf: Elf, start: int, end: int, minimum: int):
    """Walk a table of variable-size entries; each entry's byte 8 is its size in words."""
    if end < start or end - start > MAX_ENTRIES * 64:
        raise ValueError(f"table {hex32(start)}-{hex32(end)} is not a module table")
    at = start
    while at < end:
        head = elf.read(at, 4 * minimum)
        size = head[8] * 4
        if size < 4 * minimum:
            raise ValueError(f"entry at {hex32(at)} has size {size}")
        yield at, head
        at += size


def library_name(elf: Elf, address: int) -> str:
    return elf.string(address) if address else "(module)"


def named(value: int, names: dict[int, str]) -> dict:
    row = {"nid": hex32(value)}
    if value in names:
        row["name"] = names[value]
    return row


def module(data: bytes, names: dict[int, str] | None = None) -> dict:
    """An unencrypted ELF or PRX: header, module info, exports and imports by NID."""
    elf = parse_elf(data)
    names = {**SYSTEM_NIDS, **(names or {})}
    at = module_info_offset(elf)
    if at + MODULE_INFO.size > len(data):
        raise ValueError("module info lies outside the file")
    attr, minor, major, name, gp, ent, ent_end, stub, stub_end = MODULE_INFO.unpack_from(data, at)
    info = {
        "kind": {ET_EXEC: "elf", ET_PRX: "prx"}.get(elf.type, f"elf type 0x{elf.type:x}"),
        "flags": hex32(elf.flags),
        "entry": hex32(elf.entry),
        "segments": [
            {"type": t, "offset": f"0x{o:x}", "vaddr": hex32(v), "size": f"0x{s:x}"}
            for t, o, v, _, s in elf.segments
        ],
        "sections": sorted(n for n in elf.sections if n),
        "module": {
            "name": cstring(name),
            "version": f"{major}.{minor}",
            "attribute": f"0x{attr:04x}",
            "kernel": bool(attr & KERNEL_MODULE),
            "gp": hex32(gp),
        },
        "exports": [],
        "imports": [],
    }
    for address, head in tables(elf, ent, ent_end, 4):
        lib, version, attribute, _, variables, functions, table = struct.unpack_from(
            "<IHHBBHI", head
        )
        nids = struct.unpack(
            f"<{functions + variables}I", elf.read(table, 4 * (functions + variables))
        )
        info["exports"].append(
            {
                "library": library_name(elf, lib),
                "version": f"0x{version:04x}",
                "attribute": f"0x{attribute:04x}",
                "functions": [named(n, names) for n in nids[:functions]],
                "variables": [named(n, names) for n in nids[functions:]],
                "at": hex32(address),
            }
        )
    for address, head in tables(elf, stub, stub_end, 5):
        lib, version, attribute, _, variables, functions, nid_table, stubs = struct.unpack_from(
            "<IHHBBHII", head
        )
        nids = struct.unpack(f"<{functions}I", elf.read(nid_table, 4 * functions))
        info["imports"].append(
            {
                "library": library_name(elf, lib),
                "version": f"0x{version:04x}",
                "attribute": f"0x{attribute:04x}",
                "functions": [
                    {**named(n, names), "stub": hex32(stubs + 8 * i)} for i, n in enumerate(nids)
                ],
                "variables": variables,
                "at": hex32(address),
            }
        )
    unnamed = sum(1 for lib in info["imports"] for f in lib["functions"] if "name" not in f)
    info["unnamed_imports"] = unnamed
    return info


def encrypted(data: bytes) -> dict:
    """The outer header of an encrypted module (PPSSPP's PSP_Header): what it is, not its code."""
    if len(data) < 0x150:
        raise ValueError("too short for a ~PSP header")
    attribute, compressed = struct.unpack_from("<HH", data, 4)
    elf_size, psp_size = struct.unpack_from("<II", data, 0x28)
    (decrypt_mode,) = struct.unpack_from("<I", data, 0x7C)
    (tag,) = struct.unpack_from("<I", data, 0xD0)
    return {
        "kind": "encrypted",
        "module": {
            "name": cstring(data[0x0A:0x26]),
            "version": f"{data[9]}.{data[8]}",
            "attribute": f"0x{attribute:04x}",
            "kernel": bool(attribute & KERNEL_MODULE),
        },
        "compressed": bool(compressed & 1),
        "elf_size": elf_size,
        "psp_size": psp_size,
        "decrypt_mode": decrypt_mode,
        "tag": hex32(tag),
        "note": "encrypted: decrypt your own copy (docs/PSP.md, step 2), then run info on it",
    }


def executable(data: bytes, names: dict[int, str] | None = None) -> dict:
    if data.startswith(PSP_MAGIC):
        return encrypted(data)
    if data.startswith(ELF_MAGIC):
        return module(data, names)
    if not data.strip(b"\0"):
        return {"kind": "empty", "note": "all zero (many UMDs blank BOOT.BIN)"}
    raise ValueError("neither an ELF/PRX nor an encrypted ~PSP module")


def pbp(data: bytes, names: dict[int, str] | None = None) -> dict:
    found: dict = {"kind": "pbp", "version": hex32(struct.unpack_from("<I", data, 4)[0])}
    sections = pbp_sections(data)
    found["sections"] = [{"name": n, "offset": f"0x{o:x}", "size": s} for n, o, s in sections if s]
    parts = {n: data[o : o + s] for n, o, s in sections}
    if parts["PARAM.SFO"]:
        found["param_sfo"] = parse_sfo(parts["PARAM.SFO"])
    if parts["DATA.PSP"]:
        found["data_psp"] = executable(parts["DATA.PSP"], names)
    psar = parts["DATA.PSAR"]
    if psar.startswith((b"PSISOIMG", b"PSTITLEIMG")):
        found["data_psar"] = "a PS1 classic's disc image (POPS)"
    elif psar:
        found["data_psar"] = f"{len(psar)} bytes"
    return found


# --- UMD images ----------------------------------------------------------------


class Image(Protocol):
    """Random access to a UMD's 2048-byte sectors, whatever the container."""

    def read(self, offset: int, size: int) -> bytes: ...


class IsoImage:
    def __init__(self, f, size: int):
        self.f, self.size = f, size

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset + size > self.size:
            raise ValueError(f"0x{offset:x}+0x{size:x} lies outside the image")
        self.f.seek(offset)
        return self.f.read(size)


class CsoImage:
    """CISO v1 (`CISO`): blocks deflated without a zlib header, an index of block offsets whose
    top bit marks a block stored plain. CSO v2 and ZSO (LZ4) are not read here."""

    def __init__(self, f):
        self.f = f
        head = f.read(0x18)
        magic, header_size, total, block, version, align = struct.unpack("<4sIQIBB", head[:22])
        if magic != b"CISO" or version > 1 or not block or block % SECTOR:
            raise ValueError(f"CSO version {version} or block size {block}: only CSO v1 is read")
        self.total, self.block, self.align = total, block, align
        count = (total + block - 1) // block + 1
        if count > (1 << 24):
            raise ValueError("CSO index too large")
        f.seek(max(header_size, 0x18))
        self.index = struct.unpack(f"<{count}I", f.read(4 * count))

    def block_data(self, n: int) -> bytes:
        start, end = self.index[n], self.index[n + 1]
        at, stop = (start & 0x7FFFFFFF) << self.align, (end & 0x7FFFFFFF) << self.align
        self.f.seek(at)
        raw = self.f.read(stop - at)
        if start & 0x80000000:
            return raw[: self.block]
        return zlib.decompressobj(-15).decompress(raw, self.block)

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset + size > self.total:
            raise ValueError(f"0x{offset:x}+0x{size:x} lies outside the image")
        out = bytearray()
        while size:
            n, skip = divmod(offset, self.block)
            piece = self.block_data(n)[skip : skip + size]
            if not piece:
                raise ValueError(f"CSO block {n} is short")
            out += piece
            offset += len(piece)
            size -= len(piece)
        return bytes(out)


def iso_lookup(image: Image, path: str) -> tuple[int, int] | None:
    """(offset, size) of a file in an ISO 9660 image, by its path; None when absent."""
    pvd = image.read(16 * SECTOR, SECTOR)
    if pvd[1:6] != b"CD001":
        raise ValueError("no ISO 9660 volume descriptor")
    extent, size = struct.unpack_from("<I4xI", pvd, 156 + 2)
    for part in path.strip("/").split("/"):
        found = None
        data = image.read(extent * SECTOR, size)
        at = 0
        while at < len(data):
            length = data[at]
            if length == 0:  # records do not cross sectors: the rest of this one is padding
                at = (at // SECTOR + 1) * SECTOR
                continue
            name_len = data[at + 32]
            name = data[at + 33 : at + 33 + name_len].decode("ascii", "replace").split(";")[0]
            if name.upper() == part.upper():
                found = struct.unpack_from("<I4xI", data, at + 2)
                break
            at += length
        if found is None:
            return None
        extent, size = found
    return extent * SECTOR, size


def umd(image: Image, names: dict[int, str] | None = None) -> dict:
    found: dict = {"kind": "umd"}
    for key, path in (
        ("param_sfo", "PSP_GAME/PARAM.SFO"),
        ("eboot_bin", "PSP_GAME/SYSDIR/EBOOT.BIN"),
        ("boot_bin", "PSP_GAME/SYSDIR/BOOT.BIN"),
    ):
        where = iso_lookup(image, path)
        if where is None:
            continue
        data = image.read(*where)
        found[key] = parse_sfo(data) if key == "param_sfo" else executable(data, names)
    if len(found) == 1:
        raise ValueError("no PSP_GAME folder: not a PSP game UMD")
    return found


# --- the command -----------------------------------------------------------------


def info(path: Path, names: dict[int, str] | None = None) -> dict:
    with path.open("rb") as f:
        head = f.read(0x8800)
        if head.startswith(b"CISO"):
            f.seek(0)
            return umd(CsoImage(f), names)
        if head[0x8001:0x8006] == b"CD001":
            return umd(IsoImage(f, path.stat().st_size), names)
    data = path.read_bytes()
    if data.startswith(PBP_MAGIC):
        return pbp(data, names)
    if data.startswith(SFO_MAGIC):
        return {"kind": "sfo", "param_sfo": parse_sfo(data)}
    return executable(data, names)


# --- NID names ------------------------------------------------------------------


class PpssppSource:
    """PPSSPP's HLE tables (`Core/HLE/*.cpp`): every firmware function it implements or stubs,
    as `{0xNID, &Wrap..., "name", ...}` rows in an `HLEFunction` array that `RegisterHLEModule`
    registers under its library's name. Data only; never built."""

    TABLE = re.compile(r"HLEFunction\s+(\w+)\s*\[\]\s*=")
    ENTRY = re.compile(r'\{\s*0[xX]([0-9A-Fa-f]{8})\s*,[^"{}]*?"([^"]+)"')
    REGISTER = re.compile(r'RegisterHLEModule\(\s*"([^"]+)"\s*,[^;]*?,\s*(\w+)\s*\)')

    def __init__(self, root: Path):
        self.root = root
        self.hle = root / "Core" / "HLE"
        if not (self.hle / "HLETables.cpp").is_file():
            raise ValueError(f"{root} holds no PPSSPP source (Core/HLE/HLETables.cpp)")

    def describe(self) -> str:
        return f"PPSSPP source at {self.root}"

    def entries(self):
        for path in sorted(self.hle.glob("*.cpp")):
            text = path.read_text(errors="replace")
            libraries: dict[str, list[str]] = {}
            for library, table in self.REGISTER.findall(text):
                libraries.setdefault(table, []).append(library)
            for match in self.TABLE.finditer(text):
                end = text.find("};", match.end())
                block = text[match.end() : end if end >= 0 else len(text)]
                for library in libraries.get(match[1], [match[1]]):
                    for value, name in self.ENTRY.findall(block):
                        number = int(value, 16)
                        yield NidEntry(number, library, name, "function", nid(name) == number)


def default_source(explicit: Path | None) -> NidSource | None:
    """`--nid-source`, else REA_PSP_NID_SOURCE, else the installed tool; None when there is none."""
    root = explicit or (
        Path(os.environ["REA_PSP_NID_SOURCE"]) if os.environ.get("REA_PSP_NID_SOURCE") else None
    )
    if root is None:
        root = ROOT / "tools" / "ppsspp-source" / "current"
        if not root.exists():
            return None
    return PpssppSource(root)


def load_names(path: Path | None, source: NidSource | None = None) -> dict[int, str]:
    """NID -> name: the source's table, then your own candidate names, which win."""
    names: dict[int, str] = {}
    if source is not None:
        table = NidTable(source)
        names = {value: table.name(value) for value in table.by_nid}
    if path is not None:
        lines = (line.strip() for line in path.read_text().splitlines())
        names.update({nid(line): line for line in lines if line and not line.startswith("#")})
    return names


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite psp",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("info", help="EBOOT.PBP, PRX/ELF, PARAM.SFO, ISO or CSO as JSON")
    q.add_argument("file", type=Path)
    q.add_argument("--names", type=Path, help="candidate function names, one per line")
    q.add_argument(
        "--nid-source", type=Path, help="a PPSSPP source tree (default: tool ppsspp-source)"
    )
    q.add_argument("-o", "--output", type=Path)
    q = sub.add_parser("nid", help="the NID of each function name")
    q.add_argument("name", nargs="+")
    sub.add_parser("check", help="ghidra-allegrex in place for this Ghidra (files only)")
    args = p.parse_args(argv)
    if args.command == "check":
        return extcheck.check(EXTENSION, EXTENSION_FILES, FIX, "Allegrex, VFPU, PSP relocations")
    if args.command == "nid":
        for name in args.name:
            print(f"{hex32(nid(name))}\t{name}")
        return 0
    try:
        source = default_source(args.nid_source and (args.caller_cwd / args.nid_source).resolve())
        names = load_names(args.names and (args.caller_cwd / args.names).resolve(), source)
        found = info((args.caller_cwd / args.file).resolve(), names)
        found["nid_names"] = (
            source.describe()
            if source
            else ("PPSSPP's tables not installed (component psp); module and --names names only")
        )
    except (OSError, ValueError, struct.error, zlib.error) as exc:
        p.exit(1, f"psp: {exc}\n")
    out = json.dumps(found, indent=1) + "\n"
    if args.output:
        target = (args.caller_cwd / args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
