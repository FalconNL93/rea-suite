"""PlayStation 3 executables from the file alone: SELF/SPRX headers without decrypting, the ELF or PRX
inside once it is decrypted (sections, the module, imports and exports), NIDs resolved to names,
PARAM.SFO, and decryption handed to the player's own RPCS3 (docs/PS3.md).

  rea-suite ps3 info    <file> [-o JSON]        SELF/SPRX, ELF/PRX or PARAM.SFO: what it is and holds
  rea-suite ps3 imports <elf|prx> [-o TSV]      imported functions and variables, NIDs named
  rea-suite ps3 nids    <nid|name>... [-o TSV]  NID to name and name to NID
  rea-suite ps3 decrypt <self|sprx|edat>... -o DIR [--klic HEX] [--data DIR]
                                                decrypt with your RPCS3 (its keys, your firmware,
                                                your licenses); fake-signed (debug) SELFs need none
  rea-suite ps3 check                           RPCS3 and the NID source installed (component ps3)

The NID names come from RPCS3's source at the commit of the installed RPCS3 build (tool
`rpcs3-source` in common/tools.yml): every name its modules register, hashed the way the
PS3 hashes them, plus the tables it lists by NID. Nothing here holds or uses a key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[2]  # this checkout: tools/ is beside common/

# The 16 bytes the PS3 appends to a symbol name before hashing it into a NID (RPCS3's
# ppu_generate_id; the first four bytes of the SHA-1, read little-endian). A constant of
# the format, not a key.
NID_SUFFIX = bytes.fromhex("6759659904250490566427499489741a")

SCE_MAGIC = b"SCE\0"
ELF_MAGIC = b"\x7fELF"
SFO_MAGIC = b"\0PSF"
OTHER_MAGICS = {
    b"\x7fPKG": "PKG (install it with `rpcs3 --installpkg`, then read the installed files)",
    b"NPD\0": "EDAT/SDAT (NPDRM data; `rea-suite ps3 decrypt` hands it to RPCS3)",
    b"SCEU": "PUP firmware update (install it with `rpcs3 --installfw`)",
}
SCE_TYPES = {1: "SELF", 2: "RVK", 3: "PKG", 4: "SPP"}
PROGRAM_TYPES = {
    1: "lv0",
    2: "lv1",
    3: "lv2",
    4: "application",
    5: "isolated SPU module",
    6: "secure loader",
    8: "NPDRM application",
}
NPD_LICENSES = {1: "network", 2: "local", 3: "free"}
ELF_TYPES = {2: "executable", 0xFFA4: "PRX (PPU relocatable)", 0xFE04: "relocatable executable"}
OSABI_CELL_LV2 = 0x66
EM_PPC64, EM_SPU = 0x15, 0x17
PT_NAMES = {
    1: "LOAD",
    4: "NOTE",
    7: "TLS",
    0x60000001: "proc_param",
    0x60000002: "proc_prx_param",
    0x700000A4: "prx_relocations",
}
PROC_PARAM_MAGIC = 0x13BCC5F6
PRX_PARAM_MAGIC = 0x1B434CEC
EXPORT_LIBRARY, EXPORT_MANAGEMENT = 0x0001, 0x8000
LIMIT_LIBRARIES, LIMIT_ENTRIES = 1024, 65536  # bounds against a broken table


class Ps3Error(ValueError):
    pass


def nid(name: str) -> int:
    """The NID the PS3 gives a function or variable name."""
    return struct.unpack("<I", hashlib.sha1(name.encode() + NID_SUFFIX).digest()[:4])[0]


def _cstring(data: bytes, offset: int, limit: int = 256) -> str:
    end = data.find(b"\0", offset, offset + limit)
    return data[offset : end if end >= 0 else offset + limit].decode("ascii", "replace")


# --- SELF / SPRX --------------------------------------------------------------------------------


def read_self(data: bytes) -> dict:
    """The plain headers of a SELF: everything a SELF says about itself before decryption."""
    if len(data) < 0x20 or data[:4] != SCE_MAGIC:
        raise Ps3Error("no SCE magic: not a SELF")
    version, flags, kind, meta, header_size, data_size = struct.unpack_from(">IHHIQQ", data, 4)
    out = {
        "format": "SELF",
        "sce": {
            "version": version,
            "key_revision": flags,
            "type": SCE_TYPES.get(kind, f"0x{kind:x}"),
            "metadata_offset": meta,
            "header_size": header_size,
            "data_size": data_size,
        },
        # A key revision with bit 15 set marks a debug, fake-signed SELF: no metadata and
        # no encryption, so it needs no key (RPCS3's unself.cpp, ps3recomp's unfself.py).
        "fake_signed": bool(flags & 0x8000),
    }
    if kind != 1:
        return out
    ext = struct.unpack_from(">10Q", data, 0x20)
    names = (
        "version",
        "program_info",
        "elf",
        "phdr",
        "shdr",
        "segments",
        "sceversion",
        "supplemental",
        "supplemental_size",
    )
    out["offsets"] = {k: v for k, v in zip(names, ext[:9], strict=True)}
    pi = ext[1]
    authority, vendor, ptype, sceversion = struct.unpack_from(">QIIQ", data, pi)
    out["program"] = {
        "authority_id": f"0x{authority:016x}",
        "vendor_id": f"0x{vendor:08x}",
        "type": PROGRAM_TYPES.get(ptype, f"0x{ptype:x}"),
        "version": f"0x{sceversion:016x}",
    }
    elf = read_elf_header(data, ext[2], ext[3])
    out["elf"] = elf
    segments = []
    for i in range(elf["phnum"]):
        offset, size, compression, _, encryption = struct.unpack_from(
            ">QQIIQ", data, ext[5] + i * 32
        )
        segments.append(
            {
                "offset": offset,
                "size": size,
                "compressed": compression == 2,
                "encrypted": encryption == 1,
            }
        )
    out["segments"] = segments
    out["encrypted"] = not out["fake_signed"] and any(s["encrypted"] for s in segments)
    out["supplemental"] = list(_supplemental(data, ext[7], ext[8]))
    return out


def _supplemental(data: bytes, start: int, size: int) -> Iterator[dict]:
    offset, end = start, min(start + size, len(data))
    while offset + 16 <= end:
        kind, length, more = struct.unpack_from(">IIQ", data, offset)
        entry: dict = {"type": kind}
        if kind == 1:
            entry["what"] = "plaintext capability"
            entry["flags"] = f"0x{struct.unpack_from('>I', data, offset + 16)[0]:08x}"
        elif kind == 2:
            entry["what"] = "ELF digest"
        elif kind == 3 and data[offset + 16 : offset + 20] == b"NPD\0":
            ver, lic, app = struct.unpack_from(">iii", data, offset + 20)
            entry.update(
                {
                    "what": "NPDRM",
                    "version": ver,
                    "license": NPD_LICENSES.get(lic, lic),
                    "app_type": app,
                    "content_id": _cstring(data, offset + 32, 0x30),
                }
            )
        yield entry
        if not more or length < 16:
            return
        offset += length


# --- ELF / PRX ----------------------------------------------------------------------------------


def read_elf_header(data: bytes, at: int = 0, phdr_at: int | None = None) -> dict:
    if data[at : at + 4] != ELF_MAGIC:
        raise Ps3Error("no ELF magic")
    if data[at + 4] != 2 or data[at + 5] != 2:
        raise Ps3Error("not a big-endian ELF64: not a PS3 PPU program")
    etype, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx = (
        struct.unpack_from(">HHIQQQIHHHHHH", data, at + 16)
    )
    head = {
        "type": ELF_TYPES.get(etype, f"0x{etype:04x}"),
        "e_type": etype,
        "machine": {EM_PPC64: "PPC64 (PPU)", EM_SPU: "SPU"}.get(machine, f"0x{machine:x}"),
        "osabi": "CELL LV2" if data[at + 7] == OSABI_CELL_LV2 else f"0x{data[at + 7]:x}",
        "entry": f"0x{entry:x}",
        "phnum": phnum,
        "shnum": shnum,
        "phoff": phoff,
        "shoff": shoff,
        "shstrndx": shstrndx,
    }
    phdr_base = at + phoff if phdr_at is None else phdr_at
    head["program_headers"] = [_phdr(data, phdr_base + i * phentsize) for i in range(phnum)]
    if shentsize not in (0, 64):
        raise Ps3Error(f"section header size {shentsize}, not 64")
    return head


def _phdr(data: bytes, at: int) -> dict:
    ptype, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
        ">IIQQQQQQ", data, at
    )
    return {
        "type": PT_NAMES.get(ptype, f"0x{ptype:08x}"),
        "p_type": ptype,
        "flags": "".join(c if flags & b else "-" for c, b in (("r", 4), ("w", 2), ("x", 1))),
        "offset": offset,
        "vaddr": vaddr,
        "paddr": paddr,
        "filesz": filesz,
        "memsz": memsz,
        "align": align,
    }


@dataclass
class Library:
    """One entry of an import (stub) or export (entry) table."""

    name: str
    version: int
    attributes: int
    functions: list[tuple[int, int]]  # (NID, address: the import's slot or the export's code)
    variables: list[tuple[int, int]]


class Elf:
    """A decrypted PS3 PPU ELF or PRX, parsed without trusting the file."""

    def __init__(self, data: bytes):
        self.data = data
        self.header = read_elf_header(data)
        self.segments = [p for p in self.header["program_headers"] if p["p_type"] == 1]

    def offset(self, address: int, size: int = 1) -> int:
        """File offset of a virtual address in a LOAD segment's file data."""
        for p in self.segments:
            if p["vaddr"] <= address and address + size <= p["vaddr"] + p["filesz"]:
                return p["offset"] + address - p["vaddr"]
        raise Ps3Error(f"0x{address:x} is in no segment's file data")

    def u32(self, address: int) -> int:
        return struct.unpack_from(">I", self.data, self.offset(address, 4))[0]

    def string(self, address: int) -> str:
        return _cstring(self.data, self.offset(address))

    def sections(self) -> list[dict]:
        h = self.header
        if not h["shnum"] or h["shoff"] + h["shnum"] * 64 > len(self.data):
            return []
        raw = [
            struct.unpack_from(">IIQQQQIIQQ", self.data, h["shoff"] + i * 64)
            for i in range(h["shnum"])
        ]
        names = raw[h["shstrndx"]][4] if h["shstrndx"] < len(raw) else None
        out = []
        for name, kind, flags, addr, offset, size, *_ in raw:
            label = _cstring(self.data, names + name) if names is not None else ""
            out.append(
                {
                    "name": label,
                    "type": kind,
                    "address": f"0x{addr:x}",
                    "offset": offset,
                    "size": size,
                }
            )
        return out

    def _segment(self, p_type: int) -> dict | None:
        return next((p for p in self.header["program_headers"] if p["p_type"] == p_type), None)

    def process_param(self) -> dict | None:
        """sys_process_param: the SDK version the program was built with, its main thread."""
        p = self._segment(0x60000001)
        if not p or p["filesz"] < 0x20:
            return None
        _, magic, version, sdk, prio, stack, page, _ = struct.unpack_from(
            ">IIIIiIII", self.data, p["offset"]
        )
        if magic != PROC_PARAM_MAGIC:
            return {"error": f"bad magic 0x{magic:08x}"}
        return {
            "sdk_version": f"0x{sdk:08x}",
            "version": f"0x{version:x}",
            "primary_priority": prio,
            "primary_stack_size": stack,
            "malloc_page_size": page,
        }

    def tables(self) -> tuple[str, dict, tuple[int, int], tuple[int, int]]:
        """(kind, module info, exports range, imports range) of an executable or a PRX."""
        if self.header["e_type"] == 0xFFA4:
            first = self.header["program_headers"][0]
            at = first["paddr"]  # a PRX keeps its module info's file offset in p_paddr
            attributes, v0, v1 = struct.unpack_from(">HBB", self.data, at)
            name = _cstring(self.data, at + 4, 28)
            toc, ent0, ent1, stub0, stub1 = struct.unpack_from(">IIIII", self.data, at + 32)
            info = {
                "name": name,
                "version": f"{v0}.{v1}",
                "attributes": f"0x{attributes:04x}",
                "toc": f"0x{toc:x}",
            }
            return "prx", info, (ent0, ent1), (stub0, stub1)
        p = self._segment(0x60000002)
        if not p or p["filesz"] < 0x20:
            return "executable", {}, (0, 0), (0, 0)
        _, magic, _, _, ent0, ent1, stub0, stub1 = struct.unpack_from(">8I", self.data, p["offset"])
        if magic != PRX_PARAM_MAGIC:
            raise Ps3Error(f"sys_proc_prx_param has bad magic 0x{magic:08x}")
        return "executable", {}, (ent0, ent1), (stub0, stub1)

    def libraries(self, start: int, end: int, imports: bool) -> list[Library]:
        out: list[Library] = []
        address = start
        while address < end and len(out) < LIMIT_LIBRARIES:
            o = self.offset(address, 0x1C)
            size = self.data[o]
            version, attributes, nfunc, nvar, _ = struct.unpack_from(">HHHHH", self.data, o + 2)
            name_ptr, nids_ptr, addrs_ptr = struct.unpack_from(">III", self.data, o + 0x10)
            if nfunc + nvar > LIMIT_ENTRIES:
                raise Ps3Error(f"library at 0x{address:x} claims {nfunc + nvar} entries")
            name = self.string(name_ptr) if name_ptr else ""
            functions = [
                (self.u32(nids_ptr + 4 * i), self.u32(addrs_ptr + 4 * i)) for i in range(nfunc)
            ]
            if imports:
                vnids, vstubs = struct.unpack_from(">II", self.data, o + 0x1C)
                variables = [
                    (self.u32(vnids + 4 * i), self.u32(vstubs + 4 * i)) for i in range(nvar)
                ]
            else:  # exports list variables after functions in the same arrays
                variables = [
                    (self.u32(nids_ptr + 4 * i), self.u32(addrs_ptr + 4 * i))
                    for i in range(nfunc, nfunc + nvar)
                ]
            if not imports and attributes & EXPORT_MANAGEMENT and not attributes & EXPORT_LIBRARY:
                name = name or "(module management: start, stop, ...)"
            out.append(Library(name, version, attributes, functions, variables))
            address += size or 0x2C
        return out


# --- PARAM.SFO ----------------------------------------------------------------------------------


def read_sfo(data: bytes) -> dict:
    """PARAM.SFO's keys: title id, title, versions, category (little-endian, unlike the rest)."""
    if data[:4] != SFO_MAGIC:
        raise Ps3Error("no PSF magic: not a PARAM.SFO")
    _, keys, values, count = struct.unpack_from("<IIII", data, 4)
    out = {}
    for i in range(min(count, 1024)):
        key_off, fmt, length, _, value_off = struct.unpack_from("<HHIII", data, 0x14 + i * 16)
        key = _cstring(data, keys + key_off, 64)
        raw = data[values + value_off : values + value_off + length]
        if fmt == 0x0404:
            out[key] = struct.unpack("<I", raw[:4])[0]
        else:
            out[key] = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    return {"format": "PARAM.SFO", "keys": out}


# --- NIDs ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class NidEntry:
    nid: int
    module: str
    name: str
    kind: str  # "function" or "variable"
    hashed: bool  # the NID is the hash of the name (else a table lists it)


class NidSource(Protocol):
    """Where NID names come from; one implementation today (RPCS3's source)."""

    def describe(self) -> str: ...

    def entries(self) -> Iterable[NidEntry]: ...


_REG = re.compile(r"\bREG_(FUNC|VAR|FNID|VNID)\(\s*(\w+)\s*,\s*(\"[^\"]+\"|\w+)")
_MODULE_IF = re.compile(r"if \(_module\b[^)]*")
_CASE = re.compile(r'case (0x[0-9a-fA-F]{8}): return "([^"]+)";')


class Rpcs3Source:
    """Names RPCS3 registers (REG_FUNC and friends) and the NIDs PPUFunction.cpp lists."""

    def __init__(self, root: Path):
        self.root = root
        self.cell = root / "rpcs3" / "Emu" / "Cell"
        if not (self.cell / "PPUFunction.cpp").is_file():
            raise Ps3Error(f"{root} holds no RPCS3 source (rpcs3/Emu/Cell/PPUFunction.cpp)")

    def describe(self) -> str:
        return f"RPCS3 source at {self.root}"

    def entries(self) -> Iterator[NidEntry]:
        for path in sorted(self.cell.rglob("*.cpp")):
            text = path.read_text(errors="replace")
            for kind, module, name in _REG.findall(text):
                if name.startswith("0x"):
                    continue  # registered by NID alone: no name to give
                what = "variable" if kind in ("VAR", "VNID") else "function"
                name = name.strip('"')
                yield NidEntry(nid(name), module, name, what, True)
        yield from self._listed((self.cell / "PPUFunction.cpp").read_text(errors="replace"))

    @staticmethod
    def _listed(text: str) -> Iterator[NidEntry]:
        modules: list[str] = []
        kind = "function"
        for line in text.splitlines():
            if "ppu_get_variable_name" in line:
                kind = "variable"
            if m := _MODULE_IF.search(line):
                modules = re.findall(r'_module == "(\w+)"', m.group(0)) or [""]
            elif m := _CASE.search(line):
                value, name = int(m.group(1), 16), m.group(2)
                for module in modules:
                    yield NidEntry(value, module, name, kind, nid(name) == value)


class NidTable:
    def __init__(self, source: NidSource):
        self.source = source
        self.by_nid: dict[int, list[NidEntry]] = {}
        for e in source.entries():
            rows = self.by_nid.setdefault(e.nid, [])
            if e not in rows:
                rows.append(e)

    def name(self, value: int, module: str | None = None) -> str:
        rows = self.by_nid.get(value, [])
        if module is not None:
            rows = [r for r in rows if r.module == module] or rows
        return rows[0].name if rows else ""


def default_source(explicit: Path | None) -> NidSource:
    root = explicit or (
        Path(os.environ["REA_PS3_NID_SOURCE"]) if os.environ.get("REA_PS3_NID_SOURCE") else None
    )
    if root is None:
        root = ROOT / "tools" / "rpcs3-source" / "current"
        if not root.exists():
            raise Ps3Error(
                "no NID source: select component ps3 and run rea-suite setup (tool rpcs3-source)"
            )
    return Rpcs3Source(root)


# --- decryption ---------------------------------------------------------------------------------


class Decrypter(Protocol):
    """Turns a SELF, SPRX or EDAT into its plain file; one implementation today (RPCS3)."""

    def decrypt(self, source: Path, out_dir: Path, klic: str | None) -> Path: ...


_DECRYPTED = re.compile(r"^Decrypted (.+) -> (.+)$", re.MULTILINE)


class Rpcs3Decrypter:
    """`rpcs3 --decrypt`: RPCS3's own keys, the licenses (RAP files) and firmware in its data
    folder, and a KLIC given on standard input. It writes beside the input, so it works on a
    copy in a scratch folder and the result moves to out_dir."""

    def __init__(self, binary: str, data_dir: Path | None = None, timeout: int = 300):
        self.binary, self.data_dir, self.timeout = binary, data_dir, timeout

    def environment(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.data_dir:
            if sys.platform == "win32":
                env["RPCS3_CONFIG_DIR"] = str(self.data_dir)
            elif sys.platform == "darwin":
                raise Ps3Error(
                    "--data is not supported on macOS: RPCS3 there keeps its data in ~/Library"
                )
            else:
                env["XDG_CONFIG_HOME"] = str(self.data_dir / "config")
                env["XDG_CACHE_HOME"] = str(self.data_dir / "cache")
        return env

    def command(self, target: Path) -> list[str]:
        return [self.binary, "--decrypt", str(target)]

    def decrypt(self, source: Path, out_dir: Path, klic: str | None) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".ps3-decrypt-", dir=out_dir) as tmp:
            copy = Path(tmp) / source.name
            shutil.copyfile(source, copy)
            # An empty line (or the end of input) makes RPCS3 stop asking for a KLIC.
            done = subprocess.run(
                self.command(copy),
                input=(klic or "") + "\n",
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=self.environment(),
                check=False,
            )
            found = [Path(m.group(2).strip()) for m in _DECRYPTED.finditer(done.stdout)]
            if not found or not found[0].is_file():
                tail = "\n".join((done.stdout + done.stderr).strip().splitlines()[-6:])
                raise Ps3Error(f"RPCS3 did not decrypt {source.name}:\n{tail}")
            target = out_dir / found[0].name
            shutil.move(found[0], target)
            return target


def find_rpcs3(explicit: str | None) -> str | None:
    """--rpcs3, REA_RPCS3, or the launcher tools.yml wrote (it sets the AppImage's environment)."""
    for candidate in (explicit, os.environ.get("REA_RPCS3")):
        if candidate:
            return candidate
    return shutil.which("rpcs3")


# --- commands -----------------------------------------------------------------------------------


def info(data: bytes, table: NidTable | None) -> dict:
    head = data[:4]
    if head == SCE_MAGIC:
        out = read_self(data)
        if out["sce"]["type"] == "SELF":
            out["next"] = (
                "fake-signed: `rea-suite ps3 decrypt` unwraps it without a key"
                if out["fake_signed"]
                else "encrypted: `rea-suite ps3 decrypt` with your RPCS3 gives the ELF to read"
            )
        return out
    if head == SFO_MAGIC:
        return read_sfo(data)
    if head in OTHER_MAGICS:
        return {"format": OTHER_MAGICS[head]}
    if head != ELF_MAGIC:
        raise Ps3Error("not a SELF, ELF, PARAM.SFO, PKG, EDAT or PUP")
    elf = Elf(data)
    if elf.header["machine"] == "SPU":
        return {"format": "SPU ELF", "elf": elf.header, "sections": elf.sections()}
    kind, module, exports, imports = elf.tables()
    out = {
        "format": "PRX" if kind == "prx" else "ELF",
        "elf": elf.header,
        "sections": elf.sections(),
    }
    if kind == "prx":
        out["module"] = module
    if param := elf.process_param():
        out["process_param"] = param
    out["exports"] = [_library_json(lib, table) for lib in elf.libraries(*exports, imports=False)]
    out["imports"] = [_library_json(lib, table) for lib in elf.libraries(*imports, imports=True)]
    return out


def _library_json(lib: Library, table: NidTable | None) -> dict:
    def named(rows: list[tuple[int, int]]) -> list[dict]:
        return [
            {
                "nid": f"0x{n:08x}",
                "address": f"0x{a:x}",
                "name": table.name(n, lib.name) if table else "",
            }
            for n, a in rows
        ]

    return {
        "name": lib.name,
        "version": f"0x{lib.version:04x}",
        "attributes": f"0x{lib.attributes:04x}",
        "functions": named(lib.functions),
        "variables": named(lib.variables),
    }


def import_rows(elf: Elf, table: NidTable | None) -> list[tuple[str, str, int, int, str]]:
    _, _, _, imports = elf.tables()
    rows = []
    for lib in elf.libraries(*imports, imports=True):
        for kind, entries in (("function", lib.functions), ("variable", lib.variables)):
            for n, a in entries:
                rows.append((lib.name, kind, n, a, table.name(n, lib.name) if table else ""))
    return rows


def resolve(tokens: list[str], table: NidTable) -> list[tuple[int, str, str, str]]:
    """(NID, module, name, how) for each token: a NID (hex) looked up, or a name hashed. How:
    known (in the source, the NID its hash), listed (a table gives the NID for the name),
    computed (a name the source lacks: its NID all the same), unknown (a NID without a name)."""
    rows = []
    for token in tokens:
        if re.fullmatch(r"(0x)?[0-9a-fA-F]{8}", token):
            value = int(token, 16)
            hits = table.by_nid.get(value, [])
            rows += [(value, e.module, e.name, "known" if e.hashed else "listed") for e in hits]
            if not hits:
                rows.append((value, "", "", "unknown"))
        else:
            value = nid(token)
            hits = [e for e in table.by_nid.get(value, []) if e.name == token]
            rows += [(value, e.module, e.name, "known") for e in hits] or [
                (value, "", token, "computed")
            ]
    return rows


def check(source: Path | None, rpcs3: str | None) -> int:
    problems = []
    try:
        src = default_source(source)
        table = NidTable(src)
        names = sum(len(rows) for rows in table.by_nid.values())
        print(f"NID names: {names} for {len(table.by_nid)} NIDs from {src.describe()}")
    except (Ps3Error, OSError) as exc:
        problems.append(str(exc))
    binary = find_rpcs3(rpcs3)
    if binary:
        print(f"RPCS3: {binary}")
    else:
        problems.append(
            "RPCS3 not found: select component ps3 and run rea-suite setup, or pass --rpcs3"
        )
    for p in problems:
        print(p)
    return 1 if problems else 0


def emit(args: argparse.Namespace, text: str) -> None:
    if args.output:
        target = (args.caller_cwd / args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    else:
        sys.stdout.write(text)


def _table(args: argparse.Namespace, required: bool) -> NidTable | None:
    try:
        return NidTable(default_source(args.nid_source and (args.caller_cwd / args.nid_source)))
    except Ps3Error as exc:
        if required:
            raise
        print(f"Limit: NIDs not named ({exc})", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite ps3",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    p.add_argument(
        "--nid-source", type=Path, help="an RPCS3 source tree (default: tool rpcs3-source)"
    )
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("info", help="what a SELF, ELF, PRX or PARAM.SFO is and holds (JSON)")
    q.add_argument("file", type=Path)
    q.add_argument("-o", "--output", type=Path)
    q = sub.add_parser("imports", help="imported functions and variables of an ELF or PRX (TSV)")
    q.add_argument("file", type=Path)
    q.add_argument("-o", "--output", type=Path)
    q = sub.add_parser("nids", help="NID to name, name to NID (TSV)")
    q.add_argument("tokens", nargs="+", metavar="nid|name")
    q.add_argument("-o", "--output", type=Path)
    q = sub.add_parser("decrypt", help="decrypt with your RPCS3; the plain files go to -o")
    q.add_argument("files", type=Path, nargs="+")
    q.add_argument("-o", "--output", type=Path, required=True, help="the folder for the results")
    q.add_argument("--klic", help="the 32-hex-digit KLIC of an NPDRM title without a RAP file")
    q.add_argument(
        "--data", type=Path, help="an RPCS3 data folder instead of your own (Linux, Windows)"
    )
    q.add_argument("--rpcs3", help="the RPCS3 binary (default REA_RPCS3, else rpcs3 on PATH)")
    q.add_argument("--timeout", type=int, default=300)
    q = sub.add_parser("check", help="RPCS3 and the NID source installed")
    q.add_argument("--rpcs3")
    args = p.parse_args(argv)
    try:
        if args.command == "check":
            return check(args.nid_source and (args.caller_cwd / args.nid_source), args.rpcs3)
        if args.command == "nids":
            rows = resolve(args.tokens, _table(args, required=True))
            lines = ["nid\tmodule\tname\thow"] + [
                f"0x{n:08x}\t{m}\t{name}\t{h}" for n, m, name, h in rows
            ]
            emit(args, "\n".join(lines) + "\n")
            return 0
        if args.command == "decrypt":
            binary = find_rpcs3(args.rpcs3)
            if not binary:
                raise Ps3Error(
                    "RPCS3 not found: select component ps3 and run setup, or pass --rpcs3"
                )
            data = args.data and (args.caller_cwd / args.data).resolve()
            tool = Rpcs3Decrypter(binary, data, args.timeout)
            out_dir = (args.caller_cwd / args.output).resolve()
            for f in args.files:
                print(tool.decrypt((args.caller_cwd / f).resolve(), out_dir, args.klic))
            return 0
        data = (args.caller_cwd / args.file).resolve().read_bytes()
        if args.command == "info":
            needs_names = data[:4] == ELF_MAGIC
            emit(
                args,
                json.dumps(info(data, _table(args, False) if needs_names else None), indent=1)
                + "\n",
            )
        else:
            rows = import_rows(Elf(data), _table(args, required=False))
            lines = ["library\tkind\tnid\tslot\tname"] + [
                f"{lib}\t{k}\t0x{n:08x}\t0x{a:x}\t{name}" for lib, k, n, a, name in rows
            ]
            emit(args, "\n".join(lines) + "\n")
            unnamed = sum(1 for *_, name in rows if not name)
            if unnamed:
                print(f"Limit: {unnamed} of {len(rows)} NIDs without a name", file=sys.stderr)
        return 0
    except (OSError, ValueError, struct.error, subprocess.SubprocessError) as exc:
        p.exit(1, f"ps3: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
