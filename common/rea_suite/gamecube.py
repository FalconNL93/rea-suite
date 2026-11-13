"""GameCube and Wii files from the file alone: a DOL's or REL's header, or a disc image's header,
its main DOL and its file table. Ghidra analysis is `rea-ghidra analyze` with the GameCube loader
(component `gamecube`); the route is docs/GAMECUBE-WII.md.

  rea-suite gamecube info  <file> [-o JSON]   DOL, REL or disc image (ISO/GCM; RVZ, WIA, WBFS,
                                              CISO, GCZ and Wii partitions with nod-rs)
  rea-suite gamecube check                    the GameCube loader in place for this Ghidra

A plain GameCube ISO is read here. Every other container, and the encrypted partitions of a Wii
disc, are read through nod-rs (component `gamecube`, Python bindings of encounter/nod).
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from rea_suite import extcheck

DOL_HEADER = 0x100
TEXT_SLOTS, DATA_SLOTS = 7, 11
# Where code may load: MEM1 (24 MB on both consoles, cached or not) and the Wii's MEM2 (64 MB).
MEMORY = [(0x80000000, 0x81800000), (0xC0000000, 0xC1800000), (0x90000000, 0x94000000)]

GC_MAGIC, GC_MAGIC_AT = 0xC2339F3D, 0x1C
WII_MAGIC, WII_MAGIC_AT = 0x5D1C9EA3, 0x18
REGIONS = {0: "NTSC-J", 1: "NTSC-U", 2: "PAL", 3: "region free", 4: "NTSC-K"}
# Containers nod-rs reads, by their first bytes.
CONTAINERS = {
    b"RVZ\x01": "RVZ",
    b"WIA\x01": "WIA",
    b"WBFS": "WBFS",
    b"CISO": "CISO",
    b"\x01\xc0\x0b\xb1": "GCZ",
    b"\xae\x0f\x38\xa2": "TGC",
}
REL_END, REL_NOP, REL_SECTION = 203, 201, 202
# The SDK's libraries register a banner such as "<< Dolphin SDK - OS release build: ... >>"
# (RVL_SDK on the Wii); the build dates say which SDK the game linked.
SDK_BANNER = re.compile(rb"<< ([\x20-\x7e\t]{4,120}?) >>")
LOADER = "GameCubeLoader"
LOADER_FILES = ["data/languages/ppc_gekko_broadway.ldefs"]
FIX = "select component gamecube, then rea-suite setup (the loader builds from source)"


def hex32(value: int) -> str:
    return f"0x{value:08x}"


def in_memory(address: int, size: int) -> bool:
    return any(lo <= address and address + size <= hi for lo, hi in MEMORY)


# --- DOL ---------------------------------------------------------------------


@dataclass
class Dol:
    entry: int
    bss: tuple[int, int]
    sections: list[dict]  # name, offset, address, size


def parse_dol(data: bytes) -> Dol:
    """A DOL header, checked against the file: every section inside it and in console memory."""
    if len(data) < DOL_HEADER:
        raise ValueError("too short for a DOL header")
    offsets = struct.unpack_from(">18I", data, 0x00)
    addresses = struct.unpack_from(">18I", data, 0x48)
    sizes = struct.unpack_from(">18I", data, 0x90)
    bss_address, bss_size, entry = struct.unpack_from(">3I", data, 0xD8)
    sections = []
    for i in range(TEXT_SLOTS + DATA_SLOTS):
        if not sizes[i]:
            continue
        name = f"text{i}" if i < TEXT_SLOTS else f"data{i - TEXT_SLOTS}"
        if offsets[i] < DOL_HEADER or offsets[i] + sizes[i] > len(data):
            raise ValueError(f"{name} lies outside the file: not a DOL")
        if not in_memory(addresses[i], sizes[i]):
            raise ValueError(f"{name} at {hex32(addresses[i])} is outside console memory")
        sections.append(
            {"name": name, "offset": offsets[i], "address": addresses[i], "size": sizes[i]}
        )
    if not sections:
        raise ValueError("no sections: not a DOL")
    if not any(
        s["name"].startswith("text") and s["address"] <= entry < s["address"] + s["size"]
        for s in sections
    ):
        raise ValueError(f"entry {hex32(entry)} is in no text section: not a DOL")
    return Dol(entry, (bss_address, bss_size), sections)


def sdk_banners(data: bytes) -> list[str]:
    found = []
    for match in SDK_BANNER.finditer(data):
        text = " ".join(match[1].decode("ascii").split())
        if "SDK" in text and text not in found:
            found.append(text)
    return found


def dol_info(data: bytes) -> dict:
    dol = parse_dol(data)
    return {
        "kind": "dol",
        "entry": hex32(dol.entry),
        "bss": {"address": hex32(dol.bss[0]), "size": f"0x{dol.bss[1]:x}"},
        "uses_mem2": any(s["address"] >= 0x90000000 for s in dol.sections),
        "sections": [
            {
                "name": s["name"],
                "address": hex32(s["address"]),
                "size": f"0x{s['size']:x}",
                "file_offset": f"0x{s['offset']:x}",
            }
            for s in dol.sections
        ],
        "sdk": sdk_banners(data),
    }


# --- REL ---------------------------------------------------------------------


def rel_info(data: bytes) -> dict:
    """A REL module's header, sections and the modules its relocations point into (0: the DOL)."""
    if len(data) < 0x40:
        raise ValueError("too short for a REL header")
    (module, _, _, count, section_table, name_offset, name_size, version, bss_size) = (
        struct.unpack_from(">9I", data, 0)
    )
    rel_offset, imp_offset, imp_size = struct.unpack_from(">3I", data, 0x24)
    prolog_s, epilog_s, unresolved_s, bss_s = struct.unpack_from(">4B", data, 0x30)
    prolog, epilog, unresolved = struct.unpack_from(">3I", data, 0x34)
    header = {1: 0x40, 2: 0x48, 3: 0x4C}.get(version)
    if header is None:
        raise ValueError(f"version {version}: not a REL (1-3)")
    if not 0 < count <= 256 or section_table < header or section_table + count * 8 > len(data):
        raise ValueError("section table outside the file: not a REL")
    if imp_offset + imp_size > len(data) or imp_size % 8:
        raise ValueError("import table outside the file: not a REL")
    sections = []
    for i in range(count):
        offset, size = struct.unpack_from(">2I", data, section_table + i * 8)
        start = offset & ~1
        if start and start + size > len(data):
            raise ValueError(f"section {i} lies outside the file")
        if offset or size:
            sections.append(
                {
                    "index": i,
                    "file_offset": f"0x{start:x}",
                    "size": f"0x{size:x}",
                    "executable": bool(offset & 1),
                    "bss": start == 0,
                }
            )
    imports = []
    for at in range(imp_offset, imp_offset + imp_size, 8):
        target, relocs = struct.unpack_from(">2I", data, at)
        imports.append({"module": target, "relocations": count_relocations(data, relocs)})
    info = {
        "kind": "rel",
        "module_id": module,
        "version": version,
        "sections": sections,
        "bss_size": f"0x{bss_size:x}",
        "bss_section": bss_s,
        "prolog": {"section": prolog_s, "offset": f"0x{prolog:x}"},
        "epilog": {"section": epilog_s, "offset": f"0x{epilog:x}"},
        "unresolved": {"section": unresolved_s, "offset": f"0x{unresolved:x}"},
        "relocation_table": f"0x{rel_offset:x}",
        "imports": imports,
    }
    if version >= 2:
        info["align"], info["bss_align"] = struct.unpack_from(">2I", data, 0x40)
    if version >= 3:
        (info["fix_size"],) = struct.unpack_from(">I", data, 0x48)
    if name_size and name_offset + name_size <= len(data):
        info["name_offset"] = f"0x{name_offset:x}"  # into the game's module name file (str)
    return info


def count_relocations(data: bytes, at: int) -> int:
    """Relocation entries (offset u16, type u8, section u8, addend u32) up to R_DOLPHIN_END."""
    count = 0
    while at + 8 <= len(data):
        kind = data[at + 2]
        if kind == REL_END:
            return count
        if kind not in (REL_NOP, REL_SECTION):
            count += 1
        at += 8
    raise ValueError("relocation list without R_DOLPHIN_END")


# --- disc images ---------------------------------------------------------------


@dataclass
class Disc:
    """What a disc image says about itself, the same from every backend."""

    platform: str  # gamecube | wii
    format: str
    game_id: str
    title: str
    disc_number: int
    version: int
    region: str | None = None
    apploader_date: str | None = None
    partitions: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)  # path, size, [offset]
    main_dol: bytes | None = None
    notes: list[str] = field(default_factory=list)
    backend: str = ""


class DiscBackend(Protocol):
    """A reader of disc images; `open_disc` picks one by the image's format."""

    name: str

    def available(self) -> bool: ...

    def open(self, path: Path) -> Disc: ...


def text(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "replace").strip()


def disc_format(head: bytes) -> str | None:
    """`ISO-GC`, `ISO-WII`, a container's name, or None for something else."""
    for magic, name in CONTAINERS.items():
        if head.startswith(magic):
            return name
    if len(head) >= 0x20 and struct.unpack_from(">I", head, GC_MAGIC_AT)[0] == GC_MAGIC:
        return "ISO-GC"
    if len(head) >= 0x20 and struct.unpack_from(">I", head, WII_MAGIC_AT)[0] == WII_MAGIC:
        return "ISO-WII"
    return None


class GcmBackend:
    """Plain ISO images, read here: a GameCube disc whole, a Wii disc's header and partition
    table (its partitions are encrypted)."""

    name = "rea-suite"
    # A file table larger than this is not a disc's (Wii discs top out near 8 GB of files).
    MAX_FST = 64 << 20

    def available(self) -> bool:
        return True

    def open(self, path: Path) -> Disc:
        with path.open("rb") as f:
            return self.read(f, path.stat().st_size)

    def read(self, f, size: int) -> Disc:
        def at(offset: int, length: int) -> bytes:
            if offset < 0 or offset + length > size:
                raise ValueError(f"0x{offset:x}+0x{length:x} lies outside the image")
            f.seek(offset)
            return f.read(length)

        head = at(0, 0x440)
        kind = disc_format(head)
        if kind not in ("ISO-GC", "ISO-WII"):
            raise ValueError("not a GameCube or Wii ISO")
        disc = Disc(
            platform="gamecube" if kind == "ISO-GC" else "wii",
            format="ISO",
            game_id=text(head[0:6]),
            title=text(head[0x20:0x400]),
            disc_number=head[6],
            version=head[7],
            backend=self.name,
        )
        if disc.platform == "wii":
            disc.partitions = self.wii_partitions(at)
            disc.notes.append(
                "Wii partitions are encrypted; nod-rs (component gamecube) reads their files"
            )
            return disc
        (region,) = struct.unpack(">I", at(0x440 + 0x18, 4))
        disc.region = REGIONS.get(region, f"0x{region:x}")
        disc.apploader_date = text(at(0x2440, 0x10))
        dol_offset, fst_offset, fst_size = struct.unpack_from(">3I", head, 0x420)
        if fst_size > self.MAX_FST:
            raise ValueError(f"file table of 0x{fst_size:x} bytes is too large")
        disc.files = parse_fst(at(fst_offset, fst_size), shift=0)
        main = at(dol_offset, DOL_HEADER)
        dol = parse_dol_header_size(main)
        disc.main_dol = at(dol_offset, dol)
        return disc

    @staticmethod
    def wii_partitions(at) -> list[dict]:
        found = []
        groups = struct.unpack(">8I", at(0x40000, 32))
        for group in range(4):
            count, table = groups[group * 2], groups[group * 2 + 1] << 2
            for i in range(min(count, 64)):
                offset, kind = struct.unpack(">2I", at(table + i * 8, 8))
                name = {0: "Data", 1: "Update", 2: "Channel"}.get(kind, f"0x{kind:08x}")
                found.append({"group": group, "kind": name, "offset": f"0x{offset << 2:x}"})
        return found


def parse_dol_header_size(header: bytes) -> int:
    """The bytes a DOL takes on the disc: up to the end of its furthest section."""
    offsets = struct.unpack_from(">18I", header, 0x00)
    sizes = struct.unpack_from(">18I", header, 0x90)
    return max([DOL_HEADER] + [o + s for o, s in zip(offsets, sizes, strict=True) if s])


def parse_fst(fst: bytes, shift: int) -> list[dict]:
    """The file system table: entries of 12 bytes (a directory flag and a 24-bit name offset,
    then offset and size for a file, parent and end index for a directory), then the names.
    Wii offsets are stored shifted right by 2 (`shift`)."""
    if len(fst) < 12:
        raise ValueError("file table too short")
    flags, _, _, count = struct.unpack_from(">B3sII", fst, 0)
    if not flags & 1 or count == 0 or count * 12 > len(fst):
        raise ValueError("file table root entry is not a directory of the table's size")
    names = count * 12
    files: list[dict] = []
    stack: list[tuple[int, str]] = [(count, "")]
    for i in range(1, count):
        while stack and i >= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError("file table directories do not nest")
        word, a, b = struct.unpack_from(">3I", fst, i * 12)
        name_at = names + (word & 0xFFFFFF)
        end = fst.find(b"\0", name_at)
        if name_at >= len(fst) or end < 0:
            raise ValueError(f"file table entry {i} names outside the table")
        name = fst[name_at:end].decode("ascii", "replace")
        path = f"{stack[-1][1]}/{name}"
        if word >> 24:
            if not i < b <= count:
                raise ValueError(f"file table directory {i} ends outside the table")
            stack.append((b, path))
            continue
        files.append({"path": path, "offset": a << shift, "size": b})
    return files


class NodBackend:
    """Every container and Wii partition, through nod-rs (encounter/nod's Python bindings)."""

    name = "nod-rs"

    def available(self) -> bool:
        try:
            import nod_rs  # noqa: F401
        except ImportError:
            return False
        return True

    def open(self, path: Path) -> Disc:
        try:
            return self.read(path)
        except (RuntimeError, OSError) as exc:  # nod-rs raises these for a bad image
            raise ValueError(f"nod-rs: {exc}") from None

    def read(self, path: Path) -> Disc:
        import nod_rs

        reader = nod_rs.DiscReader(str(path))
        head = reader.header()
        meta = reader.meta()
        disc = Disc(
            platform="wii" if head.is_wii else "gamecube",
            format=meta.format,
            game_id=head.game_id,
            title=head.game_title,
            disc_number=head.disc_num,
            version=head.disc_version,
            backend=self.name,
        )
        disc.partitions = [{"index": p.index, "kind": p.kind} for p in reader.partitions()]
        partition = reader.open_partition_kind("Data")
        pmeta = partition.meta()
        disc.main_dol = pmeta.raw_dol
        disc.apploader_date = text(pmeta.raw_apploader[:0x10])
        (region,) = struct.unpack_from(">I", pmeta.raw_bi2, 0x18)
        disc.region = REGIONS.get(region, f"0x{region:x}")
        for node in pmeta.fst():
            if node.is_file:
                disc.files.append({"path": "/" + node.path.lstrip("/"), "size": node.length})
        if meta.compression and meta.compression != "None":
            disc.notes.append(f"{meta.format}, {meta.compression}")
        return disc


BACKENDS: list[DiscBackend] = [GcmBackend(), NodBackend()]


def open_disc(path: Path, backends: list[DiscBackend] | None = None) -> Disc:
    """A plain GameCube ISO is read here; anything else by the first backend that is installed.
    A Wii ISO without nod-rs gives its header and partition table only."""
    backends = BACKENDS if backends is None else backends
    with path.open("rb") as f:
        head = f.read(0x40)
    kind = disc_format(head)
    if kind is None:
        raise ValueError("not a GameCube or Wii disc image")
    plain, others = backends[0], backends[1:]
    if kind == "ISO-GC":
        return plain.open(path)
    for backend in others:
        if backend.available():
            return backend.open(path)
    if kind == "ISO-WII":
        return plain.open(path)
    raise ValueError(f"{kind} needs nod-rs: select component gamecube, then rea-suite setup")


def disc_info(disc: Disc) -> dict:
    info = {
        "kind": "disc",
        "platform": disc.platform,
        "format": disc.format,
        "game_id": disc.game_id,
        "title": disc.title,
        "disc_number": disc.disc_number,
        "version": disc.version,
        "region": disc.region,
        "apploader_date": disc.apploader_date,
        "read_with": disc.backend,
    }
    if disc.partitions:
        info["partitions"] = disc.partitions
    if disc.main_dol:
        try:
            info["main_dol"] = dol_info(disc.main_dol)
        except ValueError as exc:
            info["main_dol"] = {"error": str(exc)}
    info["file_count"] = len(disc.files)
    info["files"] = [
        {k: (f"0x{v:x}" if k == "offset" else v) for k, v in entry.items()} for entry in disc.files
    ]
    info["rels"] = [f["path"] for f in disc.files if f["path"].lower().endswith(".rel")]
    if disc.notes:
        info["notes"] = disc.notes
    return info


def info(path: Path) -> dict:
    """Pick the reader by the file: a disc image by its magic, else REL by its name, else DOL."""
    with path.open("rb") as f:
        head = f.read(0x40)
    if disc_format(head):
        return disc_info(open_disc(path))
    data = path.read_bytes()
    if path.suffix.lower() == ".rel":
        return rel_info(data)
    try:
        return dol_info(data)
    except ValueError as dol_error:
        try:
            return rel_info(data)
        except ValueError:
            raise ValueError(f"neither a disc image, a DOL nor a REL ({dol_error})") from None


def emit(args: argparse.Namespace, out: str) -> None:
    if args.output:
        target = (args.caller_cwd / args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(out)
    else:
        sys.stdout.write(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite gamecube",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("info", help="DOL, REL or disc image as JSON")
    q.add_argument("file", type=Path)
    q.add_argument("-o", "--output", type=Path)
    sub.add_parser("check", help="the GameCube loader in place for this Ghidra (files only)")
    args = p.parse_args(argv)
    if args.command == "check":
        return extcheck.check(LOADER, LOADER_FILES, FIX, "DOL, REL, Gekko/Broadway")
    try:
        found = info((args.caller_cwd / args.file).resolve())
    except (OSError, ValueError, struct.error) as exc:
        p.exit(1, f"gamecube: {exc}\n")
    emit(args, json.dumps(found, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
