"""Original Xbox (2001) executables: XBE headers, kernel imports, a flat image and the XDK library
functions XbSymbolDatabase finds, from the file alone. Ghidra analysis is `rea-ghidra analyze`,
which loads an XBE through the ghidra-xbe extension (docs/XBOX-CLASSIC.md).

  rea-suite xbox info    <xbe> [-o JSON]     headers, certificate, sections, XDK libraries, kernel imports
  rea-suite xbox imports <xbe> [-o TSV]      kernel thunks: address, ordinal, name
  rea-suite xbox image   <xbe> -o IMAGE      flat memory image from the base address (headers, sections)
  rea-suite xbox symbols <xbe> [-o TSV]      XDK library functions and data (XbSymbolDatabase)
  rea-suite xbox check                       ghidra-xbe installed for this Ghidra, and loading an XBE

The structures and the kernel's export names come from pyxbe (pyproject.toml); the addresses are
unscrambled here with the retail, debug and Chihiro keys alike.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import xbe as pyxbe

MAGIC = 0x48454258  # "XBEH"
# The entry point and the kernel thunk table are stored XORed with a key per build kind.
KEYS = {
    "retail": (0xA8FC57AB, 0x5B6D40B6),
    "debug": (0x94859D4B, 0xEFB1F152),
    "chihiro": (0x40B5C16E, 0x2290059D),
}
LOADER_NAME = "Xbox Executable Format (XBE)"
EXTENSION = "ghidra-xbe"
FIX = "rea-suite tools reinstall ghidra"
OS_DIRS = {"linux": "linux_x86_64", "windows": "win_x86_64", "macos": "mac_x86_64"}


class Xbe:
    """The parts of an XBE a port needs, parsed without trusting the file."""

    def __init__(self, data: bytes):
        if len(data) < ctypes.sizeof(pyxbe.XbeImageHeader):
            raise ValueError("too short for an XBE header")
        self.data = data
        self.header = pyxbe.XbeImageHeader.from_buffer_copy(data, 0)
        if self.header.magic != MAGIC:
            raise ValueError("no XBEH magic: not an XBE")
        self.base = self.header.base_addr
        self.sections = []
        for i in range(self.header.section_count):
            offset = self.offset(self.header.section_headers_addr) + i * 56
            head = pyxbe.XbeSectionHeader.from_buffer_copy(self.read(offset, 56))
            self.sections.append((self.cstring(head.section_name_addr), head))
        self.kind, self.entry, self.thunks = self.unscramble()

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset + size > len(self.data):
            raise ValueError(f"0x{offset:x}+0x{size:x} lies outside the file")
        return self.data[offset : offset + size]

    def offset(self, address: int) -> int:
        """File offset of a virtual address, in the headers or in a section's file data."""
        if self.base <= address < self.base + self.header.headers_size:
            return address - self.base
        for _, head in getattr(self, "sections", []):
            if head.virtual_addr <= address < head.virtual_addr + head.raw_size:
                return head.raw_addr + address - head.virtual_addr
        raise ValueError(f"0x{address:08x} is in no section's file data")

    def cstring(self, address: int) -> str:
        start = self.offset(address)
        end = self.data.find(b"\0", start, start + 256)
        return self.data[start : end if end >= 0 else start + 256].decode("ascii", "replace")

    def unscramble(self) -> tuple[str, int, int]:
        """The build kind whose key puts both the entry point and the thunk table in the image."""
        end = self.base + self.header.image_size
        for kind, (entry_key, thunk_key) in KEYS.items():
            entry = self.header.entry_addr ^ entry_key
            thunks = self.header.kern_thunk_addr ^ thunk_key
            if self.base <= entry < end and self.base <= thunks < end:
                return kind, entry, thunks
        raise ValueError("no retail, debug or Chihiro key puts the entry point in the image")

    def certificate(self):
        offset = self.offset(self.header.certificate_addr)
        size = ctypes.sizeof(pyxbe.XbeImageCertificate)
        return pyxbe.XbeImageCertificate.from_buffer_copy(self.read(offset, size))

    def libraries(self) -> list[dict]:
        found = []
        size = ctypes.sizeof(pyxbe.XbeLibraryVersion)
        for i in range(self.header.lib_versions_count if self.header.lib_versions_addr else 0):
            raw = self.read(self.offset(self.header.lib_versions_addr) + i * size, size)
            lib = pyxbe.XbeLibraryVersion.from_buffer_copy(raw)
            found.append(
                {
                    "name": lib.name.decode("ascii", "replace"),
                    "version": f"{lib.ver_major}.{lib.ver_minor}.{lib.ver_build}",
                    "qfe": lib.qfeversion,
                    "debug": bool(lib.debug_build),
                    "approved": lib.approved,
                }
            )
        return found

    def imports(self) -> list[tuple[int, int | None, str]]:
        """(thunk address, ordinal, name) up to the table's zero; a non-ordinal entry has None."""
        rows = []
        address = self.thunks
        while True:
            (value,) = struct.unpack("<I", self.read(self.offset(address), 4))
            if value == 0:
                return rows
            if value & 0x80000000:
                ordinal = value & 0x7FFFFFFF
                rows.append((address, ordinal, pyxbe.XbeKernelImage.exports.get(ordinal, "")))
            else:
                rows.append((address, None, f"0x{value:08x}"))
            address += 4

    def image(self) -> bytes:
        """Headers and every section's file data at its address; the rest (bss, TLS) zero."""
        top = max(
            [self.base + self.header.headers_size]
            + [h.virtual_addr + max(h.virtual_size, h.raw_size) for _, h in self.sections]
        )
        flat = bytearray(top - self.base)
        flat[: self.header.headers_size] = self.data[: self.header.headers_size]
        for name, head in self.sections:
            if head.virtual_addr < self.base:
                raise ValueError(f"section {name} lies below the base address")
            start = head.virtual_addr - self.base
            flat[start : start + head.raw_size] = self.read(head.raw_addr, head.raw_size)
        return bytes(flat)


def title_id(value: int) -> str:
    """The publisher's two letters and the title's number, as on the box: 4D530004 -> MS-004."""
    letters = bytes([(value >> 24) & 0xFF, (value >> 16) & 0xFF])
    if all(0x20 < c < 0x7F for c in letters):
        return f"{letters.decode()}-{value & 0xFFFF:03d}"
    return f"{value:08X}"


def flags(value: int, kind) -> list[str]:
    return [f.name for f in kind if value & f.value]


def info(x: Xbe) -> dict:
    cert = x.certificate()
    head = x.header
    return {
        "kind": x.kind,
        "base": f"0x{x.base:08x}",
        "image_size": f"0x{head.image_size:x}",
        "headers_size": f"0x{head.headers_size:x}",
        "entry": f"0x{x.entry:08x}",
        "kernel_thunks": f"0x{x.thunks:08x}",
        "timestamp": datetime.fromtimestamp(head.timestamp, UTC).isoformat(),
        "init_flags": flags(int(head.init_flags), pyxbe.XbeImageHeader.InitFlags),
        "title": {
            "name": bytes(cert.title_name).decode("utf-16-le", "replace").split("\0")[0],
            "id": title_id(cert.title_id),
            "id_hex": f"0x{cert.title_id:08X}",
            "version": f"0x{cert.version:08x}",
            "disc": cert.disc_num,
            "regions": flags(cert.game_region, pyxbe.XbeImageCertificate.GameRegions),
            "media": flags(cert.allowed_media, pyxbe.XbeImageCertificate.AllowedMediaTypes),
        },
        "sections": [
            {
                "name": name,
                "address": f"0x{h.virtual_addr:08x}",
                "size": f"0x{h.virtual_size:x}",
                "file_offset": f"0x{h.raw_addr:x}",
                "file_size": f"0x{h.raw_size:x}",
                "flags": flags(int(h.flags), pyxbe.XbeSectionHeader.Flags),
            }
            for name, h in x.sections
        ],
        "libraries": x.libraries(),
        "kernel_imports": len(x.imports()),
    }


def symbols_cli(install: Path) -> Path:
    """XbSymbolDatabaseCLI as ghidra-xbe bundles it for this platform (macOS: x86_64, Rosetta 2)."""
    platform = "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux"
    name = "XbSymbolDatabaseCLI.exe" if platform == "windows" else "XbSymbolDatabaseCLI"
    cli = install / "Ghidra" / "Extensions" / EXTENSION / "os" / OS_DIRS[platform] / name
    if not cli.is_file():
        raise ValueError(f"{cli} missing; run {FIX}")
    return cli


def parse_symbols(text: str) -> list[tuple[int, str, str]]:
    """`LIBRARY__name = 0xaddress` lines -> sorted (address, name, library)."""
    rows = set()
    for line in text.splitlines():
        match = re.fullmatch(r"\s*([^=\s]+?)__(\S+)\s*=\s*(0x[0-9a-fA-F]+)\s*", line)
        if match:
            rows.add((int(match[3], 16), match[2], match[1]))
    return sorted(rows)


def symbols(path: Path, install: Path, timeout: int = 300) -> list[tuple[int, str, str]]:
    cli = symbols_cli(install)
    result = subprocess.run(
        [str(cli), str(path)], capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        # XbSymbolDatabase v3.1.160 crashes on an XBE that links none of the XDK's libraries
        # (homebrew built with nxdk), so the exit says which case it is.
        reason = f"signal {-result.returncode}" if result.returncode < 0 else result.returncode
        detail = result.stderr.strip().splitlines()[-1:] or [""]
        raise ValueError(
            f"XbSymbolDatabaseCLI exited with {reason} {detail[0]}".strip()
            + "; it fails this way on an XBE without XDK libraries"
        )
    return parse_symbols(result.stdout)


def ghidra_install() -> Path:
    install = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install:
        raise ValueError("GHIDRA_INSTALL_DIR missing; run through rea-suite")
    return Path(install)


def ghidra_version(install: Path) -> str:
    props = (install / "Ghidra" / "application.properties").read_text()
    return re.search(r"^application\.version=(.+)$", props, re.MULTILINE)[1].strip()


def loader_problem(install: Path) -> str | None:
    """Why Ghidra would not load ghidra-xbe, from the files alone; None when it is in place."""
    ext = install / "Ghidra" / "Extensions" / EXTENSION
    props = ext / "extension.properties"
    if not (ext / "lib" / f"{EXTENSION}.jar").is_file() or not props.is_file():
        return f"{EXTENSION} is not installed in {install.name}; run {FIX}"
    match = re.search(r"^version=(.+)$", props.read_text(), re.MULTILINE)
    want = ghidra_version(install)
    if not match or match[1].strip() != want:
        found = match[1].strip() if match else "none"
        return f"{EXTENSION} is built for Ghidra {found}, not {want}; run {FIX}"
    try:
        symbols_cli(install)
    except ValueError as exc:
        return str(exc)
    return None


def check(install: Path) -> int:
    """Doctor's check: the files are in place, and Ghidra imports the extension's own sample XBE
    (nxdk's triangle, homebrew) through it, without analysis."""
    problem = loader_problem(install)
    if problem:
        print(problem)
        return 1
    sample = install / "Ghidra" / "Extensions" / EXTENSION / "tests" / "xbefiles" / "triangle.xbe"
    if not sample.is_file():
        print(f"{sample.name} missing from {EXTENSION}; run {FIX}")
        return 1
    runner = install / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    with tempfile.TemporaryDirectory() as tmp:
        command = [str(runner), tmp, "probe", "-import", str(sample), "-noanalysis", "-readOnly"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    if f"Using Loader: {LOADER_NAME}" not in result.stdout + result.stderr:
        print(
            f"Ghidra {ghidra_version(install)} did not load {sample.name} with {EXTENSION}; run {FIX}"
        )
        return 1
    print(f"{EXTENSION} loads XBEs in Ghidra {ghidra_version(install)}")
    return 0


def emit(args: argparse.Namespace, text: str) -> None:
    if args.output:
        target = (args.caller_cwd / args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite xbox",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    for name, text in (
        ("info", "headers, certificate, sections, XDK libraries as JSON"),
        ("imports", "kernel thunks with ordinal names (TSV)"),
        ("image", "write the flat memory image from the base address"),
        ("symbols", "XDK library functions and data by XbSymbolDatabase (TSV)"),
    ):
        q = sub.add_parser(name, help=text)
        q.add_argument("file", type=Path, help="the XBE (default.xbe)")
        q.add_argument("-o", "--output", type=Path, required=name == "image")
    sub.add_parser("check", help="ghidra-xbe installed for this Ghidra, and loading an XBE")
    args = p.parse_args(argv)
    try:
        if args.command == "check":
            return check(ghidra_install())
        path = (args.caller_cwd / args.file).resolve()
        x = Xbe(path.read_bytes())
        if args.command == "info":
            emit(args, json.dumps(info(x), indent=1) + "\n")
        elif args.command == "imports":
            rows = x.imports()
            lines = ["address\tordinal\tname"] + [
                f"0x{a:08x}\t{'' if o is None else o}\t{n}" for a, o, n in rows
            ]
            emit(args, "\n".join(lines) + "\n")
            unnamed = [str(o) for _, o, n in rows if o is not None and not n]
            if unnamed:
                print(f"Limit: ordinal(s) without a name: {', '.join(unnamed)}", file=sys.stderr)
            if any(o is None for _, o, _ in rows):
                print(
                    "Limit: thunk entries without the ordinal bit (listed as values)",
                    file=sys.stderr,
                )
        elif args.command == "image":
            target = (args.caller_cwd / args.output).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            flat = x.image()
            target.write_bytes(flat)
            print(
                f"{target}: 0x{len(flat):x} bytes at 0x{x.base:08x}, entry 0x{x.entry:08x}",
                file=sys.stderr,
            )
            print(
                "Limit: bss and TLS are zero; the kernel thunks hold ordinals (0x8000xxxx) "
                "until a loader resolves them",
                file=sys.stderr,
            )
        else:
            rows = symbols(path, ghidra_install())
            lines = ["address\tname\tlibrary"] + [f"0x{a:08x}\t{n}\t{lib}" for a, n, lib in rows]
            emit(args, "\n".join(lines) + "\n")
            if not rows:
                print("Limit: no XDK library function recognized", file=sys.stderr)
        return 0
    except (OSError, ValueError, struct.error, subprocess.SubprocessError) as exc:
        p.exit(1, f"xbox: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
