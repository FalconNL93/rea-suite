"""Does a Windows executable carry SteamStub, Steam's DRM wrapper? From the file alone, read-only.

  rea-suite steamstub <exe>... [--json]

Signs, strongest first: a `.bind` section (where SteamStub keeps its stub and its header); the
entry point inside it; a code section with near-random bytes (entropy over 7.2 bits a byte: the
code is encrypted until the stub runs); and a header timestamp in the future or different from
the debug directory's (the file was rewritten after the linker wrote it). A `.bind` section
with the entry point in it is SteamStub; `.bind` alone is reported as possible. The file's
SHA-256 is printed, for recording which file was checked.

Exit 0: no SteamStub; 1: SteamStub or possibly; 2: not a PE or not readable. Steamless removes
it (README, "SteamStub"); which variant it is, Steamless says.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import pefile

from rea_suite.text import decoded

ENCRYPTED = 7.2
CODE = 0x20  # IMAGE_SCN_CNT_CODE


def section_name(section) -> str:
    return decoded(section.Name.rstrip(b"\0"), "ascii")


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sections = []
    for s in pe.sections:
        start, size = s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData)
        sections.append(
            {
                "name": section_name(s),
                "entropy": round(s.get_entropy(), 2),
                "code": bool(s.Characteristics & CODE),
                "entry": start <= entry < start + size,
            }
        )
    bind = next((s for s in sections if s["name"] == ".bind"), None)
    header = pe.FILE_HEADER.TimeDateStamp
    debug = sorted({d.struct.TimeDateStamp for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])} - {0})
    signs = []
    if bind:
        signs.append(".bind section")
        if bind["entry"]:
            signs.append("entry point in .bind")
    encrypted = [
        s["name"]
        for s in sections
        if s["code"] and s["name"] != ".bind" and s["entropy"] > ENCRYPTED
    ]
    if encrypted:
        signs.append(f"code section(s) {', '.join(encrypted)} near random (encrypted)")
    if debug and header not in debug:
        signs.append("header timestamp differs from the debug directory's")
    if header > time.time():
        signs.append("header timestamp in the future")
    verdict = "steamstub" if bind and bind["entry"] else "possible" if bind else "none"
    return {
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
        "verdict": verdict,
        "signs": signs,
        "timestamp": header,
        "debug_timestamps": debug,
        "sections": sections,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite steamstub",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    p.add_argument("files", type=Path, nargs="+")
    p.add_argument("--json", action="store_true", help="one JSON object per file")
    args = p.parse_args(argv)
    worst = 0
    for name in args.files:
        path = (args.caller_cwd / name).resolve()
        try:
            found = inspect(path)
        except (OSError, pefile.PEFormatError) as exc:
            print(f"steamstub: {name}: {exc}", file=sys.stderr)
            worst = 2
            continue
        if found["verdict"] != "none":
            worst = max(worst, 1)
        if args.json:
            print(json.dumps(found))
            continue
        print(f"{name}: {found['verdict']}  sha256 {found['sha256']}")
        for sign in found["signs"]:
            print(f"  {sign}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
