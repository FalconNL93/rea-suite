"""Find a PS1 game's tables of disc file extents: (LBA, size) pairs that point at the disc's files.

  rea-suite playstation lba-table PROGRAM (--disc IMAGE | --files LISTING) [options]
  rea-suite playstation lba-table --disc IMAGE --list

PROGRAM is a PS-X EXE (mapped at its header's load address) or a RAM dump (--base, default
0x80000000). The disc is an image (.cue, raw .bin, .iso: iso9660.py) or a listing of
`<lba> <size> <path>` lines, as `--list` prints it, so a game's files never need the image at hand.

A table is a run of entries, each a little-endian 32-bit LBA and size at the start of an entry of
8, 12 or 16 bytes, LBA first or size first, the size in bytes, in 2048-byte sectors or in bytes
rounded up to a sector. Every entry of a run names a disc file with the same constant offset
between its stored LBA and the file's (a game may store LBA - 23, or count from the pregap): the
offset is reported, within --max-bias of zero. Up to --max-gap entries in a row may name no file
(an empty slot, a file the listing lacks). MSF (BCD) positions and 16-bit fields are not matched.

Checked on 2026-11-16 against a synthetic disc and executable (test_psx_lba.py); the case it was
written for, Duke Nukem: Time to Kill, keeps 453 (LBA - 23, size) pairs at 0x800BCC00.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from rea_suite import iso9660
from rea_suite.text import printable

SECTOR = 2048
RAM_BASE = 0x80000000
STRIDES = (8, 12, 16)
UNITS = ("bytes", "sectors", "padded")
ORDERS = ("lba,size", "size,lba")
DENSITY = 6  # tenths of a table's entries that must name a file


def program(path: Path, base: int | None) -> tuple[int, bytes]:
    """(address of the first byte, bytes) of an executable's payload or a RAM dump."""
    data = path.read_bytes()
    if data.startswith(b"PS-X EXE") and len(data) >= 0x800 and base is None:
        load, size = struct.unpack_from("<2I", data, 0x18)
        return load, data[0x800 : 0x800 + size]
    return (RAM_BASE if base is None else base), data


def stored_size(unit: str, size: int) -> int:
    sectors = -(-size // SECTOR)
    return {"bytes": size, "sectors": sectors, "padded": sectors * SECTOR}[unit]


@dataclass
class Table:
    address: int
    stride: int
    order: str
    unit: str
    bias: int
    entries: list[dict] = field(default_factory=list)

    @property
    def matched(self) -> int:
        return sum(1 for e in self.entries if e["files"])

    def layout(self) -> str:
        first, second = self.order.split(",")
        names = {"lba": "u32 lba", "size": f"u32 size ({self.unit})"}
        sign = "+" if self.bias >= 0 else "-"
        return (
            f"{names[first]}, {names[second]} at an entry's start, {self.stride} bytes an entry; "
            f"stored lba = disc lba {sign} {abs(self.bias)}"
        )

    def summary(self) -> dict:
        return {
            "address": f"0x{self.address:08X}",
            "entries": len(self.entries),
            "matched": self.matched,
            "stride": self.stride,
            "order": self.order,
            "size_unit": self.unit,
            "lba_bias": self.bias,
            "layout": self.layout(),
            "table": self.entries,
        }


def find(
    base: int,
    data: bytes,
    files: list[iso9660.DiscFile],
    min_entries: int = 8,
    max_gap: int = 2,
    max_bias: int = 512,
) -> list[Table]:
    files = sorted((f for f in files if f.size > 0), key=lambda f: f.lba)
    if not files:
        return []
    # unit -> stored size -> (the LBAs of the files of that size, the files), both by LBA
    by_size: dict[str, dict[int, tuple[list[int], list]]] = {u: {} for u in UNITS}
    for f in files:
        for unit in UNITS:
            lbas, named = by_size[unit].setdefault(stored_size(unit, f.size), ([], []))
            lbas.append(f.lba)
            named.append(f)
    low, high = files[0].lba - max_bias, files[-1].lba + max_bias
    words = struct.unpack_from(f"<{len(data) // 4}I", data)
    # (order, unit, bias) -> {word index of an entry's start: the files it names}
    hits: dict[tuple, dict[int, list]] = defaultdict(lambda: defaultdict(list))
    for i in range(len(words) - 1):
        for order, (a, s) in zip(ORDERS, ((words[i], words[i + 1]), (words[i + 1], words[i]))):
            if not low <= a <= high:
                continue
            for unit in UNITS:
                sized = by_size[unit].get(s)
                if sized is None:
                    continue
                lbas, named = sized
                at = bisect.bisect_left(lbas, a - max_bias)
                for f in named[at : bisect.bisect_right(lbas, a + max_bias)]:
                    hits[(order, unit, a - f.lba)][i].append(f)
    tables: list[Table] = []
    for (order, unit, bias), named in hits.items():
        if len(named) < min_entries:
            continue
        for stride in STRIDES:
            step = stride // 4
            phases: dict[int, list[int]] = defaultdict(list)
            for i in sorted(named):
                phases[i % step].append(i)
            for run in runs(phases.values(), step, max_gap):
                if len(run) < min_entries:
                    continue
                first, last = run[0], run[-1]
                table = Table(base + first * 4, stride, order, unit, bias)
                for n, i in enumerate(range(first, last + step, step)):
                    a, s = (
                        (words[i], words[i + 1])
                        if order == "lba,size"
                        else (words[i + 1], words[i])
                    )
                    table.entries.append({
                        "index": n,
                        "address": f"0x{base + i * 4:08X}",
                        "stored_lba": a,
                        "size": s,
                        "disc_lba": a - bias,
                        "files": [f.path for f in named.get(i, [])],
                    })  # fmt: skip
                tables.append(table)
    return distinct(tables)


def runs(phases, step: int, max_gap: int):
    for positions in phases:
        run: list[int] = []
        for i in positions:
            if run and (i - run[-1]) // step > max_gap + 1:
                yield run
                run = []
            run.append(i)
        if run:
            yield run


def distinct(tables: list[Table]) -> list[Table]:
    """The strongest reading of each stretch of memory: a table that overlaps one naming more
    files is dropped (the same entries read with a wider stride, another size unit, or a bias that
    lands on a neighbor of the same size), and so is one where most entries name nothing."""
    tables.sort(key=lambda t: (-t.matched, len(t.entries), UNITS.index(t.unit), t.address))
    kept: list[Table] = []
    for t in tables:
        end = t.address + len(t.entries) * t.stride
        if t.matched * 10 < len(t.entries) * DENSITY:
            continue
        if any(t.address < k.address + len(k.entries) * k.stride and k.address < end for k in kept):
            continue
        kept.append(t)
    return sorted(kept, key=lambda t: t.address)


def report(tables: list[Table], entries: bool) -> str:
    if not tables:
        return "No table of disc file extents found."
    lines = []
    for t in tables:
        lines.append(
            f"0x{t.address:08X}: {len(t.entries)} entries, {t.matched} name a disc file; {t.layout()}"
        )
        if entries:
            for e in t.entries:
                named = ", ".join(printable(p) for p in e["files"]) or "-"
                lines.append(
                    f"  [{e['index']}] {e['address']} lba {e['disc_lba']} size {e['size']}: {named}"
                )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite playstation lba-table",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("program", type=Path, nargs="?", help="PS-X EXE or RAM dump")
    disc = p.add_mutually_exclusive_group(required=True)
    disc.add_argument("--disc", type=Path, help="disc image: .cue, raw .bin or .iso")
    disc.add_argument("--files", type=Path, help="listing: '<lba> <size> <path>' a line")
    p.add_argument(
        "--list", action="store_true", help="print the disc's listing (that format) and stop"
    )
    p.add_argument(
        "--base",
        type=lambda v: int(v, 16),
        help="hex address of the program's first byte: a RAM dump's (default 80000000); "
        "given for a PS-X EXE, its header is read as data too",
    )
    p.add_argument("--min-entries", type=int, default=8, help="smallest table reported")
    p.add_argument("--max-gap", type=int, default=2, help="entries in a row naming no file")
    p.add_argument("--max-bias", type=int, default=512, help="largest stored-LBA offset")
    p.add_argument("--summary", action="store_true", help="the tables only, not each entry")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    if min(args.min_entries, args.max_gap + 1, args.max_bias + 1) < 1:
        p.error("limits must not be negative, --min-entries positive")
    try:
        if args.disc:
            files = iso9660.listing(iso9660.open_image(args.caller_cwd / args.disc))
        else:
            path = args.caller_cwd / args.files
            files = iso9660.read_listing(path.read_text(encoding="utf-8"), str(args.files))
        if args.list:
            for f in sorted(files, key=lambda f: f.lba):
                print(f"{f.lba} {f.size} {printable(f.path)}")
            return 0
        if args.program is None:
            p.error("give the program (PS-X EXE or RAM dump), or --list")
        base, data = program(args.caller_cwd / args.program, args.base)
    except (OSError, ValueError) as exc:
        p.exit(1, f"lba-table: {exc}\n")
    tables = find(base, data, files, args.min_entries, args.max_gap, args.max_bias)
    if args.json:
        print(json.dumps([t.summary() for t in tables], indent=2))
    else:
        print(report(tables, not args.summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
