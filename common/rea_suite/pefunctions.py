"""Function starts in a PE image: what names the function a scan's hit lies in.

One source answers, the first that applies:

- table: address/name TSVs a port or Ghidra wrote (`rea-ghidra functions`, a port's
  `function_entries.tsv` or `functions.tsv`), given with `--functions`. The address column is
  the first of `entry`, `address`, `va`, `rva`, `start` in the header (else the first column),
  hexadecimal, a VA at or above the image base; `name` and `size` (decimal bytes) are read when
  present. A
  `game` column picks rows with `--game`. Several tables merge: one may give the starts and
  another the names. A Ghidra control-flow export (`F <entry> <name> ...` with `R <first>
  <last>` body ranges under it, the `<binary>.cfg.txt` some ports write) is read too: its
  ranges give each function's body, chunks elsewhere included.
- unwind: the x64 unwind table (`Image.function_at`), chained entries followed.
- heuristic: in an image with no unwind table (x86) and no table given: the entry point,
  exports and TLS callbacks, rel32 call targets (called from two sites, or right after padding
  or a `ret`), `push ebp; mov ebp, esp` after padding or a `ret`, and the first byte after a
  `ret` followed by int3/nop padding. A guess: a function reached only through a pointer and
  without a frame is missed, bytes in data that look like a call can add a start. Rows carry
  `function_source: "heuristic"` so a reader never takes one for a fact.

With a table or the heuristic the containing function is the nearest start at or below the
address in the same section, and when the table gives the function's size (Ghidra's body, in
bytes) only if the address is within it: an address past it lies in no function the table
names (a function Ghidra split into chunks elsewhere reads as none rather than a wrong one).
A partial table (named functions only) attributes code between them to the start before it.
"""

from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from .pemodel import Image

ADDRESS_COLUMNS = ("entry", "address", "va", "rva", "start")
PADDING = (0xCC, 0x90)
CALL = re.compile(rb"\xe8", re.DOTALL)
FRAME = re.compile(rb"\x55(?:\x8b\xec|\x89\xe5)", re.DOTALL)
RET_PADDING = re.compile(rb"(?:\xc3|\xc2..)[\xcc\x90]+", re.DOTALL)


@dataclass(frozen=True)
class Function:
    start: int  # RVA
    name: str | None
    source: str  # "table", "unwind" or "heuristic"


def parse_address(text: str) -> int:
    text = text.strip()
    return int(text[2:] if text.lower().startswith("0x") else text, 16)


CFG_FUNCTION = re.compile(r"F [0-9A-Fa-f]+(?: |$)")


def is_cfg(text: str) -> bool:
    """A Ghidra control-flow export: its first line names a function (`F <entry> <name>`)."""
    first = next((line for line in text.splitlines() if line.strip()), "")
    return CFG_FUNCTION.match(first) is not None


def read_cfg(text: str) -> list[tuple[int, str | None, list[tuple[int, int]]]]:
    """(entry, name or None, body ranges as (first, end exclusive)) for each `F` line of a
    control-flow export; `R first last` lines (inclusive) under it are its body. Other lines
    (`J` jump tables, `D` code pointers in data) are not functions and are left out."""
    rows: list[tuple[int, str | None, list[tuple[int, int]]]] = []
    for line in text.splitlines():
        parts = line.split()
        try:
            if parts and parts[0] == "F" and len(parts) >= 2:
                rows.append((int(parts[1], 16), parts[2] if len(parts) > 2 else None, []))
            elif parts and parts[0] == "R" and len(parts) >= 3 and rows:
                rows[-1][2].append((int(parts[1], 16), int(parts[2], 16) + 1))
        except ValueError:
            continue
    return rows


def read_table(path: Path, game: str | None = None) -> list[tuple[int, str | None, int | None]]:
    """(address as written, name or None, size or None) for each row of a function TSV; for a
    control-flow export the size is that of the body range starting at the entry."""
    text = Path(path).read_text(encoding="utf-8")
    if is_cfg(text):
        return [
            (entry, name, next((end - lo for lo, end in ranges if lo == entry), None))
            for entry, name, ranges in read_cfg(text)
        ]
    rows = []
    columns: dict[str, int] | None = None
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if columns is None:
            try:
                parse_address(cells[0])
                columns = {}
            except ValueError:
                columns = {c.strip().lower(): i for i, c in enumerate(cells)}
                continue
        at = next((columns[c] for c in ADDRESS_COLUMNS if c in columns), 0)
        game_at = columns.get("game")
        if game is not None and game_at is not None and cell(cells, game_at) != game:
            continue
        try:
            address = parse_address(cells[at])
        except (ValueError, IndexError):
            continue
        if columns:
            name, size = cell(cells, columns.get("name")), cell(cells, columns.get("size"))
        else:  # no header: address, then a name unless the column holds numbers
            name, size = cell(cells, 1), None
            if name and name.isdigit():
                name = None
        rows.append((address, name, int(size) if size and size.isdigit() else None))
    return rows


def cell(cells: list[str], index: int | None) -> str | None:
    if index is None or index >= len(cells):
        return None
    return cells[index].strip() or None


class Functions:
    """The function starts of one image, from tables, the unwind table or the heuristic."""

    def __init__(
        self,
        image: Image,
        starts: dict[int, str | None] | None = None,
        sizes: dict[int, int] | None = None,
        ranges: dict[int, list[tuple[int, int]]] | None = None,
    ):
        self.image = image
        self.sizes = sizes or {}
        self.ranges = ranges or {}  # start -> body ranges (RVAs, end exclusive), from a cfg
        if starts is not None:
            self.source = "table"
        elif image.runtime_functions:
            self.source = "unwind"
        else:
            self.source = "heuristic"
            starts = dict.fromkeys(heuristic_starts(image))
        self.names: dict[int, str | None] = dict(starts or {})
        for export in image.exports:  # an export is a start, and names one
            if export.name and image.is_code(export.rva) and not self.names.get(export.rva):
                self.names[export.rva] = export.name
        self.starts = sorted(self.names)
        self._start_set = set(self.starts)

    @classmethod
    def from_tables(cls, image: Image, paths: list[Path], game: str | None = None) -> Functions:
        starts: dict[int, str | None] = {}
        sizes: dict[int, int] = {}
        ranges: dict[int, list[tuple[int, int]]] = {}
        for path in paths:
            text = Path(path).read_text(encoding="utf-8")
            if is_cfg(text):
                for entry, _name, body in read_cfg(text):
                    if body:
                        ranges[image.address(entry)] = [
                            (image.address(lo), image.address(end)) for lo, end in sorted(body)
                        ]
            for address, name, size in read_table(path, game):
                rva = image.address(address)
                if image.section_at(rva) is None:
                    continue
                if name or rva not in starts:
                    starts[rva] = name or starts.get(rva)
                if size:
                    sizes[rva] = size
        return cls(image, starts, sizes, ranges)

    def at(self, rva: int) -> Function | None:
        """The function rva lies in: the nearest start at or below it in the same section."""
        if self.source == "unwind":
            found = self.image.function_at(rva)
            return Function(found[0], self.name_of(found[0]), "unwind") if found else None
        index = bisect.bisect_right(self.starts, rva) - 1
        if index < 0:
            return None
        start = self.starts[index]
        if self.image.section_at(start) is not self.image.section_at(rva):
            return None
        if start in self.sizes and rva >= start + self.sizes[start]:
            return None  # past the body the table gives: in no function it names
        return Function(start, self.names.get(start), self.source)

    def is_start(self, rva: int) -> bool:
        if rva in self._start_set:
            return True
        found = self.image.function_at(rva) if self.source == "unwind" else None
        return found is not None and found[0] == rva

    def name_of(self, rva: int) -> str | None:
        return self.names.get(rva)

    def address_of(self, name: str) -> int | None:
        return next((rva for rva, n in self.names.items() if n == name), None)

    def end_of(self, start: int) -> int:
        """Where the function starting at start ends: the next start, the end of its unwind
        entry, or the end of its section's bytes; at most 64 KiB on."""
        section = self.image.section_at(start)
        limit = start + min(self.sizes.get(start, 0x10000), 0x10000)
        if section is not None:
            limit = min(limit, section.rva + section.data_size)
        if self.source == "unwind":
            found = self.image.function_at(start)
            return min(limit, found[1]) if found and found[0] == start else limit
        index = bisect.bisect_right(self.starts, start)
        return min(limit, self.starts[index]) if index < len(self.starts) else limit

    def entries(self) -> list[int]:
        """Every function start this map knows: the table's or the heuristic's, or the unwind
        table's primary functions (chained parts folded into theirs) and the exports."""
        if self.source != "unwind":
            return list(self.starts)
        found = set(self.starts)
        for begin, _end, _unwind in self.image.runtime_functions:
            primary = self.image.function_at(begin)
            if primary is not None:
                found.add(primary[0])
        return sorted(found)

    def body(self, start: int) -> list[tuple[int, int]]:
        """The function's bytes as RVA ranges (end exclusive): a control-flow export's body
        ranges, else from the start to end_of(start)."""
        return self.ranges.get(start) or [(start, self.end_of(start))]


def of(image: Image) -> Functions:
    """The image's function map: the one a caller set (from tables), else the default."""
    if image.functions is None:
        image.functions = Functions(image)
    return image.functions


def heuristic_starts(image: Image) -> set[int]:
    """Probable function starts from the bytes alone (see the module's description)."""
    found: set[int] = set()
    for rva in [image.entry, *(e.rva for e in image.exports)]:
        if image.is_code(rva):
            found.add(rva)
    if image.tls:
        for va in image.tls["callbacks"]:
            if image.is_code(va - image.base):
                found.add(va - image.base)
    sections = image.code_sections()
    calls: dict[int, int] = {}
    for section in sections:
        data = image.section_bytes(section)
        for match in CALL.finditer(data):
            at = match.start()
            if at + 5 > len(data):
                break
            target = section.rva + at + 5 + struct.unpack_from("<i", data, at + 1)[0]
            calls[target] = calls.get(target, 0) + 1
        for match in FRAME.finditer(data):
            if boundary(data, match.start()):
                found.add(section.rva + match.start())
        for match in RET_PADDING.finditer(data):
            end = match.end()
            if end + 2 <= len(data) and data[end] not in PADDING and data[end : end + 2] != b"\0\0":
                found.add(section.rva + end)  # not the zeros that fill a section's tail
    for section in sections:
        data = image.section_bytes(section)
        for target, count in calls.items():
            at = target - section.rva
            if 0 <= at < len(data) and (count > 1 or boundary(data, at)):
                found.add(target)
    return found


def boundary(data: bytes, at: int) -> bool:
    """A function can start at `at`: the section starts there, or padding or a ret ends there."""
    if at == 0:
        return True
    before = data[at - 1]
    return before in PADDING or before == 0xC3 or (at >= 3 and data[at - 3] == 0xC2)
