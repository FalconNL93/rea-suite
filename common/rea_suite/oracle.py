"""The oracle: named memory regions read at sync points of the original running in an emulator, for
comparing a port's run against the original's.

  rea-suite oracle run --target gdb://HOST:PORT --arch ARCH --regions FILE [--sync NAME@TRIGGER]
                                                    reads the regions at each sync point into a
                                                    sequence file (regions.jsonl in the run's folder)
  rea-suite oracle compare A B [--regions FILE]     the first difference between two sequences

One format for every emulator: the regions file (TOML, or JSON for a .json name) names ranges of
memory and the sync points that read them; the sequence file is JSON lines, one line per region
read, and is also what a port writes from its own run of the same scripted input. Comparing stops at
the first sync point whose regions differ, as remc2's regression test does against its DOSBox-X fork.
docs/PORT-TOOLS.md ("The oracle") specifies both.

The pieces, each behind a seam of its own:

- the format (this module): Region, the regions file through a Dialect (the addresses and triggers
  one family of emulators understands), SequenceWriter, read_sequence and first_difference;
- EmulatorTarget, the interface a back end implements: connect, set and clear breakpoints, resume
  until it stops, read memory, close. oracle_gdb.py speaks GDB's remote protocol (xemu, Dolphin,
  DuckStation, PCSX-Redux, melonDS and the other stubs), oracle_ppsspp.py PPSSPP's WebSocket
  debugger;
- run_syncs, the driver that takes a target to each sync point's trigger and reads its regions.

DOSBox-X (dosbox.py, dosbox_regions.py) writes the same format with a dialect of its own (INT
calls, file opens, SEL:OFF addresses) and drives DOSBox-X's debugger through its own tracer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

FORMAT = "rea-regions"
VERSION = 1
INLINE_MAX = 4096  # bytes a line carries as hex; a longer region goes to the sidecar
TYPES = {"bytes": 1, "ascii": 1, "u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4}
ENDIANS = ("little", "big")
ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work" / "oracle"
MAX_REGION = 1 << 28  # 256 MiB, as DOSBox-X's dumps


# --- the regions file -------------------------------------------------------------------------------


class BadRegions(ValueError):
    """A regions file that does not follow the format."""


@dataclass(frozen=True)
class Region:
    """A named range of memory: an address as the dialect reads it, a length, and for display a
    type and its byte order."""

    name: str
    address: Any
    length: int
    type: str = "bytes"
    ignore: tuple[tuple[int, int], ...] = ()  # (offset, length) a comparison skips
    endian: str = "little"


class Dialect(Protocol):
    """What one family of emulators makes of a regions file: its addresses, its triggers and any
    sync point options of its own. parse_regions does the rest, the same for all of them."""

    sync_keys: frozenset[str]  # keys a [[sync]] may have beyond name, at and regions

    def address(self, text: str) -> Any: ...

    def trigger(self, text: str) -> Any: ...

    def options(self, name: str, trigger: Any, spec: dict) -> dict:
        """The sync point's own options, checked (before its regions are)."""
        ...

    def sync(self, name: str, trigger: Any, regions: list[Region], options: dict) -> Any: ...


@dataclass
class RegionsFile:
    regions: dict[str, Region]
    syncs: list


def parse_length(text: str) -> int:
    t = text.strip().lower()
    try:
        value = int(t, 16) if t.startswith("0x") else int(t)
    except ValueError:
        raise ValueError(f"length {text!r}: decimal, or hex with 0x") from None
    if not 0 < value <= MAX_REGION:
        raise ValueError(f"length {text!r}: from 1 byte to 256 MiB")
    return value


def _length(value, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise BadRegions(f"{what}: a number, or a string in decimal or 0x hex")
    return parse_length(str(value))


def _offset(value, what: str) -> int:
    text = str(value).strip().lower()
    try:
        offset = int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        raise ValueError(f"{what}: an offset in decimal or 0x hex") from None
    if offset < 0:
        raise ValueError(f"{what}: an offset is at least 0")
    return offset


def parse_region(name: str, spec, dialect: Dialect) -> Region:
    where = f"region {name!r}"
    if not isinstance(spec, dict):
        raise BadRegions(f"{where}: a table with addr and len")
    unknown = set(spec) - {"addr", "len", "type", "ignore", "endian"}
    if unknown:
        raise ValueError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    if "addr" not in spec or "len" not in spec:
        raise ValueError(f"{where}: needs addr and len")
    address = dialect.address(str(spec["addr"]))
    length = _length(spec["len"], f"{where} len")
    kind = spec.get("type", "bytes")
    if kind not in TYPES:
        raise ValueError(f"{where}: type is one of {', '.join(TYPES)}")
    if length % TYPES[kind]:
        raise ValueError(f"{where}: len {length} is not a whole number of {kind}")
    endian = spec.get("endian", "little")
    if endian not in ENDIANS:
        raise ValueError(f"{where}: endian is little or big")
    ignore = []
    for item in spec.get("ignore", []):
        text = str(item)
        if ":" not in text:
            raise ValueError(f"{where}: ignore takes OFFSET:LEN items")
        off_text, len_text = text.split(":", 1)
        off = _offset(off_text, f"{where} ignore {text!r}")
        size = _length(len_text, f"{where} ignore {text!r}")
        if off + size > length:
            raise ValueError(f"{where}: ignore {text!r} runs past the region's {length} bytes")
        ignore.append((off, size))
    return Region(name, address, length, kind, tuple(ignore), endian)


def parse_regions(data: dict, dialect: Dialect, require_syncs: bool = True) -> RegionsFile:
    """The regions file's contents (a parsed TOML or JSON document), read by a dialect."""
    if not isinstance(data, dict):
        raise BadRegions("regions file: a table with [regions] and [[sync]]")
    unknown = set(data) - {"regions", "sync"}
    if unknown:
        raise ValueError(f"regions file: unknown key(s) {', '.join(sorted(unknown))}")
    table = data.get("regions")
    if not isinstance(table, dict) or not table:
        raise ValueError("regions file: no [regions]")
    regions = {name: parse_region(name, spec, dialect) for name, spec in table.items()}
    syncs: list = []
    for spec in data.get("sync", []):
        syncs.append(parse_sync(spec, regions, dialect, [s.name for s in syncs]))
    if require_syncs and not syncs:
        raise ValueError("regions file: no [[sync]]")
    return RegionsFile(regions, syncs)


def parse_sync(spec, regions: dict[str, Region], dialect: Dialect, taken: list[str]):
    """One [[sync]] table: its name, trigger, the dialect's options and its regions."""
    if not isinstance(spec, dict) or "name" not in spec or "at" not in spec:
        raise ValueError("regions file: each [[sync]] needs name and at")
    name = str(spec["name"])
    unknown = [k for k in spec if k not in ("name", "at", "regions") and k not in dialect.sync_keys]
    if unknown:
        raise ValueError(f"sync {name!r}: unknown key(s) {', '.join(sorted(unknown))}")
    if name in taken:
        raise ValueError(f"sync {name!r}: named twice")
    trigger = dialect.trigger(str(spec["at"]))
    options = dialect.options(name, trigger, spec)
    names = spec.get("regions", list(regions))
    if not isinstance(names, list) or not names:
        raise ValueError(f"sync {name!r}: regions is a list of region names")
    missing = [n for n in names if n not in regions]
    if missing:
        raise ValueError(f"sync {name!r}: no region {', '.join(map(repr, missing))}")
    return dialect.sync(name, trigger, [regions[n] for n in names], options)


def read_document(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{path}: {exc}") from None


def load_regions(path: Path, dialect: Dialect, require_syncs: bool = True) -> RegionsFile:
    data = read_document(path)
    try:
        return parse_regions(data, dialect, require_syncs)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from None


# --- the emulator dialect: breakpoints and time -----------------------------------------------------


@dataclass(frozen=True)
class Address:
    """A flat address in the target's own address space (a virtual address, as its debugger
    takes it)."""

    text: str
    value: int


def parse_address(text: str) -> Address:
    t = text.strip()
    try:
        value = int(t[2:] if t.lower().startswith("0x") else t, 16)
        if not 0 <= value < 1 << 64:
            raise ValueError
    except ValueError:
        raise ValueError(f"address {text!r}: an address in hex (0x optional)") from None
    return Address(t, value)


@dataclass(frozen=True)
class Trigger:
    """When a sync point's regions are read: on connecting (`start`), when the CPU reaches an
    address (`pc=ADDR`, a software breakpoint; `hw=ADDR`, a hardware one), or at a time in
    seconds after connecting, host clock (`t=SECONDS`)."""

    kind: str  # start, pc, hw, time
    text: str
    address: int | None = None
    seconds: float | None = None

    @property
    def breakpoint(self) -> tuple[int, bool] | None:
        """(address, hardware) for a breakpoint trigger."""
        if self.kind in ("pc", "hw"):
            return self.address, self.kind == "hw"  # type: ignore[return-value]
        return None


def parse_trigger(text: str) -> Trigger:
    t = text.strip()
    low = t.lower()
    if low == "start":
        return Trigger("start", "start")
    if low.startswith("t="):
        try:
            seconds = float(low[2:])
        except ValueError:
            raise ValueError(f"trigger {text!r}: t= takes seconds") from None
        if seconds < 0:
            raise ValueError(f"trigger {text!r}: a time is at least 0")
        return Trigger("time", t, seconds=seconds)
    for kind in ("pc", "hw"):
        if low.startswith(kind + "="):
            return Trigger(kind, t, address=parse_address(t[3:]).value)
    raise ValueError(f"trigger {text!r}: one of pc=ADDR, hw=ADDR, t=SECONDS, start")


@dataclass
class Sync:
    """A sync point: when its trigger comes, its regions are read in order into the sequence.
    `repeat` makes every hit of a breakpoint one, not only the first."""

    name: str
    trigger: Trigger
    regions: list[Region]
    repeat: bool = False
    done: bool = False
    hits: int = 0

    @property
    def text(self) -> str:
        return f"sync {self.name}@{self.trigger.text}"


class EmulatorDialect:
    """Regions files for the emulator back ends: flat hex addresses and breakpoint triggers."""

    sync_keys = frozenset({"repeat"})

    def address(self, text: str) -> Address:
        return parse_address(text)

    def trigger(self, text: str) -> Trigger:
        return parse_trigger(text)

    def options(self, name: str, trigger: Trigger, spec: dict) -> dict:
        repeat = spec.get("repeat", False)
        if not isinstance(repeat, bool):
            raise BadRegions(f"sync {name!r}: repeat is true or false")
        if repeat and trigger.breakpoint is None:
            raise ValueError(f"sync {name!r}: repeat needs a pc= or hw= trigger")
        return {"repeat": repeat}

    def sync(self, name: str, trigger: Trigger, regions: list[Region], options: dict) -> Sync:
        return Sync(name, trigger, regions, **options)


class TextDialect:
    """Any regions file, for `compare`: addresses and triggers kept as text, every option taken."""

    class _Every(frozenset):
        def __contains__(self, key) -> bool:
            return True

    sync_keys = _Every()

    def address(self, text: str) -> str:
        return text

    def trigger(self, text: str) -> str:
        return text

    def options(self, name: str, trigger: str, spec: dict) -> dict:
        return {}

    def sync(self, name: str, trigger: str, regions: list[Region], options: dict) -> tuple:
        return (name, trigger, regions)


EMULATOR = EmulatorDialect()


def parse_sync_option(text: str, regions: dict[str, Region], taken: list[str]) -> Sync:
    """--sync NAME@TRIGGER[@REGION,REGION...]: a sync point given on the command line."""
    parts = text.split("@")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
        raise ValueError(f"--sync {text!r}: NAME@TRIGGER, optionally @REGION,REGION")
    spec: dict = {"name": parts[0], "at": parts[1]}
    if len(parts) == 3:
        spec["regions"] = [r for r in parts[2].split(",") if r]
    try:
        return parse_sync(spec, regions, EMULATOR, taken)
    except ValueError as exc:
        raise ValueError(f"--sync {text!r}: {exc}") from None


# --- the sequence file ------------------------------------------------------------------------------


class SequenceWriter:
    """One sequence file: a header line, then a line per region read, in order; regions longer
    than INLINE_MAX go to the sidecar (the same name, .bin) and the line has their offset."""

    def __init__(self, path: Path, producer: str, inline_max: int = INLINE_MAX):
        self.path = path
        self.sidecar = path.with_suffix(".bin")
        self.inline_max = inline_max
        self.index = 0  # the next sync point's
        self.file = path.open("w", encoding="utf-8")
        self.bin = None
        self._line({"format": FORMAT, "version": VERSION, "producer": producer,
                    "sidecar": self.sidecar.name})  # fmt: skip

    def _line(self, record: dict) -> None:
        self.file.write(json.dumps(record) + "\n")
        self.file.flush()

    def region(
        self,
        sync: str,
        region: Region,
        data: bytes | None,
        error: str | None = None,
        hit: int | None = None,
        **detail,
    ) -> dict:
        """A region read at the current sync point (data), or why it could not be (error)."""
        line: dict = {"index": self.index, "sync": sync}
        if hit is not None:
            line["hit"] = hit
        line.update(region=region.name, len=region.length)
        if region.type != "bytes":
            line["type"] = region.type
        if region.endian != "little":
            line["endian"] = region.endian
        if data is not None and len(data) != region.length:
            error = f"read {len(data)} of {region.length} bytes"
        if error is not None:
            line["error"] = error
        else:
            assert data is not None
            line["sha256"] = hashlib.sha256(data).hexdigest()
            if len(data) <= self.inline_max:
                line["hex"] = data.hex()
            else:
                if self.bin is None:
                    self.bin = self.sidecar.open("wb")
                line["offset"] = self.bin.tell()
                self.bin.write(data)
                self.bin.flush()
        line.update(detail)
        self._line(line)
        return line

    def next(self) -> None:
        """The current sync point is complete."""
        self.index += 1

    def close(self) -> None:
        self.file.close()
        if self.bin:
            self.bin.close()


class BadSequence(ValueError):
    """A sequence file that does not follow the format."""


@dataclass
class Entry:
    region: str
    length: int
    data: bytes | None
    error: str | None
    type: str | None
    line: int
    endian: str | None = None


@dataclass
class Point:
    index: int
    sync: str
    hit: int | None
    entries: list[Entry] = field(default_factory=list)


def read_sequence(path: Path) -> tuple[dict, list[Point]]:
    """The header and the sync points, in order; BadSequence where the file breaks the format."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise BadSequence(f"{path}: {exc}") from None

    def bad(number: int, why: str) -> BadSequence:
        return BadSequence(f"{path}:{number}: {why}")

    records = []
    for number, text in enumerate(lines, 1):
        if not text.strip():
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError as exc:
            raise bad(number, f"not JSON ({exc.msg})") from None
        if not isinstance(record, dict):
            raise bad(number, "not a JSON object")
        records.append((number, record))
    if not records:
        raise BadSequence(f"{path}: empty")
    number, header = records[0]
    if header.get("format") != FORMAT:
        raise bad(number, f'the first line is not the header ({{"format": "{FORMAT}", ...}})')
    if header.get("version") != VERSION:
        raise bad(number, f"version {header.get('version')!r}; this reader knows {VERSION}")
    sidecar_data: bytes | None = None
    points: list[Point] = []
    for number, r in records[1:]:
        for key, kind in (("index", int), ("sync", str), ("region", str), ("len", int)):
            if not isinstance(r.get(key), kind) or isinstance(r.get(key), bool):
                raise bad(number, f"{key} missing or not {kind.__name__}")
        if r["len"] < 1:
            raise bad(number, "len is at least 1")
        if not points or points[-1].index != r["index"]:
            if points and r["index"] < points[-1].index:
                raise bad(number, f"index {r['index']} after {points[-1].index}")
            points.append(Point(r["index"], r["sync"], r.get("hit")))
        point = points[-1]
        if r["sync"] != point.sync:
            raise bad(number, f"sync {r['sync']!r} in sync point {point.index} ({point.sync!r})")
        if any(e.region == r["region"] for e in point.entries):
            raise bad(number, f"region {r['region']!r} twice in sync point {point.index}")
        data = None
        error = r.get("error")
        if error is None:
            if "hex" in r:
                try:
                    data = bytes.fromhex(r["hex"])
                except (TypeError, ValueError):
                    raise bad(number, "hex is not hex") from None
            elif "offset" in r:
                if sidecar_data is None:
                    name = header.get("sidecar")
                    if not isinstance(name, str):
                        raise bad(number, "an offset, but the header names no sidecar")
                    try:
                        sidecar_data = (path.parent / name).read_bytes()
                    except OSError as exc:
                        raise bad(number, f"sidecar: {exc}") from None
                off = r["offset"]
                if not isinstance(off, int) or off < 0 or off + r["len"] > len(sidecar_data):
                    raise bad(number, "offset outside the sidecar")
                data = sidecar_data[off : off + r["len"]]
            else:
                raise bad(number, "neither hex, offset nor error")
            if len(data) != r["len"]:
                raise bad(number, f"{len(data)} bytes, len says {r['len']}")
            if "sha256" in r and hashlib.sha256(data).hexdigest() != r["sha256"]:
                raise bad(number, "the bytes do not match sha256")
        endian = r.get("endian")
        if endian is not None and endian not in ENDIANS:
            raise bad(number, "endian is little or big")
        text = str(error) if error else None
        point.entries.append(
            Entry(r["region"], r["len"], data, text, r.get("type"), number, endian)
        )
    return header, points


# --- comparing two sequences ------------------------------------------------------------------------


def hex_rows(data: bytes, start: int, end: int, mark: int) -> list[str]:
    """Rows of 16 bytes from start to end, the byte at mark in brackets."""
    rows = []
    for row in range(start - start % 16, end, 16):
        cells = []
        for i in range(row, row + 16):
            if i < start or i >= end or i >= len(data):
                cells.append("  ")
            else:
                cells.append(f"{data[i]:02x}")
        seps = [" "] * 17  # the separator before each cell, and after the last
        if row <= mark < row + 16:
            seps[mark - row], seps[mark - row + 1] = "[", "]"
        text = "".join(sep + cell for sep, cell in zip(seps, cells, strict=False)) + seps[16]
        rows.append(f"  {row:08x} {text.rstrip()}")
    return rows


def typed_value(
    data: bytes, offset: int, kind: str | None, endian: str | None = None
) -> str | None:
    """The element of a typed region that holds the byte at offset, as its type reads it."""
    if kind not in TYPES or kind == "bytes":
        return None
    if kind == "ascii":
        return repr(data[max(0, offset - 16) : offset + 16].decode("latin-1"))
    size = TYPES[kind]
    start = offset - offset % size
    chunk = data[start : start + size]
    if len(chunk) < size:
        return None
    order = "big" if endian == "big" else "little"
    value = int.from_bytes(chunk, order, signed=kind.startswith("i"))
    return f"[{start // size}] = {value}"


def ignored(offset: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(off <= offset < off + size for off, size in ranges)


@dataclass
class Difference:
    """Where two sequences part, in words, with the bytes around it."""

    text: list[str]


def first_difference(
    a: list[Point],
    b: list[Point],
    regions: RegionsFile | None = None,
    context: int = 16,
    names: tuple[str, str] = ("A", "B"),
) -> tuple[Difference | None, int]:
    """The first difference and the number of sync points that agreed before it."""
    na, nb = names
    wanted = regions.regions if regions else None
    for count, (pa, pb) in enumerate(zip(a, b, strict=False)):
        where = f"sync point {count} ({pa.sync}"
        where += f" #{pa.hit})" if pa.hit is not None else ")"
        if pa.sync != pb.sync:
            return Difference(
                [f"sync point {count}: {na} has {pa.sync!r}, {nb} has {pb.sync!r}"]
            ), count
        eb = {e.region: e for e in pb.entries}
        ea = {e.region: e for e in pa.entries}
        for entry in pa.entries:
            if wanted is not None and entry.region not in wanted:
                continue
            other = eb.get(entry.region)
            if other is None:
                return Difference([f"{where}: {nb} has no region {entry.region!r}"]), count
            diff = compare_entry(entry, other, wanted, context, names)
            if diff:
                return Difference(
                    [f"{where}, region {entry.region!r}: {diff[0]}", *diff[1:]]
                ), count
        for entry in pb.entries:
            if entry.region not in ea and (wanted is None or entry.region in wanted):
                return Difference([f"{where}: {na} has no region {entry.region!r}"]), count
    if len(a) != len(b):
        shorter, longer, ns, nl = (a, b, na, nb) if len(a) < len(b) else (b, a, nb, na)
        nxt = longer[len(shorter)]
        return Difference(
            [
                (
                    f"{ns} ends after {len(shorter)} sync point(s); {nl} goes on with "
                    f"{nxt.sync!r} (sync point {len(shorter)})"
                )
            ]
        ), len(shorter)
    return None, len(a)


def compare_entry(
    ea: Entry,
    eb: Entry,
    wanted: dict[str, Region] | None,
    context: int,
    names: tuple[str, str],
) -> list[str]:
    na, nb = names
    for entry, name in ((ea, na), (eb, nb)):
        if entry.error:
            return [f"{name} could not read it: {entry.error}"]
    assert ea.data is not None and eb.data is not None
    if ea.length != eb.length:
        return [f"{na} has {ea.length} bytes, {nb} {eb.length}"]
    region = wanted.get(ea.region) if wanted else None
    skip = region.ignore if region else ()
    kind = region.type if region else (ea.type or eb.type)
    endian = region.endian if region else (ea.endian or eb.endian)
    differing = [i for i in range(ea.length) if ea.data[i] != eb.data[i] and not ignored(i, skip)]
    if not differing:
        return []
    first = differing[0]
    lo, hi = max(0, first - context), min(ea.length, first + context + 1)
    out = [f"offset {first:#x} ({first}), {len(differing)} byte(s) differ"]
    for entry, name in ((ea, na), (eb, nb)):
        value = typed_value(entry.data, first, kind, endian)  # type: ignore[arg-type]
        out.append(f" {name}:" + (f" {kind} {value}" if value is not None else ""))
        out += hex_rows(entry.data, lo, hi, first)  # type: ignore[arg-type]
    return out


def compare_files(
    a: Path, b: Path, regions: RegionsFile | None, context: int, labels: tuple[str, str], prog: str
) -> int:
    """Two sequence files: 0 equal, 1 a difference, 2 bad input."""
    try:
        (_, pa), (_, pb) = (read_sequence(p) for p in (a, b))
    except (OSError, ValueError) as exc:
        print(f"{prog}: {exc}", file=sys.stderr)
        return 2
    diff, agreed = first_difference(pa, pb, regions, context)
    print(f"A: {labels[0]}\nB: {labels[1]}")
    if diff is None:
        print(f"equal: {agreed} sync point(s)")
        return 0
    print(f"{agreed} sync point(s) equal, then:")
    for line in diff.text:
        print(line)
    return 1


# --- the emulator interface -------------------------------------------------------------------------


class TargetError(OSError):
    """The emulator refused a request or the connection broke."""


@dataclass
class Stop:
    """Where the target stopped: at a breakpoint (`break`), because the driver asked it to
    (`timeout`), for a reason of its own (`signal`, `stepping`), or for good (`exited`)."""

    reason: str
    pc: int | None = None
    detail: str = ""


class EmulatorTarget(ABC):
    """One emulator's debugger, as the oracle needs it. A back end implements this and nothing
    else; run_syncs does the rest. The target is stopped between calls."""

    producer: str  # the sequence header's producer

    @abstractmethod
    def connect(self) -> Stop:
        """Attach and stop the CPU where it is; where that is."""

    @abstractmethod
    def set_breakpoint(self, address: int, hardware: bool = False) -> None: ...

    @abstractmethod
    def clear_breakpoint(self, address: int, hardware: bool = False) -> None: ...

    @abstractmethod
    def resume(self, timeout: float | None) -> Stop:
        """Run until the CPU stops; past `timeout` seconds stop it and say `timeout`. Resuming
        at a breakpoint's address runs that instruction, not the breakpoint again."""

    @abstractmethod
    def read(self, address: int, length: int) -> bytes:
        """Memory at an address, as the CPU sees it; TargetError when it cannot be read."""

    @abstractmethod
    def close(self) -> None:
        """Clear the breakpoints set, leave the emulator running and disconnect."""


Backend = Callable[[str, argparse.Namespace], EmulatorTarget]


def backends() -> dict[str, Backend]:
    """The target schemes and the back end for each (imported only when used)."""

    def gdb(where: str, args) -> EmulatorTarget:
        from rea_suite import oracle_gdb

        return oracle_gdb.GdbTarget.from_url(where, args.arch, args.timeout)

    def ppsspp(where: str, args) -> EmulatorTarget:
        from rea_suite import oracle_ppsspp

        return oracle_ppsspp.PpssppTarget.from_url(where, args.timeout)

    return {"gdb": gdb, "ppsspp": ppsspp}


def open_target(url: str, args) -> EmulatorTarget:
    scheme, sep, _ = url.partition("://")
    table = backends()
    if not sep or scheme not in table:
        raise ValueError(f"--target {url!r}: one of {', '.join(s + '://HOST:PORT' for s in table)}")
    return table[scheme](url, args)


def host_port(url: str, default_host: str = "127.0.0.1") -> tuple[str, int]:
    """HOST:PORT after the scheme ([::1]:PORT for IPv6)."""
    rest = url.partition("://")[2].split("/", 1)[0]
    host, sep, port = rest.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"{url!r}: HOST:PORT after the scheme")
    return (host.strip("[]") or default_host), int(port)


# --- the driver -------------------------------------------------------------------------------------


@dataclass
class Outcome:
    points: int = 0
    stops: int = 0
    ended: str = ""


def run_syncs(
    target: EmulatorTarget,
    syncs: list[Sync],
    writer: SequenceWriter,
    seconds: float,
    max_points: int | None = None,
    emit: Callable[[dict], None] = lambda record: None,
    clock: Callable[[], float] = time.monotonic,
) -> Outcome:
    """Takes the target to each sync point's trigger and reads its regions into the writer, until
    every one-time sync point has been read and no repeating one is left, the target exits,
    `seconds` have passed or `max_points` sync points have been read."""
    out = Outcome()
    armed: set[tuple[int, bool]] = set()

    def take(sync: Sync, stop: Stop) -> None:
        sync.hits += 1
        sync.done = not sync.repeat
        errors = 0
        for region in sync.regions:
            data, error = None, None
            try:
                data = target.read(region.address.value, region.length)
            except (TargetError, ValueError) as exc:
                error, errors = str(exc), errors + 1
            detail = {"addr": region.address.text}
            if stop.pc is not None:
                detail["pc"] = f"{stop.pc:08X}"
            writer.region(sync.name, region, data, error, sync.hits, **detail)
        record = {"kind": "sync", "sync": sync.name, "index": writer.index, "hit": sync.hits,
                  "trigger": sync.trigger.text, "regions": [r.name for r in sync.regions]}  # fmt: skip
        if stop.pc is not None:
            record["pc"] = f"{stop.pc:08X}"
        if errors:
            record["errors"] = errors
        writer.next()
        out.points += 1
        emit(record)

    def pending() -> list[Sync]:
        return [s for s in syncs if not s.done]

    def full() -> bool:
        return max_points is not None and out.points >= max_points

    def rearm() -> None:
        wanted = {s.trigger.breakpoint for s in pending() if s.trigger.breakpoint}
        for bp in sorted(armed - wanted):
            target.clear_breakpoint(*bp)
            armed.discard(bp)
        for bp in sorted(wanted - armed):  # type: ignore[type-var]
            target.set_breakpoint(*bp)  # type: ignore[misc]
            armed.add(bp)  # type: ignore[arg-type]

    stop = target.connect()
    start = clock()
    emit({"kind": "connect", "producer": target.producer,
          "pc": f"{stop.pc:08X}" if stop.pc is not None else None})  # fmt: skip
    try:
        for sync in pending():
            if sync.trigger.kind == "start" and not full():
                take(sync, stop)
        for sync in pending():
            if sync.trigger.kind == "time" and sync.trigger.seconds == 0 and not full():
                take(sync, stop)
        while pending() and not full():
            rearm()
            now = clock() - start
            if now >= seconds:
                out.ended = "seconds"
                break
            timed = [s.trigger.seconds for s in pending() if s.trigger.kind == "time"]
            until = min([seconds, *timed])  # type: ignore[type-var]
            stop = target.resume(max(0.0, until - now))
            out.stops += 1
            if stop.reason == "exited":
                out.ended = f"exited {stop.detail}".strip()
                emit({"kind": "exit", "detail": stop.detail})
                break
            now = clock() - start
            hit = False
            for sync in pending():
                if full():
                    break
                t = sync.trigger
                if (t.kind == "time" and t.seconds <= now) or (
                    stop.reason == "break" and t.breakpoint and t.address == stop.pc
                ):
                    take(sync, stop)
                    hit = True
            if not hit and stop.reason not in ("timeout",):
                emit({"kind": "stop", "reason": stop.reason, "detail": stop.detail,
                      "pc": f"{stop.pc:08X}" if stop.pc is not None else None})  # fmt: skip
        else:
            out.ended = out.ended or ("max-points" if full() else "done")
    finally:
        try:
            target.close()
        except OSError:
            pass
    return out


# --- the command ------------------------------------------------------------------------------------


def run(args) -> int:
    """`rea-suite oracle run`: 0 every sync point read, 1 some were not, 2 bad input."""
    regions = (
        load_regions(args.caller_cwd / args.regions, EMULATOR, require_syncs=not args.sync)
        if args.regions
        else None
    )
    if regions is None:
        raise ValueError("--regions FILE: the regions to read")
    syncs = list(regions.syncs)
    for text in args.sync:
        syncs.append(parse_sync_option(text, regions.regions, [s.name for s in syncs]))
    target = open_target(args.target, args)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = args.caller_cwd / args.sequence if args.sequence else WORK / stamp / "regions.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = SequenceWriter(path, f"rea-suite oracle {target.producer}")

    def emit(record: dict) -> None:
        print(json.dumps(record), flush=True)

    try:
        outcome = run_syncs(target, syncs, writer, args.seconds, args.max_points, emit)
    finally:
        writer.close()
    missing = [s.name for s in syncs if s.hits == 0]
    emit({"kind": "summary", "sequence": str(path), "points": outcome.points,
          "stops": outcome.stops, "ended": outcome.ended, "never": missing})  # fmt: skip
    return 1 if missing else 0


def compare(args) -> int:
    """`rea-suite oracle compare A B`: 0 equal, 1 a difference, 2 bad input."""
    try:
        regions = (
            load_regions(args.caller_cwd / args.regions, TextDialect(), require_syncs=False)
            if args.regions
            else None
        )
    except (OSError, ValueError) as exc:
        print(f"oracle compare: {exc}", file=sys.stderr)
        return 2
    paths = (args.caller_cwd / args.a, args.caller_cwd / args.b)
    return compare_files(
        *paths, regions, args.context, (str(args.a), str(args.b)), "oracle compare"
    )


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite oracle",
        description="Named memory regions at sync points of a program running in an emulator, "
        "and the first difference from a port's run (docs/PORT-TOOLS.md, 'The oracle').",
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser(
        "run",
        help="connect to an emulator's debugger and read regions at sync points",
        description="Connects to a running emulator's debugger, takes it to each sync point's "
        "trigger and reads its regions into a sequence file. gdb://HOST:PORT speaks GDB's remote "
        "protocol (xemu, Dolphin, DuckStation, PCSX-Redux, melonDS, ...); ppsspp://HOST:PORT "
        "PPSSPP's WebSocket debugger, which you turn on yourself (while it runs, PPSSPP reports "
        "your local address to report.ppsspp.org: docs/PSP.md). The suite starts no emulator. "
        "Exit 0 when every sync point was read, 1 when one never came, 2 on bad input.",
    )
    r.add_argument("--target", required=True, help="gdb://HOST:PORT or ppsspp://HOST:PORT")
    r.add_argument(
        "--arch",
        help="the CPU, for GDB targets: x86, x86-64, ppc (Gekko, Broadway, 750), mips (R3000), arm",
    )
    r.add_argument("--regions", type=Path, required=True, help="the regions file (TOML or JSON)")
    r.add_argument(
        "--sync",
        action="append",
        default=[],
        metavar="NAME@TRIGGER[@REGION,...]",
        help="a sync point besides the file's: start, pc=ADDR, hw=ADDR or t=SECONDS (repeatable)",
    )
    r.add_argument("--sequence", type=Path, help="the sequence file (default work/oracle/<run>/)")
    r.add_argument("--seconds", type=float, default=60.0, help="stop after this long (default 60)")
    r.add_argument("--max-points", type=int, help="stop after this many sync points")
    r.add_argument(
        "--timeout", type=float, default=10.0, help="seconds to wait for a debugger's answer"
    )
    r.set_defaults(run=run)
    c = sub.add_parser(
        "compare",
        help="two region sequences (the original's and a port's): the first difference",
        description="Compares two sequence files sync point by sync point and reports the first "
        "difference: the sync point, the region, the offset and the bytes around it. Exit 0 when "
        "equal, 1 on a difference, 2 on bad input.",
    )
    c.add_argument("a", type=Path, help="a sequence file (the original's run, usually)")
    c.add_argument("b", type=Path, help="the other (the port's)")
    c.add_argument(
        "--regions",
        type=Path,
        help="the regions file: compare only its regions, with their types and ignore ranges",
    )
    c.add_argument(
        "--context", type=int, default=16, help="bytes shown each side of the difference"
    )
    c.set_defaults(run=compare)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError) as exc:
        print(f"oracle: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
