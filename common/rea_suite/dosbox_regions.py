"""Named memory regions at sync points, for comparing a port's run against the original's.

  rea-suite dosbox run --regions FILE ... PROGRAM   reads the regions at each sync point into a
                                                    sequence file (regions.jsonl in the run's folder)
  rea-suite dosbox compare A B [--regions FILE]     the first difference between two sequences

The regions file (TOML, or JSON for a .json name) names ranges of memory and the sync points that
read them; the sequence file is JSON lines, one line per region read, and is the format a port
writes from its own run of the same scripted input. docs/PORT-TOOLS.md ("Named regions at sync
points") specifies both. Comparing stops at the first sync point whose regions differ, as remc2's
regression test does against its DOSBox-X fork.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from rea_suite import dosbox_actions as acts

FORMAT = "rea-regions"
VERSION = 1
INLINE_MAX = 4096  # bytes a line carries as hex; a longer region goes to the sidecar
TYPES = {"bytes": 1, "ascii": 1, "u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4}
REPEATABLE = ("int", "open")  # triggers that come more than once; the others are one moment


# --- the regions file -------------------------------------------------------------------------------


class BadRegions(ValueError):
    """A regions file that does not follow the format."""


@dataclass
class RegionsFile:
    regions: dict[str, acts.Region]
    syncs: list[acts.Sync]


def _length(value, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise BadRegions(f"{what}: a number, or a string in decimal or 0x hex")
    return acts.parse_length(str(value))


def _offset(value, what: str) -> int:
    text = str(value).strip().lower()
    try:
        offset = int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        raise ValueError(f"{what}: an offset in decimal or 0x hex") from None
    if offset < 0:
        raise ValueError(f"{what}: an offset is at least 0")
    return offset


def parse_region(name: str, spec) -> acts.Region:
    where = f"region {name!r}"
    if not isinstance(spec, dict):
        raise BadRegions(f"{where}: a table with addr and len")
    unknown = set(spec) - {"addr", "len", "type", "ignore"}
    if unknown:
        raise ValueError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    if "addr" not in spec or "len" not in spec:
        raise ValueError(f"{where}: needs addr and len")
    address = acts.parse_address(str(spec["addr"]))
    length = _length(spec["len"], f"{where} len")
    kind = spec.get("type", "bytes")
    if kind not in TYPES:
        raise ValueError(f"{where}: type is one of {', '.join(TYPES)}")
    if length % TYPES[kind]:
        raise ValueError(f"{where}: len {length} is not a whole number of {kind}")
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
    return acts.Region(name, address, length, kind, tuple(ignore))


def parse_regions(data: dict) -> RegionsFile:
    """The regions file's contents (a parsed TOML or JSON document)."""
    if not isinstance(data, dict):
        raise BadRegions("regions file: a table with [regions] and [[sync]]")
    unknown = set(data) - {"regions", "sync"}
    if unknown:
        raise ValueError(f"regions file: unknown key(s) {', '.join(sorted(unknown))}")
    table = data.get("regions")
    if not isinstance(table, dict) or not table:
        raise ValueError("regions file: no [regions]")
    regions = {name: parse_region(name, spec) for name, spec in table.items()}
    syncs: list[acts.Sync] = []
    for spec in data.get("sync", []):
        if not isinstance(spec, dict) or "name" not in spec or "at" not in spec:
            raise ValueError("regions file: each [[sync]] needs name and at")
        name = str(spec["name"])
        unknown = set(spec) - {"name", "at", "regions", "repeat", "mode"}
        if unknown:
            raise ValueError(f"sync {name!r}: unknown key(s) {', '.join(sorted(unknown))}")
        if any(s.name == name for s in syncs):
            raise ValueError(f"sync {name!r}: named twice")
        trigger = acts.parse_trigger(str(spec["at"]))
        repeat = spec.get("repeat", False)
        if not isinstance(repeat, bool):
            raise BadRegions(f"sync {name!r}: repeat is true or false")
        if repeat and trigger.kind not in REPEATABLE:
            raise ValueError(f"sync {name!r}: repeat needs an int or open trigger")
        mode = spec.get("mode", "auto")
        if mode not in acts.MODES:
            raise ValueError(f"sync {name!r}: mode is one of {', '.join(acts.MODES)}")
        if mode == "pm" and trigger.kind not in (*acts.MOVABLE, *acts.CALLS):
            raise ValueError(f"sync {name!r}: mode pm needs an int, open, t= or input: trigger")
        names = spec.get("regions", list(regions))
        if not isinstance(names, list) or not names:
            raise ValueError(f"sync {name!r}: regions is a list of region names")
        missing = [n for n in names if n not in regions]
        if missing:
            raise ValueError(f"sync {name!r}: no region {', '.join(map(repr, missing))}")
        syncs.append(acts.Sync(name, trigger, [regions[n] for n in names], repeat, mode=mode))
    if not syncs:
        raise ValueError("regions file: no [[sync]]")
    return RegionsFile(regions, syncs)


def load_regions(path: Path) -> RegionsFile:
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{path}: {exc}") from None
    try:
        return parse_regions(data)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from None


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
        region: acts.Region,
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
        point.entries.append(
            Entry(r["region"], r["len"], data, str(error) if error else None, r.get("type"), number)
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


def typed_value(data: bytes, offset: int, kind: str | None) -> str | None:
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
    value = int.from_bytes(chunk, "little", signed=kind.startswith("i"))
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
    wanted: dict[str, acts.Region] | None,
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
    differing = [i for i in range(ea.length) if ea.data[i] != eb.data[i] and not ignored(i, skip)]
    if not differing:
        return []
    first = differing[0]
    lo, hi = max(0, first - context), min(ea.length, first + context + 1)
    out = [f"offset {first:#x} ({first}), {len(differing)} byte(s) differ"]
    for entry, name in ((ea, na), (eb, nb)):
        value = typed_value(entry.data, first, kind)  # type: ignore[arg-type]
        out.append(f" {name}:" + (f" {kind} {value}" if value is not None else ""))
        out += hex_rows(entry.data, lo, hi, first)  # type: ignore[arg-type]
    return out


def compare(args) -> int:
    """`rea-suite dosbox compare A B`: 0 equal, 1 a difference, 2 bad input."""
    import sys

    paths = [args.caller_cwd / args.a, args.caller_cwd / args.b]
    try:
        regions = load_regions(args.caller_cwd / args.regions) if args.regions else None
        (_, a), (_, b) = (read_sequence(p) for p in paths)
    except (OSError, ValueError) as exc:
        print(f"dosbox compare: {exc}", file=sys.stderr)
        return 2
    diff, agreed = first_difference(a, b, regions, args.context)
    print(f"A: {args.a}\nB: {args.b}")
    if diff is None:
        print(f"equal: {agreed} sync point(s)")
        return 0
    print(f"{agreed} sync point(s) equal, then:")
    for line in diff.text:
        print(line)
    return 1
