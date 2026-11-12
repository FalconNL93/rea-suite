"""OPL (AdLib, OPL2, OPL3) register writes: DOSBox-X's raw OPL capture as JSON lines, and comparing
one song's writes between the original and a port.

  rea-suite dosbox run --opl-log FILE ... PROGRAM    DOSBox-X captures the OPL writes (DRO); the run
                                                     converts them to FILE
  rea-suite dosbox compare-opl A B [options]         the first difference between two OPL logs

A log is any of three formats, told apart by their first bytes: a DOSBox-X .dro capture (DROv2), the
JSON lines this module writes (`rea-opl`), or a port's text log, a write a line: `SECONDS PORT BYTE`
(port and byte in hex, as Theme Park's TP_OPL_LOG). docs/PORT-TOOLS.md ("Music: OPL register
writes") specifies them.

Both logs are normalized the way DOSBox-X's capture records a song, so a capture and a port's full
log compare: only the sound registers, a write that leaves a register as it was dropped, and the log
starting at the first key-on with the registers set before it (key-on bits masked), at time 0.
Comparing then walks each register's values in order; absolute times are not compared, only how far
each write's time drifts between the two (--tolerance).
"""

from __future__ import annotations

import json
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

FORMAT = "rea-opl"
VERSION = 1
DRO_ID = b"DBRAWOPL"
DRO_HEADER = struct.Struct("<8sHHIIBBBBBB")  # id, version high, low, commands, ms, hardware, ...
HARDWARE = {0: "opl2", 1: "dual-opl2", 2: "opl3"}
# Ports: the address ports latch a register (of bank 0 or 1), the data ports write it. 388h-38Bh is
# AdLib and OPL3; a Sound Blaster's own are at its base (220h-223h, 228h-229h for 220h).
ADDRESS_PORTS = {0x388: 0, 0x38A: 1, 0x220: 0, 0x222: 1, 0x228: 0}
DATA_PORTS = {0x389, 0x38B, 0x221, 0x223, 0x229}


def _dro_registers() -> list[int]:
    """The registers DOSBox-X's capture records, in its table's order (Capture::MakeTables)."""
    regs = [0x01, 0x04, 0x05, 0x08, 0xBD]
    for i in range(24):
        if (i & 7) < 6:
            regs += [0x20 + i, 0x40 + i, 0x60 + i, 0x80 + i, 0xE0 + i]
    for i in range(9):
        regs += [0xA0 + i, 0xB0 + i, 0xC0 + i]
    return regs


DRO_REGISTERS = frozenset(_dro_registers())
TIMERS = frozenset({0x02, 0x03, 0x04})  # bank 0: the timers, no sound (the chip never caches them)


@dataclass(frozen=True)
class Write:
    """One register write: seconds, bank (0, or 1 for an OPL3's second register set), register,
    value; `line` where it came from (the line number, or the write's place in a capture)."""

    t: float
    bank: int
    reg: int
    value: int
    line: int = 0

    @property
    def key(self) -> tuple[int, int]:
        return self.bank, self.reg


class BadLog(ValueError):
    """An OPL log that follows none of the formats."""


# --- DOSBox-X's capture -----------------------------------------------------------------------------


@dataclass
class Dro:
    hardware: str
    writes: list[Write]
    closed: (
        bool  # the header has its totals: DOSBox-X closed the file; else its tail may be missing
    )


def read_dro(data: bytes, name: str = "capture") -> Dro:
    """A DROv2 file as DOSBox-X writes it (src/hardware/adlib.cpp, Adlib::Capture): a header, a
    table from codes to registers, then code/value pairs; a code with the high bit set writes bank
    1, two codes are delays (1-256 ms, and 256 ms steps). Reads to the end of the data, so a file
    whose writer was killed (its header still zero) reads as far as it got."""
    if len(data) < DRO_HEADER.size or not data.startswith(DRO_ID):
        raise BadLog(f"{name}: not a DOSBox raw OPL capture (no DBRAWOPL header)")
    _, high, low, commands, _, hardware, fmt, compression, delay256, shift8, size = (
        DRO_HEADER.unpack_from(data)
    )
    if (high, low) != (2, 0):
        raise BadLog(f"{name}: DRO version {high}.{low}; this reader knows 2.0")
    if fmt or compression:
        raise BadLog(f"{name}: DRO format {fmt}, compression {compression}; this reader knows 0, 0")
    start = DRO_HEADER.size
    table = data[start : start + size]
    if len(table) < size:
        raise BadLog(f"{name}: shorter than its register table")
    body = data[start + size :]
    ms = 0
    writes = []
    for i in range(0, len(body) - 1, 2):
        code, value = body[i], body[i + 1]
        if code == delay256:
            ms += value + 1
        elif code == shift8:
            ms += (value + 1) << 8
        elif (code & 0x7F) < size:
            writes.append(Write(ms / 1000, code >> 7, table[code & 0x7F], value, i // 2))
        else:
            raise BadLog(f"{name}: code {code:#04x} at pair {i // 2} is outside the table")
    return Dro(HARDWARE.get(hardware, str(hardware)), writes, commands > 0)


# --- the JSON lines ---------------------------------------------------------------------------------


def write_log(path: Path, writes: list[Write], **header) -> None:
    """The rea-opl JSON lines: a header, then a line per write."""
    with path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"format": FORMAT, "version": VERSION, **header}) + "\n")
        for w in writes:
            line = {
                "t": round(w.t, 6),
                "bank": w.bank,
                "reg": f"{w.reg:02x}",
                "value": f"{w.value:02x}",
            }
            f.write(json.dumps(line) + "\n")


def convert_captures(files: list[Path], out: Path, producer: str) -> dict:
    """DOSBox-X's captures of one run, in order, as one log. A capture starts at the first key-on
    and DOSBox-X begins a new file after 30 s without a write; a later file's times go on from
    the previous one's last write plus those 30 s (the true gap is not recorded: at least that)."""
    writes: list[Write] = []
    hardware = "opl2"
    unclosed = []
    offset = 0.0
    for n, path in enumerate(files):
        dro = read_dro(path.read_bytes(), str(path))
        if n and writes:
            offset = writes[-1].t + 30.0
        writes += [Write(w.t + offset, w.bank, w.reg, w.value, w.line) for w in dro.writes]
        if dro.hardware != "opl2":
            hardware = dro.hardware
        if not dro.closed:
            unclosed.append(path.name)
    header = {"producer": producer, "source": "dro", "hardware": hardware}
    header["captures"] = [p.name for p in files]
    if unclosed:
        header["unclosed"] = unclosed
    write_log(out, writes, **header)
    return {"writes": len(writes), "captures": header["captures"], "hardware": hardware,
            **({"unclosed": unclosed} if unclosed else {})}  # fmt: skip


def _hex(value, what: str, limit: int) -> int:
    """A hex string, or a JSON number."""
    number = int(str(value), 16) if isinstance(value, (str, bool)) else value
    if not isinstance(number, int):
        raise TypeError(what)
    if not 0 <= number <= limit:
        raise ValueError(what)
    return number


class PortLatch:
    """Port writes to register writes: an address port latches the register, a data port writes it."""

    def __init__(self):
        self.latched: tuple[int, int] | None = None

    def write(self, t: float, port: int, value: int, line: int) -> Write | None:
        if port in ADDRESS_PORTS:
            self.latched = (ADDRESS_PORTS[port], value)
            return None
        if port in DATA_PORTS:
            if self.latched is None:
                return None  # data before any address: the chip writes nowhere known
            return Write(t, *self.latched, value, line)
        raise ValueError(f"port {port:X}h is not an OPL port")


def read_log(path: Path) -> list[Write]:
    """Any of the three formats, as register writes in order."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BadLog(f"{path}: {exc}") from None
    if data.startswith(DRO_ID):
        return read_dro(data, str(path)).writes
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise BadLog(f"{path}: neither a DRO capture nor text") from None
    latch = PortLatch()
    writes: list[Write] = []
    json_lines: bool | None = None
    for number, text in enumerate(lines, 1):
        text = text.strip()
        if not text or text.startswith("#"):
            continue
        where = f"{path}:{number}"
        if json_lines is None:
            json_lines = text.startswith("{")
            if json_lines:
                header = _json(text)
                if not isinstance(header, dict) or header.get("format") != FORMAT:
                    raise BadLog(
                        f'{where}: the first line is not the header ({{"format": "{FORMAT}", ...}})'
                    )
                if header.get("version") != VERSION:
                    raise BadLog(
                        f"{where}: version {header.get('version')!r}; this reader knows {VERSION}"
                    )
                continue
        try:
            if json_lines:
                record = json.loads(text)
                if not isinstance(record, dict):
                    raise ValueError("not a JSON object")
                t = float(record["t"])
                value = _hex(record["value"], "value is a byte in hex", 0xFF)
                if "port" in record:
                    write = latch.write(
                        t, _hex(record["port"], "port in hex", 0xFFFF), value, number
                    )
                else:
                    bank = record["bank"]
                    if bank not in (0, 1):
                        raise ValueError("bank is 0 or 1")
                    write = Write(
                        t, bank, _hex(record["reg"], "reg is a byte in hex", 0xFF), value, number
                    )
            else:
                parts = text.split()
                if len(parts) != 3:
                    raise ValueError("a write is SECONDS PORT BYTE")
                t = float(parts[0])
                write = latch.write(
                    t, int(parts[1], 16), _hex(parts[2], "a byte in hex", 0xFF), number
                )
            if not math.isfinite(t):
                raise ValueError("the time is not a number")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            why = f"missing {exc}" if isinstance(exc, KeyError) else str(exc)
            raise BadLog(f"{where}: {why}") from None
        if write:
            writes.append(write)
    if json_lines is None:
        raise BadLog(f"{path}: empty")
    return writes


def _json(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# --- normalizing --------------------------------------------------------------------------------------


def key_on(w: Write) -> bool:
    """A write that starts DOSBox-X's capture: a key-on, or a drum struck in rhythm mode."""
    return (0xB0 <= w.reg <= 0xB8 and bool(w.value & 0x20)) or (
        w.reg == 0xBD and (w.value & 0x3F) > 0x20
    )


def sound_register(bank: int, reg: int) -> bool:
    return reg in DRO_REGISTERS and not (bank == 0 and reg in TIMERS)


def normalize(writes: list[Write], start: float = 0.0) -> tuple[list[Write], float | None]:
    """The writes as DOSBox-X's capture would record them, from the first key-on at or after
    `start` (seconds in the log's own time), and that key-on's time. Times are from it."""
    state: dict[tuple[int, int], int] = {}
    out: list[Write] = []
    origin: float | None = None
    for w in writes:
        if not sound_register(w.bank, w.reg):
            continue
        if origin is None and w.t >= start and key_on(w):
            origin = w.t
            for reg in range(256):  # the registers set so far, as the capture's first writes
                for bank in (0, 1):
                    value = state.get((bank, reg), 0)
                    if 0xB0 <= reg <= 0xB8:
                        value &= ~0x20
                    elif reg == 0xBD and bank == 0:
                        value &= ~0x1F
                    if value:
                        out.append(Write(0.0, bank, reg, value, 0))
        if state.get(w.key, 0) == w.value:
            continue
        state[w.key] = w.value
        if origin is not None:
            out.append(Write(w.t - origin, w.bank, w.reg, w.value, w.line))
    return out, origin


# --- naming registers ---------------------------------------------------------------------------------

OPERATOR_FIELDS = {
    0x20: "tremolo/vibrato/sustain/KSR/multiple",
    0x40: "key scale/level",
    0x60: "attack/decay",
    0x80: "sustain/release",
    0xE0: "waveform",
}
CHANNEL_FIELDS = {
    0xA0: "F-number low",
    0xB0: "key on/block/F-number high",
    0xC0: "feedback/connection",
}
GLOBAL_FIELDS = {
    (0, 0x01): "waveform select enable",
    (0, 0x08): "CSW/note select",
    (0, 0xBD): "depth/rhythm",
    (1, 0x04): "four-operator enable",
    (1, 0x05): "OPL3 enable",
}


def channel_of(bank: int, reg: int) -> tuple[int, int | None] | None:
    """The channel (0-17) a register belongs to, and its operator (1 or 2), or None for a global one."""
    base = reg & 0xE0
    if base in OPERATOR_FIELDS and (reg & 0x1F) < 0x16 and (reg & 7) < 6:
        slot = reg & 0x1F
        return bank * 9 + (slot >> 3) * 3 + (slot & 7) % 3, 1 if (slot & 7) < 3 else 2
    if (reg & 0xF0) in CHANNEL_FIELDS and (reg & 0x0F) < 9:
        return bank * 9 + (reg & 0x0F), None
    return None


def describe(bank: int, reg: int) -> str:
    name = f"{bank:X}{reg:02X}"
    owner = channel_of(bank, reg)
    if owner is None:
        return f"{name} ({GLOBAL_FIELDS.get((bank, reg), 'global')})"
    channel, op = owner
    field = OPERATOR_FIELDS.get(reg & 0xE0) if op else CHANNEL_FIELDS[reg & 0xF0]
    return f"{name} (channel {channel}{f' operator {op}' if op else ''}: {field})"


def timbre(channel: int) -> list[tuple[int, int]]:
    """A channel's registers: its two operators' and its own."""
    bank, ch = divmod(channel, 9)
    slots = [(ch // 3) * 8 + ch % 3, (ch // 3) * 8 + ch % 3 + 3]
    regs = [(bank, base + s) for s in slots for base in OPERATOR_FIELDS]
    return regs + [(bank, base + ch) for base in CHANNEL_FIELDS]


# --- comparing ----------------------------------------------------------------------------------------


@dataclass
class Mismatch:
    t: float  # the time it shows, from the first key-on
    key: tuple[int, int]
    index: int  # the register's write number, from 0
    kind: str  # value, missing, timing
    text: list[str]


def first_mismatch(
    a: list[Write],
    b: list[Write],
    tolerance: float | None,
    until: float,
    context: int = 6,
    names: tuple[str, str] = ("A", "B"),
) -> tuple[Mismatch | None, int]:
    """The earliest difference in any register's sequence of values up to `until` seconds, or in
    its writes' times beyond `tolerance`; and how many writes agreed before it."""
    na, nb = names
    per_a: dict[tuple[int, int], list[Write]] = {}
    per_b: dict[tuple[int, int], list[Write]] = {}
    for writes, per in ((a, per_a), (b, per_b)):
        for w in writes:
            per.setdefault(w.key, []).append(w)
    ends = {na: a[-1].t if a else 0.0, nb: b[-1].t if b else 0.0}
    slack = tolerance or 0.0
    best: Mismatch | None = None
    for key in sorted(set(per_a) | set(per_b)):
        la, lb = per_a.get(key, []), per_b.get(key, [])
        for i in range(max(len(la), len(lb))):
            wa = la[i] if i < len(la) else None
            wb = lb[i] if i < len(lb) else None
            first = min(w.t for w in (wa, wb) if w is not None)
            if first > until:
                break  # past the time both logs cover
            if (wa is None or wb is None) and first + slack > ends[nb if wb is None else na]:
                break  # the other log ends before this write could come
            if wa is None or wb is None:
                have, name, other = (wb, nb, na) if wa is None else (wa, na, nb)
                assert have is not None
                t, kind = have.t, "missing"
                text = f"{name} writes {have.value:02X} at {have.t:.3f} s, {other} no more"
            elif wa.value != wb.value:
                t, kind = min(wa.t, wb.t), "value"
                text = f"{na} {wa.value:02X} at {wa.t:.3f} s, {nb} {wb.value:02X} at {wb.t:.3f} s"
            elif tolerance is not None and abs(wa.t - wb.t) > tolerance:
                t, kind = min(wa.t, wb.t), "timing"
                apart, allowed = abs(wa.t - wb.t) * 1000, tolerance * 1000
                text = (
                    f"{wa.value:02X} at {na} {wa.t:.3f} s, {nb} {wb.t:.3f} s: "
                    f"{apart:.0f} ms apart (tolerance {allowed:.0f} ms)"
                )
            else:
                continue
            found = Mismatch(t, key, i, kind, [text])
            if best is None or (found.t, found.kind == "timing") < (best.t, best.kind == "timing"):
                best = found
            break
    if best is None:
        return None, sum(1 for w in a if w.t <= until)
    agreed = sum(1 for w in a if w.t < best.t)
    best.text = [f"{describe(*best.key)}, write {best.index + 1} of that register: {best.text[0]}"]
    best.text += _context(a, b, best, context, names)
    return best, agreed


def _state(writes: list[Write], t: float) -> dict[tuple[int, int], int]:
    state: dict[tuple[int, int], int] = {}
    for w in writes:
        if w.t >= t:
            break
        state[w.key] = w.value
    return state


def _context(
    a: list[Write], b: list[Write], m: Mismatch, context: int, names: tuple[str, str]
) -> list[str]:
    """The register's writes before it on both sides, and its channel's timbre at that moment."""
    out = []
    for writes, name in zip((a, b), names, strict=True):
        mine = [w for w in writes if w.key == m.key]
        shown = mine[max(0, m.index - context) : m.index + 2]
        out.append(f" {name}: " + " ".join(f"{w.value:02X}@{w.t:.3f}" for w in shown))
    owner = channel_of(*m.key)
    if owner is None or context <= 0:
        return out
    channel = owner[0]
    sa, sb = _state(a, m.t), _state(b, m.t)
    out.append(f" channel {channel} just before {m.t:.3f} s ({names[0]} / {names[1]}):")
    cells = []
    for key in timbre(channel):
        va, vb = sa.get(key, 0), sb.get(key, 0)
        mark = "" if va == vb else " *"
        cells.append(f"{key[0]:X}{key[1]:02X} {va:02X}/{vb:02X}{mark}")
    for i in range(0, len(cells), 5):
        out.append("  " + "   ".join(cells[i : i + 5]))
    return out


def compare(args) -> int:
    """`rea-suite dosbox compare-opl A B`: 0 equal, 1 a difference, 2 bad input."""
    try:
        logs = [read_log(args.caller_cwd / p) for p in (args.a, args.b)]
    except (OSError, ValueError) as exc:
        print(f"dosbox compare-opl: {exc}", file=sys.stderr)
        return 2
    (a, oa), (b, ob) = (
        normalize(w, s) for w, s in zip(logs, (args.start_a, args.start_b), strict=True)
    )
    print(f"A: {args.a}" + (f" (from its first key-on at {oa:.3f} s)" if oa is not None else ""))
    print(f"B: {args.b}" + (f" (from its first key-on at {ob:.3f} s)" if ob is not None else ""))
    for name, writes, start in (("A", a, args.start_a), ("B", b, args.start_b)):
        if not writes:
            print(f"{name} has no key-on" + (f" at or after {start:g} s" if start else ""))
    if not a or not b:
        return 1 if (a or b) else 0
    until = min(a[-1].t, b[-1].t)
    if args.until is not None:
        until = min(until, args.until)
    tolerance = None if args.ignore_timing else args.tolerance
    found, agreed = first_mismatch(a, b, tolerance, until, args.context)
    span = f"{until:.3f} s"
    if found is None:
        print(
            f"equal: {agreed} write(s) over {span}"
            + ("" if tolerance is None else f", within {tolerance * 1000:.0f} ms")
        )
        return 0
    print(f"{agreed} write(s) agree, then at {found.t:.3f} s ({found.kind}):")
    for line in found.text:
        print(line)
    return 1
