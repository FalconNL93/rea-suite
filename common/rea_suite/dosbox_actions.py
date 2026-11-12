"""What `rea-suite dosbox run` does to a running DOS program besides watching it: memory dumps and
writes at a trigger (--dump, --poke) and scripted keyboard and mouse input (--input). The parsing,
the encodings and the plans the runner's tracer carries out over DOSBox-X's debugger control
channel; docs/PORT-TOOLS.md ("DOS programs") has the format and the reasons.

Input goes through DOSBox-X's integration device (`[dosbox] integration device`, I/O ports 28h-2Ah,
src/ints/bios.cpp), written with the debugger's OUTB/OUTD: its register 00804200h puts a byte in the
keyboard controller's buffer as the keyboard would (set 1 scan codes, what port 60h gives a DOS
program), presses and releases a mouse button and the driver's own INT 33h functions see it as a real
button. The pointer is placed by having the CPU run INT 33h 0004h (set position) through the
debugger's INT command at a stop in the program's own code, with the registers put back afterwards;
a move reads the position with 0003h first. That keeps it exact and absolute, but the driver's
mickey counters (000Bh) do not move and no movement event reaches an 000Ch handler (the next
button event carries the new position).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

# --- triggers --------------------------------------------------------------------------------------

# INT 21h functions that end the program, and those that open a file by name.
EXIT_FUNCTIONS = (0x4C, 0x00, 0x31)
OPEN_FUNCTIONS = (0x3D, 0x6C)
# Where an action may read and write memory (a sync point's `mode`): `pm` only at a stop in the
# program's own protected-mode code (a time or input stop moves on to the next such stop, a call
# elsewhere is passed over), `any` wherever the trigger stops, `auto` (the default) `pm` for time
# and input triggers once the program has entered protected mode, `any` for the rest.
MODES = ("auto", "pm", "any")
MOVABLE = ("time", "input")  # triggers that stop wherever a BREAK lands, so may move to a later one
CALLS = ("int", "open")  # triggers that stop at a call of the program's


@dataclass(frozen=True)
class Trigger:
    """When an action runs: at an interrupt call (`int21`, `int21:3D`, `int21:3D:00`), at the
    program's open of a file (`open:DATA/LEVEL.DAT`), at a time in seconds (`t=30`, the clock of
    the records' `t`), once an item of the --input script has been delivered (`input:3`, the third
    item), at the program's first instruction (`start`) or at its end (`exit`)."""

    kind: str  # int, open, time, input, start, exit
    text: str
    n: int | None = None
    ah: int | None = None
    al: int | None = None
    name: str | None = None
    seconds: float | None = None
    item: int | None = None

    def breakpoints(self) -> list[tuple[int, int | None, int | None]]:
        """The interrupt breakpoints (INT, AH, AL) this trigger needs."""
        if self.kind == "int":
            return [(self.n, self.ah, self.al)]  # type: ignore[list-item]
        if self.kind == "open":
            return [(0x21, ah, None) for ah in OPEN_FUNCTIONS]
        if self.kind == "exit":
            return [(0x21, ah, None) for ah in EXIT_FUNCTIONS]
        return []

    def matches_call(self, n: int, ax: int, path: str | None) -> bool:
        if self.kind == "int":
            return covers((self.n, self.ah, self.al), n, ax)  # type: ignore[arg-type]
        if self.kind == "open":
            return (
                n == 0x21
                and ax >> 8 in OPEN_FUNCTIONS
                and path is not None
                and same_file(path, self.name or "")
            )
        return False


def parse_trigger(text: str) -> Trigger:
    t = text.strip()
    low = t.lower()
    if low in ("start", "exit"):
        return Trigger(low, low)
    if low.startswith("t="):
        try:
            seconds = float(low[2:])
        except ValueError:
            raise ValueError(f"trigger {text!r}: t= takes seconds") from None
        if seconds < 0:
            raise ValueError(f"trigger {text!r}: a time is at least 0")
        return Trigger("time", t, seconds=seconds)
    if low.startswith("open:"):
        name = t[5:].strip()
        if not name:
            raise ValueError(f"trigger {text!r}: open: takes a file name")
        return Trigger("open", t, name=name)
    if low.startswith("input:"):
        if not low[6:].isdigit() or int(low[6:]) < 1:
            raise ValueError(f"trigger {text!r}: input: takes an item's number, from 1")
        return Trigger("input", t, item=int(low[6:]))
    m = re.fullmatch(r"int([0-9a-f]{1,2})(?::([0-9a-f]{1,2}))?(?::([0-9a-f]{1,2}))?", low)
    if m:
        n, ah, al = (int(g, 16) if g else None for g in m.groups())
        return Trigger("int", t, n=n, ah=ah, al=al)
    raise ValueError(
        f"trigger {text!r}: one of intNN[:AH[:AL]], open:NAME, t=SECONDS, input:N, start, exit"
    )


def covers(spec: tuple[int, int | None, int | None], n: int, ax: int) -> bool:
    """Whether a breakpoint INT[:AH[:AL]] stops at this call."""
    sn, ah, al = spec
    return sn == n and (ah is None or ah == ax >> 8) and (al is None or al == ax & 0xFF)


def spec_covered(spec: tuple[int, int | None, int | None], by: list) -> bool:
    """A breakpoint another one already includes (21:3D under 21)."""
    n, ah, al = spec
    for bn, bah, bal in by:
        if bn == n and (bah is None or (bah == ah and (bal is None or bal == al))):
            return True
    return False


def same_file(path: str, name: str) -> bool:
    """A DOS path the program opens against a trigger's name: no case, either slash, the name
    whole or as the path's tail (`LEVEL.DAT` and `data/level.dat` both match C:\\GAME\\DATA\\LEVEL.DAT)."""
    p = path.upper().replace("/", "\\")
    n = name.upper().replace("/", "\\").lstrip("\\")
    if len(p) > 1 and p[1] == ":":
        p = p[2:]
    p = p.lstrip("\\")
    return p == n or p.endswith("\\" + n)


# --- addresses, dumps and pokes --------------------------------------------------------------------


@dataclass(frozen=True)
class Address:
    """A linear address, or SEL:OFF (a selector in protected mode, a segment in real or V86 mode)."""

    text: str
    linear: int | None = None
    sel: int | None = None
    off: int | None = None


def parse_address(text: str) -> Address:
    t = text.strip()
    try:
        if ":" in t:
            sel, off = (int(p, 16) for p in t.split(":"))
            if not 0 <= sel <= 0xFFFF or not 0 <= off <= 0xFFFFFFFF:
                raise ValueError
            return Address(t, sel=sel, off=off)
        value = int(t, 16)
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError
        return Address(t, linear=value)
    except ValueError:
        raise ValueError(
            f"address {text!r}: a linear address or SEL:OFF, in hex (obj<N>+off is not supported)"
        ) from None


def parse_length(text: str) -> int:
    t = text.strip().lower()
    try:
        value = int(t, 16) if t.startswith("0x") else int(t)
    except ValueError:
        raise ValueError(f"length {text!r}: decimal, or hex with 0x") from None
    if not 0 < value <= 1 << 28:
        raise ValueError(f"length {text!r}: from 1 byte to 256 MiB")
    return value


@dataclass
class Moved:
    """A time or input action held for a stop in the program's own protected-mode code: where the
    first stop for it landed instead, when (host clock), and how many stops were passed over."""

    mode: str
    at: str
    since: float
    stops: int = 1
    gave_up: bool = False


@dataclass
class Dump:
    """--dump ADDR:LEN@TRIGGER: LEN bytes from ADDR into a file of the run's folder, once."""

    address: Address
    length: int
    trigger: Trigger
    text: str
    done: bool = False
    mode: str = "auto"
    moved: Moved | None = None


@dataclass
class Poke:
    """--poke ADDR=BYTES@TRIGGER: write the bytes (hex) at ADDR, once."""

    address: Address
    data: bytes
    trigger: Trigger
    text: str
    done: bool = False
    mode: str = "auto"
    moved: Moved | None = None


def _split_trigger(text: str, option: str) -> tuple[str, Trigger]:
    if "@" not in text:
        raise ValueError(f"{option} {text!r}: no @TRIGGER")
    what, trigger = text.rsplit("@", 1)
    return what, parse_trigger(trigger)


def parse_dump(text: str) -> Dump:
    what, trigger = _split_trigger(text, "--dump")
    if ":" not in what:
        raise ValueError(f"--dump {text!r}: ADDR:LEN@TRIGGER")
    address, length = what.rsplit(":", 1)
    return Dump(parse_address(address), parse_length(length), trigger, text)


def parse_poke(text: str) -> Poke:
    what, trigger = _split_trigger(text, "--poke")
    if "=" not in what:
        raise ValueError(f"--poke {text!r}: ADDR=BYTES@TRIGGER")
    address, data = what.split("=", 1)
    try:
        raw = bytes.fromhex(data.replace(",", " "))
    except ValueError:
        raise ValueError(f"--poke {text!r}: BYTES in hex, as 90 90 or 9090") from None
    if not raw:
        raise ValueError(f"--poke {text!r}: no bytes")
    return Poke(parse_address(address), raw, trigger, text)


def memdump_pieces(
    address: Address, length: int, mode: str, cs: int = 0, cs_base: int = 0
) -> list[tuple[int, int, int]]:
    """The MEMDUMPBIN calls (segment or selector, offset, length) that read this range.

    Protected mode: SEL:OFF as given; a linear address through CS, whose base the debugger adds
    without a limit check (GetAddress in src/debug/debug.cpp; CS must be a 32-bit segment, as a
    DOS extender's flat code is). Real and V86 mode: linear = segment * 16 + offset, and since the
    debugger wraps an offset at 64 KiB there, pieces of at most FFF0h bytes from a segment each."""
    if mode == "pm":
        if address.linear is None:
            return [(address.sel, address.off, length)]  # type: ignore[list-item]
        return [(cs, (address.linear - cs_base) & 0xFFFFFFFF, length)]
    linear = address.linear if address.linear is not None else (address.sel << 4) + address.off  # type: ignore[operator]
    pieces = []
    while length > 0:
        seg = linear >> 4
        if seg > 0xFFFF:
            raise ValueError(f"{address.text}: above what real mode addresses (10FFEFh)")
        size = min(length, 0xFFF0)
        pieces.append((seg, linear & 0xF, size))
        linear += size
        length -= size
    return pieces


def linear_of(address: Address, mode: str, cs_base: int = 0) -> int | None:
    """The linear address a dump starts at, where it is known without the descriptor."""
    if address.linear is not None:
        return address.linear
    if mode != "pm":
        return (address.sel << 4) + address.off  # type: ignore[operator]
    return None


def parse_selinfo(lines: list[str]) -> tuple[int, int, bool]:
    """SELINFO's answer: base, limit, and whether the segment is 32-bit (GetDescriptorInfo)."""
    text = "\n".join(lines)
    base = re.search(r"\bb:([0-9A-Fa-f]{8})", text)
    limit = re.search(
        r"\bl:([0-9A-Fa-f]{8}) dpl : [0-9A-Fa-f] ([01])([01])([01])([01])([01])", text
    )
    if not base or not limit:
        raise ValueError(f"unexpected SELINFO answer: {lines!r}")
    return int(base[1], 16), int(limit[1], 16), limit[5] == "1"


def dump_record(
    dump: Dump, path: Path, data: bytes, mode: str, at: str, linear: int | None
) -> dict:
    record = {
        "kind": "dump",
        "addr": dump.address.text,
        "linear": f"{linear:08X}" if linear is not None else None,
        "len": dump.length,
        "trigger": dump.trigger.text,
        "mode": mode,
        "at": at,
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if len(data) != dump.length:
        record["short"] = len(data)
    return record


def poke_commands(poke: Poke, mode: str) -> list[str]:
    """SM writes at SEG:OFF or SEL:OFF, SMV at a linear address (through paging, in any mode)."""
    values = " ".join(f"0{b:02X}" for b in poke.data)
    a = poke.address
    if a.linear is not None:
        return [f"SMV 0{a.linear:X} {values}"]
    return [f"SM 0{a.sel:X}:0{a.off:X} {values}"]


def dump_filename(index: int, dump: Dump) -> str:
    trigger = re.sub(r"[^A-Za-z0-9]+", "-", dump.trigger.text).strip("-")
    return f"dump-{index:02d}-{trigger or 'x'}.bin"


# --- named regions at sync points (--regions; the file and the sequence: dosbox_regions) ----------


@dataclass(frozen=True)
class Region:
    """A named range of memory: ADDR as --dump takes it, a length, and for display a type."""

    name: str
    address: Address
    length: int
    type: str = "bytes"
    ignore: tuple[tuple[int, int], ...] = ()  # (offset, length) a comparison skips


@dataclass
class Sync:
    """A sync point: when its trigger comes, its regions are read in order into the run's
    sequence file. `repeat` makes every call or open of the trigger one, not only the first;
    `mode` is where the regions may be read (MODES)."""

    name: str
    trigger: Trigger
    regions: list[Region]
    repeat: bool = False
    done: bool = False
    hits: int = 0
    mode: str = "auto"
    moved: Moved | None = None

    @property
    def text(self) -> str:
        return f"sync {self.name}@{self.trigger.text}"


# --- input -----------------------------------------------------------------------------------------

INTEGRATION_INJECT = 0x00804200  # DOSBOX_ID_REG_8042_KB_INJECT, include/iglib.h
INJECT_KEYBOARD, INJECT_BUTTON = 0x00, 0x08
BUTTONS = {"left": 0, "right": 1, "middle": 2}
KEY_HOLD = 0.05  # seconds a key or a click is held unless the script says
TYPE_GAP = 0.08  # between the characters of a text
SHIFTED = dict(zip('!@#$%^&*()_+{}|:"<>?~', "1234567890-=[]\\;',./`", strict=True))
CHAR_KEYS = {
    " ": "SPACE", "-": "MINUS", "=": "EQUALS", "[": "LBRACKET", "]": "RBRACKET", "\\": "BACKSLASH",
    ";": "SEMICOLON", "'": "APOSTROPHE", "`": "GRAVE", ",": "COMMA", ".": "PERIOD", "/": "SLASH",
    "\n": "ENTER", "\t": "TAB",
}  # fmt: skip


def key_bytes(name: str, release: bool = False) -> list[int]:
    """Set 1 scan code bytes of a key's make (or break) code: names as `rea-suite run` takes them."""
    from rea_suite.run_harness import key

    k = key(name)
    code = k["scan"] | (0x80 if release else 0)
    return [0xE0, code] if k["extended"] else [code]


def char_keys(ch: str) -> list[str]:
    """The keys that type one character: SHIFT first for capitals and the shifted symbols."""
    if ch.isascii() and ch.isalpha():
        return ["SHIFT", ch.upper()] if ch.isupper() else [ch.upper()]
    if ch.isdigit():
        return [ch]
    if ch in SHIFTED:
        return ["SHIFT", *char_keys(SHIFTED[ch])]
    if ch in CHAR_KEYS:
        return [CHAR_KEYS[ch]]
    raise ValueError(f"no key types {ch!r}")


@dataclass(order=True)
class Step:
    """One delivery at a time: keyboard bytes, a mouse button, or a mouse position or move."""

    t: float
    seq: int
    kind: str = field(compare=False)  # keys, button, mouse, move
    value: tuple = field(compare=False)
    source: str = field(compare=False, default="")
    item: int = field(compare=False, default=0)  # the script item it comes from, from 1


INPUT_ITEM = re.compile(r't=(?P<t>[0-9.]+):(?P<action>"[^"]*"|[^\s;]+)')
GAP = re.compile(r"[\s;]*")  # items are separated by white space or ';' (one inline argument)


def parse_input(script: str) -> list[Step]:
    """`t=10:ENTER t=12:"abc" t=13:ctrl+F6 t=14:RIGHT*2 t=15:mouse:160,100 t=15.5:click
    t=16:click:right t=17:down:left t=18:up:left t=19:move:-8,4` (items separated by white space
    or ';', one a line in a file; # starts a comment) -> the steps in time order."""
    text = "\n".join(line.split("#", 1)[0] for line in script.splitlines())
    steps: list[Step] = []
    pos = 0
    for item, m in enumerate(INPUT_ITEM.finditer(text), 1):
        if not GAP.fullmatch(text[pos : m.start()]):
            raise ValueError(
                f"--input: {text[pos : m.start()].strip(' ;')!r} is not t=SECONDS:ACTION"
            )
        pos = m.end()
        try:
            t = float(m["t"])
        except ValueError:
            raise ValueError(f"--input {m[0]!r}: t= takes seconds") from None
        for s in _action_steps(t, m["action"], m[0]):
            s.item = item
            steps.append(s)
    if not GAP.fullmatch(text[pos:]):
        raise ValueError(f"--input: {text[pos:].strip(' ;')!r} is not t=SECONDS:ACTION")
    for i, s in enumerate(sorted(steps)):
        s.seq = i
    return sorted(steps)


def _action_steps(t: float, action: str, source: str) -> list[Step]:
    def step(at: float, kind: str, value: tuple) -> Step:
        return Step(at, 0, kind, value, source)

    if action.startswith('"'):
        out, at = [], t
        for ch in action[1:-1]:
            keys = char_keys(ch)
            out.append(step(at, "keys", tuple(b for k in keys for b in key_bytes(k))))
            release = [b for k in reversed(keys) for b in key_bytes(k, release=True)]
            out.append(step(at + KEY_HOLD, "keys", tuple(release)))
            at += TYPE_GAP
        return out
    word, _, rest = action.partition(":")
    lower = word.lower()
    if lower in ("click", "down", "up"):
        button = (rest or "left").lower()
        if button not in BUTTONS:
            raise ValueError(f"--input {source!r}: a button is left, right or middle")
        b = BUTTONS[button]
        if lower == "down":
            return [step(t, "button", (b, True))]
        if lower == "up":
            return [step(t, "button", (b, False))]
        return [step(t, "button", (b, True)), step(t + KEY_HOLD, "button", (b, False))]
    if lower in ("mouse", "move"):
        try:
            x, y = (int(v) for v in rest.split(","))
        except ValueError:
            raise ValueError(f"--input {source!r}: {lower}:X,Y in whole numbers") from None
        if lower == "mouse" and (x < 0 or y < 0):
            raise ValueError(f"--input {source!r}: a position is at least 0,0")
        return [step(t, lower, (x, y))]
    chord, _, hold_text = action.partition("*")
    try:
        hold = float(hold_text) if hold_text else KEY_HOLD
    except ValueError:
        raise ValueError(f"--input {source!r}: KEY*SECONDS holds a key") from None
    names = [k for k in chord.split("+") if k]
    try:
        down = tuple(b for k in names for b in key_bytes(k))
        up = tuple(b for k in reversed(names) for b in key_bytes(k, release=True))
    except ValueError as exc:
        raise ValueError(f"--input {source!r}: {exc}") from None
    return [step(t, "keys", down), step(t + hold, "keys", up)]


def integration_values(step: Step) -> list[int]:
    """The values written to the integration device's data port for keys and buttons. (Its mouse
    moves do nothing headless: the driver then takes the host pointer's place, which only an SDL
    motion event sets; the pointer is placed through INT 33h 0004h instead, see the docstring.)"""
    if step.kind == "keys":
        return [INJECT_KEYBOARD << 8 | b for b in step.value]
    if step.kind == "button":
        button, pressed = step.value
        return [INJECT_BUTTON << 8 | (0x80 if pressed else 0) | button]
    raise ValueError(f"{step.kind} does not go through the integration device")


def integration_commands(values: list[int]) -> list[str]:
    """Debugger commands: reset the device's byte latch, select the inject register, write."""
    return [
        "OUTB 02A 00",
        f"OUTD 028 0{INTEGRATION_INJECT:X}",
        *(f"OUTD 029 0{v:X}" for v in values),
    ]


@dataclass
class Actions:
    """Everything a run does besides tracing: --dump, --poke, --input and --regions' sync points."""

    dumps: list[Dump] = field(default_factory=list)
    pokes: list[Poke] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    syncs: list[Sync] = field(default_factory=list)

    @classmethod
    def from_args(
        cls,
        dumps: list[str],
        pokes: list[str],
        script: str | None,
        syncs: list[Sync] | None = None,
    ) -> Actions:
        actions = cls(
            [parse_dump(d) for d in dumps],
            [parse_poke(p) for p in pokes],
            parse_input(script) if script else [],
            list(syncs or []),
        )
        items = max((s.item for s in actions.steps), default=0)
        for action in actions.memory():
            if action.trigger.kind == "input" and action.trigger.item > items:  # type: ignore[operator]
                raise ValueError(
                    f"{action.text}: the --input script has {items} item(s), "
                    f"not {action.trigger.item}"
                )
        return actions

    def __bool__(self) -> bool:
        return bool(self.dumps or self.pokes or self.steps or self.syncs)

    def memory(self) -> list[Dump | Poke | Sync]:
        """Pokes before dumps at one trigger, so a dump shows what was written; sync points last."""
        return [*self.pokes, *self.dumps, *self.syncs]

    def breakpoints(self) -> list[tuple[int, int | None, int | None]]:
        out: list[tuple[int, int | None, int | None]] = []
        for action in self.memory():
            for spec in action.trigger.breakpoints():
                if spec not in out:
                    out.append(spec)
        return out

    def pending(self, kind: str) -> list[Dump | Poke | Sync]:
        return [a for a in self.memory() if not a.done and a.trigger.kind == kind]

    def due(self, now: float, delivered: set[int] | frozenset[int] = frozenset()) -> list:
        """The actions whose time has come, or whose --input item has been delivered."""
        timed = [a for a in self.pending("time") if a.trigger.seconds <= now]  # type: ignore[operator]
        return timed + [a for a in self.pending("input") if a.trigger.item in delivered]
