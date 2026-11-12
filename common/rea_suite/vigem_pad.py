"""A virtual Xbox 360 pad that presses buttons on a schedule, through ViGEm. Windows only.

  rea-suite pad --presses 30:DOWN,33:A,36:A+B:0.5 [--idle-pad] [--dll ViGEmClient.dll]
  rea-suite pad --check                     the driver answers (no pad is plugged in)
  rea-suite pad --presses ... --dry-run     print the schedule only (any platform)
  rea-suite pad --stdin                     press what each line of stdin says, when it arrives

For testing a game's pad input without a person: plug in a pad, wait for each press's time
(seconds from when the pad was plugged in), hold it (--hold, or :SECONDS on the press), release
it, and unplug at the end (--tail seconds after the last press). A press is a button or several
joined by +: A B X Y, UP DOWN LEFT RIGHT, START BACK, LB RB (shoulders), LS RS (stick clicks),
GUIDE, LT RT (full trigger) and LX+ LX- LY+ LY- RX+ RX- RY+ RY- (full stick deflection).
--idle-pad plugs in a pad that never presses anything first, so the scripted one is the second
(user index 1), the way a remote-play or streaming setup leaves a virtual pad in the first slot.

With --stdin the pad takes its presses live, one a line (BUTTON[+BUTTON][:HOLD]), and unplugs
--tail seconds after stdin closes: `rea-suite run` drives it that way, pressing only while the
game's window is in front. Each event is a JSON line with `t`, the seconds since the pad was
plugged in, so a harness can line its captures up with the presses.

ViGEmClient.dll comes from your own copy (--dll, or REA_VIGEMCLIENT_DLL): the ViGEmClient
library built from nefarius/ViGEmClient, or the one a Python or game tool you trust ships. The
ViGEmBus driver must be installed (docs/PORT-TOOLS.md).

Each press is confirmed: while it is held, XInputGetState (xinput1_4) is polled every 5 ms for the
pad's user index until the pressed buttons show (`confirmed`, with the delay), or the hold ends
(`lost`). A press can reach the driver and still never show in XInput (seen 2026-11-12), so a run
without `confirmed` events proves nothing. --no-confirm turns this off; --fail-lost exits 3 when a
press was lost or its update failed. A failed vigem_target_x360_update is an `update-failed` event
and a line on stderr.

Exit 0: done; 1: a bad schedule; 2: no DLL, no driver, or not Windows; 3: a press was lost
(--fail-lost).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

OK = 0x20000000  # VIGEM_ERROR_NONE
ERRORS = {
    0xE0000001: "VIGEM_ERROR_BUS_NOT_FOUND",
    0xE0000002: "VIGEM_ERROR_NO_FREE_SLOT",
    0xE0000003: "VIGEM_ERROR_INVALID_TARGET",
    0xE0000004: "VIGEM_ERROR_REMOVAL_FAILED",
    0xE0000005: "VIGEM_ERROR_ALREADY_CONNECTED",
    0xE0000006: "VIGEM_ERROR_TARGET_UNINITIALIZED",
    0xE0000007: "VIGEM_ERROR_TARGET_NOT_PLUGGED_IN",
    0xE0000008: "VIGEM_ERROR_BUS_VERSION_MISMATCH",
    0xE0000009: "VIGEM_ERROR_BUS_ACCESS_FAILED",
    0xE0000010: "VIGEM_ERROR_CALLBACK_ALREADY_REGISTERED",
    0xE0000011: "VIGEM_ERROR_CALLBACK_NOT_FOUND",
    0xE0000012: "VIGEM_ERROR_BUS_ALREADY_CONNECTED",
    0xE0000013: "VIGEM_ERROR_BUS_INVALID_HANDLE",
    0xE0000014: "VIGEM_ERROR_XUSB_USERINDEX_OUT_OF_RANGE",
    0xE0000015: "VIGEM_ERROR_INVALID_PARAMETER",
    0xE0000016: "VIGEM_ERROR_NOT_SUPPORTED",
    0xE0000017: "VIGEM_ERROR_WINAPI",
    0xE0000018: "VIGEM_ERROR_TIMED_OUT",
    0xE0000019: "VIGEM_ERROR_IS_DISPOSING",
}  # ViGEmClient.h's VIGEM_ERROR
POLL = 0.005  # seconds between XInputGetState polls while a press is confirmed
BUTTONS = {
    "UP": 0x0001, "DOWN": 0x0002, "LEFT": 0x0004, "RIGHT": 0x0008, "START": 0x0010,
    "BACK": 0x0020, "LS": 0x0040, "RS": 0x0080, "LB": 0x0100, "RB": 0x0200, "GUIDE": 0x0400,
    "A": 0x1000, "B": 0x2000, "X": 0x4000, "Y": 0x8000,
}  # fmt: skip
TRIGGERS = {"LT": "lt", "RT": "rt"}
STICKS = {f"{axis}{sign}": (axis.lower(), 32767 if sign == "+" else -32768)
          for axis in ("LX", "LY", "RX", "RY") for sign in "+-"}  # fmt: skip


class Report(ctypes.Structure):
    """XUSB_REPORT, passed by value to vigem_target_x360_update."""

    _fields_ = [
        ("buttons", ctypes.c_ushort),
        ("lt", ctypes.c_ubyte),
        ("rt", ctypes.c_ubyte),
        ("lx", ctypes.c_short),
        ("ly", ctypes.c_short),
        ("rx", ctypes.c_short),
        ("ry", ctypes.c_short),
    ]


def error_name(code: int) -> str:
    """A ViGEm result as its VIGEM_ERROR name where known, else in hex."""
    return ERRORS.get(code, f"{code:#x}")


class XInputState(ctypes.Structure):
    """XINPUT_STATE: the packet number, then XINPUT_GAMEPAD, laid out as XUSB_REPORT."""

    _fields_ = [("packet", ctypes.c_ulong), ("pad", Report)]


@dataclass
class Press:
    at: float
    names: list[str]
    hold: float

    def report(self) -> Report:
        report = Report()
        for name in self.names:
            if name in BUTTONS:
                report.buttons |= BUTTONS[name]
            elif name in TRIGGERS:
                setattr(report, TRIGGERS[name], 255)
            else:
                axis, value = STICKS[name]
                setattr(report, axis, value)
        return report


def press(buttons: str, at: float, hold: float, item: str = "") -> Press:
    """'A+B' at a time, held this long; ValueError on anything unknown."""
    item = item or buttons
    names = [n.strip().upper() for n in buttons.split("+")]
    unknown = [n for n in names if n not in BUTTONS and n not in TRIGGERS and n not in STICKS]
    if unknown:
        raise ValueError(f"unknown button {unknown[0]!r} in {item!r}")
    if at < 0 or hold <= 0:
        raise ValueError(f"time and hold must be positive: {item!r}")
    return Press(at, names, hold)


def schedule(text: str, hold: float) -> list[Press]:
    """'30:DOWN,33:A+B:0.5' -> presses sorted by time; ValueError on anything unknown."""
    presses = []
    for item in filter(None, (part.strip() for part in text.split(","))):
        parts = item.split(":")
        if len(parts) not in (2, 3):
            raise ValueError(f"a press is TIME:BUTTON[+BUTTON][:HOLD]: {item!r}")
        length = float(parts[2]) if len(parts) == 3 else hold
        presses.append(press(parts[1], float(parts[0]), length, item))
    return sorted(presses, key=lambda p: p.at)


def live_press(line: str, hold: float) -> Press:
    """A line of --stdin, 'A+B' or 'A+B:0.5': pressed now; ValueError on anything unknown."""
    parts = line.strip().split(":")
    if len(parts) not in (1, 2) or not parts[0]:
        raise ValueError(f"a live press is BUTTON[+BUTTON][:HOLD]: {line.strip()!r}")
    return press(parts[0], 0.0, float(parts[1]) if len(parts) == 2 else hold, line.strip())


def emit(start: float, **fields) -> None:
    print(json.dumps({"t": round(time.monotonic() - start, 3), **fields}), flush=True)


class Client:
    def __init__(self, dll: Path):
        self.lib = ctypes.WinDLL(str(dll))  # type: ignore[attr-defined]
        lib = self.lib
        lib.vigem_alloc.restype = ctypes.c_void_p
        lib.vigem_free.argtypes = [ctypes.c_void_p]
        lib.vigem_connect.argtypes = [ctypes.c_void_p]
        lib.vigem_connect.restype = ctypes.c_uint32
        lib.vigem_disconnect.argtypes = [ctypes.c_void_p]
        lib.vigem_target_x360_alloc.restype = ctypes.c_void_p
        lib.vigem_target_free.argtypes = [ctypes.c_void_p]
        lib.vigem_target_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.vigem_target_add.restype = ctypes.c_uint32
        lib.vigem_target_remove.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.vigem_target_remove.restype = ctypes.c_uint32
        lib.vigem_target_x360_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, Report]
        lib.vigem_target_x360_update.restype = ctypes.c_uint32
        lib.vigem_target_x360_get_user_index.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)
        ]  # fmt: skip
        lib.vigem_target_x360_get_user_index.restype = ctypes.c_uint32
        self.client = lib.vigem_alloc()
        if not self.client:
            raise OSError("vigem_alloc failed")
        result = lib.vigem_connect(self.client)
        if result != OK:
            lib.vigem_free(self.client)
            raise OSError(
                f"vigem_connect: {error_name(result)} (is the ViGEmBus driver installed?)"
            )
        self.targets: list[int] = []

    def plug(self) -> int:
        target = self.lib.vigem_target_x360_alloc()
        result = self.lib.vigem_target_add(self.client, target)
        if result != OK:
            self.lib.vigem_target_free(target)
            raise OSError(f"vigem_target_add: {error_name(result)}")
        self.targets.append(target)
        return target

    def user_index(self, target: int) -> int | None:
        index = ctypes.c_ulong()
        ok = self.lib.vigem_target_x360_get_user_index(self.client, target, ctypes.byref(index))
        return index.value if ok == OK else None

    def update(self, target: int, report: Report) -> int:
        """The driver's result: OK, or a VIGEM_ERROR code."""
        return self.lib.vigem_target_x360_update(self.client, target, report)

    def close(self) -> None:
        for target in reversed(self.targets):
            self.lib.vigem_target_remove(self.client, target)
            self.lib.vigem_target_free(target)
        self.targets = []
        self.lib.vigem_disconnect(self.client)
        self.lib.vigem_free(self.client)


def wait_until(start: float, at: float) -> None:
    while (left := at - (time.monotonic() - start)) > 0:
        time.sleep(min(left, 0.02))


class XInput:
    """xinput1_4's XInputGetState: what a game reading XInput sees of a pad."""

    def __init__(self) -> None:
        self.get = ctypes.WinDLL("xinput1_4").XInputGetState  # type: ignore[attr-defined]
        self.get.argtypes = [ctypes.c_ulong, ctypes.POINTER(XInputState)]
        self.get.restype = ctypes.c_ulong

    def state(self, index: int) -> XInputState | None:
        state = XInputState()
        return state if self.get(index, ctypes.byref(state)) == 0 else None


def wanted(report: Report) -> Report:
    """What must show in XInput for a press; XInputGetState hides GUIDE, so it is left out."""
    want = Report.from_buffer_copy(report)
    want.buttons &= ~BUTTONS["GUIDE"]
    return want


def shows(state: Report, want: Report) -> bool:
    """The state holds the press: its buttons, triggers past half, sticks past half its way."""
    if state.buttons & want.buttons != want.buttons:
        return False
    for trigger in ("lt", "rt"):
        if getattr(want, trigger) and getattr(state, trigger) < getattr(want, trigger) // 2:
            return False
    for axis in ("lx", "ly", "rx", "ry"):
        goal, now = getattr(want, axis), getattr(state, axis)
        if goal and (now * goal <= 0 or abs(now) < abs(goal) // 2):
            return False
    return True


def confirm(xinput: XInput, index: int, want: Report, limit: float) -> float | None:
    """Seconds until XInput shows the press at this user index, or None within the limit."""
    began = time.monotonic()
    while True:
        state = xinput.state(index)
        seen = time.monotonic() - began
        if state is not None and shows(state.pad, want):
            return seen
        if seen >= limit:
            return None
        time.sleep(POLL)


def update(client: Client, target: int, start: float, report: Report, item: Press, op: str) -> bool:
    """Send a report; a failure is an event and a line on stderr, never silent."""
    result = client.update(target, report)
    if result == OK:
        return True
    name = "+".join(item.names)
    emit(start, event="update-failed", op=op, press=name, error=error_name(result), code=result)
    print(f"pad: vigem_target_x360_update ({op} {name}): {error_name(result)}", file=sys.stderr)
    return False


def play(
    client: Client, target: int, start: float, item: Press, xinput: XInput | None = None
) -> bool:
    """Press, hold, release; False when the press failed to send or XInput never showed it."""
    name = "+".join(item.names)
    emit(start, event="press", press=name, hold=item.hold)
    began = time.monotonic()
    report = item.report()
    sent = update(client, target, start, report, item, "press")
    seen = True
    if sent and xinput is not None:
        want = wanted(report)
        index = client.user_index(target)
        if not any(getattr(want, field) for field, _ in Report._fields_):
            emit(start, event="unchecked", press=name, reason="XInputGetState hides GUIDE")
        elif index is None:
            seen = False
            emit(start, event="lost", press=name, reason="the pad has no XInput user index")
        elif (delay := confirm(xinput, index, want, item.hold)) is None:
            seen = False
            emit(start, event="lost", press=name, user_index=index, hold=item.hold)
        else:
            emit(start, event="confirmed", press=name, user_index=index, delay=round(delay, 3))
    time.sleep(max(0.0, item.hold - (time.monotonic() - began)))
    released = update(client, target, start, Report(), item, "release")
    return sent and seen and released


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite pad",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    p.add_argument("--presses", default="", help="TIME:BUTTON[+BUTTON][:HOLD],...")
    p.add_argument("--hold", type=float, default=0.15, help="seconds a press is held (0.15)")
    p.add_argument(
        "--tail", type=float, default=2.0, help="seconds plugged in after the last press"
    )
    p.add_argument("--idle-pad", action="store_true", help="an idle pad in the first slot")
    p.add_argument("--dll", type=Path, help="ViGEmClient.dll (default: $REA_VIGEMCLIENT_DLL)")
    p.add_argument("--check", action="store_true", help="connect to the driver and stop")
    p.add_argument("--stdin", action="store_true", help="live presses, one a line of stdin")
    p.add_argument("--dry-run", action="store_true", help="print the schedule; no DLL")
    p.add_argument(
        "--no-confirm", action="store_true", help="do not check presses show in XInputGetState"
    )
    p.add_argument("--fail-lost", action="store_true", help="exit 3 when a press was lost")
    return p


def drive(
    client: Client, xinput: XInput | None, args: argparse.Namespace, presses: list[Press]
) -> int:
    """Plug in, press, unplug; 3 when a press was lost and --fail-lost asks to fail."""
    idle = client.plug() if args.idle_pad else None
    if idle is not None:
        time.sleep(1.0)  # let XInput give the idle pad its slot first
    target = client.plug()
    start = time.monotonic()
    emit(
        start,
        event="plugged",
        user_index=client.user_index(target),
        idle_pad=None if idle is None else client.user_index(idle),
        confirm=xinput is not None,
    )
    lost = 0
    for item in presses:
        wait_until(start, item.at)
        lost += not play(client, target, start, item, xinput)
    if args.stdin:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                item = live_press(line, args.hold)
            except ValueError as exc:
                emit(start, event="refused", line=line.strip(), reason=str(exc))
                continue
            lost += not play(client, target, start, item, xinput)
    time.sleep(args.tail)
    emit(start, event="unplugged", lost=lost)
    if lost:
        print(f"pad: {lost} press(es) lost or not sent", file=sys.stderr)
    return 3 if lost and args.fail_lost else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        presses = schedule(args.presses, args.hold)
    except ValueError as exc:
        print(f"pad: {exc}", file=sys.stderr)
        return 1
    if args.dry_run:
        for item in presses:
            print(json.dumps({"at": item.at, "press": "+".join(item.names), "hold": item.hold}))
        return 0
    if args.stdin and presses:
        print("pad: give --presses or --stdin, not both", file=sys.stderr)
        return 1
    if not presses and not args.check and not args.stdin:
        print("pad: give --presses, --stdin (or --check)", file=sys.stderr)
        return 1
    if os.name != "nt":
        print("pad: ViGEm is Windows only (--dry-run works anywhere)", file=sys.stderr)
        return 2
    dll = args.dll or (
        Path(os.environ["REA_VIGEMCLIENT_DLL"]) if "REA_VIGEMCLIENT_DLL" in os.environ else None
    )
    if dll is None:
        print("pad: give --dll or set REA_VIGEMCLIENT_DLL to your ViGEmClient.dll", file=sys.stderr)
        return 2
    try:
        client = Client(args.caller_cwd / dll)
    except OSError as exc:
        print(f"pad: {exc}", file=sys.stderr)
        return 2
    try:
        if args.check:
            print(json.dumps({"driver": "connected", "dll": str(args.caller_cwd / dll)}))
            return 0
        xinput = None
        if not args.no_confirm:
            try:
                xinput = XInput()
            except (OSError, AttributeError) as exc:
                print(f"pad: no xinput1_4, presses are not confirmed: {exc}", file=sys.stderr)
        return drive(client, xinput, args, presses)
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"pad: {exc}", file=sys.stderr)
        return 2
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
