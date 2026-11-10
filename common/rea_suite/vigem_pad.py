"""A virtual Xbox 360 pad that presses buttons on a schedule, through ViGEm. Windows only.

  rea-suite pad --presses 30:DOWN,33:A,36:A+B:0.5 [--idle-pad] [--dll ViGEmClient.dll]
  rea-suite pad --check                     the driver answers (no pad is plugged in)
  rea-suite pad --presses ... --dry-run     print the schedule only (any platform)

For testing a game's pad input without a person: plug in a pad, wait for each press's time
(seconds from when the pad was plugged in), hold it (--hold, or :SECONDS on the press), release
it, and unplug at the end (--tail seconds after the last press). A press is a button or several
joined by +: A B X Y, UP DOWN LEFT RIGHT, START BACK, LB RB (shoulders), LS RS (stick clicks),
GUIDE, LT RT (full trigger) and LX+ LX- LY+ LY- RX+ RX- RY+ RY- (full stick deflection).
--idle-pad plugs in a pad that never presses anything first, so the scripted one is the second
(user index 1), the way a remote-play or streaming setup leaves a virtual pad in the first slot.

Each event is a JSON line with `t`, the seconds since the pad was plugged in, so a harness
(platforms/windows/window-oracle.ps1) can line its captures up with the presses.

ViGEmClient.dll comes from your own copy (--dll, or REA_VIGEMCLIENT_DLL): the ViGEmClient
library built from nefarius/ViGEmClient, or the one a Python or game tool you trust ships. The
ViGEmBus driver must be installed (docs/PORT-TOOLS.md). Exit 0: done; 1: a bad schedule; 2: no
DLL, no driver, or not Windows.
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


def schedule(text: str, hold: float) -> list[Press]:
    """'30:DOWN,33:A+B:0.5' -> presses sorted by time; ValueError on anything unknown."""
    presses = []
    for item in filter(None, (part.strip() for part in text.split(","))):
        parts = item.split(":")
        if len(parts) not in (2, 3):
            raise ValueError(f"a press is TIME:BUTTON[+BUTTON][:HOLD]: {item!r}")
        names = [n.strip().upper() for n in parts[1].split("+")]
        unknown = [n for n in names if n not in BUTTONS and n not in TRIGGERS and n not in STICKS]
        if unknown:
            raise ValueError(f"unknown button {unknown[0]!r} in {item!r}")
        at, length = float(parts[0]), float(parts[2]) if len(parts) == 3 else hold
        if at < 0 or length <= 0:
            raise ValueError(f"time and hold must be positive: {item!r}")
        presses.append(Press(at, names, length))
    return sorted(presses, key=lambda p: p.at)


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
            raise OSError(f"vigem_connect: {result:#x} (is the ViGEmBus driver installed?)")
        self.targets: list[int] = []

    def plug(self) -> int:
        target = self.lib.vigem_target_x360_alloc()
        result = self.lib.vigem_target_add(self.client, target)
        if result != OK:
            self.lib.vigem_target_free(target)
            raise OSError(f"vigem_target_add: {result:#x}")
        self.targets.append(target)
        return target

    def user_index(self, target: int) -> int | None:
        index = ctypes.c_ulong()
        ok = self.lib.vigem_target_x360_get_user_index(self.client, target, ctypes.byref(index))
        return index.value if ok == OK else None

    def update(self, target: int, report: Report) -> None:
        self.lib.vigem_target_x360_update(self.client, target, report)

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


def main(argv: list[str] | None = None) -> int:
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
    p.add_argument("--dry-run", action="store_true", help="print the schedule; no DLL")
    args = p.parse_args(argv)
    try:
        presses = schedule(args.presses, args.hold)
    except ValueError as exc:
        print(f"pad: {exc}", file=sys.stderr)
        return 1
    if args.dry_run:
        for press in presses:
            print(json.dumps({"at": press.at, "press": "+".join(press.names), "hold": press.hold}))
        return 0
    if not presses and not args.check:
        print("pad: give --presses (or --check)", file=sys.stderr)
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
        )
        for press in presses:
            wait_until(start, press.at)
            emit(start, event="press", press="+".join(press.names), hold=press.hold)
            client.update(target, press.report())
            time.sleep(press.hold)
            client.update(target, Report())
        time.sleep(args.tail)
        emit(start, event="unplugged")
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
