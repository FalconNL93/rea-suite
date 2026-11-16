"""Drive a PSXRecomp game from a script, through its debug server (docs/PS1.md, step 7).

  rea-suite playstation drive SCRIPT [--port N] [--host HOST] [--plan]

The game runs with `PSX_DEBUG_SERVER=1 --debug-port N`; the port and host come from the options or
REA_PSXRECOMP_PORT and REA_PSXRECOMP_HOST (default 127.0.0.1). A script line is
`<seconds from start> <step>`, `#` starts a comment, and the lines run in order of their time:

  <s> <button>[+<button>...] [frames]   hold first-pad buttons for that many guest frames (default
                                         4): start select cross circle square triangle up down left
                                         right l1 r1 l2 r2 l3 r3 (`press`, then `pad_status` logged)
  <s> host-button <name>                 press and release a host gamepad button, SDL's name (a,
                                         rightstick), as an SDL event a player's would be
  <s> host-key <name>                    the same for a key, SDL's scancode name (K, Return)
  <s> read <address> <bytes>             log guest RAM there in hex (`read_ram`)
  <s> write <address> <hex byte>         write one byte of guest RAM (`write_ram`)
  <s> raw <json>                         send any debug server command as it is
  <s> wait <address> <hex byte> [timeout]
                                         poll until guest RAM's byte there is that value (default
                                         timeout 60 s), then shift every later step by the time
                                         waited, so a script keys on the game's state, not a clock

The format is duke-nukem-ttk's tools/drive.py's, which this replaced. Every reply is logged as a
`drive:` line; the target's text goes through text.printable().
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from rea_suite.oracle_psxrecomp import exchange
from rea_suite.text import printable

# The SIO bit of each button; the debug server takes the wire's active-low word.
BITS = {
    "select": 0,
    "l3": 1,
    "r3": 2,
    "start": 3,
    "up": 4,
    "right": 5,
    "down": 6,
    "left": 7,
    "l2": 8,
    "r2": 9,
    "l1": 10,
    "r1": 11,
    "triangle": 12,
    "circle": 13,
    "cross": 14,
    "square": 15,
}
DEFAULT_FRAMES = 4
DEFAULT_WAIT = 60.0
POLL = 0.1  # seconds between a wait's reads
SETTLE = 0.05  # seconds after a press before its pad_status is read


def parse_line(words: list[str]) -> dict:
    """One script line's step (its time removed), as the debug server command it sends."""
    kind = words[0]
    if kind == "wait" and len(words) in (3, 4):
        timeout = float(words[3]) if len(words) == 4 else DEFAULT_WAIT
        return {"wait": words[1], "value": int(words[2], 16), "timeout": timeout}
    if kind == "raw" and len(words) >= 2:
        command = json.loads(" ".join(words[1:]))
        if not isinstance(command, dict) or "cmd" not in command:
            raise ValueError("raw takes a JSON object with a cmd")
        return command
    if kind == "read" and len(words) == 3:
        return {"cmd": "read_ram", "addr": words[1], "len": int(words[2], 0)}
    if kind == "write" and len(words) == 3:
        value = int(words[2], 16)
        if not 0 <= value <= 0xFF:
            raise ValueError("write takes one hex byte")
        return {"cmd": "write_ram", "addr": words[1], "val": f"{value:02x}"}
    if kind in ("host-button", "host-key") and len(words) == 2:
        return {"cmd": kind.replace("-", "_"), "name": words[1]}
    if len(words) not in (1, 2):
        raise ValueError("expected '<seconds> <buttons> [frames]' or a named step")
    mask = 0
    for name in kind.split("+"):
        if name not in BITS:
            raise ValueError(f"unknown button {name}")
        mask |= 1 << BITS[name]
    frames = int(words[1]) if len(words) == 2 else DEFAULT_FRAMES
    return {"cmd": "press", "buttons": ~mask & 0xFFFF, "frames": frames}


def parse(text: str, origin: str = "script") -> list[tuple[float, dict]]:
    steps = []
    for number, raw in enumerate(text.splitlines(), 1):
        words = raw.split("#", 1)[0].split()
        if not words:
            continue
        try:
            if len(words) < 2:
                raise ValueError("expected '<seconds> <step>'")
            steps.append((float(words[0]), parse_line(words[1:])))
        except ValueError as exc:  # json.JSONDecodeError is one
            raise ValueError(f"{origin}:{number}: {exc}") from None
    return sorted(steps, key=lambda step: step[0])  # stable: equal times keep the script's order


class Driver:
    def __init__(self, host: str, port: int, timeout: float, out=None):
        self.host, self.port, self.timeout, self.out = host, port, timeout, out

    def send(self, command: dict) -> str:
        return (
            exchange(self.host, self.port, command, self.timeout).decode("utf-8", "replace").strip()
        )

    def log(self, text: str) -> None:
        print(f"drive: {text}", file=self.out or sys.stdout, flush=True)

    def wait(self, step: dict) -> str:
        """Poll a guest byte until it has the value or the step times out."""
        until = time.monotonic() + step["timeout"]
        while time.monotonic() < until:
            try:
                reply = json.loads(self.send({"cmd": "read_ram", "addr": step["wait"], "len": 1}))
                if int(reply.get("hex", "zz"), 16) == step["value"]:
                    return "reached"
            except (OSError, ValueError):
                pass
            time.sleep(POLL)
        return "timed out"

    def run(self, steps: list[tuple[float, dict]]) -> None:
        start = time.monotonic()
        for at, command in steps:
            time.sleep(max(0.0, start + at - time.monotonic()))
            if "wait" in command:
                began = time.monotonic()
                result = self.wait(command)
                waited = time.monotonic() - began
                start += waited
                self.log(
                    f"{at:.1f}s wait {printable(command['wait'])} == 0x{command['value']:02X}: "
                    f"{result} after {waited:.1f}s"
                )
                continue
            try:
                reply = self.send(command)
            except OSError as error:
                reply = f"no answer ({error})"
            status = ""
            if command["cmd"] == "press":
                time.sleep(SETTLE)
                try:
                    status = " pad " + self.send({"cmd": "pad_status"})
                except OSError as error:
                    status = f" pad: no answer ({error})"
            self.log(f"{at:.1f}s {json.dumps(command)}: {printable(reply + status)}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite playstation drive",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("script", type=Path, help="the script (format above)")
    p.add_argument(
        "--host",
        default=os.environ.get("REA_PSXRECOMP_HOST", "127.0.0.1"),
        help="the debug server's host (REA_PSXRECOMP_HOST; default 127.0.0.1)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=os.environ.get("REA_PSXRECOMP_PORT"),
        help="the debug server's port, the game's --debug-port (REA_PSXRECOMP_PORT)",
    )
    p.add_argument(
        "--timeout", type=float, default=10.0, help="seconds a command waits for its reply"
    )
    p.add_argument(
        "--plan", action="store_true", help="print the parsed steps as JSON; connect to nothing"
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    try:
        path = args.caller_cwd / args.script
        steps = parse(path.read_text(encoding="utf-8"), str(args.script))
    except (OSError, ValueError) as exc:
        p.exit(2, f"drive: {exc}\n")
    if args.plan:
        print(json.dumps([{"at": at, **command} for at, command in steps], indent=2))
        return 0
    if args.port is None or not 0 < int(args.port) < 65536:
        p.error("give the debug server's port: --port N or REA_PSXRECOMP_PORT")
    Driver(args.host, int(args.port), args.timeout).run(steps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
