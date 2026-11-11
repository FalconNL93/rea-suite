"""One bounded, observed run of a Windows program, driven by a script of steps. Windows and WSL.

  rea-suite run [options] --start PROGRAM [ARG...]   start it, run the script, end it, report
  rea-suite run [options] --attach NAME|PID          the same for a process started some other way
  rea-suite run --script FILE --dry-run --start PROGRAM   check the script, print the plan (anywhere)

--start comes last: everything after it is the program and its arguments.

For running a game without a person at it, and keeping what happened: the program starts with
the arguments, environment (--env NAME=VALUE) and working folder (--cwd) given, inside a job
object, so everything it starts ends with it. The script's steps run in order (--script FILE or
--steps 'wait 5; key ENTER'); one a line, # starts a comment:

  wait SECONDS                 pause
  at SECONDS                   wait until this long after the start
  wait-window [SECONDS]        until the program has a window (default 60)
  focus                        bring the window to the front; fails when it does not come
  key CHORD [hold SECONDS]     keys joined by +, by scan code: ENTER, ctrl+shift+F6, sc:0x29
  text "STRING"                typed as characters (KEYEVENTF_UNICODE; menus, consoles)
  click X Y [left|right|middle] [hold SECONDS]   at the window's client coordinates
  move X Y                     the mouse to client coordinates
  pad BUTTONS [hold SECONDS]   a press on rea-suite pad's virtual pad: A, A+B, DOWN, LT, LX-
  capture [NAME]               a capture now
  close                        end the run now

Keyboard, mouse and pad input go out only while the program's window is verified in front (one
focus attempt first); otherwise the step is refused and the report says which window was in
front instead. The window is kept in front for the whole run (--no-keep-front to leave it):
some engines only tick while active. Captures (every --capture-every seconds, at `capture`
steps and at the end) use PrintWindow on the window's client area, and the window's area of
the screen when PrintWindow blocks, fails or comes out black while the window is in front.
Message boxes (#32770) of the program are recorded with their title, text and buttons, and
answered with --answer BUTTON or --answer 'REGEX=BUTTON' (the first matching rule wins). Every
--sample-every seconds the loaded modules, the processes of the program's tree and their TCP and
UDP endpoints are written as JSON lines. --snapshot DIR (repeatable) records the install folder
before and after (size, modification time, and a SHA-256 of executables and DLLs) and fails the
run when anything in it changed.

The run ends at the `close` step, after --seconds, or when the program exits: the window gets
WM_CLOSE first, then after --close-grace seconds the job (and every process it saw) is killed.
An attached process is left running unless --close. Everything goes to --out (default
work/run/<time>): plan.json, events.jsonl, samples.jsonl, captures/, pad.jsonl and report.json
(exit code, timings, steps, captures, dialogs, what was seen, the install's changes, findings).

Under WSL the engine runs in Windows PowerShell 7 (pwsh.exe) and paths are translated. Take the
machine's display first where `heavy` exists: `heavy run --display -- rea-suite run ...`.

Exit 0: the run went as scripted; 1: it ran, with an error finding (a step refused or failed,
the install changed, something left running); 2: a bad script or arguments, no Windows, or the
program did not start.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

from rea_suite import vigem_pad

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "platforms" / "windows" / "run-harness.ps1"
REPORT_FORMAT = "rea-suite-run/1"
PLAN_FORMAT = "rea-suite-run-plan/1"
WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]|^\\\\")  # D:\x, D:/x, \\server\share
HASHED = (".exe", ".dll", ".sys", ".asi", ".ocx", ".drv", ".cpl", ".scr", ".com")

# Scan codes, set 1 (what SendInput's KEYEVENTF_SCANCODE takes): the physical key, whatever the
# keyboard layout, as a game reading raw input or DirectInput sees it. E0-prefixed keys are
# "extended" (KEYEVENTF_EXTENDEDKEY).
_ROWS = {
    0x02: "1 2 3 4 5 6 7 8 9 0 MINUS EQUALS BACKSPACE TAB Q W E R T Y U I O P LBRACKET RBRACKET "
          "ENTER CTRL A S D F G H J K L SEMICOLON APOSTROPHE GRAVE SHIFT BACKSLASH Z X C V B N M "
          "COMMA PERIOD SLASH RSHIFT MULTIPLY ALT SPACE CAPSLOCK F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 "
          "NUMLOCK SCROLLLOCK NUMPAD7 NUMPAD8 NUMPAD9 SUBTRACT NUMPAD4 NUMPAD5 NUMPAD6 ADD NUMPAD1 "
          "NUMPAD2 NUMPAD3 NUMPAD0 DECIMAL",
}  # fmt: skip
KEYS: dict[str, tuple[int, bool]] = {
    "ESC": (0x01, False),
    "F11": (0x57, False),
    "F12": (0x58, False),
}
for _first, _names in _ROWS.items():
    KEYS.update({name: (_first + i, False) for i, name in enumerate(_names.split())})
KEYS.update({
    name: (code, True) for name, code in {
        "RCTRL": 0x1D, "RALT": 0x38, "NUMPADENTER": 0x1C, "DIVIDE": 0x35, "HOME": 0x47,
        "UP": 0x48, "PGUP": 0x49, "LEFT": 0x4B, "RIGHT": 0x4D, "END": 0x4F, "DOWN": 0x50,
        "PGDN": 0x51, "INSERT": 0x52, "DELETE": 0x53, "LWIN": 0x5B, "RWIN": 0x5C, "APPS": 0x5D,
    }.items()
})  # fmt: skip
ALIASES = {
    "ESCAPE": "ESC", "RETURN": "ENTER", "LCTRL": "CTRL", "CONTROL": "CTRL", "LSHIFT": "SHIFT",
    "LALT": "ALT", "TILDE": "GRAVE", "BACKQUOTE": "GRAVE", "BACK": "BACKSPACE", "DEL": "DELETE",
    "INS": "INSERT", "PAGEUP": "PGUP", "PAGEDOWN": "PGDN", "WIN": "LWIN", "MENU": "APPS",
}  # fmt: skip
BUTTONS = ("left", "right", "middle")


class ScriptError(ValueError):
    """A step the parser refuses, with its line."""

    def __init__(self, line: int, message: str):
        super().__init__(f"line {line}: {message}")
        self.line = line


def key(name: str) -> dict:
    """'ENTER', 'sc:0x1c' or 'sc:0xe01c' -> {name, scan, extended}; ValueError when unknown."""
    upper = name.strip().upper()
    if upper.startswith("SC:"):
        value = int(upper[3:], 16)
        if value & 0xFF00 not in (0, 0xE000) or not value & 0xFF:
            raise ValueError(f"a scan code is 0xNN or 0xE0NN: {name!r}")
        return {"name": upper, "scan": value & 0xFF, "extended": bool(value & 0xE000)}
    upper = ALIASES.get(upper, upper)
    if upper not in KEYS:
        raise ValueError(f"unknown key {name!r}")
    scan, extended = KEYS[upper]
    return {"name": upper, "scan": scan, "extended": extended}


def _number(value: str, what: str, *, positive: bool = False) -> float:
    try:
        number = float(value)
    except ValueError:
        raise ValueError(f"{what} is a number: {value!r}") from None
    if number < 0 or (positive and number == 0):
        raise ValueError(f"{what} must be {'above' if positive else 'at least'} 0: {value!r}")
    return number


def _hold(words: list[str], default: float) -> tuple[list[str], float]:
    """Takes a trailing `hold SECONDS` off the words."""
    if len(words) >= 2 and words[-2].lower() == "hold":
        return words[:-2], _number(words[-1], "hold", positive=True)
    return words, default


def step(words: list[str]) -> dict:
    """One step's words -> its plan entry; ValueError on anything wrong."""
    op, rest = words[0].lower(), words[1:]
    if op in ("wait", "at"):
        if len(rest) != 1:
            raise ValueError(f"{op} SECONDS")
        return {"op": op, "seconds": _number(rest[0], "seconds")}
    if op == "wait-window":
        if len(rest) > 1:
            raise ValueError("wait-window [SECONDS]")
        return {"op": op, "seconds": _number(rest[0], "seconds", positive=True) if rest else 60.0}
    if op in ("focus", "close"):
        if rest:
            raise ValueError(f"{op} takes nothing")
        return {"op": op}
    if op == "capture":
        if len(rest) > 1 or (rest and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", rest[0])):
            raise ValueError("capture [NAME], a name of letters, digits, _ . -")
        return {"op": op, "name": rest[0] if rest else None}
    if op == "key":
        rest, hold = _hold(rest, 0.1)
        if len(rest) != 1:
            raise ValueError("key CHORD [hold SECONDS]")
        return {"op": op, "chord": [key(k) for k in rest[0].split("+")], "hold": hold}
    if op == "text":
        if len(rest) != 1 or not rest[0]:
            raise ValueError('text "STRING"')
        if any(ord(c) > 0xFFFF for c in rest[0]):
            raise ValueError("text outside the Basic Multilingual Plane")
        return {"op": op, "text": rest[0]}
    if op in ("click", "move"):
        rest, hold = _hold(rest, 0.1) if op == "click" else (rest, 0.0)
        button = "left"
        if op == "click" and len(rest) == 3:
            button = rest.pop().lower()
        if len(rest) != 2 or button not in BUTTONS:
            raise ValueError(
                f"{op} X Y" + (" [left|right|middle] [hold SECONDS]" * (op == "click"))
            )
        try:
            x, y = int(rest[0]), int(rest[1])
        except ValueError:
            raise ValueError(f"{op} takes whole pixels: {' '.join(rest)!r}") from None
        if x < 0 or y < 0:
            raise ValueError("client coordinates are at least 0")
        entry = {"op": op, "x": x, "y": y}
        return entry | ({"button": button, "hold": hold} if op == "click" else {})
    if op == "pad":
        rest, hold = _hold(rest, 0.15)
        if len(rest) != 1:
            raise ValueError("pad BUTTONS [hold SECONDS]")
        press = vigem_pad.press(rest[0], 0.0, hold)
        return {"op": op, "press": "+".join(press.names), "hold": hold}
    raise ValueError(f"unknown step {words[0]!r}")


def split_inline(text: str) -> list[str]:
    """--steps text: lines, and ; outside quotes, separate steps."""
    lines, current, quote = [], [], ""
    for char in text:
        if quote:
            quote = "" if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char in ";\n":
            lines.append("".join(current))
            current = []
            continue
        current.append(char)
    lines.append("".join(current))
    return lines


def parse_steps(lines: list[str]) -> list[dict]:
    """Script lines -> the plan's steps, each with its line and source; ScriptError when wrong."""
    steps = []
    for number, line in enumerate(lines, 1):
        try:
            words = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ScriptError(number, str(exc)) from None
        if not words:
            continue
        try:
            entry = step(words)
        except ValueError as exc:
            raise ScriptError(number, str(exc)) from None
        steps.append({"line": number, "source": line.strip()} | entry)
    return steps


def answers(rules: list[str]) -> list[dict]:
    """--answer BUTTON or REGEX=BUTTON -> rules; ValueError on a bad pattern."""
    out = []
    for rule in rules:
        pattern, _, button = rule.rpartition("=")
        if not button.strip():
            raise ValueError(f"--answer needs a button: {rule!r}")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"--answer {rule!r}: {exc}") from None
        out.append({"pattern": pattern or None, "button": button.strip()})
    return out


# --- the install snapshot ---------------------------------------------------------------


def snapshot(roots: list[Path], hashed: tuple[str, ...] = HASHED) -> dict:
    """Every file under the roots: size, mtime and, for executables and DLLs, a SHA-256.
    Links are recorded as links and never followed."""
    files: dict[str, dict] = {}
    for index, root in enumerate(roots):
        for folder, dirs, names in os.walk(root, followlinks=False):
            base = Path(folder)
            for name in sorted(dirs):
                if (base / name).is_symlink() or (base / name).is_junction():
                    files[_key(index, root, base / name)] = {"link": os.readlink(base / name)}
            for name in sorted(names):
                path = base / name
                if path.is_symlink():
                    files[_key(index, root, path)] = {"link": os.readlink(path)}
                    continue
                stat = path.stat()
                entry: dict = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
                if name.lower().endswith(hashed):
                    entry["sha256"] = _sha256(path)
                files[_key(index, root, path)] = entry
    return {"roots": [str(r) for r in roots], "time": _now(), "files": files}


def _key(index: int, root: Path, path: Path) -> str:
    return f"{index}:{path.relative_to(root).as_posix()}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def diff(before: dict, after: dict) -> dict:
    """What changed between two snapshots: added, removed, and changed with the fields that moved."""
    old, new = before["files"], after["files"]
    changed = []
    for name in sorted(old.keys() & new.keys()):
        fields = sorted(
            f for f in old[name].keys() | new[name].keys() if old[name].get(f) != new[name].get(f)
        )
        if fields:
            changed.append({"file": name, "fields": fields})
    return {
        "roots": before["roots"],
        "files": len(old),
        "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()),
        "changed": changed,
        "unchanged": not changed and old.keys() == new.keys(),
    }


# --- the report -------------------------------------------------------------------------


def findings(engine: dict, install: dict | None, display_lock: bool | None) -> list[dict]:
    """What a reader of the run should know, worst first: errors fail the run."""
    out: list[dict] = []

    def add(severity: str, kind: str, message: str, **extra) -> None:
        out.append({"severity": severity, "kind": kind, "message": message} | extra)

    if engine.get("error"):
        add("error", "harness", f"the harness failed: {engine['error']}")
    for item in engine.get("steps", []):
        if item.get("status") in ("refused", "failed"):
            add("error", f"step-{item['status']}",
                f"line {item.get('line')}: {item.get('source')}: {item.get('detail')}",
                line=item.get("line"))  # fmt: skip
    not_run = [s for s in engine.get("steps", []) if s.get("status") == "not-run"]
    if not_run:
        add("warning", "steps-not-run",
            f"{len(not_run)} step(s) not run, from line {not_run[0].get('line')}: "
            f"{not_run[0].get('detail')}")  # fmt: skip
    if install is not None and not install["unchanged"]:
        count = len(install["added"]) + len(install["removed"]) + len(install["changed"])
        add("error", "install-changed", f"{count} change(s) under the install folder")
    for item in engine.get("left_running", []):
        add(
            "error",
            "left-running",
            f"still running after the run: {item.get('name')} ({item.get('pid')})",
        )
    end = engine.get("end") or {}
    if end.get("ended_by") == "killed":
        add("warning", "killed",
            "the program did not end on WM_CLOSE and was killed"
            if (engine.get("window") or {}).get("first_seen") is not None
            else "the program had no window to close and was killed")  # fmt: skip
    code = end.get("exit_code")
    if (
        end.get("ended_by") in ("exit", "wm_close")
        and isinstance(code, int)
        and (code & 0xFFFFFFFF) >= 0xC0000000
    ):
        add("warning", "crashed", f"exit code {code & 0xFFFFFFFF:#010x} (an NTSTATUS error)")
    for item in engine.get("focus", []):
        if item.get("event") == "lost":
            window = item.get("window") or {}
            add("warning", "focus-lost",
                f"at {item.get('t')} s another window was in front: {window.get('process')} "
                f"({window.get('title')!r}, class {window.get('class')})")  # fmt: skip
    for item in engine.get("dialogs", []):
        answered = f"answered {item['answered']}" if item.get("answered") else "not answered"
        add(
            "warning",
            "dialog",
            f"message box {item.get('title')!r}: {item.get('text')!r} ({answered})",
        )
    for item in engine.get("captures", []):
        if item.get("black"):
            add("warning", "capture-black", f"capture {item.get('name')} came out black")
        elif item.get("method") == "screen":
            add(
                "info",
                "capture-screen",
                f"capture {item.get('name')} from the screen: {item.get('reason')}",
            )
    if engine.get("job"):
        add("info", "job", engine["job"])
    if not (engine.get("window") or {}).get("first_seen") and engine.get("pid"):
        add("info", "no-window", "the program never showed a window")
    seen = engine.get("seen") or {}
    others = [p for p in seen.get("processes", []) if p.get("pid") != engine.get("pid")]
    if others:
        names = ", ".join(sorted({p.get("name") or "?" for p in others}))
        add("info", "child-processes", f"{len(others)} other process(es) in its tree: {names}")
    endpoints = len(seen.get("tcp", [])) + len(seen.get("udp", []))
    if endpoints:
        add(
            "info",
            "network",
            f"{len(seen.get('tcp', []))} TCP and {len(seen.get('udp', []))} UDP endpoint(s)",
        )
    if display_lock is False and shutil.which("heavy"):
        add("info", "display", "the display lock was not held (heavy run --display)")
    order = {"error": 0, "warning": 1, "info": 2}
    return sorted(out, key=lambda f: order[f["severity"]])


def report(plan: dict, engine: dict, install: dict | None, started: str, seconds: float) -> dict:
    """The run's report.json: the plan's essentials, what the engine saw, the findings."""
    end = engine.get("end") or {}
    code = end.get("exit_code")
    found = findings(engine, install, plan.get("display_lock"))
    return {
        "format": REPORT_FORMAT,
        "ok": not any(f["severity"] == "error" for f in found),
        "program": plan.get("program"),
        "args": plan.get("args", []),
        "cwd": plan.get("cwd"),
        "env": sorted(plan.get("env", {})),  # names only: values may be secrets
        "attach": plan.get("attach"),
        "pid": engine.get("pid"),
        "exit_code": code,
        "exit_code_hex": f"{code & 0xFFFFFFFF:#010x}" if isinstance(code, int) else None,
        "ended_by": end.get("ended_by"),
        "end_reason": end.get("reason"),
        "timings": {
            "started": started,
            "seconds": round(seconds, 3),
            "window_after": (engine.get("window") or {}).get("first_seen"),
            "ended_after": end.get("t"),
        },
        "display_lock": plan.get("display_lock"),
        "steps": engine.get("steps", []),
        "captures": engine.get("captures", []),
        "dialogs": engine.get("dialogs", []),
        "focus": engine.get("focus", []),
        "window_titles": (engine.get("window") or {}).get("titles", []),
        "seen": engine.get("seen", {}),
        "left_running": engine.get("left_running", []),
        "pad": engine.get("pad"),
        "install": install,
        "findings": found,
    }


# --- the host ---------------------------------------------------------------------------


def host() -> str | None:
    """'windows', 'wsl' or None (no Windows to run on)."""
    if os.name == "nt":
        return "windows"
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return None
    return "wsl" if "microsoft" in release and shutil.which("wslpath") else None


def windows_path(path: str | Path, where: str | None) -> str:
    """A path as Windows sees it (unchanged on Windows, or already a Windows path)."""
    text = str(path)
    if where != "wsl" or WINDOWS_PATH.match(text):
        return text
    return subprocess.run(
        ["wslpath", "-w", text], check=True, capture_output=True, text=True
    ).stdout.strip()


def local_path(text: str, where: str | None, cwd: Path) -> Path:
    """A path as this side reads it: D:\\x under WSL becomes /mnt/d/x."""
    if where == "wsl" and WINDOWS_PATH.match(text):
        return Path(
            subprocess.run(
                ["wslpath", "-u", text], check=True, capture_output=True, text=True
            ).stdout.strip()
        )
    return cwd / text


def program_file(text: str, where: str | None, cwd: Path) -> str:
    """The program as Windows starts it: a file here resolved and translated, else left to PATH."""
    if WINDOWS_PATH.match(text):
        return text
    path = Path(text) if Path(text).is_absolute() else cwd / text
    return windows_path(path, where) if path.exists() else text


def pwsh(where: str | None) -> str | None:
    if where == "windows":
        return shutil.which("pwsh")
    fallback = "/mnt/c/Program Files/PowerShell/7/pwsh.exe"
    return shutil.which("pwsh.exe") or (fallback if Path(fallback).exists() else None)


def pad_command(where: str | None, dll: str | None, idle: bool) -> list[str]:
    """The pad, run by the engine on the Windows side: this checkout's vigem_pad.py, stdlib only."""
    script = windows_path(Path(vigem_pad.__file__), where)
    if where == "windows":
        command = [sys.executable, script]
    else:
        uv = shutil.which("uv.exe")
        if not uv:
            raise ValueError("pad steps under WSL need Windows uv (uv.exe) on PATH")
        command = [windows_path(uv, where), "run", "--no-project", "python", script]
    command += ["--stdin", "--tail", "1"]
    if dll:
        command += ["--dll", dll]
    return command + (["--idle-pad"] if idle else [])


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite run",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    p.add_argument("--script", type=Path, help="the steps, one a line")
    p.add_argument("--steps", help="the steps inline, separated by ; or newlines")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--start", nargs=argparse.REMAINDER, metavar="PROGRAM", help="start it (comes last)"
    )
    target.add_argument("--attach", help="a running process's name or pid")
    p.add_argument("--attach-wait", type=float, default=240, help="seconds to wait for it (240)")
    p.add_argument("--cwd", help="the program's working folder (default: its own folder)")
    p.add_argument(
        "--env", action="append", default=[], metavar="NAME=VALUE", help="set (repeatable)"
    )
    p.add_argument("--seconds", type=float, default=120, help="the run's bound (120)")
    p.add_argument(
        "--close-grace", type=float, default=15, help="seconds after WM_CLOSE before the kill (15)"
    )
    p.add_argument("--close", action="store_true", help="also end an attached process")
    p.add_argument("--window-title", help="pick the window whose title matches this regex")
    p.add_argument("--no-keep-front", action="store_true", help="do not keep the window in front")
    p.add_argument(
        "--capture-every", type=float, default=0, help="a capture every N seconds (0: off)"
    )
    p.add_argument(
        "--capture-timeout", type=float, default=2, help="seconds PrintWindow may take (2)"
    )
    p.add_argument(
        "--sample-every", type=float, default=5, help="modules, processes, endpoints (5)"
    )
    p.add_argument("--answer", action="append", default=[], metavar="[REGEX=]BUTTON",
                   help="answer message boxes (matched against title and text)")  # fmt: skip
    p.add_argument("--snapshot", action="append", default=[], metavar="DIR",
                   help="an install folder that must stay unchanged (repeatable)")  # fmt: skip
    p.add_argument("--pad-dll", help="ViGEmClient.dll for pad steps (default: REA_VIGEMCLIENT_DLL)")
    p.add_argument("--idle-pad", action="store_true", help="an idle pad in the first slot first")
    p.add_argument("--out", type=Path, help="output folder (default work/run/<time>)")
    p.add_argument("--dry-run", action="store_true", help="print the plan; start nothing")
    args = p.parse_args(argv)
    cwd = args.caller_cwd

    def fail(message: str) -> int:
        print(f"run: {message}", file=sys.stderr)
        return 2

    program: list[str] = args.start or []
    if args.start is not None and not program:
        return fail("--start needs a program")
    if args.seconds <= 0 or args.close_grace < 0 or args.capture_every < 0 or args.sample_every < 0:
        return fail("--seconds is above 0; the other durations at least 0")
    lines: list[str] = []
    if args.script:
        lines = (cwd / args.script).read_text(encoding="utf-8").splitlines()
    if args.steps:
        lines += split_inline(args.steps)
    try:
        steps = parse_steps(lines)
        rules = answers(args.answer)
    except ValueError as exc:
        return fail(str(exc))
    env = {}
    for item in args.env:
        name, sep, value = item.partition("=")
        if not sep or not name or "\0" in item:
            return fail(f"--env is NAME=VALUE: {item!r}")
        env[name] = value

    where = host()
    out = (
        (cwd / args.out)
        if args.out
        else ROOT / "work" / "run" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    )
    try:
        program_path = program_file(program[0], where, cwd) if program else None
        dll = args.pad_dll or os.environ.get("REA_VIGEMCLIENT_DLL")
        pad = None
        if any(s["op"] == "pad" for s in steps):
            pad = pad_command(
                where,
                windows_path(local_path(dll, where, cwd), where) if dll else None,
                args.idle_pad,
            )
        plan = {
            "format": PLAN_FORMAT,
            "out": windows_path(out, where) if where else str(out),
            "program": program_path,
            "args": program[1:],
            "command_line": subprocess.list2cmdline([program_path, *program[1:]])
            if program
            else None,
            "cwd": windows_path(local_path(args.cwd, where, cwd), where) if args.cwd else None,
            "env": env,
            "attach": {"target": args.attach, "wait": args.attach_wait, "close": args.close}
            if args.attach
            else None,
            "seconds": args.seconds,
            "close_grace": args.close_grace,
            "window_title": args.window_title,
            "keep_front": not args.no_keep_front,
            "capture_every": args.capture_every,
            "capture_timeout": args.capture_timeout,
            "sample_every": args.sample_every,
            "answers": rules,
            "pad": pad,
            "display_lock": "FALCON_HEAVY_DISPLAY_PID" in os.environ,
            "steps": steps,
        }
    except (ValueError, subprocess.CalledProcessError) as exc:
        return fail(str(exc))
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    shell = pwsh(where)
    if where is None or shell is None:
        return fail("needs Windows (or WSL) with PowerShell 7; --dry-run works anywhere")
    roots = [local_path(r, where, cwd) for r in args.snapshot]
    if missing := [str(r) for r in roots if not r.is_dir()]:
        return fail(f"no such folder to snapshot: {', '.join(missing)}")

    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    before = snapshot(roots) if roots else None
    if before:
        (out / "install-before.json").write_text(json.dumps(before), encoding="utf-8")
    started, clock = _now(), time.monotonic()
    command = [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
               windows_path(ENGINE, where), "-Plan", windows_path(out / "plan.json", where)]  # fmt: skip
    bound = args.seconds + args.close_grace + (args.attach_wait if args.attach else 0) + 120
    try:
        engine_exit = subprocess.run(command, check=False, timeout=bound).returncode
    except subprocess.TimeoutExpired:
        engine_exit = None
    engine_file = out / "engine.json"
    engine = json.loads(engine_file.read_text(encoding="utf-8-sig")) if engine_file.exists() else {}
    if engine_exit != 0 and not engine.get("error"):
        engine["error"] = (
            "the engine timed out" if engine_exit is None else f"the engine exited {engine_exit}"
        )
    install = None
    if before:
        after = snapshot(roots)
        (out / "install-after.json").write_text(json.dumps(after), encoding="utf-8")
        install = diff(before, after)
    result = report(plan, engine, install, started, time.monotonic() - clock)
    (out / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    for item in result["findings"]:
        print(f"{item['severity']}: {item['message']}", file=sys.stderr)
    print(out / "report.json")
    if not engine.get("pid") and not engine.get("launched") and engine.get("error"):
        return 2
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
