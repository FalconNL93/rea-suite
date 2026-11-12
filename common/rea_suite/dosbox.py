"""Run a DOS program in DOSBox-X and log what it asks of DOS, the DPMI host, the mouse driver and the
video BIOS, one JSON object a line.

  rea-suite dosbox run PROGRAM [ARG...] [options]   run it, log its interrupts and DOSBox-X's log
  rea-suite dosbox parse LOGFILE [options]          a DOSBox-X log file (taken elsewhere) as JSON lines
  rea-suite dosbox compare A B [--regions FILE]     two region sequences: the first difference
  rea-suite dosbox info                             which DOSBox-X, and whether it has the debugger

An analysis aid for DOS games, the way `rea-suite frida` is for Windows games: a comparison run of
the original. The program's folder (or --mount DIR) is drive C:, DOSBox-X runs headless (SDL's dummy
video and audio drivers; --window shows it) and quits when the program ends or after --seconds.

Two sources, both DOSBox-X's own, nothing patched:

- DOSBox-X's log ([log] section): every INT 21h that reaches DOS with AH and AL (`int21`), file
  opens, creates, reads, writes and closes by name (`fileio`, group FILES), memory and EXEC, mouse
  and video messages, and text a program writes to the Bochs debug port E9h. Any build has it.
- The debugger (--ints, on by default; a build without it takes --ints ''): an interrupt breakpoint per
  traced interrupt, driven over DOSBox-X's debugger control channel (`[dosbox] mcp_server`, a TCP
  connection DOSBox-X opens to this runner). Each call is logged with every register, the CPU mode
  (rm, pm, v86), the place it came from, the service named from le_services' tables and decoded
  arguments (a file name at DS:DX, the real-mode registers of DPMI 0300h-0302h). Real-mode
  callbacks are followed: the address DPMI 0303h returns and the handler INT 33h AX=000Ch installs
  get a breakpoint, and every entry into them is a `callback` record. --returns also logs the
  registers each call returns with. A stop costs about 15 ms of round trips, so a game runs slower
  than normal; its own timing is unaffected (the emulated clock stops with it).

With nobody at the keyboard: --dump ADDR:LEN@TRIGGER writes memory to a file of the run's folder and
--poke ADDR=BYTES@TRIGGER writes into it, at an interrupt call (int21:3D), a file open
(open:DATA/MAP.DAT), a time (t=30), the program's start or its exit; --input 't=10:ENTER
t=12:"abc" t=13:mouse:160,100 t=13.5:click' types keys (DOSBox-X's integration device) and places
the pointer and clicks (INT 33h 0004h run from the debugger at a stop in the program's own code).
--regions FILE reads named memory regions at sync points into a sequence file, which `compare` holds
against a port's own (dosbox_regions.py).

Options come before PROGRAM; everything after it is the program's arguments. docs/PORT-TOOLS.md
("DOS programs") has the details, the limits and the sources.

Records: {"t": seconds since the start, "kind": ...} with kind `int` (and `return`, `callback`) from
the debugger, `dos-int` (INT 21h from the log), `file`, `log` (any other log line: group, severity,
message), `e9` (port E9h text), `message` (DOSBox-X's own lines), `start`, `exit`, `error`.
DOSBox-X's records carry `cycle`, its instruction counter, which orders them; the debugger's and the
log's records are interleaved by the time they were read.

Exit 0: ran; 1: DOSBox-X failed or was stopped by --seconds; 2: no DOSBox-X, or --ints without a
build that has the debugger and its control channel. `compare`: 0 equal, 1 a difference, 2 bad input.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from rea_suite import dosbox_actions as acts
from rea_suite import dosbox_regions as rg

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work" / "dosbox"
DEFAULT_INTS = "21,31,33,10"
# DOSBox-X log groups switched on for every run, at debug level (names as in its [log] section).
DEFAULT_GROUPS = "files,dosmisc,exec,mouse,int10"
MEMFILE = "REAMEM.BIN"  # the debugger's MEMDUMPBIN target, in DOSBox-X's working folder
CALL_STRUCT = 0x32  # DPMI real-mode call structure
MOUSE_BP = ("int", 0x33, "mouse")  # the INT 33h breakpoint set while a pointer move waits
MOUSE_PATIENCE = 0.5  # seconds to wait for the program's own INT 33h call before BREAKs
MOUSE_RETRY = 0.05  # between BREAKs that land outside the program's code
PM_RETRY = 0.05  # between BREAKs for an action that waits for the program's protected-mode code
PM_PATIENCE = 5.0  # seconds such an action waits before it takes the stop it has (`gave_up`)
MOVED_KEYS = ("wanted", "moved", "gave_up")  # what a sequence line says of such a wait
# Interrupts a protected-mode program calls itself (DOS, DPMI, mouse, keyboard, video), whose
# breakpoints stop in its own code while an action waits for that (the extender's real-mode
# reflections of them stop too, and are run past).
PM_TRAPS = (0x21, 0x31, 0x33, 0x16, 0x10)
REGISTERS = (
    "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS",
    "CS", "DS", "ES", "FS", "GS", "SS", "CR0",
)  # fmt: skip
FLAG_CF, FLAG_VM = 0x1, 0x20000
# INT 21h functions that take an ASCIIZ path at DS:DX (6Ch at DS:SI).
DOS_PATH_AT_DX = {0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x41, 0x43, 0x4B, 0x4E, 0x56, 0x5A, 0x5B}


# --- DOSBox-X's log ------------------------------------------------------------------------------

# LOG::operator() in src/debug/debug_gui.cpp: "%10u%s %s:%s", the instruction counter, the severity
# (" DEBUG", six spaces for normal, " WARN ", " ERROR", " FATAL"), the group, the message.
LOG_LINE = re.compile(
    r"^\s*(?P<cycle>\d+)\s+(?:(?P<severity>DEBUG|WARN|ERROR|FATAL)\s+)?"
    r"(?P<group>[A-Z][A-Z0-9_]*):(?P<message>.*)$"
)
DOS_INT = re.compile(r"^Executing interrupt 21, ah=(?P<ah>[0-9a-f]+), al=(?P<al>[0-9a-f]+)$")
FILE_MESSAGES = [
    (re.compile(r"^(?P<special>Special )?file open command (?P<mode>[0-9A-F]+) file (?P<name>.+)$"), "open"),
    (re.compile(r"^file create attributes (?P<attributes>[0-9A-F]+) file (?P<name>.+)$"), "create"),
    (re.compile(r"^Reading (?P<bytes>\d+) bytes from (?P<name>.+?) ?$"), "read"),
    (re.compile(r"^Writing (?P<bytes>\d+) bytes to (?P<name>.+)$"), "write"),
    (re.compile(r"^Seeking to (?P<position>-?\d+) bytes from position type \((?P<whence>\d+)\) in (?P<name>.+?) ?$"), "seek"),
    (re.compile(r"^Closing file (?P<name>.+)$"), "close"),
    (re.compile(r"^Deleting file (?P<name>.+)$"), "delete"),
    (re.compile(r"^file search attributes (?P<attributes>[0-9A-F]+) name (?P<name>.+)$"), "search"),
]  # fmt: skip
E9_PREFIX = "Bochs port E9h: "
# What the debugger answers the runner's own commands with; it lands in the log file too.
DEBUGGER_ECHO = re.compile(
    r"^(EV of '.*' is:|[0-9a-f]+( [0-9a-f]+)*|DEBUG: .*|\*\*\*\| TYPE HELP .*)$"
)


def parse_line(line: str) -> dict | None:
    """One line of DOSBox-X's log (its log file, or its console with the `LOG: ` prefix)."""
    line = line.rstrip("\r\n")
    line = line.removeprefix("LOG: ")
    if not line.strip() or line == "--END OF LOG--":
        return None
    if line.startswith(E9_PREFIX):
        return {"kind": "e9", "text": line[len(E9_PREFIX) :]}
    m = LOG_LINE.match(line)
    if not m:
        return {"kind": "message", "message": line.strip()}
    cycle, group, message = int(m["cycle"]), m["group"], m["message"]
    severity = (m["severity"] or "normal").lower()
    if group == "DOSMISC" and (d := DOS_INT.match(message)):
        ah, al = int(d["ah"], 16), int(d["al"], 16)
        return {"kind": "dos-int", "cycle": cycle, "int": "21", **service(0x21, ah << 8 | al)}
    if group == "FILES":
        for pattern, op in FILE_MESSAGES:
            if f := pattern.match(message):
                record = {"kind": "file", "cycle": cycle, "op": op}
                for key, value in f.groupdict().items():
                    if key == "special":
                        record["special"] = value is not None
                    elif key in ("bytes", "position", "whence"):
                        record[key] = int(value)
                    elif key in ("mode", "attributes"):
                        record[key] = int(value, 16)
                    else:
                        record[key] = value
                return record
    return {
        "kind": "log",
        "cycle": cycle,
        "group": group,
        "severity": severity,
        "message": message.strip(),
    }


def service(n: int, ax: int, bl: int | None = None) -> dict:
    """The function a call asks for, named from le_services' tables (one set of names)."""
    from rea_suite.le_services import DPMI, FUNCTIONS, INTERRUPTS, SUBFUNCTION

    d: dict = {"name": INTERRUPTS.get(n)}
    if n not in FUNCTIONS:
        return d
    reg, names = FUNCTIONS[n]
    function = ax >> 8 if reg == "ah" else ax
    d["function"] = f"{function:02X}" if reg == "ah" else f"{function:04X}"
    d["service"] = names.get(function)
    if n == 0x31:
        d["group"] = DPMI.get(function, (None, None))[1]
    sub = SUBFUNCTION.get((n, function))
    if sub == "al":
        d["al"] = f"{ax & 0xFF:02X}"
    elif sub == "bl" and bl is not None:
        d["bl"] = f"{bl:02X}"
    return d


class LogTail:
    """Reads what DOSBox-X appends to its log file, whole lines only."""

    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self.rest = b""

    def lines(self) -> list[str]:
        try:
            with self.path.open("rb") as f:
                f.seek(self.offset)
                data = f.read()
        except FileNotFoundError:
            return []
        self.offset += len(data)
        data = self.rest + data
        *whole, self.rest = data.split(b"\n")
        return [w.decode("latin-1") for w in whole]

    def flush(self) -> list[str]:
        out = self.lines()
        if self.rest:
            out.append(self.rest.decode("latin-1"))
            self.rest = b""
        return out


class Scope:
    """Keeps the log's records of the program's run, not DOSBox-X's shell around it (mount, the
    DPMI host, the exit): from the DOS open of the program's file to the shell going back to its
    AUTOEXEC.BAT when the program has ended."""

    def __init__(self, program: str | None):
        self.program = program.upper() if program else None
        self.state = "before" if program else "all"

    def keep(self, record: dict) -> bool:
        if self.state in ("all", "after"):
            return self.state == "all"
        if record.get("kind") != "file" or record.get("op") != "open":
            return self.state == "during"
        name = str(record.get("name", "")).upper().replace("/", "\\")
        if self.state == "before" and (name == self.program or name.endswith("\\" + self.program)):
            self.state = "during"
        elif self.state == "during" and name.endswith("\\AUTOEXEC.BAT") and record.get("special"):
            self.state = "after"
        return self.state == "during"


# --- the debugger's control channel ----------------------------------------------------------------


class ChannelError(Exception):
    """The control channel closed or did not answer."""


class Channel:
    """DOSBox-X's debugger control channel (src/debug/debug_mcp.cpp): DOSBox-X connects to us and
    takes `REQ <id> PING|BREAK|EXEC <debugger command>` lines, one answer each, `BEGIN <id> OK|ERR`,
    the command's output lines, `END <id>`.

    DOSBox-X's network thread sends an answer only on its next turn, which comes when a line
    arrives or after 50 ms; so while an answer is outstanding a PING goes out every few ms to bring
    it (their answers are dropped)."""

    NUDGE = 0.002

    def __init__(self, conn: socket.socket, timeout: float = 30.0):
        self.conn = conn
        self.timeout = timeout
        self.buffer = b""
        self.blocks: dict[str, list[str]] = {}
        self.current: tuple[str, list[str]] | None = None
        self.serial = 0

    def _send(self, line: str) -> None:
        try:
            self.conn.sendall(line.encode("ascii") + b"\n")
        except OSError as exc:
            raise ChannelError(f"control channel: {exc}") from exc

    def _receive(self) -> None:
        try:
            data = self.conn.recv(65536)
        except OSError as exc:
            raise ChannelError(f"control channel: {exc}") from exc
        if not data:
            raise ChannelError("control channel closed")
        self.buffer += data
        *lines, self.buffer = self.buffer.split(b"\n")
        for raw in lines:
            line = raw.decode("latin-1").rstrip("\r")
            if self.current is None:
                if line.startswith("BEGIN "):
                    parts = line.split()
                    self.current = (parts[1], [] if parts[2:3] == ["OK"] else ["ERR"])
            elif line == f"END {self.current[0]}":
                self.blocks[self.current[0]] = self.current[1]
                self.current = None
            else:
                self.current[1].append(line)

    def request(self, command: str = "", kind: str = "EXEC") -> list[str]:
        """The output lines of one request; a refused one starts with "ERR"."""
        self.serial += 1
        rid = str(self.serial)
        self._send(f"REQ {rid} {kind} {command}".rstrip())
        deadline = time.monotonic() + self.timeout
        wait, nudges = self.NUDGE, 0
        while rid not in self.blocks:
            if time.monotonic() > deadline:
                raise ChannelError(f"no answer to {command or kind} in {self.timeout:.0f} s")
            if select.select([self.conn], [], [], wait)[0]:
                self._receive()
                continue
            nudges += 1
            self._send(f"REQ n{nudges} PING")
            if nudges > 50:  # DOSBox-X busy elsewhere for 0.1 s: nudge less often
                wait = 0.02
        for key in [k for k in self.blocks if k.startswith("n")]:
            del self.blocks[key]
        return self.blocks.pop(rid)

    def request_all(self, commands: list[str], batch: int = 200) -> list[list[str]]:
        """Several EXEC requests sent at once: DOSBox-X takes every line that has arrived in one
        turn, so a batch costs a few round trips, not one a command. Its queues hold 1024 lines
        each way and drop the oldest beyond that, so a batch waits for its answers (a PING's,
        which come after them) before the next goes out."""
        out = []
        for start in range(0, len(commands), batch):
            rids = []
            lines = []
            for command in commands[start : start + batch]:
                self.serial += 1
                rids.append(str(self.serial))
                lines.append(f"REQ {self.serial} EXEC {command}")
            self._send("\n".join(lines))
            self.request("", "PING")
            out += [self.blocks.pop(rid, ["ERR", "no answer"]) for rid in rids]
        return out


def parse_ev(lines: list[str], names: Iterable[str]) -> dict[str, int]:
    """The `EV A B C` command's answer: a header line, then the values in hex on one line."""
    names = list(names)
    values = next((ln.split() for ln in reversed(lines) if ln and not ln.startswith("EV ")), [])
    if len(values) != len(names) or not all(re.fullmatch(r"[0-9a-fA-F]+", v) for v in values):
        raise ChannelError(f"unexpected EV answer: {lines!r}")
    return {n: int(v, 16) for n, v in zip(names, values, strict=True)}


def hexarg(value: int) -> str:
    """A number the debugger cannot take for a register or flag name (CF, DF, AH...)."""
    return f"0{value:X}"


# --- interrupt records ---------------------------------------------------------------------------


def cpu_mode(regs: dict[str, int]) -> str:
    if not regs["CR0"] & 1:
        return "rm"
    return "v86" if regs["EFLAGS"] & FLAG_VM else "pm"


def at(regs: dict[str, int]) -> str:
    return f"{regs['CS']:04X}:{regs['EIP']:0{4 if cpu_mode(regs) != 'pm' else 8}X}"


def register_dump(regs: dict[str, int]) -> dict[str, str]:
    return {
        k.lower(): f"{v:0{4 if len(k) == 2 and k != 'CR0' else 8}X}"
        for k, v in regs.items()
        if k not in ("EIP", "CR0")
    }


def from_bios(regs: dict[str, int]) -> bool:
    """A call made by BIOS or DOSBox-X code (the ROM area, DOSBox-X's callbacks at F000h), as when
    DOS writes a string through INT 10h: not the program's own."""
    return cpu_mode(regs) != "pm" and regs["CS"] >= 0xC000


def asciiz(data: bytes, end: int = 0) -> str:
    text = data.split(bytes([end]), 1)[0]
    return text.decode("latin-1")


def call_struct(data: bytes) -> dict[str, str]:
    """A DPMI real-mode call structure (DPMI 0.9, function 0300h)."""
    import struct

    edi, esi, ebp, _, ebx, edx, ecx, eax = struct.unpack_from("<8I", data, 0)
    flags, es, ds, fs, gs, ip, cs, sp, ss = struct.unpack_from("<9H", data, 0x20)
    d = {"eax": eax, "ebx": ebx, "ecx": ecx, "edx": edx, "esi": esi, "edi": edi, "ebp": ebp}
    out = {k: f"{v:08X}" for k, v in d.items()}
    for k, v in (("flags", flags), ("es", es), ("ds", ds), ("fs", fs), ("gs", gs)):
        out[k] = f"{v:04X}"
    out["cs:ip"] = f"{cs:04X}:{ip:04X}"
    out["ss:sp"] = f"{ss:04X}:{sp:04X}"
    return out


def int_record(n: int, regs: dict[str, int], read: Callable[[int, int, int], bytes]) -> dict:
    """One interrupt call at a BPINT stop: what was asked and with which arguments."""
    ax = regs["EAX"] & 0xFFFF
    record = {
        "kind": "int",
        "int": f"{n:02X}",
        **service(n, ax, regs["EBX"] & 0xFF),
        "mode": cpu_mode(regs),
        "at": at(regs),
        "regs": register_dump(regs),
    }
    wide = cpu_mode(regs) == "pm"
    dx = regs["EDX"] if wide else regs["EDX"] & 0xFFFF
    si = regs["ESI"] if wide else regs["ESI"] & 0xFFFF
    di = regs["EDI"] if wide else regs["EDI"] & 0xFFFF
    ah = ax >> 8
    if n == 0x21 and ah in DOS_PATH_AT_DX:
        record["path"] = asciiz(read(regs["DS"], dx, 128))
        if ah == 0x56:
            record["new_path"] = asciiz(read(regs["ES"], di, 128))
    elif n == 0x21 and ah == 0x6C:
        record["path"] = asciiz(read(regs["DS"], si, 128))
    elif n == 0x21 and ah == 0x09:
        record["text"] = asciiz(read(regs["DS"], dx, 128), ord("$"))
    elif n == 0x31 and ax in (0x0300, 0x0301, 0x0302):
        record["real_mode"] = call_struct(read(regs["ES"], di, CALL_STRUCT))
    elif n == 0x31 and ax == 0x0303:
        record["handler"] = f"{regs['DS']:04X}:{si:X}"
    elif n == 0x33 and ax == 0x000C:
        record["handler"] = f"{regs['ES']:04X}:{dx:X}"
    return record


def return_record(call: dict, regs: dict[str, int]) -> dict:
    return {
        "kind": "return",
        "call": call["call"],
        "int": call["int"],
        "function": call.get("function"),
        "carry": bool(regs["EFLAGS"] & FLAG_CF),
        "regs": register_dump(regs),
    }


def parse_ints(spec: str) -> list[tuple[int, int | None, int | None]]:
    """`21,31,33:00` -> BPINT arguments: interrupt, AH (or None for all), AL."""
    out = []
    for item in filter(None, (s.strip() for s in spec.split(","))):
        parts = [int(p, 16) for p in item.split(":")]
        if not 1 <= len(parts) <= 3 or any(not 0 <= p <= 0xFF for p in parts):
            raise ValueError(f"--ints: {item!r} is not INT[:AH[:AL]] in hex")
        out.append(
            (parts[0], parts[1] if len(parts) > 1 else None, parts[2] if len(parts) > 2 else None)
        )
    return out


def bpint(n: int, ah: int | None, al: int | None) -> str:
    # `BPINT 21 *` does not work: the debugger reads `21 *` as an expression (21 times nothing)
    words = ["BPINT", hexarg(n)] + [hexarg(v) for v in (ah, al) if v is not None]
    return " ".join(words)


# --- the run ---------------------------------------------------------------------------------------


@dataclass
class Breakpoints:
    """The debugger's breakpoint list as it numbers it: the newest first (BPDEL takes the index)."""

    keys: list = field(default_factory=list)

    def add(self, key) -> None:
        self.keys.insert(0, key)

    def remove(self, key) -> int:
        index = self.keys.index(key)
        del self.keys[index]
        return index


class Output:
    """JSON lines on stdout and/or appended to a file; `t` is the seconds since the start."""

    def __init__(self, path: Path | None, quiet: bool, timed: bool = True):
        self.timed = timed
        self.start = time.monotonic()
        self.file = path.open("a", encoding="utf-8") if path else None
        self.quiet = quiet

    def close(self) -> None:
        if self.file:
            self.file.close()

    def write(self, record: dict) -> None:
        if self.timed:
            record = {"t": round(time.monotonic() - self.start, 3), **record}
        line = json.dumps(record)
        if self.file:
            self.file.write(line + "\n")
            self.file.flush()
        if not self.quiet:
            print(line, flush=True)


def find_dosbox(explicit: str | None) -> str | None:
    """--dosbox, REA_DOSBOX_X, the binary tools.yml installed (not its launcher: on Windows a .cmd
    would stand between the runner and the process it ends), or one on PATH."""
    for candidate in (explicit, os.environ.get("REA_DOSBOX_X")):
        if candidate:
            return candidate
    try:
        from rea_suite import cli

        spec = cli.load_tools()["dosbox-x"].bin.get(cli.PLATFORM, {}).get("dosbox-x")
        path = spec["path"] if isinstance(spec, dict) else spec
        if path and (found := sorted((cli.TOOLS_DIR / "dosbox-x" / "current").glob(path))):
            return str(found[-1])
    except (ImportError, KeyError, OSError):
        pass
    return shutil.which("dosbox-x")


def dos_command(program: Path, mount: Path, args: list[str]) -> tuple[str, str]:
    """The DOS folder (from C:\\) and the command line that starts the program."""
    relative = program.resolve().relative_to(mount.resolve())
    folder = "\\" + "\\".join(relative.parts[:-1])
    return folder, " ".join([relative.name, *args])


def dosbox_command(
    args, binary: str, run_dir: Path, port: int | None, actions: acts.Actions | None = None
) -> list[str]:
    program = (args.caller_cwd / args.program).resolve()
    mount = (args.caller_cwd / args.mount).resolve() if args.mount else program.parent
    folder, command = dos_command(program, mount, args.args)
    settings = {
        "dosbox quit warning": "false",  # a running program would ask, in a dialog, before quitting
        "log logfile": str(run_dir / "dosbox-x.log"),
        "log fileio": "true",
        "log int21": "false" if port else "true",  # the debugger logs INT 21h with registers
        "dosbox bochs debug port e9": "true",
    }
    for group in filter(None, args.groups.split(",")):
        settings[f"log {group.strip().lower()}"] = "debug"
    if port:
        settings["dosbox mcp_server"] = str(port)
        settings["cpu core"] = "normal"  # only the normal core checks interrupt breakpoints
    if actions and actions.steps:
        settings["cpu integration device"] = "true"  # the input goes in through it
    if not args.window:
        # no MIDI either: DOSBox-X's default tries a TiMidity server and can hang connecting to it
        settings.update({"midi mididevice": "none", "mixer nosound": "true"})
    cmd = [binary, "-defaultconf", "-nopromptfolder", "-fastlaunch", "-nogui", "-nomenu", "-exit"]
    if args.conf:
        cmd += ["-conf", str(args.caller_cwd / args.conf)]
    for key, value in settings.items():
        cmd += ["-set", f"{key}={value}"]
    for extra in args.set:
        cmd += ["-set", extra]
    cmd += ["-c", f'mount c "{mount}"', "-c", "c:"]
    if folder != "\\":
        cmd += ["-c", f"cd {folder}"]
    if args.dpmi:
        cmd += ["-c", "Z:\\BIN\\CWSDPMI.EXE -p"]  # DOSBox-X's built-in DPMI host, resident
    cmd += ["-c", ("DEBUGBOX " if port else "") + command, "-c", "exit"]
    return cmd


class Tracer:
    """Interrupt breakpoints through the control channel, one stop at a time.

    A stop is seen as two register reads in a row that agree (while DOSBox-X runs, each read is
    answered at a later emulated millisecond), then told apart by the code at CS:EIP: `int n` for a
    traced n is a call, a known address a return or a callback, `hlt` a running CPU that waits."""

    def __init__(
        self, channel: Channel, out: Output, run_dir: Path, args, actions=None, sequence=None
    ):
        self.ch = channel
        self.out = out
        self.run_dir = run_dir
        self.mem = run_dir / MEMFILE
        self.actions = actions or acts.Actions()
        self.steps = list(self.actions.steps)  # input still to deliver, in time order
        self.delivered: set[int] = set()  # the --input items delivered whole
        self.sequence = sequence  # dosbox_regions.SequenceWriter, for the sync points' regions
        self.logged = parse_ints(args.ints)  # the calls --ints asks to log
        # and the breakpoints the triggers need besides, where --ints' own do not include them
        self.ints = list(self.logged)
        for spec in self.actions.breakpoints():
            if not acts.spec_covered(spec, self.ints):
                self.ints.append(spec)
        self.traced = {n for n, _, _ in self.ints}
        self.returns = args.returns
        self.nested = args.nested
        self.bps = Breakpoints()
        self.pending_returns: dict[tuple[int, int], dict] = {}
        self.callbacks: dict[tuple[int, int], dict] = {}
        self.pending_real_callbacks: list[tuple[int, int, dict]] = []
        self.calls = 0
        self.started = False
        self.psp: int | None = None
        self.done = False  # the program ended: the breakpoints are gone, DOSBox-X runs on its own
        self.breaking = False  # a BREAK went out for actions at a time: the next stop is theirs
        self.ending = False  # the run's time is up: no more input or timed actions
        self.dumps = 0
        self.app_cs: int | None = None  # the program's protected-mode code selector, once seen
        self.seen_pm = False  # the program has run in protected mode: a DPMI program
        self.pm_break = 0.0  # when a BREAK may be made for actions waiting for protected mode
        self.mouse_break = 0.0  # when a BREAK may be made for the pointer

    def regs(self) -> dict[str, int]:
        return parse_ev(self.ch.request("EV " + " ".join(REGISTERS)), REGISTERS)

    def read(self, seg: int, off: int, size: int) -> bytes:
        self.mem.unlink(missing_ok=True)
        self.ch.request(f"MEMDUMPBIN {hexarg(seg)}:{hexarg(off)} {hexarg(size)} {MEMFILE}")
        try:
            return self.mem.read_bytes()
        except FileNotFoundError:
            return b""

    def resume(self) -> None:
        self.ch.request("RUN")

    def add_bp(self, seg: int, off: int) -> None:
        if (seg, off) not in self.bps.keys:
            self.ch.request(f"BP {hexarg(seg)}:{hexarg(off)}")
            self.bps.add((seg, off))

    def del_bp(self, seg: int, off: int) -> None:
        if (seg, off) in self.bps.keys:
            self.ch.request(f"BPDEL {hexarg(self.bps.remove((seg, off)))}")

    def wait_stop(self, alive: Callable[[], bool], tick: Callable[[], None]) -> dict | None:
        previous, same, flushed = None, 0, time.monotonic()
        while alive():
            if self.started and not self.done and not self.ending:
                self.deliver_input()
                # the pointer: a first BREAK to set an INT 33h breakpoint (one set while the CPU
                # runs takes effect only at the next stop), then the program's own INT 33h calls
                # for a while, then BREAKs spaced out (back to back they starve the program)
                mouse = self.mouse_due() and time.monotonic() >= self.mouse_break
                if not self.breaking and (self.break_due() or mouse):
                    self.ch.request("", "BREAK")  # a stop for the actions due now
                    self.breaking = True
            regs = self.regs()
            if self.started and cpu_mode(regs) == "pm":  # read while it runs, too
                self.seen_pm = True
            same = same + 1 if regs == previous else 0
            previous = regs
            if same >= 1:
                return regs
            if time.monotonic() - flushed > 0.1:  # the log, while the program runs without stops
                tick()
                flushed = time.monotonic()
            time.sleep(0.001)
        return None

    def start(self, regs: dict[str, int]) -> None:
        """The stop DEBUGBOX makes at the program's first instruction."""
        for n, ah, al in self.ints:
            self.ch.request(bpint(n, ah, al))
            self.bps.add(("int", n, ah, al))
        self.out.write({"kind": "start", "entry": at(regs), "mode": cpu_mode(regs)})
        self.started = True
        for action in self.actions.pending("start"):
            self.act(action, regs)

    def call(self, n: int, regs: dict[str, int]) -> None:
        if from_bios(regs) and not self.nested:
            return
        ax = regs["EAX"] & 0xFFFF
        if cpu_mode(regs) == "pm":
            self.app_cs = regs["CS"]
        record = int_record(n, regs, self.read)
        if any(acts.covers(spec, n, ax) for spec in self.logged):
            self.log_call(n, regs, record)
        for action in self.actions.memory():
            if action.done or not action.trigger.matches_call(n, ax, record.get("path")):
                continue
            if action.mode == "pm" and not self.own_pm(regs):  # its extender's reflection of it
                continue
            detail = {"path": record["path"]} if action.trigger.kind == "open" else {}
            self.act(action, regs, detail)

    def log_call(self, n: int, regs: dict[str, int], record: dict) -> None:
        self.calls += 1
        record["call"] = self.calls
        if from_bios(regs):
            record["from"] = "bios"
        self.out.write(record)
        ax = regs["EAX"] & 0xFFFF
        if n == 0x33 and ax == 0x000C:
            dx = regs["EDX"] if cpu_mode(regs) == "pm" else regs["EDX"] & 0xFFFF
            if regs["ECX"] & 0xFFFF and (regs["ES"] or dx):
                self.callbacks[(regs["ES"], dx)] = {"via": "mouse 000C", "call": record["call"]}
                self.add_bp(regs["ES"], dx)
        if n == 0x31 and ax == 0x0304:  # the program frees a real-mode callback
            key = (regs["ECX"] & 0xFFFF, regs["EDX"] & 0xFFFF)
            self.pending_real_callbacks = [c for c in self.pending_real_callbacks if c[:2] != key]
            if self.callbacks.pop(key, None):
                self.del_bp(*key)
        back = (regs["CS"], regs["EIP"] + 2)  # after `int n`
        if (self.returns or (n == 0x31 and ax == 0x0303)) and back not in self.pending_returns:
            self.pending_returns[back] = record
            self.add_bp(*back)

    def returned(self, key: tuple[int, int], regs: dict[str, int]) -> None:
        call = self.pending_returns.pop(key)
        self.del_bp(*key)
        record = return_record(call, regs)
        if call["int"] == "31" and call.get("function") == "0303" and not regs["EFLAGS"] & FLAG_CF:
            seg, off = regs["ECX"] & 0xFFFF, regs["EDX"] & 0xFFFF
            record["callback"] = f"{seg:04X}:{off:04X}"
            # A real-mode address takes a breakpoint only while the CPU is in real mode (the
            # debugger reads BP's segment as a selector in protected mode): at the next stop there.
            via = {"via": "dpmi 0303", "call": call["call"], "handler": call.get("handler")}
            self.pending_real_callbacks.append((seg, off, via))
        if self.returns or "callback" in record:
            self.out.write(record)

    def place_real_callbacks(self, regs: dict[str, int]) -> None:
        if cpu_mode(regs) == "pm":
            return
        for seg, off, via in self.pending_real_callbacks:
            self.callbacks[(seg, off)] = via
            self.add_bp(seg, off)
        self.pending_real_callbacks.clear()

    def current_psp(self) -> int:
        return parse_ev(self.ch.request("EV PSPSEG"), ["PSPSEG"])["PSPSEG"]

    def is_entry(self, regs: dict[str, int]) -> bool:
        """DEBUGBOX's stop at the program's first instruction: DS and ES hold its PSP."""
        psp = self.current_psp()
        if (
            cpu_mode(regs) == "rm"
            and regs["DS"] == regs["ES"] == psp
            and psp <= regs["CS"] < 0xC000
        ):
            self.psp = psp
            return True
        return False

    def ends_program(self, n: int, regs: dict[str, int]) -> bool:
        """INT 21h AH=00h, 31h or 4Ch from the program itself (not a child it started)."""
        ah = regs["EAX"] >> 8 & 0xFF
        return n == 0x21 and ah in (0x00, 0x31, 0x4C) and self.current_psp() == self.psp

    def finish(self) -> None:
        """No more stops: DOSBox-X's shell and its exit run at full speed."""
        for _ in range(len(self.bps.keys)):
            self.ch.request(f"BPDEL {hexarg(0)}")
        self.bps.keys.clear()
        self.done = True

    def stop(self, regs: dict[str, int], taken: bool = False) -> bool:
        """Handle one stop; False when it was none (a CPU waiting in `hlt` or in a DOSBox-X
        callback agrees with itself too) and nothing was resumed. `taken`: the actions due were
        looked at for this stop already (a BREAK's)."""
        key = (regs["CS"], regs["EIP"])
        code = self.read(regs["CS"], regs["EIP"], 2)
        traced_int = code[:1] == b"\xcd" and code[1] in self.traced
        if code[:1] == b"\xf4":
            return False  # hlt: running, waiting for an interrupt
        if not self.started:
            if not self.is_entry(regs):
                return False
            self.start(regs)
        elif key in self.pending_returns:
            self.returned(key, regs)
        elif key in self.callbacks:
            self.out.write(
                {
                    "kind": "callback",
                    **self.callbacks[key],
                    "mode": cpu_mode(regs),
                    "at": at(regs),
                    "regs": register_dump(regs),
                }
            )
        elif not traced_int:
            return False
        # Resuming runs the first instruction without checking interrupt breakpoints, so an
        # `int n` where the entry, a return or a callback lands is logged here.
        if traced_int:
            self.call(code[1], regs)
            if self.waiting() and not taken:  # a call stops for certain: maybe where awaited
                self.take_due(regs)
            if self.ends_program(code[1], regs):
                for action in self.actions.pending("exit"):
                    self.act(action, regs)
                self.finish()
        self.place_real_callbacks(regs)
        self.resume()
        return True

    def run(
        self,
        alive: Callable[[], bool],
        tick: Callable[[], None],
        running: Callable[[], bool] | None = None,
    ) -> None:
        while alive() and not self.done:
            regs = self.wait_stop(alive, tick)
            tick()
            if regs is None:
                continue
            placed = False
            if self.started and self.mouse_due():
                if 0x33 not in self.traced:  # the program's own INT 33h calls: the best places
                    self.ch.request(bpint(0x33, None, None))
                    self.bps.add(MOUSE_BP)
                    self.traced.add(0x33)
                    self.mouse_break = time.monotonic() + MOUSE_PATIENCE
                placed = self.place_mouse(regs)
                if not placed and self.breaking:  # not in the program's own code: later again
                    self.mouse_break = max(self.mouse_break, time.monotonic() + MOUSE_RETRY)
            if self.breaking:  # the stop the BREAK made, or a breakpoint's that came first
                self.breaking = False
                self.take_due(regs)
                if not self.stop(regs, taken=True):
                    self.resume()
            elif not self.stop(regs):
                if placed:  # the stop of the INT 33h breakpoint, gone now
                    self.resume()
                else:
                    time.sleep(0.002)
        if running and self.started and not self.done and self.actions.pending("exit"):
            self.end(running, tick)

    # --- actions: dumps, pokes, input ---

    def now(self) -> float:
        """Seconds on the records' clock (their `t`)."""
        return time.monotonic() - self.out.start

    def due(self) -> list:
        """Actions due now: their time has come, or their --input item has been delivered."""
        return self.actions.due(self.now(), self.delivered)

    def take_due(self, regs: dict[str, int]) -> None:
        """At a BREAK's stop: the actions due, but those that wait for a better stop (holds)."""
        for action in self.due():
            if not self.holds(action, regs):
                self.act(action, regs)
        self.pm_traps(self.waiting())

    def waiting(self) -> bool:
        """Whether an action due waits for a stop in the program's protected-mode code."""
        return any(a.moved is not None for a in self.due())

    def pm_traps(self, on: bool) -> None:
        """While an action waits, breakpoints on the interrupts the program calls itself
        (PM_TRAPS) besides the BREAKs: a program that spends little time in its own code (one that
        polls the mouse through its extender) is found at its next call. Set at a stop: one set
        while the CPU runs takes effect only at the next."""
        for n in PM_TRAPS:
            key = ("int", n, "pm")
            if on and key not in self.bps.keys and n not in self.traced:
                self.ch.request(bpint(n, None, None))
                self.bps.add(key)
            elif not on and key in self.bps.keys:
                self.ch.request(f"BPDEL {hexarg(self.bps.remove(key))}")
        self.retrace()

    def retrace(self) -> None:
        """The interrupts whose `int` is a stop: --ints' and the triggers', and those of the
        breakpoints set for a while (the mouse's, PM_TRAPS)."""
        temporary = {k[1] for k in self.bps.keys if len(k) == 3 and k[0] == "int"}
        self.traced = {n for n, _, _ in self.ints} | temporary

    def break_due(self) -> bool:
        """Whether to BREAK for the actions due: at once, unless all of them are waiting for the
        program's protected-mode code, whose BREAKs are spaced out (back to back they starve it)."""
        due = self.due()
        if not due:
            return False
        return time.monotonic() >= self.pm_break or any(a.moved is None for a in due)

    def wants_pm(self, action) -> bool:
        """Whether a time or input action waits for a stop in the program's own protected-mode
        code: asked for (`mode = "pm"`), or by default once the program has run in protected mode,
        since a BREAK can land in its extender's real-mode side, where a high linear address or
        a selector does not read (a selector reads as a segment there)."""
        if action.trigger.kind not in acts.MOVABLE:
            return False
        return action.mode == "pm" or (action.mode == "auto" and self.seen_pm)

    def own_pm(self, regs: dict[str, int]) -> bool:
        """A stop in the program's own protected-mode code: its code selector (that of its own
        last call), or, before one is seen, a 32-bit code segment (a DOS extender's own code and
        a DPMI host's are 16-bit, a 32-bit program's flat code is not)."""
        if cpu_mode(regs) != "pm":
            return False
        if self.app_cs is not None:
            return regs["CS"] == self.app_cs
        try:
            return acts.parse_selinfo(self.ch.request("SELINFO CS"))[2]
        except ValueError:
            return False

    def holds(self, action, regs: dict[str, int]) -> bool:
        """Whether a due action waits for a later stop (wants_pm, and this one is elsewhere). It
        waits PM_PATIENCE at most, then takes the stop it has; input waits with it (held)."""
        if not self.wants_pm(action) or self.own_pm(regs):
            return False
        now = time.monotonic()
        if action.moved is None:
            action.moved = acts.Moved(cpu_mode(regs), at(regs), now)
        elif now - action.moved.since >= PM_PATIENCE:
            action.moved.gave_up = True
            return False
        else:
            action.moved.stops += 1
        self.pm_break = now + PM_RETRY
        return True

    def moved(self, action) -> dict:
        """What a record and a sequence line say of an action that wanted protected mode: where its
        first stop landed when it moved on from there, how long it waited and whether it gave up."""
        if not self.wants_pm(action):
            return {}
        detail: dict = {"wanted": "pm"}
        if action.moved is not None:
            m = action.moved
            detail["moved"] = {"from": m.at, "mode": m.mode, "stops": m.stops,
                               "waited": round(time.monotonic() - m.since, 3)}  # fmt: skip
            if m.gave_up:
                detail["gave_up"] = True
            action.moved = None
        return detail

    def held(self, step) -> bool:
        """Input that waits: an action due before it has not been taken yet (an input item's, or
        one at an earlier time), so a sync point never reads what came after its moment."""
        for action in self.due():
            if action.trigger.kind == "input" or action.trigger.seconds < step.t:
                return True
        return False

    def took(self, step) -> None:
        """A step delivered: its item is whole once no step of it is left."""
        if not any(s.item == step.item for s in self.steps):
            self.delivered.add(step.item)

    def end(self, running: Callable[[], bool], tick: Callable[[], None]) -> None:
        """The run's time is up with the program still running: a last stop for `exit` actions."""
        self.ending = True
        until = time.monotonic() + 10
        self.ch.request("", "BREAK")
        regs = self.wait_stop(lambda: running() and time.monotonic() < until, tick)
        if regs is not None:
            for action in self.actions.pending("exit"):
                self.act(action, regs, {"ended": "seconds"})

    def act(self, action, regs: dict[str, int], detail: dict | None = None) -> None:
        """A dump or a poke, once, or a sync point, at a stop (the mode and CS say how an address
        reads)."""
        detail = {**self.moved(action), **(detail or {})}
        if isinstance(action, acts.Sync):
            self.sync(action, regs, detail)
            return
        action.done = True
        try:
            record = (
                self.poke(action, regs)
                if isinstance(action, acts.Poke)
                else self.dump(action, regs)
            )
        except (ValueError, OSError) as exc:
            record = {"kind": "error", "error": str(exc), "action": action.text}
        record.update(detail or {})
        self.out.write(record)

    def dump(self, dump: acts.Dump, regs: dict[str, int]) -> dict:
        data, linear = self.read_range(dump.address, dump.length, regs, dump.text)
        self.dumps += 1
        path = self.run_dir / acts.dump_filename(self.dumps, dump)
        path.write_bytes(data)
        return acts.dump_record(dump, path, data, cpu_mode(regs), at(regs), linear)

    def read_range(
        self, address: acts.Address, length: int, regs: dict[str, int], what: str
    ) -> tuple[bytes, int | None]:
        """LENGTH bytes from ADDR at this stop, and the linear address they start at if known."""
        mode = cpu_mode(regs)
        cs_base = 0
        linear = acts.linear_of(address, mode)
        if mode == "pm" and address.linear is not None:
            cs_base, _, big = acts.parse_selinfo(self.ch.request("SELINFO CS"))
            # stopped in 16-bit code (a DPMI host's, an extender's): a 32-bit selector covering it
            if not big:
                address = self.flat_address(address, length, regs, what)
        elif mode == "pm":  # SEL:OFF: the linear address from the descriptor, for the record
            with contextlib.suppress(ValueError):
                base = acts.parse_selinfo(self.ch.request(f"SELINFO {hexarg(address.sel)}"))[0]
                linear = (base + address.off) & 0xFFFFFFFF  # type: ignore[operator]
        pieces = acts.memdump_pieces(address, length, mode, regs["CS"], cs_base)
        return b"".join(self.read(seg, off, size) for seg, off, size in pieces), linear

    def sync(self, sync: acts.Sync, regs: dict[str, int], detail: dict | None = None) -> None:
        """A sync point: its regions, in order, into the sequence file, and a record of it."""
        sync.hits += 1
        sync.done = not sync.repeat
        mode, where = cpu_mode(regs), at(regs)
        errors = 0
        for region in sync.regions:
            data, linear, error = None, None, None
            try:
                data, linear = self.read_range(region.address, region.length, regs, region.name)
            except (ValueError, OSError) as exc:
                error, errors = str(exc), errors + 1
            line = {"addr": region.address.text, "mode": mode, "at": where}
            if linear is not None:
                line["linear"] = f"{linear:08X}"
            line.update({k: v for k, v in (detail or {}).items() if k in MOVED_KEYS})
            if self.sequence:
                self.sequence.region(sync.name, region, data, error, sync.hits, **line)
        index = self.sequence.index if self.sequence else None
        if self.sequence:
            self.sequence.next()
        record = {"kind": "sync", "sync": sync.name, "index": index, "hit": sync.hits,
                  "trigger": sync.trigger.text, "mode": mode, "at": where,
                  "regions": [r.name for r in sync.regions]}  # fmt: skip
        if errors:
            record["errors"] = errors
        record.update(detail or {})
        self.out.write(record)

    def flat_address(
        self, address: acts.Address, length: int, regs: dict[str, int], what: str
    ) -> acts.Address:
        """A linear range as SEL:OFF through a 32-bit selector whose limit covers it: the
        program's own code selector, then the data and stack registers'."""
        linear = address.linear
        for sel in dict.fromkeys([self.app_cs, *(regs[r] for r in ("DS", "ES", "SS", "FS", "GS"))]):
            if not sel:
                continue
            try:
                base, limit, big = acts.parse_selinfo(self.ch.request(f"SELINFO {hexarg(sel)}"))
            except ValueError:
                continue
            off = (linear - base) & 0xFFFFFFFF  # type: ignore[operator]
            if big and off + length - 1 <= limit:
                return acts.Address(address.text, linear=None, sel=sel, off=off)
        raise ValueError(f"{what}: no 32-bit selector covers it at this stop; give SEL:OFF")

    def poke(self, poke: acts.Poke, regs: dict[str, int]) -> dict:
        mode = cpu_mode(regs)
        refused = [
            a for a in self.ch.request_all(acts.poke_commands(poke, mode)) if a[:1] == ["ERR"]
        ]
        if refused:
            raise ValueError(f"{poke.text}: the debugger refused it: {refused[0]!r}")
        return {
            "kind": "poke",
            "addr": poke.address.text,
            "bytes": poke.data.hex(),
            "trigger": poke.trigger.text,
            "mode": mode,
            "at": at(regs),
        }

    def deliver_input(self) -> None:
        """Keys and buttons due now, through the integration device (taken whether the emulation
        runs or stands at a stop), up to a mouse position, which needs a stop (place_mouse)."""
        now = self.now()
        while (
            self.steps
            and self.steps[0].t <= now
            and self.steps[0].kind in ("keys", "button")
            and not self.held(self.steps[0])
        ):
            step = self.steps.pop(0)
            self.took(step)
            values = acts.integration_values(step)
            answers = self.ch.request_all(acts.integration_commands(values))
            record = {"kind": "input", "input": step.kind, "source": step.source}
            if step.kind == "keys":
                record["bytes"] = bytes(step.value).hex()
            else:
                record.update(button=step.value[0], pressed=step.value[1])
            self.input_record(record, step, now, answers)

    def input_record(self, record: dict, step, now: float, answers: list[list[str]]) -> None:
        if late := round(now - step.t, 3):
            record["late"] = late
        # the rest of the script moves back as much: holds and gaps keep their length
        if late > 0.01:
            for later in self.steps:
                later.t += late
        if any(a[:1] == ["ERR"] for a in answers):
            record["error"] = "the debugger refused a command"
        self.out.write(record)

    def mouse_due(self) -> bool:
        return (
            bool(self.steps)
            and self.steps[0].kind in ("mouse", "move")
            and self.steps[0].t <= self.now()
            and not self.held(self.steps[0])
        )

    def own_code(self, regs: dict[str, int]) -> bool:
        """A stop in the program's own code, where running an interrupt is as safe as the program
        making the call there: in protected mode its code selector (that of its own last call),
        in real mode its memory (from its PSP up to A000h). Not in the DOS extender, the DPMI host,
        DOS or the BIOS."""
        if cpu_mode(regs) == "pm":
            return self.app_cs is None or regs["CS"] == self.app_cs
        if self.app_cs is not None:  # a protected-mode program in real mode: its extender's
            return False
        return self.psp is not None and self.psp <= regs["CS"] < 0xA000

    def place_mouse(self, regs: dict[str, int]) -> bool:
        """The mouse positions due now, by INT 33h 0004h run at this stop; False when this stop
        is not in the program's own code (the caller resumes and stops again later)."""
        if not self.own_code(regs):
            return False
        # a stop for certain (equal registers can be a CPU waiting in hlt while it runs): the BREAK
        # asked for, or an interrupt breakpoint's
        code = self.read(regs["CS"], regs["EIP"], 2)
        if not self.breaking and not (code[:1] == b"\xcd" and code[1] in self.traced):
            return False
        now = self.now()
        while self.mouse_due():
            step = self.steps.pop(0)
            self.took(step)
            x, y = step.value
            record = {"kind": "input", "input": step.kind, "source": step.source}
            if step.kind == "move":
                back = self.int33(regs, 0x0003)
                x += _signed16(back["ECX"])
                y += _signed16(back["EDX"])
                record["from"] = [_signed16(back["ECX"]), _signed16(back["EDX"])]
            self.int33(regs, 0x0004, x, y)
            after = self.int33(regs, 0x0003)
            record.update(
                x=step.value[0],
                y=step.value[1],
                at=[_signed16(after["ECX"]), _signed16(after["EDX"])],
            )
            self.input_record(record, step, now, [])
        self.mouse_break = 0.0
        if MOUSE_BP in self.bps.keys and not self.mouse_due():
            self.ch.request(f"BPDEL {hexarg(self.bps.remove(MOUSE_BP))}")
            self.retrace()
        self.deliver_input()  # keys and buttons after it, at this stop
        return True

    def int33(self, regs: dict[str, int], ax: int, cx: int = 0, dx: int = 0) -> dict[str, int]:
        """Run INT 33h with AX, CX, DX from this stop (the debugger's INT command: an interrupt
        taken here, and a one-time breakpoint where it returns), and put the registers back.
        Stops elsewhere on the way (a traced interrupt the driver's path makes) are run past."""
        self.ch.request(f"SR EAX {hexarg(ax)} ECX {hexarg(cx & 0xFFFF)} EDX {hexarg(dx & 0xFFFF)}")
        self.ch.request("INT 033")
        home = (regs["CS"], regs["EIP"])
        until = time.monotonic() + 10
        previous = None
        while True:
            if time.monotonic() > until:
                raise ChannelError("INT 33h run from the debugger did not come back")
            now = self.regs()
            if now == previous:
                if (now["CS"], now["EIP"]) == home:
                    break
                self.resume()
                now = None
            previous = now
            time.sleep(0.001)
        self.ch.request(
            f"SR EAX {hexarg(regs['EAX'])} ECX {hexarg(regs['ECX'])} EDX {hexarg(regs['EDX'])}"
        )
        return previous


def _signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


class Terminal:
    """A pseudo-terminal for DOSBox-X: its debugger works only with a terminal on stdin, stdout and
    stderr (Linux, macOS), and draws its curses screen there. What it draws is read and dropped."""

    def __init__(self):
        import fcntl
        import pty
        import struct
        import termios

        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
        self.tail = b""
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        os.close(self.slave)
        self.thread.start()

    def close(self) -> None:
        self.thread.join(1)
        os.close(self.master)

    def _drain(self) -> None:
        while True:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return
            if not data:
                return
            self.tail = (self.tail + data)[-4096:]


def run(args) -> int:
    binary = find_dosbox(args.dosbox)
    if not binary:
        print(
            "dosbox: no DOSBox-X (component `dos`: rea-suite select; or --dosbox)", file=sys.stderr
        )
        return 2
    program = (args.caller_cwd / args.program).resolve()
    if not program.is_file():
        print(f"dosbox: {program}: no such file", file=sys.stderr)
        return 2
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = (args.caller_cwd / args.workdir) if args.workdir else WORK / f"{stamp}-{program.stem}"
    script = args.input
    if args.input_file:
        script = (args.caller_cwd / args.input_file).read_text(encoding="utf-8")
    syncs = rg.load_regions(args.caller_cwd / args.regions).syncs if args.regions else []
    actions = acts.Actions.from_args(args.dump, args.poke, script, syncs)  # ValueError: exit 2
    run_dir.mkdir(parents=True, exist_ok=True)
    sequence = None
    if syncs:
        path = args.caller_cwd / args.sequence if args.sequence else run_dir / "regions.jsonl"
        sequence = rg.SequenceWriter(path, "rea-suite dosbox")
    out = Output(args.caller_cwd / args.log if args.log else None, args.quiet)
    trace = bool(args.ints) or bool(actions)  # dumps, pokes and input go through the debugger
    server = None
    port = None
    if trace:
        server = socket.create_server(("127.0.0.1", 0))
        server.settimeout(0.2)
        port = server.getsockname()[1]
    cmd = dosbox_command(args, binary, run_dir, port, actions)
    (run_dir / "command.txt").write_text(shlex.join(cmd) + "\n")
    env = dict(os.environ)
    if not args.window:
        env.update({"SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"})
    env.setdefault("TERM", "xterm")
    terminal = Terminal() if trace and os.name != "nt" else None
    tty = terminal.slave if terminal else subprocess.DEVNULL
    streams = {"stdin": tty, "stdout": tty, "stderr": tty}
    popen = {"start_new_session": True} if os.name != "nt" else {}
    if os.name == "nt" and trace:
        # the debugger opens a console of its own; a hidden one keeps the run headless (untested)
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = 0
        popen = {"creationflags": subprocess.CREATE_NEW_CONSOLE, "startupinfo": info}
    proc = subprocess.Popen(cmd, cwd=run_dir, env=env, **streams, **popen)
    if terminal:
        terminal.start()
    out.write(
        {
            "kind": "start",
            "program": str(program),
            "dosbox": binary,
            "run_dir": str(run_dir),
            "trace": args.ints if trace else None,
            **({"actions": [a.text for a in actions.memory()]} if actions.memory() else {}),
            **({"input": len(actions.steps)} if actions.steps else {}),
            **({"sequence": str(sequence.path)} if sequence else {}),
        }
    )
    tail = LogTail(run_dir / "dosbox-x.log")
    scope = Scope(None if args.all else program.name)
    deadline = time.monotonic() + args.seconds if args.seconds else None
    timed_out = False  # --seconds reached: the stop asked for, not a failure
    interrupted = False

    def alive() -> bool:
        nonlocal timed_out
        if deadline and time.monotonic() > deadline:
            timed_out = True
            return False
        return proc.poll() is None

    def emit(lines: list[str]) -> None:
        for line in lines:
            record = parse_line(line)
            if not record or not scope.keep(record):
                continue
            if trace and record["kind"] == "message" and DEBUGGER_ECHO.match(record["message"]):
                continue
            out.write(record)

    def tick() -> None:
        emit(tail.lines())

    def connect() -> socket.socket | None:
        """DOSBox-X connects once its debugger is up (and again every second until then)."""
        until = time.monotonic() + args.connect_timeout
        while alive() and time.monotonic() < until:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                tick()
                continue
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # no 40 ms Nagle waits
            return conn
        return None

    status, conn = 0, None
    try:
        if trace:
            conn = connect()
            if conn is None and proc.poll() is None and not timed_out:
                out.write(
                    {
                        "kind": "error",
                        "error": "DOSBox-X opened no debugger control channel: this build has no "
                        "debugger or no mcp_server (rea-suite dosbox info; --ints '' without "
                        "--dump, --poke or --input for the log alone)",
                    }
                )
                status = 2
                stop_process(proc)
            elif conn is not None:
                try:
                    tracer = Tracer(Channel(conn), out, run_dir, args, actions, sequence)
                    tracer.run(alive, tick, running=lambda: proc.poll() is None)
                except ChannelError as exc:
                    try:
                        proc.wait(5)  # the channel closes when DOSBox-X quits
                    except subprocess.TimeoutExpired:
                        out.write({"kind": "error", "error": str(exc)})
                        status = 1
        while alive():
            tick()
            time.sleep(0.05)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if proc.poll() is None:
            stop_process(proc)
        for closable in (conn, server):
            if closable:
                closable.close()
        if terminal:
            terminal.close()
        if sequence:
            sequence.close()
    emit(tail.flush())
    out.write(
        {
            "kind": "exit",
            "code": proc.returncode,
            "timed_out": timed_out,
            "interrupted": interrupted,
        }
    )
    out.close()
    # Stopped at --seconds, DOSBox-X's own exit code is that of its stop, not the program's.
    if interrupted or (proc.returncode and not status and not timed_out):
        status = status or 1
    return status


def stop_process(proc: subprocess.Popen) -> None:
    """End DOSBox-X and anything it started (its session on Linux and macOS)."""
    try:
        if os.name == "nt":
            proc.terminate()
        else:
            os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    if proc.poll() is None:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()


def parse(args) -> int:
    out = Output(args.caller_cwd / args.log if args.log else None, args.quiet, timed=False)
    scope = Scope(args.program)
    with (args.caller_cwd / args.logfile).open(encoding="latin-1") as f:
        for line in f:
            record = parse_line(line)
            if record and scope.keep(record):
                out.write(record)
    out.close()
    return 0


def capabilities(binary: str) -> dict[str, bool]:
    """What the build has, from strings only its debugger and control channel carry."""
    marks = {
        "debugger": b"Set interrupt breakpoint at INT",
        "control channel": b"[ControlClient] mcp command",
    }
    found = dict.fromkeys(marks, False)
    tail = b""
    with open(binary, "rb") as f:
        while chunk := f.read(1 << 20):
            data = tail + chunk
            for name, mark in marks.items():
                found[name] = found[name] or mark in data
            tail = data[-64:]
    return found


def info(args) -> int:
    binary = find_dosbox(args.dosbox)
    if not binary:
        print("DOSBox-X: not installed (component `dos`: rea-suite select, then setup)")
        return 2
    print(f"DOSBox-X: {binary}")
    result = subprocess.run(
        [binary, "-version"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"},
        check=False,
        timeout=60,
    )
    text = result.stdout + result.stderr
    version = next((ln for ln in text.splitlines() if "version" in ln.lower()), "")
    print(f"version:  {version.strip() or 'unknown'}")
    try:
        caps = capabilities(binary)
    except OSError as exc:
        print(f"build:    unknown ({exc})")
        return 0
    for name, present in caps.items():
        print(f"{name + ':':17} {'yes' if present else 'no'}")
    if not all(caps.values()):
        print("--ints needs both; without them `run --ints ''` logs DOSBox-X's log only")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite dosbox",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run a DOS program and log it")
    r.add_argument("program", type=Path, help="the DOS program (its folder becomes C:)")
    r.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="its arguments (this command's options go before PROGRAM)",
    )
    r.add_argument("--mount", type=Path, help="mount this folder as C: (it holds the program)")
    r.add_argument("--dpmi", action="store_true", help="load DOSBox-X's CWSDPMI first")
    r.add_argument(
        "--ints",
        default=DEFAULT_INTS,
        help=f"interrupts to trace in the debugger, INT[:AH[:AL]] in hex (default {DEFAULT_INTS}; "
        "empty: the log only). Each stop costs about 20 ms: for a DOS/4GW game's load trace narrowly "
        "(21:3D,33,10), the full set only for a short window",
    )
    r.add_argument(
        "--dump",
        action="append",
        default=[],
        metavar="ADDR:LEN@TRIGGER",
        help="write LEN bytes (decimal, or 0x hex) from ADDR (hex: linear, or SEL:OFF) to a file in "
        "the run's folder when TRIGGER comes, once: intNN[:AH[:AL]], open:NAME, t=SECONDS, start, "
        "exit (repeatable)",
    )
    r.add_argument(
        "--poke",
        action="append",
        default=[],
        metavar="ADDR=BYTES@TRIGGER",
        help="write the bytes (hex) at ADDR when TRIGGER comes, once, before that trigger's dumps "
        "(repeatable)",
    )
    r.add_argument(
        "--input",
        "--keys",
        metavar="SCRIPT",
        help='keyboard and mouse input at times: \'t=10:ENTER t=12:"abc" t=13:mouse:160,100 '
        "t=13.5:click' (docs/PORT-TOOLS.md)",
    )
    r.add_argument("--input-file", type=Path, help="the --input script from a file, an item a line")
    r.add_argument(
        "--regions",
        type=Path,
        help="named memory regions read at sync points (a TOML or JSON file) into a sequence file "
        "for `compare` (docs/PORT-TOOLS.md)",
    )
    r.add_argument(
        "--sequence",
        type=Path,
        help="the sequence file (default regions.jsonl in the run's folder)",
    )
    r.add_argument("--returns", action="store_true", help="log the registers each call returns")
    r.add_argument("--nested", action="store_true", help="also calls made by BIOS code")
    r.add_argument(
        "--groups",
        default=DEFAULT_GROUPS,
        help=f"DOSBox-X log groups at debug level (default {DEFAULT_GROUPS})",
    )
    r.add_argument(
        "--all", action="store_true", help="the log from DOSBox-X's start, not the program's"
    )
    r.add_argument("--seconds", type=float, help="stop after this long")
    r.add_argument("--log", type=Path, help="append the JSON lines to this file too")
    r.add_argument("--quiet", action="store_true", help="no lines on stdout (with --log)")
    r.add_argument("--window", action="store_true", help="show DOSBox-X's window and play sound")
    r.add_argument("--conf", type=Path, help="a dosbox-x.conf for everything else")
    r.add_argument("--set", action="append", default=[], help="'section key=value', repeatable")
    r.add_argument("--workdir", type=Path, help="DOSBox-X's log and scratch (default work/dosbox/)")
    r.add_argument("--dosbox", help="the DOSBox-X binary (default tools/bin/dosbox-x)")
    r.add_argument("--connect-timeout", type=float, default=20.0, help=argparse.SUPPRESS)
    r.set_defaults(run=run)
    p.run_parser = r  # misplaced_options reads its option names

    a = sub.add_parser("parse", help="a DOSBox-X log file as JSON lines")
    a.add_argument("logfile", type=Path)
    a.add_argument("--program", help="drop what comes before this program's start")
    a.add_argument("--log", type=Path, help="append the JSON lines to this file too")
    a.add_argument("--quiet", action="store_true")
    a.set_defaults(run=parse)

    c = sub.add_parser(
        "compare",
        help="two region sequences (a run's and a port's): the first difference",
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
    c.set_defaults(run=rg.compare)

    i = sub.add_parser("info", help="which DOSBox-X runs")
    i.add_argument("--dosbox")
    i.set_defaults(run=info)
    return p


def misplaced_options(args: argparse.Namespace, p: argparse.ArgumentParser) -> list[str]:
    """This command's options written after PROGRAM, which argparse would hand the program unseen (a DOS program's
    own options are `-x` or `/x`, never one of these)."""
    if getattr(args, "command", None) != "run" or not args.args:
        return []
    known = {o for action in p.run_parser._actions for o in action.option_strings}
    return [a for a in args.args if a.split("=", 1)[0] in known]


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if misplaced := misplaced_options(args, p):
        print(
            f"dosbox: {', '.join(misplaced)} after PROGRAM would go to the program: put this command's options "
            "before PROGRAM",
            file=sys.stderr,
        )
        return 2
    try:
        return args.run(args)
    except (OSError, ValueError) as exc:
        print(f"dosbox: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
