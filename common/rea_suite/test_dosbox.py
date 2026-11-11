"""`rea-suite dosbox`: DOSBox-X's log lines as records, the debugger's answers, interrupt records and
the stop handling against a stand-in debugger. The runs against a real DOSBox-X (a .COM and a DPMI
client assembled with nasm) are opt-in: REA_DOSBOX_INTEGRATION=1, with DOSBox-X installed
(component `dos`) or REA_DOSBOX_X naming one with its debugger."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from rea_suite import dosbox
from rea_suite import dosbox_actions as acts

ROOT = Path(__file__).resolve().parents[2]


def regs(**values: int) -> dict[str, int]:
    base = dict.fromkeys(dosbox.REGISTERS, 0)
    base.update({"EFLAGS": 0x7202, "CS": 0x814, "DS": 0x814, "ES": 0x814, "SS": 0x814})
    base.update({k.upper(): v for k, v in values.items()})
    return base


class LogLines(unittest.TestCase):
    def test_int21_line_names_the_function(self) -> None:
        r = dosbox.parse_line("      2765 DEBUG DOSMISC:Executing interrupt 21, ah=3d, al=2\n")
        self.assertEqual(r["kind"], "dos-int")
        self.assertEqual((r["cycle"], r["int"], r["function"]), (2765, "21", "3D"))
        self.assertEqual((r["service"], r["al"]), ("open file", "02"))

    def test_console_prefix_is_dropped(self) -> None:
        r = dosbox.parse_line("LOG:       2855       MOUSE:INT 33h reset")
        self.assertEqual(r, {"kind": "log", "cycle": 2855, "group": "MOUSE",
                             "severity": "normal", "message": "INT 33h reset"})  # fmt: skip

    def test_file_messages(self) -> None:
        cases = {
            "        82       FILES:Special file open command 80 file Z:\\AUTOEXEC.BAT": {
                "op": "open", "special": True, "mode": 0x80, "name": "Z:\\AUTOEXEC.BAT"},
            "      2759       FILES:file open command 0 file HELLO.COM": {
                "op": "open", "special": False, "mode": 0, "name": "HELLO.COM"},
            "      2862       FILES:file create attributes 20 file OUT.TXT": {
                "op": "create", "attributes": 0x20, "name": "OUT.TXT"},
            "      2924 DEBUG FILES:Reading 28 bytes from HELLO.COM ": {
                "op": "read", "bytes": 28, "name": "HELLO.COM"},
            "      2924 DEBUG FILES:Seeking to 0 bytes from position type (2) in HELLO.COM ": {
                "op": "seek", "position": 0, "whence": 2, "name": "HELLO.COM"},
            "       872 DEBUG FILES:Writing 16 bytes to OUT.TXT": {
                "op": "write", "bytes": 16, "name": "OUT.TXT"},
            "       891       FILES:Closing file OUT.TXT": {"op": "close", "name": "OUT.TXT"},
        }  # fmt: skip
        for line, expected in cases.items():
            r = dosbox.parse_line(line)
            self.assertEqual(r.pop("kind"), "file", line)
            r.pop("cycle")
            self.assertEqual(r, expected, line)

    def test_severities_e9_and_plain_lines(self) -> None:
        self.assertEqual(dosbox.parse_line("  10 ERROR CPU:LTR failed")["severity"], "error")
        self.assertEqual(dosbox.parse_line("  10 WARN  PIC:x")["severity"], "warn")
        self.assertEqual(dosbox.parse_line("Bochs port E9h: phase one"),
                         {"kind": "e9", "text": "phase one"})  # fmt: skip
        self.assertEqual(dosbox.parse_line("Early LOG Init complete")["kind"], "message")
        self.assertIsNone(dosbox.parse_line("--END OF LOG--"))
        self.assertIsNone(dosbox.parse_line("   \n"))

    def test_scope_keeps_the_programs_run_only(self) -> None:
        lines = [
            "  1 DEBUG FILES:Reading 4 bytes from MOUNT.COM",
            "  2       FILES:file open command 0 file C:\\GAME\\MAIN.EXE",
            "  3 DEBUG FILES:Reading 4 bytes from MAIN.EXE",
            "  4       FILES:file open command 0 file DATA.DAT",
            "  5       FILES:Special file open command 80 file Z:\\AUTOEXEC.BAT",
            "  6       FILES:Closing file AUTOEXEC.BAT",
        ]
        scope = dosbox.Scope("main.exe")
        kept = [r["cycle"] for r in map(dosbox.parse_line, lines) if scope.keep(r)]
        self.assertEqual(kept, [2, 3, 4])
        everything = dosbox.Scope(None)
        self.assertTrue(all(everything.keep(dosbox.parse_line(ln)) for ln in lines))

    def test_debugger_echo_is_recognized(self) -> None:
        for line in ("EV of 'EAX EBX' is:", "900 0 ff", "DEBUG: Set breakpoint at 0814:0107",
                     "***| TYPE HELP (+ENTER) TO GET AN OVERVIEW OF ALL COMMANDS |***"):  # fmt: skip
            self.assertTrue(dosbox.DEBUGGER_ECHO.match(line), line)
        self.assertFalse(dosbox.DEBUGGER_ECHO.match("DOSBox-X has switched to max cycles"))

    def test_log_tail_returns_whole_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.log"
            tail = dosbox.LogTail(path)
            self.assertEqual(tail.lines(), [])
            path.write_bytes(b"one\ntw")
            self.assertEqual(tail.lines(), ["one"])
            with path.open("ab") as f:
                f.write(b"o\nthree")
            self.assertEqual(tail.lines(), ["two"])
            self.assertEqual(tail.flush(), ["three"])


class DebuggerText(unittest.TestCase):
    def test_ev_answer(self) -> None:
        lines = ["EV of 'CS EIP EAX' is:", "814 100 0"]
        self.assertEqual(dosbox.parse_ev(lines, ["CS", "EIP", "EAX"]),
                         {"CS": 0x814, "EIP": 0x100, "EAX": 0})  # fmt: skip
        with self.assertRaises(dosbox.ChannelError):
            dosbox.parse_ev(["ERR", "*** Debugger command not recognized"], ["CS"])

    def test_numbers_never_read_as_names(self) -> None:
        self.assertEqual(dosbox.hexarg(0xCF), "0CF")  # CF is the carry flag to the debugger
        self.assertEqual(dosbox.bpint(0x21, None, None), "BPINT 021")
        self.assertEqual(dosbox.bpint(0x21, 0x3D, None), "BPINT 021 03D")

    def test_interrupt_list(self) -> None:
        self.assertEqual(dosbox.parse_ints("21, 31,33:00,21:3d:02"),
                         [(0x21, None, None), (0x31, None, None), (0x33, 0, None),
                          (0x21, 0x3D, 2)])  # fmt: skip
        self.assertEqual(dosbox.parse_ints(""), [])
        for bad in ("100", "21:1:2:3", "zz"):
            with self.assertRaises(ValueError):
                dosbox.parse_ints(bad)

    def test_breakpoint_numbers_follow_the_debuggers_list(self) -> None:
        bps = dosbox.Breakpoints()
        for key in ("int21", "a", "b", "c"):
            bps.add(key)
        self.assertEqual(bps.remove("b"), 1)  # newest first: c, b, a, int21
        self.assertEqual(bps.remove("int21"), 2)
        self.assertEqual(bps.keys, ["c", "a"])


class Records(unittest.TestCase):
    def test_protected_mode_open_reads_the_path_at_ds_edx(self) -> None:
        memory = {(0x168, 0x12345): b"DATA\\LEVEL.DAT\x00junk"}
        r = dosbox.int_record(
            0x21,
            regs(eax=0x3D00, edx=0x12345, ds=0x168, cs=0x160, eip=0x10234, cr0=1),
            lambda seg, off, n: memory[(seg, off)][:n],
        )
        self.assertEqual((r["function"], r["service"], r["mode"]), ("3D", "open file", "pm"))
        self.assertEqual((r["path"], r["at"]), ("DATA\\LEVEL.DAT", "0160:00010234"))
        self.assertEqual(r["regs"]["edx"], "00012345")

    def test_real_mode_reads_only_the_low_word(self) -> None:
        seen = []
        dosbox.int_record(0x21, regs(eax=0x0900, edx=0xABCD0139),
                          lambda s, o, n: seen.append((s, o)) or b"hi$")  # fmt: skip
        self.assertEqual(seen, [(0x814, 0x139)])

    def test_dpmi_real_mode_call_structure(self) -> None:
        data = struct.pack("<8I", 1, 2, 3, 0, 5, 6, 7, 0x0900) + struct.pack(
            "<9H", 0x202, 0x10, 0x12E6, 0, 0, 0x1B3, 0x12E6, 0x200, 0x9000
        )
        r = dosbox.int_record(0x31, regs(eax=0x0300, ebx=0x21, edi=0x40, es=0x8F, cr0=1),
                              lambda s, o, n: data)  # fmt: skip
        self.assertEqual((r["function"], r["bl"], r["group"]), ("0300", "21", "real-mode calls"))
        rm = r["real_mode"]
        self.assertEqual((rm["eax"], rm["ds"], rm["cs:ip"], rm["ss:sp"]),
                         ("00000900", "12E6", "12E6:01B3", "9000:0200"))  # fmt: skip

    def test_mouse_handler_and_callback_allocation(self) -> None:
        r = dosbox.int_record(0x33, regs(eax=0x000C, ecx=0x1F, es=0x2000, edx=0x40),
                              lambda s, o, n: b"")  # fmt: skip
        self.assertEqual((r["service"], r["handler"]), ("set event handler (callback)", "2000:40"))
        r = dosbox.int_record(0x31, regs(eax=0x0303, ds=0x87, esi=0x1A5, cr0=1),
                              lambda s, o, n: b"")  # fmt: skip
        self.assertEqual(r["handler"], "0087:1A5")

    def test_bios_calls_and_modes(self) -> None:
        self.assertTrue(dosbox.from_bios(regs(cs=0xF000)))
        self.assertFalse(dosbox.from_bios(regs(cs=0xF000, cr0=1)))  # a selector
        self.assertEqual(dosbox.cpu_mode(regs(cr0=1, eflags=0x20202)), "v86")


class FakeDebugger:
    """The debugger stopped at `current` (registers, the bytes MEMDUMPBIN gives); records every
    command for the assertions."""

    def __init__(self, memdir: Path, psp: int = 0x814):
        self.memdir, self.psp = memdir, psp
        self.current: tuple[dict, bytes] = (regs(), b"")
        self.commands: list[str] = []
        self.memory: dict[str, bytes] = {}  # MEMDUMPBIN's address argument -> its bytes

    def request(self, command: str = "", kind: str = "EXEC") -> list[str]:
        self.commands.append(command)
        state, code = self.current
        word = command.split()[0]
        if command == "EV PSPSEG":
            return ["EV of 'PSPSEG' is:", f"{self.psp:x}"]
        if word == "EV":
            names = command.split()[1:]
            return [f"EV of '{' '.join(names)}' is:", " ".join(f"{state[n]:x}" for n in names)]
        if word == "MEMDUMPBIN":
            (self.memdir / dosbox.MEMFILE).write_bytes(self.memory.get(command.split()[1], code))
        return ["DEBUG: ok"]

    def request_all(self, commands: list[str]) -> list[list[str]]:
        return [self.request(c) for c in commands]

    def stop(self, t: dosbox.Tracer, state: dict, code: bytes) -> bool:
        self.current = (state, code)
        return t.stop(state)


def tracer(
    fake: FakeDebugger, tmp: Path, actions: acts.Actions | None = None, **options
) -> tuple[dosbox.Tracer, list[dict]]:
    records: list[dict] = []
    out = dosbox.Output(None, quiet=True)
    out.write = records.append  # type: ignore[method-assign]
    options = {"ints": "21,31,33,10", "returns": False, "nested": False, **options}
    t = dosbox.Tracer(fake, out, tmp, argparse.Namespace(**options), actions)  # type: ignore[arg-type]
    return t, records


class Stops(unittest.TestCase):
    def test_entry_calls_bios_calls_and_the_programs_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stops = [
                (regs(eip=0x100), b"\xb4\x09"),  # DEBUGBOX's stop at the entry
                (regs(eax=0x0900, edx=0x139, eip=0x105), b"\xcd\x21"),
                (regs(eax=0x0E68, cs=0xF000, eip=0xDA60), b"\xcd\x10"),  # not traced: 10h
                (regs(eax=0x0000, eip=0x10B), b"\xcd\x33"),
                (regs(eax=0x4C00, eip=0x137), b"\xcd\x21"),
            ]
            fake = FakeDebugger(Path(tmp))
            t, records = tracer(fake, Path(tmp))
            for state, code in stops:
                self.assertTrue(fake.stop(t, state, code))
            kinds = [(r["kind"], r.get("int"), r.get("function")) for r in records]
            self.assertEqual(kinds, [("start", None, None), ("int", "21", "09"),
                                     ("int", "33", "0000"), ("int", "21", "4C")])  # fmt: skip
            self.assertEqual(records[1]["text"], "\xcd!")  # what MEMDUMPBIN gave, to the $
            self.assertTrue(t.done)  # the program's own exit: breakpoints gone
            self.assertEqual(fake.commands.count("BPDEL 00"), 4)
            self.assertEqual(fake.commands.count("RUN"), 5)

    def test_a_halted_cpu_or_another_process_is_no_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeDebugger(Path(tmp))
            t, records = tracer(fake, Path(tmp))
            self.assertFalse(fake.stop(t, regs(eip=0x100), b"\xf4\x00"))  # hlt
            not_entry = regs(ds=0x900, es=0x900, eip=0x100)  # another program's registers
            self.assertFalse(fake.stop(t, not_entry, b"\x90\x90"))
            self.assertEqual(records, [])
            self.assertNotIn("RUN", fake.commands)

    def test_returns_and_a_dpmi_callback_placed_in_real_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pm = {"cr0": 1, "cs": 0x87, "ds": 0x8F, "es": 0x8F, "ss": 0x8F}
            stops = [
                (regs(eip=0x100), b"\x90\x90"),
                (regs(eax=0x0303, esi=0x1A5, eip=0x16D, **pm), b"\xcd\x31"),
                (regs(ecx=0x824, edx=0xF87, eip=0x16F, **pm), b"\x89\xd0"),  # its return
                (regs(eax=0x3000, eip=0x1B3, cs=0x12E6), b"\xcd\x21"),  # real mode
                (regs(cs=0x824, eip=0xF87), b"\x9a\x00"),  # the callback is entered
            ]
            fake = FakeDebugger(Path(tmp), psp=0x814)
            t, records = tracer(fake, Path(tmp))
            for state, code in stops:
                self.assertTrue(fake.stop(t, state, code))
            kinds = [r["kind"] for r in records]
            self.assertEqual(kinds, ["start", "int", "return", "int", "callback"])
            self.assertEqual(records[2]["callback"], "0824:0F87")
            self.assertEqual((records[4]["via"], records[4]["handler"]), ("dpmi 0303", "008F:1A5"))
            self.assertIn("BP 087:016F", fake.commands)  # the return, while in protected mode
            self.assertIn("BP 0824:0F87", fake.commands)  # the callback, once in real mode
            self.assertIn("BPDEL 00", fake.commands)  # the return's, the newest


class StandIn(threading.Thread):
    """DOSBox-X's side of the control channel: it answers a request only when the next line
    arrives, as its network thread does (it sends between reads)."""

    def __init__(self, sock: socket.socket):
        super().__init__(daemon=True)
        self.sock, self.pings = sock, 0

    def run(self) -> None:
        pending, buffer = [], b""
        while data := self.sock.recv(4096):
            buffer += data
            *lines, buffer = buffer.split(b"\n")
            for line in lines:
                for answer in pending:
                    self.sock.sendall(answer)
                pending = []
                _, rid, kind, *rest = line.decode().split(" ", 3)
                self.pings += kind == "PING"
                body = "PONG" if kind == "PING" else f"did {rest[0]}"
                pending.append(f"BEGIN {rid} OK\n{body}\nEND {rid}\n".encode())


class Channel(unittest.TestCase):
    def test_answers_come_with_nudges_and_pongs_are_dropped(self) -> None:
        ours, theirs = socket.socketpair()
        stand_in = StandIn(theirs)
        stand_in.start()
        channel = dosbox.Channel(ours, timeout=5)
        self.assertEqual(channel.request("EV CS"), ["did EV CS"])
        self.assertEqual(channel.request("RUN"), ["did RUN"])
        self.assertGreaterEqual(stand_in.pings, 2)
        self.assertEqual(channel.blocks, {})
        ours.close()
        stand_in.join(2)
        theirs.close()


class Command(unittest.TestCase):
    def test_dosbox_command_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            game = (Path(tmp) / "My Game").resolve()  # macOS: /var is /private/var
            (game / "BIN").mkdir(parents=True)
            (game / "BIN" / "MAIN.EXE").write_bytes(b"MZ")
            args = argparse.Namespace(
                caller_cwd=Path(tmp), program=Path("My Game/BIN/MAIN.EXE"), args=["-nosound"],
                mount=Path("My Game"), groups="files,mouse", window=False, conf=None,
                set=["cpu cycles=max"], dpmi=True,
            )  # fmt: skip
            cmd = dosbox.dosbox_command(args, "dosbox-x", Path(tmp) / "run", 5555)
            joined = " | ".join(cmd)
            for part in (f'mount c "{game}"', "cd \\BIN", "Z:\\BIN\\CWSDPMI.EXE -p",
                         "DEBUGBOX MAIN.EXE -nosound", "dosbox mcp_server=5555",
                         "cpu core=normal", "log int21=false", "log files=debug",
                         "midi mididevice=none", "cpu cycles=max"):  # fmt: skip
                self.assertIn(part, joined)
            cmd = dosbox.dosbox_command(args, "dosbox-x", Path(tmp) / "run", None)
            self.assertIn("MAIN.EXE -nosound", cmd)
            self.assertIn("log int21=true", cmd)


HELLO = """org 100h
        mov ah, 09h
        mov dx, msg
        int 21h
        mov ah, 0Fh
        int 10h
        xor ax, ax
        int 33h
        mov dx, 0E9h
        mov si, mark
.e9:    lodsb
        out dx, al
        cmp al, 10
        jne .e9
        mov ax, 4C00h
        int 21h
msg     db 'hello', 13, 10, '$'
mark    db 'phase one', 10
"""

# A 32-bit DPMI client (CWSDPMI takes no other) in 16-bit segments: INT 31h in protected mode,
# 0300h, and a real-mode callback (0303h) called from real-mode code through 0301h.
DPMI = """org 100h
        mov [rmseg], cs
        mov ah, 4Ah
        mov bx, 1000h
        int 21h
        mov ax, 1687h
        int 2Fh
        test ax, ax
        jnz fail
        mov [entry], di
        mov [entry+2], es
        mov ax, cs
        add ax, 1000h
        mov es, ax
        mov ax, 1
        call far [entry]
        jc fail
        xor esi, esi
        xor edi, edi
        mov ax, 0400h
        int 31h
        mov ax, [rmseg]
        mov [rm+24h], ax
        mov word [rm+14h], msg
        mov word [rm+1Ch], 0900h
        push ds
        pop es
        mov di, rm
        mov ax, 0300h
        mov bx, 0021h
        xor cx, cx
        int 31h
        push ds
        push es
        push cs
        pop ds
        mov si, pm_cb
        mov di, cbregs
        mov ax, 0303h
        int 31h
        pop es
        pop ds
        jc done
        mov [cbaddr], dx
        mov [cbaddr+2], cx
        mov word [rmcall+2Ah], rmproc
        mov ax, [rmseg]
        mov [rmcall+2Ch], ax
        mov di, rmcall
        mov ax, 0301h
        xor bx, bx
        xor cx, cx
        int 31h
        mov ax, 0304h
        mov dx, [cbaddr]
        mov cx, [cbaddr+2]
        int 31h
done:   mov ax, 4C00h
        int 21h
fail:   mov ax, 4C01h
        int 21h
rmproc: mov ah, 30h
        int 21h
        call far [cs:cbaddr]
        retf
pm_cb:  cld
        a32 lodsw
        mov [es:edi+2Ah], ax
        a32 lodsw
        mov [es:edi+2Ch], ax
        add word [es:edi+2Eh], 4
        iretd
msg     db 'from protected mode', 13, 10, '$'
entry   dd 0
cbaddr  dd 0
rmseg   dw 0
rm:     times 32h db 0
rmcall: times 32h db 0
cbregs: times 32h db 0
"""


class ActionOptions(unittest.TestCase):
    def test_triggers(self) -> None:
        t = acts.parse_trigger("int21:3D")
        self.assertEqual((t.kind, t.n, t.ah, t.al), ("int", 0x21, 0x3D, None))
        self.assertEqual(t.breakpoints(), [(0x21, 0x3D, None)])
        self.assertEqual(acts.parse_trigger("INT33").breakpoints(), [(0x33, None, None)])
        self.assertEqual(acts.parse_trigger("t=2.5").seconds, 2.5)
        self.assertEqual(acts.parse_trigger("exit").breakpoints(),
                         [(0x21, 0x4C, None), (0x21, 0x00, None), (0x21, 0x31, None)])  # fmt: skip
        self.assertEqual(acts.parse_trigger("open:data/foo.dat").name, "data/foo.dat")
        for bad in ("int", "int123", "t=x", "t=-1", "open:", "soon"):
            with self.assertRaises(ValueError, msg=bad):
                acts.parse_trigger(bad)

    def test_an_open_matches_the_name_or_the_paths_tail(self) -> None:
        t = acts.parse_trigger("open:data/level.dat")
        self.assertTrue(t.matches_call(0x21, 0x3D00, "C:\\GAME\\DATA\\LEVEL.DAT"))
        self.assertTrue(t.matches_call(0x21, 0x6C00, "data\\level.dat"))
        self.assertFalse(t.matches_call(0x21, 0x3D00, "C:\\GAME\\XDATA\\LEVEL.DAT"))
        self.assertFalse(t.matches_call(0x21, 0x3C00, "DATA\\LEVEL.DAT"))  # a create
        self.assertTrue(acts.parse_trigger("int21:3D:02").matches_call(0x21, 0x3D02, None))
        self.assertFalse(acts.parse_trigger("int21:3D:02").matches_call(0x21, 0x3D00, None))

    def test_dumps_and_pokes(self) -> None:
        d = acts.parse_dump("0168:00012345:0x400@open:MAIN.DAT")
        self.assertEqual((d.address.sel, d.address.off, d.length), (0x168, 0x12345, 0x400))
        self.assertEqual(d.trigger.kind, "open")
        d = acts.parse_dump("1A2B30:64@t=30")
        self.assertEqual((d.address.linear, d.length, d.trigger.seconds), (0x1A2B30, 64, 30))
        p = acts.parse_poke("90020=CA FE,01@start")
        self.assertEqual((p.address.linear, p.data), (0x90020, b"\xca\xfe\x01"))
        self.assertEqual(acts.poke_commands(p, "pm"), ["SMV 090020 0CA 0FE 001"])
        p = acts.parse_poke("9000:20=90@exit")
        self.assertEqual(acts.poke_commands(p, "rm"), ["SM 09000:020 090"])
        for bad in ("90000:16", "90000@exit", "obj1+10:16@exit", "90000:0@exit", "zz:1@exit"):
            with self.assertRaises(ValueError, msg=bad):
                acts.parse_dump(bad)
        for bad in ("90000=@exit", "90000=xyz@exit", "90000@exit"):
            with self.assertRaises(ValueError, msg=bad):
                acts.parse_poke(bad)

    def test_memdump_pieces_by_mode(self) -> None:
        linear = acts.parse_address("12345")
        # real mode: segment = linear / 16, at most FFF0h bytes a piece (offsets wrap at 64 KiB)
        self.assertEqual(acts.memdump_pieces(linear, 0x20000, "rm"),
                         [(0x1234, 5, 0xFFF0), (0x2233, 5, 0xFFF0), (0x3232, 5, 0x20)])  # fmt: skip
        self.assertEqual(acts.memdump_pieces(acts.parse_address("9000:0010"), 8, "v86"),
                         [(0x9001, 0, 8)])  # fmt: skip
        with self.assertRaises(ValueError):
            acts.memdump_pieces(acts.parse_address("200000"), 1, "rm")
        # protected mode: SEL:OFF as is, a linear address through CS less its base, mod 4 GiB
        self.assertEqual(acts.memdump_pieces(acts.parse_address("A7:1000"), 9, "pm"),
                         [(0xA7, 0x1000, 9)])  # fmt: skip
        self.assertEqual(acts.memdump_pieces(linear, 4, "pm", cs=0x160, cs_base=0x10000),
                         [(0x160, 0x2345, 4)])  # fmt: skip
        self.assertEqual(acts.memdump_pieces(linear, 4, "pm", cs=0x160, cs_base=0x20000),
                         [(0x160, 0xFFFF2345, 4)])  # fmt: skip

    def test_selinfo_answer(self) -> None:
        lines = ["SelectorInfo CS:", "CS: b:00010000 type:1B parbg", "    l:0000FFFF dpl : 3 11110"]
        self.assertEqual(acts.parse_selinfo(lines), (0x10000, 0xFFFF, True))
        lines[2] = "    l:0000FFFF dpl : 3 11100"
        self.assertFalse(acts.parse_selinfo(lines)[2])
        with self.assertRaises(ValueError):
            acts.parse_selinfo(["SelectorInfo 0:", "   ", "   "])

    def test_dump_record(self) -> None:
        d = acts.parse_dump("90000:4@exit")
        r = acts.dump_record(
            d, Path("dump-01-exit.bin"), b"\x01\x02", "pm", "00A7:00000199", 0x90000
        )
        self.assertEqual((r["kind"], r["addr"], r["linear"], r["len"], r["trigger"], r["short"]),
                         ("dump", "90000", "00090000", 4, "exit", 2))  # fmt: skip
        self.assertEqual(r["sha256"], hashlib.sha256(b"\x01\x02").hexdigest())
        self.assertEqual(
            acts.dump_filename(3, acts.parse_dump("1:1@int21:3D")), "dump-03-int21-3D.bin"
        )


class InputScript(unittest.TestCase):
    def test_keys_text_and_mouse(self) -> None:
        steps = acts.parse_input(
            't=10:ENTER t=12:"aB" t=13:ctrl+F6 t=14:RIGHT*2\n'
            "# a comment\nt=15:mouse:160,100 t=16:click:right t=17:move:-8,4 t=18:down t=19:up"
        )
        got = [(s.t, s.kind, s.value) for s in steps]
        self.assertEqual(got[:2], [(10, "keys", (0x1C,)), (10 + acts.KEY_HOLD, "keys", (0x9C,))])
        typed = [v for t, k, v in got if 12 <= t < 13]
        self.assertEqual(typed, [(0x1E,), (0x9E,), (0x2A, 0x30), (0xB0, 0xAA)])  # a, then shift+b
        self.assertIn((13, "keys", (0x1D, 0x40)), got)
        self.assertIn((16, "keys", (0xE0, 0xCD)), got)  # RIGHT, extended, released after 2 s
        self.assertIn((15, "mouse", (160, 100)), got)
        self.assertIn((16, "button", (1, True)), got)
        self.assertIn((17, "move", (-8, 4)), got)
        self.assertEqual([t for t, _, _ in got], sorted(t for t, _, _ in got))

    def test_bad_items(self) -> None:
        for bad in ("ENTER", "t=1:NOKEY", "t=1:mouse:1", "t=1:mouse:-1,0", "t=1:click:side",
                    't=1:"é"', "t=1:ENTER*x", "t=1:ENTER junk"):  # fmt: skip
            with self.assertRaises(ValueError, msg=bad):
                acts.parse_input(bad)

    def test_integration_device_writes(self) -> None:
        keys, button = acts.parse_input("t=1:ENTER t=2:down:middle")[0::2]
        self.assertEqual(acts.integration_values(keys), [0x1C])
        self.assertEqual(acts.integration_values(button), [0x0882])
        self.assertEqual(acts.integration_commands([0x1C]),
                         ["OUTB 02A 00", "OUTD 028 0804200", "OUTD 029 01C"])  # fmt: skip
        with self.assertRaises(ValueError):
            acts.integration_values(acts.parse_input("t=1:mouse:1,1")[0])


class ActionStops(unittest.TestCase):
    """The tracer's triggers against the stand-in debugger."""

    def test_triggered_dumps_once_and_breakpoints_for_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeDebugger(Path(tmp))
            actions = acts.Actions.from_args(
                ["9000:0:4@int16", "814:200:2@open:LEVEL.DAT", "90000:2@exit"],
                ["90000=AA@start"],
                None,
            )
            fake.memory["0814:0139"] = b"C:\\GAME\\LEVEL.DAT\0"
            fake.memory["09000:00"] = b"PATT"
            t, records = tracer(fake, Path(tmp), actions=actions, ints="33")
            stops = [
                (regs(eip=0x100), b"\xb4\x09"),
                (regs(eip=0x105), b"\xcd\x16"),
                (regs(eip=0x107), b"\xcd\x16"),  # again: once only
                (regs(eax=0x3D00, edx=0x139, eip=0x109), b"\xcd\x21"),
                (regs(eax=0x4C00, eip=0x10B), b"\xcd\x21"),
            ]
            for state, code in stops:
                fake.stop(t, state, code)
            for bp in ("BPINT 016", "BPINT 021 03D", "BPINT 021 06C", "BPINT 021 04C", "BPINT 033"):
                self.assertIn(bp, fake.commands)
            kinds = [(r["kind"], r.get("trigger")) for r in records]
            self.assertEqual(kinds, [("start", None), ("poke", "start"), ("dump", "int16"),
                                     ("dump", "open:LEVEL.DAT"), ("dump", "exit")])  # fmt: skip
            self.assertIn("SMV 090000 0AA", fake.commands)
            self.assertIn("MEMDUMPBIN 09000:00 04 REAMEM.BIN", fake.commands)
            self.assertEqual(records[3]["path"], "C:\\GAME\\LEVEL.DAT")
            self.assertNotIn("int", [r["kind"] for r in records])  # 21 and 16 are not --ints
            first = Path(records[2]["file"])
            self.assertEqual(first.read_bytes(), b"PATT")
            self.assertEqual(records[2]["sha256"], hashlib.sha256(b"PATT").hexdigest())
            self.assertTrue(t.done)

    def test_the_mouse_is_placed_only_in_the_programs_own_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t, _ = tracer(FakeDebugger(Path(tmp)), Path(tmp))
            t.psp = 0x814
            self.assertTrue(t.own_code(regs(cs=0x814)))
            self.assertFalse(t.own_code(regs(cs=0xF000)))  # BIOS, DOSBox-X's callbacks
            self.assertTrue(t.own_code(regs(cs=0xA7, cr0=1)))  # protected mode, none seen yet
            t.app_cs = 0xA7
            self.assertFalse(t.own_code(regs(cs=0x8F, cr0=1)))  # the DPMI host's
            self.assertFalse(t.own_code(regs(cs=0x814)))  # its extender's real-mode part


# Writes a pattern at 9000:0000, waits for a key (INT 16h), resets the mouse and polls it (INT 33h
# 0003h) until the left button is down, keeps the key, the reset's answer and the position at
# 9000:0010, and exits. The 32-bit protected-mode variant does the same from a 32-bit code segment
# it makes, under CWSDPMI.
INPUT = """org 100h
        mov ax, 9000h
        mov es, ax
        xor di, di
        mov si, pattern
        mov cx, 16
        rep movsb
        xor ah, ah
        int 16h
        mov [es:10h], ax
        xor ax, ax
        int 33h
        mov [es:12h], ax
.poll:  mov ax, 3
        int 33h
        test bx, 1
        jz .poll
        mov [es:14h], cx
        mov [es:16h], dx
        mov ax, 4C00h
        int 21h
pattern db 'REA-DUMP-PATTERN'
"""

INPUT_PM = """org 100h
        mov [rmseg], cs
        mov ah, 4Ah
        mov bx, 1000h
        int 21h
        mov ax, 1687h
        int 2Fh
        test ax, ax
        jnz fail
        mov [entry], di
        mov [entry+2], es
        mov ax, cs
        add ax, 1000h
        mov es, ax
        mov ax, 1
        call far [entry]
        jc fail
        xor ax, ax
        mov cx, 1
        int 31h
        jc fail
        mov [sel32], ax
        mov bx, ax
        mov dx, [rmseg]
        mov cx, dx
        shl dx, 4
        shr cx, 12
        mov ax, 7
        int 31h
        mov bx, [sel32]
        xor cx, cx
        mov dx, 0FFFFh
        mov ax, 8
        int 31h
        mov bx, [sel32]
        mov cx, 40FAh
        mov ax, 9
        int 31h
        jc fail
        mov ax, 2
        mov bx, 9000h
        int 31h
        mov [sel9000], ax
        push word [sel32]
        push word code32
        retf
fail:   mov ax, 4C01h
        int 21h
bits 32
code32: mov ah, 30h
        int 21h
        mov es, [sel9000]
        xor edi, edi
        mov esi, pattern
        mov ecx, 16
        rep movsb
        xor ah, ah
        int 16h
        mov [es:10h], ax
        xor eax, eax
        int 33h
        mov [es:12h], ax
.poll:  mov eax, 3
        int 33h
        test bx, 1
        jz .poll
        mov [es:14h], cx
        mov [es:16h], dx
        mov ax, 4C00h
        int 21h
bits 16
pattern db 'REA-DUMP-PATTERN'
rmseg   dw 0
entry   dd 0
sel32   dw 0
sel9000 dw 0
"""


@unittest.skipUnless(os.environ.get("REA_DOSBOX_INTEGRATION"), "runs DOSBox-X")
class RealRun(unittest.TestCase):
    def run_program(self, source: str, name: str, *options: str) -> list[dict]:
        if not shutil.which("nasm"):
            self.skipTest("needs nasm (component `build`)")
        scratch = ROOT / "work" / "test-dosbox"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            asm = Path(tmp) / "prog.asm"
            asm.write_text(source)
            subprocess.run(["nasm", "-f", "bin", "-o", str(Path(tmp) / name), str(asm)], check=True)
            log = Path(tmp) / "log.jsonl"
            argv = ["run", "--quiet", "--log", str(log), "--seconds", "120",
                    "--workdir", str(Path(tmp) / "run"), *options, str(Path(tmp) / name)]  # fmt: skip
            status = dosbox.main(argv)
            records = [json.loads(line) for line in log.read_text().splitlines()]
            for r in records:  # the dumps' bytes, before the folder goes
                if r["kind"] == "dump":
                    r["data"] = Path(r["file"]).read_bytes()
        self.assertEqual(status, 0, records[-3:])
        return records

    def check_dumps_and_input(self, records: list[dict], x: int, y: int) -> None:
        dumps = {r["trigger"]: r for r in records if r["kind"] == "dump"}
        self.assertEqual(dumps["int16"]["data"], b"REA-DUMP-PATTERN")  # before the key is read
        self.assertEqual(dumps["int16"]["sha256"], hashlib.sha256(b"REA-DUMP-PATTERN").hexdigest())
        # at the exit: ENTER (scan code 1Ch, character 0Dh), the mouse reset's FFFFh, the
        # position placed, and the bytes the poke wrote
        self.assertEqual(
            dumps["exit"]["data"], struct.pack("<4H", 0x1C0D, 0xFFFF, x, y) + bytes(8) + b"\xca\xfe"
        )
        placed = next(r for r in records if r["kind"] == "input" and r["input"] == "mouse")
        self.assertEqual(placed["at"], [x, y])
        self.assertEqual(records[-1]["kind"], "exit")
        self.assertFalse(records[-1]["timed_out"])  # the scripted click ended it

    def test_real_mode_program(self) -> None:
        records = self.run_program(HELLO, "HELLO.COM")
        ints = [(r["int"], r["function"]) for r in records if r["kind"] == "int"]
        self.assertEqual(ints, [("21", "09"), ("10", "0F"), ("33", "0000"), ("21", "4C")])
        self.assertIn({"kind": "e9", "text": "phase one"},
                      [{k: r[k] for k in ("kind", "text")} for r in records if r["kind"] == "e9"])  # fmt: skip
        self.assertEqual(records[-1]["kind"], "exit")

    def test_dpmi_client_and_its_callback(self) -> None:
        records = self.run_program(DPMI, "DPMI.COM", "--dpmi")
        pm = [
            (r["int"], r["function"]) for r in records if r["kind"] == "int" and r["mode"] == "pm"
        ]
        self.assertEqual(pm, [("31", "0400"), ("31", "0300"), ("31", "0303"), ("31", "0301"),
                              ("31", "0304"), ("21", "4C")])  # fmt: skip
        call = next(r for r in records if r.get("function") == "0300")
        self.assertEqual((call["bl"], call["real_mode"]["eax"]), ("21", "00000900"))
        back = next(r for r in records if r["kind"] == "return")
        callback = next(r for r in records if r["kind"] == "callback")
        self.assertEqual(callback["at"], back["callback"])
        self.assertEqual(callback["via"], "dpmi 0303")

    def test_dumps_pokes_keys_and_mouse_in_real_mode(self) -> None:
        records = self.run_program(
            INPUT, "INPUT.COM", "--ints", "21",
            "--dump", "90000:16@int16", "--dump", "9000:0010:18@exit", "--dump", "90000:4@t=3",
            "--poke", "90020=CAFE@start",
            "--input", "t=0:ENTER t=2:mouse:104,48 t=4:click",
        )  # fmt: skip
        self.check_dumps_and_input(records, 104, 48)
        timed = next(r for r in records if r.get("trigger") == "t=3")
        self.assertEqual(timed["data"], b"REA-")

    def test_dumps_pokes_keys_and_mouse_in_protected_mode(self) -> None:
        records = self.run_program(
            INPUT_PM, "INPUT32.COM", "--dpmi", "--ints", "21",
            "--dump", "90000:16@int16", "--dump", "90010:18@exit", "--poke", "90020=CAFE@int16",
            "--input", "t=0:ENTER t=2:mouse:200,64 t=5:click",
        )  # fmt: skip
        self.check_dumps_and_input(records, 200, 64)
        self.assertEqual({r["mode"] for r in records if r["kind"] in ("dump", "poke")}, {"pm"})


if __name__ == "__main__":
    unittest.main()


class Options(unittest.TestCase):
    def test_an_option_after_the_program_is_refused_not_passed_on(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = dosbox.main(["run", "GAME/MAIN.EXE", "--mount", ".", "--seconds", "30"])
        self.assertEqual(code, 2)
        self.assertIn("--mount, --seconds after PROGRAM", err.getvalue())

    def test_the_programs_own_options_are_passed_on(self) -> None:
        p = dosbox.parser()
        args = p.parse_args(["run", "--seconds", "5", "MAIN.EXE", "-nosound", "/m"])
        self.assertEqual(dosbox.misplaced_options(args, p), [])
        self.assertEqual(args.args, ["-nosound", "/m"])
