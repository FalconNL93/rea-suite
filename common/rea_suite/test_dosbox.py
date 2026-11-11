"""`rea-suite dosbox`: DOSBox-X's log lines as records, the debugger's answers, interrupt records and
the stop handling against a stand-in debugger. The runs against a real DOSBox-X (a .COM and a DPMI
client assembled with nasm) are opt-in: REA_DOSBOX_INTEGRATION=1, with DOSBox-X installed
(component `dos`) or REA_DOSBOX_X naming one with its debugger."""

from __future__ import annotations

import argparse
import contextlib
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
            (self.memdir / dosbox.MEMFILE).write_bytes(code)
        return ["DEBUG: ok"]

    def stop(self, t: dosbox.Tracer, state: dict, code: bytes) -> bool:
        self.current = (state, code)
        return t.stop(state)


def tracer(fake: FakeDebugger, tmp: Path, **options) -> tuple[dosbox.Tracer, list[dict]]:
    records: list[dict] = []
    out = dosbox.Output(None, quiet=True)
    out.write = records.append  # type: ignore[method-assign]
    args = argparse.Namespace(ints="21,31,33,10", returns=False, nested=False, **options)
    t = dosbox.Tracer(fake, out, tmp, args)  # type: ignore[arg-type]
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
        self.assertEqual(status, 0, records[-3:])
        return records

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
