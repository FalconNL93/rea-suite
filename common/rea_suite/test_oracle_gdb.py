"""The oracle's GDB back end against an in-process stand-in stub: packets, acknowledgments and
no-ack mode, run-length answers, memory in chunks, Z0/Z1 breakpoints and stepping over one, stop
replies with and without the PC, the 0x03 stop at the time limit, the program's end, and
`rea-suite oracle run` and `compare` end to end. No emulator runs here; the real stubs' behavior
was read from their source (oracle_gdb.py's docstring)."""

from __future__ import annotations

import contextlib
import io
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from rea_suite import oracle
from rea_suite import oracle_gdb as gdb


class FakeStub(threading.Thread):
    """A GDB stub over a pretend CPU: `program` is the PCs it runs through in order, `writes` the
    memory each PC changes when it runs; past the end it exits (W00), or with `spin` loops until
    0x03 stops it."""

    def __init__(
        self,
        arch: gdb.Arch,
        program: list[int],
        writes: dict[int, tuple[int, bytes]] | None = None,
        memory_base: int = 0x80000000,
        memory_size: int = 0x4000,
        no_ack: bool = True,
        pc_in_stop: bool = True,
        rle: bool = False,
        packet_size: int = 0x400,
        spin: bool = False,
        detach: bool = True,
    ):
        super().__init__(daemon=True)
        self.arch, self.program, self.writes = arch, program, writes or {}
        self.base = memory_base
        self.memory = bytearray(memory_size)
        self.no_ack_offered, self.pc_in_stop, self.rle = no_ack, pc_in_stop, rle
        self.packet_size, self.spin, self.detach = packet_size, spin, detach
        self.index = 0
        self.ack = True
        self.breakpoints: set[tuple[str, int]] = set()
        self.log: list[str] = []
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.reads: list[int] = []

    @property
    def pc(self) -> int:
        return self.program[min(self.index, len(self.program) - 1)]

    def reg_hex(self, value: int) -> str:
        return value.to_bytes(self.arch.size, self.arch.endian).hex()

    def stop(self, signal: int = 5) -> str:
        if self.pc_in_stop:
            return f"T{signal:02x}{self.arch.pc:02x}:{self.reg_hex(self.pc)};thread:1;"
        return f"S{signal:02x}"

    def send(self, conn: socket.socket, text: str) -> None:
        body = text.encode()
        if self.rle:  # compress runs of 4 to 97 equal characters, as gdbserver does
            out, i = bytearray(), 0
            while i < len(body):
                j = i
                while j < len(body) and body[j] == body[i] and j - i < 97:
                    j += 1
                run = j - i
                n = run - 1 + 29
                if run >= 4 and chr(n) not in "#$+-":
                    out += bytes((body[i], 0x2A, n))
                else:
                    out += body[i:j]
                i = j
            body = bytes(out)
        conn.sendall(gdb.frame(body) if not self.rle else b"$" + body + b"#" + gdb.checksum(body))

    def armed(self, pc: int) -> bool:
        return any(addr == pc for _, addr in self.breakpoints)

    def execute(self) -> None:
        if self.pc in self.writes:
            addr, data = self.writes[self.pc]
            off = addr - self.base
            self.memory[off : off + len(data)] = data
        self.index += 1

    def run_on(self, conn: socket.socket) -> None:
        if self.armed(self.pc):  # a real CPU traps at once on a breakpoint it stands on
            self.send(conn, self.stop())
            return
        while True:
            self.execute()
            if self.index >= len(self.program):
                if self.spin:
                    self.index = len(self.program) - 1
                    conn.settimeout(None)
                    while (byte := conn.recv(1)) != b"\x03":
                        if not byte:
                            return
                    self.send(conn, self.stop(2))
                    return
                self.send(conn, "W00")
                return
            if self.armed(self.pc):
                self.send(conn, self.stop())
                return

    def answer(self, conn: socket.socket, packet: str) -> None:
        self.log.append(packet)
        kind = packet[:1]
        if packet.startswith("qSupported"):
            features = f"PacketSize={self.packet_size:x};swbreak+;hwbreak+"
            self.send(conn, features + (";QStartNoAckMode+" if self.no_ack_offered else ""))
        elif packet == "QStartNoAckMode":
            self.send(conn, "OK")
            self.ack = False
        elif packet == "?":
            self.send(conn, self.stop(5))
        elif kind == "p":
            if int(packet[1:], 16) == self.arch.pc:
                self.send(conn, self.reg_hex(self.pc))
            else:
                self.send(conn, "E01")
        elif kind == "g":
            regs = bytearray(self.arch.g_offset + self.arch.size)
            regs[self.arch.g_offset :] = self.pc.to_bytes(self.arch.size, self.arch.endian)
            self.send(conn, regs.hex())
        elif kind == "m":
            addr, size = (int(v, 16) for v in packet[1:].split(","))
            self.reads.append(size)
            off = addr - self.base
            if off < 0 or off + size > len(self.memory) or size * 2 + 4 > self.packet_size:
                self.send(conn, "E14")
            else:
                self.send(conn, self.memory[off : off + size].hex())
        elif kind in "Zz" and packet[1:2] in ("0", "1"):
            addr_value = int(packet.split(",")[1], 16)
            if kind == "Z":
                self.breakpoints.add((packet[1], addr_value))
            else:
                self.breakpoints.discard((packet[1], addr_value))
            self.send(conn, "OK")
        elif kind == "c":
            self.run_on(conn)
        elif kind == "s":
            self.execute()
            if self.index >= len(self.program):
                self.send(conn, "W00")
            else:
                self.send(conn, self.stop())
        elif packet == "D":
            self.send(conn, "OK" if self.detach else "")
        else:
            self.send(conn, "")

    def run(self) -> None:
        with self.server:
            conn, _ = self.server.accept()
        buf = bytearray()
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                buf += data
                while True:
                    while buf[:1] in (b"+", b"-", b"\x03"):
                        del buf[:1]
                    end = buf.find(b"#")
                    if not buf.startswith(b"$") or end < 0 or len(buf) < end + 3:
                        break
                    body = bytes(buf[1:end])
                    del buf[: end + 3]
                    if self.ack:
                        conn.sendall(b"+")
                    self.answer(conn, gdb.unpack(body).decode())
                    if self.log[-1] == "D" and self.detach:
                        return


PPC = gdb.ARCHES["ppc"]
MIPS = gdb.ARCHES["mips"]


def target(stub: FakeStub, arch: gdb.Arch, timeout: float = 5.0) -> gdb.GdbTarget:
    stub.start()
    return gdb.GdbTarget("127.0.0.1", stub.port, arch, timeout)


class Packets(unittest.TestCase):
    def test_framing_escapes_and_run_lengths(self) -> None:
        self.assertEqual(gdb.frame(b"m0,4"), b"$m0,4#fd")
        self.assertEqual(gdb.frame(b"a#b"), b"$a}\x03b#" + gdb.checksum(b"a}\x03b"))
        self.assertEqual(gdb.unpack(b"a}\x03b"), b"a#b")
        self.assertEqual(gdb.unpack(b"0* "), b"0" * 4)  # ' ' is 32: three more
        self.assertEqual(gdb.unpack(b"ab"), b"ab")

    def test_stop_replies(self) -> None:
        stop = gdb.stop_reply(b"T0540:80003100;01:8000ff00;", PPC)
        self.assertEqual((stop.reason, stop.pc), ("signal", 0x80003100))
        stop = gdb.stop_reply(b"T0525:00100080;swbreak:;", MIPS)  # little-endian 0x80001000
        self.assertEqual(stop.pc, 0x80001000)
        self.assertEqual(gdb.stop_reply(b"S05", MIPS).pc, None)
        self.assertEqual(gdb.stop_reply(b"W00", MIPS).reason, "exited")
        with self.assertRaises(oracle.TargetError):
            gdb.stop_reply(b"OK", MIPS)

    def test_architectures_and_their_names(self) -> None:
        self.assertIs(gdb.arch("Gekko"), PPC)
        self.assertIs(gdb.arch("r3000"), MIPS)
        self.assertEqual(gdb.arch("xemu").pc, 8)
        self.assertEqual(gdb.arch("arm9").pc, 15)
        for bad in (None, "z80"):
            with self.assertRaises(ValueError):
                gdb.arch(bad)


class Target(unittest.TestCase):
    def test_no_ack_mode_breakpoints_and_memory(self) -> None:
        stub = FakeStub(PPC, [0x80003000, 0x80003004, 0x80003008, 0x8000300C],
                        writes={0x80003004: (0x80000010, b"\x12\x34\x56\x78")})  # fmt: skip
        t = target(stub, PPC)
        stop = t.connect()
        self.assertEqual(stop.pc, 0x80003000)
        self.assertFalse(t.conn.ack)  # type: ignore[union-attr]
        t.set_breakpoint(0x80003008)
        t.set_breakpoint(0x8000300C, hardware=True)
        stop = t.resume(5)
        self.assertEqual((stop.reason, stop.pc), ("break", 0x80003008))
        self.assertEqual(t.read(0x80000010, 4), b"\x12\x34\x56\x78")
        stop = t.resume(5)  # steps over the breakpoint it stands on
        self.assertEqual((stop.reason, stop.pc), ("break", 0x8000300C))
        self.assertIn("Z1,8000300c,4", stub.log)
        self.assertIn("s", stub.log)
        self.assertEqual(t.resume(5).reason, "exited")
        t.close()
        stub.join(5)

    def test_ack_mode_run_lengths_and_the_pc_by_p(self) -> None:
        stub = FakeStub(MIPS, [0x80010000, 0x80010004, 0x80010008],
                        no_ack=False, pc_in_stop=False, rle=True)  # fmt: skip
        t = target(stub, MIPS)
        self.assertEqual(t.connect().pc, 0x80010000)
        self.assertTrue(t.conn.ack)  # type: ignore[union-attr]
        self.assertEqual(t.read(0x80000000, 64), bytes(64))  # zeros come run-length encoded
        t.set_breakpoint(0x80010008)
        self.assertEqual(t.resume(5).pc, 0x80010008)
        self.assertIn("p25", stub.log)
        t.close()
        stub.join(5)

    def test_memory_comes_in_packet_sized_chunks_and_errors_are_named(self) -> None:
        stub = FakeStub(PPC, [0x80003000], packet_size=0x100)
        t = target(stub, PPC)
        t.connect()
        self.assertEqual(len(t.read(0x80000000, 0x300)), 0x300)
        self.assertTrue(all(size * 2 + 4 <= 0x100 for size in stub.reads))
        with self.assertRaises(oracle.TargetError) as caught:
            t.read(0x90000000, 4)
        self.assertIn("E14", str(caught.exception))
        t.close()
        stub.join(5)

    def test_the_time_limit_stops_the_cpu_with_0x03(self) -> None:
        stub = FakeStub(PPC, [0x80003000, 0x80003004], spin=True, detach=False)
        t = target(stub, PPC)
        t.connect()
        stop = t.resume(0.2)
        self.assertEqual((stop.reason, stop.pc), ("timeout", 0x80003004))
        t.close()  # no detach: it continues the CPU instead
        stub.join(5)
        self.assertEqual(stub.log[-2:], ["D", "c"])

    def test_no_stub_is_a_target_error(self) -> None:
        with socket.create_server(("127.0.0.1", 0)) as s:
            port = s.getsockname()[1]
        with self.assertRaises(oracle.TargetError):
            gdb.GdbTarget("127.0.0.1", port, PPC, 1).connect()


REGIONS = """
[regions.score]
addr = "0x80000010"
len = 4
type = "u32"
endian = "big"

[regions.table]
addr = "80000100"
len = 0x20

[[sync]]
name = "boot"
at = "start"

[[sync]]
name = "frame"
at = "pc=80003008"
repeat = true
"""


class Command(unittest.TestCase):
    def run_oracle(self, stub: FakeStub, tmp: Path, name: str, *extra: str) -> tuple[int, str]:
        stub.start()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = oracle.main(["--caller-cwd", str(tmp), "run",
                                  "--target", f"gdb://127.0.0.1:{stub.port}", "--arch", "gekko",
                                  "--regions", "r.toml", "--sequence", name, *extra])  # fmt: skip
        stub.join(5)
        return status, out.getvalue()

    def test_run_writes_a_sequence_and_compare_finds_the_difference(self) -> None:
        program = [0x80003000, 0x80003004, 0x80003008, 0x80003004, 0x80003008, 0x8000300C]
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "r.toml").write_text(REGIONS)
            one = FakeStub(PPC, program, writes={0x80003004: (0x80000010, b"\0\0\0\x07")})
            status, out = self.run_oracle(one, tmp, "a.jsonl", "--sync", "late@pc=8000300C@score")
            self.assertEqual(status, 0, out)
            _, points = oracle.read_sequence(tmp / "a.jsonl")
            self.assertEqual([(p.sync, p.hit) for p in points],
                             [("boot", 1), ("frame", 1), ("frame", 2), ("late", 1)])  # fmt: skip
            self.assertEqual(points[1].entries[0].data, b"\0\0\0\x07")
            self.assertEqual(points[1].entries[0].endian, "big")
            two = FakeStub(PPC, program, writes={0x80003004: (0x80000010, b"\0\0\0\x08")})
            self.run_oracle(two, tmp, "b.jsonl", "--sync", "late@pc=8000300C@score")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = oracle.main(["--caller-cwd", str(tmp), "compare", "a.jsonl", "b.jsonl"])
            self.assertEqual(status, 1)
            self.assertIn("sync point 1 (frame #1), region 'score': offset 0x3", out.getvalue())
            self.assertIn("u32 [0] = 7", out.getvalue())  # read big-endian

    def test_a_sync_point_that_never_comes_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "r.toml").write_text(REGIONS)
            stub = FakeStub(PPC, [0x80003000, 0x80003004])
            status, out = self.run_oracle(stub, tmp, "a.jsonl")
            self.assertEqual(status, 1)
            self.assertIn('"never": ["frame"]', out)
            self.assertIn('"ended": "exited W00"', out)


if __name__ == "__main__":
    unittest.main()
