"""The oracle's PPSSPP back end against an in-process stand-in for PPSSPP's WebSocket debugger: the
handshake, masked frames both ways, tickets, breakpoints, stepping events, base64 memory, the stop
at the time limit, and `rea-suite oracle run` end to end. PPSSPP itself is not run here."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from rea_suite import oracle
from rea_suite import oracle_ppsspp as pp


class FakePpsspp(threading.Thread):
    """PPSSPP's debugger over a pretend CPU running through `program`; past the end it runs on
    until asked to stop (cpu.stepping)."""

    def __init__(self, program: list[int], memory: dict[int, bytes], writes=None):
        super().__init__(daemon=True)
        self.program, self.memory, self.writes = program, memory, writes or {}
        self.index = 0
        self.breakpoints: set[int] = set()
        self.events: list[str] = []
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.protocol = ""

    def frame(self, conn, text: str) -> None:
        data = text.encode()
        head = bytes((0x81,)) + (bytes((len(data),)) if len(data) < 126 else
                                 bytes((126,)) + struct.pack(">H", len(data)))  # fmt: skip
        conn.sendall(head + data)

    def message(self, conn, buf: bytearray) -> dict | None:
        while True:
            if len(buf) >= 2:
                n, at = buf[1] & 0x7F, 2
                if n == 126:
                    n, at = struct.unpack(">H", bytes(buf[2:4]))[0], 4
                if len(buf) >= at + 4 + n:
                    assert buf[1] & 0x80, "a client frame is masked"
                    opcode = buf[0] & 0x0F
                    mask = buf[at : at + 4]
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(buf[at + 4 : at + 4 + n]))
                    del buf[: at + 4 + n]
                    if opcode == 0x8:
                        return None
                    return json.loads(payload)
            data = conn.recv(4096)
            if not data:
                return None
            buf += data

    def stepping(self, conn) -> None:
        self.frame(conn, json.dumps({"event": "cpu.stepping", "pc": self.program[self.index],
                                     "ticks": 1}))  # fmt: skip

    def run(self) -> None:
        with self.server:
            conn, _ = self.server.accept()
        with conn:
            head = b""
            while b"\r\n\r\n" not in head:
                head += conn.recv(4096)
            lines = head.decode().split("\r\n")
            headers = {
                k.lower(): v.strip() for k, _, v in (h.partition(":") for h in lines[1:] if h)
            }
            self.protocol = headers.get("sec-websocket-protocol", "")
            accept = base64.b64encode(
                hashlib.sha1((headers["sec-websocket-key"] + pp.GUID).encode()).digest()
            ).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                          f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode())  # fmt: skip
            buf = bytearray(head.partition(b"\r\n\r\n")[2])
            stepping = False
            while (m := self.message(conn, buf)) is not None:
                event, ticket = m["event"], m.get("ticket")
                self.events.append(event)
                reply = {"event": event, "ticket": ticket}
                if event == "version":
                    reply.update(name="PPSSPP", version="v1.20.4")
                elif event == "cpu.status":
                    reply.update(stepping=stepping, paused=False, pc=self.program[self.index])
                elif event == "cpu.stepping":
                    stepping = True
                    self.frame(conn, json.dumps({"event": "log", "message": "noise"}))
                    self.stepping(conn)
                    continue
                elif event == "cpu.resume":
                    stepping = False
                    self.frame(conn, json.dumps({"event": "cpu.resume"}))
                    while self.index + 1 < len(self.program):
                        if self.program[self.index] in self.writes:
                            addr, data = self.writes[self.program[self.index]]
                            self.memory[addr] = data
                        self.index += 1
                        if self.program[self.index] in self.breakpoints:
                            stepping = True
                            self.stepping(conn)
                            break
                    continue
                elif event == "cpu.breakpoint.add":
                    self.breakpoints.add(m["address"])
                elif event == "cpu.breakpoint.remove":
                    self.breakpoints.discard(m["address"])
                elif event == "memory.read":
                    data = self.memory.get(m["address"])
                    if data is None:
                        reply = {"event": "error", "message": "Invalid address", "ticket": ticket}
                    else:
                        reply["base64"] = base64.b64encode(data[: m["size"]]).decode()
                self.frame(conn, json.dumps(reply))


REGIONS = """
[regions.lives]
addr = "0x08900000"
len = 4
type = "u32"

[[sync]]
name = "loop"
at = "pc=08804010"
repeat = true
"""


class Target(unittest.TestCase):
    def test_breakpoints_memory_and_the_time_limit(self) -> None:
        fake = FakePpsspp([0x08804000, 0x08804010, 0x08804020], {0x08900000: b"\x03\0\0\0"})
        fake.start()
        t = pp.PpssppTarget("127.0.0.1", fake.port, 5)
        self.assertEqual(t.connect().pc, 0x08804000)
        self.assertEqual(fake.protocol, "debugger.ppsspp.org")
        t.set_breakpoint(0x08804010)
        stop = t.resume(5)
        self.assertEqual((stop.reason, stop.pc), ("break", 0x08804010))
        self.assertEqual(t.read(0x08900000, 4), b"\x03\0\0\0")
        with self.assertRaises(oracle.TargetError) as caught:
            t.read(0x1000, 4)
        self.assertIn("Invalid address", str(caught.exception))
        stop = t.resume(0.2)  # runs on past the end: stopped at the limit
        self.assertEqual((stop.reason, stop.pc), ("timeout", 0x08804020))
        t.close()
        fake.join(5)
        self.assertEqual(fake.events[:3], ["version", "cpu.status", "cpu.stepping"])
        self.assertEqual(fake.events[-2:], ["cpu.breakpoint.remove", "cpu.resume"])

    def test_oracle_run_end_to_end(self) -> None:
        program = [0x08804000, 0x08804010, 0x08804004, 0x08804010, 0x08804020]
        fake = FakePpsspp(program, {0x08900000: b"\x03\0\0\0"},
                          writes={0x08804004: (0x08900000, b"\x02\0\0\0")})  # fmt: skip
        fake.start()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "r.toml").write_text(REGIONS)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = oracle.main(["--caller-cwd", d, "run", "--target",
                                      f"ppsspp://127.0.0.1:{fake.port}", "--regions", "r.toml",
                                      "--sequence", "s.jsonl", "--seconds", "1"])  # fmt: skip
            fake.join(5)
            self.assertEqual(status, 0, out.getvalue())
            _, points = oracle.read_sequence(Path(d, "s.jsonl"))
        self.assertEqual([p.entries[0].data for p in points], [b"\x03\0\0\0", b"\x02\0\0\0"])


if __name__ == "__main__":
    unittest.main()
