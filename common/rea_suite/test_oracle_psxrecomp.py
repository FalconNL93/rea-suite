"""The oracle's PSXRecomp back end against an in-process stand-in for the runtime's debug server:
one JSON line a connection, a frame counter that advances, snapshot slots recorded every frame."""

from __future__ import annotations

import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from rea_suite import oracle, oracle_psxrecomp


class StandIn:
    """The commands the back end uses, as the runtime answers them."""

    def __init__(self):
        self.frame = 0
        self.ram = bytearray(0x1000)
        self.slots = [0] * 4
        self.history: dict[int, dict[int, bytes]] = {}

    def tick(self) -> None:  # the end of a frame: the guest wrote, the runtime recorded
        self.ram[0x100] = self.frame & 0xFF
        self.history[self.frame] = {
            a: bytes(self.ram[a & 0xFFF : (a & 0xFFF) + 128]) for a in self.slots if a
        }
        self.frame += 1

    def answer(self, request: dict) -> dict:
        cmd = request["cmd"]
        if cmd == "ping":
            return {"ok": True, "pong": True}
        if cmd == "frame":
            for _ in range(5):
                self.tick()
            return {"ok": True, "frame": self.frame}
        if cmd == "read_ram":
            at = int(request["addr"], 16) & 0xFFF
            return {"ok": True, "hex": bytes(self.ram[at : at + request["len"]]).hex()}
        if cmd == "set_snapshot":
            self.slots[request["slot"]] = int(request["addr"], 16)
            return {"ok": True}
        if cmd == "read_frame_ram":
            addr, frame = int(request["addr"], 16), request["frame"]
            for base, data in self.history.get(frame, {}).items():
                if base <= addr and addr + request["len"] <= base + 128:
                    return {
                        "ok": True,
                        "hex": data[addr - base : addr - base + request["len"]].hex(),
                    }
            return {"ok": False, "error": "address not in any snapshot region for this frame"}
        return {"ok": False, "error": f"unknown command {cmd}"}


class Server:
    def __init__(self, standin: StandIn):
        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline()
                self.wfile.write((json.dumps(standin.answer(json.loads(line))) + "\n").encode())

        self.server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class PsxRecomp(unittest.TestCase):
    def setUp(self) -> None:
        self.standin = StandIn()
        self.server = Server(self.standin)
        self.addCleanup(self.server.close)
        self.target = oracle_psxrecomp.PsxRecompTarget("127.0.0.1", self.server.port, 5)
        self.addCleanup(lambda: setattr(oracle_psxrecomp, "POLL", 0.2))
        oracle_psxrecomp.POLL = 0.0

    def test_frame_triggers_read_the_frame_history(self) -> None:
        regions = {"counter": oracle.Region("counter", oracle.parse_address("80000100"), 1)}
        syncs = [oracle.parse_sync_option(f"f{n}@frame={n}", regions, []) for n in (12, 30)]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.jsonl"
            writer = oracle.SequenceWriter(path, self.target.producer)
            outcome = oracle.run_syncs(self.target, syncs, writer, seconds=30)
            writer.close()
            _, points = oracle.read_sequence(path)
        self.assertEqual(outcome.ended, "done")
        # the value as it was at the end of each frame, not when the driver looked
        self.assertEqual([p.entries[0].data for p in points], [bytes([12]), bytes([30])])
        self.assertEqual(self.standin.slots, [0, 0, 0, 0])  # close() clears the slots it set

    def test_the_command_records_a_back_end_error_and_goes_on(self) -> None:
        # bin/rea-suite runs oracle.py as a script: a back end's TargetError must still be caught
        answer = self.standin.answer
        self.standin.answer = lambda r: (
            {"ok": False, "error": "frame not in buffer"}
            if r["cmd"] == "read_frame_ram"
            else answer(r)
        )
        with tempfile.TemporaryDirectory() as d:
            regions = Path(d) / "r.toml"
            regions.write_text(
                '[regions.c]\naddr = "0x80000100"\nlen = 1\n\n'
                '[[sync]]\nname = "f"\nat = "frame=3"\n\n[[sync]]\nname = "live"\nat = "t=0"\n'
            )
            script = Path(oracle.__file__)
            done = subprocess.run(
                [sys.executable, str(script), "run", "--target", f"psxrecomp://127.0.0.1:{self.server.port}",
                 "--regions", str(regions), "--seconds", "20", "--sequence", str(Path(d) / "s.jsonl")],
                check=False, capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONPATH": str(script.parents[1])},
            )  # fmt: skip
            self.assertEqual(done.returncode, 0, done.stderr)
            _, points = oracle.read_sequence(Path(d) / "s.jsonl")
        self.assertEqual([p.sync for p in points], ["live", "f"])
        self.assertIn("PSX_NO_DEBUG_TOOLS", points[1].entries[0].error)  # why, not only what

    def test_no_breakpoints_and_the_history_limits(self) -> None:
        with self.assertRaises(oracle.TargetError):
            self.target.set_breakpoint(0x80010000)
        big = [oracle.Region(f"r{i}", oracle.parse_address(f"8000{i}000"), 16) for i in range(5)]
        with self.assertRaises(oracle.TargetError):
            self.target.watch(big)
        with self.assertRaises(oracle.TargetError):
            self.target.watch([oracle.Region("wide", oracle.parse_address("80000000"), 256)])
        self.assertEqual(self.target.read(0x80000100, 2), b"\0\0")

    def test_a_target_without_a_history_refuses_frame_triggers(self) -> None:
        class NoFrames(oracle.EmulatorTarget):
            producer = "gdb"

            def connect(self):
                return oracle.Stop("signal", 0)

            def set_breakpoint(self, address, hardware=False): ...
            def clear_breakpoint(self, address, hardware=False): ...
            def resume(self, timeout):
                return oracle.Stop("exited")

            def read(self, address, length):
                return b""

            def close(self): ...

        regions = {"a": oracle.Region("a", oracle.parse_address("0"), 1)}
        syncs = [oracle.parse_sync_option("f@frame=1", regions, [])]
        with tempfile.TemporaryDirectory() as d:
            writer = oracle.SequenceWriter(Path(d) / "s.jsonl", "x")
            with self.assertRaises(ValueError):
                oracle.run_syncs(NoFrames(), syncs, writer, seconds=5)
            writer.close()


if __name__ == "__main__":
    unittest.main()
