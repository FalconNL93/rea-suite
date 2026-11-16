"""`playstation drive` against a fake PSXRecomp debug server: the script format (duke-nukem-ttk's
tools/drive.py's), the commands sent, and a wait that shifts the later steps."""

from __future__ import annotations

import io
import json
import socketserver
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rea_suite import playstation, psx_drive


class FakeServer:
    """One JSON line a connection; RAM byte 0x80000010 turns 0x01 on the third read of it."""

    def __init__(self):
        self.requests: list[tuple[float, dict]] = []
        self.ram = bytearray(0x100)
        self.reads = 0
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                request = json.loads(self.rfile.readline())
                fake.requests.append((time.monotonic(), request))
                self.wfile.write((json.dumps(fake.answer(request)) + "\n").encode())

        self.server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, request: dict) -> dict:
        cmd = request["cmd"]
        if cmd == "read_ram":
            at = int(request["addr"], 16) & 0xFF
            if at == 0x10:
                self.reads += 1
                if self.reads == 3:
                    self.ram[0x10] = 1
            return {"ok": True, "hex": bytes(self.ram[at : at + request["len"]]).hex()}
        if cmd == "write_ram":
            self.ram[int(request["addr"], 16) & 0xFF] = int(request["val"], 16)
            return {"ok": True}
        if cmd == "pad_status":
            return {"ok": True, "buttons": "fff7"}
        if cmd in ("press", "host_key", "host_button", "ping"):
            return {"ok": True}
        if cmd == "host_text":  # as the server: UTF-8, 1 to 255 bytes; "refuse" stands in for SDL2
            size = len(request.get("text", "").encode())
            if 0 < size <= 255 and request["text"] != "refuse":
                return {"id": 1, "ok": True}
            return {"id": 1, "ok": False, "error": "host_text needs 1 to 255 bytes of text"}
        return {"ok": False, "error": f"unknown command {cmd}"}

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


SCRIPT = """\
# the title, then the game's state
0.0 start 30
0.0 host-key Return        # equal times keep the script's order
0.1 write 0x80000020 7f
0.1 wait 0x80000010 01 5
0.2 read 0x80000020 1
0.2 cross+square
0.3 host-button a
0.3 raw {"cmd": "ping"}
"""


class Drive(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeServer()
        self.addCleanup(self.fake.close)
        patcher = patch.object(psx_drive, "POLL", 0.05)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_script_format(self) -> None:
        steps = psx_drive.parse(SCRIPT)
        self.assertEqual(steps[0], (0.0, {"cmd": "press", "buttons": 0xFFF7, "frames": 30}))
        self.assertEqual(steps[1], (0.0, {"cmd": "host_key", "name": "Return"}))
        self.assertEqual(steps[2][1], {"cmd": "write_ram", "addr": "0x80000020", "val": "7f"})
        self.assertEqual(steps[3][1], {"wait": "0x80000010", "value": 1, "timeout": 5.0})
        self.assertEqual(steps[5][1], {"cmd": "press", "buttons": 0x3FFF, "frames": 4})
        for bad in ("1 jump", "1 read 0x80000000", "x start", '1 raw ["ping"]', "1 write 0 100"):
            with self.assertRaises(ValueError, msg=bad):
                psx_drive.parse(bad)

    def test_a_run_sends_the_steps_and_a_wait_shifts_the_rest(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "run.txt").write_text(SCRIPT)
            out = io.StringIO()
            with redirect_stdout(out), patch.dict("os.environ", {"REA_PSXRECOMP_PORT": str(self.fake.port)}):  # fmt: skip
                code = playstation.main(["--caller-cwd", d, "drive", "run.txt"])
        self.assertEqual(code, 0)
        sent = [r["cmd"] for _, r in self.fake.requests]
        self.assertEqual(sent[:3], ["press", "pad_status", "host_key"])
        self.assertEqual(sent.count("read_ram"), 4)  # three polls, then the read step
        self.assertEqual(sent[-4:], ["press", "pad_status", "host_button", "ping"])
        log = out.getvalue()
        self.assertIn("wait 0x80000010 == 0x01: reached", log)
        self.assertIn('"hex": "7f"', log)  # the write landed before the read
        self.assertIn('pad {"ok": true, "buttons": "fff7"}', log)
        # the read at 0.2 s came 0.1 s after the wait ended, not at 0.2 s from the start
        reached = [t for t, r in self.fake.requests if r["cmd"] == "read_ram"][2]
        read_step = [t for t, r in self.fake.requests if r["cmd"] == "read_ram"][3]
        self.assertGreaterEqual(read_step - reached, 0.08)

    def test_host_text_takes_the_rest_of_the_line(self) -> None:
        steps = psx_drive.parse(
            "1 host-text  two  spaces # kept\n2 host-text Ünïcødé ✓\n3 host-text " + "a" * 255
        )
        self.assertEqual(steps[0][1], {"cmd": "host_text", "text": " two  spaces # kept"})
        self.assertEqual(steps[1][1], {"cmd": "host_text", "text": "Ünïcødé ✓"})
        self.assertEqual(len(steps[2][1]["text"]), 255)
        for bad in ("1 host-text", "1 host-text ", "1 host-text " + "a" * 256, "1 host-text " + "é" * 128):  # fmt: skip
            with self.assertRaises(ValueError, msg=bad):
                psx_drive.parse(bad)

    def test_host_text_on_the_wire_and_a_refusal_fails_the_run(self) -> None:
        out = io.StringIO()
        psx_drive.Driver("127.0.0.1", self.fake.port, 5, out).run(
            psx_drive.parse('0 host-text say "hi"\\ ✓\n')
        )
        self.assertEqual(self.fake.requests[-1][1], {"cmd": "host_text", "text": 'say "hi"\\ ✓'})
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "run.txt").write_text("0 host-text refuse\n0.1 host-key Return\n")
            err = io.StringIO()
            with redirect_stderr(err), patch.dict("os.environ", {"REA_PSXRECOMP_PORT": str(self.fake.port)}):  # fmt: skip
                code = psx_drive.main(["run.txt", "--caller-cwd", d])
        self.assertEqual(code, 1)
        self.assertIn("host-text refused", err.getvalue())
        self.assertIn('"ok": false', err.getvalue())
        self.assertEqual(self.fake.requests[-1][1]["cmd"], "host_text")  # Return never sent

    def test_a_wait_that_never_comes_times_out_and_the_run_goes_on(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            psx_drive.Driver("127.0.0.1", self.fake.port, 5, out).run(
                psx_drive.parse("0 wait 0x80000030 02 0.2\n0 host-key K\n")
            )
        self.assertIn("timed out", out.getvalue())
        self.assertEqual(self.fake.requests[-1][1], {"cmd": "host_key", "name": "K"})

    def test_host_button_takes_an_edge(self) -> None:
        steps = psx_drive.parse("1 host-button back down\n2 host-button back up\n3 host-button a")
        self.assertEqual(steps[0][1], {"cmd": "host_button", "name": "back", "down": 1})
        self.assertEqual(steps[1][1], {"cmd": "host_button", "name": "back", "down": 0})
        self.assertEqual(steps[2][1], {"cmd": "host_button", "name": "a"})  # press and release
        for bad in ("1 host-button a held", "1 host-button a Down", "1 host-button a down 4", "1 host-key K down"):  # fmt: skip
            with self.assertRaises(ValueError, msg=bad):
                psx_drive.parse(bad)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "run.txt").write_text("0 host-button a sideways\n")
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as exit_:
                psx_drive.main(["run.txt", "--plan", "--caller-cwd", d])
            self.assertEqual(exit_.exception.code, 2)
            self.assertIn("run.txt:1: host-button takes down or up", err.getvalue())
            (Path(d) / "run.txt").write_text("0 host-button back down\n")
            out = io.StringIO()
            with redirect_stdout(out):
                psx_drive.main(["run.txt", "--plan", "--caller-cwd", d])
        self.assertEqual(
            json.loads(out.getvalue()),
            [{"at": 0.0, "cmd": "host_button", "name": "back", "down": 1}],
        )
        self.assertEqual(self.fake.requests, [])

    def test_a_chord_holds_three_host_buttons_then_lets_go(self) -> None:
        chord = ("back", "leftshoulder", "rightshoulder")
        script = "".join(f"0 host-button {b} down\n" for b in chord)
        script += "".join(f"0.1 host-button {b} up\n" for b in chord)
        out = io.StringIO()
        psx_drive.Driver("127.0.0.1", self.fake.port, 5, out).run(psx_drive.parse(script))
        sent = [r for _, r in self.fake.requests]
        self.assertEqual(
            sent,
            [{"cmd": "host_button", "name": b, "down": 1} for b in chord]
            + [{"cmd": "host_button", "name": b, "down": 0} for b in chord],
        )
        self.assertEqual(out.getvalue().count('"ok": true'), 6)

    def test_plan_and_a_missing_port(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "run.txt").write_text(SCRIPT)
            out = io.StringIO()
            with redirect_stdout(out):
                psx_drive.main(["run.txt", "--plan", "--caller-cwd", d])
            self.assertEqual(json.loads(out.getvalue())[0]["cmd"], "press")
            with patch.dict("os.environ", {}, clear=True), self.assertRaises(SystemExit):
                psx_drive.main(["run.txt", "--caller-cwd", d])
        self.assertEqual(self.fake.requests, [])


if __name__ == "__main__":
    unittest.main()
