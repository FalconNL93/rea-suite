"""The Frida runner and the passive observer. The message mapping is a unit test; the observer
runs against a real process only with REA_FRIDA_INTEGRATION=1 (Linux or macOS: it spawns a
Python that calls getenv through ctypes)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from rea_suite import frida_run

OBSERVER = Path(__file__).resolve().parents[1] / "frida" / "observer.js"
TARGET = """
import ctypes, time
libc = ctypes.CDLL(None)
libc.getenv.restype = ctypes.c_char_p
time.sleep(0.3)
for _ in range(3):
    libc.getenv(b"REA_FRIDA_A"); libc.getenv(b"REA_FRIDA_B"); time.sleep(0.05)
"""


class Messages(unittest.TestCase):
    def test_sends_become_lines_and_errors_fail_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.jsonl"
            log = frida_run.Log(path, quiet=True)
            log.message({"type": "send", "payload": {"kind": "call", "target": "f"}}, None)
            log.message({"type": "send", "payload": 7}, b"\x01\x02")
            log.message({"type": "error", "description": "boom", "stack": "at x"}, None)
            lines = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual([r.get("kind") for r in lines], ["call", None, "script-error"])
        self.assertEqual((lines[1]["payload"], lines[1]["data"]), (7, "0102"))
        self.assertTrue(all("t" in r for r in lines))
        self.assertTrue(log.failed)


@unittest.skipUnless(os.environ.get("REA_FRIDA_INTEGRATION"), "spawns a process under Frida")
class Observer(unittest.TestCase):
    def test_change_mode_groups_and_reads_arguments_and_results(self) -> None:
        config = {
            "interval_ms": 0,
            "targets": [
                {
                    "name": "getenv",
                    "export": ["libc.so.6!getenv", "libsystem_c.dylib!getenv"],
                    "mode": "change",
                    "reads": [
                        {"as": "variable", "from": "arg0", "type": "utf8"},
                        {"as": "value", "from": "result", "type": "utf8"},
                    ],
                    "group": "variable",
                    "format": "{variable}={value}",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "target.py"
            script.write_text(TARGET)
            log = Path(tmp) / "log.jsonl"
            env = {"REA_FRIDA_A": "one", "REA_FRIDA_B": "two"}
            old = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = frida_run.main(
                        [str(OBSERVER), "--config-json", json.dumps(config), "--log", str(log),
                         "--quiet", "--seconds", "20", "--spawn", sys.executable, str(script)]
                    )  # fmt: skip
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k)
                    else:
                        os.environ[k] = v
            records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(code, 0, records)
        texts = [r["text"] for r in records if r.get("kind") == "call" and "REA_FRIDA" in r["text"]]
        # three calls each, but only the first per variable is a change
        self.assertEqual(texts, ["REA_FRIDA_A=one", "REA_FRIDA_B=two"])


if __name__ == "__main__":
    unittest.main()
