"""SteamStub detection on synthetic PEs: a plain one, a wrapped one and a .bind alone."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rea_suite import samples, steamstub

PLAIN = bytes(i % 7 for i in range(0x800))  # low entropy, as compiled code is
RANDOM = b"".join(hashlib.sha256(bytes([i, j])).digest() for i in range(4) for j in range(16))


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = steamstub.main(list(argv))
    return code, out.getvalue()


class SteamStub(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, name: str, data: bytes) -> str:
        (self.root / name).write_bytes(data)
        return str(self.root / name)

    def test_a_plain_executable_has_none(self) -> None:
        exe = self.write(
            "plain.exe",
            samples.pe(
                [(".text", PLAIN), (".rdata", bytes(64))],
                timestamp=0x3A000000,
                debug_timestamp=0x3A000000,
            ),
        )
        code, out = run(exe)
        self.assertEqual(code, 0, out)
        self.assertIn(": none  sha256 ", out)

    def test_a_wrapped_executable_shows_every_sign(self) -> None:
        data = samples.pe(
            [(".text", RANDOM), (".rdata", bytes(64)), (".bind", PLAIN[:0x100])],
            entry=0x3010,
            timestamp=0xF0000000,  # 2097
            debug_timestamp=0x3A000000,
        )
        exe = self.write("game.exe", data)
        code, out = run(exe, "--json")
        self.assertEqual(code, 1)
        found = json.loads(out)
        self.assertEqual(found["verdict"], "steamstub")
        self.assertEqual(found["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(
            found["signs"],
            [
                ".bind section",
                "entry point in .bind",
                "code section(s) .text near random (encrypted)",
                "header timestamp differs from the debug directory's",
                "header timestamp in the future",
            ],
        )

    def test_a_bind_section_alone_is_possible(self) -> None:
        exe = self.write(
            "bind.exe", samples.pe([(".text", PLAIN), (".bind", PLAIN[:0x100])], entry=0x1000)
        )
        code, out = run(exe)
        self.assertEqual(code, 1)
        self.assertIn(": possible", out)
        self.assertIn(".bind section", out)
        self.assertNotIn("entry point", out)

    def test_x64_executables_are_read_too(self) -> None:
        exe = self.write(
            "x64.exe",
            samples.pe([(".text", PLAIN), (".bind", PLAIN[:0x100])], entry=0x2000, x64=True),
        )
        code, out = run(exe, "--json")
        self.assertEqual((code, json.loads(out)["machine"]), (1, "0x8664"))

    def test_a_file_that_is_no_pe_exits_2(self) -> None:
        self.assertEqual(run(self.write("notes.txt", b"hello"))[0], 2)


if __name__ == "__main__":
    unittest.main()
