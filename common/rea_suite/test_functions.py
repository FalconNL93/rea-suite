"""Function index and gate: a flat Xbox 360 style image under the PPC gate's own config, and
x86 PEs mapped through their section table (synthetic samples, no game bytes)."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import functions, samples

BASE = 0x82000000


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            code = functions.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue()


def code_bytes(seed: int, size: int) -> bytes:
    return bytes((seed * 7 + i * 13) & 0xFF for i in range(size))


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def config(self, games: dict) -> str:
        path = self.root / "re" / "functions.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps({"index": "functions.tsv", "games": games}))
        return str(path)

    def rows(self) -> list[str]:
        return (self.root / "re" / "functions.tsv").read_text().splitlines()


class PpcGateConfig(Workspace):
    """The rexglue-sdk PPC gate's config shape: a flat image at a base, codegen's partition."""

    def setUp(self) -> None:
        super().setUp()
        image = code_bytes(1, 0x400)
        (self.root / "xex").mkdir()
        (self.root / "xex" / "default.bin").write_bytes(image)
        part = {"assignments": {"0x82000100": 0, "0x82000200": 0}}
        (self.root / "codegen.partition.json").write_text(json.dumps(part))
        self.image = image
        self.cfg = self.config(
            {
                "sp": {
                    "image": "../xex/default.bin",
                    "base": "0x82000000",
                    "partition": "../codegen.partition.json",
                }
            }
        )

    def test_an_empty_index_exits_2(self) -> None:
        code, out = run(self.cfg, "check")
        self.assertEqual(code, 2)
        self.assertIn("no entries", out)

    def test_add_records_the_head_signature_and_check_passes(self) -> None:
        code, out = run(self.cfg, "add", "sp", "0x82000100", "Net_Send", "sends", "src/net.cpp")
        self.assertEqual(code, 0, out)
        want = hashlib.sha256(self.image[0x100:0x120]).hexdigest()[:12]
        header, entry = self.rows()
        self.assertEqual(header.split("\t"), functions.FIELDS)
        fields = entry.split("\t")
        self.assertEqual(fields[:6], ["sp", "0x82000100", "Net_Send", "sends", "src/net.cpp", want])
        self.assertRegex(fields[6], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(run(self.cfg, "check"), (0, "1/1 entries match\n"))

    def test_check_fails_when_the_bytes_change(self) -> None:
        run(self.cfg, "add", "sp", "82000200", "Net_Recv", "receives")
        changed = bytearray(self.image)
        changed[0x210] ^= 0xFF
        (self.root / "xex" / "default.bin").write_bytes(bytes(changed))
        code, out = run(self.cfg, "check")
        self.assertEqual(code, 1)
        self.assertIn("FAIL  sp 0x82000200 Net_Recv: signature differs", out)

    def test_add_refuses_an_address_where_no_function_starts(self) -> None:
        code, out = run(self.cfg, "add", "sp", "0x82000104", "Mid", "inside a function")
        self.assertEqual(code, 1)
        self.assertIn("no function starts there", out)
        self.assertFalse((self.root / "re" / "functions.tsv").exists())

    def test_find_matches_name_text_place_and_address(self) -> None:
        run(self.cfg, "add", "sp", "0x82000100", "Net_Send", "sends a packet", "src/net.cpp")
        for text in ("net_send", "PACKET", "net.cpp", "82000100"):
            self.assertIn("Net_Send", run(self.cfg, "find", text)[1], text)
        self.assertEqual(run(self.cfg, "find", "nothing")[1], "")

    def test_a_tab_in_a_field_is_refused(self) -> None:
        code, out = run(self.cfg, "add", "sp", "0x82000100", "Net_Send", "a\tb")
        self.assertEqual(code, 1)
        self.assertIn("tab", out)

    def test_a_missing_image_names_itself(self) -> None:
        run(self.cfg, "add", "sp", "0x82000100", "Net_Send", "sends")
        (self.root / "xex" / "default.bin").unlink()
        code, out = run(self.cfg, "check")
        self.assertEqual(code, 1)
        self.assertIn("default.bin is missing", out)


class PeImages(Workspace):
    """x86 PEs: addresses map through the section table; body signatures to the next start."""

    def setUp(self) -> None:
        super().setUp()
        self.text = code_bytes(3, 0x300)
        self.exe = self.root / "game" / "Game.exe"
        self.exe.parent.mkdir()
        self.exe.write_bytes(samples.pe([(".text", self.text), (".data", b"data")]))
        entries = "entry\tsize\tname\n00401000\t16\ta\n00401040\t16\tb\n00401100\t16\tc\n"
        (self.root / "re").mkdir()
        (self.root / "re" / "function_entries.tsv").write_text(entries)

    def game(self, **extra) -> dict:
        return {
            "image": "${GAME_DIR:-../game}/Game.exe",
            "entries": "function_entries.tsv",
            **extra,
        }

    def test_head_signatures_read_through_the_section_table(self) -> None:
        cfg = self.config({"pc": self.game()})
        self.assertEqual(run(cfg, "add", "pc", "00401040", "Frame", "one frame")[0], 0)
        want = hashlib.sha256(self.text[0x40:0x60]).hexdigest()[:12]
        self.assertEqual(self.rows()[1].split("\t")[5], want)

    def test_body_signatures_run_to_the_next_entry(self) -> None:
        cfg = self.config({"pc": self.game(signature="body")})
        run(cfg, "add", "pc", "0x401040", "Frame", "one frame")
        want = hashlib.sha256(self.text[0x40:0x100]).hexdigest()[:16]
        self.assertEqual(self.rows()[1].split("\t")[5], want)
        self.assertEqual(run(cfg, "check")[0], 0)

    def test_the_environment_and_image_override_choose_the_executable(self) -> None:
        cfg = self.config({"pc": self.game()})
        other = self.root / "elsewhere"
        other.mkdir()
        (other / "Game.exe").write_bytes(samples.pe([(".text", code_bytes(9, 0x300))]))
        run(cfg, "add", "pc", "0x401000", "Start", "the start")
        self.assertEqual(run(cfg, "check")[0], 0)
        with patch.dict(os.environ, {"GAME_DIR": str(other)}):
            self.assertEqual(run(cfg, "check")[0], 1)
        self.assertEqual(run("--image", f"pc={other / 'Game.exe'}", cfg, "check")[0], 1)

    def test_an_unset_variable_without_a_default_is_named(self) -> None:
        cfg = self.config({"pc": {"image": "${NO_SUCH_GAME_DIR_SET}/Game.exe"}})
        code, out = run(cfg, "add", "pc", "0x401000", "Start", "the start")
        self.assertEqual(code, 1)
        self.assertIn("NO_SUCH_GAME_DIR_SET is not set", out)

    def test_a_body_signature_needs_function_starts(self) -> None:
        cfg = self.config({"pc": {"image": "../game/Game.exe", "signature": "body"}})
        code, out = run(cfg, "add", "pc", "0x401000", "Start", "the start")
        self.assertEqual(code, 1)
        self.assertIn("needs 'entries' or 'partition'", out)

    def test_an_address_outside_the_image_is_refused(self) -> None:
        cfg = self.config({"pc": {"image": "../game/Game.exe"}})
        code, out = run(cfg, "add", "pc", "0x10000", "Low", "below the image")
        self.assertEqual(code, 1)
        self.assertIn("outside the image", out)

    def test_a_legacy_table_converts_and_still_checks(self) -> None:
        cfg = self.config({"pc": self.game(signature="body")})
        # the last function runs to the end of its section, file alignment padding included
        body = hashlib.sha256(self.text[0x100:] + bytes(0x100)).hexdigest()[:16]
        legacy = self.root / "re" / "legacy.tsv"
        legacy.write_text(f"address\tname\thash\twhat\n00401100\tTick\t{body}\tthe tick\n")
        code, out = run(cfg, "convert", "pc", str(legacy))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.rows()[1], f"pc\t0x00401100\tTick\tthe tick\t\t{body}\t")
        self.assertEqual(run(cfg, "check"), (0, "1/1 entries match\n"))

    def test_a_legacy_hash_of_the_wrong_kind_is_refused(self) -> None:
        cfg = self.config({"pc": self.game()})
        legacy = self.root / "re" / "legacy.tsv"
        legacy.write_text("address\tname\thash\twhat\n00401100\tTick\t0123456789abcdef\tx\n")
        code, out = run(cfg, "convert", "pc", str(legacy))
        self.assertEqual(code, 1)
        self.assertIn("not a head signature (12 digits)", out)

    def test_a_flat_file_without_a_base_is_not_taken_for_a_pe(self) -> None:
        (self.root / "game" / "dump.bin").write_bytes(bytes(64))
        cfg = self.config({"pc": {"image": "../game/dump.bin"}})
        code, out = run(cfg, "add", "pc", "0x401000", "Start", "the start")
        self.assertEqual(code, 1)
        self.assertIn("not a PE", out)


if __name__ == "__main__":
    unittest.main()
