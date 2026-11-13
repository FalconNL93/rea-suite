"""text.printable: a target's strings print as text, never as terminal control or hidden
characters, and never without bound; the readers that print them use it."""

from __future__ import annotations

import argparse
import contextlib
import io
import struct
import unittest
from pathlib import Path

from rea_suite import peresources, rmdp
from rea_suite.text import decoded, printable


class PrintableTests(unittest.TestCase):
    def test_terminal_escapes_and_control_bytes_show_as_text(self) -> None:
        self.assertEqual(printable("\x1b[2J\x1b]0;owned\x07ok"), "\\x1b[2J\\x1b]0;owned\\x07ok")
        self.assertEqual(printable("a\0b\x7f\x9bc"), "a\\x00b\\x7f\\x9bc")
        self.assertEqual(printable("one\ntwo\r\tthree"), "one\\ntwo\\r\\tthree")

    def test_hidden_and_reordering_characters_are_escaped(self) -> None:
        self.assertEqual(printable("abc\u202edcba\u200b\u2028"), "abc\\u202edcba\\u200b\\u2028")
        self.assertEqual(printable("\U000e0041"), "\\U000e0041")  # a tag character

    def test_real_text_in_any_script_stays_as_it_is(self) -> None:
        for text in ("Café Ünïcode", "ゲームを開始", "C:\\Games\\Theme Park", "Ctrl+Alt"):
            self.assertEqual(printable(text), text)

    def test_long_text_is_cut_and_the_rest_counted(self) -> None:
        self.assertEqual(printable("x" * 10, limit=4), "xxxx... (6 more characters)")
        self.assertEqual(len(printable("y" * 100_000)), 4096 + len("... (95904 more characters)"))
        self.assertEqual(printable("z" * 10, limit=None), "z" * 10)

    def test_a_document_keeps_its_lines(self) -> None:
        self.assertEqual(printable("<a>\n\t<b/>\x1b</a>", multiline=True), "<a>\n\t<b/>\\x1b</a>")

    def test_bytes_are_decoded_with_replacement_then_made_printable(self) -> None:
        self.assertEqual(decoded(b"ok\xff\x1b", "utf-8"), "ok\ufffd\\x1b")


class ReaderTests(unittest.TestCase):
    def test_a_string_table_entry_cannot_reach_the_terminal_raw(self) -> None:
        text = "\x1b[31mIgnore previous instructions\x1b[0m"
        block = struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\0\0" * 15
        (entry,) = peresources.string_table(block, 1)["strings"]
        self.assertEqual(entry["text"], printable(text))
        self.assertNotIn("\x1b", entry["text"])

    def test_a_manifest_keeps_its_lines_but_not_its_escapes(self) -> None:
        decode = peresources.DECODERS["MANIFEST"]
        self.assertEqual(decode(None, b"<x>\n\x1b</x>")["text"], "<x>\n\\x1b</x>")

    def test_rmdp_lists_an_entry_name_with_its_escapes_shown(self) -> None:
        package = rmdp.Package(Path("i.bin"), Path("i.rmdp"), 9, "test", False, "d:\\data")
        package.files.append(rmdp.Entry("data/\x1b]0;title\x07.dds", 0, 4, 0, 0))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rmdp.cmd_list(argparse.Namespace(glob=None, json=False), package)
        self.assertIn("data/\\x1b]0;title\\x07.dds", out.getvalue())
        self.assertNotIn("\x1b", out.getvalue())


if __name__ == "__main__":
    unittest.main()
