"""`rea-suite dosbox --opl-log` and `compare-opl`: DOSBox-X's raw OPL capture (DRO) read and converted,
a port's text log read, both normalized the capture's way and compared. A DOSBox-X run is in
test_dosbox.py's opt-in RealRun."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rea_suite import dosbox
from rea_suite import dosbox_opl as opl

TABLE = bytes([0x20, 0x40, 0xA0, 0xB0, 0xBD])  # codes 0-4; 5 and 6 are the delays
DELAY, SHIFT = 5, 6


def dro(pairs: list[tuple[int, int]], closed: bool = True, hardware: int = 2) -> bytes:
    """A DROv2 file as DOSBox-X writes it, with a small table."""
    header = opl.DRO_HEADER.pack(
        opl.DRO_ID, 2, 0, len(pairs) if closed else 0, 0, hardware, 0, 0, DELAY, SHIFT, len(TABLE)
    )
    return header + TABLE + b"".join(bytes(p) for p in pairs)


# A short song: an instrument, a key-on, a new note 220 ms later, a key-off 220 ms after that.
SONG = [(0, 0x01), (1, 0x10), (2, 0x98), (3, 0x31),
        (DELAY, 219), (2, 0xC0), (3, 0x32),
        (DELAY, 219), (3, 0x12)]  # fmt: skip


def port_log(start: float = 46.0, drift: float = 0.0, change: dict | None = None) -> str:
    """The same song as a port's TP_OPL_LOG would list it, with what a capture leaves out: the
    timer writes, a write that changes nothing, port writes before any note."""
    change = change or {}
    lines = []

    def out(t: float, reg: int, value: int, port: int = 0x388) -> None:
        value = change.get((round(t - start, 3), reg), value)
        lines.append(f"{t:.6f} {port:X} {reg:02X}")
        lines.append(f"{t:.6f} {port + 1:X} {value:02X}")

    out(start - 2, 0x04, 0x60)  # the timers' reset, no sound
    out(start - 1, 0x20, 0x01)
    out(start - 1, 0x40, 0x10)
    out(start - 1, 0x40, 0x10)  # the same value again
    out(start, 0xA0, 0x98)
    out(start, 0xB0, 0x31)
    out(start + 0.22 + drift, 0xA0, 0xC0)
    out(start + 0.22 + drift, 0xB0, 0x32)
    out(start + 0.44 + drift, 0x04, 0x80)
    out(start + 0.44 + drift, 0xB0, 0x12)
    return "\n".join(lines) + "\n"


def compare(*argv: str) -> tuple[int, str]:
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(out):
        status = dosbox.main(["compare-opl", *argv])
    return status, out.getvalue()


class Capture(unittest.TestCase):
    def test_codes_delays_and_the_second_bank(self) -> None:
        data = dro([(0, 0x01), (3, 0x31), (DELAY, 9), (0x80 | 2, 0x98), (SHIFT, 1), (3, 0x11)])
        got = opl.read_dro(data)
        self.assertEqual(got.hardware, "opl3")
        self.assertTrue(got.closed)
        self.assertEqual(
            [(w.t, w.bank, w.reg, w.value) for w in got.writes],
            [
                (0.0, 0, 0x20, 0x01),
                (0.0, 0, 0xB0, 0x31),
                (0.01, 1, 0xA0, 0x98),
                (0.522, 0, 0xB0, 0x11),
            ],
        )

    def test_a_capture_its_writer_did_not_close_reads_as_far_as_it_got(self) -> None:
        got = opl.read_dro(dro(SONG, closed=False) + b"\x03")  # half a pair at the end
        self.assertFalse(got.closed)
        self.assertEqual(len(got.writes), 7)

    def test_bad_captures(self) -> None:
        for data, why in (
            (b"RIFF" + bytes(40), "no DBRAWOPL"),
            (dro(SONG).replace(b"DBRAWOPL\x02", b"DBRAWOPL\x01"), "version 1.0"),
            (dro([(9, 0)]), "outside the table"),
            (dro(SONG)[:28], "shorter than its register table"),
        ):
            with self.assertRaises(opl.BadLog) as caught:
                opl.read_dro(data)
            self.assertIn(why, str(caught.exception))

    def test_captures_convert_to_one_log_a_later_one_at_least_30_s_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = [Path(tmp) / "opl_000.dro", Path(tmp) / "opl_001.dro"]
            files[0].write_bytes(dro(SONG))
            files[1].write_bytes(dro([(3, 0x31)], closed=False, hardware=0))
            out = Path(tmp) / "opl.jsonl"
            summary = opl.convert_captures(files, out, "test")
            lines = [json.loads(line) for line in out.read_text().splitlines()]
            self.assertEqual(summary["writes"], 8)
            self.assertEqual(summary["unclosed"], ["opl_001.dro"])
            self.assertEqual(lines[0]["format"], "rea-opl")
            self.assertEqual(lines[0]["hardware"], "opl3")
            self.assertEqual(lines[2], {"t": 0.0, "bank": 0, "reg": "40", "value": "10"})
            self.assertEqual(lines[-1], {"t": 30.44, "bank": 0, "reg": "b0", "value": "31"})
            back = opl.read_log(out)
            self.assertEqual(
                [(w.reg, w.value) for w in back][:4],
                [(0x20, 1), (0x40, 0x10), (0xA0, 0x98), (0xB0, 0x31)],
            )

    def test_the_run_records_the_conversion_or_why_there_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            caps = Path(tmp) / "opl"
            record = dosbox.opl_record(Path(tmp) / "out.jsonl", caps)
            self.assertEqual(record["writes"], 0)
            self.assertIn("no key-on", record["note"])
            caps.mkdir()
            (caps / "prog_000.dro").write_bytes(b"junk")
            record = dosbox.opl_record(Path(tmp) / "out.jsonl", caps)
            self.assertEqual(record["kind"], "error")

    def test_the_command_line_starts_the_capture_before_the_program(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            game = Path(tmp).resolve() / "GAME"
            game.mkdir()
            (game / "MAIN.EXE").write_bytes(b"MZ")
            args = argparse.Namespace(
                caller_cwd=Path(tmp), program=Path("GAME/MAIN.EXE"), args=[], mount=None,
                groups="", window=False, conf=None, set=[], dpmi=False, opl_log=Path("o.jsonl"),
            )  # fmt: skip
            run = Path(tmp) / "run"
            cmd = dosbox.dosbox_command(args, "dosbox-x", run, 5555)
            self.assertIn(f"dosbox captures={run / 'opl'}", cmd)
            self.assertIn("DX-CAPTURE /O /-D DEBUGBOX MAIN.EXE", cmd)
            self.assertIn("DX-CAPTURE /O /-D MAIN.EXE", dosbox.dosbox_command(args, "x", run, None))


class PortLogs(unittest.TestCase):
    def read(self, text: str) -> list[opl.Write]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.txt"
            path.write_text(text)
            return opl.read_log(path)

    def test_address_and_data_ports_of_both_banks(self) -> None:
        writes = self.read(
            "# a comment\n1.0 389 55\n1.5 388 B0\n1.5 389 31\n2 38A 05\n2 38B 01\n2.5 220 C0\n2.5 221 30\n"
        )
        self.assertEqual(
            [(w.t, w.bank, w.reg, w.value, w.line) for w in writes],
            [(1.5, 0, 0xB0, 0x31, 4), (2.0, 1, 0x05, 0x01, 6), (2.5, 0, 0xC0, 0x30, 8)],
        )

    def test_json_lines_with_banks_or_ports(self) -> None:
        text = (
            '{"format": "rea-opl", "version": 1}\n{"t": 0.5, "bank": 1, "reg": "b2", "value": "2a"}\n'
            '{"t": 1, "port": "388", "value": "bd"}\n{"t": 1, "port": "389", "value": "3f"}\n'
        )
        self.assertEqual(
            [(w.bank, w.reg, w.value) for w in self.read(text)], [(1, 0xB2, 0x2A), (0, 0xBD, 0x3F)]
        )

    def test_bad_lines_name_their_line(self) -> None:
        for text, why in (
            ("1.0 388\n", ":1: a write is SECONDS PORT BYTE"),
            ("1.0 388 B0\n1.0 3C8 10\n", ":2: port 3C8h is not an OPL port"),
            ("1.0 388 1B0\n", ":1: a byte in hex"),
            ("nan 388 B0\n", ":1: the time is not a number"),
            ('{"format": "rea-regions", "version": 1}\n', ":1: the first line is not the header"),
            ('{"format": "rea-opl", "version": 2}\n', ":1: version 2"),
            (
                '{"format": "rea-opl", "version": 1}\n{"t": 1, "bank": 2, "reg": "b0", "value": "1"}\n',
                ":2: bank is 0 or 1",
            ),
            (
                '{"format": "rea-opl", "version": 1}\n{"t": 1, "bank": 0, "value": "1"}\n',
                ":2: missing 'reg'",
            ),
            ("\n", "empty"),
        ):
            with self.assertRaises(opl.BadLog) as caught:
                self.read(text)
            self.assertIn(why, str(caught.exception), text)


class Normalizing(unittest.TestCase):
    def test_from_the_first_key_on_with_the_registers_set_before_it(self) -> None:
        W = opl.Write
        writes = [W(1, 0, 0x04, 0x80), W(1, 0, 0x20, 0x01), W(1, 0, 0xB1, 0x25), W(1, 0, 0xB1, 0x05),
                  W(1, 0, 0xBD, 0x3F), W(1, 0, 0xBD, 0xC0), W(2, 1, 0x05, 0x01), W(2, 0, 0x20, 0x01),
                  W(3, 0, 0xB0, 0x31), W(3, 0, 0xB0, 0x31), W(3.5, 0, 0x20, 0x02), W(4, 0, 0xB0, 0x11)]  # fmt: skip
        got, origin = opl.normalize(writes)
        self.assertEqual(origin, 1)  # B1 25 is a key-on: the snapshot is what came before it
        self.assertEqual(
            [(w.t, w.bank, w.reg, w.value) for w in got][:3],
            [(0.0, 0, 0x20, 0x01), (0.0, 0, 0xB1, 0x25), (0.0, 0, 0xB1, 0x05)],
        )
        got, origin = opl.normalize(writes, start=2.5)
        self.assertEqual(origin, 3)
        self.assertEqual(
            [(w.t, w.bank, w.reg, w.value) for w in got],
            [(0.0, 1, 0x05, 0x01), (0.0, 0, 0x20, 0x01), (0.0, 0, 0xB1, 0x05), (0.0, 0, 0xBD, 0xC0),
             (0.0, 0, 0xB0, 0x31), (0.5, 0, 0x20, 0x02), (1.0, 0, 0xB0, 0x11)],
        )  # fmt: skip

    def test_a_capture_normalizes_to_itself(self) -> None:
        writes = opl.read_dro(dro(SONG)).writes
        got, origin = opl.normalize(writes)
        self.assertEqual(origin, 0.0)
        self.assertEqual(
            [(w.t, w.key, w.value) for w in got], [(w.t, w.key, w.value) for w in writes]
        )

    def test_registers_are_named_by_channel_and_operator(self) -> None:
        self.assertEqual(opl.channel_of(0, 0x43), (0, 2))
        self.assertEqual(opl.channel_of(0, 0x55), (8, 2))
        self.assertEqual(opl.channel_of(1, 0xB2), (11, None))
        self.assertIsNone(opl.channel_of(0, 0xBD))
        self.assertIsNone(opl.channel_of(0, 0x26))  # no operator there
        self.assertEqual(opl.describe(0, 0x48), "048 (channel 3 operator 1: key scale/level)")
        self.assertEqual(opl.describe(1, 0x05), "105 (OPL3 enable)")
        self.assertEqual(opl.timbre(4)[:5], [(0, 0x29), (0, 0x49), (0, 0x69), (0, 0x89), (0, 0xE9)])


class Comparing(unittest.TestCase):
    def files(self, tmp: str, port: str) -> tuple[str, str]:
        a, b = Path(tmp) / "orig.dro", Path(tmp) / "port.txt"
        a.write_bytes(dro(SONG))
        b.write_text(port)
        return str(a), str(b)

    def test_a_capture_and_a_ports_full_log_of_the_same_song_are_equal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status, out = compare(*self.files(tmp, port_log(drift=0.03)))
        self.assertEqual(status, 0, out)
        self.assertIn("B: ", out)
        self.assertIn("first key-on at 46.000 s", out)
        self.assertIn("equal: 7 write(s) over 0.440 s, within 50 ms", out)

    def test_a_different_value_names_the_register_and_shows_the_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status, out = compare(*self.files(tmp, port_log(change={(0.22, 0xA0): 0xC1})))
        self.assertEqual(status, 1, out)
        self.assertIn("4 write(s) agree, then at 0.220 s (value):", out)
        self.assertIn(
            "0A0 (channel 0: F-number low), write 2 of that register: A C0 at 0.220 s, B C1 at 0.220 s",
            out,
        )
        self.assertIn(" A: 98@0.000 C0@0.220", out)
        self.assertIn(" channel 0 just before 0.220 s (A / B):", out)
        self.assertIn("020 01/01", out)

    def test_drift_beyond_the_tolerance_is_a_difference_unless_timing_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = self.files(tmp, port_log(drift=0.08))
            status, out = compare(*files)
            self.assertEqual(status, 1, out)
            self.assertIn("(timing):", out)
            self.assertIn("C0 at A 0.220 s, B 0.300 s: 80 ms apart (tolerance 50 ms)", out)
            self.assertEqual(compare(*files, "--tolerance", "0.1")[0], 0)
            self.assertEqual(compare(*files, "--ignore-timing")[0], 0)

    def test_a_missing_write_and_the_compared_span(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port = port_log().replace("46.220000 388 B0\n46.220000 389 32\n", "")
            status, out = compare(*self.files(tmp, port))
            self.assertEqual(status, 1, out)
            self.assertIn(
                "0B0 (channel 0: key on/block/F-number high), write 2 of that register: A 32 at 0.220 s, B 12 at 0.440 s",
                out,
            )
            # the port's log stops early: only the time both cover is compared
            short = port_log().split("46.440000")[0]
            self.assertEqual(compare(*self.files(tmp, short))[0], 0)
            self.assertEqual(compare(*self.files(tmp, short), "--until", "0.1")[0], 0)

    def test_where_a_song_starts_in_each_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            earlier = "10.000000 388 B3\n10.000000 389 2A\n10.500000 388 B3\n10.500000 389 0A\n"
            a, b = self.files(tmp, earlier + port_log())
            self.assertEqual(compare(a, b)[0], 1)  # the port's first key-on is an earlier tune
            status, out = compare(a, b, "--start-b", "40")
            self.assertEqual(status, 1, out)  # its key-off of B3 is still in the registers set
            self.assertIn("0B3", out)
            no_tune = port_log().replace("388 B0\n46.000000 389 31", "388 B0\n46.000000 389 11")
            no_tune = no_tune.replace("389 32", "389 12")
            status, out = compare(*self.files(tmp, no_tune))
            self.assertEqual(status, 1)
            self.assertIn("B has no key-on", out)

    def test_bad_input_is_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status, out = compare(str(Path(tmp) / "none.dro"), str(Path(tmp) / "none.txt"))
        self.assertEqual(status, 2)
        self.assertIn("compare-opl:", out)


if __name__ == "__main__":
    unittest.main()
