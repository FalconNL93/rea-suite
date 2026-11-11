"""The pad's schedule and reports; the driver itself is Windows only and not run here."""

from __future__ import annotations

import contextlib
import io
import json
import unittest

from rea_suite import vigem_pad


class Schedule(unittest.TestCase):
    def test_presses_sort_by_time_and_take_their_own_hold(self) -> None:
        presses = vigem_pad.schedule("33:a+b:0.5, 30:DOWN", 0.15)
        self.assertEqual(
            [(p.at, p.names, p.hold) for p in presses],
            [(30.0, ["DOWN"], 0.15), (33.0, ["A", "B"], 0.5)],
        )

    def test_reports_combine_buttons_triggers_and_sticks(self) -> None:
        (press,) = vigem_pad.schedule("1:A+START+LT+LX-", 0.1)
        report = press.report()
        self.assertEqual(
            (report.buttons, report.lt, report.rt, report.lx), (0x1010, 255, 0, -32768)
        )

    def test_unknown_buttons_and_bad_times_are_refused(self) -> None:
        for text in ("1:Z", "1", "-1:A", "1:A:0"):
            with self.assertRaises(ValueError, msg=text):
                vigem_pad.schedule(text, 0.1)

    def test_live_presses_take_buttons_and_an_optional_hold(self) -> None:
        item = vigem_pad.live_press("a+b:0.5\n", 0.15)
        self.assertEqual((item.names, item.hold), (["A", "B"], 0.5))
        self.assertEqual(vigem_pad.live_press("DOWN", 0.15).hold, 0.15)
        for text in ("", "Z", "A:0", "1:A:0.5"):
            with self.assertRaises(ValueError, msg=text):
                vigem_pad.live_press(text, 0.15)

    def test_stdin_and_presses_together_are_refused(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vigem_pad.main(["--presses", "1:A", "--stdin"]), 1)

    def test_dry_run_prints_the_schedule(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = vigem_pad.main(["--presses", "2:UP,1:A", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(
            [json.loads(line) for line in out.getvalue().splitlines()],
            [{"at": 1.0, "press": "A", "hold": 0.15}, {"at": 2.0, "press": "UP", "hold": 0.15}],
        )

    def test_a_bad_schedule_exits_1(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vigem_pad.main(["--presses", "1:Q", "--dry-run"]), 1)


if __name__ == "__main__":
    unittest.main()
