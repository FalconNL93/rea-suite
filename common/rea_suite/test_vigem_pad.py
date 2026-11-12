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


class FakeClient:
    """Stands in for ViGEmClient.dll: records the reports and answers with a set result."""

    def __init__(self, result: int = vigem_pad.OK, index: int | None = 0) -> None:
        self.result, self.index = result, index
        self.sent: list[vigem_pad.Report] = []

    def plug(self) -> int:
        return 1

    def user_index(self, target: int) -> int | None:
        return self.index

    def update(self, target: int, report: vigem_pad.Report) -> int:
        self.sent.append(vigem_pad.Report.from_buffer_copy(report))
        return self.result


class FakeXInput:
    """Stands in for XInputGetState: shows the last report sent, or nothing when it is lost."""

    def __init__(self, client: FakeClient, lost: bool = False) -> None:
        self.client, self.lost, self.packet = client, lost, 0

    def state(self, index: int) -> vigem_pad.XInputState:
        self.packet += 1  # the packet number moves either way, as on the 2026-11-12 host
        state = vigem_pad.XInputState(packet=self.packet)
        if not self.lost and self.client.sent:
            state.pad = self.client.sent[-1]
        return state


def run(client: FakeClient, xinput: FakeXInput | None, *flags: str) -> tuple[int, list[dict], str]:
    args = vigem_pad.parser().parse_args(["--presses", "0:A+LT:0.05", "--tail", "0", *flags])
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = vigem_pad.drive(client, xinput, args, vigem_pad.schedule(args.presses, args.hold))  # type: ignore[arg-type]
    return code, [json.loads(line) for line in out.getvalue().splitlines()], err.getvalue()


class Confirm(unittest.TestCase):
    def test_a_failed_update_is_reported_by_name(self) -> None:
        client = FakeClient(result=0xE0000007)
        code, events, err = run(client, FakeXInput(client), "--fail-lost")
        failed = [e for e in events if e["event"] == "update-failed"]
        self.assertEqual([e["op"] for e in failed], ["press", "release"])
        self.assertEqual(failed[0]["error"], "VIGEM_ERROR_TARGET_NOT_PLUGGED_IN")
        self.assertIn("VIGEM_ERROR_TARGET_NOT_PLUGGED_IN", err)
        self.assertEqual(code, 3)

    def test_an_unknown_error_is_reported_in_hex(self) -> None:
        self.assertEqual(vigem_pad.error_name(0xE00000FF), "0xe00000ff")

    def test_a_press_seen_in_xinput_is_confirmed(self) -> None:
        client = FakeClient()
        code, events, _ = run(client, FakeXInput(client), "--fail-lost")
        (confirmed,) = [e for e in events if e["event"] == "confirmed"]
        self.assertEqual((confirmed["press"], confirmed["user_index"]), ("A+LT", 0))
        self.assertLess(confirmed["delay"], 0.05)
        self.assertNotIn("lost", [e["event"] for e in events])
        self.assertEqual((code, [r.buttons for r in client.sent]), (0, [0x1000, 0]))

    def test_a_press_never_seen_is_lost_and_fails_only_when_asked(self) -> None:
        for flags, want in (((), 0), (("--fail-lost",), 3)):
            client = FakeClient()
            code, events, err = run(client, FakeXInput(client, lost=True), *flags)
            (lost,) = [e for e in events if e["event"] == "lost"]
            self.assertEqual((lost["press"], lost["hold"]), ("A+LT", 0.05))
            self.assertEqual(events[-1]["lost"], 1)
            self.assertIn("1 press(es) lost", err)
            self.assertEqual(code, want, flags)

    def test_a_pad_without_a_user_index_loses_its_presses(self) -> None:
        client = FakeClient(index=None)
        _, events, _ = run(client, FakeXInput(client))
        self.assertIn(
            "no XInput user index", next(e for e in events if e["event"] == "lost")["reason"]
        )

    def test_no_confirm_sends_without_checking(self) -> None:
        client = FakeClient()
        code, events, _ = run(client, None, "--fail-lost")
        self.assertEqual(code, 0)
        self.assertFalse(events[0]["confirm"])
        self.assertFalse({"confirmed", "lost"} & {e["event"] for e in events})

    def test_a_trigger_or_stick_counts_past_half_its_way(self) -> None:
        want = vigem_pad.schedule("0:LT+LX-", 0.1)[0].report()
        state = vigem_pad.Report(lt=200, lx=-20000)
        self.assertTrue(vigem_pad.shows(state, want))
        self.assertFalse(vigem_pad.shows(vigem_pad.Report(lt=200, lx=20000), want))
        self.assertFalse(vigem_pad.shows(vigem_pad.Report(lt=100, lx=-20000), want))

    def test_guide_is_left_out_because_xinput_hides_it(self) -> None:
        want = vigem_pad.wanted(vigem_pad.schedule("0:GUIDE+A", 0.1)[0].report())
        self.assertEqual(want.buttons, 0x1000)


if __name__ == "__main__":
    unittest.main()
