"""The run harness's step script, report and install snapshot; the engine itself is Windows only."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from rea_suite import run_harness, vigem_pad


class Steps(unittest.TestCase):
    def parse(self, text: str) -> list[dict]:
        return run_harness.parse_steps(text.splitlines())

    def test_each_step_becomes_its_plan_entry_with_line_and_source(self) -> None:
        steps = self.parse(
            "# the title screen\n"
            "wait-window\n"
            "at 12.5\n"
            "key ctrl+shift+F6 hold 0.2   # the hub\n"
            'text "tweak cam; x"\n'
            "click 640 360 right hold 0.3\n"
            "move 10 20\n"
            "pad A+B hold 0.5\n"
            "capture menu\n"
            "focus\n"
            "wait 3\n"
            "close\n"
        )
        self.assertEqual([s["line"] for s in steps], list(range(2, 13)))
        self.assertEqual(
            steps[0], {"line": 2, "source": "wait-window", "op": "wait-window", "seconds": 60.0}
        )
        self.assertEqual(steps[1]["seconds"], 12.5)
        self.assertEqual(steps[2]["source"], "key ctrl+shift+F6 hold 0.2   # the hub")
        self.assertEqual(
            [(k["name"], k["scan"], k["extended"]) for k in steps[2]["chord"]],
            [("CTRL", 0x1D, False), ("SHIFT", 0x2A, False), ("F6", 0x40, False)],
        )
        self.assertEqual(steps[2]["hold"], 0.2)
        self.assertEqual(steps[3]["text"], "tweak cam; x")
        self.assertEqual(steps[4], steps[4] | {"x": 640, "y": 360, "button": "right", "hold": 0.3})
        self.assertEqual(steps[5], steps[5] | {"op": "move", "x": 10, "y": 20})
        self.assertEqual(steps[6], steps[6] | {"press": "A+B", "hold": 0.5})
        self.assertEqual(steps[7]["name"], "menu")
        self.assertEqual([s["op"] for s in steps[8:]], ["focus", "wait", "close"])

    def test_defaults_for_hold_button_and_capture_name(self) -> None:
        key, click, pad, capture = self.parse("key ENTER\nclick 1 2\npad DOWN\ncapture")
        self.assertEqual(key["hold"], 0.1)
        self.assertEqual((click["button"], click["hold"]), ("left", 0.1))
        self.assertEqual(pad["hold"], 0.15)
        self.assertIsNone(capture["name"])

    def test_keys_are_scan_codes_whatever_the_layout(self) -> None:
        cases = {
            "ESC": (0x01, False), "1": (0x02, False), "0": (0x0B, False), "Q": (0x10, False),
            "a": (0x1E, False), "grave": (0x29, False), "tilde": (0x29, False), "M": (0x32, False),
            "SPACE": (0x39, False), "F1": (0x3B, False), "F10": (0x44, False), "F12": (0x58, False),
            "NUMPAD0": (0x52, False), "DECIMAL": (0x53, False), "return": (0x1C, False),
            "NUMPADENTER": (0x1C, True), "UP": (0x48, True), "DELETE": (0x53, True),
            "RCTRL": (0x1D, True), "sc:0x29": (0x29, False), "SC:0xE01C": (0x1C, True),
        }  # fmt: skip
        for name, expected in cases.items():
            entry = run_harness.key(name)
            self.assertEqual((entry["scan"], entry["extended"]), expected, name)

    def test_inline_steps_split_on_semicolons_outside_quotes(self) -> None:
        self.assertEqual(
            run_harness.split_inline("wait 5; text \"a;b\"; key ENTER\ncapture 'x;y'"),
            ["wait 5", ' text "a;b"', " key ENTER", "capture 'x;y'"],
        )

    def test_wrong_steps_are_refused_with_their_line(self) -> None:
        wrong = [
            "jump", "wait", "wait -1", "wait soon", "at 1 2", "wait-window 0", "focus now",
            "key", "key HYPER", "key sc:0x1234", "key A hold 0", "text", 'text ""', "click 1",
            "click 1 2 sideways", "click -1 2", "click 1.5 2", "move 1 2 left", "pad Z",
            "pad A hold", "capture a/b", "capture a b", 'text "open', "close now",
        ]  # fmt: skip
        for text in wrong:
            with self.assertRaises(run_harness.ScriptError, msg=text) as caught:
                self.parse("wait 1\n" + text)
            self.assertEqual(caught.exception.line, 2, text)

    def test_pad_steps_use_the_pads_own_buttons(self) -> None:
        for name in ("A", "DOWN", "LT", "LX-", "START+BACK"):
            (step,) = self.parse(f"pad {name}")
            vigem_pad.press(step["press"], 0, step["hold"])

    def test_answers_take_a_button_or_a_pattern_and_a_button(self) -> None:
        self.assertEqual(
            run_harness.answers(["OK", "minimum spec.*=Continue", "a=b=No"]),
            [
                {"pattern": None, "button": "OK"},
                {"pattern": "minimum spec.*", "button": "Continue"},
                {"pattern": "a=b", "button": "No"},
            ],
        )
        for rule in ("x=", "", "(=OK"):
            with self.assertRaises(ValueError, msg=rule):
                run_harness.answers([rule])


class Snapshot(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "bin").mkdir()
        (self.root / "bin" / "Game.EXE").write_bytes(b"MZ game")
        (self.root / "bin" / "engine.dll").write_bytes(b"MZ engine")
        (self.root / "data.pak").write_bytes(b"x" * 100)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_executables_and_dlls_are_hashed_other_files_only_sized(self) -> None:
        files = run_harness.snapshot([self.root])["files"]
        self.assertEqual(sorted(files), ["0:bin/Game.EXE", "0:bin/engine.dll", "0:data.pak"])
        self.assertIn("sha256", files["0:bin/Game.EXE"])
        self.assertIn("sha256", files["0:bin/engine.dll"])
        self.assertNotIn("sha256", files["0:data.pak"])
        self.assertEqual(files["0:data.pak"]["size"], 100)

    def test_an_untouched_install_is_unchanged(self) -> None:
        before = run_harness.snapshot([self.root])
        result = run_harness.diff(before, run_harness.snapshot([self.root]))
        self.assertTrue(result["unchanged"])
        self.assertEqual(result["files"], 3)

    def test_added_removed_and_changed_files_are_named_with_their_fields(self) -> None:
        before = run_harness.snapshot([self.root])
        dll = self.root / "bin" / "engine.dll"
        stat = dll.stat()
        dll.write_bytes(b"MZ patch!")  # same size: only the hash tells
        os.utime(dll, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        (self.root / "data.pak").unlink()
        (self.root / "settings.ini").write_text("x")
        result = run_harness.diff(before, run_harness.snapshot([self.root]))
        self.assertFalse(result["unchanged"])
        self.assertEqual(result["added"], ["0:settings.ini"])
        self.assertEqual(result["removed"], ["0:data.pak"])
        self.assertEqual(result["changed"], [{"file": "0:bin/engine.dll", "fields": ["sha256"]}])

    def test_links_are_recorded_not_followed(self) -> None:
        outside = Path(self.tmp.name + "-outside")
        outside.mkdir()
        try:
            (outside / "big.bin").write_bytes(b"y")
            (self.root / "content").symlink_to(outside, target_is_directory=True)
            files = run_harness.snapshot([self.root])["files"]
            self.assertEqual(files["0:content"], {"link": str(outside)})
            self.assertNotIn("0:content/big.bin", files)
        finally:
            (outside / "big.bin").unlink()
            outside.rmdir()

    def test_two_roots_keep_their_files_apart(self) -> None:
        files = run_harness.snapshot([self.root / "bin", self.root])["files"]
        self.assertIn("0:Game.EXE", files)
        self.assertIn("1:bin/Game.EXE", files)


ENGINE = {
    "error": None,
    "launched": True,
    "pid": 100,
    "job": None,
    "window": {"first_seen": 2.5, "titles": ["Game"]},
    "end": {"t": 30.1, "reason": "close-step", "ended_by": "wm_close", "exit_code": 0},
    "steps": [{"line": 1, "source": "key ENTER", "op": "key", "status": "done", "detail": None}],
    "captures": [
        {"name": "menu", "file": "captures/menu.png", "method": "printwindow", "black": False}
    ],
    "dialogs": [],
    "focus": [],
    "seen": {"processes": [{"pid": 100, "name": "Game.exe"}], "modules": [], "tcp": [], "udp": []},
    "left_running": [],
    "pad": None,
}
PLAN = {"program": "D:\\g\\Game.exe", "args": ["-w"], "cwd": None, "env": {"TOKEN": "s3cret"},
        "attach": None, "display_lock": True}  # fmt: skip


class Report(unittest.TestCase):
    def build(self, engine: dict, install: dict | None = None) -> dict:
        return run_harness.report(PLAN, engine, install, "2026-11-11T10:00:00+00:00", 31.0)

    def test_a_clean_run_is_ok_and_keeps_the_report_format(self) -> None:
        report = self.build(ENGINE, {"unchanged": True, "added": [], "removed": [], "changed": []})
        self.assertTrue(report["ok"])
        self.assertEqual(report["format"], "rea-suite-run/1")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["exit_code_hex"], "0x00000000")
        self.assertEqual(report["timings"]["window_after"], 2.5)
        self.assertEqual(report["ended_by"], "wm_close")
        expected = {
            "format", "ok", "program", "args", "cwd", "env", "attach", "pid", "exit_code",
            "exit_code_hex", "ended_by", "end_reason", "timings", "display_lock", "steps",
            "captures", "dialogs", "focus", "window_titles", "seen", "left_running", "pad",
            "install", "findings",
        }  # fmt: skip
        self.assertEqual(set(report), expected)
        json.dumps(report)

    def test_environment_values_never_reach_the_report(self) -> None:
        report = self.build(ENGINE)
        self.assertEqual(report["env"], ["TOKEN"])
        self.assertNotIn("s3cret", json.dumps(report))

    def test_errors_fail_the_run_and_come_first(self) -> None:
        engine = ENGINE | {
            "steps": [{"line": 4, "source": "key ENTER", "status": "refused", "detail": "not in front"},
                      {"line": 5, "source": "wait 1", "status": "not-run", "detail": "exited"}],
            "end": {"ended_by": "exit", "exit_code": -1073741819},
            "focus": [{"t": 3, "event": "lost", "window": {"process": "GameBar", "title": "", "class": "x"}}],
            "dialogs": [{"title": "Error", "text": "Out of memory", "answered": "id 1"}],
            "left_running": [{"pid": 7, "name": "crashpad.exe"}],
        }  # fmt: skip
        install = {"unchanged": False, "added": ["0:x.ini"], "removed": [], "changed": []}
        report = self.build(engine, install)
        self.assertFalse(report["ok"])
        kinds = [(f["severity"], f["kind"]) for f in report["findings"]]
        self.assertEqual(
            kinds,
            [
                ("error", "step-refused"), ("error", "install-changed"), ("error", "left-running"),
                ("warning", "steps-not-run"), ("warning", "crashed"), ("warning", "focus-lost"),
                ("warning", "dialog"),
            ],
        )  # fmt: skip
        self.assertIn("0xc0000005", report["findings"][4]["message"])
        self.assertIn("GameBar", report["findings"][5]["message"])

    def test_a_kill_is_a_warning_and_not_a_crash(self) -> None:
        engine = ENGINE | {"end": {"ended_by": "killed", "exit_code": 4294967295}}
        report = self.build(engine)
        self.assertTrue(report["ok"])
        self.assertEqual([f["kind"] for f in report["findings"]], ["killed"])

    def test_captures_from_the_screen_or_black_are_reported(self) -> None:
        engine = ENGINE | {
            "captures": [{"name": "a", "method": "screen", "black": False, "reason": "PrintWindow blocked"},
                         {"name": "b", "method": "screen", "black": True}],
        }  # fmt: skip
        kinds = [f["kind"] for f in self.build(engine)["findings"]]
        self.assertEqual(kinds, ["capture-black", "capture-screen"])

    def test_a_failed_engine_is_an_error(self) -> None:
        report = self.build({"error": "the engine exited 1"})
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"][0]["kind"], "harness")


class Cli(unittest.TestCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_harness.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_prints_the_plan(self) -> None:
        code, out, _ = self.run_cli(
            "--steps", "wait 1; key ENTER", "--env", "A=1", "--answer", "OK", "--seconds", "30",
            "--dry-run", "--start", "C:\\Games\\Game.exe", "-windowed", "two words",
        )  # fmt: skip
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual(plan["format"], "rea-suite-run-plan/1")
        self.assertEqual(plan["program"], "C:\\Games\\Game.exe")
        self.assertEqual(plan["command_line"], 'C:\\Games\\Game.exe -windowed "two words"')
        self.assertEqual(plan["env"], {"A": "1"})
        self.assertEqual([s["op"] for s in plan["steps"]], ["wait", "key"])
        self.assertIsNone(plan["pad"])

    def test_a_bad_script_or_arguments_exit_2(self) -> None:
        for argv in (
            ["--steps", "jump", "--dry-run", "--start", "x.exe"],
            ["--env", "NOVALUE", "--dry-run", "--start", "x.exe"],
            ["--seconds", "0", "--dry-run", "--start", "x.exe"],
            ["--dry-run", "--start"],
        ):
            self.assertEqual(self.run_cli(*argv)[0], 2, argv)


if __name__ == "__main__":
    unittest.main()
