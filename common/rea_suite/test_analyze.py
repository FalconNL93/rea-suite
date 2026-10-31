"""Offline project behavior, with optional real-provider smoke tests."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import analyze


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=analyze.ROOT / "work")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "research"
        self.binary = self.root / "game"
        self.binary.write_bytes(b"\x7fELF\x00ServerList\x00\x00" + "connect".encode("utf-16le"))

    def call(self, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return analyze.main(["--caller-cwd", str(self.root), "--project", "research", *args])

    def test_plan_resolves_relative_paths_without_creating_project(self):
        self.assertEqual(self.call("game", "--plan"), 0)
        self.assertFalse(self.project.exists())

    @unittest.skipIf(sys.platform == "win32", "POSIX entrypoint")
    def test_suite_entrypoint_keeps_the_callers_directory(self):
        result = subprocess.run(
            [
                str(analyze.ROOT / "bin/rea-suite"),
                "analyze",
                "game",
                "--project",
                "research",
                "--plan",
            ],
            cwd=self.root,
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.binary), result.stdout)
        self.assertFalse(self.project.exists())

    def test_application_cannot_include_its_own_output_tree(self):
        with self.assertRaisesRegex(ValueError, "outside the input"):
            analyze.discover([self.root], self.project, "javascript", 100)

    def test_unknown_existing_manifest_is_not_overwritten(self):
        self.project.mkdir()
        manifest = self.project / "project.json"
        manifest.write_text('{"another_project": true}')
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            self.call("game")
        self.assertEqual(manifest.read_text(), '{"another_project": true}')

    def test_resume_is_only_used_after_an_export_exists(self):
        args = analyze.parser().parse_args(["--preset", "decompile"])
        first = next(
            command
            for label, command in analyze.steps(self.binary, "native", args, self.project)
            if label == "decompile"
        )
        self.assertNotIn("--resume", first)
        output = Path(first[first.index("--output") + 1])
        output.mkdir(parents=True)
        second = next(
            command
            for label, command in analyze.steps(self.binary, "native", args, self.project)
            if label == "decompile"
        )
        self.assertIn("--resume", second)

    def test_discovery_handles_multiple_roots_and_skips_output_and_symlinks(self):
        self.project.mkdir()
        (self.project / "generated").write_bytes(b"\x7fELF")
        (self.root / "link").symlink_to(self.binary)
        other = self.root / "other"
        other.mkdir()
        (other / "game").write_bytes(b"\x7fELFdifferent")
        found = analyze.discover([self.root, other], self.project, "auto", 100)
        self.assertEqual({p for p, _ in found}, {self.binary, other / "game"})
        self.assertNotEqual(analyze.digest(self.binary), analyze.digest(other / "game"))

    def test_directory_limit_fails_instead_of_silently_truncating(self):
        with self.assertRaisesRegex(ValueError, "max-files"):
            analyze.discover([self.root], self.project, "auto", 0)

    def test_literal_strings_keep_file_offsets_and_encoding(self):
        values = analyze.triage(self.binary)["strings"]
        server = next(v for v in values if v["value"] == "ServerList")
        self.assertEqual(server["file_offset"], "0x5")
        self.assertTrue(
            any(v["value"] == "connect" and v["encoding"] == "utf-16le" for v in values)
        )

    def test_verified_cache_skips_command_but_corrupt_report_is_rebuilt(self):
        self.project.mkdir()
        command = [sys.executable, "-c", "print('original report')"]
        state = {}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(analyze.run_step("test", command, self.project, state, False, True))
            with patch.object(analyze.subprocess, "run") as run:
                self.assertTrue(analyze.run_step("test", command, self.project, state, False, True))
            run.assert_not_called()
            saved = self.project / next(iter(state.values()))["output"]
            saved.write_text("modified")
            self.assertTrue(analyze.run_step("test", command, self.project, state, False, True))
        self.assertEqual(saved.read_text(), "modified")
        current = self.project / next(iter(state.values()))["output"]
        self.assertEqual(current.read_text().strip(), "original report")

    def test_failed_tool_returns_nonzero_and_retains_diagnostics(self):
        with patch.object(analyze, "REA", [sys.executable, "-c", "import sys; sys.exit(7)"]):
            self.assertEqual(self.call("game", "--preset", "triage"), 1)
        state = json.loads((self.project / "project.json").read_text())
        step = next(iter(next(iter(state["artifacts"].values()))["steps"].values()))
        self.assertEqual(step["exit_code"], 7)
        self.assertTrue((self.project / "REPORT.md").exists())

    def test_query_selects_only_requested_saved_target(self):
        with patch.object(analyze, "run_step", return_value=True):
            self.assertEqual(self.call("game"), 0)
        with patch.object(analyze, "run_step", return_value=True) as run:
            self.assertEqual(self.call("--query", "ServerList", "--select", "game"), 0)
        self.assertEqual([c.args[0] for c in run.call_args_list], ["overview", "trace"])

    def test_an_existing_project_can_resume_without_repeating_input_paths(self):
        with patch.object(analyze, "run_step", return_value=True):
            self.assertEqual(self.call("game"), 0)
            self.assertEqual(self.call("--preset", "decompile", "--plan"), 0)

    def test_local_search_starts_no_analysis_tool(self):
        with patch.object(analyze, "run_step", return_value=True):
            self.call("game")
        output = io.StringIO()
        with patch.object(analyze.subprocess, "run") as run, contextlib.redirect_stdout(output):
            self.assertEqual(
                analyze.main(["--project", str(self.project), "--search", "ServerList"]), 0
            )
        run.assert_not_called()
        self.assertIn("triage.json", output.getvalue())

    def test_changed_input_is_not_recorded_as_success(self):
        def changed(label, command, out, state, *args):
            state["test"] = {"exit_code": 0}
            self.binary.write_bytes(b"\x7fELFreplaced")
            return True

        with (
            patch.object(analyze, "run_step", side_effect=changed),
            self.assertRaisesRegex(ValueError, "input changed"),
        ):
            self.call("game")
        state = json.loads((self.project / "project.json").read_text())
        self.assertEqual(next(iter(state["artifacts"].values()))["steps"]["test"]["exit_code"], 1)

    def test_lock_does_not_remove_another_runs_lock(self):
        self.project.mkdir()
        lock = self.project / ".analysis.lock"
        lock.write_text("another run")
        with self.assertRaisesRegex(ValueError, "locked"), analyze.locked(self.project):
            self.fail("entered competing project")
        self.assertEqual(lock.read_text(), "another run")

    @unittest.skipUnless(os.environ.get("REA_ANALYZE_INTEGRATION"), "real-provider smoke test")
    def test_real_javascript_pipeline_without_executing_the_target(self):
        app = self.root / "app"
        app.mkdir()
        (app / "package.json").write_text('{"name":"analysis-fixture","main":"index.js"}')
        (app / "index.js").write_text(
            'throw new Error("must never run");\nexport const feature = "ServerList";\n'
        )
        self.assertEqual(self.call(str(app), "--kind", "javascript"), 0)

    @unittest.skipUnless(os.environ.get("REA_ANALYZE_INTEGRATION"), "real-provider smoke test")
    def test_real_native_function_dossier(self):
        source = self.root / "fixture.c"
        source.write_text(
            '#include <stdio.h>\n__attribute__((noinline)) int server_browser(void) { return puts("ServerList"); }\nint main(void) { return server_browser(); }\n'
        )
        subprocess.run(
            ["cc", "-g", "-O0", str(source), "-o", str(self.binary)], check=True, timeout=30
        )
        symbol = "_server_browser" if sys.platform == "darwin" else "server_browser"
        result = self.call(
            str(self.binary),
            "--function",
            symbol,
            "--query",
            "ServerList",
            "--preset",
            "decompile",
            "--max-functions",
            "2",
        )
        diagnostics = "\n".join(p.read_text()[:5000] for p in self.project.rglob("*.json"))
        self.assertEqual(result, 0, diagnostics)
        self.assertTrue(list(self.project.rglob("function-*.c")), diagnostics)
        self.assertTrue(list(self.project.rglob("function-*.asm")), diagnostics)
        self.assertTrue(
            list((self.project / "artifacts").glob("*/code/*/functions/*.c")), diagnostics
        )
        before = {
            p: analyze.digest(p) for p in self.project.glob("artifacts/*/code/*/functions/*.c")
        }
        self.assertEqual(
            self.call(str(self.binary), "--preset", "decompile", "--max-functions", "2"), 0
        )
        self.assertEqual({p: analyze.digest(p) for p in before}, before)
        state = json.loads((self.project / "project.json").read_text())
        stages = next(iter(state["artifacts"].values()))["steps"].values()
        self.assertTrue(any("--resume" in s["command"] and s["exit_code"] == 0 for s in stages))
        self.assertEqual(self.call("--search", "server_browser"), 0)


if __name__ == "__main__":
    unittest.main()
