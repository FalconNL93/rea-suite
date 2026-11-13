"""ghidra_headless and bounded against a stand-in analyzeHeadless: the time limit stops the whole
process tree, the heap cap and the decompiler's limit reach Ghidra, a dotted project path is
refused before Ghidra starts, and every failure names the log."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from rea_suite import bounded, ghidra_headless
from rea_suite.ghidra_headless import AnalyzeHeadless, GhidraError

# Records its arguments and two settings; STUB_MODE picks a behavior: "ok", "fail" (exit 3) or
# "hang" (starts a child that would outlive it, records the child's pid, then waits).
STUB = r"""#!/usr/bin/env bash
set -euo pipefail
echo "$*" > "$STUB_DIR/args"
echo "${GHIDRA_HEADLESS_MAXMEM:-} ${REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS:-}" > "$STUB_DIR/env"
echo "INFO  analyzeHeadless ran"
case "${STUB_MODE:-ok}" in
  fail) exit 3 ;;
  hang) sleep 60 & echo $! > "$STUB_DIR/child"; wait ;;
esac
"""


def alive(pid: int) -> bool:
    """Running, not a zombie: in a container without an init (CI's), a killed grandchild stays a
    zombie, since nothing reaps orphans there, and a signal 0 still finds it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True  # no /proc (macOS): signal 0 is all there is
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


@unittest.skipIf(sys.platform == "win32", "POSIX stand-in")
class AnalyzeHeadlessTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        support = self.root / "ghidra" / "support"
        support.mkdir(parents=True)
        (support / "analyzeHeadless").write_text(STUB)
        (support / "analyzeHeadless").chmod(0o755)
        self.project = self.root / "port" / "ghidra"
        self.log = self.project / "logs" / "analyze.log"

    def runner(self, mode: str = "ok", **settings: str) -> AnalyzeHeadless:
        env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("REA_GHIDRA_")},
            "STUB_DIR": str(self.root),
            "STUB_MODE": mode,
            **settings,
        }
        return AnalyzeHeadless(self.root / "ghidra", env)

    def test_a_run_writes_the_named_log_with_the_heap_cap_and_the_decompile_limit(self) -> None:
        runner = self.runner(REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS="45")
        command = runner.command(self.project, "game", "-import", "/x/Game.exe")
        self.assertEqual(runner.run(command, self.log), 0)
        self.assertIn("analyzeHeadless ran", self.log.read_text())
        self.assertEqual((self.root / "args").read_text().split()[:3],
                         [str(self.project), "game", "-import"])  # fmt: skip
        self.assertEqual((self.root / "env").read_text().split(), ["4G", "45"])

    def test_the_heap_cap_is_a_setting(self) -> None:
        runner = self.runner(REA_GHIDRA_MAXMEM="6000M")
        runner.run(runner.command(self.project, "game"), self.log)
        self.assertEqual((self.root / "env").read_text().split(), ["6000M"])

    def test_a_failed_run_names_the_log_unless_the_caller_reads_the_exit_itself(self) -> None:
        runner = self.runner("fail")
        command = runner.command(self.project, "game")
        with self.assertRaisesRegex(GhidraError, f"exited with 3; see {self.log}"):
            runner.run(command, self.log)
        self.assertEqual(runner.run(command, self.log, check=False), 3)

    def test_past_the_limit_the_whole_tree_is_stopped_and_the_log_named(self) -> None:
        runner = self.runner("hang", REA_GHIDRA_IMPORT_TIMEOUT_SECONDS="1")
        started = time.monotonic()
        with self.assertRaisesRegex(GhidraError, rf"ran past 1s .*{self.log}"):
            runner.run(runner.command(self.project, "game"), self.log)
        self.assertLess(time.monotonic() - started, 15)
        child = int((self.root / "child").read_text())
        for _ in range(50):
            if not alive(child):
                break
            time.sleep(0.1)
        self.assertFalse(alive(child), "the analyzer's child outlived the timeout")

    def test_a_dotted_project_path_is_refused_before_ghidra_starts(self) -> None:
        runner = self.runner()
        project = self.root / ".claude" / "worktrees" / "x" / "ghidra"
        with self.assertRaisesRegex(GhidraError, r"'\.claude' starts with '\.'"):
            runner.run(runner.command(project, "game"), self.log)
        self.assertFalse((self.root / "args").exists())
        self.assertFalse(project.exists())

    def test_a_name_with_a_dot_inside_is_no_dotted_component(self) -> None:
        self.assertIsNone(ghidra_headless.dotted_component(Path("/w/ghidra/Game.exe")))
        self.assertEqual(ghidra_headless.dotted_component(Path("/w/.cache/p")), ".cache")

    def test_the_module_level_run_finds_the_install_from_the_command(self) -> None:
        os.environ["STUB_DIR"] = str(self.root)
        self.addCleanup(os.environ.pop, "STUB_DIR")
        command = AnalyzeHeadless(self.root / "ghidra").command(self.project, "game")
        self.assertEqual(ghidra_headless.run(command, self.log), 0)
        self.assertTrue((self.root / "args").is_file())


class SettingsTests(unittest.TestCase):
    def test_an_import_takes_a_loader_and_its_options_in_ghidras_order(self) -> None:
        self.assertEqual(
            ghidra_headless.import_arguments("/g/main.dol"), ["-import", "/g/main.dol"]
        )
        self.assertEqual(
            ghidra_headless.import_arguments(
                Path("/g/main.dol"), "GameCubeLoader", [("autoloadMaps", "false")]
            ),
            [
                "-import",
                "/g/main.dol",
                "-loader",
                "GameCubeLoader",
                "-loader-autoloadMaps",
                "false",
            ],
        )
        with self.assertRaisesRegex(GhidraError, "need a loader"):
            ghidra_headless.import_arguments("x", None, [("autoloadMaps", "false")])
        with self.assertRaisesRegex(GhidraError, "autoloadMaps"):
            ghidra_headless.import_arguments("x", "L", [("-bad", "1")])

    def test_the_time_limit_is_a_setting_with_a_default(self) -> None:
        self.assertEqual(ghidra_headless.timeout_seconds({}), 3600)
        setting = ghidra_headless.TIMEOUT_SETTING
        self.assertEqual(ghidra_headless.timeout_seconds({setting: "120"}), 120)
        for bad in ("0", "-5", "1h"):
            with self.assertRaisesRegex(GhidraError, setting):
                ghidra_headless.timeout_seconds({setting: bad})


@unittest.skipIf(sys.platform == "win32", "POSIX signals")
class BoundedTests(unittest.TestCase):
    def test_a_program_that_ignores_sigterm_is_killed_after_the_grace(self) -> None:
        script = "trap '' TERM; sleep 60"
        with tempfile.TemporaryFile("w+") as log:
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                bounded.run(["bash", "-c", script], Path.cwd(), log, 0.3, grace=0.3)
        self.assertLess(time.monotonic() - started, 10)


if __name__ == "__main__":
    unittest.main()
