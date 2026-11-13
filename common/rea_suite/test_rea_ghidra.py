"""bin/rea-ghidra against a stand-in analyzeHeadless that records its arguments: a port's own
project folder, logs under it, no re-import that would lose the project's names, and no project
Ghidra would refuse. The limits of every run are test_ghidra_headless's."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "bin" / "rea-ghidra"

# Records each call; -import adds the program to the project's index, -postScript with an output
# file writes its script's name and arguments there, as the real query scripts write their results.
STUB = r"""#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "$STUB_CALLS"
project=$1 name=$2; shift 2
args=("$@")
for i in "${!args[@]}"; do
  case "${args[$i]}" in
    -import)
      mkdir -p "$project/$name.rep/idata"
      printf 'VERSION=1\n/\n  00000000:%s:1\n' "$(basename "${args[$((i + 1))]}")" \
        >> "$project/$name.rep/idata/~index.dat"
      touch "$project/$name.gpr" ;;
    -postScript)
      out="${args[$((i + 2))]:-}"
      [[ -z "$out" ]] || echo "${args[*]:$((i + 1))}" > "$out" ;;
  esac
done
"""


class ReaGhidra(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        support = self.root / "ghidra" / "support"
        support.mkdir(parents=True)
        (support / "analyzeHeadless").write_text(STUB)
        (support / "analyzeHeadless").chmod(0o755)
        self.calls = self.root / "calls.txt"
        self.binary = self.root / "game" / "Game.exe"
        self.binary.parent.mkdir()
        self.binary.write_bytes(b"MZ")
        self.project = self.root / "port" / "re" / "ghidra"

    def run_tool(self, *args: str) -> subprocess.CompletedProcess:
        # Without REA_SUITE_COMPUTED: under `rea-suite check` it lists GHIDRA_INSTALL_DIR, and
        # common/env.sh would drop the stand-in for the suite's own Ghidra.
        env = {
            **{k: v for k, v in os.environ.items() if k != "REA_SUITE_COMPUTED"},
            "GHIDRA_INSTALL_DIR": str(self.root / "ghidra"),
            "STUB_CALLS": str(self.calls),
            "REA_SUITE_DISTROBOX": "",
        }
        return subprocess.run(
            [str(TOOL), *args], capture_output=True, text=True, env=env, cwd=self.root, check=False
        )

    def call_lines(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_analyze_imports_once_into_the_ports_own_project(self) -> None:
        first = self.run_tool(
            "analyze", "--project", str(self.project), "--name", "game", str(self.binary)
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(
            self.run_tool("analyze", "--project", str(self.project), str(self.binary)).returncode, 0
        )
        (call,) = self.call_lines()
        self.assertTrue(call.startswith(f"{self.project} game -import {self.binary}"), call)
        self.assertNotIn("-overwrite", call)
        self.assertTrue((self.project / "logs" / "analyze.log").is_file())

    def test_force_analyzes_the_program_in_place_and_never_imports_over_it(self) -> None:
        self.run_tool("analyze", "--project", str(self.project), "--name", "game", str(self.binary))
        forced = self.run_tool(
            "analyze", "--force", "--project", str(self.project), str(self.binary)
        )
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertTrue(
            self.call_lines()[1].startswith(f"{self.project} game -process Game.exe -scriptPath")
        )
        self.assertNotIn("-overwrite", self.calls.read_text())

    def test_every_analysis_clears_alignment_after_data(self) -> None:
        self.run_tool("analyze", "--project", str(self.project), "--name", "game", str(self.binary))
        self.run_tool("analyze", "--force", "--project", str(self.project), str(self.binary))
        imported, forced = self.call_lines()
        for call in (imported, forced):
            self.assertIn(f"-scriptPath {ROOT}/common/ghidra_scripts", call)
            self.assertTrue(call.endswith("-postScript ClearDataAlignment.java"), call)
        self.assertTrue((ROOT / "common" / "ghidra_scripts" / "ClearDataAlignment.java").is_file())

    def test_queries_are_read_only_and_take_options_after_the_binary(self) -> None:
        self.run_tool("analyze", "--project", str(self.project), "--name", "game", str(self.binary))
        out = self.root / "out" / "functions.tsv"
        done = self.run_tool(
            "functions", "--project", str(self.project), "Game.exe", "-o", str(out)
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "")
        self.assertTrue(out.read_text().startswith("ExportFunctions.java "))
        call = self.call_lines()[-1]
        self.assertIn("-process Game.exe -noanalysis -readOnly", call)
        self.assertTrue((self.project / "logs" / "ExportFunctions.log").is_file())

    def test_decomp_passes_the_addresses_and_a_dashed_text_after_double_dash(self) -> None:
        self.run_tool("analyze", "--project", str(self.project), "--name", "game", str(self.binary))
        done = self.run_tool("decomp", "--project", str(self.project), "Game.exe", "0x401000")
        self.assertIn("DecompileAt.java", done.stdout)
        self.assertTrue(done.stdout.rstrip().endswith("0x401000"))
        done = self.run_tool("xrefs", "--project", str(self.project), "Game.exe", "--", "-server")
        self.assertTrue(done.stdout.rstrip().endswith("-server"), done.stderr)

    def test_a_program_missing_from_the_project_is_named(self) -> None:
        self.project.mkdir(parents=True)
        done = self.run_tool("functions", "--project", str(self.project), "Other.exe")
        self.assertEqual(done.returncode, 1)
        self.assertIn("no program Other.exe", done.stderr)
        self.assertEqual(self.call_lines(), [])

    def test_a_project_under_a_dotted_folder_is_refused_with_the_reason(self) -> None:
        project = self.root / ".claude" / "worktrees" / "port" / "ghidra"
        done = self.run_tool("analyze", "--project", str(project), str(self.binary))
        self.assertEqual(done.returncode, 1)
        self.assertIn("starts with '.'", done.stderr)
        self.assertEqual(self.call_lines(), [])
        self.assertFalse(project.exists())

    def test_force_is_refused_for_queries(self) -> None:
        done = self.run_tool("decomp", "--force", str(self.binary), "0x401000")
        self.assertEqual(done.returncode, 1)
        self.assertIn("--force is for analyze", done.stderr)


if __name__ == "__main__":
    unittest.main()
