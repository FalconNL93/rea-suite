"""Ghidra extensions pinned to a commit: built from that commit's source, no release lookup."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rea_suite import ghidra, github

COMMIT = "60bae5199fdada5b3b825741a94bfbbe04cb7a5f"


class CommitPinTests(unittest.TestCase):
    def test_source_url_of_a_commit_and_of_a_tag(self):
        self.assertEqual(
            github.source_url("owner/repo", COMMIT),
            f"https://github.com/owner/repo/archive/{COMMIT}.tar.gz",
        )
        self.assertEqual(
            github.source_url("owner/repo", "v1.0"),
            "https://github.com/owner/repo/archive/refs/tags/v1.0.tar.gz",
        )

    def test_a_commit_pin_builds_that_commit_without_asking_for_releases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Ghidra/Extensions").mkdir(parents=True)
            built = root / "built.zip"
            with zipfile.ZipFile(built, "w") as z:
                z.writestr("ghidra-lx-loader/extension.properties", "name=LxLoader\nversion=@x@\n")
                z.writestr("ghidra-lx-loader/lib/ghidra-lx-loader.jar", b"fixture")
            spec = {"github": "owner/ghidra-lx-loader", "commit": COMMIT, "build": True}
            with (
                patch.object(ghidra.github, "releases", side_effect=AssertionError("no lookup")),
                patch.object(ghidra.github, "release", side_effect=AssertionError("no lookup")),
                patch.object(ghidra, "_build", return_value=built) as build,
            ):
                ghidra._sync_one(root, "12.1.4", "lxloader", spec, None, False)
                ghidra._sync_one(
                    root, "12.1.4", "lxloader", spec, ghidra.installed(root)["lxloader"], False
                )
            self.assertEqual(build.call_count, 1)
            self.assertEqual(build.call_args.args[2], COMMIT)
            marker = ghidra.installed(root)["lxloader"]
            self.assertEqual((marker["tag"], marker["source"]), (COMMIT, "built"))
            props = root / "Ghidra/Extensions/ghidra-lx-loader/extension.properties"
            self.assertIn("version=12.1.4", props.read_text())


if __name__ == "__main__":
    unittest.main()
