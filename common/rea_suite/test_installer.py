"""Installer pieces: 7z archives (no downloads)."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import archive


class SevenZip(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @unittest.skipUnless(archive.seven_zip(), "7-Zip not installed")
    def test_a_7z_archive_is_extracted_with_strip(self) -> None:
        source = self.root / "src" / "top" / "bin"
        source.mkdir(parents=True)
        (source / "tool.exe").write_bytes(b"MZ")
        packed = self.root / "tool.7z"
        subprocess.run(
            [archive.seven_zip(), "a", "-bso0", str(packed), "top"],
            cwd=self.root / "src",
            check=True,
        )
        dest = self.root / "out"
        archive.extract(packed, dest, 1)
        self.assertEqual((dest / "bin" / "tool.exe").read_bytes(), b"MZ")

    def test_a_7z_archive_without_7_zip_names_the_fix(self) -> None:
        with (
            patch.object(archive.shutil, "which", return_value=None),
            patch.object(archive.os, "name", "posix"),
            self.assertRaisesRegex(LookupError, "rea-suite setup"),
        ):
            archive.extract(self.root / "tool.7z", self.root / "out", 0)


if __name__ == "__main__":
    unittest.main()
