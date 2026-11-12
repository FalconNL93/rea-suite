"""Installer pieces: 7z archives, AppDistrib releases, components' uv tools (no downloads)."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import appdistrib, archive

ROOT = Path(__file__).resolve().parents[2]


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


MANIFESTS = {
    "pcsx-redux/dev-linux-x64/manifest.json": {"builds": [{"id": 9}, {"id": 12}]},
    "pcsx-redux/dev-linux-x64/manifest-12.json": {
        "path": "/storage/assets/aa/bb/PCSX-Redux-1234abcd-linux-x86_64.zip",
        "manifest": {"version": "1234abcd"},
    },
}


class AppDistrib(unittest.TestCase):
    def fake_open(self, url: str, timeout: int = 60):
        path = url.removeprefix(f"{appdistrib.BASE}/storage/manifests/")
        return io.BytesIO(json.dumps(MANIFESTS[path]).encode())

    def test_the_newest_build_reads_as_a_release(self) -> None:
        with patch.object(appdistrib, "_open", self.fake_open):
            release = appdistrib.release("pcsx-redux", "dev-linux-x64")
        self.assertEqual(release["tag_name"], "1234abcd")
        self.assertEqual(
            release["assets"],
            [
                {
                    "name": "PCSX-Redux-1234abcd-linux-x86_64.zip",
                    "browser_download_url": "https://distrib.app/storage/assets/aa/bb/"
                    "PCSX-Redux-1234abcd-linux-x86_64.zip",
                }
            ],
        )


class ComponentUvTools(unittest.TestCase):
    def test_both_scripts_install_and_check_components_uv_tools(self) -> None:
        shell = (ROOT / "bin" / "rea-suite").read_text()
        self.assertIn("components values uv-tools", shell)
        self.assertEqual(shell.count("done < <(uv_tool_specs)"), 2)  # setup and doctor
        self.assertIn(
            "Components values uv-tools",
            (ROOT / "platforms" / "windows" / "rea-suite.ps1").read_text(),
        )

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_doctor_checks_the_package_name_of_a_spec(self) -> None:
        name = subprocess.run(
            ["bash", "-c", 'tool="splat64[mips]>=0.50"; echo "${tool%%[[<>=~!]*}"'],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(name, "splat64")


if __name__ == "__main__":
    unittest.main()
