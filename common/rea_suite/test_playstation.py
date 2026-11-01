"""Console project and optional-loader regression checks (no games or emulators)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rea_suite import ghidra, playstation


def psx() -> bytes:
    data = bytearray(4096)
    data[:8] = b"PS-X EXE"
    struct.pack_into("<4I", data, 0x10, 0x80010000, 0, 0x80010000, 2048)
    struct.pack_into("<2I", data, 2048, 0x03E00008, 0)
    return bytes(data)


def elf(flags: int = 0x20924001) -> bytes:
    data = bytearray(4096 + 32)
    data[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into(
        "<HHIIIIIHHHHHH", data, 16, 2, 8, 1, 0x100000, 52, 0, flags, 52, 32, 1, 40, 0, 0
    )
    struct.pack_into("<8I", data, 52, 1, 4096, 0x100000, 0x100000, 32, 32, 5, 4096)
    struct.pack_into("<3I", data, 4096, 0x2408002A, 0x03E00008, 0)
    return bytes(data)


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.disc = self.root / "disc"
        self.disc.mkdir()

    def args(self, **changes):
        values = {
            "caller_cwd": self.root,
            "input": self.disc,
            "project": self.root / "project",
            "plan": False,
            "ghidra": False,
            "max_files": 100,
            "timeout": 30,
            "boot": None,
        }
        return argparse.Namespace(**(values | changes))

    def test_ps1_boot_and_original_unchanged(self):
        boot = self.disc / "SLUS_000.00"
        boot.write_bytes(psx())
        (self.disc / "SYSTEM.CNF").write_text("BOOT = cdrom:\\slus_000.00;1\n")
        result = playstation.prepare(self.args())
        self.assertEqual((result["system"], result["boot"]), ("ps1", boot.name))
        self.assertEqual(result["boot_executable"]["entry"], "0x80010000")
        self.assertEqual(boot.read_bytes(), psx())
        self.assertEqual(
            json.loads((self.root / "project/project.json").read_text())["status"], "prepared"
        )
        with self.assertRaisesRegex(ValueError, "already exists"):
            playstation.prepare(self.args())

    def test_ps2_boot_and_iop_separate(self):
        (self.disc / "SLES_000.00").write_bytes(elf())
        (self.disc / "MODULE.IRX").write_bytes(elf(0))
        (self.disc / "SYSTEM.CNF").write_text("BOOT2 = cdrom0:\\SLES_000.00;1\n")
        result = playstation.inventory(self.disc, 100)
        self.assertEqual(result["boot_executable"]["kind"], "ps2-ee")
        self.assertEqual({p["kind"] for p in result["executables"]}, {"ps2-ee", "mips-elf"})
        self.assertIsNone(playstation.inventory(self.disc / "MODULE.IRX", 100)["system"])

    def test_no_guessed_boot_with_multiple_executables(self):
        for n in ("one", "two"):
            (self.disc / n).write_bytes(psx())
        self.assertIsNone(playstation.inventory(self.disc, 100)["boot"])
        self.assertEqual(playstation.inventory(self.disc, 100, "TWO;1")["boot"], "two")

    def test_plan_no_writes_or_execution(self):
        with patch.object(playstation.subprocess, "run", side_effect=AssertionError("executed")):
            self.assertFalse(playstation.prepare(self.args(plan=True))["writes"])
        self.assertFalse((self.root / "project").exists())

    def test_paths_and_inventory_bounds(self):
        (self.disc / "SYSTEM.CNF").write_text("BOOT2=cdrom0:\\..\\outside;1")
        with self.assertRaisesRegex(ValueError, "unsafe boot"):
            playstation.inventory(self.disc, 100)
        (self.disc / "other").write_bytes(b"asset")
        with self.assertRaisesRegex(ValueError, "more than"):
            playstation.inventory(self.disc, 1)
        with self.assertRaisesRegex(ValueError, "outside the input"):
            playstation.prepare(self.args(project=self.disc / "project"))

    def test_cue_tracks_hashed_scope(self):
        cue = self.root / "disc.cue"
        track = self.root / "track.bin"
        track.write_bytes(b"track")
        cue.write_text('FILE "track.bin" BINARY\n TRACK 01 MODE2/2352\n')
        self.assertEqual(playstation.image_sources(cue), [cue, track])
        cue.write_text('FILE "../outside.bin" BINARY\n')
        with self.assertRaisesRegex(ValueError, "inside the image directory"):
            playstation.image_sources(cue)

    def test_image_sector_detection(self):
        for size, offset, kind in [(2048, 0, "iso"), (2352, 24, "cd"), (2352, 16, "cd")]:
            data = bytearray(17 * size)
            start = 16 * size + offset
            data[start : start + 7] = b"\x01CD001\x01"
            image = self.root / "disc.bin"
            image.write_bytes(data)
            self.assertEqual(playstation.image_kind(image), kind)
        with self.assertRaisesRegex(ValueError, "chdman"):
            playstation.image_kind(self.root / "disc.chd")

    def test_tool_timeout(self):
        with (
            (self.root / "timeout.log").open("w") as log,
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            playstation.run(
                [sys.executable, "-c", "import time; time.sleep(60)"], self.root, log, 0.05
            )

    def test_import_failure_recorded(self):
        (self.disc / "boot").write_bytes(elf())
        error = subprocess.CalledProcessError(1, "analyzeHeadless")
        with (
            patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": str(self.root)}),
            patch.object(playstation, "run", side_effect=error),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            playstation.prepare(self.args(ghidra=True))
        manifest = json.loads((self.root / "project/project.json").read_text())
        self.assertEqual(manifest["status"], "incomplete")
        self.assertIn("error", manifest)
        self.assertIn("r5900:LE:32:default", manifest["ghidra_command"])


@unittest.skipUnless(os.environ.get("REA_PLAYSTATION_INTEGRATION") == "1", "opt-in Ghidra smoke")
class RealGhidraTests(unittest.TestCase):
    def test_console_loaders_mapping_and_exports(self):
        work = Path(__file__).resolve().parents[2] / "work/playstation-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            root = Path(tmp)
            for system, blob, entry in [("ps1", psx(), "80010000"), ("ps2", elf(), "00100000")]:
                target = root / f"{system}.exe"
                target.write_bytes(blob)
                args = argparse.Namespace(
                    caller_cwd=root,
                    input=target,
                    project=root / system,
                    plan=False,
                    ghidra=True,
                    max_files=100,
                    timeout=90,
                    boot=None,
                )
                result = playstation.prepare(args)
                self.assertTrue(Path(result["ghidra_project"]).is_file())
                self.assertIn(entry, (root / system / "analysis/functions.tsv").read_text())
                self.assertNotIn("no function", (root / system / "analysis/entry.c").read_text())
                self.assertNotIn(
                    "decompile failed", (root / system / "analysis/entry.c").read_text()
                )
                print(system, result.get("warnings", []))


class OptionalExtensionTests(unittest.TestCase):
    def test_legacy_alias_migrates_and_keeps_logical_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "Ghidra/Extensions/psx"
            old.mkdir(parents=True)
            (root / "Ghidra/application.properties").write_text("application.version=12.1.4\n")
            (old / "extension.properties").write_text("name=ghidra_psx_ldr\nversion=12.1.4\n")
            (old / "payload").write_bytes(b"unchanged extension")
            marker = {"tag": "test", "ghidra": "12.1.4", "source": "release", "repo": "test/repo"}
            (old / ghidra.MARKER).write_text(json.dumps(marker))
            ghidra.normalize_location(root, "psx", ghidra.installed(root)["psx"])
            current = ghidra.installed(root)
            self.assertEqual(set(current), {"psx"})
            self.assertEqual(current["psx"]["directory"], "ghidra_psx_ldr")
            self.assertEqual(
                (old.parent / "ghidra_psx_ldr/payload").read_bytes(), b"unchanged extension"
            )
            self.assertFalse(old.exists())
            ghidra.normalize_location(root, "psx", current["psx"])
            (old.parent / "unconfigured").mkdir()
            self.assertEqual(ghidra.sync(root, {}), [])
            self.assertFalse((old.parent / "ghidra_psx_ldr").exists())
            self.assertTrue((old.parent / "unconfigured").exists())

    def test_release_install_keeps_upstream_module_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Ghidra/Extensions").mkdir(parents=True)
            archive = root / "release.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr(
                    "ghidra_psx_ldr/extension.properties", "name=ghidra_psx_ldr\nversion=12.1.4\n"
                )
                z.writestr("ghidra_psx_ldr/lib/ghidra_psx_ldr.jar", b"fixture")
            release = {
                "tag_name": "test",
                "assets": [{"name": "release.zip", "browser_download_url": "unused"}],
            }
            spec = {"github": "test/repo", "asset": r"^release\.zip$"}
            with (
                patch.object(ghidra.github, "releases", return_value=[release]),
                patch.object(
                    ghidra.github,
                    "download",
                    side_effect=lambda _, dest: shutil.copyfile(archive, dest),
                ),
            ):
                ghidra._sync_one(root, "12.1.4", "psx", spec, None, False)
                ghidra._sync_one(root, "12.1.4", "psx", spec, ghidra.installed(root)["psx"], False)
            self.assertTrue(
                (root / "Ghidra/Extensions/ghidra_psx_ldr/lib/ghidra_psx_ldr.jar").is_file()
            )
            self.assertEqual(ghidra.installed(root)["psx"]["source"], "release")

    def test_case_only_module_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "Ghidra/Extensions/psx"
            old.mkdir(parents=True)
            (old / "extension.properties").write_text("name=PSX\nversion=12.1.4\n")
            marker = {"tag": "test", "ghidra": "12.1.4", "source": "release"}
            (old / ghidra.MARKER).write_text(json.dumps(marker))
            ghidra.normalize_location(root, "psx", marker)
            self.assertEqual([p.name for p in old.parent.iterdir()], ["PSX"])
            self.assertEqual(ghidra.installed(root)["psx"]["directory"], "PSX")

    def test_module_basename_takes_precedence_over_display_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "kaiju"
            (root / "lib").mkdir(parents=True)
            (root / "extension.properties").write_text("name=CERT Kaiju\n")
            (root / "lib/kaiju.jar").write_bytes(b"fixture")
            self.assertEqual(ghidra.module_name(root), "kaiju")

    def test_module_name_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "extension.properties").write_text("name=../outside\n")
            with self.assertRaises(LookupError):
                ghidra.module_name(root)

    def test_selection_and_deselection_preserve_installed_copy(self):
        specs = {"base": {}, "psx": {"component": "playstation"}}
        with patch.object(ghidra.components, "selected", return_value=[]):
            self.assertEqual(list(ghidra.selected_specs(specs)), ["base"])
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "Ghidra/Extensions/psx").mkdir(parents=True)
                (root / "Ghidra/application.properties").write_text("application.version=12.1.4\n")
                marker = root / "Ghidra/Extensions/psx" / ghidra.MARKER
                marker.write_text("{}")
                with patch.object(ghidra, "_sync_one") as sync:
                    self.assertEqual(ghidra.sync(root, specs), [])
                self.assertEqual([c.args[2] for c in sync.call_args_list], ["base"])
                self.assertTrue(marker.exists())
        with patch.object(ghidra.components, "selected", return_value=["playstation"]):
            self.assertEqual(set(ghidra.selected_specs(specs)), {"base", "psx"})


if __name__ == "__main__":
    unittest.main()
