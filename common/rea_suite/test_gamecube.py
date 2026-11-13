"""GameCube and Wii: DOL, REL and disc image headers, the file table, the backend choice and the
loader check, on synthetic files built here (no game bytes).

Opt-in with a real file, read-only: REA_GAMECUBE_SAMPLE=<main.dol, a .rel or a disc image> runs
`info` on it (RVZ, WBFS and Wii discs need nod-rs, component gamecube).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import extcheck, gamecube

TEXT_ADDR, DATA_ADDR, ENTRY = 0x80003100, 0x80005000, 0x80003100
BANNER = b"<< Dolphin SDK - OS\trelease build: Apr  5 2004 04:14:49 (0x2301) >>\0"


def dol() -> bytes:
    """One text and one data section, bss behind them, an SDK banner in the data."""
    data = bytearray(0x100)
    text = bytes([0x94, 0x21, 0xFF, 0xF0, 0x4E, 0x80, 0x00, 0x20])  # stwu r1,-16(r1); blr
    payload = BANNER.ljust(0x60, b"\0")
    struct.pack_into(">I", data, 0x00, 0x100)  # text0 offset
    struct.pack_into(">I", data, 0x1C, 0x120)  # data0 offset
    struct.pack_into(">I", data, 0x48, TEXT_ADDR)
    struct.pack_into(">I", data, 0x64, DATA_ADDR)
    struct.pack_into(">I", data, 0x90, 0x20)
    struct.pack_into(">I", data, 0xAC, len(payload))
    struct.pack_into(">3I", data, 0xD8, 0x80006000, 0x400, ENTRY)
    return bytes(data) + text.ljust(0x20, b"\0") + payload


def rel(version: int = 3) -> bytes:
    """A module with a text and a bss section, importing from the DOL (0) and itself (7)."""
    header = {1: 0x40, 2: 0x48, 3: 0x4C}[version]
    sections_at = header
    text_at = sections_at + 3 * 8
    imp_at = text_at + 0x10
    relocs_at = imp_at + 16
    data = bytearray(relocs_at + 8 * 5)
    struct.pack_into(
        ">9I", data, 0, 7, 0, 0, 3, sections_at, 0, 0, version, 0x40
    )  # id 7, three sections, bss 0x40
    struct.pack_into(">3I", data, 0x24, relocs_at, imp_at, 16)
    struct.pack_into(">4B", data, 0x30, 1, 1, 0, 2)
    struct.pack_into(">3I", data, 0x34, 0x0, 0x4, 0)
    if version >= 2:
        struct.pack_into(">2I", data, 0x40, 32, 32)
    if version >= 3:
        struct.pack_into(">I", data, 0x48, relocs_at)
    struct.pack_into(">2I", data, sections_at + 8, text_at | 1, 0x10)  # section 1: code
    struct.pack_into(">2I", data, sections_at + 16, 0, 0x40)  # section 2: bss
    struct.pack_into(">2I2I", data, imp_at, 0, relocs_at, 7, relocs_at + 24)
    entries = [
        (0, gamecube.REL_SECTION, 1, 0),
        (4, 10, 0, 0x80003100),  # R_PPC_REL24 into the DOL
        (0, gamecube.REL_END, 0, 0),
        (8, 6, 1, 0),  # R_PPC_ADDR16_HA, own module
        (0, gamecube.REL_END, 0, 0),
    ]
    for i, (offset, kind, section, addend) in enumerate(entries):
        struct.pack_into(">HBBI", data, relocs_at + i * 8, offset, kind, section, addend)
    return bytes(data)


def fst(entries: list[tuple[str, int, int, int]]) -> bytes:
    """(name, is_dir, a, b) after the root; names packed behind the table."""
    names = bytearray()
    table = bytearray(struct.pack(">B3sII", 1, b"\0\0\0", 0, len(entries) + 1))
    for name, is_dir, a, b in entries:
        table += struct.pack(">II", (is_dir << 24) | len(names), a) + struct.pack(">I", b)
        names += name.encode() + b"\0"
    return bytes(table + names)


def gc_iso() -> bytes:
    """A GameCube disc: header, bi2 with the region, apploader date, the DOL and a file table
    with /opening.bnr, /rels/a.rel and /rels/b.rel."""
    main = dol()
    dol_at, fst_at = 0x3000, 0x4000
    table = fst(
        [
            ("opening.bnr", 0, 0x5000, 0x20),
            ("rels", 1, 0, 5),  # the end index is exclusive
            ("a.rel", 0, 0x5020, 0x10),
            ("b.rel", 0, 0x5030, 0x10),
        ]
    )
    data = bytearray(0x5040)
    data[0:6] = b"GTSE01"
    data[6], data[7] = 0, 1
    struct.pack_into(">I", data, gamecube.GC_MAGIC_AT, gamecube.GC_MAGIC)
    data[0x20:0x2A] = b"Test Title"
    struct.pack_into(">3I", data, 0x420, dol_at, fst_at, len(table))
    struct.pack_into(">I", data, 0x440 + 0x18, 1)
    data[0x2440:0x244A] = b"2004/04/05"
    data[dol_at : dol_at + len(main)] = main
    data[fst_at : fst_at + len(table)] = table
    return bytes(data)


def wii_iso() -> bytes:
    data = bytearray(0x40000 + 0x40 + 16)
    data[0:6] = b"RTSE01"
    struct.pack_into(">I", data, gamecube.WII_MAGIC_AT, gamecube.WII_MAGIC)
    data[0x20:0x2C] = b"Wii Test 123"
    struct.pack_into(">2I", data, 0x40000, 2, (0x40000 + 0x40) >> 2)
    struct.pack_into(">4I", data, 0x40040, 0x50000 >> 2, 1, 0xF800000 >> 2, 0)
    return bytes(data)


def written(tmp: str, name: str, data: bytes) -> Path:
    path = Path(tmp) / name
    path.write_bytes(data)
    return path


class Dol(unittest.TestCase):
    def test_sections_entry_bss_and_the_sdk_banner_are_read(self):
        found = gamecube.dol_info(dol())
        self.assertEqual(found["entry"], "0x80003100")
        self.assertEqual(
            [(s["name"], s["address"], s["file_offset"]) for s in found["sections"]],
            [("text0", "0x80003100", "0x100"), ("data0", "0x80005000", "0x120")],
        )
        self.assertEqual(found["bss"], {"address": "0x80006000", "size": "0x400"})
        self.assertFalse(found["uses_mem2"])
        self.assertEqual(
            found["sdk"], ["Dolphin SDK - OS release build: Apr 5 2004 04:14:49 (0x2301)"]
        )

    def test_a_section_outside_the_file_or_memory_is_refused(self):
        broken = bytearray(dol())
        struct.pack_into(">I", broken, 0x90, 0x10000)
        with self.assertRaisesRegex(ValueError, "outside the file"):
            gamecube.parse_dol(bytes(broken))
        broken = bytearray(dol())
        struct.pack_into(">I", broken, 0x48, 0x00003100)
        with self.assertRaisesRegex(ValueError, "outside console memory"):
            gamecube.parse_dol(bytes(broken))

    def test_an_entry_outside_the_text_is_refused(self):
        broken = bytearray(dol())
        struct.pack_into(">I", broken, 0xE0, DATA_ADDR)
        with self.assertRaisesRegex(ValueError, "no text section"):
            gamecube.parse_dol(bytes(broken))


class Rel(unittest.TestCase):
    def test_every_version_gives_sections_and_imports_with_their_relocations(self):
        for version in (1, 2, 3):
            found = gamecube.rel_info(rel(version))
            self.assertEqual(found["module_id"], 7)
            self.assertEqual(found["version"], version)
            self.assertEqual(
                [(s["index"], s["executable"], s["bss"]) for s in found["sections"]],
                [(1, True, False), (2, False, True)],
            )
            self.assertEqual(
                found["imports"],
                [{"module": 0, "relocations": 1}, {"module": 7, "relocations": 1}],
            )
            self.assertEqual(found["prolog"], {"section": 1, "offset": "0x0"})
        relocations_at = 0x4C + 3 * 8 + 0x10 + 16
        self.assertEqual(gamecube.rel_info(rel(3))["fix_size"], relocations_at)

    def test_an_unknown_version_or_a_table_outside_the_file_is_refused(self):
        broken = bytearray(rel())
        struct.pack_into(">I", broken, 0x1C, 9)
        with self.assertRaisesRegex(ValueError, "not a REL"):
            gamecube.rel_info(bytes(broken))
        broken = bytearray(rel())
        struct.pack_into(">I", broken, 0x10, 0x10000)
        with self.assertRaisesRegex(ValueError, "section table"):
            gamecube.rel_info(bytes(broken))

    def test_a_relocation_list_without_its_end_is_refused(self):
        broken = bytearray(rel())
        broken[-6] = 6  # the last R_DOLPHIN_END becomes a relocation
        with self.assertRaisesRegex(ValueError, "R_DOLPHIN_END"):
            gamecube.rel_info(bytes(broken))


class Disc(unittest.TestCase):
    def test_a_gamecube_iso_gives_its_header_main_dol_and_file_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            found = gamecube.info(written(tmp, "game.iso", gc_iso()))
        self.assertEqual(
            (found["platform"], found["game_id"], found["title"], found["version"]),
            ("gamecube", "GTSE01", "Test Title", 1),
        )
        self.assertEqual((found["region"], found["apploader_date"]), ("NTSC-U", "2004/04/05"))
        self.assertEqual(found["main_dol"]["entry"], "0x80003100")
        self.assertEqual(
            found["files"],
            [
                {"path": "/opening.bnr", "offset": "0x5000", "size": 0x20},
                {"path": "/rels/a.rel", "offset": "0x5020", "size": 0x10},
                {"path": "/rels/b.rel", "offset": "0x5030", "size": 0x10},
            ],
        )
        self.assertEqual(found["rels"], ["/rels/a.rel", "/rels/b.rel"])
        self.assertEqual(found["read_with"], "rea-suite")

    def test_a_file_table_whose_directory_runs_past_its_end_is_refused(self):
        table = fst([("rels", 1, 0, 9), ("a.rel", 0, 0, 1)])
        with self.assertRaisesRegex(ValueError, "ends outside the table"):
            gamecube.parse_fst(table, 0)

    def test_a_wii_iso_without_nod_gives_its_header_and_partitions(self):
        absent = Fake("nod-rs", available=False)
        with tempfile.TemporaryDirectory() as tmp:
            path = written(tmp, "game.iso", wii_iso())
            disc = gamecube.open_disc(path, [gamecube.GcmBackend(), absent])
        self.assertEqual(
            (disc.platform, disc.game_id, disc.title), ("wii", "RTSE01", "Wii Test 123")
        )
        self.assertEqual(
            disc.partitions,
            [
                {"group": 0, "kind": "Update", "offset": "0x50000"},
                {"group": 0, "kind": "Data", "offset": "0xf800000"},
            ],
        )
        self.assertIn("encrypted", disc.notes[0])
        self.assertEqual(absent.opened, [])

    def test_containers_and_wii_discs_go_to_nod_and_a_gamecube_iso_does_not(self):
        nod = Fake("nod-rs")
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in [("a.rvz", b"RVZ\x01" + bytes(60)), ("b.iso", wii_iso())]:
                self.assertEqual(
                    gamecube.open_disc(written(tmp, name, data), [None, nod]).backend, "fake"
                )
            gamecube.open_disc(written(tmp, "c.iso", gc_iso()), [gamecube.GcmBackend(), nod])
        self.assertEqual([p.name for p in nod.opened], ["a.rvz", "b.iso"])

    def test_a_container_without_nod_says_what_to_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = written(tmp, "game.wbfs", b"WBFS" + bytes(60))
            with self.assertRaisesRegex(ValueError, "WBFS needs nod-rs: select component gamecube"):
                gamecube.open_disc(path, [gamecube.GcmBackend(), Fake("nod-rs", available=False)])

    @unittest.skipUnless(
        gamecube.NodBackend().available(), "nod-rs not installed (component gamecube)"
    )
    def test_nod_reads_the_same_gamecube_iso(self):
        with tempfile.TemporaryDirectory() as tmp:
            disc = gamecube.NodBackend().open(written(tmp, "game.iso", gc_iso()))
        self.assertEqual(
            (disc.platform, disc.game_id, disc.title), ("gamecube", "GTSE01", "Test Title")
        )
        self.assertEqual(
            [f["path"] for f in disc.files], ["/opening.bnr", "/rels/a.rel", "/rels/b.rel"]
        )
        self.assertEqual(gamecube.dol_info(disc.main_dol)["entry"], "0x80003100")


class Fake:
    def __init__(self, name: str, available: bool = True):
        self.name, self._available, self.opened = name, available, []

    def available(self) -> bool:
        return self._available

    def open(self, path: Path) -> gamecube.Disc:
        self.opened.append(path)
        return gamecube.Disc("wii", "X", "", "", 0, 0, backend="fake")


class Command(unittest.TestCase):
    def test_info_picks_the_reader_by_the_file_and_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            written(tmp, "main.dol", dol())
            written(tmp, "a.rel", rel())
            written(tmp, "unnamed", rel())
            for name, kind in [("main.dol", "dol"), ("a.rel", "rel"), ("unnamed", "rel")]:
                gamecube.main(["--caller-cwd", tmp, "info", name, "-o", "out.json"])
                self.assertEqual(json.loads((Path(tmp) / "out.json").read_text())["kind"], kind)

    def test_something_else_is_refused_with_the_dol_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            written(tmp, "x.bin", bytes(0x200))
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                gamecube.main(["--caller-cwd", tmp, "info", "x.bin"])
        self.assertEqual(stop.exception.code, 1)
        self.assertIn("neither a disc image, a DOL nor a REL", err.getvalue())


def fake_install(tmp: str, version: str = "12.1.4", files: bool = True) -> Path:
    root = Path(tmp)
    (root / "Ghidra").mkdir()
    (root / "Ghidra" / "application.properties").write_text("application.version=12.1.4\n")
    ext = root / "Ghidra" / "Extensions" / gamecube.LOADER
    (ext / "lib").mkdir(parents=True)
    (ext / "lib" / "GameCubeLoader.jar").write_bytes(b"")
    (ext / "extension.properties").write_text(f"name=GameCubeLoader\nversion={version}\n")
    for name in gamecube.LOADER_FILES if files else []:
        (ext / name).parent.mkdir(parents=True, exist_ok=True)
        (ext / name).write_text("")
    return root


class Check(unittest.TestCase):
    def test_a_loader_built_for_another_ghidra_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp, version="12.1")
            found = extcheck.problem(install, gamecube.LOADER, gamecube.LOADER_FILES, "fix")
        self.assertEqual(found, "GameCubeLoader is built for Ghidra 12.1, not 12.1.4; fix")

    def test_the_check_passes_with_the_files_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp)
            out = io.StringIO()
            with (
                patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(install)}),
                contextlib.redirect_stdout(out),
            ):
                self.assertEqual(gamecube.main(["check"]), 0)
        self.assertIn("GameCubeLoader in place for Ghidra 12.1.4", out.getvalue())

    def test_a_missing_language_file_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp, files=False)
            found = extcheck.problem(install, gamecube.LOADER, gamecube.LOADER_FILES, "fix")
        self.assertEqual(found, "GameCubeLoader lacks data/languages/ppc_gekko_broadway.ldefs; fix")


@unittest.skipUnless(os.environ.get("REA_GAMECUBE_SAMPLE"), "REA_GAMECUBE_SAMPLE not set")
class Sample(unittest.TestCase):
    def test_the_sample_is_read(self):
        found = gamecube.info(Path(os.environ["REA_GAMECUBE_SAMPLE"]))
        self.assertIn(found["kind"], ("dol", "rel", "disc"))


if __name__ == "__main__":
    unittest.main()
