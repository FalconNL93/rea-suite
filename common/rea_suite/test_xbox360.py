"""Xbox 360 lane: detection, the Ghidra commands, limits and the loader check (no game bytes).

Opt-in runs with the suite's Ghidra: REA_XBOX360_INTEGRATION=1 analyzes a synthetic PowerPC PE
built here; REA_XBOX360_SAMPLE=<an XEX or its PE image> analyzes a real one in a scratch project
under work/ (read-only on the file).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import xbox360

BASE = 0x82000000
TEXT = 0x1000
CALLERS = 3


def be(*words: int) -> bytes:
    return struct.pack(f">{len(words)}I", *words)


def branch(source: int, target: int, link: bool) -> int:
    return 0x48000000 | ((target - source) & 0x03FFFFFC) | int(link)


def code() -> tuple[bytes, list[int]]:
    """CALLERS functions saving from r27, r28 or r29, a leaf, the helpers; the function entries.

    Calls into several entries of one helper split it into 4-byte functions that fall into each
    other, as on the console."""
    start = BASE + TEXT
    leaf = start + 0x20 * CALLERS
    save = leaf + 0x80  # __savegprlr_14
    restore = save + 0x50  # __restgprlr_14
    words = []
    entries = []
    for n in range(CALLERS):
        at = start + 0x20 * n
        entries.append(at)
        words += [
            0x7D8802A6,  # mflr r12
            branch(at + 4, save + (13 + n % 3) * 4, True),  # __savegprlr_27..29
            0x9421FFA0,  # stwu r1,-0x60(r1)
            0x38600000 | n,  # li r3,n
            branch(at + 16, leaf, True),
            0x38630001,  # addi r3,r3,1
            0x38210060,  # addi r1,r1,0x60
            branch(at + 28, restore + (13 + n % 3) * 4, False),  # __restgprlr_27..29
        ]
    words += [0x60000000] * ((leaf - start) // 4 - len(words))  # nop
    entries.append(leaf)
    words += [0x38630002, 0x4E800020]  # addi r3,r3,2; blr
    words += [0x60000000] * ((save - start) // 4 - len(words))
    entries += [save, restore]  # .pdata lists each helper routine once, at its first entry
    words += [0xF8010000 | r << 21 | (-8 * (33 - r)) & 0xFFFF for r in range(14, 32)]  # std
    words += [0x9181FFF8, 0x4E800020]  # stw r12,-8(r1); blr
    words += [0xE8010000 | r << 21 | (-8 * (33 - r)) & 0xFFFF for r in range(14, 32)]  # ld
    words += [0x8181FFF8, 0x7D8803A6, 0x4E800020]  # lwz r12,-8(r1); mtlr r12; blr
    # __savevmx_30/31 (stvx) and __restvmx_64 (lvx128)
    words += [0x3960FFE0, 0x7C0001CE | 30 << 21 | 11 << 16 | 12 << 11]
    words += [0x3960FFF0, 0x7C0001CE | 31 << 21 | 11 << 16 | 12 << 11, 0x4E800020]
    words += [0x3960FFF0, 0x100B60CB, 0x4E800020]
    return be(*words), entries


def pe(machine: int = xbox360.MACHINE_POWERPCBE) -> bytes:
    """A minimal PE32: headers little-endian, .text and .pdata big-endian as on the console."""
    text, entries = code()
    text += bytes(-len(text) % 0x200)
    pdata = b"".join(be(e, (8 << 8) | 2) for e in entries)
    pdata += bytes(-len(pdata) % 0x200)
    head = bytearray(0x400)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, 0x44, machine, 2, 0, 0, 0, 0xE0, 0x0102)
    struct.pack_into(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        head,
        0x58,
        0x10B, 8, 0, len(text), len(pdata), 0, TEXT, TEXT, 0x2000, BASE, 0x1000, 0x200,
        4, 0, 0, 0, 4, 0, 0, 0x3000, 0x400, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )  # fmt: skip
    sections = 0x58 + 0xE0
    for i, (name, rva, raw, size, flags) in enumerate(
        [
            (b".text", TEXT, 0x400, len(text), 0x60000020),
            (b".pdata", 0x2000, 0x400 + len(text), len(pdata), 0x40000040),
        ]
    ):
        struct.pack_into(
            "<8sIIIIIIHHI", head, sections + 40 * i, name, size, rva, size, raw, 0, 0, 0, 0, flags
        )
    return bytes(head) + text + pdata


def fake_ghidra(root: Path, version: str = "12.1.4", extension: str | None = "12.1.4") -> Path:
    install = root / "ghidra"
    (install / "Ghidra").mkdir(parents=True)
    (install / "Ghidra/application.properties").write_text(f"application.version={version}\n")
    if extension:
        ext = install / "Ghidra/Extensions/XEXLoaderWV"
        (ext / "lib").mkdir(parents=True)
        (ext / "lib/XEXLoaderWV.jar").write_bytes(b"PK")
        (ext / "extension.properties").write_text(f"name=XEXLoaderWV\nversion={extension}\n")
    return install


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_xex_is_recognized_by_its_magic(self):
        self.assertEqual(xbox360.kind(self.write("a.xex", b"XEX2" + bytes(60))), "xex")

    def test_powerpc_big_endian_pe_is_recognized(self):
        self.assertEqual(xbox360.kind(self.write("a.bin", pe())), "pe")

    def test_other_pe_machines_and_files_are_refused(self):
        with self.assertRaisesRegex(ValueError, "0x014c"):
            xbox360.kind(self.write("x86.exe", pe(0x014C)))
        with self.assertRaisesRegex(ValueError, "neither"):
            xbox360.kind(self.write("x.bin", b"\x7fELF" + bytes(60)))

    def test_xex_imports_through_xexloaderwv_and_pe_as_altivec_powerpc(self):
        install = fake_ghidra(self.root)
        summary = self.root / "s.json"
        xex = xbox360.import_command(
            install, self.root, "p", self.write("a.xex", b"XEX2"), summary, 60, False
        )
        self.assertEqual(xex[xex.index("-loader") + 1], "XEXLoaderWVLoader")
        self.assertNotIn("-overwrite", xex)
        image = xbox360.import_command(
            install, self.root, "p", self.write("a.bin", pe()), summary, 60, True
        )
        self.assertEqual(image[image.index("-processor") + 1], "PowerPC:BE:64:A2ALT-32addr")
        self.assertIn("-overwrite", image)
        for command in (xex, image):
            self.assertEqual(
                command[command.index("-preScript") + 1 :][:2], ["XenonHelpers.java", "prepare"]
            )
            self.assertIn("repair", command)

    def test_queries_open_the_project_read_only_after_the_repair(self):
        command = xbox360.query_command(
            self.root,
            self.root,
            "cod3",
            "default.xex",
            self.root / "s.json",
            ["DecompileAt.java", "o", "0x1"],
        )
        self.assertIn("-readOnly", command)
        self.assertIn("-noanalysis", command)
        scripts = [command[i + 1] for i, v in enumerate(command) if v == "-postScript"]
        self.assertEqual(scripts, ["XenonHelpers.java", "DecompileAt.java"])


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_project_name_comes_from_the_folders_one_gpr(self):
        (self.root / "cod3.gpr").touch()
        self.assertEqual(xbox360.project_name(self.root, None), "cod3")
        with self.assertRaisesRegex(ValueError, "not other"):
            xbox360.project_name(self.root, "other")
        (self.root / "mp.gpr").touch()
        with self.assertRaisesRegex(ValueError, "several"):
            xbox360.project_name(self.root, None)
        with self.assertRaisesRegex(ValueError, "no Ghidra project"):
            xbox360.project_name(self.root / "none", None)

    def test_program_names_are_read_from_the_project_index(self):
        index = self.root / "cod3.rep/idata"
        index.mkdir(parents=True)
        (index / "~index.dat").write_text(
            "VERSION=1\n/\n  00000000:default.xex:7f011aa2925980863577626\nNEXT-ID:1\nMD5:x\n"
        )
        self.assertEqual(xbox360.program_names(self.root, "cod3"), {"default.xex"})
        self.assertEqual(xbox360.program_names(self.root, "none"), set())

    def test_plan_prints_the_command_and_writes_nothing(self):
        install = fake_ghidra(self.root)
        (self.root / "a.xex").write_bytes(b"XEX2" + bytes(60))
        out = io.StringIO()
        with (
            patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(install)}),
            contextlib.redirect_stdout(out),
        ):
            code = xbox360.main(
                ["--caller-cwd", str(self.root), "analyze", "a.xex", "--project", "proj", "--plan"]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["kind"], "xex")
        self.assertFalse((self.root / "proj").exists())

    def test_an_xex_is_refused_without_the_loader(self):
        install = fake_ghidra(self.root, extension=None)
        (self.root / "a.xex").write_bytes(b"XEX2")
        args = argparse.Namespace(
            caller_cwd=self.root, file=Path("a.xex"), project=Path("p"), name=None,
            timeout=60, force=False, plan=False,
        )  # fmt: skip
        with self.assertRaisesRegex(ValueError, "rea-suite tools reinstall ghidra"):
            xbox360.analyze(args, install)

    def test_another_loader_than_xexloaderwv_fails_the_import(self):
        install = fake_ghidra(self.root)
        (self.root / "a.xex").write_bytes(b"XEX2")

        def ghidra(command, project, log, timeout):
            log.write("INFO  Using Loader: Raw Binary (ProgramLoader)\nREPORT: Import succeeded\n")

        args = argparse.Namespace(
            caller_cwd=self.root, file=Path("a.xex"), project=Path("p"), name=None,
            timeout=60, force=False, plan=False,
        )  # fmt: skip
        with patch.object(xbox360, "run", ghidra), self.assertRaisesRegex(ValueError, "Raw Binary"):
            xbox360.analyze(args, install)


class NamesTests(unittest.TestCase):
    """`names`: a port's map of names and comments written into its project (the RE rule "the whole unit once",
    master-server docs/PORTING.md: the names in the REA session too)."""

    MAP = (
        "game\taddress\tname\twhat\twhere\n"
        "mp\t0x820B00C0\tKeyHash\tkey hash h = h*33 + lower(c)\tdocs/12.md\n"
        "# a note\n"
        "sp\t0x8250A030\tIN_SprintDown\tbare blr in SP\tdocs/04.md\n"
        "\n"
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "map.tsv").write_text(self.MAP)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_map_is_read_by_its_header_and_filtered(self):
        rows = xbox360.read_names(self.root / "map.tsv", ["game=mp"])
        self.assertEqual(rows, [("820b00c0", "KeyHash", "key hash h = h*33 + lower(c)")])
        self.assertEqual(len(xbox360.read_names(self.root / "map.tsv", [])), 2)

    def test_a_map_without_its_columns_or_with_a_bad_row_is_refused(self):
        (self.root / "bad.tsv").write_text("addr\tname\n0x1\tx\n")
        with self.assertRaisesRegex(ValueError, "no `address` column"):
            xbox360.read_names(self.root / "bad.tsv", [])
        (self.root / "bad.tsv").write_text("address\tname\nnowhere\tx\n")
        with self.assertRaisesRegex(ValueError, "no hex address"):
            xbox360.read_names(self.root / "bad.tsv", [])
        with self.assertRaisesRegex(ValueError, "--where level=3"):
            xbox360.read_names(self.root / "map.tsv", ["level=3"])

    def test_names_is_the_one_query_that_writes_after_the_repair(self):
        command = xbox360.names_command(
            self.root, self.root, "cod3", "default.xex", self.root / "s.json",
            self.root / "in.tsv", self.root / "out.tsv",
        )  # fmt: skip
        self.assertNotIn("-readOnly", command)
        self.assertIn("-noanalysis", command)
        scripts = [command[i + 1] for i, v in enumerate(command) if v == "-postScript"]
        self.assertEqual(scripts, ["XenonHelpers.java", "ApplyNames.java"])

    def test_a_project_of_several_programs_needs_one_named(self):
        install = fake_ghidra(self.root)
        (self.root / "proj").mkdir()
        (self.root / "proj/cod3.gpr").touch()
        index = self.root / "proj/cod3.rep/idata"
        index.mkdir(parents=True)
        (index / "~index.dat").write_text(
            "VERSION=1\n/\n  00000000:sp.xex:1\n  00000001:mp.xex:2\n"
        )
        base = [
            "--caller-cwd",
            str(self.root),
            "names",
            "--project",
            "proj",
            "--from",
            "map.tsv",
            "--plan",
        ]
        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(install)}):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                xbox360.main(base)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(
                    xbox360.main([*base, "--program", "mp.xex", "--where", "game=mp"]), 0
                )
        self.assertEqual(json.loads(out.getvalue())["names"], 1)


class LimitTests(unittest.TestCase):
    def test_undecoded_vmx128_and_the_lane_choices_are_stated(self):
        summary = {
            "mode": "prepare",
            "helpers": 4,
            "undecoded_instructions": 7,
            "undecoded_sample": ["82001000"],
            "undecoded_opcodes": {"4": 5, "6": 1, "31": 1},
        }
        text = "\n".join(xbox360.limits(summary, "pcode error at 8200a: Unable to resolve", "pe"))
        self.assertIn("7 instruction(s) Ghidra cannot decode, 6 of them in the VMX128", text)
        self.assertIn("31: 1", text)
        self.assertIn("p-code", text)
        self.assertIn("no XEX import names", text)
        self.assertIn("call-fixup", text)

    def test_missing_helpers_are_stated(self):
        self.assertIn("no register save/restore helpers", " ".join(xbox360.limits({}, "", "xex")))


class LoaderCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_or_mismatched_extension_names_the_fix(self):
        missing = xbox360.loader_problem(fake_ghidra(self.root / "a", extension=None))
        self.assertIn("not installed", missing)
        self.assertIn("rea-suite tools reinstall ghidra", missing)
        stale = xbox360.loader_problem(fake_ghidra(self.root / "b", extension="12.1.3"))
        self.assertIn("built for Ghidra 12.1.3, not 12.1.4", stale)
        self.assertIsNone(xbox360.loader_problem(fake_ghidra(self.root / "c")))

    def test_check_fails_when_ghidra_does_not_ask_the_loader(self):
        install = fake_ghidra(self.root)
        result = argparse.Namespace(stdout="INFO nothing\n", stderr="")
        out = io.StringIO()
        with (
            patch.object(xbox360.subprocess, "run", return_value=result),
            contextlib.redirect_stdout(out),
        ):
            self.assertEqual(xbox360.check(install), 1)
        self.assertIn("did not load XEXLoaderWV", out.getvalue())


WORK = Path(__file__).resolve().parents[2] / "work"


def analyze_and_query(target: Path, project: Path, address: str) -> tuple[str, str, str]:
    """Runs analyze, decomp and functions through main(); returns their outputs."""
    outputs = []
    for argv in (
        ["analyze", str(target), "--project", str(project), "--name", "check"],
        ["decomp", "--project", str(project), "-o", str(project / "out.c"), address],
        ["functions", "--project", str(project), "-o", str(project / "functions.tsv")],
    ):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            assert xbox360.main(argv) == 0, argv
        outputs.append(buffer.getvalue())
    return outputs[0], (project / "out.c").read_text(), (project / "functions.tsv").read_text()


@unittest.skipUnless(os.environ.get("REA_XBOX360_INTEGRATION"), "set REA_XBOX360_INTEGRATION=1")
class GhidraIntegrationTests(unittest.TestCase):
    def test_synthetic_pe_keeps_its_helpers_returning(self):
        WORK.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=WORK) as tmp:
            target = Path(tmp) / "synthetic.bin"
            target.write_bytes(pe())
            report, decompiled, functions = analyze_and_query(target, Path(tmp) / "p", "0x82001000")
        self.assertIn(
            "Helpers: 39 save/restore entries kept returning; 6 functions defined", report
        )
        for name in ("__savegprlr_29", "__restgprlr_29", "__savevmx_31", "__restvmx_64"):
            self.assertIn(f"\t{name}\t", functions)
        self.assertIn("@ 82001000", decompiled)
        # The call after the prologue and the code after it survive: not cut at __savegprlr_29.
        self.assertIn(f"FUN_{BASE + TEXT + 0x20 * CALLERS:08x}(0)", decompiled)
        self.assertIn("+ 1", decompiled)  # the code after that call
        self.assertNotIn("__savegprlr_27(", decompiled)  # the call-fixup drops the call
        self.assertIn("; 0 call sites repaired", report)  # prepare left nothing to repair
        self.assertNotIn("does not return", decompiled)

    def test_names_are_written_once_and_kept_afterwards(self):
        WORK.mkdir(exist_ok=True)
        callee = BASE + TEXT + 0x20 * CALLERS
        with tempfile.TemporaryDirectory(dir=WORK) as tmp:
            target, project = Path(tmp) / "synthetic.bin", Path(tmp) / "p"
            target.write_bytes(pe())
            analyze_and_query(target, project, "0x82001000")
            (Path(tmp) / "map.tsv").write_text(
                f"address\tname\twhat\n0x{callee:08x}\tCallee_Named\tthe callers' target\n0xdead0000\tNowhere\t\n"
            )
            argv = ["names", "--project", str(project), "--from", str(Path(tmp) / "map.tsv")]
            for expected in ("1 named, 1 missing", "1 same, 1 missing"):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(xbox360.main(argv), 0)
                self.assertEqual(out.getvalue().strip(), expected)
            listing = Path(tmp) / "functions.tsv"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    xbox360.main(["functions", "--project", str(project), "-o", str(listing)]), 0
                )
            functions = listing.read_text()
        self.assertIn(f"{callee:08x}\t", functions)
        self.assertIn("\tCallee_Named\t", functions)


@unittest.skipUnless(os.environ.get("REA_XBOX360_SAMPLE"), "set REA_XBOX360_SAMPLE=<xex or pe>")
class SampleTests(unittest.TestCase):
    def test_a_real_executable_opens_and_decompiles_its_entry(self):
        target = Path(os.environ["REA_XBOX360_SAMPLE"]).resolve()
        address = os.environ.get("REA_XBOX360_ADDRESS", "")
        WORK.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=WORK) as tmp:
            report, decompiled, functions = analyze_and_query(
                target, Path(tmp) / "p", address or "0x82000000"
            )
        print(report, decompiled[:3000], sep="\n")
        self.assertIn("__savegprlr_14", functions)
        if address:
            self.assertIn("// ---- ", decompiled)


if __name__ == "__main__":
    unittest.main()
