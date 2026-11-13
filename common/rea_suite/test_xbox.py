"""Original Xbox lane: XBE parsing, the flat image, XbSymbolDatabase output and the loader check,
on a synthetic XBE built here (no game bytes).

Opt-in with a real executable, read-only: REA_XBOX_SAMPLE=<default.xbe> parses it and runs
XbSymbolDatabase on it through the suite's Ghidra install.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import xbe as pyxbe

from rea_suite import xbox

BASE = 0x10000
TEXT, RDATA = 0x11000, 0x12000
CODE = bytes([0x55, 0x89, 0xE5, 0x5D, 0xC3])  # push ebp; mov ebp,esp; pop ebp; ret
THUNKS = [0x80000001, 0x80000000 | 187, 0x80000000 | 370]  # 370: profiling builds, unnamed


def synthetic(kind: str = "retail") -> bytes:
    """A two-section XBE: .text with CODE, .rdata with the kernel thunk table and a bss tail."""
    entry_key, thunk_key = xbox.KEYS[kind]
    data = bytearray(0x1020)
    head = pyxbe.XbeImageHeader()
    head.magic = xbox.MAGIC
    head.base_addr = BASE
    head.headers_size = 0x1000
    head.image_size = 0x4000
    head.image_header_size = 376
    head.timestamp = 1_000_000_000
    head.certificate_addr = BASE + 0x178
    head.section_count = 2
    head.section_headers_addr = BASE + 0x350
    head.init_flags = 0x5
    head.entry_addr = TEXT ^ entry_key
    head.kern_thunk_addr = RDATA ^ thunk_key
    head.lib_versions_count = 2
    head.lib_versions_addr = BASE + 0x3D0
    data[0:376] = bytes(head)
    cert = pyxbe.XbeImageCertificate()
    cert.size = 464
    cert.title_id = 0x4D530004
    name = "Test Game".encode("utf-16-le")
    ctitle = (type(cert.title_name)).from_buffer_copy(name.ljust(80, b"\0"))
    cert.title_name = ctitle
    cert.game_region = 0x1
    cert.allowed_media = 0x2
    cert.version = 0x100
    data[0x178 : 0x178 + 464] = bytes(cert)
    for i, (addr, vsize, raw, rsize, name_at, sflags) in enumerate(
        [(TEXT, 0x1000, 0x1000, 0x10, 0x3C0, 0x6), (RDATA, 0x2000, 0x1010, 0x10, 0x3C6, 0x3)]
    ):
        sec = pyxbe.XbeSectionHeader()
        sec.flags, sec.virtual_addr, sec.virtual_size = sflags, addr, vsize
        sec.raw_addr, sec.raw_size, sec.section_name_addr = raw, rsize, BASE + name_at
        data[0x350 + i * 56 : 0x350 + (i + 1) * 56] = bytes(sec)
    data[0x3C0:0x3CD] = b".text\0.rdata\0"
    for i, (lib, build) in enumerate([(b"XAPILIB", 5849), (b"D3D8", 5849)]):
        ver = pyxbe.XbeLibraryVersion()
        ver.name, ver.ver_major, ver.ver_minor, ver.ver_build = lib, 1, 0, build
        data[0x3D0 + i * 16 : 0x3E0 + i * 16] = bytes(ver)
    data[0x1000 : 0x1000 + len(CODE)] = CODE
    data[0x1010:0x1020] = struct.pack("<4I", *THUNKS, 0)
    return bytes(data)


def fake_install(tmp: str) -> Path:
    """A Ghidra install holding ghidra-xbe's files (no Ghidra)."""
    root = Path(tmp)
    (root / "Ghidra").mkdir()
    (root / "Ghidra" / "application.properties").write_text("application.version=12.1.4\n")
    ext = root / "Ghidra" / "Extensions" / "ghidra-xbe"
    (ext / "lib").mkdir(parents=True)
    (ext / "lib" / "ghidra-xbe.jar").write_bytes(b"")
    (ext / "extension.properties").write_text("version=12.1.4\n")
    for platform in xbox.OS_DIRS.values():
        (ext / "os" / platform).mkdir(parents=True)
        for name in ("XbSymbolDatabaseCLI", "XbSymbolDatabaseCLI.exe"):
            (ext / "os" / platform / name).write_bytes(b"")
    return root


class Parsing(unittest.TestCase):
    def test_the_headers_certificate_and_libraries_are_read(self):
        found = xbox.info(xbox.Xbe(synthetic()))
        self.assertEqual(found["kind"], "retail")
        self.assertEqual(found["entry"], f"0x{TEXT:08x}")
        self.assertEqual(found["kernel_thunks"], f"0x{RDATA:08x}")
        self.assertEqual(found["title"]["name"], "Test Game")
        self.assertEqual(found["title"]["id"], "MS-004")
        self.assertEqual(found["title"]["regions"], ["NA"])
        self.assertEqual(found["init_flags"], ["MOUNT_UTILITY_DRIVE", "LIMIT64MB"])
        self.assertEqual([s["name"] for s in found["sections"]], [".text", ".rdata"])
        self.assertEqual(found["sections"][0]["flags"], ["PRELOAD", "EXECUTABLE"])
        self.assertEqual(
            [(lib["name"], lib["version"]) for lib in found["libraries"]],
            [("XAPILIB", "1.0.5849"), ("D3D8", "1.0.5849")],
        )
        self.assertEqual(found["kernel_imports"], 3)

    def test_debug_and_chihiro_keys_are_recognized(self):
        for kind in ("debug", "chihiro"):
            parsed = xbox.Xbe(synthetic(kind))
            self.assertEqual((parsed.kind, parsed.entry, parsed.thunks), (kind, TEXT, RDATA))

    def test_kernel_imports_are_named_by_ordinal_and_unknown_ones_stay_empty(self):
        rows = xbox.Xbe(synthetic()).imports()
        self.assertEqual(
            rows,
            [
                (RDATA, 1, "AvGetSavedDataAddress"),
                (RDATA + 4, 187, pyxbe.XbeKernelImage.exports[187]),
                (RDATA + 8, 370, ""),
            ],
        )

    def test_the_flat_image_puts_each_section_at_its_address(self):
        flat = xbox.Xbe(synthetic()).image()
        self.assertEqual(len(flat), 0x4000)
        self.assertEqual(flat[:4], b"XBEH")
        self.assertEqual(flat[TEXT - BASE : TEXT - BASE + len(CODE)], CODE)
        self.assertEqual(struct.unpack_from("<I", flat, RDATA - BASE)[0], THUNKS[0])
        self.assertEqual(flat[RDATA - BASE + 0x10 :], bytes(0x4000 - (RDATA - BASE + 0x10)))

    def test_other_files_and_scrambled_garbage_are_refused(self):
        with self.assertRaisesRegex(ValueError, "XBEH"):
            xbox.Xbe(b"MZ" + bytes(500))
        broken = bytearray(synthetic())
        struct.pack_into("<I", broken, 0x128, 0x12345678)  # entry_addr
        with self.assertRaisesRegex(ValueError, "key"):
            xbox.Xbe(bytes(broken))

    def test_title_ids_without_publisher_letters_stay_hexadecimal(self):
        self.assertEqual(xbox.title_id(0xFFFF0002), "FFFF0002")


class Symbols(unittest.TestCase):
    def test_the_cli_lines_become_address_name_and_library(self):
        text = "D3D8__Direct3D_CreateDevice = 0x0001a2b0\nXAPILIB__XapiInitProcess = 0x00011000\n"
        self.assertEqual(
            xbox.parse_symbols(text + "noise\n"),
            [(0x11000, "XapiInitProcess", "XAPILIB"), (0x1A2B0, "Direct3D_CreateDevice", "D3D8")],
        )

    def test_a_crash_of_the_cli_is_reported_with_its_likely_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp)
            crashed = subprocess.CompletedProcess([], -11, "", "")
            with (
                patch("subprocess.run", return_value=crashed),
                self.assertRaisesRegex(ValueError, "signal 11.*without XDK libraries"),
            ):
                xbox.symbols(Path("default.xbe"), install)

    def test_the_symbols_command_writes_a_tsv(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp)
            sample = Path(tmp) / "default.xbe"
            sample.write_bytes(synthetic())
            done = subprocess.CompletedProcess([], 0, "XAPILIB__XapiInitProcess = 0x00011000\n", "")
            out = io.StringIO()
            with (
                patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(install)}),
                patch("subprocess.run", return_value=done),
                contextlib.redirect_stdout(out),
            ):
                self.assertEqual(xbox.main(["symbols", str(sample)]), 0)
        self.assertEqual(
            out.getvalue(), "address\tname\tlibrary\n0x00011000\tXapiInitProcess\tXAPILIB\n"
        )


class Loader(unittest.TestCase):
    def test_missing_or_mismatched_extension_names_the_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp)
            self.assertIsNone(xbox.loader_problem(install))
            props = install / "Ghidra" / "Extensions" / "ghidra-xbe" / "extension.properties"
            props.write_text("version=12.0\n")
            self.assertIn("built for Ghidra 12.0, not 12.1.4", xbox.loader_problem(install))
            (install / "Ghidra" / "Extensions" / "ghidra-xbe" / "lib" / "ghidra-xbe.jar").unlink()
            self.assertIn(xbox.FIX, xbox.loader_problem(install))

    def test_check_fails_when_ghidra_uses_another_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = fake_install(tmp)
            sample = install / "Ghidra/Extensions/ghidra-xbe/tests/xbefiles/triangle.xbe"
            sample.parent.mkdir(parents=True)
            sample.write_bytes(synthetic())
            for text, code in (
                ("INFO  Using Loader: Raw Binary (ProgramLoader)", 1),
                (f"INFO  Using Loader: {xbox.LOADER_NAME} (ProgramLoader)", 0),
            ):

                def probe(runner, command, log, timeout=None, check=True, text=text):
                    log.write_text(text)
                    return 0

                with (
                    patch.object(xbox.ghidra_headless.AnalyzeHeadless, "run", probe),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(xbox.check(install), code)


@unittest.skipUnless(os.environ.get("REA_XBOX_SAMPLE"), "REA_XBOX_SAMPLE=<default.xbe> not set")
class RealExecutable(unittest.TestCase):
    def test_a_real_executable_parses_and_names_its_libraries(self):
        path = Path(os.environ["REA_XBOX_SAMPLE"])
        parsed = xbox.Xbe(path.read_bytes())
        found = xbox.info(parsed)
        self.assertTrue(found["libraries"])
        self.assertTrue(all(name for _, ordinal, name in parsed.imports() if ordinal))
        rows = xbox.symbols(path, xbox.ghidra_install())
        self.assertTrue(rows, "XbSymbolDatabase found nothing")
        print(json.dumps({"title": found["title"], "symbols": len(rows)}))


if __name__ == "__main__":
    unittest.main()
