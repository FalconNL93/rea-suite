"""PS3 lane: SELF headers, an executable's and a PRX's module tables, PARAM.SFO, NID hashing and
the RPCS3 name source, and the RPCS3 decrypter, on synthetic files built here (no game bytes, no
keys, no RPCS3 needed).

Opt-in with real files, read-only: REA_PS3_SAMPLE=<a SELF, ELF or PRX> reads it with `info`, and
with REA_PS3_NID_SOURCE=<an RPCS3 source tree> names its imports.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rea_suite import ps3

BASE = 0x10000
STRCPY = 0x04A183FC  # RPCS3's PPUFunction.cpp lists strcpy (sys_libc) under this NID
MODULE_START = 0xBC9A0086  # module_start, a management export listed by NID


def elf(e_type: int, phdrs: list[tuple], body: bytes, entry: int = BASE + 0x200) -> bytes:
    """ELF64 big-endian, PPC64, CELL LV2; phdrs are (type, offset, vaddr, paddr, filesz[, flags])."""
    head = b"\x7fELF" + bytes([2, 2, 1, ps3.OSABI_CELL_LV2]) + bytes(8)
    head += struct.pack(">HHIQQQIHHHHHH", e_type, 0x15, 1, entry, 64, 0, 0, 64, 56,
                        len(phdrs), 64, 0, 0)  # fmt: skip
    for kind, offset, vaddr, paddr, size, *flags in phdrs:
        head += struct.pack(">IIQQQQQQ", kind, (flags or [5])[0], offset, vaddr, paddr, size,
                            size, 0x10)  # fmt: skip
    return head + body[len(head) :]


def at(offset: int) -> int:
    """The address of a file offset in the synthetic executable's one segment."""
    return BASE + offset


def executable() -> bytes:
    """An executable importing strcpy from sys_libc and one unnamed NID, through
    sys_proc_prx_param, as the SDK's linker lays it out."""
    body = bytearray(0x400)
    body[0x300:0x309] = b"sys_libc\0"
    struct.pack_into(">II", body, 0x310, STRCPY, 0x12345678)  # function NIDs
    struct.pack_into(">II", body, 0x318, at(0x380), at(0x384))  # their slots
    stub = struct.pack(">BBHHHHHBB2xIIIII8x", 0x2C, 0, 1, 0x0009, 2, 0, 0, 0, 0,
                       at(0x300), at(0x310), at(0x318), 0, 0)  # fmt: skip
    body[0x340 : 0x340 + 0x2C] = stub
    param = struct.pack(">8IHHI", 0x40, ps3.PRX_PARAM_MAGIC, 4, 0, at(0x340), at(0x340),
                        at(0x340), at(0x36C), 1, 0, 0)  # fmt: skip
    body[0x3A0 : 0x3A0 + len(param)] = param
    return elf(
        2, [(1, 0, BASE, BASE, 0x400), (0x60000002, 0x3A0, at(0x3A0), at(0x3A0), 0x40)], body
    )


def prx() -> bytes:
    """A PRX: module info at p_paddr, one library export and the management export."""
    body = bytearray(0x400)
    body[0x300:0x30A] = b"libtestA\0\0"
    struct.pack_into(">III", body, 0x310, MODULE_START, ps3.nid("testFunc"), 0)
    struct.pack_into(">III", body, 0x320, 0x200, 0x240, 0)
    entries = struct.pack(">BBHHHHHBB2xIII", 0x1C, 0, 0, ps3.EXPORT_MANAGEMENT, 1, 0, 0, 0, 0,
                          0, 0x310, 0x320)  # fmt: skip
    entries += struct.pack(">BBHHHHHBB2xIII", 0x1C, 0, 1, ps3.EXPORT_LIBRARY, 1, 0, 0, 0, 0,
                           0x300, 0x314, 0x324)  # fmt: skip
    body[0x340 : 0x340 + len(entries)] = entries
    info = struct.pack(">HBB28sIIIII", 0x0006, 1, 2, b"test_prx", 0x8000, 0x340, 0x340 + 0x38,
                       0, 0)  # fmt: skip
    body[0x380 : 0x380 + len(info)] = info
    return elf(0xFFA4, [(1, 0, 0, 0x380, 0x400)], body)


def self_wrapping(inner: bytes, flags: int, npdrm: bool = False) -> bytes:
    """A SELF's plain headers around an ELF (the payload is the ELF unchanged here)."""
    out = bytearray(0x400)
    phnum = struct.unpack_from(">H", inner, 0x38)[0]
    struct.pack_into(">4sIHHIQQ", out, 0, b"SCE\0", 2, flags, 1, 0x200, 0x400, len(inner))
    supplemental = 0x2C0
    sup = struct.pack(">IIQ", 1, 0x30, 1) + bytes(0x20)
    if npdrm:
        npd = struct.pack(">4siii48s", b"NPD\0", 3, 2, 1, b"UP0000-NPUB00000_00-0000000000000001")
        sup += struct.pack(">IIQ", 3, 0x90, 0) + npd.ljust(0x80, b"\0")
    struct.pack_into(">10Q", out, 0x20, 3, 0x70, 0x90, 0xD0, 0, 0x200, 0, supplemental, len(sup), 0)
    struct.pack_into(
        ">QIIQQ", out, 0x70, 0x1010000001000003, 0x01000002, 8 if npdrm else 4, 1 << 48, 0
    )
    out[0x90:0xD0] = inner[:0x40]
    out[0xD0 : 0xD0 + 56 * phnum] = inner[0x40 : 0x40 + 56 * phnum]
    for i in range(phnum):
        struct.pack_into(
            ">QQIIQ", out, 0x200 + 32 * i, 0x400, 0x40, 1, 0, 2 if flags & 0x8000 else 1
        )
    out[supplemental : supplemental + len(sup)] = sup
    return bytes(out) + inner


def sfo(values: dict[str, str | int]) -> bytes:
    keys, data, index = b"", b"", b""
    for name, value in values.items():
        raw = struct.pack("<I", value) if isinstance(value, int) else value.encode() + b"\0"
        fmt = 0x0404 if isinstance(value, int) else 0x0204
        index += struct.pack("<HHIII", len(keys), fmt, len(raw), len(raw), len(data))
        keys += name.encode() + b"\0"
        data += raw
    key_start = 0x14 + len(index)
    head = b"\0PSF" + struct.pack("<IIII", 0x101, key_start, key_start + len(keys), len(values))
    return head + index + keys + data


class FakeSource:
    def describe(self) -> str:
        return "test"

    def entries(self):
        yield ps3.NidEntry(STRCPY, "sys_libc", "strcpy", "function", True)
        yield ps3.NidEntry(MODULE_START, "", "module_start", "function", False)

    def syscalls(self):
        return {}


class Nids(unittest.TestCase):
    def test_nid_is_the_ps3_hash_of_the_name(self):
        self.assertEqual(ps3.nid("strcpy"), STRCPY)

    def test_rpcs3_source_reads_registrations_and_listed_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp) / "rpcs3" / "Emu" / "Cell"
            (cell / "Modules").mkdir(parents=True)
            (cell / "Modules" / "cellPad.cpp").write_text(
                'DECLARE(ppu_module_manager::cellPad)("cellPad", []()\n{\n'
                "\tREG_FUNC(sys_io, cellPadGetData);\n"
                '\tREG_FNID(cellPad, "cellPadOdd", cellPad_odd);\n'
                "\tREG_FNID(cellPad, 0x1F3CD9F1, cellPad_1F3CD9F1);\n"
                "\tREG_VAR(cellPad, g_padVar);\n});\n"
            )
            (cell / "PPUFunction.cpp").write_text(
                "extern std::string ppu_get_function_name(const std::string& _module, u32 fnid)\n{\n"
                "\tif (_module.empty()) switch (fnid)\n\t{\n"
                '\tcase 0xbc9a0086: return "module_start";\n\t}\n'
                '\tif (_module == "sys_libc" || _module == "sys_libm") switch (fnid)\n\t{\n'
                '\tcase 0x04a183fc: return "strcpy";\n\t}\n}\n'
                "extern std::string ppu_get_variable_name(const std::string& _module, u32 vnid)\n{\n"
                '\tif (_module == "sys_libc") switch (vnid)\n\t{\n'
                '\tcase 0x12345678: return "_Ctype";\n\t}\n}\n'
            )
            entries = list(ps3.Rpcs3Source(Path(tmp)).entries())
        got = {(e.module, e.name, e.kind, e.hashed) for e in entries}
        self.assertIn(("sys_io", "cellPadGetData", "function", True), got)
        self.assertIn(("cellPad", "cellPadOdd", "function", True), got)
        self.assertIn(("cellPad", "g_padVar", "variable", True), got)
        self.assertIn(("", "module_start", "function", False), got)
        self.assertIn(("sys_libc", "strcpy", "function", True), got)
        self.assertIn(("sys_libm", "strcpy", "function", True), got)
        self.assertIn(("sys_libc", "_Ctype", "variable", False), got)
        self.assertFalse(any(e.name.startswith("cellPad_") for e in entries))
        self.assertEqual(next(e.nid for e in entries if e.name == "cellPadGetData"), 0x8B72CDA1)

    def test_a_tree_without_rpcs3_source_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ps3.Ps3Error):
            ps3.Rpcs3Source(Path(tmp))

    def test_resolve_names_nids_and_unknowns(self):
        table = ps3.NidTable(FakeSource())
        rows = ps3.resolve(["0x04a183fc", "bc9a0086", "deadbeef", "strcpy", "noSuchName"], table)
        self.assertEqual(rows[0], (STRCPY, "sys_libc", "strcpy", "known"))
        self.assertEqual(rows[1], (MODULE_START, "", "module_start", "listed"))
        self.assertEqual(rows[2], (0xDEADBEEF, "", "", "unknown"))
        self.assertEqual(rows[3], (STRCPY, "sys_libc", "strcpy", "known"))
        self.assertEqual(rows[4], (ps3.nid("noSuchName"), "", "noSuchName", "computed"))


class Formats(unittest.TestCase):
    def test_executable_imports_through_sys_proc_prx_param(self):
        rows = ps3.import_rows(ps3.Elf(executable()), ps3.NidTable(FakeSource()))
        self.assertEqual(
            rows,
            [
                ("sys_libc", "function", STRCPY, BASE + 0x318, BASE + 0x380, "strcpy"),
                ("sys_libc", "function", 0x12345678, BASE + 0x31C, BASE + 0x384, ""),
            ],
        )

    def test_prx_module_info_and_exports(self):
        out = ps3.info(prx(), ps3.NidTable(FakeSource()))
        self.assertEqual(out["format"], "PRX")
        self.assertEqual(out["module"]["name"], "test_prx")
        self.assertEqual(out["module"]["version"], "1.2")
        names = [lib["name"] for lib in out["exports"]]
        self.assertEqual(names, ["(module management: start, stop, ...)", "libtestA"])
        self.assertEqual(out["exports"][0]["functions"][0]["name"], "module_start")
        self.assertEqual(out["exports"][1]["functions"][0]["nid"], f"0x{ps3.nid('testFunc'):08x}")
        self.assertEqual(out["imports"], [])

    def test_fake_signed_self_needs_no_key(self):
        out = ps3.info(self_wrapping(executable(), 0x8000), None)
        self.assertEqual(out["format"], "SELF")
        self.assertTrue(out["fake_signed"])
        self.assertFalse(out["encrypted"])
        self.assertEqual(out["program"]["type"], "application")
        self.assertEqual(out["elf"]["type"], "executable")
        self.assertEqual(out["elf"]["osabi"], "CELL LV2")
        self.assertIn("without a key", out["next"])

    def test_retail_npdrm_self_reports_its_license_without_decrypting(self):
        out = ps3.info(self_wrapping(executable(), 0x0004, npdrm=True), None)
        self.assertTrue(out["encrypted"])
        self.assertEqual(out["program"]["type"], "NPDRM application")
        npd = next(s for s in out["supplemental"] if s["type"] == 3)
        self.assertEqual(npd["license"], "local")
        self.assertEqual(npd["content_id"], "UP0000-NPUB00000_00-0000000000000001")
        self.assertIn("RPCS3", out["next"])

    def test_param_sfo(self):
        out = ps3.info(
            sfo(
                {
                    "TITLE_ID": "BLUS00000",
                    "TITLE": "Test",
                    "PS3_SYSTEM_VER": "01.0000",
                    "RESOLUTION": 63,
                }
            ),
            None,
        )
        self.assertEqual(out["keys"]["TITLE_ID"], "BLUS00000")
        self.assertEqual(out["keys"]["RESOLUTION"], 63)

    def test_other_files_are_named_or_refused(self):
        self.assertIn("PKG", ps3.info(b"\x7fPKG" + bytes(60), None)["format"])
        with self.assertRaises(ps3.Ps3Error):
            ps3.info(b"MZ" + bytes(60), None)
        little = bytearray(executable())
        little[5] = 1
        with self.assertRaises(ps3.Ps3Error):
            ps3.info(bytes(little), None)

    def test_a_pointer_outside_the_file_is_an_error_not_a_crash(self):
        data = bytearray(executable())
        struct.pack_into(">I", data, 0x340 + 0x10, 0x7FFF0000)  # library name pointer
        with self.assertRaises(ps3.Ps3Error):
            ps3.import_rows(ps3.Elf(bytes(data)), None)


FAKE_RPCS3 = r"""
import sys, pathlib
path = pathlib.Path(sys.argv[2])
klic = sys.stdin.readline().strip()
if path.suffix == ".BIN" and klic != "00112233445566778899aabbccddeeff":
    print("Enter KLIC of " + path.name)
    sys.exit(0)
out = path.with_suffix(".elf")
out.write_bytes(b"plain:" + path.read_bytes())
print(f"Decrypted {path} -> {out}")
"""


class FakeRpcs3(ps3.Rpcs3Decrypter):
    def command(self, target: Path) -> list[str]:
        return [sys.executable, self.binary, "--decrypt", str(target)]


class Decrypt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fake = self.root / "rpcs3.py"
        self.fake.write_text(FAKE_RPCS3)
        (self.root / "game").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_result_lands_in_the_output_and_the_original_stays_untouched(self):
        src = self.root / "game" / "TEST.SELF"
        src.write_bytes(b"x")
        out = FakeRpcs3(str(self.fake)).decrypt(src, self.root / "out", None)
        self.assertEqual(out, self.root / "out" / "TEST.elf")
        self.assertEqual(out.read_bytes(), b"plain:x")
        self.assertEqual(sorted(p.name for p in (self.root / "game").iterdir()), ["TEST.SELF"])
        self.assertEqual([p.name for p in (self.root / "out").iterdir()], ["TEST.elf"])

    def test_klic_goes_to_standard_input_and_a_refusal_is_reported(self):
        src = self.root / "game" / "EBOOT.BIN"
        src.write_bytes(b"x")
        with self.assertRaisesRegex(ps3.Ps3Error, "Enter KLIC"):
            FakeRpcs3(str(self.fake)).decrypt(src, self.root / "out", None)
        out = FakeRpcs3(str(self.fake)).decrypt(
            src, self.root / "out", "00112233445566778899aabbccddeeff"
        )
        self.assertEqual(out.name, "EBOOT.elf")

    @unittest.skipIf(sys.platform in ("win32", "darwin"), "XDG folders are RPCS3's on Linux")
    def test_data_folder_points_rpcs3_at_another_profile(self):
        env = ps3.Rpcs3Decrypter("rpcs3", self.root / "data").environment()
        self.assertEqual(env["XDG_CONFIG_HOME"], str(self.root / "data" / "config"))
        self.assertEqual(env["XDG_CACHE_HOME"], str(self.root / "data" / "cache"))


class Cli(unittest.TestCase):
    def test_imports_tsv_through_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.elf").write_bytes(executable())
            out = io.StringIO()
            err = io.StringIO()
            with (
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
                mock.patch.object(ps3, "default_source", lambda _: FakeSource()),
            ):
                code = ps3.main(["--caller-cwd", tmp, "imports", "a.elf"])
        self.assertEqual(code, 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "library\tkind\tnid\tslot\tstub\tname")
        self.assertIn("sys_libc\tfunction\t0x04a183fc\t0x10318\t0x10380\tstrcpy", lines)
        self.assertIn("1 of 2 NIDs without a name", err.getvalue())


CODE, DATA, TOC = 0x10000, 0x20000, 0x28000
LI_R11_403, SC, LVLX, BLR = 0x39600193, 0x44000002, 0x7C03240E, 0x4E800020


def data(offset: int) -> int:
    """The address of a file offset in program()'s data segment."""
    return DATA + offset - 0x400


def program() -> bytes:
    """An executable with code (r-x) and data (rw-) segments: two OPDs (the entry's first), a
    `li r11,403; sc`, a bare `sc`, an lvlx, one import with its stub, and an SPU ELF in the data."""
    body = bytearray(0x800)
    words = [BLR] * 0x60
    words[0] = LI_R11_403
    words[1] = SC
    words[0x10] = SC  # no li r11 before it
    words[0x11] = LVLX
    for i, w in enumerate(words):
        struct.pack_into(">I", body, 0x200 + 4 * i, w)
    struct.pack_into(">IIII", body, 0x400, CODE + 0x200, TOC, CODE + 0x240, TOC)  # OPDs
    body[0x500:0x509] = b"sys_libc\0"
    struct.pack_into(">I", body, 0x510, STRCPY)
    struct.pack_into(">I", body, 0x518, CODE + 0x300)  # slot -> stub
    stub = struct.pack(">BBHHHHHBB2xIIIII8x", 0x2C, 0, 1, 0x0009, 1, 0, 0, 0, 0,
                       data(0x500), data(0x510), data(0x518), 0, 0)  # fmt: skip
    body[0x540 : 0x540 + 0x2C] = stub
    param = struct.pack(">8IHHI", 0x40, ps3.PRX_PARAM_MAGIC, 4, 0, data(0x540), data(0x540),
                        data(0x540), data(0x56C), 1, 0, 0)  # fmt: skip
    body[0x580 : 0x580 + len(param)] = param
    spu = bytearray(0x80)
    spu[0:7] = ps3.SPU_ELF
    struct.pack_into(">HH", spu, 16, 2, ps3.EM_SPU)
    struct.pack_into(">III", spu, 24, 0x40, 52, 0)
    struct.pack_into(">HHHH", spu, 42, 32, 1, 40, 0)
    struct.pack_into(">IIIII", spu, 52, 1, 0x60, 0, 0, 0x20)
    body[0x600:0x680] = spu
    phdrs = [
        (1, 0, CODE, CODE, 0x400, 5),
        (1, 0x400, DATA, DATA, 0x400, 6),
        (0x60000002, 0x580, data(0x580), data(0x580), 0x40, 4),
    ]
    return elf(2, phdrs, body, entry=DATA)


class FakeSyscalls(FakeSource):
    def syscalls(self):
        return {403: "sys_tty_write"}


class Census(unittest.TestCase):
    def setUp(self):
        self.elf = ps3.Elf(program())
        self.table = ps3.NidTable(FakeSyscalls())

    def test_toc_from_the_entry_opd_and_functions_from_the_opds(self):
        self.assertEqual(ps3.toc_of(self.elf), TOC)
        self.assertEqual(ps3.opd_functions(self.elf, TOC), [CODE + 0x200, CODE + 0x240])
        self.assertEqual(ps3.opd_functions(self.elf, 0), [])

    def test_syscalls_by_the_li_r11_before_each_sc(self):
        self.assertEqual(ps3.syscall_sites(self.elf), [(CODE + 0x204, 403), (CODE + 0x240, None)])

    def test_census_counts_libraries_syscalls_spu_images_and_cell_vmx(self):
        facts = ps3.census(self.elf, self.table)
        self.assertEqual(facts["toc"], "0x28000")
        self.assertEqual(
            facts["imports"], {"sys_libc": {"functions": 1, "variables": 0, "unnamed": 0}}
        )
        self.assertEqual(facts["syscalls"], [{"number": 403, "name": "sys_tty_write", "sites": 1}])
        self.assertEqual(facts["syscall_sites_unresolved"], ["0x10240"])
        self.assertEqual(facts["cell_vmx"], {"lvlx": 1})
        self.assertEqual(
            facts["spu"]["images"],
            [{"offset": 0x600, "size": 0x80, "entry": "0x40", "address": "0x20200"}],
        )
        self.assertEqual(facts["opd_functions"], 2)
        lines = ps3.limits(facts)
        self.assertTrue(any("lvlx: 1" in line for line in lines))
        self.assertTrue(any("SPU image" in line for line in lines))
        self.assertTrue(any("0x10240" in line for line in lines))

    def test_ghidra_names_stubs_slots_and_seeds(self):
        functions, labels, seeds = ps3.ghidra_names(self.elf, self.table)
        self.assertEqual(functions, ["0x10300\tstrcpy\timport sys_libc 0x04a183fc"])
        self.assertEqual(labels, ["0x20118\t__imp_strcpy\t"])
        self.assertEqual(seeds, [CODE + 0x200, CODE + 0x240, CODE + 0x300])

    def test_unnamed_imports_get_the_library_and_nid(self):
        functions, _, _ = ps3.ghidra_names(self.elf, None)
        self.assertEqual(functions, ["0x10300\tsys_libc_04A183FC\timport sys_libc 0x04a183fc"])

    def test_prx_exports_name_the_opd_and_its_code(self):
        functions, labels, _ = ps3.ghidra_names(ps3.Elf(prx()), ps3.NidTable(FakeSource()))
        self.assertIn("0x200\t__opd_module_start\t", labels)
        self.assertTrue(
            any(
                row.endswith("export libtestA 0x" + f"{ps3.nid('testFunc'):08x}")
                for row in functions
            )
        )

    def test_rpcs3_source_names_syscalls_by_their_comment_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp) / "rpcs3" / "Emu" / "Cell"
            (cell / "lv2").mkdir(parents=True)
            (cell / "PPUFunction.cpp").write_text("")
            (cell / "lv2" / "lv2.cpp").write_text(
                "{\n\tnull_func,\n"
                "\tBIND_SYSC(sys_process_getpid),                          //1   (0x001)\n"
                "\tuns_func, uns_func,                                     //2-3  UNS\n"
                "\tNULL_FUNC(_sys_process_spawn),                          //21  (0x015)  DBG\n"
                "\tnull_func,//BIND_SYSC(sys_usbd_...),                    //557 (0x22D)\n}\n"
            )
            self.assertEqual(
                ps3.Rpcs3Source(Path(tmp)).syscalls(),
                {1: "sys_process_getpid", 21: "_sys_process_spawn"},
            )


class Analyze(unittest.TestCase):
    def test_plan_imports_with_the_32_bit_address_language_and_the_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "EBOOT.elf").write_bytes(program())
            out = io.StringIO()
            with (
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(io.StringIO()),
                mock.patch.object(ps3, "default_source", lambda _: FakeSyscalls()),
                mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": tmp}),
            ):
                code = ps3.main(
                    ["--caller-cwd", tmp, "analyze", "EBOOT.elf", "--project", "gh", "--plan"]
                )
        self.assertEqual(code, 0)
        plan = json.loads(out.getvalue())
        command = plan["command"]
        self.assertEqual(command[command.index("-processor") + 1], ps3.LANGUAGE)
        self.assertEqual(command[command.index("-preScript") + 1 : command.index("-preScript") + 3],
                         ["Ps3Prepare.java", "0x28000"])  # fmt: skip
        self.assertEqual(command.count("ApplyNames.java"), 2)
        self.assertEqual(command[2], "EBOOT")
        self.assertNotIn("-overwrite", command)
        self.assertEqual((plan["functions"], plan["labels"], plan["seeds"]), (1, 1, 3))

    def test_ghidra_runs_through_the_suites_one_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = ps3.ghidra_command(Path(tmp), Path(tmp) / "gh", "game", "-import", "x")
            self.assertEqual(command[0], str(Path(tmp) / "support" / Path(command[0]).name))
            self.assertEqual(command[1:], [str(Path(tmp) / "gh"), "game", "-import", "x"])
            with mock.patch.object(ps3.ghidra_headless, "run") as run:
                ps3.ghidra_run(command, Path(tmp) / "gh", Path(tmp) / "log", 60)
            run.assert_called_once_with(command, Path(tmp) / "log", 60)

    def test_an_spu_elf_or_other_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.bin").write_bytes(b"MZ" + bytes(60))
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                ps3.main(["--caller-cwd", tmp, "analyze", "x.bin", "--project", "gh", "--plan"])


class Build(unittest.TestCase):
    def test_the_pin_the_setting_and_latest(self):
        base = {"installed": "build-a", "pinned": "build-a", "wanted": None, "source": "a"}
        self.assertIsNone(ps3.build_problem(base))
        self.assertIn("the pin build-b", ps3.build_problem({**base, "pinned": "build-b"}))
        self.assertIn("REA_RPCS3_BUILD=build-c", ps3.build_problem({**base, "wanted": "build-c"}))
        self.assertIsNone(ps3.build_problem({**base, "wanted": "latest", "pinned": "build-b"}))
        self.assertIsNone(ps3.build_problem({**base, "installed": None}))


@unittest.skipUnless(os.environ.get("REA_PS3_SAMPLE"), "set REA_PS3_SAMPLE to a SELF, ELF or PRX")
class Sample(unittest.TestCase):
    def test_reads_a_real_file(self):
        path = Path(os.environ["REA_PS3_SAMPLE"])
        source = os.environ.get("REA_PS3_NID_SOURCE")
        table = ps3.NidTable(ps3.Rpcs3Source(Path(source))) if source else None
        out = ps3.info(path.read_bytes(), table)
        print(json.dumps({k: out[k] for k in ("format",) if k in out}))
        self.assertIn(out["format"], ("SELF", "ELF", "PRX", "SPU ELF", "PARAM.SFO"))


if __name__ == "__main__":
    unittest.main()
