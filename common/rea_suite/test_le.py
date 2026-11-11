"""le: small LE executables built here (a DOS/4GW-style stub, a code and a data object, internal and
imported fixups), read back and dumped at another base."""

from __future__ import annotations

import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from rea_suite import le

PAGE = 0x100
CODE_BASE, DATA_BASE = 0x10000, 0x20000
HEADER_AT = 0x80


def fixup_internal(srcoff: int, obj: int, offset: int, source: int = 0x07) -> bytes:
    # 32-bit target offset (0x10), 8-bit object number
    return struct.pack("<BBhBI", source, 0x10, srcoff, obj, offset)


def fixup_import(srcoff: int, module: int, ordinal: int) -> bytes:
    return struct.pack("<BBhBH", 0x07, 0x01, srcoff, module, ordinal)


def build(folder: Path) -> Path:
    """MAIN.EXE: object 1 code (two pages, 32-bit, r-x) at CODE_BASE, object 2 data (one page, rw-)
    at DATA_BASE, the entry point at object 1 + 0x20, and four fixups on the code:
      page 1 +0x04  32-bit offset to object 2 + 0x10
      page 1 +0x40  32-bit self-relative to object 1 + 0x120
      page 1 +0xFE  32-bit offset to object 2 + 0x30, crossing into page 2 (listed again there at -2)
      page 2 +0x08  32-bit offset imported by ordinal (KERNEL.5), left alone"""
    stub = bytearray(HEADER_AT)
    stub[0:2] = b"MZ"
    struct.pack_into("<HHHH", stub, 2, HEADER_AT % 512, 1, 0, 4)  # last page, pages, relocs, paras
    struct.pack_into("<I", stub, 0x3C, HEADER_AT)
    stub[0x40:0x4A] = b"DOS4GPATH\0"

    code = bytearray(2 * PAGE)
    for i in range(len(code)):
        code[i] = 0x90
    data = bytearray(b"D" * PAGE)

    page1 = (
        fixup_internal(0x04, 2, 0x10)
        + fixup_internal(0x40, 1, 0x120, source=0x08)
        + fixup_internal(0xFE, 2, 0x30)
    )
    page2 = fixup_internal(-2, 2, 0x30) + fixup_import(0x08, 1, 5)
    page3 = b""

    objects = struct.pack("<6I", 2 * PAGE, CODE_BASE, 0x2045, 1, 2, 0) + struct.pack(
        "<6I", PAGE, DATA_BASE, 0x2043, 3, 1, 0
    )
    pages = b"".join(bytes([0, 0, n, 0]) for n in (1, 2, 3))  # 24-bit page numbers, high byte first
    resident = b"\x04main\x00\x00\x00"
    entry = b"\x00"
    imports = b"\x06KERNEL"
    fixup_pages = struct.pack(
        "<4I", 0, len(page1), len(page1) + len(page2), len(page1) + len(page2) + len(page3)
    )
    records = page1 + page2 + page3

    tables = bytearray()
    at = {}
    for name, blob in [
        ("objects", objects),
        ("pages", pages),
        ("resident", resident),
        ("entry", entry),
        ("fixup_pages", fixup_pages),
        ("records", records),
        ("imports", imports),
    ]:
        at[name] = 0xB0 + len(tables)
        tables += blob
    header = bytearray(0xB0)
    header[0:2] = b"LE"
    values = {
        0x08: (2, "H"),  # 80386
        0x0A: (1, "H"),  # OS/2, as Watcom marks DOS/4GW programs
        0x10: (0x200, "I"),
        0x14: (3, "I"),
        0x18: (1, "I"),
        0x1C: (0x20, "I"),
        0x20: (2, "I"),
        0x24: (0x80, "I"),
        0x28: (PAGE, "I"),
        0x2C: (PAGE, "I"),
        0x40: (at["objects"], "I"),
        0x44: (2, "I"),
        0x48: (at["pages"], "I"),
        0x58: (at["resident"], "I"),
        0x5C: (at["entry"], "I"),
        0x68: (at["fixup_pages"], "I"),
        0x6C: (at["records"], "I"),
        0x70: (at["imports"], "I"),
        0x74: (1, "I"),
        0x94: (2, "I"),
    }
    for off, (value, kind) in values.items():
        struct.pack_into("<" + kind, header, off, value)
    data_pages = HEADER_AT + len(header) + len(tables)
    data_pages += -data_pages % 16
    struct.pack_into("<I", header, 0x80, data_pages)
    image = bytes(stub) + bytes(header) + bytes(tables)
    image += b"\0" * (data_pages - len(image)) + bytes(code) + bytes(data)
    path = folder / "MAIN.EXE"
    path.write_bytes(image)
    return path


class LeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.exe = build(self.folder)

    def tearDown(self):
        self.tmp.cleanup()

    def test_object_table_and_header(self):
        d = le.info(le.read_module(self.exe))
        self.assertEqual(d["stub"]["extender"], "DOS/4GW stub (starts DOS4GW.EXE)")
        self.assertEqual(d["header"]["format"], "LE")
        self.assertEqual(d["header"]["offset"], HEADER_AT)
        self.assertEqual(d["header"]["name"], "main")
        objects = [(o["base"], o["size"], o["bits"], o["access"], o["pages"]) for o in d["objects"]]
        self.assertEqual(
            objects, [(CODE_BASE, 2 * PAGE, 32, "r-x", 2), (DATA_BASE, PAGE, 32, "rw-", 1)]
        )
        self.assertEqual(d["objects"][0]["flag_names"], ["preload"])
        self.assertEqual(d["imports"], ["KERNEL"])
        self.assertEqual(d["problems"], [])

    def test_fixup_counts_by_kind(self):
        d = le.info(le.read_module(self.exe))
        self.assertEqual(d["fixups"]["records"], 5)
        self.assertEqual(
            d["fixups"]["by_kind"],
            {
                "32-bit offset, internal": 3,
                "32-bit offset, import by ordinal": 1,
                "32-bit self-relative, internal": 1,
            },
        )

    def test_entry_point(self):
        e = le.read_module(self.exe).entry_point()
        self.assertEqual(e, {"object": 1, "offset": 0x20, "address": CODE_BASE + 0x20})

    def test_dump_applies_internal_32_bit_fixups_at_the_chosen_base(self):
        module = le.read_module(self.exe)
        base = 0x400000
        bases = le.load_bases(module, 1, base, [])
        self.assertEqual(bases, {1: base, 2: base + (DATA_BASE - CODE_BASE)})
        dump = le.dump_object(module, 1, bases)
        word = lambda at: struct.unpack_from("<I", dump.data, at)[0]
        self.assertEqual(len(dump.data), 2 * PAGE)
        self.assertEqual(word(0x04), bases[2] + 0x10)
        self.assertEqual(word(0x40), (base + 0x120) - (base + 0x40 + 4))
        self.assertEqual(word(0xFE), bases[2] + 0x30)  # across the page boundary
        self.assertEqual(word(PAGE + 0x08), 0x90909090)  # the import stays as it was
        self.assertEqual(
            dump.applied, {"32-bit offset, internal": 2, "32-bit self-relative, internal": 1}
        )
        self.assertEqual(dump.skipped, {"32-bit offset, import by ordinal": 1})
        self.assertEqual(dump.data[0x20], 0x90)

    def test_object_base_override(self):
        module = le.read_module(self.exe)
        bases = le.load_bases(module, 1, None, ["2=0x800000"])
        dump = le.dump_object(module, 1, bases)
        self.assertEqual(struct.unpack_from("<I", dump.data, 0x04)[0], 0x800010)

    def test_dump_object_command_writes_the_file(self):
        out = self.folder / "out" / "code.bin"
        err = io.StringIO()
        with redirect_stderr(err):
            code = le.main(
                [
                    "--caller-cwd",
                    str(self.folder),
                    "dump-object",
                    "MAIN.EXE",
                    "2",
                    "--out",
                    str(out),
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(out.read_bytes(), b"D" * PAGE)
        self.assertIn("0 fixups applied", err.getvalue())

    def test_info_command_json_and_text(self):
        for extra in (["--json"], []):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = le.main(["--caller-cwd", str(self.folder), "info", "MAIN.EXE", *extra])
            self.assertEqual(code, 0)
            if extra:
                self.assertEqual(json.loads(buf.getvalue())["entry_point"]["object"], 1)
            else:
                self.assertIn("entry point object 1 + 0x20 = 0x00010020", buf.getvalue())

    def test_refuses_a_file_that_is_not_le(self):
        pe = bytearray(0x200)
        pe[0:2] = b"MZ"
        struct.pack_into("<HH", pe, 2, 0x200 % 512, 1)
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\0\0"
        (self.folder / "pe.exe").write_bytes(pe)
        (self.folder / "text.txt").write_bytes(b"not an executable at all")
        for name in ("pe.exe", "text.txt"):
            with self.assertRaises(le.LeError):
                le.read_module(self.folder / name)
            with redirect_stderr(io.StringIO()):
                code = le.main(["--caller-cwd", str(self.folder), "info", name])
            self.assertEqual(code, 2)

    def test_refuses_a_truncated_module(self):
        data = self.exe.read_bytes()
        cut = self.folder / "cut.exe"
        cut.write_bytes(data[: HEADER_AT + 0x60])
        with self.assertRaises(le.LeError):
            le.read_module(cut)


if __name__ == "__main__":
    unittest.main()
