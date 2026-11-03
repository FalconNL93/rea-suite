"""XEX reader and PowerPC searches on synthetic inputs (no game bytes)."""

from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rea_suite import ppc, xbox360, xex
from rea_suite.test_xbox360 import BASE, CALLERS, TEXT, pe

IMAGE_SIZE = 0x4000
THUNK = 0x3000  # rva of the one import thunk
XDBF_AT = 0x3100
TITLE = 0x41560001


def png(width: int = 64, height: int = 32) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I4sII", 13, b"IHDR", width, height) + bytes(9)


def xdbf(image: bytes) -> bytes:
    entries = struct.pack(">HQII", 2, 0x8000, 0, len(image))
    return struct.pack(">4sIIIII", b"XDBF", 0x10000, 1, 1, 0, 0) + entries + image


def memory_image() -> bytes:
    data = bytearray(IMAGE_SIZE)
    data[:2] = b"MZ"
    struct.pack_into(">I", data, THUNK, (1 << 24) | 3)  # function thunk, xboxkrnl ordinal 3
    resource = xdbf(png())
    data[XDBF_AT : XDBF_AT + len(resource)] = resource
    return bytes(data)


def aes(key: bytes, data: bytes, cbc: bool) -> bytes:
    mode = modes.CBC(bytes(16)) if cbc else modes.ECB()
    cipher = Cipher(algorithms.AES(key), mode).encryptor()
    return cipher.update(data) + cipher.finalize()


def make_xex(compression: int = 1, encrypted: bool = True) -> bytes:
    """An XEX2 with basic compression (stored bytes, then zeros), retail-key encryption, one
    import library, execution info and the title's XDBF resource."""
    img = memory_image()
    stored = 0x3200  # the rest of the image is zeros
    payload = img[:stored]
    session = bytes(range(16))
    if encrypted:
        payload = aes(session, payload, True)
    security, ffi, execution, imports, resources = 0x100, 0x300, 0x340, 0x380, 0x400
    pe_offset = 0x1000
    headers = [
        (0x000003FF, ffi),
        (0x00010201, BASE),
        (0x00010100, BASE + 0x100),
        (0x00040006, execution),
        (0x000103FF, imports),
        (0x000002FF, resources),
    ]
    out = bytearray(pe_offset)
    struct.pack_into(">4sIIIII", out, 0, b"XEX2", 1, pe_offset, 0, security, len(headers))
    for i, (key, value) in enumerate(headers):
        struct.pack_into(">II", out, 0x18 + 8 * i, key, value)
    struct.pack_into(">II", out, security, 0x184, IMAGE_SIZE)
    struct.pack_into(">I", out, security + 0x110, BASE)
    out[security + 0x150 : security + 0x160] = aes(xex.RETAIL_KEY, session, False)
    struct.pack_into(
        ">IHHII", out, ffi, 16, int(encrypted), compression, stored, IMAGE_SIZE - stored
    )
    struct.pack_into(">IIII4B", out, execution, 0x1234, 1, 1, TITLE, 0, 0, 1, 1)
    strings = b"xboxkrnl.exe\0\0\0\0"
    record = struct.pack(">I", 0x2C) + bytes(0x18) + struct.pack(">IIHH", 0x20000, 0x20000, 0, 1)
    record += struct.pack(">I", BASE + THUNK)
    struct.pack_into(">III", out, imports, 12 + len(strings) + len(record), len(strings), 1)
    out[imports + 12 : imports + 12 + len(strings) + len(record)] = strings + record
    name = f"{TITLE:08X}".encode()
    struct.pack_into(">I8sII", out, resources, 20, name, BASE + XDBF_AT, len(xdbf(png())))
    return bytes(out) + payload


class XexTests(unittest.TestCase):
    def test_headers_are_read(self):
        info = xex.parse(make_xex())
        h = info["headers"]
        self.assertEqual(h["FILE_FORMAT_INFO"]["compression_name"], "basic")
        self.assertEqual(h["EXECUTION_INFO"]["title_id"], "41560001")
        self.assertEqual(h["IMAGE_BASE_ADDRESS"]["value"], hex(BASE))
        libs = h["IMPORT_LIBRARIES"]["libraries"]
        self.assertEqual(
            (libs[0]["name"], libs[0]["records"]), ("xboxkrnl.exe", [hex(BASE + THUNK)])
        )

    def test_the_retail_key_opens_the_image(self):
        _, img, key = xex.image(make_xex())
        self.assertEqual((key, img), ("retail", memory_image()))
        self.assertEqual(xex.image(make_xex(encrypted=False))[2], "plain")

    def test_imports_are_named_from_xenias_tables(self):
        info, img, _ = xex.image(make_xex())
        [row] = xex.imports(info, img)
        self.assertEqual((row["type"], row["ordinal"], row["name"]), ("func", 3, "DbgPrint"))

    def test_the_title_image_is_found_and_wrapped_as_an_icon(self):
        info, img, _ = xex.image(make_xex())
        image = xex.title_image(info, img)
        self.assertEqual(image, png())
        icon = xex.ico(image)
        self.assertEqual(struct.unpack_from("<HHHBB", icon), (0, 1, 1, 64, 32))

    def test_lzx_is_refused_with_the_way_that_reads_it(self):
        with self.assertRaisesRegex(xex.XexError, "LZX.*rea-suite xbox360 analyze"):
            xex.image(make_xex(compression=2))

    def test_damaged_files_are_refused_not_overread(self):
        data = make_xex()
        with self.assertRaises(xex.XexError):
            xex.parse(data[:0x200])
        with self.assertRaisesRegex(xex.XexError, "no XEX2"):
            xex.parse(b"XEX1" + data[4:])
        bad = bytearray(data)
        struct.pack_into(">I", bad, 0x14, 100000)
        with self.assertRaisesRegex(xex.XexError, "optional headers"):
            xex.parse(bytes(bad))

    def test_the_cli_writes_the_image_and_the_named_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.xex").write_bytes(make_xex())
            with contextlib.redirect_stderr(io.StringIO()):
                xbox360.main(["--caller-cwd", tmp, "extract", "a.xex", "-o", "a.bin"])
                xbox360.main(["--caller-cwd", tmp, "imports", "a.xex", "-o", "a.tsv"])
                xbox360.main(["--caller-cwd", tmp, "icon", "a.xex", "-o", "a.png"])
            self.assertEqual((root / "a.bin").read_bytes(), memory_image())
            self.assertIn("DbgPrint", (root / "a.tsv").read_text())
            self.assertEqual((root / "a.png").read_bytes(), png())


def memory_layout(file_image: bytes) -> bytes:
    """The synthetic PE as an XEX's extracted image: sections at their RVAs."""
    _, size, sections = ppc.pe_sections(file_image)
    out = bytearray(size)
    out[:0x400] = file_image[:0x400]
    for rva, _, raw, raw_size in sections.values():
        out[rva : rva + raw_size] = file_image[raw : raw + raw_size]
    return bytes(out)


class PowerPcTests(unittest.TestCase):
    def setUp(self):
        self.img = ppc.load(pe())

    def test_pdata_lists_the_functions(self):
        entries = ppc.pdata(self.img)
        self.assertIn((BASE + TEXT, 32), entries)
        self.assertEqual(ppc.containing(entries, BASE + TEXT + 8), (BASE + TEXT, 32))
        self.assertIsNone(ppc.containing(entries, BASE))

    def test_callers_and_helpers(self):
        leaf = BASE + TEXT + 0x20 * CALLERS
        found = ppc.callers(self.img, [leaf])
        self.assertEqual(
            [(s, m) for _, s, m in found], [(BASE + TEXT + 0x20 * n + 16, "bl") for n in range(3)]
        )
        self.assertEqual(ppc.helpers(self.img)["savegprlr_14_address"], [leaf + 0x80])
        self.assertEqual(ppc.helpers(self.img)["restgprlr_14_address"], [leaf + 0xD0])

    def test_address_refs_find_lis_addi_pairs_to_a_string(self):
        data = bytearray(0x100)
        struct.pack_into(">II", data, 0, 0x3C608200, 0x38630080)  # lis r3,-0x7e00; addi r3,r3,0x80
        data[0x80:0x86] = b"hello\0"
        img = ppc.load(bytes(data), BASE)
        self.assertEqual(ppc.strings_at(img, "hello"), [BASE + 0x80])
        self.assertEqual(ppc.address_refs(img, [BASE + 0x80]), [(BASE + 0x80, BASE, BASE + 4)])

    def test_disassembly_marks_vmx128(self):
        self.assertEqual(ppc.disassemble(self.img, BASE + TEXT, 1)[0][2], "mflr r12")
        lvx128 = self.img.data.find(bytes.fromhex("100b60cb"))
        [(_, _, text)] = ppc.disassemble(self.img, BASE + lvx128, 1)
        self.assertIn("opcode 4 not decoded (VMX128?)", text)

    def test_a_memory_layout_image_is_recognized_and_its_headers_rewritten(self):
        dump = memory_layout(pe())
        self.assertTrue(ppc.memory_layout(dump))
        self.assertFalse(ppc.memory_layout(pe()))
        self.assertEqual(ppc.load(dump).data[0x1000:], self.img.data[0x1000:])
        fixed = ppc.loaded_headers(dump)
        self.assertFalse(ppc.memory_layout(fixed))
        self.assertEqual(ppc.load(fixed).data[0x1000:], self.img.data[0x1000:])

    def test_rtti_follows_descriptor_locator_and_vtable(self):
        data = bytearray(0x200)
        data[0x18:0x28] = b".?AVThing@@\0"  # descriptor at 0x10: {vtable*, spare, name}
        struct.pack_into(">5I", data, 0x40, 0, 4, 0, BASE + 0x10, 0)  # locator at 0x40
        struct.pack_into(">II", data, 0x80, BASE + 0x40, 0x82001234)  # vtable at 0x84
        result = ppc.rtti(ppc.load(bytes(data), BASE), "Thing")
        self.assertEqual(result["type_descriptor"], f"{BASE + 0x10:08X}")
        [locator] = result["locators"]
        self.assertEqual(locator["address"], f"{BASE + 0x40:08X}")
        self.assertEqual(locator["vtables"][0]["slots"][0], "82001234")

    def test_the_cli_reads_a_raw_dump_at_a_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pe.bin").write_bytes(pe())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                xbox360.main(["--caller-cwd", tmp, "helpers", "pe.bin"])
                xbox360.main(["--caller-cwd", tmp, "rtti", "pe.bin", "Nothing"])
            self.assertIn("savegprlr_14_address = 0x", out.getvalue())
            self.assertEqual(json.loads(out.getvalue().splitlines()[-1])["found"], False)


if __name__ == "__main__":
    unittest.main()
