"""le services: an LE program built here with known INT, IN/OUT, segment load, far and 16-bit
sequences, a pointer table in the code, dead code and a table of `int n; ret` stubs, inventoried."""

from __future__ import annotations

import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rea_suite import le, le_services
from rea_suite.test_le import fixup_internal

PAGE = 0x100
CODE, DATA = 0x10000, 0x20000
HEADER_AT = 0x80


def fixup_selector(srcoff: int, obj: int) -> bytes:
    return struct.pack("<BBhB", 0x02, 0x00, srcoff, obj)


def assemble(folder: Path, objects: list[tuple[int, int, bytes]], fixups: list[bytes]) -> Path:
    """An LE module: `objects` as (base, flags, bytes), one page each, `fixups` the records of each
    page, the entry point at object 1 + 0."""
    stub = bytearray(HEADER_AT)
    stub[0:2] = b"MZ"
    struct.pack_into("<HHHH", stub, 2, HEADER_AT % 512, 1, 0, 4)
    struct.pack_into("<I", stub, 0x3C, HEADER_AT)
    table = b"".join(
        struct.pack("<6I", len(data), base, flags, i + 1, 1, 0)
        for i, (base, flags, data) in enumerate(objects)
    )
    pages = b"".join(bytes([0, 0, i + 1, 0]) for i in range(len(objects)))
    starts, total = [], 0
    for records in fixups:
        starts.append(total)
        total += len(records)
    starts.append(total)
    blobs = [
        ("objects", table),
        ("pages", pages),
        ("fixup_pages", struct.pack(f"<{len(starts)}I", *starts)),
        ("records", b"".join(fixups)),
    ]
    tables, at = bytearray(), {}
    for name, blob in blobs:
        at[name] = 0xB0 + len(tables)
        tables += blob
    header = bytearray(0xB0)
    header[0:2] = b"LE"
    for off, value in {
        0x08: 2,
        0x0A: 1,
        0x14: len(objects),
        0x18: 1,
        0x28: PAGE,
        0x2C: PAGE,
        0x40: at["objects"],
        0x44: len(objects),
        0x48: at["pages"],
        0x68: at["fixup_pages"],
        0x6C: at["records"],
    }.items():
        struct.pack_into("<I" if off != 0x08 and off != 0x0A else "<H", header, off, value)
    data_pages = HEADER_AT + len(header) + len(tables)
    data_pages += -data_pages % 16
    struct.pack_into("<I", header, 0x80, data_pages)
    image = bytes(stub) + bytes(header) + bytes(tables)
    image += b"\0" * (data_pages - len(image))
    image += b"".join(data.ljust(PAGE, b"\0") for _, _, data in objects)
    path = folder / "MAIN.EXE"
    path.write_bytes(image)
    return path


def program() -> tuple[bytes, list[bytes]]:
    """The code page and its fixups. Offsets in the comments; CODE is the object's base."""
    code = bytearray(b"\x90" * PAGE)

    def put(at: int, hexes: str) -> None:
        raw = bytes.fromhex(hexes)
        code[at : at + len(raw)] = raw

    # entry (0x00): reached by flow
    put(0x00, "66b80003 b310 cd31")  # mov ax,0300h; mov bl,10h; int 31h (simulate RM int 10h)
    put(0x08, "b43d b002 cd21")  # mov ah,3Dh; mov al,2; int 21h (open, read/write)
    put(0x0E, "66bac803 ee 6642 ee")  # mov dx,3C8h; out dx,al; inc dx; out dx,al (3C9h)
    put(0x16, "e460")  # in al,60h
    put(0x18, "668cd8 8ec0")  # mov ax,ds; mov es,ax
    put(0x1D, "1e 0fa1")  # push ds; pop fs
    put(0x20, "0fb54514")  # lgs eax,[ebp+14h]
    put(0x24, "8b03 cd21")  # mov eax,[ebx]; int 21h (AH unknown)
    put(0x28, "e853000000")  # call 0x80
    put(0x2D, "66b80000 8ed8")  # mov ax,<selector of object 2>; mov ds,ax
    put(0x33, "678b07")  # mov eax,[bx]: the address-size prefix
    put(0x36, "ff18 c3")  # call fword ptr [eax]; ret
    # 0x40: a pointer to 0xA0 (a fixup), whose bytes would decode as `mov al, [...]`
    # 0x60: dead code, found only by the gap pass
    put(0x60, "b44c cd21 c3")  # mov ah,4Ch; int 21h; ret
    # 0x80: called from the entry
    put(0x80, "66b80c00 cd33 c3")  # mov ax,000Ch; int 33h (event handler); ret
    # 0xA0: reached only through pointers (a fixup target)
    put(0xA0, "b400 b013 cd10 c3")  # mov ah,0; mov al,13h; int 10h (mode 13h); ret
    # 0xB0: AH set before a branch target does not count
    put(0xB0, "b409 eb00 cd21 c3")  # mov ah,9; jmp 0xB4; int 21h; ret
    # 0xC0: a table of `int n; ret` for n = 0..9, reached by the gap pass
    put(0xC0, "".join(f"cd{n:02x}c3" for n in range(10)))
    fixups = (
        fixup_selector(0x2F, 2)
        + fixup_internal(0x40, 1, 0xA0)
        + fixup_internal(0x44, 1, 0xB0)  # makes 0xB0 reachable
    )
    return bytes(code), [fixups]


class LeServicesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        code, fixups = program()
        data_fixups = fixup_internal(0x00, 1, 0xA0)
        self.exe = assemble(
            self.folder,
            [(CODE, 0x2045, code), (DATA, 0x2043, b"D" * 0x10)],
            [fixups[0], data_fixups],
        )
        self.d = le_services.inventory(le.read_module(self.exe))

    def tearDown(self):
        self.tmp.cleanup()

    def sites(self, kind: str) -> dict[int, dict]:
        return {s["address"] - CODE: s for s in self.d[kind]}

    def test_interrupts_with_their_function_registers(self):
        ints = self.sites("interrupts")
        self.assertEqual(sorted(ints), [0x06, 0x0C, 0x26, 0x62, 0x84, 0xA4, 0xB4])
        dpmi = ints[0x06]
        self.assertEqual((dpmi["service_function"], dpmi["subfunction"]), (0x0300, 0x10))
        self.assertEqual(dpmi["service"], "simulate real-mode interrupt")
        self.assertEqual(dpmi["group"], "real-mode calls")
        self.assertEqual(le_services.service_key(dpmi), "INT 31h AX=0300h BL=10h")
        self.assertEqual(le_services.service_key(ints[0x0C]), "INT 21h AH=3Dh AL=02h")
        self.assertEqual(ints[0x84]["service"], "set event handler (callback)")
        self.assertEqual(le_services.service_key(ints[0xA4]), "INT 10h AH=00h AL=13h")
        self.assertEqual(ints[0x62]["service"], "exit")

    def test_unknown_or_out_of_block_values_stay_unresolved(self):
        ints = self.sites("interrupts")
        self.assertFalse(ints[0x26]["resolved"])  # AH from memory
        self.assertFalse(ints[0xB4]["resolved"])  # AH set before a branch target
        self.assertEqual(self.d["summary"]["unresolved"]["interrupts"], 2)

    def test_how_each_site_was_reached_and_its_function(self):
        ints = self.sites("interrupts")
        self.assertEqual(ints[0x06]["found_by"], "flow")
        self.assertEqual(ints[0xA4]["found_by"], "flow")  # a fixup target
        self.assertEqual(ints[0x62]["found_by"], "gap")  # dead code
        self.assertEqual(ints[0x84]["function"], CODE + 0x80)
        self.assertTrue(ints[0x84]["function_known"])

    def test_a_pointer_in_code_is_not_decoded(self):
        code = le_services.decode(le.read_module(self.exe))
        self.assertFalse(any(CODE + 0x40 <= a < CODE + 0x48 for a in code.insns))

    def test_a_table_of_int_stubs_is_listed_once(self):
        (table,) = self.d["interrupt_tables"]
        self.assertEqual((table["address"] - CODE, table["first"], table["last"]), (0xC0, 0, 9))
        self.assertFalse(any(0xC0 <= a < 0xDE for a in self.sites("interrupts")))

    def test_ports_immediate_and_through_dx(self):
        ports = self.sites("ports")
        self.assertEqual(ports[0x12]["port"], 0x3C8)
        self.assertEqual(ports[0x12]["port_name"], "VGA DAC write index")
        self.assertEqual(ports[0x15]["port"], 0x3C9)  # after inc dx
        self.assertEqual((ports[0x16]["direction"], ports[0x16]["port"]), ("in", 0x60))
        self.assertEqual(ports[0x16]["via"], "immediate")

    def test_segment_loads(self):
        loads = self.sites("segment_loads")
        self.assertEqual((loads[0x1B]["register"], loads[0x1B]["value"]), ("es", "copy of ds"))
        self.assertEqual((loads[0x1E]["register"], loads[0x1E]["value"]), ("fs", "copy of ds"))
        self.assertEqual(loads[0x20]["register"], "gs")
        self.assertEqual(loads[0x20]["source"], "far pointer in memory")
        self.assertFalse(loads[0x20]["resolved"])
        self.assertEqual(loads[0x31]["value"], "selector of object 2")

    def test_far_and_sixteen_bit(self):
        far = self.sites("far_transfers")
        self.assertEqual(far[0x36]["kind"], "far call")
        six = self.d["sixteen_bit"]
        self.assertEqual([s["address"] - CODE for s in six["address_size_prefix"]], [0x33])
        self.assertEqual(six["fixups_in_code"], {"16-bit selector, internal": 1})
        self.assertEqual(six["objects"], [])

    def test_command_text_and_json(self):
        for extra in (["--json"], []):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = le.main(["--caller-cwd", str(self.folder), "services", "MAIN.EXE", *extra])
            self.assertEqual(code, 0)
            if extra:
                services = json.loads(buf.getvalue())["summary"]["services"]
                self.assertIn("INT 33h AX=000Ch", [s["key"] for s in services])
            else:
                self.assertIn("INT 31h AX=0300h BL=10h", buf.getvalue())
                self.assertIn("unresolved  2 interrupts, 0 ports", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
