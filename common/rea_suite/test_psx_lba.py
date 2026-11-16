"""`playstation lba-table` and the ISO 9660 listing, on a synthetic disc and executable (no game
bytes): the shape of Duke Nukem: Time to Kill's table, (LBA - 23, size) pairs, with an empty slot."""

from __future__ import annotations

import io
import json
import random
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rea_suite import iso9660, playstation, psx_lba

LOAD = 0x80010000
TABLE_OFFSET = 0x400  # in the payload


def record(name: bytes, lba: int, size: int, directory: bool = False) -> bytes:
    body = struct.pack("<BB", 0, 0)  # length set below, no extended attributes
    body += struct.pack("<I", lba) + struct.pack(">I", lba)
    body += struct.pack("<I", size) + struct.pack(">I", size)
    body += bytes(7) + bytes([2 if directory else 0, 0, 0]) + struct.pack("<HH", 1, 1)
    body += bytes([len(name)]) + name
    if len(body) % 2:
        body += b"\0"
    return bytes([len(body)]) + body[1:]


def directory(own: int, parent: int, entries: list[bytes]) -> bytes:
    data = record(b"\0", own, 2048, True) + record(b"\1", parent, 2048, True) + b"".join(entries)
    return data.ljust(2048, b"\0")


def disc(files: list[tuple[str, int]]) -> tuple[bytes, list[iso9660.DiscFile]]:
    """A cooked ISO 9660 image: the root at 18, a DATA folder at 19, the files from 30 on."""
    sectors: dict[int, bytes] = {}
    lba, placed = 30, []
    for name, size in files:
        placed.append(iso9660.DiscFile(name, lba, size))
        sectors[lba] = bytes([len(placed)]) * max(size, 1)
        lba += max(1, -(-size // 2048))
    root = [record(f.path.encode() + b";1", f.lba, f.size) for f in placed if "/" not in f.path]
    root.append(record(b"DATA", 19, 2048, True))
    sub = [
        record(f.path.split("/")[1].encode() + b";1", f.lba, f.size)
        for f in placed
        if "/" in f.path
    ]
    sectors[18] = directory(18, 18, root)
    sectors[19] = directory(19, 18, sub)
    pvd = bytearray(2048)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[156 : 156 + 34] = record(b"\0", 18, 2048, True)
    sectors[16] = bytes(pvd)
    sectors[17] = b"\xffCD001\x01".ljust(2048, b"\0")
    image = bytearray(lba * 2048)
    for n, data in sectors.items():
        image[n * 2048 : n * 2048 + len(data)] = data
    return bytes(image), placed


def raw(cooked: bytes) -> bytes:
    """The same image as Mode 2 Form 1 raw sectors, as a .bin holds it."""
    out = bytearray()
    for n in range(len(cooked) // 2048):
        out += iso9660.SYNC + bytes([0, 2, n % 75, 2]) + bytes(8)
        out += cooked[n * 2048 : (n + 1) * 2048] + bytes(280)
    return bytes(out)


def executable(table: bytes) -> bytes:
    rng = random.Random(7)  # noise with small words in it, as a real data section has
    words = [rng.choice((0, 1, 2, 3, 0x80, 4096, rng.getrandbits(32))) for _ in range(0x800)]
    payload = bytearray(struct.pack(f"<{len(words)}I", *words))
    payload[TABLE_OFFSET : TABLE_OFFSET + len(table)] = table
    head = bytearray(0x800)
    head[:8] = b"PS-X EXE"
    struct.pack_into("<4I", head, 0x10, LOAD, 0, LOAD, len(payload))
    return bytes(head + payload)


FILES = [("SYSTEM.CNF", 68), ("SLUS_000.00", 300000)] + [
    (f"DATA/LEVEL{n:02}.OVR", 5000 + n * 777) for n in range(12)
]


class LbaTable(unittest.TestCase):
    def setUp(self) -> None:
        self.image, self.files = disc(FILES)
        pairs = [(f.lba - 23, f.size) for f in self.files]
        pairs.insert(5, (0, 0))  # an empty slot
        self.table = b"".join(struct.pack("<2I", a, s) for a, s in pairs)

    def test_the_listing_reads_cooked_and_raw_images_and_a_cue(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            iso, binary, cue = Path(d) / "g.iso", Path(d) / "g.bin", Path(d) / "g.cue"
            iso.write_bytes(self.image)
            binary.write_bytes(raw(self.image))
            cue.write_text('FILE "g.bin" BINARY\n  TRACK 01 MODE2/2352\n')
            want = sorted(self.files, key=lambda f: f.path)
            for path in (iso, binary, cue):
                self.assertEqual(iso9660.listing(iso9660.open_image(path)), want, path.name)

    def test_the_ttk_shape_is_found_with_its_bias_and_its_empty_slot(self) -> None:
        tables = psx_lba.find(LOAD, executable(self.table)[0x800:], self.files)
        self.assertEqual(len(tables), 1, [t.layout() for t in tables])
        t = tables[0]
        self.assertEqual(t.address, LOAD + TABLE_OFFSET)
        self.assertEqual((len(t.entries), t.matched), (15, 14))
        self.assertEqual((t.stride, t.order, t.unit, t.bias), (8, "lba,size", "bytes", -23))
        self.assertEqual(t.entries[0]["files"], ["SYSTEM.CNF"])
        self.assertEqual(t.entries[5]["files"], [])
        self.assertEqual(t.entries[6]["files"], ["DATA/LEVEL03.OVR"])
        self.assertIn("stored lba = disc lba - 23", t.layout())

    def test_a_wider_entry_in_sectors_size_first(self) -> None:
        table = b"".join(
            struct.pack("<4I", -(-f.size // 2048), f.lba, 0xDEADBEEF, 0) for f in self.files
        )
        tables = psx_lba.find(LOAD, executable(table)[0x800:], self.files)
        self.assertEqual(len(tables), 1, [t.layout() for t in tables])
        t = tables[0]
        self.assertEqual((t.stride, t.order, t.unit, t.bias), (16, "size,lba", "sectors", 0))
        self.assertEqual(t.matched, len(self.files))

    def test_too_short_a_run_is_not_a_table(self) -> None:
        table = b"".join(struct.pack("<2I", f.lba, f.size) for f in self.files[:5])
        self.assertEqual(psx_lba.find(LOAD, executable(table)[0x800:], self.files), [])

    def test_the_command_with_a_listing_and_a_ram_dump(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            iso, listing, ram = Path(d) / "g.iso", Path(d) / "files.txt", Path(d) / "ram.bin"
            iso.write_bytes(self.image)
            out = io.StringIO()
            with redirect_stdout(out):
                code = playstation.main(["--caller-cwd", d, "lba-table", "--disc", "g.iso", "--list"])  # fmt: skip
            self.assertEqual(code, 0)
            listing.write_text(out.getvalue())
            self.assertEqual(
                sorted(iso9660.read_listing(out.getvalue()), key=lambda f: f.path),
                sorted(self.files, key=lambda f: f.path),
            )
            memory = bytearray(0x20000)
            program = executable(self.table)[0x800:]
            memory[0x10000 : 0x10000 + len(program)] = program  # at 0x80010000
            ram.write_bytes(memory)
            out = io.StringIO()
            with redirect_stdout(out):
                code = playstation.main(
                    ["--caller-cwd", d, "lba-table", "ram.bin", "--files", "files.txt", "--json"]
                )
            self.assertEqual(code, 0)
            found = json.loads(out.getvalue())
        self.assertEqual([(t["address"], t["entries"], t["lba_bias"]) for t in found],
                         [("0x80010400", 15, -23)])  # fmt: skip


if __name__ == "__main__":
    unittest.main()
