"""rmdp: Remedy packages built here in two layouts (Alan Wake Remastered's version 2, big-endian with 64-bit
links and aligned records; American Nightmare's version 7, little-endian and packed), read back."""

from __future__ import annotations

import io
import struct
import tempfile
import unittest
import zlib
from contextlib import redirect_stdout
from pathlib import Path

from rea_suite import rmdp

FILES = {
    "data/maps.txt": b"Map list\n",
    "data/maps/intro.txt": b"Intro\n",
    "data/Readme.txt": b"Read me first\n",
}


def build(folder: Path, version: int, aligned: bool, big: bool) -> Path:
    """A package of FILES in the given layout, with the root, `data` and `maps` folders."""
    order = ">" if big else "<"
    link = "Q" if aligned or version >= 8 else "I"
    null = 0xFFFFFFFFFFFFFFFF if link == "Q" else 0xFFFFFFFF
    names = b""

    def name(text: str) -> int:
        nonlocal names
        at = len(names)
        names += text.encode() + b"\0"
        return at

    # Folders: 0 root, 1 data, 2 maps. Files: 0 maps.txt, 1 intro.txt, 2 Readme.txt.
    folder_names = [None, "data", "maps"]
    folder_rows = [
        (null, null, 1, null),
        (null, 0, 2, 0),
        (null, 1, null, 1),
    ]  # next, parent, child, first file
    file_rows = [
        ("maps.txt", 2, 1),
        ("intro.txt", null, 2),
        ("Readme.txt", null, 1),
    ]  # name, next, parent
    contents = [FILES["data/maps.txt"], FILES["data/maps/intro.txt"], FILES["data/Readme.txt"]]
    data = b""
    offsets = []
    for c in contents:
        offsets.append(len(data))
        data += c + b"\0" * (-len(c) % 8)
    folder_bytes = b""
    for n, (nxt, parent, child, first) in zip(folder_names, folder_rows):
        at = name(n) if n else null
        check = rmdp.name_checksum(n.encode()) if n else 0
        if aligned:
            folder_bytes += struct.pack(
                order + "I4xQQI4xQQQ", check, nxt, parent, 0, at, child, first
            )
        else:
            folder_bytes += struct.pack(
                order + "I" + link * 2 + "I" + link * 3, check, nxt, parent, 0, at, child, first
            )
    file_bytes = b""
    for (n, nxt, parent), off, c in zip(file_rows, offsets, contents):
        at = name(n)
        check = rmdp.name_checksum(n.encode())
        crc = struct.pack("<I", zlib.crc32(c))
        if aligned:
            head = struct.pack(order + "I4xQQI4xQQQ", check, nxt, parent, 0, at, off, len(c))
            file_bytes += head + crc + b"\0" * 4
        else:
            head = struct.pack(
                order + "I" + link * 2 + "I" + link + "QQ", check, nxt, parent, 0, at, off, len(c)
            )
            file_bytes += head + crc + (struct.pack(order + "Q", 0) if version >= 7 else b"")
    header = bytes([1 if big else 0]) + struct.pack(order + "III", version, 3, 3)
    if version >= 7:
        header += struct.pack(order + "Q", 1)
    header += struct.pack(order + "I", len(names)) + b"d:\\data".ljust(128, b"\0")
    closing = b""
    if version >= 7:
        closing = struct.pack(
            order + "I" + link * 2 + "I" + link * 3, 0, null, null, 0, null, null, null
        )
    index = folder / "sample.bin"
    index.write_bytes(header + folder_bytes + file_bytes + closing + names)
    (folder / "sample.rmdp").write_bytes(data)
    return index


def container(width: int) -> bytes:
    fmt = "<Q" if width == 8 else "<I"
    entries = [("cid_script.bin", b"call UnlockAchievement 7"), ("dp_ldcell.bin", b"\x01\x02")]
    table = struct.pack(fmt, len(entries))
    for n, c in entries:
        table += struct.pack(fmt, len(n)) + n.encode() + struct.pack(fmt, len(c))
    return table + zlib.compress(b"".join(c for _, c in entries))


class RmdpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def check_layout(self, version: int, aligned: bool, big: bool, expected: str) -> None:
        package = rmdp.read_package(build(self.dir, version, aligned, big))
        self.assertEqual(package.layout, expected)
        self.assertEqual(package.base_path, "d:\\data")
        self.assertEqual(package.warnings, [])
        self.assertEqual(sorted(e.path for e in package.files), sorted(FILES))
        with package.data.open("rb") as data:
            for e in package.files:
                self.assertEqual(rmdp.read_file(data, e), FILES[e.path])
                self.assertEqual(zlib.crc32(FILES[e.path]), e.crc)

    def test_remastered_layout(self) -> None:
        self.check_layout(2, aligned=True, big=True, expected="v2-aligned")

    def test_alan_wake_layout(self) -> None:
        self.check_layout(2, aligned=False, big=True, expected="v2-packed")

    def test_american_nightmare_layout(self) -> None:
        self.check_layout(7, aligned=False, big=False, expected="v7")

    def test_name_checksum_is_case_blind(self) -> None:
        self.assertEqual(rmdp.name_checksum(b"Readme.txt"), 0x22598B08)
        self.assertEqual(rmdp.name_checksum(b"readme.txt"), 0x22598B08)

    def test_extract_refuses_the_package_folder(self) -> None:
        index = build(self.dir, 2, aligned=True, big=True)
        code = rmdp.main(
            [
                "--caller-cwd",
                str(self.dir),
                "extract",
                str(index),
                "*",
                "--out",
                str(self.dir / "x"),
            ]
        )
        self.assertEqual(code, 2)

    def test_extract_and_find(self) -> None:
        (self.dir / "pkg").mkdir()
        index = build(self.dir / "pkg", 2, aligned=True, big=True)
        out = self.dir / "out"
        self.assertEqual(
            rmdp.main(["extract", str(index), "data/maps/*", "--out", str(out), "--check"]), 0
        )
        self.assertEqual((out / "data" / "maps" / "intro.txt").read_bytes(), b"Intro\n")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(rmdp.main(["find", str(index), "--text", "first"]), 0)
        self.assertIn("data/Readme.txt  1x  0x8", buffer.getvalue())

    def test_inner_containers_in_both_widths(self) -> None:
        for width in (4, 8):
            entries = rmdp.inner_entries(container(width))
            self.assertEqual([n for n, _ in entries], ["cid_script.bin", "dp_ldcell.bin"])
            self.assertEqual(entries[0][1], b"call UnlockAchievement 7")
        self.assertIsNone(rmdp.inner_entries(b"not a container at all"))

    def test_safe_names(self) -> None:
        self.assertEqual(rmdp.safe_name("d:"), "d%3A")
        self.assertEqual(rmdp.safe_name("nul.txt"), "%6Eul.txt")
        self.assertEqual(rmdp.safe_name("trailing."), "trailing%2E")


if __name__ == "__main__":
    unittest.main()
