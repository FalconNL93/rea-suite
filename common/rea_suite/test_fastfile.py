"""IW3 fastfiles on synthetic files built here (the layout fastfile.py describes): the header, the
zlib stream, the zone's sizes and asset list, the simple assets found by shape among others, the
extraction and its path checks. REA_FASTFILE_SAMPLE=<a CoD4 PC .ff> reads a real one too."""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from rea_suite import fastfile

FF = struct.pack("<I", 0xFFFFFFFF)


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


def type_id(name: str) -> int:
    return fastfile.IW3_ASSET_TYPES.index(name)


def zone(assets: list[tuple[str, bytes]], strings: list[str] = ("j_head",)) -> bytes:
    """The zone: sizes, the asset list (script strings, then the assets' types), then each
    asset's data in order."""
    body = u32(len(strings)) + FF + u32(len(assets)) + FF
    body += FF * len(strings) + b"".join(s.encode() + b"\0" for s in strings)
    # the assets' array follows the last string unaligned, as in the game's zones ("j_head" ends
    # at an odd offset)
    body += b"".join(u32(type_id(kind)) + FF for kind, _ in assets)
    body += b"".join(data for _, data in assets)
    head = u32(len(body)) + u32(0) + b"".join(u32(0x1000 * (i + 1)) for i in range(9))
    return head + body


def rawfile(name: str, data: bytes) -> bytes:
    return FF + u32(len(data)) + FF + name.encode() + b"\0" + data + b"\0"


def stringtable(name: str, rows: list[list[str]]) -> bytes:
    cells = [c for row in rows for c in row]
    return (FF + u32(len(rows[0])) + u32(len(rows)) + FF + name.encode() + b"\0" + FF * len(cells)
            + b"".join(c.encode() + b"\0" for c in cells))  # fmt: skip


def localize(name: str, value: str) -> bytes:
    return FF + FF + value.encode() + b"\0" + name.encode() + b"\0"


def fastfile_bytes(z: bytes, magic: bytes = b"IWffu100", version: bytes = u32(5)) -> bytes:
    return magic + version + zlib.compress(z)


SAMPLE = [
    ("material", b"\x00\x11" + FF + b"noise that is no asset we read\x00" + bytes(range(40))),
    ("rawfile", rawfile("maps/mp/_load.gsc", b"main()\n{\n}\n")),
    ("stringtable", stringtable("mp/statstable.csv", [["0", "rank"], ["1", "a,b"]])),
    ("localize", localize("MENU_START_GAME", "Start game")),
    ("rawfile", rawfile("../../escape.cfg", b"bind x quit\n")),
    ("rawfile", rawfile("empty.cfg", b"")),  # a zero-length raw file
    ("material", localize("P0", "PC")),  # the ordinary shape with a name that is no localize key
    (
        "localize",
        FF + FF + "\u00a9 2007".encode("cp1252") + b"\0MENU_COPYRIGHT\0",
    ),  # cp1252, not UTF-8
    # a table of {u32, -1} pairs, which has a raw file's shape with 47 ('/') as its name
    ("material", FF + u32(8) + FF + u32(0x2F) + FF + u32(2) + FF + u32(0x11) + FF + bytes(8)),
    # a name or value that is an earlier string: an encoded pointer (block 4, offset 0x122) for -1
    ("localize", u32(0x40000123) + FF + b"CGAME_SPECTATORS\0"),
    ("rawfile", u32(0x40000200) + u32(5) + FF + b"hello\0"),  # not found: its name is unresolved
    # material data with the shared localize shape and a name that is no localize key
    ("material", u32(0x40000300) + FF + b"P0\0" + bytes(4)),
    ("image", b"\x00" * 16),
]


class Reading(unittest.TestCase):
    def setUp(self) -> None:
        self.zone = fastfile.read(fastfile_bytes(zone(SAMPLE)))

    def test_header_sizes_and_the_asset_list(self) -> None:
        z = self.zone
        self.assertEqual((z.game, z.platform, z.version), ("IW3", "pc", 5))
        self.assertEqual(z.blocks["temp"], 0x1000)
        self.assertEqual(z.blocks["index"], 0x9000)
        self.assertEqual(z.strings, ["j_head"])
        self.assertEqual(z.counts()["rawfile"], 4)
        self.assertEqual(z.assets[0], "material")
        self.assertTrue(all(not kind.startswith("type") for kind in z.assets))  # each a known type

    def test_the_simple_assets_are_found_among_others(self) -> None:
        found = {(f.type, f.name) for f in self.zone.found}
        self.assertFalse(any(f.type == "rawfile" and f.shared for f in self.zone.found))
        self.assertNotIn("P0", {f.name for f in self.zone.found})
        spectators = next(f for f in self.zone.found if f.name == "CGAME_SPECTATORS")
        self.assertEqual((spectators.value, spectators.shared), (None, 0x40000123))
        self.assertEqual(
            found,
            {("rawfile", "maps/mp/_load.gsc"), ("stringtable", "mp/statstable.csv"),
             ("localize", "MENU_START_GAME"), ("rawfile", "../../escape.cfg"),
             ("rawfile", "empty.cfg"), ("localize", "MENU_COPYRIGHT"),
             ("localize", "CGAME_SPECTATORS")},
        )  # fmt: skip
        table = next(f for f in self.zone.found if f.type == "stringtable")
        self.assertEqual(table.rows, [["0", "rank"], ["1", "a,b"]])
        self.assertEqual(self.zone.as_json()["by_type"]["rawfile"], {"listed": 4, "found": 3})

    def test_extraction_stays_inside_its_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            written = fastfile.extract(self.zone, root, set(fastfile.EXTRACTED))
            self.assertEqual(written, {"rawfile": 3, "stringtable": 1, "localize": 3})
            self.assertEqual((root / "maps/mp/_load.gsc").read_bytes(), b"main()\n{\n}\n")
            self.assertEqual((root / "escape.cfg").read_bytes(), b"bind x quit\n")  # `..` dropped
            self.assertEqual((root / "mp/statstable.csv").read_text(), '0,rank\n1,"a,b"\n')
            self.assertEqual(
                json.loads((root / "localize.json").read_text()),
                {
                    "MENU_START_GAME": "Start game",
                    "MENU_COPYRIGHT": "\u00a9 2007",
                    "CGAME_SPECTATORS": None,  # a shared string, not resolved
                },
            )
            self.assertFalse((Path(tmp) / "escape.cfg").exists())

    def test_debug_shows_the_gap_where_an_asset_was_not_found(self) -> None:
        hidden = list(SAMPLE)
        hidden.insert(
            2, ("rawfile", u32(0) + rawfile("hidden.gsc", b"x")[4:])
        )  # a name pointer of 0
        lines = fastfile.debug_lines(fastfile.read(fastfile_bytes(zone(hidden))))
        self.assertIn("rawfile: 3 found of 5 listed, in 3 run(s) of the list", lines)
        gap = next(
            i
            for i, line in enumerate(lines)
            if "between maps/mp/_load.gsc and ../../escape.cfg" in line
        )
        self.assertTrue(
            lines[gap + 1].strip().startswith("00 00 00 00 01 00 00 00 ff ff ff ff 68 69")
        )

    def test_other_fastfiles_are_named_and_refused(self) -> None:
        z = zone(SAMPLE)
        with self.assertRaisesRegex(fastfile.FastfileError, "xbox360"):
            fastfile.read(fastfile_bytes(z, version=struct.pack(">I", 1)))
        with self.assertRaisesRegex(fastfile.FastfileError, "signed"):
            fastfile.read(fastfile_bytes(z, magic=b"IWff0100"))
        with self.assertRaisesRegex(fastfile.FastfileError, "does not know"):
            fastfile.read(fastfile_bytes(z, version=u32(0x114)))  # IW4
        with self.assertRaisesRegex(fastfile.FastfileError, "no IWff"):
            fastfile.read(b"PK\x03\x04" + bytes(20))
        with self.assertRaisesRegex(fastfile.FastfileError, "zlib"):
            fastfile.read(b"IWffu100" + u32(5) + b"not zlib at all")

    def test_the_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "mp_test.ff").write_bytes(fastfile_bytes(zone(SAMPLE)))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(fastfile.main(["--caller-cwd", tmp, "info", "mp_test.ff"]), 0)
            self.assertIn("rawfile                 4 (3 found)", out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = fastfile.main(
                    [
                        "--caller-cwd",
                        tmp,
                        "extract",
                        "mp_test.ff",
                        "--out",
                        "x",
                        "--type",
                        "rawfile",
                    ]
                )
            self.assertEqual((code, out.getvalue().strip()), (0, "3 rawfile"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                fastfile.main(["--caller-cwd", tmp, "list", "mp_test.ff", "--json"])
            values = {r["name"]: r.get("value", "-") for r in json.loads(out.getvalue())}
            self.assertEqual(
                (values["MENU_START_GAME"], values["CGAME_SPECTATORS"]), ("Start game", None)
            )
            self.assertEqual(values["maps/mp/_load.gsc"], "-")  # only a localized string has one
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fastfile.main(["--caller-cwd", tmp, "info", "missing.ff"]), 2)


@unittest.skipUnless(os.environ.get("REA_FASTFILE_SAMPLE"), "reads a real CoD4 PC fastfile")
class Sample(unittest.TestCase):
    def test_a_real_fastfile(self) -> None:
        z = fastfile.read(Path(os.environ["REA_FASTFILE_SAMPLE"]).read_bytes())
        self.assertEqual((z.game, z.platform), ("IW3", "pc"))
        self.assertTrue(z.assets)
        # every type one of IW3's 33 (an array read at the wrong offset gives 0xFFFFFF00)
        unknown = [kind for kind in z.assets if kind.startswith("type")]
        self.assertEqual(unknown, [], f"{len(unknown)} assets of unknown types")
        listed, found = z.counts(), z.found_counts()
        print("\n".join(fastfile.info_lines(z)))
        for kind in fastfile.EXTRACTED:
            names = sorted(f.name for f in z.found if f.type == kind)
            self.assertLessEqual(found[kind], listed[kind], f"{kind}: {names}")


if __name__ == "__main__":
    unittest.main()
