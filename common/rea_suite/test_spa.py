"""SPA reader and writers on a synthetic SPA built here (no game bytes)."""

from __future__ import annotations

import base64
import contextlib
import gzip
import io
import json
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path

from rea_suite import spa, spa_out, xbox360, xdbf
from rea_suite.spa_out import DeclarationError, Options
from rea_suite.test_xex import make_xex

SDK = Path(os.environ.get(spa_out.SDK_ENV) or spa_out.SDK_DEFAULT)
HAVE_SDK = (SDK / spa_out.LIMITS).is_file() and (SDK / spa_out.CHECKER).is_file()


def real_png(width: int, height: int, noisy: bool = False) -> bytes:
    """An RGBA PNG; noisy pixels compress badly, to push a picture over the size limit."""
    if noisy:
        return spa_out.encode_png(width, height, random.Random(1).randbytes(width * height * 4))
    rgba = bytearray()
    for y in range(height):
        for x in range(width):
            v = (x + y) % 256
            rgba += bytes((v, (v * 3) % 256, (v * 5) % 256, 255))
    return spa_out.encode_png(width, height, bytes(rgba))


def section(magic: bytes, body: bytes) -> bytes:
    return magic + struct.pack(">II", 1, len(body) + 8) + body


def bag(contexts: list[int], properties: list[int]) -> bytes:
    ids = struct.pack(f">{len(contexts) + len(properties)}I", *contexts, *properties)
    return section(b"XPBM", struct.pack(">II", len(contexts), len(properties)) + ids)


def strings(table: dict[int, str]) -> bytes:
    body = struct.pack(">H", len(table))
    for string_id, text in table.items():
        raw = text.encode()
        body += struct.pack(">HH", string_id, len(raw)) + raw
    return section(b"XSTR", body)


def achievement(aid, name, unlocked, locked, image, points, flags) -> bytes:
    return struct.pack(">HHHHIHHI16x", aid, name, unlocked, locked, image, points, 0, flags)


XLAST = """<?xml version="1.0" encoding="UTF-16"?>
<XboxLiveSubmissionProject xmlns="http://www.xboxlive.com/xlast">
 <GameConfigProject titleName="Test Title" titleId="0x41560001">
  <Achievements>
   <Achievement id="1" titleStringId="10" descriptionStringId="11" unachievedStringId="12"
     showUnachieved="true" achievementType="Completion" friendlyName="First" cred="20" imageId="1"/>
   <Achievement id="2" titleStringId="13" descriptionStringId="14" showUnachieved="false"
     achievementType="Event" friendlyName="Hidden" cred="5" imageId="1"/>
  </Achievements>
  <Contexts>
   <Context id="0x00000000" stringId="20" friendlyName="LEVEL" defaultValue="0">
    <ContextValue friendlyName="LEVEL_BEACH" value="0" stringId="21"/>
    <ContextValue friendlyName="LEVEL_CAVE" value="1" stringId="22"/>
   </Context>
  </Contexts>
  <Properties>
   <Property id="0x10000001" stringId="23" dataSize="4" friendlyName="SCORE"/>
  </Properties>
  <Presence>
   <PresenceMode contextValue="0" stringId="30" friendlyName="MainMenu"/>
   <PresenceMode contextValue="1" stringId="31" friendlyName="Playing"/>
  </Presence>
  <LocalizedStrings>
   <LocalizedString id="10"><Translation locale="en-US">First steps</Translation>
    <Translation locale="de-DE">Erste Schritte</Translation></LocalizedString>
  </LocalizedStrings>
 </GameConfigProject>
</XboxLiveSubmissionProject>
"""

EN = {
    0x8000: "Test Title",
    10: "First steps",
    11: "You took them",
    12: "Take them",
    13: "Café “secret”",
    14: "Found it",
    20: "Level",
    21: "Beach",
    22: "Cave",
    23: "Score",
    30: "In the menus",
    31: "{c0}\r\n{p1} points",
}
DE = {**EN, 10: "Erste Schritte", 0x8000: "Testtitel"}


def make_spa(xlast: bool = True, en: dict[int, str] | None = None) -> bytes:
    """A small SPA: two achievements, English and German strings, one picture, a context,
    a property, two presence modes, the XLAST, and an unknown section."""
    xsrc = None
    if xlast:
        packed = gzip.compress(XLAST.encode("utf-16-le"))
        name = b"41560001.xlast\0"
        size = len(XLAST.encode("utf-16-le"))
        xsrc = section(
            b"XSRC",
            struct.pack(">I", len(name)) + name + struct.pack(">II", size, len(packed)) + packed,
        )
    entries = [
        (1, b"XTHD", section(b"XTHD", struct.pack(">II4H16x", 0x41560001, 1, 1, 2, 3, 4))),
        (1, b"XSTC", section(b"XSTC", struct.pack(">I", 1))),
        (
            1,
            b"XACH",
            section(
                b"XACH",
                struct.pack(">H", 2)
                + achievement(1, 10, 11, 12, 1, 20, 0x8 | 1)
                + achievement(2, 13, 14, 0xFFFF, 1, 5, 4),
            ),
        ),
        (
            1,
            b"XCXT",
            section(b"XCXT", struct.pack(">I4I4I", 2, 0, 20, 1, 0, 0x8001, 0xFFFF, 1, 0)),
        ),
        (1, b"XPRP", section(b"XPRP", struct.pack(">HIHH", 1, 0x10000001, 23, 4))),
        (
            1,
            b"XRPT",
            section(
                b"XRPT",
                bag([0, 0x8001], [0x10000001])
                + struct.pack(">H", 2)
                + bag([], [])
                + bag([0], [0x10000001]),
            ),
        ),
        (1, b"XZZZ", section(b"XZZZ", b"\1\2\3\4")),
        (2, 1, real_png(64, 64)),
        (2, 0x8000, real_png(32, 32)),
        (3, 1, strings(en or EN)),
        (3, 3, strings(DE)),
        (9, 7, b"other namespace"),
    ]
    if xsrc:
        entries.append((1, b"XSRC", xsrc))
    table, data = b"", b""
    for namespace, eid, body in entries:
        number = int.from_bytes(eid, "big") if isinstance(eid, bytes) else eid
        table += struct.pack(">HQII", namespace, number, len(data), len(body))
        data += body
    header = struct.pack(">4sIIIII", b"XDBF", 0x10000, len(entries), len(entries), 0, 0)
    return header + table + data


def write(fmt: str, data: bytes, **kw) -> tuple[Path, Options, list[Path]]:
    tmp = Path(tempfile.mkdtemp())
    options = Options(tmp / "out", **kw)
    return tmp, options, spa_out.WRITERS[fmt].write(spa.read(data), options)


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.spa = spa.read(make_spa())

    def test_the_title_comes_from_xthd_xstc_and_string_0x8000(self):
        self.assertEqual(
            self.spa.title(),
            {
                "titleId": "41560001",
                "titleType": "full",
                "version": "1.2.3.4",
                "name": "Test Title",
                "names": {"en-US": "Test Title", "de-DE": "Testtitel"},
                "defaultLanguage": "en-US",
            },
        )

    def test_achievements_carry_their_ids_texts_points_type_and_secrecy(self):
        first, hidden = self.spa.achievements()
        self.assertEqual(
            (first["id"], first["points"], first["type"], first["secret"], first["imageId"]),
            (1, 20, "Completion", False, 1),
        )
        self.assertEqual(first["name"], {"en-US": "First steps", "de-DE": "Erste Schritte"})
        self.assertEqual(first["lockedDescription"]["en-US"], "Take them")
        self.assertEqual(first["friendlyName"], "First")
        self.assertEqual(
            (hidden["type"], hidden["secret"], hidden["lockedDescription"]), ("Event", True, None)
        )

    def test_strings_are_read_per_language(self):
        self.assertEqual(self.spa.languages(), ["de-DE", "en-US"])
        self.assertEqual(self.spa.strings["de-DE"][10], "Erste Schritte")
        self.assertEqual(len(self.spa.strings["en-US"]), len(EN))

    def test_images_are_kept_by_id(self):
        self.assertEqual(sorted(self.spa.images), [1, 0x8000])
        self.assertEqual(spa_out.png_size(self.spa.images[1]), (64, 64))

    def test_presence_joins_the_binary_sections_and_the_xlast(self):
        p = self.spa.presence()
        menu, playing = p["modes"]
        self.assertEqual(menu["template"]["en-US"], "In the menus")
        self.assertEqual(
            (playing["friendlyName"], playing["contexts"]), ("Playing", ["0x00000000"])
        )
        level = p["contexts"][0]
        self.assertEqual((level["friendlyName"], level["maxValue"]), ("LEVEL", 1))
        self.assertEqual([v["text"]["en-US"] for v in level["values"]], ["Beach", "Cave"])
        self.assertEqual(p["properties"][0]["type"], "int32")

    def test_the_xlast_agrees_and_its_own_strings_are_compared(self):
        self.assertEqual(self.spa.notes, [])
        self.assertTrue(self.spa.xlast_bytes.startswith("<?xml".encode("utf-16-le")))

    def test_an_unknown_section_and_namespace_are_listed_not_dropped(self):
        listed = {(u["namespace"], u["section"]) for u in self.spa.unknown}
        self.assertEqual(listed, {(1, "XZZZ"), (9, None)})
        self.assertEqual(self.spa.summary()["unknown"], 2)

    def test_damaged_files_are_refused_not_overread(self):
        data = make_spa()
        with self.assertRaises(xdbf.XdbfError):
            spa.read(data[:200])
        bad = bytearray(data)
        struct.pack_into(">I", bad, 12, 10**6)
        with self.assertRaisesRegex(xdbf.XdbfError, "entries"):
            spa.read(bytes(bad))
        with self.assertRaisesRegex(xdbf.XdbfError, "no XDBF"):
            spa.read(b"GPDF" + data[4:])

    def test_a_disagreeing_xlast_is_reported(self):
        data = make_spa().replace(b"First steps", b"Other steps")
        notes = spa.read(data).notes
        self.assertIn("string 10 (en-US) differs from the XLAST", notes)

    def test_the_spa_is_found_in_an_xex(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "default.xex"
            path.write_bytes(make_xex())
            found, kind = spa.load(path)
        self.assertEqual((kind, sorted(found.images)), ("xex", [0x8000]))


class WriterTests(unittest.TestCase):
    def test_json_holds_everything_with_the_images_and_the_xlast_beside_it(self):
        _, options, files = write("json", make_spa())
        doc = json.loads((options.out / "spa.json").read_text())
        self.assertEqual(doc["summary"]["achievements"], 2)
        self.assertEqual(doc["strings"]["de-DE"]["10"], "Erste Schritte")
        self.assertEqual({p.name for p in files}, {"spa.json", "1.png", "32768.png", "xlast.xml"})
        self.assertEqual(len(doc["unknown"]), 2)

    def test_declarations_map_achievements_and_presence(self):
        _, options, _ = write("declarations", make_spa())
        ach = json.loads((options.out / "achievements.json").read_text())
        self.assertEqual(ach["game"], "41560001")
        first, hidden = ach["achievements"]
        self.assertEqual(
            (first["name"], first["lockedDescription"], first["type"], first["points"]),
            ("First steps", "Take them", 1, 20),
        )
        self.assertEqual(
            (hidden["name"], hidden["lockedDescription"], hidden["secret"]),
            ('Cafe "secret"', "", True),
        )
        self.assertEqual(base64.b64decode(first["picture"])[:8], spa.PNG)
        self.assertTrue(any("folded to ASCII" in n for n in options.notes))
        pres = json.loads((options.out / "presence.json").read_text())
        self.assertEqual(pres["lists"], {"level": {"level_beach": "Beach", "level_cave": "Cave"}})
        playing = pres["entries"][1]
        self.assertEqual(
            (playing["id"], playing["template"]), ("playing", "{level} - {score} points")
        )
        self.assertEqual([t["kind"] for t in playing["tokens"]], ["choice", "number"])

    def test_declarations_take_the_chosen_language(self):
        _, options, _ = write("declarations", make_spa(), lang="de-DE")
        ach = json.loads((options.out / "achievements.json").read_text())
        self.assertEqual(ach["achievements"][0]["name"], "Erste Schritte")

    def test_without_the_xlast_presence_is_left_out_and_said(self):
        _, options, files = write("declarations", make_spa(xlast=False))
        self.assertEqual([p.name for p in files], ["achievements.json"])
        self.assertTrue(any("presence.json not written" in n for n in options.notes))

    def test_a_text_over_the_limit_stops_the_run(self):
        data = make_spa(xlast=False, en={**EN, 14: "F" * 300})
        with self.assertRaisesRegex(DeclarationError, "achievement 2 description: 300 characters"):
            write("declarations", data)

    def test_a_large_picture_is_scaled_within_the_limits(self):
        big = real_png(300, 300, noisy=True)
        self.assertGreater(len(big), 65536)
        fitted = spa_out.PngScaler().fit(big, 256, 65536)
        self.assertLessEqual(len(fitted), 65536)
        self.assertLessEqual(max(spa_out.png_size(fitted)), 256)
        width, height, _ = spa_out.decode_png(fitted)
        self.assertEqual(width, height)

    @unittest.skipUnless(HAVE_SDK, "master-sdk checkout not found")
    def test_the_declarations_pass_master_sdks_check(self):
        _, options, _ = write("declarations", make_spa(), sdk=SDK)
        passed, report = spa_out.check(options.out, options)
        self.assertTrue(passed, report)

    @unittest.skipUnless(HAVE_SDK, "master-sdk checkout not found")
    def test_the_fallback_limits_are_master_sdks(self):
        real = json.loads((SDK / spa_out.LIMITS).read_text())
        for kind, values in spa_out.FALLBACK_LIMITS.items():
            for key, value in values.items():
                self.assertEqual(real[kind][key], value, f"{kind}.{key}")

    def test_the_cli_writes_json_from_an_spa(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "t.spa").write_bytes(make_spa())
            with (
                contextlib.redirect_stderr(io.StringIO()) as err,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = xbox360.main(["--caller-cwd", tmp, "spa", "t.spa"])
            self.assertEqual(code, 0)
            self.assertTrue((Path(tmp) / "spa-41560001" / "spa.json").is_file())
            self.assertIn("Test Title", err.getvalue())


if __name__ == "__main__":
    unittest.main()
