"""GX textures (gxtexture.py) on texels worked out by hand from the formats: colour expansion,
the tile order, a partial tile, palettes, CMPR's two modes, the TPL and BTI containers, the PNG and
`rea-suite gamecube texture`."""

from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from rea_suite import gamecube, gxtexture

RED, GREEN, BLUE = (255, 0, 0, 255), (0, 255, 0, 255), (0, 0, 255, 255)


def pixel(rgba: bytes, width: int, x: int, y: int) -> tuple[int, ...]:
    at = (y * width + x) * 4
    return tuple(rgba[at : at + 4])


def tile565(colour: int) -> bytes:
    return struct.pack(">16H", *[colour] * 16)


class Texels(unittest.TestCase):
    def test_colour_expansion(self):
        self.assertEqual(gxtexture.rgb565(0xF800), RED)
        self.assertEqual(gxtexture.rgb565(0x07E0), GREEN)
        self.assertEqual(gxtexture.rgb5a3(0x8000 | 0x001F), BLUE)  # top bit: opaque RGB555
        self.assertEqual(gxtexture.rgb5a3(0x3F00), (255, 0, 0, 0x6D))  # A3 = 3, then RGB444
        self.assertEqual(gxtexture.ia8(0x80FF), (255, 255, 255, 128))

    def test_tiles_are_laid_out_row_by_row(self):
        # 8x8 RGB565: four 4x4 tiles, red, green, blue, then white
        data = tile565(0xF800) + tile565(0x07E0) + tile565(0x001F) + tile565(0xFFFF)
        rgba = gxtexture.decode(0x4, 8, 8, data)
        self.assertEqual(pixel(rgba, 8, 0, 0), RED)
        self.assertEqual(pixel(rgba, 8, 7, 3), GREEN)
        self.assertEqual(pixel(rgba, 8, 0, 4), BLUE)
        self.assertEqual(pixel(rgba, 8, 7, 7), (255, 255, 255, 255))

    def test_a_partial_tile_is_padded_in_the_data_and_cut_from_the_image(self):
        self.assertEqual(gxtexture.size(0x4, 5, 4), 64)  # two tiles for five columns
        rgba = gxtexture.decode(0x4, 5, 4, tile565(0xF800) + tile565(0x001F))
        self.assertEqual((len(rgba), pixel(rgba, 5, 4, 0)), (5 * 4 * 4, BLUE))
        with self.assertRaisesRegex(ValueError, "needs 64 bytes"):
            gxtexture.decode(0x4, 5, 4, tile565(0xF800))

    def test_intensity_and_rgba8(self):
        i4 = gxtexture.decode(0x0, 8, 8, b"\x0f" + bytes(31))
        self.assertEqual((pixel(i4, 8, 0, 0), pixel(i4, 8, 1, 0)), ((0,) * 4, (255,) * 4))
        ia4 = gxtexture.decode(0x2, 8, 4, b"\xf3" + bytes(31))
        self.assertEqual(pixel(ia4, 8, 0, 0), (51, 51, 51, 255))
        # RGBA8: texel 5 (x 1, y 1) gets A,R from the first half and G,B from the second
        block = bytearray(64)
        block[10:12], block[42:44] = b"\x80\x11", b"\x22\x33"
        self.assertEqual(
            pixel(gxtexture.decode(0x6, 4, 4, bytes(block)), 4, 1, 1), (17, 34, 51, 128)
        )

    def test_palettes(self):
        palette = struct.pack(">3H", 0x8000 | 0x7C00, 0x8000 | 0x03E0, 0x3000)
        c8 = gxtexture.decode(0x9, 8, 4, bytes([1, 0, 2]) + bytes(29), palette, 2)
        self.assertEqual(pixel(c8, 8, 0, 0), GREEN)
        self.assertEqual(pixel(c8, 8, 1, 0), RED)
        self.assertEqual(pixel(c8, 8, 2, 0), (0, 0, 0, 0x6D))
        c14 = gxtexture.decode(0xA, 4, 4, struct.pack(">16H", *[0xC001] * 16), palette, 2)
        self.assertEqual(pixel(c14, 4, 3, 3), GREEN)  # the top two bits are not the index
        with self.assertRaisesRegex(ValueError, "needs a palette"):
            gxtexture.decode(0x9, 8, 4, bytes(32))
        with self.assertRaisesRegex(ValueError, "past the palette"):
            gxtexture.decode(0x9, 8, 4, bytes([9]) + bytes(31), palette, 2)

    def test_cmpr_modes(self):
        # c0 > c1: two blends of red and blue at 5/8 and 3/8; c0 <= c1: their mean, and it
        # made transparent (Dolphin's DecodeDXTBlock)
        four = struct.pack(">HH", 0xF800, 0x001F) + bytes([0b10110001]) + bytes(3)
        three = struct.pack(">HH", 0x001F, 0xF800) + bytes([0b10110000]) + bytes(3)
        rgba = gxtexture.decode(0xE, 8, 8, four + three + four + four)
        self.assertEqual(pixel(rgba, 8, 0, 0), (159, 0, 95, 255))  # index 2: (5 c0 + 3 c1) / 8
        self.assertEqual(pixel(rgba, 8, 1, 0), (95, 0, 159, 255))  # index 3: (3 c0 + 5 c1) / 8
        self.assertEqual(pixel(rgba, 8, 3, 0), BLUE)  # index 1: c1
        self.assertEqual(pixel(rgba, 8, 4, 0), (127, 0, 128, 255))  # mean, rounded toward c0 (blue)
        self.assertEqual(pixel(rgba, 8, 5, 0), (127, 0, 128, 0))  # the mean, transparent
        self.assertEqual(pixel(rgba, 8, 0, 4), (159, 0, 95, 255))  # the third: below the first

    def test_an_unknown_format_is_refused(self):
        with self.assertRaisesRegex(ValueError, "0x7"):
            gxtexture.decode(0x7, 4, 4, bytes(64))


def tpl() -> bytes:
    """Two images: an RGB565 one and a C8 one with an RGB5A3 palette."""
    table, image0, image1, palette1 = 0x0C, 0x20, 0x40, 0x60
    data0, data1, entries = 0x80, 0xA0, 0xC0
    out = bytearray(0xC0 + 4)
    struct.pack_into(">III", out, 0, gxtexture.TPL_MAGIC, 2, table)
    struct.pack_into(">4I", out, table, image0, 0, image1, palette1)
    struct.pack_into(">HHII", out, image0, 4, 4, 0x4, data0)
    struct.pack_into(">HHII", out, image1, 4, 8, 0x9, data1)
    struct.pack_into(">HBBII", out, palette1, 2, 0, 0, 2, entries)
    out[data0 : data0 + 32] = tile565(0x07E0)
    out[data1 : data1 + 32] = bytes([1] * 32)
    struct.pack_into(">2H", out, entries, 0x8000, 0x8000 | 0x001F)
    return bytes(out)


def bti() -> bytes:
    head = bytearray(0x20)
    head[0] = 0x4
    struct.pack_into(">HH", head, 2, 4, 4)
    head[0x18] = 3
    struct.pack_into(">I", head, 0x1C, 0x20)
    return bytes(head) + tile565(0xF800)


class Containers(unittest.TestCase):
    def test_a_tpl_and_its_palette(self):
        first, second = gxtexture.read(tpl())
        self.assertEqual((first.format_name, first.width, first.height), ("RGB565", 4, 4))
        self.assertEqual(pixel(first.rgba(), 4, 0, 0), GREEN)
        self.assertEqual((second.format_name, second.palette_format), ("C8", 2))
        self.assertEqual(pixel(second.rgba(), 8, 7, 3), BLUE)
        broken = bytearray(tpl())
        struct.pack_into(">I", broken, 0x48, 0x1000)  # the second image's data past the end
        with self.assertRaisesRegex(ValueError, "outside the file"):
            gxtexture.read(bytes(broken))

    def test_a_bti(self):
        (texture,) = gxtexture.read(bti(), "a.bti")
        self.assertEqual((texture.format_name, texture.mipmaps), ("RGB565", 3))
        self.assertEqual(pixel(texture.rgba(), 4, 3, 3), RED)
        with self.assertRaisesRegex(ValueError, "TPL magic"):
            gxtexture.read(bti(), "a.tpl")

    def test_the_png_holds_the_pixels(self):
        rgba = bytes(RED + GREEN + BLUE + (1, 2, 3, 4))
        data = gxtexture.png(2, 2, rgba)
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
        width, height, depth, kind = struct.unpack_from(">IIBB", data, 16)
        self.assertEqual((width, height, depth, kind), (2, 2, 8, 6))
        idat = data.index(b"IDAT")
        (length,) = struct.unpack_from(">I", data, idat - 4)
        rows = zlib.decompress(data[idat + 4 : idat + 4 + length])
        self.assertEqual(rows, b"\0" + rgba[:8] + b"\0" + rgba[8:])

    def test_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "font.tpl").write_bytes(tpl())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = gamecube.main(["--caller-cwd", tmp, "texture", "font.tpl", "-o", "png"])
            rows = json.loads(out.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual([r["format"] for r in rows], ["RGB565", "C8"])
            self.assertEqual(rows[1]["palette"], "RGB5A3")
            self.assertTrue(Path(tmp, "png", "font.1.png").is_file())


if __name__ == "__main__":
    unittest.main()
