"""GameCube/Wii GX textures to RGBA and PNG: the texel formats the GX hardware reads (big-endian,
stored in tiles of 4x4, 8x4 or 8x8 texels, row by row), their palettes, and the two containers
games ship them in, TPL (a table of images, Nintendo's SDK) and BTI (one image, J3D's), as
YAGCD (the GameCube documentation's "Texture formats") and noclip.website's JUTTexture.ts describe
them, and Dolphin's TextureDecoder (CMPR's blend). Mipmaps below the first level are not decoded.

  decode(fmt, width, height, data, palette=None, palette_format=0) -> bytes   RGBA, row by row
  read_tpl(data) / read_bti(data) -> [Texture]
  png(width, height, rgba) -> bytes
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass

# format id: (name, block width, block height, bits per texel)
FORMATS = {
    0x0: ("I4", 8, 8, 4),
    0x1: ("I8", 8, 4, 8),
    0x2: ("IA4", 8, 4, 8),
    0x3: ("IA8", 4, 4, 16),
    0x4: ("RGB565", 4, 4, 16),
    0x5: ("RGB5A3", 4, 4, 16),
    0x6: ("RGBA8", 4, 4, 32),
    0x8: ("C4", 8, 8, 4),
    0x9: ("C8", 8, 4, 8),
    0xA: ("C14X2", 4, 4, 16),
    0xE: ("CMPR", 8, 8, 4),
}
PALETTE_FORMATS = {0: "IA8", 1: "RGB565", 2: "RGB5A3"}
TPL_MAGIC = 0x0020AF30


def _x5(v: int) -> int:
    return v << 3 | v >> 2


def _x6(v: int) -> int:
    return v << 2 | v >> 4


def _x3(v: int) -> int:
    return v << 5 | v << 2 | v >> 1


def rgb565(v: int) -> tuple[int, int, int, int]:
    return _x5(v >> 11), _x6(v >> 5 & 0x3F), _x5(v & 0x1F), 255


def rgb5a3(v: int) -> tuple[int, int, int, int]:
    if v & 0x8000:  # opaque: 5 bits a channel
        return _x5(v >> 10 & 0x1F), _x5(v >> 5 & 0x1F), _x5(v & 0x1F), 255
    return (v >> 8 & 0xF) * 17, (v >> 4 & 0xF) * 17, (v & 0xF) * 17, _x3(v >> 12 & 7)


def ia8(v: int) -> tuple[int, int, int, int]:
    return v & 0xFF, v & 0xFF, v & 0xFF, v >> 8


COLOURS: dict[int, Callable[[int], tuple[int, int, int, int]]] = {0: ia8, 1: rgb565, 2: rgb5a3}


def size(fmt: int, width: int, height: int) -> int:
    """Bytes of the first level: whole tiles, a partial one padded."""
    _, bw, bh, bits = FORMATS[fmt]
    return -(-width // bw) * -(-height // bh) * bw * bh * bits // 8


def _midpoint(x: int, y: int) -> int:
    """Half way, rounded toward the first value (C++'s std::midpoint, as Dolphin uses)."""
    return x + int((y - x) / 2)


def _cmpr_block(data: bytes, at: int) -> list[tuple[int, int, int, int]]:
    """One 4x4 DXT1-like sub-block: two RGB565 colours (big-endian), 2-bit indices MSB first.
    The GameCube blends at 5/8 and 3/8, not DXT1's thirds, and its fourth colour in the
    three-colour mode is the midpoint made transparent, not black (Dolphin's DecodeDXTBlock)."""
    c0, c1 = struct.unpack_from(">HH", data, at)
    a, b = rgb565(c0), rgb565(c1)
    if c0 > c1:
        mid = tuple((y * 3 + x * 5) >> 3 for x, y in zip(a[:3], b[:3], strict=True)) + (255,)
        far = tuple((x * 3 + y * 5) >> 3 for x, y in zip(a[:3], b[:3], strict=True)) + (255,)
    else:
        rgb = tuple(_midpoint(x, y) for x, y in zip(a[:3], b[:3], strict=True))
        mid, far = rgb + (255,), rgb + (0,)
    table = [a, b, mid, far]
    return [table[data[at + 4 + row] >> (6 - 2 * col) & 3] for row in range(4) for col in range(4)]


def decode(
    fmt: int, width: int, height: int, data: bytes, palette: bytes | None = None,
    palette_format: int = 0,
) -> bytes:  # fmt: skip
    """The first level as RGBA, `width * height * 4` bytes."""
    if fmt not in FORMATS:
        raise ValueError(f"texture format {fmt:#x} is not a GX format this reads")
    name, bw, bh, bits = FORMATS[fmt]
    if not 0 < width <= 4096 or not 0 < height <= 4096:
        raise ValueError(f"texture size {width}x{height} out of range")
    need = size(fmt, width, height)
    if len(data) < need:
        raise ValueError(f"{name} {width}x{height} needs {need} bytes, has {len(data)}")
    colours: list[tuple[int, int, int, int]] = []
    if name in ("C4", "C8", "C14X2"):
        if palette is None or palette_format not in COLOURS:
            raise ValueError(f"{name} needs a palette (IA8, RGB565 or RGB5A3)")
        convert = COLOURS[palette_format]
        colours = [convert(v) for v in struct.unpack(f">{len(palette) // 2}H", palette)]
    out = bytearray(width * height * 4)

    def put(x: int, y: int, rgba: tuple[int, int, int, int]) -> None:
        if x < width and y < height:
            at = (y * width + x) * 4
            out[at : at + 4] = bytes(rgba)

    def index(i: int) -> tuple[int, int, int, int]:
        if i >= len(colours):
            raise ValueError(f"palette index {i} past the palette's {len(colours)} entries")
        return colours[i]

    tile = bw * bh * bits // 8
    at = 0
    for ty in range(0, height, bh):
        for tx in range(0, width, bw):
            block = data[at : at + tile]
            at += tile
            if name == "CMPR":
                for sub in range(4):
                    texels = _cmpr_block(block, sub * 8)
                    ox, oy = tx + (sub & 1) * 4, ty + (sub >> 1) * 4
                    for n, rgba in enumerate(texels):
                        put(ox + n % 4, oy + n // 4, rgba)
                continue
            if name == "RGBA8":  # alpha-red pairs, then green-blue pairs
                for n in range(16):
                    a, r = block[2 * n], block[2 * n + 1]
                    g, b = block[32 + 2 * n], block[33 + 2 * n]
                    put(tx + n % 4, ty + n // 4, (r, g, b, a))
                continue
            for n in range(bw * bh):
                if bits == 4:
                    v = block[n // 2] >> (0 if n & 1 else 4) & 0xF
                elif bits == 8:
                    v = block[n]
                else:
                    v = block[2 * n] << 8 | block[2 * n + 1]
                rgba = {
                    "I4": lambda v: (v * 17,) * 4,
                    "I8": lambda v: (v,) * 4,
                    "IA4": lambda v: ((v & 0xF) * 17,) * 3 + ((v >> 4) * 17,),
                    "IA8": ia8,
                    "RGB565": rgb565,
                    "RGB5A3": rgb5a3,
                    "C4": index,
                    "C8": index,
                    "C14X2": lambda v: index(v & 0x3FFF),
                }[name](v)
                put(tx + n % bw, ty + n // bw, rgba)
    return bytes(out)


@dataclass
class Texture:
    name: str
    fmt: int
    width: int
    height: int
    data: bytes
    palette: bytes | None = None
    palette_format: int = 0
    mipmaps: int = 1

    @property
    def format_name(self) -> str:
        return FORMATS.get(self.fmt, (f"{self.fmt:#x}",))[0]

    def rgba(self) -> bytes:
        return decode(self.fmt, self.width, self.height, self.data, self.palette,
                      self.palette_format)  # fmt: skip


def _slice(data: bytes, at: int, length: int, what: str) -> bytes:
    if at < 0 or at + length > len(data):
        raise ValueError(f"{what} at {at:#x} (+{length:#x}) lies outside the file")
    return data[at : at + length]


def read_tpl(data: bytes) -> list[Texture]:
    """A TPL's images: the image table, each image's header (height, width, format, data) and its
    palette header (entries, format, data) when it has one."""
    if len(data) < 12 or struct.unpack_from(">I", data)[0] != TPL_MAGIC:
        raise ValueError("no TPL magic (0x0020AF30)")
    count, table = struct.unpack_from(">II", data, 4)
    if not 0 < count <= 1024:
        raise ValueError(f"{count} images: not a TPL")
    textures = []
    for i in range(count):
        image_at, palette_at = struct.unpack(">II", _slice(data, table + 8 * i, 8, "image table"))
        height, width, fmt, data_at = struct.unpack(">HHII", _slice(data, image_at, 12, "image"))
        if fmt not in FORMATS:
            raise ValueError(f"image {i}: format {fmt:#x} is not a GX format")
        palette, palette_format = None, 0
        if palette_at:
            entries, _, _, palette_format, entries_at = struct.unpack(
                ">HBBII", _slice(data, palette_at, 12, "palette header")
            )
            palette = _slice(data, entries_at, 2 * entries, "palette")
        pixels = _slice(data, data_at, size(fmt, width, height), f"image {i}'s texels")
        textures.append(Texture(f"{i}", fmt, width, height, pixels, palette, palette_format))
    return textures


def read_bti(data: bytes) -> list[Texture]:
    """A BTI's one image: its 0x20-byte header (format, size, palette, mipmap count, data)."""
    if len(data) < 0x20:
        raise ValueError("too short for a BTI header")
    fmt = data[0]
    width, height = struct.unpack_from(">HH", data, 2)
    palette_format = data[9]
    entries, palette_at = struct.unpack_from(">HI", data, 0x0A)
    mipmaps = data[0x18]
    (data_at,) = struct.unpack_from(">I", data, 0x1C)
    if fmt not in FORMATS or not width or not height:
        raise ValueError(f"format {fmt:#x} or size {width}x{height}: not a BTI")
    palette = _slice(data, palette_at, 2 * entries, "palette") if palette_at and entries else None
    pixels = _slice(data, data_at, size(fmt, width, height), "texels")
    return [Texture("0", fmt, width, height, pixels, palette, palette_format, mipmaps)]


def read(data: bytes, name: str = "") -> list[Texture]:
    """A TPL by its magic, else a BTI (whose header has none)."""
    if len(data) >= 4 and struct.unpack_from(">I", data)[0] == TPL_MAGIC:
        return read_tpl(data)
    if name.lower().endswith(".tpl"):
        raise ValueError("no TPL magic (0x0020AF30)")
    return read_bti(data)


def png(width: int, height: int, rgba: bytes) -> bytes:
    """An 8-bit RGBA PNG, rows unfiltered."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        )

    stride = width * 4
    rows = b"".join(b"\0" + rgba[y * stride : (y + 1) * stride] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9))
            + chunk(b"IEND", b""))  # fmt: skip
