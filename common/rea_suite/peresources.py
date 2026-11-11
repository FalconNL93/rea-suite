"""A PE image's resources, decoded: dialogs with their controls, menus, string tables, version
information, accelerators, message tables, icons, cursors, bitmaps and manifests.

pefile walks the resource directory (type, name, language); the resources themselves are read
here, by the layouts Microsoft documents for them (DLGTEMPLATE and DLGTEMPLATEEX with their
items, MENUITEMTEMPLATE and MENUEX_TEMPLATE_ITEM, string table blocks, ACCELTABLEENTRY,
VS_VERSIONINFO with VS_FIXEDFILEINFO, MESSAGE_RESOURCE_DATA, GRPICONDIR). Every reader is
bounded and a malformed resource gives an `error` member rather than stopping the walk.

`export` writes each icon and cursor group as an .ico or .cur file plus one .png per image
(stored PNGs as they are, 1/4/8/24/32-bit DIBs converted, transparency from the alpha channel
or the AND mask), bitmaps as .bmp, manifests as .xml and everything else raw (.bin).
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

import pefile

from .pemodel import Image

TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR",
    8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
    21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}  # fmt: skip
TYPE_IDS = {name: number for number, name in TYPES.items()}
CONTROL_CLASSES = {0x80: "Button", 0x81: "Edit", 0x82: "Static", 0x83: "ListBox",
                   0x84: "ScrollBar", 0x85: "ComboBox"}  # fmt: skip
DS_SETFONT = 0x40  # DS_SHELLFONT includes it
MAX_ITEMS = 4096
MAX_DEPTH = 16
PNG = b"\x89PNG\r\n\x1a\n"
KEYS = {0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 0x13: "Pause", 0x1B: "Esc",
        0x20: "Space", 0x21: "PageUp", 0x22: "PageDown", 0x23: "End", 0x24: "Home",
        0x25: "Left", 0x26: "Up", 0x27: "Right", 0x28: "Down", 0x2D: "Insert", 0x2E: "Delete",
        0x6A: "Num*", 0x6B: "Num+", 0x6D: "Num-", 0x6E: "Num.", 0x6F: "Num/"}  # fmt: skip


@dataclass
class Resource:
    type: int | str
    name: int | str
    lang: int
    rva: int
    size: int
    codepage: int

    @property
    def type_name(self) -> str:
        return TYPES.get(self.type, str(self.type)) if isinstance(self.type, int) else self.type

    def key(self) -> dict:
        return {"type": self.type_name, "name": self.name, "lang": f"{self.lang:#06x}"}


def label(entry) -> int | str:
    if entry.name is not None:
        return (
            entry.name.decode("utf-8", "replace")
            if hasattr(entry.name, "decode")
            else str(entry.name)
        )
    return entry.id


def walk(image: Image) -> list[Resource]:
    """Every resource: type, name, language, where its bytes are."""
    if not image.directory(2)[1]:
        return []
    image.pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    root = getattr(image.pe, "DIRECTORY_ENTRY_RESOURCE", None)
    found = []
    for kind in getattr(root, "entries", []):
        for name in getattr(getattr(kind, "directory", None), "entries", []):
            for lang in getattr(getattr(name, "directory", None), "entries", []):
                data = getattr(lang, "data", None)
                if data is None:
                    continue
                s = data.struct
                found.append(
                    Resource(
                        label(kind), label(name), lang.id or 0, s.OffsetToData, s.Size, s.CodePage
                    )
                )
    return found


def matches(resource: Resource, types: list[str], names: list[str]) -> bool:
    if types:
        wanted = {TYPE_IDS.get(t.upper(), t) for t in types}
        wanted |= {int(t) for t in types if t.isdigit()}
        if resource.type not in wanted and resource.type_name not in wanted:
            return False
    return not names or str(resource.name) in names


# --- small readers -------------------------------------------------------------------------


class Reader:
    """Little-endian reads over one resource's bytes; IndexError past its end."""

    def __init__(self, data: bytes, at: int = 0):
        self.data, self.at = data, at

    def take(self, fmt: str):
        size = struct.calcsize("<" + fmt)
        if self.at + size > len(self.data):
            raise IndexError(f"read past the end at {self.at:#x}")
        values = struct.unpack_from("<" + fmt, self.data, self.at)
        self.at += size
        return values if len(values) > 1 else values[0]

    def wstring(self) -> str:
        end = self.at
        while end + 1 < len(self.data) and self.data[end : end + 2] != b"\0\0":
            end += 2
        if end + 1 >= len(self.data):
            raise IndexError("unterminated string")
        value = self.data[self.at : end].decode("utf-16-le", "replace")
        self.at = end + 2
        return value

    def sz_or_ord(self) -> str | int | None:
        """A string, an ordinal (0xFFFF then a word) or nothing (0x0000)."""
        first = self.take("H")
        if first == 0:
            return None
        if first == 0xFFFF:
            return self.take("H")
        self.at -= 2
        return self.wstring()

    def align(self, to: int = 4) -> None:
        self.at = (self.at + to - 1) // to * to


def signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value >= 1 << (bits - 1) else value


# --- dialogs ----------------------------------------------------------------------------


def dialog(data: bytes) -> dict:
    r = Reader(data)
    version, signature = struct.unpack_from("<HH", data, 0)
    extended = version == 1 and signature == 0xFFFF
    if extended:
        r.take("HH")
        help_id, ex_style, style = r.take("III")
    else:
        help_id = None
        style, ex_style = r.take("II")
    count, x, y, cx, cy = r.take("Hhhhh")
    result = {
        "kind": "dialogex" if extended else "dialog",
        "style": f"{style:#010x}",
        "ex_style": f"{ex_style:#010x}",
        "x": x, "y": y, "cx": cx, "cy": cy,
        "menu": r.sz_or_ord(),
        "class": r.sz_or_ord(),
        "title": r.wstring(),
    }  # fmt: skip
    if help_id:
        result["help_id"] = help_id
    if style & DS_SETFONT:
        font = {"size": r.take("H")}
        if extended:
            font["weight"], font["italic"], font["charset"] = r.take("HBB")
            font["italic"] = bool(font["italic"])
        font["name"] = r.wstring()
        result["font"] = font
    controls = []
    for _ in range(min(count, MAX_ITEMS)):
        r.align()
        if extended:
            help_id, ex_style, style = r.take("III")
            x, y, cx, cy = r.take("hhhh")
            ident = r.take("I")
            ident = -1 if ident in (0xFFFF, 0xFFFFFFFF) else ident  # IDC_STATIC, as rc writes it
        else:
            help_id = None
            style, ex_style = r.take("II")
            x, y, cx, cy = r.take("hhhh")
            ident = signed(r.take("H"), 16)
        cls = r.sz_or_ord()
        title = r.sz_or_ord()
        extra = r.take("H")  # bytes of creation data that follow
        blob = data[r.at : r.at + extra]
        r.at += extra
        control = {
            "id": ident,
            "class": CONTROL_CLASSES.get(cls, f"#{cls}") if isinstance(cls, int) else cls,
            "text": f"#{title}" if isinstance(title, int) else (title or ""),
            "style": f"{style:#010x}",
            "ex_style": f"{ex_style:#010x}",
            "x": x, "y": y, "cx": cx, "cy": cy,
        }  # fmt: skip
        if help_id:
            control["help_id"] = help_id
        if blob:
            control["extra"] = blob.hex()
        controls.append(control)
    result["controls"] = controls
    return result


# --- menus ------------------------------------------------------------------------------

MF_POPUP, MF_END, MF_SEPARATOR = 0x10, 0x80, 0x800


def menu(data: bytes) -> dict:
    version, offset = struct.unpack_from("<HH", data, 0)
    if version == 1:
        r = Reader(data, 4 + offset)
        return {"kind": "menuex", "items": menuex_items(r, 0)}
    r = Reader(data, 4 + offset)
    return {"kind": "menu", "items": menu_items(r, 0)}


def menu_items(r: Reader, depth: int) -> list[dict]:
    items: list[dict] = []
    while len(items) < MAX_ITEMS:
        flags = r.take("H")
        item: dict = {"flags": f"{flags:#06x}"}
        if flags & MF_POPUP:
            item["text"] = r.wstring()
            item["items"] = menu_items(r, depth + 1) if depth < MAX_DEPTH else []
        else:
            item["id"] = r.take("H")
            item["text"] = r.wstring()
            if not item["text"] and not item["id"]:
                item["separator"] = True
        items.append(item)
        if flags & MF_END:
            break
    return items


def menuex_items(r: Reader, depth: int) -> list[dict]:
    items: list[dict] = []
    while len(items) < MAX_ITEMS:
        kind, state, ident, flags = r.take("IIIH")
        item: dict = {"id": signed(ident, 32), "type": f"{kind:#x}", "state": f"{state:#x}"}
        item["text"] = r.wstring()
        r.align()
        if kind & MF_SEPARATOR:
            item["separator"] = True
        if flags & 0x01:
            item["help_id"] = r.take("I")
            item["items"] = menuex_items(r, depth + 1) if depth < MAX_DEPTH else []
        items.append(item)
        if flags & MF_END:
            break
    return items


# --- strings, accelerators, message tables ----------------------------------------------


def string_table(data: bytes, block: int) -> dict:
    """One block of 16 strings: ids (block - 1) * 16 onwards; empty strings left out."""
    r = Reader(data)
    strings = []
    for index in range(16):
        if r.at + 2 > len(data):
            break
        length = r.take("H")
        text = data[r.at : r.at + 2 * length].decode("utf-16-le", "replace")
        r.at += 2 * length
        if length:
            strings.append({"id": (block - 1) * 16 + index, "text": text})
    return {"strings": strings}


def accelerators(data: bytes) -> dict:
    r = Reader(data)
    entries = []
    while r.at + 8 <= len(data) and len(entries) < MAX_ITEMS:
        flags, key, ident, _ = r.take("HHHH")
        entries.append({"key": key_name(flags, key), "id": ident, "flags": f"{flags:#x}"})
        if flags & 0x80:
            break
    return {"entries": entries}


def key_name(flags: int, key: int) -> str:
    mods = [m for bit, m in ((0x08, "Ctrl"), (0x10, "Alt"), (0x04, "Shift")) if flags & bit]
    if flags & 0x01:  # FVIRTKEY
        if 0x30 <= key <= 0x39 or 0x41 <= key <= 0x5A:
            name = chr(key)
        elif 0x70 <= key <= 0x87:
            name = f"F{key - 0x6F}"
        elif 0x60 <= key <= 0x69:
            name = f"Num{key - 0x60}"
        else:
            name = KEYS.get(key, f"VK_{key:#04x}")
    elif key < 0x20:
        name = "^" + chr(key + 0x40)
    else:
        name = repr(chr(key & 0xFF))
    return "+".join([*mods, name])


def message_table(data: bytes) -> dict:
    r = Reader(data)
    blocks = r.take("I")
    messages = []
    for index in range(min(blocks, MAX_ITEMS)):
        low, high, offset = struct.unpack_from("<III", data, 4 + 12 * index)
        at = offset
        for ident in range(low, min(high, low + MAX_ITEMS) + 1):
            length, flags = struct.unpack_from("<HH", data, at)
            if length < 4:
                break
            raw = data[at + 4 : at + length]
            text = raw.decode("utf-16-le" if flags & 1 else "cp1252", "replace")
            messages.append({"id": ident, "text": text.rstrip("\0").rstrip("\r\n")})
            at += length
    return {"messages": messages}


# --- version ----------------------------------------------------------------------------


def version_node(data: bytes, at: int, depth: int = 0) -> tuple[dict, int]:
    """One VS_VERSIONINFO-style node: (key, value, children) and where the next one starts."""
    length, value_length, kind = struct.unpack_from("<HHH", data, at)
    if length < 6 or at + length > len(data):
        raise IndexError(f"bad version node at {at:#x}")
    r = Reader(data[: at + length], at + 6)
    key = r.wstring()
    r.align()
    if kind == 1:  # text: the length counts UTF-16 units
        value = data[r.at : r.at + 2 * value_length].decode("utf-16-le", "replace").rstrip("\0")
        r.at += 2 * value_length
    else:
        value = data[r.at : r.at + value_length]
        r.at += value_length
    r.align()
    children = []
    while r.at + 6 <= at + length and depth < MAX_DEPTH and len(children) < MAX_ITEMS:
        child, r.at = version_node(data, r.at, depth + 1)
        children.append(child)
        r.align()
    return {"key": key, "value": value, "children": children}, at + length


def version_number(high: int, low: int) -> str:
    return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"


def version(data: bytes) -> dict:
    root, _ = version_node(data, 0)
    result: dict = {}
    fixed = root["value"]
    if isinstance(fixed, bytes) and len(fixed) >= 52:
        f = struct.unpack_from("<13I", fixed)
        if f[0] == 0xFEEF04BD:
            result.update(
                file_version=version_number(f[2], f[3]),
                product_version=version_number(f[4], f[5]),
                file_flags=f"{f[7] & f[6]:#x}",
                file_os=f"{f[8]:#x}",
                file_type=f[9],
                file_subtype=f[10],
            )
    strings: dict[str, dict[str, str]] = {}
    translations = []
    for child in root["children"]:
        if child["key"] == "StringFileInfo":
            for table in child["children"]:
                strings[table["key"]] = {
                    s["key"]: s["value"] if isinstance(s["value"], str) else s["value"].hex()
                    for s in table["children"]
                }
        elif child["key"] == "VarFileInfo":
            for var in child["children"]:
                value = var["value"] if isinstance(var["value"], bytes) else b""
                for lang, cp in struct.iter_unpack("<HH", value[: len(value) // 4 * 4]):
                    translations.append(f"{lang:04x}:{cp:04x}")
    result["strings"] = strings
    result["translations"] = translations
    return result


# --- icons, cursors, bitmaps ------------------------------------------------------------


def group(data: bytes, cursor: bool) -> dict:
    _, kind, count = struct.unpack_from("<HHH", data, 0)
    images = []
    for index in range(min(count, MAX_ITEMS)):
        at = 6 + 14 * index
        if cursor:
            width, height, _planes, bpp, size, ident = struct.unpack_from("<HHHHIH", data, at)
            height //= 2
        else:
            width, height, _colors, _, _planes, bpp, size, ident = struct.unpack_from(
                "<BBBBHHIH", data, at
            )
            width, height = width or 256, height or 256
        images.append({"id": ident, "width": width, "height": height, "bpp": bpp, "size": size})
    return {"kind": "cursor" if cursor or kind == 2 else "icon", "images": images}


def bitmap_info(data: bytes) -> dict:
    if data.startswith(PNG):
        width, height = struct.unpack_from(">II", data, 16)
        return {"format": "png", "width": width, "height": height}
    header, width, height, _planes, bpp, compression = struct.unpack_from("<IiiHHI", data, 0)
    return {"format": "dib", "width": width, "height": height, "bpp": bpp,
            "compression": compression, "header": header}  # fmt: skip


DECODERS = {
    "DIALOG": lambda r, d: dialog(d),
    "MENU": lambda r, d: menu(d),
    "STRING": lambda r, d: string_table(d, r.name) if isinstance(r.name, int) else {},
    "ACCELERATOR": lambda r, d: accelerators(d),
    "MESSAGETABLE": lambda r, d: message_table(d),
    "VERSION": lambda r, d: version(d),
    "GROUP_ICON": lambda r, d: group(d, cursor=False),
    "GROUP_CURSOR": lambda r, d: group(d, cursor=True),
    "BITMAP": lambda r, d: bitmap_info(d),
    "ICON": lambda r, d: bitmap_info(d),
    "CURSOR": lambda r, d: bitmap_info(d[4:]),
    "MANIFEST": lambda r, d: {"text": d.decode("utf-8", "replace")},
}


def decode(image: Image, resource: Resource) -> dict:
    """The resource's place and size, and its decoded content where a reader knows it."""
    row = {**resource.key(), "rva": f"{resource.rva:#x}", "size": resource.size}
    try:
        data = image.read(resource.rva, resource.size)
    except ValueError as exc:
        return {**row, "error": str(exc)}
    reader = DECODERS.get(resource.type_name)
    if reader is None:
        row["head"] = data[:16].hex()
        return row
    try:
        row.update(reader(resource, data))
    except (struct.error, IndexError, ValueError) as exc:
        row["error"] = f"undecodable: {exc}"
    return row


def resources(image: Image, types: list[str] = (), names: list[str] = ()) -> list[dict]:
    return [decode(image, r) for r in walk(image) if matches(r, list(types), list(names))]


# --- export -----------------------------------------------------------------------------


def png(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        )

    rows = b"".join(b"\0" + rgba[y * width * 4 : (y + 1) * width * 4] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return PNG + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def dib_to_png(data: bytes, icon: bool = True) -> bytes | None:
    """An icon or cursor image (BITMAPINFOHEADER, XOR pixels, AND mask) or a bitmap as PNG;
    None for a layout this does not convert (compressed, 16-bit, an OS/2 header)."""
    if data.startswith(PNG):
        return data
    header, width, height, _planes, bpp, compression = struct.unpack_from("<IiiHHI", data, 0)
    used = struct.unpack_from("<I", data, 32)[0] if header >= 36 else 0
    if header < 40 or compression not in (0, 3) or bpp not in (1, 4, 8, 24, 32) or width <= 0:
        return None
    top_down = height < 0
    height = abs(height) // (2 if icon else 1)
    if not 0 < width <= 4096 or not 0 < height <= 4096:
        return None
    colors = used or (1 << bpp if bpp <= 8 else 0)
    palette_at = header + (12 if compression == 3 and header == 40 else 0)
    palette = [data[palette_at + 4 * i : palette_at + 4 * i + 3][::-1] for i in range(colors)]
    pixels = palette_at + 4 * colors
    stride = (width * bpp + 31) // 32 * 4
    mask_at, mask_stride = pixels + stride * height, (width + 31) // 32 * 4
    if pixels + stride * height > len(data):
        return None
    has_mask = icon and mask_at + mask_stride * height <= len(data)
    alpha_used = bpp == 32 and any(data[pixels + 3 : pixels + stride * height : 4])
    out = bytearray()
    for y in range(height):
        row = y if top_down else height - 1 - y
        line = data[pixels + row * stride : pixels + (row + 1) * stride]
        mask = data[mask_at + row * mask_stride : mask_at + (row + 1) * mask_stride]
        for x in range(width):
            if bpp == 32:
                b, g, r, a = line[4 * x : 4 * x + 4]
                rgb = bytes((r, g, b))
            elif bpp == 24:
                rgb, a = line[3 * x : 3 * x + 3][::-1], 255
            else:
                bit = x * bpp
                index = (line[bit // 8] >> (8 - bpp - bit % 8)) & ((1 << bpp) - 1)
                rgb, a = (palette[index] if index < len(palette) else b"\0\0\0"), 255
            if not alpha_used:
                a = 0 if has_mask and mask[x // 8] >> (7 - x % 8) & 1 else 255
            out += rgb + bytes((a,))
    return png(width, height, bytes(out))


def safe(name: int | str) -> str:
    return re.sub(
        r"[^A-Za-z0-9_.-]", lambda m: "".join(f"%{b:02X}" for b in m[0].encode()), str(name)
    )


def export(image: Image, chosen: list[Resource], out: Path) -> list[Path]:
    """Write the chosen resources under out (see the module's description); the paths written."""
    every = walk(image)
    singles = {(r.type_name, r.name): r for r in every if r.type_name in ("ICON", "CURSOR")}
    langs: dict[tuple, int] = {}
    for r in chosen:
        langs[(r.type_name, r.name)] = langs.get((r.type_name, r.name), 0) + 1
    written = []

    def write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        written.append(path)

    for r in chosen:
        if r.type_name in ("ICON", "CURSOR"):
            continue  # written through their groups
        stem = safe(r.name) + (f"-{r.lang:04x}" if langs[(r.type_name, r.name)] > 1 else "")
        folder = out / safe(r.type_name.lower())
        try:
            data = image.read(r.rva, r.size)
        except ValueError:
            continue
        if r.type_name in ("GROUP_ICON", "GROUP_CURSOR"):
            cursor = r.type_name == "GROUP_CURSOR"
            try:
                found = group(data, cursor)
            except struct.error:
                write(folder / f"{stem}.bin", data)
                continue
            parts = []
            for entry in found["images"]:
                single = singles.get(("CURSOR" if cursor else "ICON", entry["id"]))
                if single is None:
                    continue
                try:
                    blob = image.read(single.rva, single.size)
                except ValueError:
                    continue
                hotspot, body = (blob[:4], blob[4:]) if cursor else (b"", blob)
                parts.append((entry, hotspot, body))
                converted = dib_to_png(body) if body.startswith(PNG) or len(body) >= 40 else None
                if converted:
                    name = f"{entry['width']}x{entry['height']}-{entry['bpp']}bpp-{entry['id']}.png"
                    write(folder / stem / name, converted)
            write(folder / f"{stem}{'.cur' if cursor else '.ico'}", icon_file(parts, cursor))
        elif r.type_name == "BITMAP":
            write(folder / f"{stem}.bmp", bmp_file(data))
        elif r.type_name in ("MANIFEST", "HTML"):
            write(folder / f"{stem}.{'xml' if r.type_name == 'MANIFEST' else 'html'}", data)
        else:
            write(folder / f"{stem}.bin", data)
    return written


def icon_file(parts: list[tuple[dict, bytes, bytes]], cursor: bool) -> bytes:
    """An .ico or .cur file of the images (an .ico entry carries planes and bit count, a .cur
    one the hotspot)."""
    head = struct.pack("<HHH", 0, 2 if cursor else 1, len(parts))
    offset, entries, bodies = 6 + 16 * len(parts), b"", b""
    for entry, hotspot, body in parts:
        width, height = entry["width"] % 256, entry["height"] % 256
        second = hotspot if cursor else struct.pack("<HH", 1, entry["bpp"])
        entries += struct.pack("<BBBB", width, height, 0, 0) + second
        entries += struct.pack("<II", len(body), offset + len(bodies))
        bodies += body
    return head + entries + bodies


def bmp_file(data: bytes) -> bytes:
    """A .bmp file around an RT_BITMAP (a DIB without the file header)."""
    header = struct.unpack_from("<I", data, 0)[0]
    if header == 12:  # BITMAPCOREHEADER: 3-byte palette entries
        bpp = struct.unpack_from("<H", data, 10)[0]
        palette = (3 << bpp) if bpp <= 8 else 0
    else:
        bpp, compression = struct.unpack_from("<HI", data, 14)
        used = struct.unpack_from("<I", data, 32)[0] if header >= 36 else 0
        palette = 4 * (used or (1 << bpp if bpp <= 8 else 0))
        if compression == 3 and header == 40:
            palette += 12
    pixels = 14 + header + palette
    return b"BM" + struct.pack("<IHHI", 14 + len(data), 0, 0, pixels) + data
