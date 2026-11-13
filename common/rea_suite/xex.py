"""Xbox 360 XEX2 executables: header, decrypted in-memory image, imports by name, title image.

From the CoD3 port's tools/xex_info.py, xex_extract.py and title_icon.py, made general and bounded:
every offset an XEX names is checked against the file, so a damaged or hostile file is refused
with XexError rather than read past its end. Formats: Xenia's xex2_info.h and kernel/util/
xex2.cc, free60's XEX documentation, and XEXLoaderWV's XEXHeader.java.
"""

from __future__ import annotations

import struct
from functools import cache
from pathlib import Path

from rea_suite import xdbf
from rea_suite.text import decoded

MAGIC = b"XEX2"
# The retail and devkit keys that wrap each title's AES key (public: Xenia, XEXLoaderWV, free60)
RETAIL_KEY = bytes.fromhex("20B185A59D28FDC340583FBB0896BF91")
DEVKIT_KEY = bytes(16)
MAX_HEADERS = 1024
MAX_IMAGE = 1 << 30
EXPORTS = Path(__file__).resolve().parent / "data" / "xbox360_exports.tsv"

OPT_NAMES = {
    0x000002FF: "RESOURCE_INFO",
    0x000003FF: "FILE_FORMAT_INFO",
    0x00000405: "BASE_REFERENCE",
    0x000005FF: "DELTA_PATCH_DESCRIPTOR",
    0x000080FF: "BOUNDING_PATH",
    0x00008105: "DEVICE_ID",
    0x00010001: "ORIGINAL_BASE_ADDRESS",
    0x00010100: "ENTRY_POINT",
    0x00010201: "IMAGE_BASE_ADDRESS",
    0x000103FF: "IMPORT_LIBRARIES",
    0x00018002: "CHECKSUM_TIMESTAMP",
    0x00018102: "ENABLED_FOR_CALLCAP",
    0x00018200: "ENABLED_FOR_FASTCAP",
    0x000183FF: "ORIGINAL_PE_NAME",
    0x000200FF: "STATIC_LIBRARIES",
    0x00020104: "TLS_INFO",
    0x00020200: "DEFAULT_STACK_SIZE",
    0x00020301: "DEFAULT_FILESYSTEM_CACHE_SIZE",
    0x00020401: "DEFAULT_HEAP_SIZE",
    0x00028002: "PAGE_HEAP_SIZE_AND_FLAGS",
    0x00030000: "SYSTEM_FLAGS",
    0x00040006: "EXECUTION_INFO",
    0x00040201: "TITLE_WORKSPACE_SIZE",
    0x00040310: "GAME_RATINGS",
    0x00040404: "LAN_KEY",
    0x000405FF: "XBOX360_LOGO",
    0x000406FF: "MULTIDISC_MEDIA_IDS",
    0x000407FF: "ALTERNATE_TITLE_IDS",
    0x00040801: "ADDITIONAL_TITLE_MEMORY",
    0x00E10402: "EXPORTS_BY_NAME",
}
COMPRESSION = {0: "none", 1: "basic", 2: "normal (LZX)", 3: "delta (LZX)"}


class XexError(ValueError):
    """Not an XEX2, or one this reader cannot or will not read."""


class Reader:
    """Big-endian reads that refuse to leave the buffer."""

    def __init__(self, data: bytes):
        self.data = data

    def check(self, offset: int, size: int) -> int:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise XexError(f"offset 0x{offset:x}+{size} is outside the {len(self.data)}-byte file")
        return offset

    def u32(self, offset: int) -> int:
        return struct.unpack_from(">I", self.data, self.check(offset, 4))[0]

    def u16(self, offset: int) -> int:
        return struct.unpack_from(">H", self.data, self.check(offset, 2))[0]

    def bytes(self, offset: int, size: int) -> bytes:
        return self.data[self.check(offset, size) : offset + size]

    def cstr(self, offset: int, limit: int = 4096) -> str:
        self.check(offset, 1)
        end = self.data.find(b"\0", offset, offset + limit)
        if end < 0:
            raise XexError(f"unterminated string at 0x{offset:x}")
        return decoded(self.data[offset:end], "latin-1", limit)


def parse(data: bytes) -> dict:
    """The XEX2 header as JSON-ready data (offsets and ids in hex)."""
    if data[:4] != MAGIC:
        raise XexError("not an XEX2 (no XEX2 magic)")
    r = Reader(data)
    count = r.u32(0x14)
    if count > MAX_HEADERS:
        raise XexError(f"{count} optional headers (at most {MAX_HEADERS})")
    info = {
        "size": len(data),
        "module_flags": hex(r.u32(4)),
        "pe_data_offset": hex(r.u32(8)),
        "security_offset": hex(r.u32(0x10)),
        "headers": {},
    }
    for i in range(count):
        key, value = r.u32(0x18 + i * 8), r.u32(0x1C + i * 8)
        name = OPT_NAMES.get(key, hex(key))
        header = {"key": hex(key)}
        header["value" if key & 0xFF in (0, 1) else "offset"] = hex(value)
        info["headers"][name] = header
        optional(r, name, value, header)
    s = r.u32(0x10)
    info["security"] = {
        "header_size": hex(r.u32(s)),
        "image_size": hex(r.u32(s + 4)),
        "image_flags": hex(r.u32(s + 0x10C)),
        "load_address": hex(r.u32(s + 0x110)),
        "region": hex(r.u32(s + 0x178)),
        "allowed_media": hex(r.u32(s + 0x17C)),
        "page_descriptor_count": r.u32(s + 0x180),
        "encrypted_aes_key": r.bytes(s + 0x150, 16).hex(),
    }
    return info


def optional(r: Reader, name: str, at: int, h: dict) -> None:
    if name == "FILE_FORMAT_INFO":
        encryption, compression = r.u16(at + 4), r.u16(at + 6)
        h.update(
            encryption=encryption,
            compression=compression,
            compression_name=COMPRESSION.get(compression, "unknown"),
        )
        if compression == 1:
            h["basic_blocks"] = (r.u32(at) - 8) // 8
        elif compression == 2:
            h["lzx_window_size"] = hex(r.u32(at + 8))
    elif name == "ORIGINAL_PE_NAME":
        h["name"] = r.cstr(at + 4)
    elif name == "EXECUTION_INFO":
        media, version, base, title = (r.u32(at + 4 * k) for k in range(4))
        platform, exe_type, disc, discs = r.bytes(at + 16, 4)
        h.update(
            media_id=hex(media),
            version=hex(version),
            base_version=hex(base),
            title_id=f"{title:08X}",
            platform=platform,
            exe_type=exe_type,
            disc=disc,
            disc_count=discs,
        )
    elif name == "STATIC_LIBRARIES":
        libs = []
        for j in range(min((r.u32(at) - 4) // 16, MAX_HEADERS)):
            o = at + 4 + j * 16
            lib = decoded(r.bytes(o, 8).rstrip(b"\0"), "latin-1")
            major, minor, build, qfe = (r.u16(o + 8 + 2 * k) for k in range(4))
            libs.append(f"{lib} {major}.{minor}.{build}.{qfe & 0x7FFF}")
        h["libs"] = libs
    elif name == "TLS_INFO":
        h["tls"] = [hex(r.u32(at + 4 * k)) for k in range(4)]
    elif name == "IMPORT_LIBRARIES":
        h["libraries"] = imports_header(r, at)
    elif name == "RESOURCE_INFO":
        h["resources"] = [
            {
                "name": decoded(r.bytes(at + 4 + j * 16, 8).rstrip(b"\0"), "latin-1"),
                "addr": hex(r.u32(at + 12 + j * 16)),
                "size": hex(r.u32(at + 16 + j * 16)),
            }
            for j in range(min((r.u32(at) - 4) // 16, MAX_HEADERS))
        ]


def imports_header(r: Reader, at: int) -> list[dict]:
    """Import libraries: size, string table size and count, the strings, then library records."""
    size, table, count = r.u32(at), r.u32(at + 4), r.u32(at + 8)
    r.check(at, size)
    strings, p, end = [], at + 12, at + 12 + table
    while p < end and len(strings) < min(count, MAX_HEADERS):
        name = r.cstr(p, end - p)
        strings.append(name)
        p += len(name) + 1
        while p < end and r.data[p] == 0:
            p += 1
    libs, p = [], end
    while p < at + size and len(libs) < MAX_HEADERS:
        record = r.u32(p)
        if record < 0x28:
            raise XexError(f"import library record of {record} bytes at 0x{p:x}")
        index = r.u16(p + 0x24) & 0xFF
        thunks = r.u16(p + 0x26)
        libs.append(
            {
                "name": strings[index] if index < len(strings) else f"#{index}",
                "version": hex(r.u32(p + 0x1C)),
                "min_version": hex(r.u32(p + 0x20)),
                "record_count": thunks,
                "records": [hex(r.u32(p + 0x28 + j * 4)) for j in range(thunks)],
            }
        )
        p += record
    return libs


def _aes(key: bytes, data: bytes, cbc: bool) -> bytes:
    # cryptography is a suite dependency (pyproject.toml); loaded only to decrypt
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    mode = modes.CBC(bytes(16)) if cbc else modes.ECB()
    cipher = Cipher(algorithms.AES(key), mode).decryptor()
    return cipher.update(data) + cipher.finalize()


def image(data: bytes) -> tuple[dict, bytes, str]:
    """The decrypted, decompressed image as loaded at its base; which key opened it.

    Basic and no compression only: an LZX-compressed XEX (normal/delta) is refused with that
    reason; `rea-suite xbox360 analyze` reads those through XEXLoaderWV."""
    info = parse(data)
    r = Reader(data)
    ffi = info["headers"].get("FILE_FORMAT_INFO")
    if not ffi:
        raise XexError("no FILE_FORMAT_INFO header")
    if ffi["compression"] not in (0, 1):
        raise XexError(
            f"{ffi['compression_name']} compression is not read by this tool;"
            " `rea-suite xbox360 analyze` opens it through XEXLoaderWV"
        )
    size = int(info["security"]["image_size"], 16)
    if not 0 < size <= MAX_IMAGE:
        raise XexError(f"image size 0x{size:x} out of range")
    payload = data[r.check(int(info["pe_data_offset"], 16), 0) :]
    payload = payload[: len(payload) // 16 * 16]
    candidates = [("plain", payload)]
    if ffi["encryption"]:
        wrapped = bytes.fromhex(info["security"]["encrypted_aes_key"])
        candidates = [
            (name, _aes(_aes(key, wrapped, False), payload, True))
            for name, key in (("retail", RETAIL_KEY), ("devkit", DEVKIT_KEY))
        ]
    for name, plain in candidates:
        result = expand(r, int(ffi["offset"], 16), ffi["compression"], plain, size)
        if result[:2] == b"MZ":
            return info, result, name
    raise XexError("no PE image after decryption (retail and devkit keys tried)")


def expand(r: Reader, ffi: int, compression: int, data: bytes, size: int) -> bytes:
    if compression == 0:
        return (data + bytes(max(0, size - len(data))))[:size]
    out, p = bytearray(), 0
    for j in range((r.u32(ffi) - 8) // 8):
        stored, zeros = r.u32(ffi + 8 + j * 8), r.u32(ffi + 12 + j * 8)
        if len(out) + stored + zeros > size:
            raise XexError("basic compression blocks exceed the image size")
        out += data[p : p + stored] + bytes(zeros)
        p += stored
    return bytes(out + bytes(size - len(out)))


@cache
def exports() -> dict[tuple[str, int], tuple[str, str]]:
    """(module, ordinal) -> (name, kind), from Xenia's tables (data/LICENSE.xenia)."""
    table = {}
    for line in EXPORTS.read_text().splitlines():
        if line and not line.startswith("#"):
            module, ordinal, name, kind = line.split("\t")
            table[module, int(ordinal)] = (name, kind)
    return table


def imports(info: dict, img: bytes) -> list[dict]:
    """Every import thunk: library, address, variable or function, ordinal and its name."""
    base = int(info["headers"]["IMAGE_BASE_ADDRESS"]["value"], 16)
    r = Reader(img)
    rows = []
    for lib in info["headers"].get("IMPORT_LIBRARIES", {}).get("libraries", []):
        module = lib["name"].rsplit(".", 1)[0].lower()
        for record in lib["records"]:
            address = int(record, 16)
            value = r.u32(address - base)
            ordinal = value & 0xFFFF
            name, _ = exports().get((module, ordinal), ("", ""))
            rows.append(
                {
                    "library": lib["name"],
                    "address": f"{address:08X}",
                    "type": "func" if value >> 24 == 1 else "var",
                    "ordinal": ordinal,
                    "name": name,
                }
            )
    return rows


def title_resource(info: dict, img: bytes) -> bytes:
    """The title's own resource (its SPA, an XDBF): the one named after the title id."""
    base = int(info["headers"]["IMAGE_BASE_ADDRESS"]["value"], 16)
    title = info["headers"].get("EXECUTION_INFO", {}).get("title_id", "")
    r = Reader(img)
    for res in info["headers"].get("RESOURCE_INFO", {}).get("resources", []):
        if title and res["name"].upper() == title:
            return r.bytes(int(res["addr"], 16) - base, int(res["size"], 16))
    raise XexError(f"no resource named after the title id ({title or 'none'}) in this XEX")


def title_image(info: dict, img: bytes) -> bytes:
    """The dashboard title image (PNG): the title's XDBF resource, image entry 0x8000."""
    try:
        entry = xdbf.read(title_resource(info, img)).find(xdbf.IMAGE, 0x8000)
    except xdbf.XdbfError as exc:
        raise XexError(f"title resource: {exc}") from exc
    if entry and entry.data[:8] == b"\x89PNG\r\n\x1a\n":
        return entry.data
    raise XexError("no title image (XDBF image 0x8000) in this XEX")


def ico(png: bytes) -> bytes:
    """A one-image .ico holding the PNG (Windows scales it)."""
    width, height = struct.unpack(">II", png[16:24])
    entry = struct.pack("<BBBBHHII", width % 256, height % 256, 0, 0, 1, 32, len(png), 22)
    return struct.pack("<HHH", 0, 1, 1) + entry + png
