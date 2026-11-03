"""Static searches over an Xbox 360 image (big-endian PowerPC) without Ghidra.

From the CoD3 port's tools (pdata.py, rtti.py, blxref.py, strxref.py, find_patterns.py,
ppc_dis.py), made general: the image is an XEX (decrypted in memory), a PE image extracted from
one, or a raw memory dump with --base. Every result is an address in the loaded image.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field

from rea_suite import xex

DEFAULT_BASE = 0x82000000
MAX_PDATA = 1 << 22


@dataclass
class Image:
    """The image as loaded: memory from `base`, and its sections (name -> (address, size))."""

    data: bytes
    base: int
    sections: dict[str, tuple[int, int]] = field(default_factory=dict)
    source: str = "raw"

    def words(self) -> tuple[int, ...]:
        usable = len(self.data) // 4 * 4
        return struct.unpack(f">{usable // 4}I", self.data[:usable])

    def u32(self, address: int) -> int:
        offset = address - self.base
        if not 0 <= offset <= len(self.data) - 4:
            raise ValueError(f"0x{address:08x} is outside the image")
        return struct.unpack_from(">I", self.data, offset)[0]

    def code(self) -> list[tuple[int, int]]:
        """Executable ranges (start index, end index in words); the whole image without sections."""
        ranges = [
            ((a - self.base) // 4, (a - self.base + s) // 4)
            for name, (a, s) in self.sections.items()
            if name in (".text", ".init") or name.startswith(".text")
        ]
        return ranges or [(0, len(self.data) // 4)]


def pe_sections(data: bytes) -> tuple[int, int, dict[str, tuple[int, int, int, int]]]:
    """Image base, image size and sections (name -> (rva, virtual size, file offset, raw size))."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError("not a PE image (no MZ)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature)")
    count, optional = (
        struct.unpack_from("<H", data, pe + 6)[0],
        struct.unpack_from("<H", data, pe + 20)[0],
    )
    base, size = (
        struct.unpack_from("<I", data, pe + 52)[0],
        struct.unpack_from("<I", data, pe + 80)[0],
    )
    sections = {}
    for i in range(min(count, 96)):
        name, vsize, rva, raw_size, raw = struct.unpack_from(
            "<8sIIII", data, pe + 24 + optional + 40 * i
        )
        sections[name.rstrip(b"\0").decode("latin-1")] = (rva, vsize or raw_size, raw, raw_size)
    return base, size, sections


def memory_layout(data: bytes) -> bool:
    """True for an image dumped as loaded (an XEX's extracted PE): its sections sit at their
    RVAs and the file outgrows the raw layout its section table still describes."""
    _, _, sections = pe_sections(data)
    raw_end = max((raw + raw_size for _, _, raw, raw_size in sections.values()), default=0)
    moved = any(raw != rva for rva, _, raw, raw_size in sections.values() if raw_size)
    return moved and len(data) > raw_end


def loaded_headers(data: bytes) -> bytes:
    """A memory-layout image whose section table is rewritten to describe it (file offset = RVA,
    raw size = virtual size), which is how Ghidra's PE loader then maps it. Lossless: an XEX's
    image holds data past a section's original raw size, so moving bytes back would drop them."""
    out = bytearray(data)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count, optional = (
        struct.unpack_from("<H", data, pe + 6)[0],
        struct.unpack_from("<H", data, pe + 20)[0],
    )
    for i in range(min(count, 96)):
        at = pe + 24 + optional + 40 * i
        vsize, rva = struct.unpack_from("<II", data, at + 8)
        size = max(0, min(vsize, len(data) - rva))
        struct.pack_into("<II", out, at + 16, size, rva if size else 0)
    return bytes(out)


def load(data: bytes, base: int | None = None) -> Image:
    """An XEX, a PE image (file or memory layout, mapped by its section table) or a raw dump."""
    source = "raw"
    if data[:4] == xex.MAGIC:
        _, data, _ = xex.image(data)
        source = "xex"
    if data[:2] == b"MZ":
        image_base, size, sections = pe_sections(data)
        if size > xex.MAX_IMAGE:
            raise ValueError(f"image size 0x{size:x} out of range")
        loaded = source == "xex" or memory_layout(data)
        memory = bytearray(max(size, len(data) if loaded else 0))
        # The headers end where the first section's bytes start.
        header = min([len(data), 0x1000, *(raw for _, _, raw, n in sections.values() if n)])
        memory[:header] = data[:header]
        for rva, vsize, raw, raw_size in sections.values():
            start, size = (rva, vsize) if loaded else (raw, min(vsize, raw_size))
            chunk = data[start : start + size]
            memory[rva : rva + len(chunk)] = chunk
        found = {name: (image_base + rva, vsize) for name, (rva, vsize, _, _) in sections.items()}
        return Image(bytes(memory), base or image_base, found, source if source == "xex" else "pe")
    return Image(data, DEFAULT_BASE if base is None else base, {}, source)


def pdata(img: Image) -> list[tuple[int, int]]:
    """The .pdata function table: (begin, length in bytes), sorted."""
    if ".pdata" not in img.sections:
        raise ValueError("no .pdata section (a raw dump has no section table)")
    start, size = img.sections[".pdata"]
    code = img.code()
    entries = []
    for at in range(start, start + min(size, MAX_PDATA * 8) - 7, 8):
        begin, word = img.u32(at), img.u32(at + 4)
        # Skips empty and padding records: a function starts on a word in the code.
        index = (begin - img.base) // 4
        if begin % 4 == 0 and any(lo <= index < hi for lo, hi in code):
            entries.append((begin, ((word >> 8) & 0x3FFFFF) * 4))
    return sorted(entries)


def containing(entries: list[tuple[int, int]], address: int) -> tuple[int, int] | None:
    starts = [b for b, _ in entries]
    i = bisect.bisect_right(starts, address) - 1
    if i >= 0 and entries[i][0] <= address < entries[i][0] + entries[i][1]:
        return entries[i]
    return None


def callers(img: Image, targets: list[int]) -> list[tuple[int, int, str]]:
    """Relative b/bl instructions to the targets: (target, source, mnemonic)."""
    wanted, found = set(targets), []
    words = img.words()
    for lo, hi in img.code():
        for i in range(lo, min(hi, len(words))):
            w = words[i]
            if w >> 26 != 18 or w & 2:
                continue
            offset = w & 0x03FFFFFC
            if offset & 0x02000000:
                offset -= 0x04000000
            source = img.base + 4 * i
            if source + offset in wanted:
                found.append((source + offset, source, "bl" if w & 1 else "b"))
    return sorted(found)


# D-form instructions that take rA plus a 16-bit displacement: addi, and the loads and stores.
D_FORM = {14, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 58, 62}


def address_refs(img: Image, targets: list[int], window: int = 24) -> list[tuple[int, int, int]]:
    """lis rD,hi followed within `window` words by a D-form on rD with lo: the way 32-bit
    addresses are built on PowerPC, which Ghidra often leaves unresolved. (target, lis, use)."""
    words = img.words()
    found = []
    for target in targets:
        hi, lo = ((target + 0x8000) >> 16) & 0xFFFF, target & 0xFFFF
        for start, end in img.code():
            for i in range(start, min(end, len(words))):
                w = words[i]
                if w >> 26 != 15 or (w >> 16) & 31 or w & 0xFFFF != hi:  # lis rD,hi (addis rD,0)
                    continue
                rd = (w >> 21) & 31
                for j in range(i + 1, min(i + 1 + window, len(words))):
                    x = words[j]
                    if x >> 26 in D_FORM and (x >> 16) & 31 == rd and x & 0xFFFF == lo:
                        found.append((target, img.base + 4 * i, img.base + 4 * j))
                        break
    return found


def strings_at(img: Image, text: str) -> list[int]:
    """Addresses of the NUL-terminated string (starting after a NUL or at the image start)."""
    needle, found = text.encode() + b"\0", []
    i = img.data.find(needle)
    while i >= 0:
        if i == 0 or img.data[i - 1] == 0:
            found.append(img.base + i)
        i = img.data.find(needle, i + 1)
    return found


def rtti(img: Image, name: str) -> dict | None:
    """MSVC RTTI for a class: its type descriptor, complete object locators and vtables."""
    i = img.data.find(f".?AV{name}@@".encode() + b"\0")
    if i < 0:
        return None
    descriptor = img.base + i - 8  # {vtable*, spare, name[]}
    h = "{:08X}".format
    words = img.words()
    locators = [
        img.base + k * 4 - 12
        for k, w in enumerate(words)
        if w == descriptor and k >= 3 and not words[k - 3]
    ]
    result = {"type_descriptor": h(descriptor), "locators": []}
    for col in locators:
        vtables = [img.base + k * 4 + 4 for k, w in enumerate(words) if w == col]
        result["locators"].append(
            {
                "address": h(col),
                "offset": img.u32(col + 4),
                "vtables": [
                    {"address": h(vt), "slots": [h(img.u32(vt + 4 * s)) for s in range(12)]}
                    for vt in vtables
                    if vt - img.base + 48 <= len(img.data)
                ],
            }
        )
    return result


# The register save/restore helpers by their first entry (XenonRecomp's config keys).
HELPERS = {
    "restgprlr_14_address": bytes.fromhex("e9c1ff68"),
    "savegprlr_14_address": bytes.fromhex("f9c1ff68"),
    "restfpr_14_address": bytes.fromhex("c9ccff70"),
    "savefpr_14_address": bytes.fromhex("d9ccff70"),
    "restvmx_14_address": bytes.fromhex("3960fee07dcb60ce"),
    "savevmx_14_address": bytes.fromhex("3960fee07dcb61ce"),
    "restvmx_64_address": bytes.fromhex("3960fc00100b60cb"),
    "savevmx_64_address": bytes.fromhex("3960fc00100b61cb"),
}


def helpers(img: Image) -> dict[str, list[int]]:
    """Word-aligned matches of each helper's first entry (XenonHelpers.java finds every entry)."""
    found = {}
    for key, pattern in HELPERS.items():
        hits, i = [], img.data.find(pattern)
        while i >= 0:
            if i % 4 == 0:
                hits.append(img.base + i)
            i = img.data.find(pattern, i + 1)
        found[key] = hits
    return found


def disassemble(img: Image, address: int, count: int) -> list[tuple[int, str, str]]:
    """Capstone's PowerPC (64-bit, big-endian); words it cannot decode (VMX128 among them) are
    shown as `.long` with their primary opcode."""
    import capstone  # a suite dependency (pyproject.toml)

    engine = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN)
    rows = []
    for k in range(count):
        at = address + 4 * k
        word = img.u32(at)
        raw = word.to_bytes(4, "big")
        decoded = next(engine.disasm(raw, at), None)
        if decoded:
            text = f"{decoded.mnemonic} {decoded.op_str}".strip()
        else:
            note = " (VMX128?)" if word >> 26 in (4, 5, 6) else ""
            text = f".long 0x{word:08x}  ; opcode {word >> 26} not decoded{note}"
        rows.append((at, raw.hex(), text))
    return rows
