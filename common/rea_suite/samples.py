"""Synthetic PE files for the tests: no game bytes, only what a test spells out."""

from __future__ import annotations

import struct

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000


def align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


def pe(
    sections: list[tuple[str, bytes]],
    *,
    base: int = 0x400000,
    entry: int = 0x1000,
    timestamp: int = 0x3A000000,
    debug_timestamp: int | None = None,
    x64: bool = False,
) -> bytes:
    """A PE32 (or PE32+) image with the sections in order from RVA 0x1000, each in its own
    page; file offsets differ from RVAs, so a reader has to map through the section table.
    With debug_timestamp, a CodeView debug directory carrying it goes at the start of the
    last section (its first 28 bytes are overwritten)."""
    sections = list(sections)
    count = len(sections)
    optional = 0xF0 if x64 else 0xE0
    headers = align(0x40 + 4 + 20 + optional + 40 * count, FILE_ALIGN)
    table, body, rva, offset = b"", b"", SECTION_ALIGN, headers
    places = []
    for name, data in sections:
        raw = align(max(len(data), 1), FILE_ALIGN)
        places.append((rva, offset))
        table += struct.pack(
            "<8sIIIIIIHHI",
            name.encode()[:8],
            max(len(data), 1),
            rva,
            raw,
            offset,
            0,
            0,
            0,
            0,
            0xE0000020 if name == ".text" else 0x40000040,
        )
        body += data.ljust(raw, b"\0")
        rva += align(max(len(data), 1), SECTION_ALIGN)
        offset += raw
    size_of_image = rva
    directories = [(0, 0)] * 16
    if debug_timestamp is not None:
        last_rva, last_offset = places[-1]
        entry_bytes = struct.pack("<IIHHIIII", 0, debug_timestamp, 0, 0, 2, 0, 0, 0)
        start = last_offset - headers
        body = body[:start] + entry_bytes + body[start + len(entry_bytes) :]
        directories[6] = (last_rva, len(entry_bytes))
    dirs = b"".join(struct.pack("<II", *d) for d in directories)
    if x64:
        opt = struct.pack(
            "<HBBIIIII",
            0x20B, 6, 0, 0, 0, 0, entry, SECTION_ALIGN,
        ) + struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII",
            base, SECTION_ALIGN, FILE_ALIGN, 4, 0, 0, 0, 4, 0, 0, size_of_image, headers,
            0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )  # fmt: skip
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 6, 0, 0, 0, 0, entry, SECTION_ALIGN, 0, base, SECTION_ALIGN, FILE_ALIGN,
            4, 0, 0, 0, 4, 0, 0, size_of_image, headers, 0, 2, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )  # fmt: skip
    opt += dirs
    assert len(opt) == optional
    coff = struct.pack(
        "<HHIIIHH", 0x8664 if x64 else 0x14C, count, timestamp, 0, 0, optional, 0x102
    )
    dos = b"MZ".ljust(0x3C, b"\0") + struct.pack("<I", 0x40)
    head = (dos + b"PE\0\0" + coff + opt + table).ljust(headers, b"\0")
    return head + body
