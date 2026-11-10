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
    directories: dict[int, tuple[int, int]] | None = None,
    flags: dict[str, int] | None = None,
) -> bytes:
    """A PE32 (or PE32+) image with the sections in order from RVA 0x1000, each in its own
    page; file offsets differ from RVAs, so a reader has to map through the section table.
    With debug_timestamp, a CodeView debug directory carrying it goes at the start of the
    last section (its first 28 bytes are overwritten). directories sets data directories by
    index (RVA, size); flags overrides a section's characteristics by name."""
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
            (flags or {}).get(name, 0xE0000020 if name == ".text" else 0x40000040),
        )
        body += data.ljust(raw, b"\0")
        rva += align(max(len(data), 1), SECTION_ALIGN)
        offset += raw
    size_of_image = rva
    given, directories = directories or {}, [(0, 0)] * 16
    for index, value in given.items():
        directories[index] = value
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


def _put(buffer: bytearray, at: int, data: bytes) -> None:
    buffer[at : at + len(data)] = data


def program_x64() -> tuple[bytes, dict[str, int]]:
    """A small x64 program for the scanners: code that loads an ASCII and a UTF-16 string, calls
    a function directly, through an import and through a jmp thunk; an import table
    (KERNEL32.dll); an unwind table with a chained entry; and MSVC RTTI for `Base` and
    `game::Derived : Base`, each with a vtable. Returns the image and the RVAs a test names."""
    base, text, rdata, pdata = 0x140000000, 0x1000, 0x2000, 0x3000
    at = {
        "f1": 0x1000, "f1_chained": 0x1030, "f2": 0x1040, "vf1": 0x1050, "vf2": 0x1060,
        "vf3": 0x1070, "thunk": 0x1080, "via_thunk": 0x1090,
        "hello": 0x2000, "wide": 0x2020, "iat_tick": 0x2040, "iat_exit": 0x2048,
        "td_base": 0x2200, "td_derived": 0x2240, "chd_base": 0x2300, "chd_derived": 0x2320,
        "col_base": 0x2340, "col_derived": 0x2360, "vt_base": 0x2388, "vt_derived": 0x23A8,
    }  # fmt: skip
    code = bytearray(b"\xcc" * 0xA0)

    def rel(site: int, size: int, target: int) -> bytes:
        return struct.pack("<i", target - (site + size))

    _put(code, 0x00, b"\x48\x8d\x05" + rel(0x1000, 7, at["hello"]))  # lea rax, [hello]
    _put(code, 0x07, b"\xe8" + rel(0x1007, 5, at["f2"]))  # call f2
    _put(code, 0x0C, b"\xff\x15" + rel(0x100C, 6, at["iat_tick"]))  # call [GetTickCount]
    _put(code, 0x12, b"\x48\x8d\x0d" + rel(0x1012, 7, at["wide"]))  # lea rcx, [wide]
    _put(code, 0x19, b"\xc3")
    _put(code, 0x30, b"\xe9" + rel(0x1030, 5, at["f2"]))  # jmp f2 (tail call)
    for name in ("f2", "vf1", "vf2", "vf3"):
        _put(code, at[name] - text, b"\xc3")
    _put(code, 0x80, b"\xff\x25" + rel(0x1080, 6, at["iat_exit"]))  # jmp [ExitProcess]
    _put(code, 0x90, b"\xe8" + rel(0x1090, 5, at["thunk"]) + b"\xc3")  # call thunk

    data = bytearray(0x440)
    _put(data, 0x000, b"hello world\0")
    _put(data, 0x020, "wide".encode("utf-16-le") + b"\0\0")
    _put(data, 0x040, struct.pack("<QQQ", 0x2080, 0x20A0, 0))  # IAT
    _put(data, 0x060, struct.pack("<QQQ", 0x2080, 0x20A0, 0))  # lookup table
    _put(data, 0x080, b"\0\0GetTickCount\0")
    _put(data, 0x0A0, b"\0\0ExitProcess\0")
    _put(data, 0x0C0, b"KERNEL32.dll\0")
    _put(data, 0x0E0, struct.pack("<5I", 0x2060, 0, 0, 0x20C0, 0x2040))  # + zero descriptor
    _put(data, 0x200, bytes(16) + b".?AVBase@@\0")
    _put(data, 0x240, bytes(16) + b".?AVDerived@game@@\0")
    _put(data, 0x280, struct.pack("<IIiiiII", 0x2200, 0, 0, -1, 0, 0x40, 0x2300))
    _put(data, 0x2A0, struct.pack("<IIiiiII", 0x2240, 1, 0, -1, 0, 0x40, 0x2320))
    _put(data, 0x2E0, struct.pack("<I", 0x2280))
    _put(data, 0x2E8, struct.pack("<II", 0x22A0, 0x2280))
    _put(data, 0x300, struct.pack("<4I", 0, 0, 1, 0x22E0))
    _put(data, 0x320, struct.pack("<4I", 0, 0, 2, 0x22E8))
    _put(data, 0x340, struct.pack("<6I", 1, 0, 0, 0x2200, 0x2300, 0x2340))
    _put(data, 0x360, struct.pack("<6I", 1, 0, 0, 0x2240, 0x2320, 0x2360))
    _put(data, 0x380, struct.pack("<4Q", base + 0x2340, base + 0x1050, base + 0x1060, 0))
    _put(data, 0x3A0, struct.pack("<4Q", base + 0x2360, base + 0x1070, base + 0x1060, 0))
    _put(data, 0x400, b"\x01\0\0\0")  # unwind info
    _put(data, 0x410, b"\x21\0\0\0" + struct.pack("<3I", 0x1000, 0x1030, 0x2400))  # chained
    unwind = struct.pack(
        "<9I", 0x1000, 0x1030, 0x2400, 0x1030, 0x1040, 0x2410, 0x1040, 0x1050, 0x2400
    )
    image = pe(
        [(".text", bytes(code)), (".rdata", bytes(data)), (".pdata", unwind)],
        base=base,
        entry=0x1000,
        x64=True,
        directories={1: (0x20E0, 40), 3: (pdata, len(unwind)), 12: (0x2040, 24)},
    )
    assert text == 0x1000 and rdata == 0x2000
    return image, at


def program_x86() -> tuple[bytes, dict[str, int]]:
    """A small x86 program: code that pushes a string's address, and MSVC RTTI (VAs, signature
    0) for one class `Thing` with a two-slot vtable."""
    base = 0x400000
    at = {"push": 0x1000, "vf1": 0x1010, "vf2": 0x1020, "hello": 0x2000, "td": 0x2100,
          "col": 0x2180, "vtable": 0x21A4}  # fmt: skip
    code = bytearray(b"\xcc" * 0x30)
    _put(code, 0x00, b"\x68" + struct.pack("<I", base + at["hello"]) + b"\xc3")
    _put(code, 0x10, b"\xc3")
    _put(code, 0x20, b"\xc3")
    data = bytearray(0x200)
    _put(data, 0x000, b"hello\0")
    _put(data, 0x100, bytes(8) + b".?AVThing@@\0")
    _put(data, 0x140, struct.pack("<IIiiiII", base + 0x2100, 0, 0, -1, 0, 0x40, base + 0x2170))
    _put(data, 0x160, struct.pack("<I", base + 0x2140))
    _put(data, 0x170, struct.pack("<4I", 0, 0, 1, base + 0x2160))
    _put(data, 0x180, struct.pack("<5I", 0, 0, 0, base + 0x2100, base + 0x2170))
    _put(data, 0x1A0, struct.pack("<4I", base + 0x2180, base + 0x1010, base + 0x1020, 0))
    return pe([(".text", bytes(code)), (".rdata", bytes(data))], base=base), at


def program_registry() -> tuple[bytes, dict[str, int]]:
    """x64 code that registers three settings the way an engine's option table does: strings
    loaded with RIP-relative lea, a bool's default stored to [rsp+0x30], then a call to the
    registrar for the type. Assembled with Keystone (a suite dependency)."""
    from keystone import KS_ARCH_X86, KS_MODE_64, Ks

    base, start = 0x140000000, 0x1000
    names = ["Enables fog", "fog", "en", "language code", "Interface language", "language",
             "Skips intros", "skipintro"]  # fmt: skip
    strings, at, data = {}, 0x2000, b""
    for text in names:
        strings[text] = at + len(data)
        data += text.encode() + b"\0"
    reg_bool, reg_string, other = 0x1200, 0x1210, 0x1220
    lines = [
        ("lea", "rcx", "Enables fog"), ("lea", "rdx", "fog"), "mov byte ptr [rsp + 0x30], 1",
        f"call {reg_bool:#x}",
        ("lea", "r8", "en"), ("lea", "r9", "language code"), ("lea", "rcx", "Interface language"),
        ("lea", "rdx", "language"), f"call {reg_string:#x}",
        "xor r14d, r14d", ("lea", "rcx", "Skips intros"), ("lea", "rdx", "skipintro"),
        "mov byte ptr [rsp + 0x30], r14b", f"call {reg_bool:#x}", f"call {other:#x}", "ret",
    ]  # fmt: skip
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    code, sites = b"", []
    for line in lines:
        address = start + len(code)
        if isinstance(line, tuple):
            _, register, text = line
            line = f"lea {register}, [rip + {strings[text] - (address + 7):#x}]"
        encoded = bytes(ks.asm(line, address)[0])
        if line.startswith("call"):
            sites.append(address)
        code += encoded
    end = len(code)
    code = code.ljust(reg_bool - start, b"\xcc")
    for _ in range(3):
        code += b"\xc3".ljust(0x10, b"\xcc")
    image = pe([(".text", code), (".rdata", data)], base=base, x64=True)
    return image, {"start": start, "size": end, "bool": reg_bool, "string": reg_string,
                   "sites": sites}  # fmt: skip


def program_dll() -> tuple[bytes, dict[str, int]]:
    """An x64 DLL-like image for the PE model's other directories: two exports, a delay-loaded
    import, a TLS directory with one callback and two base relocations."""
    base = 0x180000000
    code = bytearray(b"\xcc" * 0x20)
    _put(code, 0x00, b"\xc3")
    _put(code, 0x10, b"\xc3")
    data = bytearray(0x460)
    _put(
        data,
        0x000,
        struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, 0x2100, 1, 2, 2, 0x2040, 0x2050, 0x2060),
    )
    _put(data, 0x040, struct.pack("<II", 0x1000, 0x1010))
    _put(data, 0x050, struct.pack("<II", 0x2110, 0x2118))
    _put(data, 0x060, struct.pack("<HH", 0, 1))
    _put(data, 0x100, b"lib.dll\0")
    _put(data, 0x110, b"Alpha\0")
    _put(data, 0x118, b"Beta\0")
    _put(
        data,
        0x200,
        struct.pack("<QQQQII", base + 0x2300, base + 0x2308, base + 0x2310, base + 0x2320, 0, 0),
    )
    _put(data, 0x320, struct.pack("<QQ", base + 0x1010, 0))
    _put(data, 0x380, struct.pack("<8I", 1, 0x2400, 0x2410, 0x2420, 0x2430, 0, 0, 0))
    _put(data, 0x400, b"late.dll\0")
    _put(data, 0x420, struct.pack("<QQ", 0x2440, 0))
    _put(data, 0x430, struct.pack("<QQ", 0x2440, 0))
    _put(data, 0x440, b"\0\0Later\0")
    relocs = struct.pack("<IIHH", 0x2000, 12, 0xA000 | 0x320, 0xA000 | 0x200)
    image = pe(
        [(".text", bytes(code)), (".rdata", bytes(data)), (".reloc", relocs)],
        base=base,
        x64=True,
        directories={
            0: (0x2000, 0x70),
            5: (0x3000, len(relocs)),
            9: (0x2200, 40),
            13: (0x2380, 64),
        },
    )
    return image, {"alpha": 0x1000, "beta": 0x1010, "late_slot": 0x2420}
