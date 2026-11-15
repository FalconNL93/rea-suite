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


def program_rtti() -> tuple[bytes, dict[str, int]]:
    """An x64 program for comparing vtables with their bases': `Iface` (abstract: its first
    slot is a thunk to VCRUNTIME140's imported `_purecall`), `Other` (whose second slot is a
    `ret` a test can declare a static purecall stub), and `Impl : Iface, Other` with one vtable
    per base: at offset 0 it overrides, inherits and adds a slot, at offset 8 it overrides
    Other's first and keeps the stub. Returns the image and the RVAs a test names."""
    base, text, rdata = 0x140000000, 0x1000, 0x2000
    fn = {"purecall": 0x1000, "stub": 0x1010, "a": 0x1020, "other": 0x1030, "impl": 0x1040,
          "added": 0x1050, "other2": 0x1060}  # fmt: skip
    iat = 0x2040
    code = bytearray(b"\xcc" * 0x70)
    _put(code, 0, b"\xff\x25" + struct.pack("<i", iat - (fn["purecall"] + 6)))  # jmp [_purecall]
    for name, rva in fn.items():
        if name != "purecall":
            _put(code, rva - text, b"\xc3")
    data = bytearray(0x600)
    _put(data, 0x040, struct.pack("<QQ", 0x2080, 0))  # IAT
    _put(data, 0x060, struct.pack("<QQ", 0x2080, 0))  # lookup table
    _put(data, 0x080, b"\0\0_purecall\0")
    _put(data, 0x0C0, b"VCRUNTIME140.dll\0")
    _put(data, 0x0E0, struct.pack("<5I", 0x2060, 0, 0, 0x20C0, iat))  # + zero descriptor
    cursor = 0x2100

    def put(blob: bytes) -> int:
        nonlocal cursor
        at = cursor
        _put(data, at - rdata, blob)
        cursor = align(at + len(blob), 8)
        return at

    names = ("Iface", "Other", "Impl")
    td = {n: put(bytes(16) + f".?AV{n}@@\0".encode()) for n in names}
    chd = {n: put(bytes(16)) for n in names}
    hierarchy = {"Iface": [("Iface", 0, 0)], "Other": [("Other", 0, 0)],
                 "Impl": [("Impl", 2, 0), ("Iface", 0, 0), ("Other", 0, 8)]}  # fmt: skip
    for name, entries in hierarchy.items():
        descriptors = [
            put(struct.pack("<IIiiiII", td[b], contained, mdisp, -1, 0, 0x40, chd[b]))
            for b, contained, mdisp in entries
        ]
        array = put(struct.pack(f"<{len(descriptors)}I", *descriptors))
        attributes = 1 if len(entries) > 2 else 0  # multiple inheritance
        _put(data, chd[name] - rdata, struct.pack("<4I", 0, attributes, len(entries), array))
    at = {**fn, "iat": iat}
    vtables = {("Iface", 0): ["purecall", "a"], ("Other", 0): ["other", "stub"],
               ("Impl", 0): ["impl", "a", "added"], ("Impl", 8): ["other2", "stub"]}  # fmt: skip
    for (name, offset), slots in vtables.items():
        locator = cursor
        put(struct.pack("<6I", 1, offset, 0, td[name], chd[name], locator))
        table = put(struct.pack(f"<{len(slots) + 2}Q", base + locator,
                                *(base + fn[s] for s in slots), 0)) + 8  # fmt: skip
        at[f"vt_{name.lower()}_{offset}"] = table
    image = pe(
        [(".text", bytes(code)), (".rdata", bytes(data))],
        base=base,
        x64=True,
        directories={1: (0x20E0, 40), 12: (iat, 16)},
    )
    return image, at


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


def resource_section(entries: list[tuple[int | str, int | str, int, bytes]], rva: int) -> bytes:
    """A .rsrc section at rva holding (type, name, language, data) entries: the three-level
    directory (named entries before numbered ones, as the format orders them), the data
    entries, the names and the data, each aligned to 4."""
    tree: dict = {}
    for kind, name, lang, data in entries:
        tree.setdefault(kind, {}).setdefault(name, {})[lang] = data

    def ordered(keys) -> list:
        return sorted(k for k in keys if isinstance(k, str)) + sorted(
            k for k in keys if isinstance(k, int)
        )

    # sizes first: directories, then data entries, then strings, then data
    directories = []  # (key path, children keys)

    def plan(node: dict, path: tuple) -> None:
        directories.append((path, ordered(node)))
        for key in ordered(node):
            if isinstance(node[key], dict):
                plan(node[key], (*path, key))

    plan(tree, ())
    places, at = {}, 0
    for path, keys in directories:
        places[path] = at
        at += 16 + 8 * len(keys)
    leaves = [
        (k, n, lang)
        for k in ordered(tree)
        for n in ordered(tree[k])
        for lang in ordered(tree[k][n])
    ]
    leaf_at = {}
    for leaf in leaves:
        leaf_at[leaf] = at
        at += 16
    names = sorted({key for path, keys in directories for key in keys if isinstance(key, str)})
    name_at = {}
    for name in names:
        name_at[name] = at
        at = align(at + 2 + 2 * len(name), 4)
    data_at = {}
    for leaf in leaves:
        data_at[leaf] = at
        at = align(at + len(tree[leaf[0]][leaf[1]][leaf[2]]), 4)
    out = bytearray(at)
    for path, keys in directories:
        named = sum(isinstance(k, str) for k in keys)
        head = struct.pack("<IIHHHH", 0, 0, 0, 0, named, len(keys) - named)
        body = b""
        for key in keys:
            ident = (0x80000000 | name_at[key]) if isinstance(key, str) else key
            if len(path) == 2:
                target = leaf_at[(*path, key)]
            else:
                target = 0x80000000 | places[(*path, key)]
            body += struct.pack("<II", ident, target)
        _put(out, places[path], head + body)
    for leaf in leaves:
        data = tree[leaf[0]][leaf[1]][leaf[2]]
        _put(out, leaf_at[leaf], struct.pack("<IIII", rva + data_at[leaf], len(data), 0, 0))
        _put(out, data_at[leaf], data)
    for name in names:
        _put(out, name_at[name], struct.pack("<H", len(name)) + name.encode("utf-16-le"))
    return bytes(out)


def _w(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\0\0"


def _pad4(data: bytes) -> bytes:
    return data.ljust(align(len(data), 4), b"\0")


def _version_node(key: str, value: bytes | str | None, children: list[bytes] = ()) -> bytes:
    text = isinstance(value, str)
    raw = _w(value) if text else (value or b"")
    head = struct.pack("<HHH", 0, len(raw) // 2 if text else len(raw), 1 if text else 0)
    body = _pad4(head + _w(key)) + _pad4(raw) + b"".join(_pad4(c) for c in children)
    return struct.pack("<H", len(body)) + body[2:]


def icon_dib(width: int, height: int, bpp: int, pixels: bytes, mask: bytes) -> bytes:
    """An icon image: BITMAPINFOHEADER (height doubled for the mask), pixels bottom-up, then
    the AND mask; pixels and mask already padded to their rows."""
    header = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, bpp, 0, 0, 0, 0, 0, 0)
    return header + pixels + mask


def program_resources() -> tuple[bytes, dict]:
    """An x86 image with one resource of each kind `pe resources` decodes: a DIALOG and a
    DIALOGEX with controls, a MENU and a MENUEX, a string table block, accelerators, version
    information, a message table, an icon group of a 32-bit DIB and a PNG, a cursor group, a
    bitmap, a manifest and a named RCDATA. Returns the image and what a test checks."""
    dlg = struct.pack("<IIHhhhh", 0x80C800C0, 0, 2, 0, 0, 200, 100) + b"\0\0" + b"\0\0"
    dlg += _w("About") + struct.pack("<H", 8) + _w("MS Sans Serif")
    dlg = _pad4(dlg) + struct.pack("<IIhhhhH", 0x50010001, 0, 10, 70, 50, 14, 1)
    dlg += b"\xff\xff\x80\x00" + _w("OK") + b"\0\0"
    dlg = _pad4(dlg) + struct.pack("<IIhhhhH", 0x50000000, 0, 10, 10, 100, 8, 0xFFFF)
    dlg += b"\xff\xff\x82\x00" + _w("Version 1") + b"\0\0"
    dlgex = struct.pack("<HHIIIHhhhh", 1, 0xFFFF, 0, 0, 0x80C80048, 1, 0, 0, 160, 80)
    dlgex += (
        b"\0\0" + b"\0\0" + _w("Launcher") + struct.pack("<HHBB", 9, 400, 0, 1) + _w("Segoe UI")
    )
    dlgex = _pad4(dlgex) + struct.pack("<IIIhhhhI", 0, 0, 0x50010000, 5, 5, 60, 14, 1001)
    dlgex += _w("SysListView32") + _w("&Play") + struct.pack("<H", 2) + b"\xab\xcd"
    menu = struct.pack("<HH", 0, 0)
    menu += struct.pack("<H", 0x10) + _w("&File")
    menu += struct.pack("<HH", 0, 40001) + _w("&Open")
    menu += struct.pack("<HH", 0, 0) + _w("")
    menu += struct.pack("<HH", 0x80, 40002) + _w("E&xit")
    menu += struct.pack("<HH", 0x80, 40003) + _w("&Help")
    menuex = struct.pack("<HHI", 1, 4, 0)
    menuex += _pad4(struct.pack("<IIIH", 0, 0, 0, 0x81) + _w("&Game"))
    menuex += struct.pack("<I", 0)
    menuex += _pad4(struct.pack("<IIIH", 0, 8, 50001, 0) + _w("&Start"))
    menuex += _pad4(struct.pack("<IIIH", 0x800, 0, 0, 0x80) + _w(""))
    table = b"".join(
        struct.pack("<H", len(s)) + s.encode("utf-16-le") for s in ["", "Hello", *[""] * 13, "Last"]
    )  # block 2: ids 16..31
    accel = struct.pack("<HHHH", 0x09, ord("O"), 40001, 0) + struct.pack(
        "<HHHH", 0x81, 0x70, 40100, 0
    )
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x10000, 0x10002, 0x30004, 0x10002, 0, 0x3F, 0,
                        0x40004, 1, 0, 0, 0)  # fmt: skip
    strings = _version_node("040904b0", None, [
        _version_node("CompanyName", "Example"), _version_node("FileVersion", "1.2.3.4")])  # fmt: skip
    version = _version_node("VS_VERSION_INFO", fixed, [
        _version_node("StringFileInfo", None, [strings]),
        _version_node("VarFileInfo", None, [_version_node("Translation", struct.pack("<HH", 0x409, 0x4B0))]),
    ])  # fmt: skip
    message = b"Disk full\r\n\0\0"
    messages = struct.pack("<IIII", 1, 7, 7, 16) + struct.pack("<HH", 4 + len(message), 0) + message
    rows = b"\x00\x00\xff\xff" + b"\xff\x00\x00\x80"  # bottom row: red opaque, blue half
    rows += b"\x00\xff\x00\xff" + b"\x00\x00\x00\x00"  # top row: green opaque, transparent
    dib = icon_dib(2, 2, 32, rows, b"\0" * 8)
    tiny_png = (
        PNG_SIGNATURE
        + struct.pack(">I", 13)
        + b"IHDR"
        + struct.pack(">IIBBBBB", 256, 256, 8, 6, 0, 0, 0)
    ) + b"\0" * 4  # only the header matters to the reader
    group_icon = struct.pack("<HHH", 0, 1, 2)
    group_icon += struct.pack("<BBBBHHIH", 2, 2, 0, 0, 1, 32, len(dib), 1)
    group_icon += struct.pack("<BBBBHHIH", 0, 0, 0, 0, 1, 32, len(tiny_png), 2)
    mono = icon_dib(1, 1, 1, b"\x80\0\0\0", b"\0\0\0\0")
    mono = mono[:40] + b"\0\0\0\0\xff\xff\xff\0" + mono[40:]  # palette: black, white
    cursor = struct.pack("<HH", 0, 0) + mono
    group_cursor = struct.pack("<HHH", 0, 2, 1) + struct.pack("<HHHHIH", 1, 2, 1, 1, len(cursor), 5)
    bitmap = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 4, 0, 0, 0, 0) + b"\x00\x00\xff\x00"
    manifest = b'<?xml version="1.0"?><assembly/>'
    entries = [
        (5, 101, 0x409, dlg), (5, "LAUNCHER", 0x409, dlgex), (4, 102, 0x409, menu),
        (4, 103, 0x409, menuex), (6, 2, 0x409, table), (9, 104, 0x409, accel),
        (16, 1, 0x409, version), (11, 1, 0x409, messages), (3, 1, 0x409, dib),
        (3, 2, 0x409, tiny_png), (14, 105, 0x409, group_icon), (1, 5, 0x409, cursor),
        (12, 106, 0x409, group_cursor), (2, 107, 0x409, bitmap), (24, 1, 0x409, manifest),
        (10, "CONFIG", 0x409, b"key=value"), (10, "CONFIG", 0x407, b"Schluessel=Wert"),
    ]  # fmt: skip
    rsrc_rva = 0x2000
    rsrc = resource_section(entries, rsrc_rva)
    image = pe(
        [(".text", b"\xc3"), (".rsrc", rsrc)],
        directories={2: (rsrc_rva, len(rsrc))},
    )
    return image, {"dib": dib, "png": tiny_png, "cursor": cursor, "bitmap": bitmap}


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def program_x86_functions() -> tuple[bytes, dict[str, int]]:
    """An x86 program for naming containing functions without an unwind table: `main` (frame,
    pushes a string, calls `helper`, an import and `leaf`, loads `callback`'s address),
    `helper` (frame, reads a global), `leaf` (no frame, one caller, after padding) and
    `callback` (no frame, no caller: found by the ret and padding before it). Assembled with
    Keystone."""
    from keystone import KS_ARCH_X86, KS_MODE_32, Ks

    base = 0x400000
    at = {"main": 0x1000, "helper": 0x1020, "leaf": 0x1040, "callback": 0x1060,
          "hello": 0x2000, "leafstr": 0x2008, "global": 0x2010, "iat": 0x2040}  # fmt: skip
    va = {k: base + v for k, v in at.items()}
    functions = {
        "main": ["push ebp", "mov ebp, esp", f"push {va['hello']:#x}", f"call {va['helper']:#x}",
                 f"call dword ptr [{va['iat']:#x}]", f"call {va['leaf']:#x}",
                 f"mov eax, {va['callback']:#x}", "pop ebp", "ret"],
        "helper": ["push ebp", "mov ebp, esp", f"mov eax, dword ptr [{va['global']:#x}]", "pop ebp",
                   "ret"],
        "leaf": ["xor eax, eax", f"push {va['leafstr']:#x}", "add esp, 4", "ret"],
        "callback": ["mov eax, 1", "ret"],
    }  # fmt: skip
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    code = bytearray(b"\xcc" * 0x70)
    sites = {}
    for name, lines in functions.items():
        address = at[name]
        for line in lines:
            encoded = bytes(ks.asm(line, base + address)[0])
            sites.setdefault(name, []).append(address)
            _put(code, address - 0x1000, encoded)
            address += len(encoded)
    at["main_push"] = sites["main"][2]
    at["main_call_iat"] = sites["main"][4]
    at["leaf_push"] = sites["leaf"][1]
    data = bytearray(0x100)
    _put(data, 0x00, b"hello\0")
    _put(data, 0x08, b"leaf\0")
    _put(data, 0x40, struct.pack("<II", 0x2080, 0))  # IAT
    _put(data, 0x60, struct.pack("<II", 0x2080, 0))  # lookup table
    _put(data, 0x80, b"\0\0GetTickCount\0")
    _put(data, 0xA0, b"KERNEL32.dll\0")
    _put(data, 0xC0, struct.pack("<5I", 0x2060, 0, 0, 0x20A0, 0x2040))
    image = pe(
        [(".text", bytes(code)), (".rdata", bytes(data))],
        base=base,
        entry=at["main"],
        directories={1: (0x20C0, 40), 12: (0x2040, 8)},
    )
    return image, at


MATCH_CODE = {
    "x86": {
        "main": ["push ebp", "mov ebp, esp", "call {init}", "call {leaf_a}", "call {leaf_b}",
                 "mov eax, dword ptr [{counter}]", "inc eax", "mov dword ptr [{counter}], eax",
                 "pop ebp", "ret"],
        "init": ["push ebp", "mov ebp, esp", "push {hello}", "call {report}", "add esp, 4",
                 "pop ebp", "ret"],
        "report": ["push ebp", "mov ebp, esp", "push {fail}", "push {fmt}", "add esp, 8",
                   "pop ebp", "ret"],
        "leaf_a": ["mov eax, 1", "ret"],
        "leaf_b": ["mov eax, 2", "ret"],
        "twin1": ["push ebp", "mov ebp, esp", "xor eax, eax", "pop ebp", "ret"],
        "twin2": ["push ebp", "mov ebp, esp", "xor eax, eax", "pop ebp", "ret"],
        "added": ["push ebp", "mov ebp, esp", "push {extra}", "add esp, 4", "pop ebp", "ret"],
    },
    "x64": {
        "main": ["sub rsp, 0x28", "call {init}", "call {leaf_a}", "call {leaf_b}",
                 "mov eax, dword ptr [{counter}]", "inc eax", "mov dword ptr [{counter}], eax",
                 "add rsp, 0x28", "ret"],
        "init": ["sub rsp, 0x28", "lea rcx, [{hello}]", "call {report}", "add rsp, 0x28", "ret"],
        "report": ["sub rsp, 0x28", "lea rcx, [{fmt}]", "lea rdx, [{fail}]", "add rsp, 0x28",
                   "ret"],
        "leaf_a": ["mov eax, 1", "ret"],
        "leaf_b": ["mov eax, 2", "ret"],
        "twin1": ["sub rsp, 0x28", "xor eax, eax", "nop", "add rsp, 0x28", "ret"],
        "twin2": ["sub rsp, 0x28", "xor eax, eax", "nop", "add rsp, 0x28", "ret"],
        "added": ["sub rsp, 0x28", "lea rcx, [{extra}]", "add rsp, 0x28", "ret"],
    },
}  # fmt: skip
MATCH_DATA = {"hello": b"hello there\0", "fmt": b"report %d\0", "fail": b"cannot open %s\0",
              "counter": bytes(4), "extra": b"only in the new build\0"}  # fmt: skip


def program_match(new: bool, x64: bool = False) -> tuple[bytes, dict[str, int]]:
    """One of two builds of the same small program for `pe match`, old or new: `main` calls
    `init`, `leaf_a` and `leaf_b` and counts in a global; `init` passes a string to `report`,
    which loads two more; `leaf_a` and `leaf_b` are too short to match by their code;
    `twin1` and `twin2` have the same code. The new build moves every function and string,
    adds a function and a string, and gives `report` one more instruction. Each function sits
    in a 0x40-byte slot; `at` gives RVAs. x64 code names its data RIP-relative. Assembled with
    Keystone."""
    from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks

    base = 0x140000000 if x64 else 0x400000
    code = MATCH_CODE["x64" if x64 else "x86"]
    if new:
        order = ["added", "twin2", "main", "leaf_b", "init", "report", "leaf_a", "twin1"]
        strings = ["extra", "counter", "fail", "hello", "fmt"]
    else:
        order = ["main", "init", "report", "leaf_a", "leaf_b", "twin1", "twin2"]
        strings = ["hello", "fmt", "fail", "counter"]
    at = {name: 0x1000 + 0x40 * i for i, name in enumerate(order)}
    data = bytearray()
    for name in strings:
        at[name] = 0x2000 + len(data)
        data += MATCH_DATA[name].ljust(16, b"\0")
    lines = {name: list(code[name]) for name in order}
    if new:
        lines["report"].insert(2, "xor eax, eax")
    ks = Ks(KS_ARCH_X86, KS_MODE_64 if x64 else KS_MODE_32)
    text = bytearray(b"\xcc" * (0x40 * len(order)))
    for name in order:
        address = base + at[name]
        for line in lines[name]:
            encoded = b""
            for _ in range(2):  # a RIP-relative operand's displacement needs the length first
                values = {k: v + base for k, v in at.items()}
                if x64 and "[{" in line:
                    values = {
                        k: f"rip + {v - address - len(encoded):#x}" for k, v in values.items()
                    }
                encoded = bytes(ks.asm(line.format(**values), address)[0])
            _put(text, address - base - 0x1000, encoded)
            address += len(encoded)
    image = pe([(".text", bytes(text)), (".rdata", bytes(data))], base=base, x64=x64,
               entry=at["main"])  # fmt: skip
    return image, at


def import_directory(
    dlls: dict[str, list[str]], rva: int
) -> tuple[bytes, dict[str, int], tuple[int, int]]:
    """An x86 import directory at rva: descriptors, lookup tables, IATs, names. Returns the bytes,
    each function's IAT slot RVA by `dll!name`, and the import data directory (RVA, size)."""
    count = len(dlls)
    desc_size = 20 * (count + 1)
    tables_at = rva + desc_size
    table_sizes = [4 * (len(names) + 1) for names in dlls.values()]
    names_at = tables_at + 2 * sum(table_sizes)
    blob = bytearray()
    hints: dict[str, int] = {}
    for dll, names in dlls.items():
        for name in names:
            hints[f"{dll}!{name}"] = names_at + len(blob)
            blob += b"\0\0" + name.encode() + b"\0"
            if len(blob) % 2:
                blob += b"\0"
    dll_names: dict[str, int] = {}
    for dll in dlls:
        dll_names[dll] = names_at + len(blob)
        blob += dll.encode() + b"\0"
    out = bytearray(names_at - rva) + blob
    slots: dict[str, int] = {}
    at = tables_at
    for i, (dll, names) in enumerate(dlls.items()):
        lookup, iat = at, at + table_sizes[i]
        for j, name in enumerate(names):
            entry = struct.pack("<I", hints[f"{dll}!{name}"])
            _put(out, lookup - rva + 4 * j, entry)
            _put(out, iat - rva + 4 * j, entry)
            slots[f"{dll}!{name}"] = iat + 4 * j
        _put(out, 20 * i, struct.pack("<5I", lookup, 0, 0, dll_names[dll], iat))
        at = iat + table_sizes[i]
    return bytes(out), slots, (rva, desc_size)


IID_IDIRECTINPUT8A = bytes.fromhex("3080 79bf 3a48 a24d aa99 5d64ed369700".replace(" ", ""))


def program_census() -> tuple[bytes, dict[str, int]]:
    """A small x86 program for the interface census: Direct3D 9 through a global and an
    out-parameter into a global, a function that returns the device, DirectInput 8 by its IID,
    DirectSound through a jmp thunk, PhysX 2.x by thiscall with the scene in a field of a global
    object whose methods take it as `this`, and one call through an unknown object. Returns the
    image and the VAs a test names (functions `f_*`, call sites `c_*`, globals `g_*`)."""
    base, text, rdata, bss = 0x400000, 0x1000, 0x2000, 0x3000
    dlls = {
        "d3d9.dll": ["Direct3DCreate9"],
        "DINPUT8.dll": ["DirectInput8Create"],
        "DSOUND.dll": ["DirectSoundCreate8"],
        "PhysXLoader.dll": ["NxCreatePhysicsSDK"],
    }
    imports, slots, directory = import_directory(dlls, rdata + 0x100)
    iat = {k.split("!")[1]: base + v for k, v in slots.items()}
    g = {name: base + bss + 4 * i for i, name in enumerate(
        ["g_d3d", "g_dev", "g_di", "g_kbd", "g_ds", "g_sdk", "g_world", "g_scene", "g_rend"])}  # fmt: skip
    iid = base + rdata
    at: dict[str, int] = dict(g)
    code = bytearray(b"\xcc" * 0x400)
    pos = 0

    def u32(v: int) -> bytes:
        return struct.pack("<I", v & 0xFFFFFFFF)

    def fn(name: str) -> None:
        nonlocal pos
        pos = (pos + 15) & ~15
        at[name] = base + text + pos

    def emit(data: bytes, mark: str | None = None) -> None:
        nonlocal pos
        if mark:
            at[mark] = base + text + pos
        _put(code, pos, data)
        pos += len(data)

    def call_rel(target: int, mark: str | None = None) -> None:
        emit(b"\xe8" + struct.pack("<i", target - (base + text + pos + 5)), mark)

    fn("f_d3d")
    emit(b"\x6a\x20")  # push 32
    emit(b"\xff\x15" + u32(iat["Direct3DCreate9"]), "c_create9")
    emit(b"\xa3" + u32(g["g_d3d"]))  # mov [g_d3d], eax
    emit(b"\xc3")
    fn("f_device")
    emit(b"\xa1" + u32(g["g_d3d"]))  # mov eax, [g_d3d]
    emit(b"\x68" + u32(g["g_dev"]))  # push offset g_dev: ppReturnedDeviceInterface
    emit(b"\x6a\x00" * 5)  # pp, flags, hwnd, type, adapter
    emit(b"\x8b\x08\x50")  # mov ecx, [eax]; push eax
    emit(b"\xff\x51\x40", "c_createdevice")  # call [ecx+0x40]: IDirect3D9::CreateDevice
    emit(b"\xc3")
    fn("f_getdev")
    emit(b"\xa1" + u32(g["g_dev"]) + b"\xc3")  # mov eax, [g_dev]; ret
    fn("f_query")
    call_rel(at["f_getdev"])
    emit(b"\x6a\x00\x6a\x09")  # push 0 (ppQuery); push 9 (D3DQUERYTYPE_EVENT... any)
    emit(b"\x8b\x10\x50")  # mov edx, [eax]; push eax
    emit(b"\xff\x92" + u32(0x1D8), "c_createquery")  # call [edx+0x1d8]: slot 118
    emit(b"\xc3")
    fn("f_dinput")
    emit(b"\x6a\x00\x68" + u32(g["g_di"]) + b"\x68" + u32(iid) + b"\x68" + u32(0x800) + b"\x6a\x00")
    emit(b"\xff\x15" + u32(iat["DirectInput8Create"]), "c_di8create")
    emit(b"\xa1" + u32(g["g_di"]))  # mov eax, [g_di]
    emit(b"\x6a\x00\x68" + u32(g["g_kbd"]) + b"\x6a\x00")  # punk, lplpDevice, rguid
    emit(b"\x8b\x08\x50")
    emit(b"\xff\x51\x0c", "c_dicreatedevice")  # IDirectInput8A::CreateDevice
    emit(b"\x8b\x0d" + u32(g["g_kbd"]))  # mov ecx, [g_kbd]
    emit(b"\x6a\x00\x6a\x00\x6a\x00\x8b\x01\x51")  # 3 args; mov eax, [ecx]; push ecx
    emit(b"\xff\x50\x38", "c_getobjectinfo")  # IDirectInputDevice8A::GetObjectInfo
    emit(b"\xc3")
    fn("f_thunk")
    emit(b"\xff\x25" + u32(iat["DirectSoundCreate8"]))  # jmp [DirectSoundCreate8]
    fn("f_dsound")
    emit(b"\x6a\x00\x68" + u32(g["g_ds"]) + b"\x6a\x00")
    call_rel(at["f_thunk"], "c_dscreate")
    emit(b"\x8b\x0d" + u32(g["g_ds"]) + b"\x6a\x00\x6a\x00\x6a\x00\x8b\x01\x51")
    emit(b"\xff\x50\x0c", "c_createsoundbuffer")  # IDirectSound8::CreateSoundBuffer
    emit(b"\xc3")
    fn("f_physx")
    emit(b"\x6a\x00" * 5)
    emit(b"\xff\x15" + u32(iat["NxCreatePhysicsSDK"]), "c_nxcreate")
    emit(b"\x83\xc4\x14")  # add esp, 0x14 (cdecl)
    emit(b"\xa3" + u32(g["g_sdk"]) + b"\xc3")
    fn("f_world_init")  # this: the world object
    emit(b"\x57\x8b\xf9")  # push edi; mov edi, ecx
    emit(
        b"\x8b\x0d" + u32(g["g_sdk"]) + b"\x6a\x00\x8b\x01"
    )  # mov ecx, [g_sdk]; push 0; mov eax, [ecx]
    emit(b"\xff\x50\x10", "c_createscene")  # NxPhysicsSDK::createScene
    emit(b"\x89\x47\x08\x5f\xc3")  # mov [edi+8], eax; pop edi; ret
    fn("f_world_spawn")  # this: the world object
    emit(b"\x8b\x49\x08\x6a\x00\x8b\x01")  # mov ecx, [ecx+8]; push 0; mov eax, [ecx]
    emit(b"\xff\x50\x18", "c_createactor")  # NxScene::createActor
    emit(b"\x8b\xc8\x6a\x00\x8b\x11")  # mov ecx, eax; push 0; mov edx, [ecx]
    emit(b"\xff\x52\x44", "c_createshape")  # NxActor::createShape
    emit(b"\xc3")
    fn("f_world")
    emit(b"\xb9" + u32(g["g_world"]))  # mov ecx, offset g_world
    call_rel(at["f_world_init"])
    emit(b"\xb9" + u32(g["g_world"]))
    call_rel(at["f_world_spawn"])
    emit(b"\xc3")
    fn("f_rend_init")  # the renderer in EDI (link-time code generation): the device at +0x10
    emit(b"\x55\xa1" + u32(g["g_d3d"]))  # push ebp; mov eax, [g_d3d]
    emit(b"\x8d\x6f\x10\x55")  # lea ebp, [edi+0x10]; push ebp
    emit(b"\x6a\x00" * 5 + b"\x8b\x08\x50")
    emit(b"\xff\x51\x40", "c_rend_createdevice")
    emit(b"\x5d\xc3")  # pop ebp; ret
    fn("f_rend")
    emit(b"\x57\x8b\x3d" + u32(g["g_rend"]))  # push edi; mov edi, [g_rend]
    call_rel(at["f_rend_init"])
    emit(b"\x5f\xc3")
    fn("f_rend_draw")
    emit(b"\xa1" + u32(g["g_rend"]) + b"\x8b\x48\x10")  # mov eax, [g_rend]; mov ecx, [eax+0x10]
    emit(b"\x6a\x01\x6a\x07\x8b\x11\x51")  # push 1; push 7; mov edx, [ecx]; push ecx
    emit(b"\xff\x92" + u32(0xE4), "c_setrenderstate")  # IDirect3DDevice9::SetRenderState
    emit(b"\xc3")
    vtable = base + rdata + 0x40
    fn("f_make")  # a constructor: the object's vtable, then a virtual call on it
    emit(b"\x56\x8b\x74\x24\x08")  # push esi; mov esi, [esp+8]
    emit(b"\xc7\x06" + u32(vtable))  # mov dword ptr [esi], vtable
    emit(b"\xa1" + u32(g["g_di"]) + b"\x50")  # mov eax, [g_di]; push eax
    emit(b"\x8b\x16\x8b\xce")  # mov edx, [esi]; mov ecx, esi
    emit(b"\xff\x52\x04", "c_virtual")  # call [edx+4]: slot 1, the class's own method
    emit(b"\x5e\xc2\x04\x00")
    fn("f_unknown")
    emit(b"\x8b\x44\x24\x04\x8b\x08\x50")  # mov eax, [esp+4]; mov ecx, [eax]; push eax
    emit(b"\xff\x51\x08", "c_unknown")  # call [ecx+8]: no interface known
    emit(b"\xc2\x04\x00")  # ret 4
    # the class's methods, which the function table leaves out (reached through the vtable)
    fn("v_m0")
    emit(b"\xc3")
    fn("v_m1")  # thiscall (IDirectInput8A*): the device into this+8
    emit(b"\x8b\x44\x24\x04\x56\x8b\xf1\x8d\x56\x08")  # mov eax, [esp+4]; push esi; ...
    emit(b"\x6a\x00\x52\x6a\x00\x8b\x08\x50")  # punk, lplpDevice, rguid; this
    emit(b"\xff\x51\x0c", "c_m1_createdevice")  # IDirectInput8A::CreateDevice
    emit(b"\x5e\xc2\x04\x00")
    fn("v_m2")  # thiscall: the device in this+8
    emit(b"\x8b\x49\x08\x6a\x00\x6a\x00\x6a\x00\x8b\x01\x51")
    emit(b"\xff\x50\x38", "c_m2_getobjectinfo")  # IDirectInputDevice8A::GetObjectInfo
    emit(b"\xc3")
    data = bytearray(0x100) + imports
    _put(data, 0, IID_IDIRECTINPUT8A)
    _put(data, 0x40, struct.pack("<3I", at["v_m0"], at["v_m1"], at["v_m2"]))
    image = pe(
        [(".text", bytes(code[:pos])), (".rdata", bytes(data)), (".data", bytes(0x40))],
        base=base,
        directories={1: directory},
        flags={".data": 0xC0000040},
    )
    return image, at
