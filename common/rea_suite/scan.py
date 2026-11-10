"""Code scans over a PE image without a disassembler project: what references an address, who
calls a function, which strings a code range loads. x64 and x86.

Whole-image scans look for the bytes an instruction would have and confirm every candidate by
decoding it with Capstone: RIP-relative operands (x64) and absolute addresses (x86) for
references, rel32 `call`/`jmp` for callers. A linear scan finds instructions in code that is
reachable or not, and misses references computed at run time (a register plus an offset, a
table); it complements a decompiler's cross-references, it does not replace them.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP

from .pemodel import Image

RIP_MODRM = re.compile(rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
REL32 = re.compile(rb"[\xe8\xe9]")


@dataclass
class Site:
    """One instruction at rva; function is the containing function's start (x64 unwind table)."""

    rva: int
    text: str
    target: int
    function: int | None = None

    def as_json(self, image: Image) -> dict:
        return {
            "rva": f"{self.rva:#x}",
            "va": f"{image.va(self.rva):#x}",
            "instruction": self.text,
            "target": f"{self.target:#x}",
            "function": None if self.function is None else f"{self.function:#x}",
        }


def disassembler(image: Image) -> Cs:
    cs = Cs(CS_ARCH_X86, CS_MODE_64 if image.x64 else CS_MODE_32)
    cs.detail = True
    return cs


def references(insn, x64: bool) -> list[int]:
    """The VAs an instruction names: RIP-relative memory (x64), absolute memory and immediates
    (x86; on x64 an immediate as wide as an address is rare and left out)."""
    found = []
    try:
        operands = insn.operands
    except CsError:
        return found
    for op in operands:
        if op.type == X86_OP_MEM:
            if op.mem.base == X86_REG_RIP:
                found.append(insn.address + insn.size + op.mem.disp)
            elif not x64 and op.mem.base == X86_REG_INVALID and op.mem.index == X86_REG_INVALID:
                found.append(op.mem.disp & 0xFFFFFFFF)
        elif op.type == X86_OP_IMM and not x64:
            found.append(op.imm & 0xFFFFFFFF)
    return found


def decode(image: Image, cs: Cs, rva: int, max_size: int = 15):
    try:
        code = image.read(rva, max_size)
    except ValueError:
        try:
            code = image.read(rva, 1)
            section = image.section_at(rva)
            code = image.read(rva, min(max_size, section.rva + section.raw_size - rva))
        except (ValueError, AttributeError):
            return None
    return next(cs.disasm(code, image.va(rva), 1), None)


def text(insn) -> str:
    return f"{insn.mnemonic} {insn.op_str}".strip()


def site(image: Image, rva: int, insn, target: int) -> Site:
    function = image.function_at(rva)
    return Site(rva, text(insn), target, function[0] if function else None)


def refs(image: Image, target: int) -> list[Site]:
    """Instructions whose operand names target (an RVA): x64 RIP-relative, x86 absolute."""
    cs = disassembler(image)
    va = image.va(target)
    found: dict[int, Site] = {}
    for section in image.code_sections():
        data = image.section_bytes(section)
        if image.x64:
            for match in RIP_MODRM.finditer(data):
                at = match.start()
                if at + 5 > len(data):
                    break
                disp = struct.unpack_from("<i", data, at + 1)[0]
                after = section.rva + at + 5
                if target - disp - after not in (0, 1, 2, 4):  # immediate bytes after disp32
                    continue
                confirm(image, cs, section.rva + at, after, va, found, back=4)
        else:
            needle = struct.pack("<I", va & 0xFFFFFFFF)
            at = data.find(needle)
            while at >= 0:
                confirm(image, cs, section.rva + at, section.rva + at + 4, va, found, back=3)
                at = data.find(needle, at + 1)
    return sorted(found.values(), key=lambda s: s.rva)


def confirm(image: Image, cs: Cs, anchor: int, after: int, va: int, found: dict, back: int) -> None:
    """Decode from up to `back` bytes before anchor (the ModRM or the address bytes); keep the
    longest instruction that spans the address bytes and names va."""
    for start in range(anchor - back, anchor):
        insn = decode(image, cs, start)
        if insn is None or start + insn.size < after or start + insn.size > after + 4:
            continue
        if va in references(insn, image.x64):
            found.setdefault(start, site(image, start, insn, image.rva(va)))
            return


def callers(image: Image, function: int, jumps: bool = True) -> list[Site]:
    """E8 calls (and E9 jumps: tail calls, thunks) to function, by byte scan."""
    cs = disassembler(image)
    result = []
    for section in image.code_sections():
        data = image.section_bytes(section)
        for match in REL32.finditer(data):
            at = match.start()
            if at + 5 > len(data) or (data[at] == 0xE9 and not jumps):
                continue
            if section.rva + at + 5 + struct.unpack_from("<i", data, at + 1)[0] != function:
                continue
            insn = decode(image, cs, section.rva + at)
            if insn is not None and insn.size == 5:
                result.append(site(image, section.rva + at, insn, function))
    return result


def string_at(image: Image, rva: int, min_length: int = 4) -> tuple[str, str] | None:
    """A printable ASCII or UTF-16LE string starting at rva: (encoding, text)."""
    try:
        section = image.section_at(rva)
        if section is None:
            return None
        raw = image.read(rva, min(1024, section.rva + section.raw_size - rva))
    except ValueError:
        return None
    end = raw.find(b"\0")
    if end >= min_length and all(32 <= c < 127 or c in (9, 10, 13) for c in raw[:end]):
        return "ascii", raw[:end].decode("ascii")
    wide = re.match(rb"((?:[\x20-\x7e\t\r\n]\0)+)\0\0", raw)
    if wide and len(wide.group(1)) // 2 >= min_length:
        return "utf16", wide.group(1).decode("utf-16-le")
    return None


def instructions(image: Image, start: int, size: int):
    """Linear disassembly of [start, start+size); undecodable bytes are skipped one at a time."""
    cs = disassembler(image)
    code = image.read(start, size)
    at = 0
    while at < len(code):
        decoded = False
        for insn in cs.disasm(code[at:], image.va(start + at)):
            decoded = True
            at = insn.address - image.base - start + insn.size
            yield insn
        if not decoded:
            at += 1


def strings_in(image: Image, start: int, size: int, min_length: int = 4) -> list[dict]:
    """The strings the code in a range loads: instruction, string address, encoding, text."""
    result = []
    for insn in instructions(image, start, size):
        for va in references(insn, image.x64):
            found = string_at(image, va - image.base, min_length)
            if found:
                rva = insn.address - image.base
                result.append(
                    {
                        "rva": f"{rva:#x}",
                        "instruction": text(insn),
                        "string": f"{va - image.base:#x}",
                        "encoding": found[0],
                        "text": found[1],
                    }
                )
    return result


def find_string(image: Image, value: str) -> list[int]:
    """RVAs where value is stored as a whole NUL-terminated ASCII or UTF-16LE string."""
    found = []
    for needle in (value.encode("ascii") + b"\0", value.encode("utf-16-le") + b"\0\0"):
        for section in image.sections:
            data = image.section_bytes(section)
            at = data.find(needle)
            while at >= 0:
                before = data[at - 1] if at else 0
                # whole string: the byte before ends another string (or the section starts)
                if before == 0:
                    found.append(section.rva + at)
                at = data.find(needle, at + 1)
    return sorted(set(found))


# Indirect transfers through a pointer slot: (pattern, kind, length of the instruction before
# the address bytes). x64 addresses are RIP-relative disp32, x86 ones absolute.
SLOT_PATTERNS = {
    True: [
        (re.compile(rb"\xff\x15"), "call", 2),
        (re.compile(rb"\xff\x25"), "jmp", 2),
        (re.compile(rb"[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]"), "load", 3),
    ],
    False: [
        (re.compile(rb"\xff\x15"), "call", 2),
        (re.compile(rb"\xff\x25"), "jmp", 2),
        (re.compile(rb"\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]"), "load", 2),
        (re.compile(rb"\xa1"), "load", 1),
    ],
}


def slot_sites(image: Image, slots: set[int]) -> list[tuple[int, str, int]]:
    """(instruction RVA, kind, slot) for every call, jmp or load through one of the slots."""
    found = []
    for section in image.code_sections():
        data = image.section_bytes(section)
        for pattern, kind, head in SLOT_PATTERNS[image.x64]:
            for match in pattern.finditer(data):
                at = match.start()
                if at + head + 4 > len(data):
                    break
                value = struct.unpack_from("<i" if image.x64 else "<I", data, at + head)[0]
                end = section.rva + at + head + 4
                slot = end + value if image.x64 else value - image.base
                if slot in slots:
                    # a REX.W before ff 15 / ff 25 belongs to the instruction
                    start = (
                        at - 1
                        if image.x64 and kind != "load" and at and data[at - 1] == 0x48
                        else at
                    )
                    found.append((section.rva + start, kind, slot))
    return sorted(set(found))


def rel32_sites(image: Image, targets: set[int]) -> dict[int, list[int]]:
    """E8 calls and E9 jumps to any of targets, in one pass: target -> [site RVAs]."""
    result: dict[int, list[int]] = {}
    for section in image.code_sections():
        data = image.section_bytes(section)
        for match in REL32.finditer(data):
            at = match.start()
            if at + 5 > len(data):
                break
            target = section.rva + at + 5 + struct.unpack_from("<i", data, at + 1)[0]
            if target in targets:
                result.setdefault(target, []).append(section.rva + at)
    return result


def import_calls(image: Image, dll: str | None = None, name: str | None = None) -> list[dict]:
    """Every site that uses an imported function: calls, jumps and loads through its IAT slot,
    and rel32 calls to a `jmp [slot]` thunk; with the functions they lie in. Filter by DLL and
    function name (case-insensitive)."""
    wanted = [
        row
        for row in image.imports
        if (dll is None or row.dll.lower() == dll.lower())
        and (name is None or (row.name or "").lower() == name.lower())
    ]
    slots = {row.slot: row for row in wanted}
    sites = slot_sites(image, set(slots))
    thunks = {rva: slot for rva, kind, slot in sites if kind == "jmp"}
    via = rel32_sites(image, set(thunks)) if thunks else {}
    cs = disassembler(image)
    by_slot: dict[int, list[dict]] = {}

    def add(rva: int, kind: str, slot: int, thunk: int | None = None) -> None:
        insn = decode(image, cs, rva)
        function = image.function_at(rva)
        by_slot.setdefault(slot, []).append(
            {
                "rva": f"{rva:#x}",
                "kind": kind,
                "instruction": text(insn) if insn else "?",
                "function": f"{function[0]:#x}" if function else None,
                **({"thunk": f"{thunk:#x}"} if thunk is not None else {}),
            }
        )

    for rva, kind, slot in sites:
        add(rva, kind, slot)
    for thunk, callers_ in via.items():
        for rva in callers_:
            add(rva, "via-thunk", thunks[thunk], thunk)
    result = []
    for row in wanted:
        uses = sorted(by_slot.get(row.slot, []), key=lambda u: int(u["rva"], 16))
        result.append(
            {
                "import": row.label,
                "dll": row.dll,
                "name": row.name,
                "ordinal": row.ordinal,
                "slot": f"{row.slot:#x}",
                "delay": row.delay,
                "sites": uses,
                "functions": sorted({u["function"] for u in uses if u["function"]}),
            }
        )
    return result
