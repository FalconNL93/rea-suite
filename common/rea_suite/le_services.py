"""The DOS services an LE program uses, from its code: what a host layer that runs it has to provide.

`rea-suite le services <exe> [--json]` (le.py) reads the module with le.py's one LE model, applies its
fixups at the relocation bases (le.dump_image) and decodes the executable objects with Capstone by
flow: from the entry point, every exported entry and every internal fixup target in a code object
(function pointers), following direct jumps and calls, and never across a fixup that is not an
instruction's displacement or immediate (a pointer table). Then each stretch nothing reached is
decoded the same way from its first byte past padding: functions only called through a computed
pointer, dead code, and data that happens to decode; every site says which (`found_by`: `flow` or
`gap`). A linear sweep or a byte search for `CD ??` finds `int` in data and in the middle of other
instructions; this does not.
It lists:

- every `int n` with AH/AX (and AL or BL where they pick a subfunction) set before it in its basic
  block, named from the tables below: DOS (21h), DPMI (31h), mouse (33h), video (10h) and others;
- every `in`/`out`/`ins`/`outs` with its port, an immediate or DX followed back through
  `mov`/`inc`/`dec`/`add`/`sub`;
- every segment register load: `mov sreg`, `pop sreg`, `lds`/`les`/`lfs`/`lgs`/`lss`, with the value
  where the block shows it (a constant, a copy of another segment register, an object's selector);
- far calls, jumps and returns, `iret`, and anything 16-bit: 16-bit objects, the address-size prefix
  in 32-bit code, selector and 16:16 fixups;
- a summary by service and the sites left unresolved.

A value counts only when the same basic block sets it: a register loaded from memory, passed in by a
caller or set before a branch target stays unresolved, as do wrappers such as Watcom's `int386()`
whose `int` takes AH from a structure (their callers then show what they ask for). The containing
function is the nearest direct-call target at or before the site (`function_known` false when none);
a heuristic, since LE has no function table.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_16, CS_MODE_32, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from rea_suite import le

GRP_JUMP, GRP_CALL, GRP_RET, GRP_INT, GRP_IRET = 1, 2, 3, 4, 5
SEGMENT_REGISTERS = ("ds", "es", "fs", "gs", "ss")
FAR_POINTER_LOADS = {"lds": "ds", "les": "es", "lfs": "fs", "lgs": "gs", "lss": "ss"}
STUB_TABLE = 8  # consecutive `int n; ret` stubs that make a dispatch table
MAX_BLOCK = 64  # instructions looked at backward from a site
# Register name -> (family, the bytes of the low word it writes).
PARTS = {}
for _f in "abcd":
    PARTS.update(
        {
            f"e{_f}x": (_f, ("lo", "hi")),
            f"{_f}x": (_f, ("lo", "hi")),
            f"{_f}l": (_f, ("lo",)),
            f"{_f}h": (_f, ("hi",)),
        }
    )

INTERRUPTS = {
    0x00: "divide error",
    0x03: "breakpoint",
    0x04: "overflow",
    0x05: "print screen / BOUND",
    0x08: "IRQ 0 timer",
    0x09: "IRQ 1 keyboard",
    0x10: "BIOS video",
    0x11: "BIOS equipment list",
    0x12: "BIOS memory size",
    0x13: "BIOS disk",
    0x14: "BIOS serial",
    0x15: "BIOS system services",
    0x16: "BIOS keyboard",
    0x17: "BIOS printer",
    0x19: "bootstrap",
    0x1A: "BIOS time / PCI",
    0x1C: "timer tick",
    0x20: "DOS terminate",
    0x21: "DOS",
    0x23: "DOS Ctrl-C handler",
    0x24: "DOS critical error handler",
    0x25: "DOS absolute disk read",
    0x26: "DOS absolute disk write",
    0x27: "DOS terminate and stay resident",
    0x28: "DOS idle",
    0x2F: "multiplex",
    0x31: "DPMI",
    0x33: "mouse",
    0x4B: "Virtual DMA Services",
    0x67: "EMS / VCPI",
}
DOS = {
    0x00: "terminate",
    0x01: "read character with echo",
    0x02: "write character",
    0x06: "direct console I/O",
    0x07: "direct character input",
    0x08: "character input",
    0x09: "write string",
    0x0A: "buffered input",
    0x0B: "check input status",
    0x0C: "flush buffer and read",
    0x0D: "disk reset",
    0x0E: "select drive",
    0x19: "get current drive",
    0x1A: "set DTA",
    0x25: "set interrupt vector",
    0x2A: "get date",
    0x2B: "set date",
    0x2C: "get time",
    0x2D: "set time",
    0x2F: "get DTA",
    0x30: "get DOS version",
    0x31: "terminate and stay resident",
    0x33: "Ctrl-Break check",
    0x35: "get interrupt vector",
    0x36: "get free disk space",
    0x39: "create directory",
    0x3A: "remove directory",
    0x3B: "change directory",
    0x3C: "create file",
    0x3D: "open file",
    0x3E: "close file",
    0x3F: "read file",
    0x40: "write file",
    0x41: "delete file",
    0x42: "seek",
    0x43: "file attributes",
    0x44: "IOCTL",
    0x45: "duplicate handle",
    0x46: "force duplicate handle",
    0x47: "get current directory",
    0x48: "allocate memory",
    0x49: "free memory",
    0x4A: "resize memory",
    0x4B: "execute program",
    0x4C: "exit",
    0x4D: "get return code",
    0x4E: "find first",
    0x4F: "find next",
    0x56: "rename file",
    0x57: "file date and time",
    0x58: "allocation strategy",
    0x59: "get extended error",
    0x5A: "create temporary file",
    0x5B: "create new file",
    0x62: "get PSP",
    0x67: "set handle count",
    0x68: "commit file",
    0x6C: "extended open",
}
# DPMI 0.9 functions: name and the group a host layer implements them in.
DPMI = {
    0x0000: ("allocate LDT descriptors", "descriptors"),
    0x0001: ("free LDT descriptor", "descriptors"),
    0x0002: ("segment to descriptor", "descriptors"),
    0x0003: ("get selector increment", "descriptors"),
    0x0006: ("get segment base", "descriptors"),
    0x0007: ("set segment base", "descriptors"),
    0x0008: ("set segment limit", "descriptors"),
    0x0009: ("set access rights", "descriptors"),
    0x000A: ("create alias descriptor", "descriptors"),
    0x000B: ("get descriptor", "descriptors"),
    0x000C: ("set descriptor", "descriptors"),
    0x000D: ("allocate specific descriptor", "descriptors"),
    0x0100: ("allocate DOS memory", "DOS memory"),
    0x0101: ("free DOS memory", "DOS memory"),
    0x0102: ("resize DOS memory", "DOS memory"),
    0x0200: ("get real-mode interrupt vector", "interrupt vectors"),
    0x0201: ("set real-mode interrupt vector", "interrupt vectors"),
    0x0202: ("get exception handler", "interrupt vectors"),
    0x0203: ("set exception handler", "interrupt vectors"),
    0x0204: ("get protected-mode interrupt vector", "interrupt vectors"),
    0x0205: ("set protected-mode interrupt vector", "interrupt vectors"),
    0x0300: ("simulate real-mode interrupt", "real-mode calls"),
    0x0301: ("call real-mode far procedure", "real-mode calls"),
    0x0302: ("call real-mode IRET procedure", "real-mode calls"),
    0x0303: ("allocate real-mode callback", "real-mode callbacks"),
    0x0304: ("free real-mode callback", "real-mode callbacks"),
    0x0305: ("get state save/restore addresses", "mode switching"),
    0x0306: ("get raw mode switch addresses", "mode switching"),
    0x0400: ("get DPMI version", "version"),
    0x0500: ("get free memory information", "memory"),
    0x0501: ("allocate memory block", "memory"),
    0x0502: ("free memory block", "memory"),
    0x0503: ("resize memory block", "memory"),
    0x0600: ("lock linear region", "paging"),
    0x0601: ("unlock linear region", "paging"),
    0x0602: ("mark real-mode region pageable", "paging"),
    0x0603: ("relock real-mode region", "paging"),
    0x0604: ("get page size", "paging"),
    0x0702: ("mark page as paging candidate", "paging"),
    0x0703: ("discard page contents", "paging"),
    0x0800: ("map physical address", "physical mapping"),
    0x0801: ("free physical mapping", "physical mapping"),
    0x0900: ("disable virtual interrupts", "virtual interrupts"),
    0x0901: ("enable virtual interrupts", "virtual interrupts"),
    0x0902: ("get virtual interrupt state", "virtual interrupts"),
    0x0A00: ("get vendor API entry", "vendor"),
    0x0B00: ("set debug watchpoint", "debug"),
    0x0B01: ("clear debug watchpoint", "debug"),
    0x0B02: ("get debug watchpoint state", "debug"),
    0x0B03: ("reset debug watchpoint", "debug"),
}
MOUSE = {
    0x0000: "reset",
    0x0001: "show cursor",
    0x0002: "hide cursor",
    0x0003: "get position and buttons",
    0x0004: "set position",
    0x0005: "button press data",
    0x0006: "button release data",
    0x0007: "set horizontal range",
    0x0008: "set vertical range",
    0x0009: "set graphics cursor",
    0x000A: "set text cursor",
    0x000B: "read motion counters",
    0x000C: "set event handler (callback)",
    0x000F: "set mickey ratio",
    0x0010: "conditional hide",
    0x0014: "swap event handler (callback)",
    0x0015: "get state size",
    0x0016: "save state",
    0x0017: "restore state",
    0x001A: "set sensitivity",
    0x001B: "get sensitivity",
    0x001C: "set interrupt rate",
    0x001D: "set display page",
    0x0021: "software reset",
    0x0024: "get version",
}
VIDEO = {
    0x00: "set video mode",
    0x01: "set cursor shape",
    0x02: "set cursor position",
    0x03: "get cursor position",
    0x05: "select page",
    0x06: "scroll up",
    0x07: "scroll down",
    0x08: "read character",
    0x09: "write character and attribute",
    0x0A: "write character",
    0x0B: "set palette",
    0x0C: "write pixel",
    0x0D: "read pixel",
    0x0E: "teletype output",
    0x0F: "get video mode",
    0x10: "palette registers",
    0x11: "character generator",
    0x12: "alternate select",
    0x13: "write string",
    0x1A: "display combination",
    0x1B: "functionality information",
    0x4F: "VESA BIOS extensions",
}
KEYBOARD = {
    0x00: "read key",
    0x01: "check key",
    0x02: "shift flags",
    0x10: "read extended key",
    0x11: "check extended key",
    0x12: "extended shift flags",
}
MULTIPLEX = {
    0x1600: "Windows enhanced mode check",
    0x1680: "release time slice",
    0x1686: "get CPU mode",
    0x1687: "get DPMI mode switch entry",
    0x4300: "XMS installation check",
    0x4310: "XMS driver address",
}
VDS = {
    0x8102: "get version",
    0x8103: "lock DMA region",
    0x8104: "unlock DMA region",
    0x8105: "scatter/gather lock",
    0x8106: "scatter/gather unlock",
    0x8107: "request DMA buffer",
    0x8108: "release DMA buffer",
    0x8109: "copy into DMA buffer",
    0x810A: "copy out of DMA buffer",
    0x810B: "disable DMA translation",
    0x810C: "enable DMA translation",
}
# Interrupt -> (the register that picks the function, its names).
FUNCTIONS = {
    0x21: ("ah", DOS),
    0x31: ("ax", {k: v[0] for k, v in DPMI.items()}),
    0x33: ("ax", MOUSE),
    0x10: ("ah", VIDEO),
    0x16: ("ah", KEYBOARD),
    0x2F: ("ax", MULTIPLEX),
    0x4B: ("ax", VDS),
    0x15: ("ah", {}),
    0x1A: ("ah", {}),
    0x13: ("ah", {}),
    0x14: ("ah", {}),
    0x17: ("ah", {}),
    0x67: ("ah", {}),
}
# (interrupt, function) -> the register holding its subfunction or its interrupt number.
SUBFUNCTION = {
    **{(0x21, f): "al" for f in (0x25, 0x35, 0x3D, 0x42, 0x43, 0x44, 0x4B, 0x4C, 0x57, 0x58)},
    **{(0x10, f): "al" for f in (0x00, 0x10, 0x11, 0x4F)},
    **{(0x31, f): "bl" for f in (0x0200, 0x0201, 0x0202, 0x0203, 0x0204, 0x0205, 0x0300)},
}
PORTS = [
    (0x00, 0x0F, "DMA controller 1"),
    (0x20, 0x21, "PIC 1"),
    (0x40, 0x43, "PIT timer"),
    (0x60, 0x60, "keyboard data"),
    (0x61, 0x61, "system control (speaker)"),
    (0x64, 0x64, "keyboard controller"),
    (0x70, 0x71, "CMOS / RTC"),
    (0x80, 0x8F, "DMA page registers"),
    (0xA0, 0xA1, "PIC 2"),
    (0xC0, 0xDF, "DMA controller 2"),
    (0x1F0, 0x1F7, "IDE"),
    (0x201, 0x201, "game port"),
    (0x220, 0x22F, "Sound Blaster (base 220h)"),
    (0x240, 0x24F, "Sound Blaster (base 240h)"),
    (0x2F8, 0x2FF, "COM2"),
    (0x330, 0x331, "MPU-401 MIDI"),
    (0x378, 0x37A, "LPT1"),
    (0x388, 0x38B, "AdLib / OPL"),
    (0x3B4, 0x3B5, "MDA CRTC"),
    (0x3BA, 0x3BA, "MDA status"),
    (0x3C0, 0x3C1, "VGA attribute controller"),
    (0x3C2, 0x3C2, "VGA misc output / input status 0"),
    (0x3C4, 0x3C5, "VGA sequencer"),
    (0x3C6, 0x3C6, "VGA DAC mask"),
    (0x3C7, 0x3C7, "VGA DAC read index"),
    (0x3C8, 0x3C8, "VGA DAC write index"),
    (0x3C9, 0x3C9, "VGA DAC data"),
    (0x3CC, 0x3CC, "VGA misc output read"),
    (0x3CE, 0x3CF, "VGA graphics controller"),
    (0x3D4, 0x3D5, "VGA CRTC"),
    (0x3DA, 0x3DA, "VGA input status 1"),
    (0x3F0, 0x3F7, "floppy"),
    (0x3F8, 0x3FF, "COM1"),
]
SIXTEEN_BIT_FIXUPS = (0x2, 0x3, 0x5)  # selector, 16:16 pointer, 16-bit offset
FIXUP_WIDTH = {0x0: 1, 0x2: 2, 0x3: 4, 0x5: 2, 0x6: 6, 0x7: 4, 0x8: 4}


def port_name(port: int | None) -> str | None:
    if port is None:
        return None
    return next((name for lo, hi, name in PORTS if lo <= port <= hi), None)


@dataclass
class Code:
    """The decoded code: instructions by address, the flow facts the backward walks need."""

    insns: dict  # address -> CsInsn
    previous: dict  # address -> the instruction that falls through into it
    labels: set  # addresses something branches to, or a seed
    functions: list  # sorted direct-call targets and the entry point
    fixups: dict  # site address -> le.Fixup, in code objects
    objects: dict  # object number -> (base, end, bits)
    origin: dict  # address -> "flow" or "gap", how decoding reached it

    def function(self, address: int) -> int | None:
        i = bisect.bisect_right(self.functions, address)
        return self.functions[i - 1] if i else None

    def object_of(self, address: int) -> tuple[int, int] | None:
        for number, (base, end, _) in self.objects.items():
            if base <= address < end:
                return number, address - base
        return None


def code_objects(module) -> list:
    return [o for o in module.objects if o.flags & 0x4 and o.size]


def fixup_sites(module, bases: dict[int, int]) -> dict:
    """Each fixup's source address at the given bases (the page-crossing repeat left out)."""
    page_size = module.header["page_size"]
    owner = {}
    for o in module.objects:
        for i in range(o.pages):
            owner[o.first_page + i] = (o, i)
    sites = {}
    for f in module.fixups:
        if f.page not in owner:
            continue
        o, i = owner[f.page]
        for offset in f.offsets:
            if offset >= 0:
                sites[bases[o.number] + i * page_size + offset] = f
    return sites


def seeds(module, bases: dict[int, int], objects: list) -> set[int]:
    """Where decoding starts: the entry point, exported entries and internal fixup targets that lie
    in a code object."""
    numbers = {o.number for o in objects}
    out = set()
    entry = module.entry_point()
    if entry and entry["object"] in numbers:
        out.add(bases[entry["object"]] + entry["offset"])
    for obj, offset in module.entries.values():
        if obj in numbers:
            out.add(bases[obj] + offset)
    for f in module.fixups:
        target = None
        if f.target == 0 and f.source != 0x2:
            target = (f.object, f.offset)
        elif f.target == 3:
            target = module.entries.get(f.entry)
        if target and target[0] in numbers:
            out.add(bases[target[0]] + target[1])
    return out


def is_transfer(insn) -> bool:
    return any(g in insn.groups for g in (GRP_JUMP, GRP_CALL, GRP_RET, GRP_INT, GRP_IRET))


def direct_target(insn) -> int | None:
    if insn.mnemonic in ("ljmp", "lcall"):
        return None
    ops = insn.operands
    if len(ops) == 1 and ops[0].type == X86_OP_IMM:
        return ops[0].imm & 0xFFFFFFFF
    return None


def decode(module) -> Code:
    """Recursive descent over the code objects of the module loaded at its relocation bases: first
    from the seeds (`flow`), then from the start of each stretch nothing reached (`gap`: functions
    only called through a computed pointer, or dead code; also data such a start lands on), until
    no stretch is left that decodes."""
    image = le.dump_image(module)
    objects = code_objects(module)
    spans = {
        o.number: (image.bases[o.number], image.bases[o.number] + o.size, o.bits) for o in objects
    }
    engines = {}
    for bits in (16, 32):
        cs = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_16)
        cs.detail = True
        engines[bits] = cs
    fixups = fixup_sites(module, image.bases)
    start = seeds(module, image.bases, objects)
    code = Code({}, {}, set(start), [], fixups, spans, {})
    calls: set[int] = set()
    covered = bytearray(len(image.data))  # 1 where a decoded instruction lies

    def walk(work: list[int], origin: str) -> None:
        while work:
            address = work.pop()
            while address not in code.insns:
                span = next((s for s in spans.values() if s[0] <= address < s[1]), None)
                if span is None:
                    break
                at = address - image.base
                try:
                    chunk = bytes(image.data[at : min(at + 16, span[1] - image.base)])
                    insn = next(engines[span[2]].disasm(chunk, address, 1), None)
                except CsError:
                    insn = None
                if insn is None or not fixups_fit(insn, fixups):
                    break
                code.insns[address] = insn
                code.origin[address] = origin
                covered[at : at + insn.size] = b"\1" * insn.size
                jumps = GRP_JUMP in insn.groups or GRP_CALL in insn.groups
                target = direct_target(insn) if jumps else None
                if target is not None:
                    code.labels.add(target)
                    if GRP_CALL in insn.groups:
                        calls.add(target)
                    if target not in code.insns:
                        work.append(target)
                if ends_flow(insn):
                    break
                following = address + insn.size
                code.previous.setdefault(following, insn)  # flow, decoded first, wins
                if GRP_JUMP in insn.groups:  # conditional: the next instruction starts a block
                    code.labels.add(following)
                address = following

    walk(sorted(start, reverse=True), "flow")
    gap_starts: set[int] = set()
    for base, end, _ in spans.values():
        p, stop = base - image.base, end - image.base
        while p < stop:
            if covered[p]:
                p = covered.find(0, p, stop)
                p = stop if p < 0 else p
                continue
            if image.data[p] in PADDING:
                p += 1
                continue
            address = image.base + p
            code.labels.add(address)
            walk([address], "gap")
            if address in code.insns:
                gap_starts.add(address)
            elif (end := pointer_end(fixups, address)) is not None:  # a pointer: step over it
                p = end - image.base
            else:  # not code: skip to what is
                p = covered.find(1, p, stop)
                p = stop if p < 0 else p
    entry = module.entry_point()
    functions = calls | gap_starts
    if entry and entry["object"] in spans:
        functions.add(image.bases[entry["object"]] + entry["offset"])
    code.functions = sorted(functions)
    return code


PADDING = (0x00, 0x90)  # Watcom pads with nops; int3 (0xCC) is decoded


def pointer_end(fixups: dict, address: int) -> int | None:
    """The end of the fixup that covers `address`, if one does."""
    for at in range(address - 5, address + 1):
        f = fixups.get(at)
        if f is not None and at + FIXUP_WIDTH[f.source] > address:
            return at + FIXUP_WIDTH[f.source]
    return None


def fixups_fit(insn, fixups: dict) -> bool:
    """False when a fixup overlaps the instruction other than as its whole displacement or
    immediate: the bytes are a pointer (a jump table, a function table) rather than code. A fixup
    target in a code object is often such a table, and this keeps the decoder out of it."""
    start, end = insn.address, insn.address + insn.size
    fields = {start + o for o in (insn.disp_offset, insn.imm_offset) if o}
    for at in range(start - 5, end):
        f = fixups.get(at)
        if f is None or at + FIXUP_WIDTH[f.source] <= start:
            continue
        if at not in fields or at + FIXUP_WIDTH[f.source] > end:
            return False
    return True


def ends_flow(insn) -> bool:
    if GRP_RET in insn.groups or GRP_IRET in insn.groups:
        return True
    return insn.mnemonic in ("jmp", "ljmp", "hlt", "ud2")


def block_before(code: Code, insn):
    """The instructions before `insn` in its basic block, nearest first."""
    address, n = insn.address, 0
    while address not in code.labels and n < MAX_BLOCK:
        p = code.previous.get(address)
        if p is None or is_transfer(p):
            return
        yield p
        address, n = p.address, n + 1


def written(insn) -> set[str]:
    try:
        _, writes = insn.regs_access()
    except CsError:
        return set(PARTS)  # unknown: assume it clobbers everything
    return {insn.reg_name(r) for r in writes}


def constant_byte(insn, reg: str, part: str) -> int | None:
    """The byte `part` of `reg` that `insn` sets, when it is a constant."""
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != X86_OP_REG:
        return None
    dest = insn.reg_name(ops[0].reg)
    if insn.mnemonic in ("xor", "sub") and ops[1].type == X86_OP_REG and ops[1].reg == ops[0].reg:
        return 0
    if insn.mnemonic != "mov" or ops[1].type != X86_OP_IMM or dest != reg:
        return None
    value = ops[1].imm
    if PARTS[dest][1] == ("hi",):
        return value & 0xFF
    return value & 0xFF if part == "lo" else (value >> 8) & 0xFF


def resolve_bytes(code: Code, insn, family: str) -> dict[str, int | None]:
    """The low word of register `family` (a, b, c, d) as `insn` sees it, byte by byte: a constant,
    or None when set otherwise or not set in the block."""
    out: dict[str, int | None] = {}
    for p in block_before(code, insn):
        for reg in written(p):
            if reg not in PARTS or PARTS[reg][0] != family:
                continue
            for part in PARTS[reg][1]:
                if part not in out:
                    out[part] = constant_byte(p, reg, part)
        if "lo" in out and "hi" in out:
            break
    return {"lo": out.get("lo"), "hi": out.get("hi")}


def resolve_dx(code: Code, insn) -> int | None:
    """DX as `insn` sees it, following inc, dec, add and sub back to the mov that set it."""
    delta = 0
    for p in block_before(code, insn):
        regs = {r for r in written(p) if r in PARTS and PARTS[r][0] == "d"}
        if not regs:
            continue
        ops = p.operands
        dest = p.reg_name(ops[0].reg) if ops and ops[0].type == X86_OP_REG else None
        if dest not in ("dx", "edx"):
            return None
        if p.mnemonic == "inc":
            delta += 1
        elif p.mnemonic == "dec":
            delta -= 1
        elif p.mnemonic in ("add", "sub") and len(ops) == 2 and ops[1].type == X86_OP_IMM:
            delta += ops[1].imm if p.mnemonic == "add" else -ops[1].imm
        elif p.mnemonic == "mov" and len(ops) == 2 and ops[1].type == X86_OP_IMM:
            return (ops[1].imm + delta) & 0xFFFF
        else:
            return None
    return None


def fixup_in(code: Code, insn):
    return next(
        (code.fixups[a] for a in range(insn.address, insn.address + insn.size) if a in code.fixups),
        None,
    )


def segment_source(code: Code, insn) -> tuple[str, str | None]:
    """What a segment register load takes, and its value where the block shows it."""
    if insn.mnemonic in FAR_POINTER_LOADS:
        return "far pointer in memory", None
    if insn.mnemonic == "pop":
        # The push that put it there: the nearest instruction before it in the block that moves ESP.
        for p in block_before(code, insn):
            moves = p.mnemonic.startswith(("push", "pop")) or p.mnemonic in ("enter", "leave")
            if not moves and not {"esp", "sp"} & written(p):
                continue
            if p.mnemonic == "push" and p.operands[0].type == X86_OP_REG:
                name = p.reg_name(p.operands[0].reg)
                if name in SEGMENT_REGISTERS or name == "cs":
                    return "stack", f"copy of {name}"
            if p.mnemonic == "push" and p.operands[0].type == X86_OP_IMM:
                return "stack", f"0x{p.operands[0].imm & 0xFFFF:04x}"
            break
        return "stack", None
    src = insn.operands[1]
    if src.type == X86_OP_MEM:
        return "memory", None
    name = insn.reg_name(src.reg)
    if name not in PARTS:
        return name, None
    for p in block_before(code, insn):
        regs = {r for r in written(p) if r in PARTS and PARTS[r][0] == PARTS[name][0]}
        if not regs:
            continue
        ops = p.operands
        if p.mnemonic == "mov" and len(ops) == 2:
            if ops[1].type == X86_OP_REG and p.reg_name(ops[1].reg) in (*SEGMENT_REGISTERS, "cs"):
                return name, f"copy of {p.reg_name(ops[1].reg)}"
            if ops[1].type == X86_OP_IMM:
                f = fixup_in(code, p)
                if f is not None and f.source == 0x2 and f.target == 0:
                    return name, f"selector of object {f.object}"
                return name, f"0x{ops[1].imm & 0xFFFF:04x}"
        return name, None
    return name, None


def far_kind(insn) -> str | None:
    """Far transfers by opcode: Capstone spells an indirect far call `call ptr [...]`."""
    op = insn.opcode[0]
    reg = (insn.modrm >> 3) & 7
    if op == 0x9A or (op == 0xFF and reg == 3):
        return "far call"
    if op == 0xEA or (op == 0xFF and reg == 5):
        return "far jump"
    if op in (0xCA, 0xCB):
        return "far return"
    if op == 0xCF:
        return "iret"
    return None


def site(code: Code, insn) -> dict:
    where = code.object_of(insn.address)
    function = code.function(insn.address)
    return {
        "address": insn.address,
        "object": where[0] if where else None,
        "offset": where[1] if where else None,
        "function": function,
        "function_known": function is not None,
        "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
        "found_by": code.origin[insn.address],
    }


def hexbyte(value: int | None) -> str:
    return "??" if value is None else f"{value:02X}"


def interrupt(code: Code, insn) -> dict:
    n = {"int3": 3, "into": 4}.get(insn.mnemonic) or insn.bytes[1]
    a, b = resolve_bytes(code, insn, "a"), resolve_bytes(code, insn, "b")
    registers = {"ah": a["hi"], "al": a["lo"], "bh": b["hi"], "bl": b["lo"]}
    d = {
        **site(code, insn),
        "interrupt": n,
        "interrupt_name": INTERRUPTS.get(n),
        "registers": registers,
        "function_register": None,
        "service_function": None,
        "subfunction_register": None,
        "subfunction": None,
        "service": None,
        "group": None,
        "resolved": True,
    }
    if n not in FUNCTIONS:
        d["service"] = INTERRUPTS.get(n)
        return d
    reg, names = FUNCTIONS[n]
    d["function_register"] = reg
    value = a["hi"] if reg == "ah" else None
    if reg == "ax" and a["hi"] is not None and a["lo"] is not None:
        value = a["hi"] << 8 | a["lo"]
    if value is None:
        d["resolved"] = False
        return d
    d["service_function"] = value
    d["service"] = names.get(value)
    if n == 0x31:
        d["group"] = DPMI.get(value, (None, None))[1]
    sub = SUBFUNCTION.get((n, value))
    if sub:
        d["subfunction_register"] = sub
        d["subfunction"] = registers[sub]
    return d


def port_io(code: Code, insn) -> dict:
    m = insn.mnemonic
    direction = "in" if m.startswith("in") else "out"
    ops = insn.operands
    port, via = None, "dx"
    if m in ("in", "out"):
        p = ops[1] if m == "in" else ops[0]
        data = ops[0] if m == "in" else ops[1]
        width = data.size * 8
        if p.type == X86_OP_IMM:
            port, via = p.imm & 0xFF, "immediate"
    else:
        width = {"b": 8, "w": 16, "d": 32}.get(m[-1], 0)
    if via == "dx":
        port = resolve_dx(code, insn)
    return {
        **site(code, insn),
        "direction": direction,
        "width": width,
        "via": via,
        "port": port,
        "port_name": port_name(port),
        "resolved": port is not None,
    }


def segment_load(code: Code, insn) -> dict:
    if insn.mnemonic in FAR_POINTER_LOADS:
        register = FAR_POINTER_LOADS[insn.mnemonic]
    else:
        register = insn.reg_name(insn.operands[0].reg)
    source, value = segment_source(code, insn)
    return {
        **site(code, insn),
        "register": register,
        "source": source,
        "value": value,
        "resolved": value is not None,
    }


def is_segment_load(insn) -> bool:
    m, ops = insn.mnemonic, insn.operands
    if m in FAR_POINTER_LOADS:
        return True
    if m in ("mov", "pop") and ops and ops[0].type == X86_OP_REG:
        return insn.reg_name(ops[0].reg) in SEGMENT_REGISTERS
    return False


def count(table: dict, key) -> None:
    table[key] = table.get(key, 0) + 1


def service_key(d: dict) -> str:
    n = d["interrupt"]
    text = f"INT {n:02X}h"
    if d["function_register"]:
        width = 4 if d["function_register"] == "ax" else 2
        text += f" {d['function_register'].upper()}=" + (
            f"{d['service_function']:0{width}X}h" if d["service_function"] is not None else "?"
        )
    if d["subfunction_register"]:
        text += f" {d['subfunction_register'].upper()}={hexbyte(d['subfunction'])}h"
    return text


def is_stub(code: Code, address: int) -> int | None:
    """The interrupt number when the three bytes at `address` are `int n; ret` (or `int3; nop;
    ret`, as INT 3 is one byte shorter)."""
    insn = code.insns.get(address)
    if insn is None or insn.bytes[0] not in (0xCC, 0xCD):
        return None
    n = 3 if insn.bytes[0] == 0xCC else insn.bytes[1]
    at = address + insn.size
    while at < address + 2 and (pad := code.insns.get(at)) is not None and pad.mnemonic == "nop":
        at += pad.size
    ret = code.insns.get(at)
    if at != address + 2 or ret is None or ret.mnemonic != "ret" or ret.operands:
        return None
    return n


def stub_tables(code: Code) -> list[dict]:
    """Runs of `int n; ret` stubs for consecutive n: a dispatch table that code calls at
    base + 3 * n (Watcom's int386() in some runtimes), so the interrupt is picked at run time and
    every one of them is listed once here rather than as a site each."""
    tables = []
    for address in sorted(code.insns):
        n = is_stub(code, address)
        if n is None or (tables and address < tables[-1]["end"]):
            continue
        run, at = [], address
        while (m := is_stub(code, at)) is not None and m == n + len(run):
            run.append(at)
            at += 3
        if len(run) >= STUB_TABLE:
            tables.append(
                {
                    **site(code, code.insns[address]),
                    "end": at,
                    "first": n,
                    "last": n + len(run) - 1,
                    "sites": run,
                }
            )
    return tables


def inventory(module) -> dict:
    code = decode(module)
    interrupts, ports, loads, far, prefixed = [], [], [], [], []
    tables = stub_tables(code)
    in_tables = {a for t in tables for a in t.pop("sites")}
    for address in sorted(code.insns):
        insn = code.insns[address]
        m = insn.mnemonic
        if address in in_tables:
            continue
        if m in ("int", "int3", "into"):
            interrupts.append(interrupt(code, insn))
        elif m in ("in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd"):
            ports.append(port_io(code, insn))
        elif is_segment_load(insn):
            loads.append(segment_load(code, insn))
        kind = far_kind(insn)
        if kind:
            far.append({**site(code, insn), "kind": kind})
        if 0x67 in insn.prefix and code.objects[code.object_of(address)[0]][2] == 32:
            prefixed.append(site(code, insn))
    objects = code_objects(module)
    covered = sum(i.size for i in code.insns.values())
    sixteen_fixups: dict[str, int] = {}
    for f in code.fixups.values():
        if f.source in SIXTEEN_BIT_FIXUPS:
            count(sixteen_fixups, f.kind)
    return {
        "file": str(module.path),
        "code_objects": [
            {"number": o.number, "base": o.base, "size": o.size, "bits": o.bits} for o in objects
        ],
        "decoded": {
            "instructions": len(code.insns),
            "bytes": covered,
            "of": sum(o.size for o in objects),
            "functions": len(code.functions),
            "from_gaps": sum(o == "gap" for o in code.origin.values()),
        },
        "interrupts": interrupts,
        "interrupt_tables": tables,
        "ports": ports,
        "segment_loads": loads,
        "far_transfers": far,
        "sixteen_bit": {
            "objects": [o.number for o in objects if o.bits == 16],
            "address_size_prefix": prefixed,
            "fixups_in_code": dict(sorted(sixteen_fixups.items())),
        },
        "summary": {
            **summarize(interrupts, ports, loads, far),
            "interrupt_tables": [
                f"0x{t['address']:08x}: INT {t['first']:02X}h-{t['last']:02X}h" for t in tables
            ],
        },
    }


def summarize(interrupts, ports, loads, far) -> dict:
    services: dict[str, dict] = {}
    for d in interrupts:
        key = service_key(d)
        entry = services.setdefault(
            key,
            {
                "key": key,
                "interrupt": d["interrupt"],
                "service": d["service"],
                "group": d["group"],
                "sites": 0,
            },
        )
        entry["sites"] += 1
    by_port: dict[str, dict] = {}
    for d in ports:
        key = "?" if d["port"] is None else f"{d['port']:04X}h"
        e = by_port.setdefault(key, {"port": d["port"], "name": d["port_name"], "in": 0, "out": 0})
        e[d["direction"]] += 1
    registers: dict[str, dict] = {}
    for d in loads:
        e = registers.setdefault(d["register"], {"sites": 0, "values": {}})
        e["sites"] += 1
        count(e["values"], d["value"] or f"? ({d['source']})")
    groups: dict[str, int] = {}
    for d in interrupts:
        if d["group"]:
            count(groups, d["group"])
    far_kinds: dict[str, int] = {}
    for d in far:
        count(far_kinds, d["kind"])
    return {
        "services": sorted(services.values(), key=lambda e: e["key"]),
        "dpmi_groups": dict(sorted(groups.items())),
        "ports": [by_port[k] for k in sorted(by_port)],
        "segment_loads": dict(sorted(registers.items())),
        "far_transfers": far_kinds,
        "unresolved": {
            "interrupts": sum(not d["resolved"] for d in interrupts),
            "ports": sum(not d["resolved"] for d in ports),
            "segment_loads": sum(not d["resolved"] for d in loads),
        },
    }


def where(d: dict) -> str:
    function = f"in 0x{d['function']:08x}" if d["function_known"] else "in ?"
    gap = "gap " if d["found_by"] == "gap" else "    "
    return f"0x{d['address']:08x} {gap} {function:13} {d['instruction']:34}"


def print_inventory(d: dict) -> None:
    print(d["file"])
    dec = d["decoded"]
    print(
        f"decoded     {dec['instructions']} instructions, {dec['bytes']} of {dec['of']} code bytes, "
        f"{dec['functions']} functions; {dec['from_gaps']} instructions from gaps (marked gap), "
        "the rest by flow from the entry point, entries and fixup targets"
    )
    print(f"\ninterrupts  {len(d['interrupts'])}")
    for i in d["interrupts"]:
        mark = "" if i["resolved"] else "  UNRESOLVED"
        print(f"  {where(i)} {service_key(i)} {i['service'] or ''}{mark}".rstrip())
    for t in d["interrupt_tables"]:
        print(
            f"  {where(t)} table of 'int n; ret' stubs, INT {t['first']:02X}h-{t['last']:02X}h "
            f"to 0x{t['end']:08x}: the interrupt is chosen at run time"
        )
    print(f"\nports       {len(d['ports'])}")
    for p in d["ports"]:
        port = "?" if p["port"] is None else f"{p['port']:04X}h"
        mark = "" if p["resolved"] else "  UNRESOLVED"
        print(f"  {where(p)} {p['direction']:3} {port} {p['port_name'] or ''}{mark}".rstrip())
    print(f"\nsegment loads {len(d['segment_loads'])}")
    for s in d["segment_loads"]:
        print(f"  {where(s)} {s['register']} <- {s['value'] or '? (' + s['source'] + ')'}")
    print(f"\nfar transfers {len(d['far_transfers'])}")
    for f in d["far_transfers"]:
        print(f"  {where(f)} {f['kind']}")
    six = d["sixteen_bit"]
    print("\n16-bit")
    print(f"  16-bit code objects     {six['objects'] or 'none'}")
    print(f"  address-size prefix     {len(six['address_size_prefix'])} sites in 32-bit code")
    for s in six["address_size_prefix"]:
        print(f"    {where(s)}")
    for kind, n in six["fixups_in_code"].items():
        print(f"  fixups in code          {n} {kind}")
    print_summary(d["summary"])


def print_summary(s: dict) -> None:
    print("\nsummary: services")
    for e in s["services"]:
        print(f"  {e['sites']:5}  {e['key']:26} {e['service'] or ''}".rstrip())
    for t in s["interrupt_tables"]:
        print(f"  table  {t} stubs, chosen at run time")
    if s["dpmi_groups"]:
        print("summary: DPMI by group")
        for group, n in s["dpmi_groups"].items():
            print(f"  {n:5}  {group}")
    print("summary: ports")
    for e in s["ports"]:
        port = "?" if e["port"] is None else f"{e['port']:04X}h"
        print(f"  in {e['in']:4}  out {e['out']:4}  {port:6} {e['name'] or ''}".rstrip())
    print("summary: segment loads")
    for reg, e in s["segment_loads"].items():
        values = ", ".join(
            f"{v} x{n}" for v, n in sorted(e["values"].items(), key=lambda kv: -kv[1])
        )
        print(f"  {e['sites']:5}  {reg}: {values}")
    print("summary: far transfers")
    for kind, n in s["far_transfers"].items():
        print(f"  {n:5}  {kind}")
    u = s["unresolved"]
    print(
        f"unresolved  {u['interrupts']} interrupts, {u['ports']} ports, "
        f"{u['segment_loads']} segment loads"
    )
