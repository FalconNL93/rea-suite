"""Cross-build function matching: the functions and data of a known PE found in a later build of
the same code (`rea-suite pe match`). x86 and x64.

Each side's functions come from its function map (pefunctions: `--functions` tables or a
control-flow export with body ranges, else the unwind table or the heuristic). Then:

1. every function becomes a sequence of normalized instructions: the mnemonic and operands, an
   operand that is an address inside the image replaced by `A` (on x64 a RIP-relative one too),
   so a function that moved, or whose globals moved, reads the same. A sequence of four
   instructions or more that occurs exactly once in each binary is a match (`same code`);
2. a function whose set of referenced strings (four printable characters or more) occurs
   exactly once in each binary is a match (`same strings`): it survives code that changed
   around the same messages;
3. propagation, until nothing new: a matched pair of the same length, or matched by its
   strings, pairs its direct call targets in order when both have as many (`called from`); a
   pair of the same length pairs its data addresses in order, and each old data address takes
   the new one most of its pairs voted for (a split vote is marked uncertain).

Matches are candidates: a function matched by its strings or its callers can be a sibling of
the right one. Check one before relying on it. The method is a port's `funcmatch.py`, made
general (docs/PORT-TOOLS.md compares the two).
"""

from __future__ import annotations

import collections
import re
from dataclasses import dataclass, field

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from . import pefunctions, scan
from .pemodel import Image

MIN_CODE = 4  # shorter sequences (stubs, thunks) occur too often to mean anything
PADDING = ("int3", "nop")
DEFINE = re.compile(r"#define\s+(\w+)\s+0x([0-9a-fA-F]+)[uUlL]*\b")


@dataclass
class Shape:
    """One function, normalized: tokens, direct call targets and data addresses (RVAs) in
    instruction order, and the strings it references, sorted."""

    tokens: tuple[str, ...]
    calls: list[int] = field(default_factory=list)
    data: list[int] = field(default_factory=list)
    strings: tuple[str, ...] = ()


class Side:
    """One binary: its image and every function's shape."""

    def __init__(self, image: Image):
        self.image = image
        self.functions = pefunctions.of(image)
        self.mask = (1 << 64) - 1 if image.x64 else 0xFFFFFFFF
        self.cs = scan.disassembler(image)
        self.starts = set(self.functions.entries())
        self.shapes = {start: self.shape(start) for start in sorted(self.starts)}

    def is_address(self, va: int) -> bool:
        return self.image.base <= va & self.mask < self.image.base + self.image.size_of_image

    def code(self, start: int, end: int) -> bytes:
        """The file's bytes of [start, end), cut where the section's file bytes end."""
        section = self.image.section_at(start)
        if section is None:
            return b""
        end = min(end, section.rva + section.raw_size)
        try:
            return self.image.read(start, end - start) if end > start else b""
        except ValueError:
            return b""

    def shape(self, start: int) -> Shape:
        found = Shape(())
        tokens = []
        for lo, end in sorted(self.functions.body(start)):
            # disassembly stops at the first byte that does not decode: data in the body
            for insn in self.cs.disasm(self.code(lo, end), self.image.va(lo)):
                tokens.append(self.token(insn, found))
        while tokens and tokens[-1].split(" ", 1)[0] in PADDING:
            tokens.pop()  # the padding up to the next start, when the body runs to it
        found.tokens = tuple(tokens)
        strings = {scan.string_at(self.image, rva) for rva in found.data}
        found.strings = tuple(sorted({s[1] for s in strings if s}))
        return found

    def token(self, insn, found: Shape) -> str:
        """The instruction with its addresses as `A`; the addresses go to found's calls (a
        direct call to a function start) or data (anything else but a branch target)."""
        try:
            operands = insn.operands
            branch = insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL)
        except CsError:
            return insn.mnemonic
        ops = []
        for op in operands:
            if op.type == X86_OP_IMM:
                value = op.imm & self.mask
                if not self.is_address(value):
                    ops.append(f"{value:x}")
                    continue
                ops.append("A")
                rva = self.image.rva(value)
                if insn.mnemonic == "call" and rva in self.starts:
                    found.calls.append(rva)
                elif not branch:
                    found.data.append(rva)
            elif op.type == X86_OP_MEM:
                mem = op.mem
                if mem.base == X86_REG_RIP:
                    va, base = (insn.address + insn.size + mem.disp) & self.mask, "rip"
                else:
                    va, base = mem.disp & self.mask, insn.reg_name(mem.base) if mem.base else ""
                if self.is_address(va):
                    disp = "A"
                    found.data.append(self.image.rva(va))
                else:
                    disp = f"{mem.disp & self.mask:x}" if base != "rip" else f"{mem.disp:x}"
                index = insn.reg_name(mem.index) if mem.index else ""
                ops.append(f"[{base}+{index}*{mem.scale}+{disp}]")
            else:
                ops.append(insn.reg_name(op.reg))
        return insn.mnemonic + " " + ",".join(ops)


@dataclass
class Result:
    """Function pairs (old RVA -> new RVA) with how each was found; data pairs (old RVA ->
    (new RVA, votes for it, votes in all))."""

    functions: dict[int, int]
    how: dict[int, str]
    data: dict[int, tuple[int, int, int]]


def unique_pairs(old: dict, new: dict) -> list[tuple[int, int]]:
    """Keys that map to exactly one function on each side: (old start, new start)."""
    return [(o[0], new[k][0]) for k, o in old.items() if len(o) == 1 and len(new.get(k, ())) == 1]


def group(side: Side, key) -> dict:
    found: dict = collections.defaultdict(list)
    for start, shape in side.shapes.items():
        value = key(shape)
        if value:
            found[value].append(start)
    return found


def match(old: Side, new: Side) -> Result:
    functions: dict[int, int] = {}
    how: dict[int, str] = {}
    taken: set[int] = set()
    by_strings: set[int] = set()

    def pair(o: int, n: int, why: str) -> bool:
        if o in functions or n in taken:
            return False
        functions[o] = n
        taken.add(n)
        how[o] = why
        return True

    def code(s: Shape):
        return s.tokens if len(s.tokens) >= MIN_CODE else None

    for o, n in unique_pairs(group(old, code), group(new, code)):
        pair(o, n, "same code")
    strings = group(old, lambda s: s.strings), group(new, lambda s: s.strings)
    for o, n in unique_pairs(*strings):
        first = old.shapes[o].strings[0]
        if pair(o, n, f"same strings ({first[:40]!r}...)"):
            by_strings.add(o)
    votes: dict[int, collections.Counter] = collections.defaultdict(collections.Counter)
    work = list(functions.items())
    while work:
        found = []
        for o, n in work:
            so, sn = old.shapes[o], new.shapes[n]
            same_length = len(so.tokens) == len(sn.tokens)
            if not same_length and o not in by_strings:
                continue  # neither the same length nor the same messages: calls need not line up
            if len(so.calls) == len(sn.calls):
                for co, cn in zip(so.calls, sn.calls, strict=True):
                    if pair(
                        co, cn, f"called from {old.image.va(o):08x} like {new.image.va(n):08x}"
                    ):
                        found.append((co, cn))
            if same_length and len(so.data) == len(sn.data):
                for do, dn in zip(so.data, sn.data, strict=True):
                    votes[do][dn] += 1
        work = found
    data = {}
    for do, counter in votes.items():
        (dn, count), total = counter.most_common(1)[0], sum(counter.values())
        data[do] = (dn, count, total)
    return Result(functions, how, data)


def rows(old: Side, new: Side, result: Result) -> list[dict]:
    """The map: functions, then data, each by old address. VAs as 8 (x64: 16) hex digits."""
    width = 16 if old.image.x64 else 8
    found = []
    for o, n in sorted(result.functions.items()):
        found.append({"kind": "func", "old": f"{old.image.va(o):0{width}x}",
                      "new": f"{new.image.va(n):0{width}x}", "how": result.how[o],
                      "name": old.functions.name_of(o)})  # fmt: skip
    for o, (n, count, total) in sorted(result.data.items()):
        why = f"{count} of {total} references" + ("" if count == total else ", UNCERTAIN")
        found.append({"kind": "data", "old": f"{old.image.va(o):0{width}x}",
                      "new": f"{new.image.va(n):0{width}x}", "how": why, "name": None})  # fmt: skip
    return found


def translate_header(text: str, old: Side, new: Side, result: Result) -> list[dict]:
    """Each `#define NAME 0x...` of a header for the old binary, with its candidate in the new
    one: a function, a data address, `same` (a constant, not an address of the old image) or
    none (an address nothing matched)."""
    found = []
    for line in text.splitlines():
        m = DEFINE.match(line.strip())
        if not m:
            continue
        name, value = m[1], int(m[2], 16)
        entry = {"name": name, "old": value, "new": None, "kind": None, "how": None}
        rva = old.image.rva(value)
        if not old.is_address(value):
            entry.update(new=value, kind="same", how="a constant, check it")
        elif rva in result.functions:
            entry.update(new=new.image.va(result.functions[rva]), kind="function",
                         how=result.how[rva])  # fmt: skip
        elif rva in result.data:
            n, count, total = result.data[rva]
            uncertain = "" if count == total else ", UNCERTAIN"
            entry.update(new=new.image.va(n), kind="data",
                         how=f"{count} of {total} references{uncertain}")  # fmt: skip
        found.append(entry)
    return found


def header_lines(entries: list[dict], x64: bool) -> list[str]:
    width = 16 if x64 else 8
    suffix = "ull" if x64 else "u"
    lines = []
    for e in entries:
        old = f"{e['old']:0{width}x}"
        if e["new"] is None:
            lines.append(f"// {e['name']}: ? (0x{old} not matched)")
            continue
        new = f"0x{e['new']:0{width}x}{suffix}"
        if e["kind"] == "same":
            note = "same: a constant, check it"
        else:
            note = f"{e['kind']} {old}" + (f": {e['how']}" if e["kind"] == "data" else "")
        lines.append(f"#define {e['name']:32} {new}   // {note}")
    return lines
