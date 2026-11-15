"""The static interface census of a 32-bit PE (docs/census.md), from the file alone, with Capstone.

Each function is walked forward once per pass, in address order, with a small abstract state:
registers and stack slots hold values such as "the interface IDirect3DDevice9", "its vtable",
"method 118 of it", "the dword in global 0x9f3c10", "field 0x1c of this", "what 0x4f0000
returned", "parameter 1". A state reaching a forward branch target is merged there (what both
sides agree on); a backward branch is not followed.

What a function learns outlives it as facts, flow-insensitive and per image: the interface a
global or an object field holds (a store of a typed value), a function's return, a parameter
(from the calls that pass a typed value), the object `this` is (from the calls that pass one: a
class's virtual methods, from RTTI, share one `this`), and an out-parameter a function writes.
Passes repeat until no fact changes (at most --passes). Two facts that disagree on one place
keep the common base interface, or none.

Seeds: the factory imports and every method that hands out an interface, from the slot tables
(census.Slots): its EAX, its out-parameters (a stack slot, a global or a field passed by
address), and QueryInterface-shaped ones by their IID constant's bytes. A `call [reg+off]` or
`jmp [reg+off]` whose reg holds a vtable is a call of slot off/4.

What it misses: an object reached through an array or a container, a computed offset, a value
kept in a register across a loop's back edge, a `this` that differs from call to call, code the
function table does not cover. The coverage line counts the indirect calls left unresolved.
"""

from __future__ import annotations

import bisect
import struct
from collections import defaultdict
from dataclasses import dataclass, field

from capstone import CS_ARCH_X86, CS_MODE_32, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

from . import census as census_mod
from . import pefunctions, rtti
from .pemodel import Image

UNKNOWN = ("?",)
CONFLICT = ("conflict",)
REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
FAMILY = {
    **{r: r for r in REGS},
    "ax": "eax", "al": "eax", "ah": "eax", "cx": "ecx", "cl": "ecx", "ch": "ecx",
    "dx": "edx", "dl": "edx", "dh": "edx", "bx": "ebx", "bl": "ebx", "bh": "ebx",
    "sp": "esp", "bp": "ebp", "si": "esi", "di": "edi",
}  # fmt: skip
CLOBBERED_BY_CALL = ("eax", "ecx", "edx")
ENTRY_REGS = ("eax", "edx", "ebx", "esi", "edi", "ebp")  # ECX is `this`, ESP the stack
STOP = {"ret", "retf", "jmp", "ud2", "int3", "hlt"}


@dataclass
class Insn:
    """What the walk needs of one instruction (decoded per function, dropped after)."""

    address: int  # VA
    size: int
    mnemonic: str
    ops: list[tuple]  # ("reg", name) | ("imm", value) | ("mem", base, index, disp)
    writes: tuple[str, ...]


@dataclass
class State:
    regs: dict[str, tuple] = field(default_factory=dict)
    slots: dict[int, tuple] = field(default_factory=dict)  # offset from the entry's esp
    pending: int = 0  # pushes since the last call

    def copy(self) -> State:
        return State(dict(self.regs), dict(self.slots), self.pending)

    def merge(self, other: State, join=None) -> State:
        """What both states agree on; join(a, b) may give a value for two that differ."""

        def keep(mine: dict, theirs: dict) -> dict:
            out = {}
            for k, v in mine.items():
                w = theirs.get(k)
                if w == v:
                    out[k] = v
                elif join is not None and w is not None and (j := join(v, w)) is not None:
                    out[k] = j
            return out

        return State(
            keep(self.regs, other.regs),
            keep(self.slots, other.slots),
            min(self.pending, other.pending),
        )


@dataclass
class Site:
    call: int
    ret: int | None
    function: int | None
    how: str


class Facts:
    def __init__(self, slots: census_mod.Slots):
        self.slots = slots
        self.types: dict[tuple, object] = {}
        self.votes: dict[tuple, dict[str, set[int]]] = {}
        self.rejected: set[tuple] = set()
        self.site = 0  # the instruction a fact comes from: Tracer.step sets it
        self.alias: dict[tuple, object] = {}  # ("this", K) -> the object source the callers pass
        # a place -> a vtable of the object it points to; vtables stored into one object (a
        # base's and its derived class's constructors) are one class, by union-find
        self.classes: dict[tuple, int] = {}
        self.parent: dict[int, int] = {}
        self.changed = False

    def find(self, vtable: int) -> int:
        root = vtable
        while self.parent.get(root, root) != root:
            root = self.parent[root]
        while self.parent.get(vtable, vtable) != root:
            self.parent[vtable], vtable = root, self.parent[vtable]
        return root

    def union(self, a: int, b: int) -> None:
        a, b = self.find(a), self.find(b)
        if a != b:
            self.parent[max(a, b)] = min(a, b)
            self.changed = True

    def set_class(self, key: tuple | None, vtable: int) -> None:
        """The object at key is of vtable's class. Places that see two classes (a generic
        function's parameter) keep none; only a constructor joins classes (union)."""
        if key is None:
            return
        old = self.classes.get(key)
        if old is None:
            self.classes[key] = vtable
            self.changed = True
        elif old is not CONFLICT and self.find(old) != self.find(vtable):
            self.classes[key] = CONFLICT
            self.changed = True

    def class_of(self, key: tuple | None) -> int | None:
        found = self.classes.get(key) if key is not None else None
        return None if found is None or found is CONFLICT else self.find(found)

    def reject(self, key: tuple | None) -> None:
        """A call through key used a slot its interface does not have: the type was wrong."""
        if key is not None and self.types.get(key) is not CONFLICT:
            self.types[key] = CONFLICT
            self.rejected.add(key)
            self.changed = True

    def set_type(self, key: tuple | None, interface: str) -> None:
        """A vote, by the instruction at self.site, that key holds interface. The place's type is
        the one most sites say (a base and its derived interfaces counted together, the base
        kept), unless the sites for unrelated ones are half as many or more: one wrong store
        does not undo six right ones."""
        if key is None or key in self.rejected:
            return
        votes = self.votes.setdefault(key, {})
        sites = votes.setdefault(interface, set())
        if self.site in sites:
            return
        sites.add(self.site)
        new = self.decide(votes)
        if self.types.get(key) != new:
            self.types[key] = new
        self.changed = True

    def decide(self, votes: dict[str, set[int]]) -> object:
        best = max(votes, key=lambda i: (len(votes[i]), i))
        related = [i for i in votes if self.slots.is_base(i, best) or self.slots.is_base(best, i)]
        support = sum(len(votes[i]) for i in related)
        against = max((len(v) for i, v in votes.items() if i not in related), default=0)
        if 2 * against >= support:
            return CONFLICT
        return next((i for i in related if all(self.slots.is_base(i, r) for r in related)), best)

    def type(self, key: tuple | None) -> str | None:
        found = self.types.get(key) if key is not None else None
        return found if isinstance(found, str) else None

    def set_alias(self, key: tuple, value: tuple) -> None:
        old = self.alias.get(key)
        if old == value or old is CONFLICT:
            return
        self.alias[key] = value if old is None else CONFLICT
        self.changed = True


class Tracer:
    def __init__(self, image: Image, slots: census_mod.Slots, functions: pefunctions.Functions):
        self.image = image
        self.slots = slots
        self.functions = functions
        self.facts = Facts(slots)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.iat = {self.image.va(slot): row for slot, row in image.iat_slots.items()}
        self.thunks: dict[int, object] = {}  # function VA -> the import its jmp [IAT] reaches
        self.pops: dict[int, int] = {}  # function VA -> bytes its ret pops
        self.owners: dict[int, set[int]] = defaultdict(set)  # function VA -> vtables listing it
        self.vtables: dict[int, list[int]] = {}  # a vtable's VA -> its slots (function VAs)
        self.method_sites: dict[int, tuple[str, int, Site]] = {}
        self.import_sites: dict[int, tuple[object, Site]] = {}
        self.indirect: dict[int, int] = {}  # unresolved call VA -> its function
        self.function = 0  # the VA of the function being walked
        self._starts: list[int] | None = None

    # -- set-up --

    def classes(self) -> None:
        """RTTI's primary vtables, a hierarchy's joined into one class (the object layout a class
        shares with its bases, so their methods see one set of fields). Vtables without RTTI are
        found as constructors store them (vtable())."""
        try:
            found = rtti.classes(self.image)
        except Exception:  # noqa: BLE001 - RTTI is a help, a broken one is no reason to stop
            found = []
        primary: dict[str, int] = {}
        for cls in found:
            for vtable in cls.vtables:
                if vtable.offset == 0:
                    primary[cls.name] = self.image.va(vtable.rva)
                    self.vtable(primary[cls.name])
        for cls in found:
            for base in cls.bases[1:]:
                if base.mdisp == 0 and cls.name in primary and base.name in primary:
                    self.facts.union(primary[cls.name], primary[base.name])

    def vtable(self, va: int) -> bool:
        """va is a vtable: in read-only data, its first slot a pointer to code. Its slots are
        noted the first time (what each function is a method of)."""
        if va in self.vtables:
            return bool(self.vtables[va])
        slots: list[int] = []
        section = self.image.section_at(va - self.image.base) if va >= self.image.base else None
        if section is not None and not section.executable and not section.writable:
            for i in range(1024):
                try:
                    target = self.image.u32(va - self.image.base + 4 * i)
                except (ValueError, IndexError, struct.error):
                    break
                if target < self.image.base or not self.image.is_code(target - self.image.base):
                    break
                slots.append(target)
        self.vtables[va] = slots
        for target in slots:
            self.owners[target].add(va)
        return bool(slots)

    def method_class(self, function: int) -> int | None:
        """The one class whose vtables list function, if it is one."""
        roots = {self.facts.find(v) for v in self.owners.get(function, ())}
        return next(iter(roots)) if len(roots) == 1 else None

    def entries(self) -> list[int]:
        return [
            self.image.va(start) for start in self.functions.entries() if self.image.is_code(start)
        ]

    def body(self, start: int) -> list[tuple[int, int]]:
        """The RVA ranges to decode: a control-flow export's ranges, else up to the next
        function start (a table's size is often the first block only, as Ghidra's for a
        function whose switch cases it placed after the table)."""
        rva = self.image.rva(start)
        if self.functions.ranges.get(rva):
            return self.functions.ranges[rva]
        if self._starts is None:
            self._starts = sorted(self.functions.entries())
        index = bisect.bisect_right(self._starts, rva)
        end = self._starts[index] if index < len(self._starts) else rva + 0x10000
        section = self.image.section_at(rva)
        if section is not None:
            end = min(end, section.rva + section.data_size)
        return [(rva, min(end, rva + 0x10000))]

    def decode(self, start: int) -> list[Insn]:
        out: list[Insn] = []
        for lo, hi in self.body(start):
            try:
                data = self.image.read(lo, hi - lo)
            except (ValueError, IndexError):
                continue
            try:
                for insn in self.cs.disasm(data, self.image.va(lo)):
                    out.append(compact(insn))
            except CsError:
                continue
        return out

    # -- values --

    def this_key(self, function: int) -> tuple:
        cls = self.method_class(function)
        return ("this", ("class", cls) if cls is not None else ("fn", function))

    def resolve(self, value: tuple, depth: int = 0) -> tuple:
        """A `this` followed to the object its callers pass, when they agree on one."""
        while value[0] in ("this", "in") and depth < 8:
            target = self.facts.alias.get(value)
            if not isinstance(target, tuple) or target is CONFLICT or target == value:
                break
            value = target
            depth += 1
        return value

    def canon(self, value: tuple, depth: int = 0) -> tuple | None:
        """The fact key a source value stands for, aliases followed; None for an untrackable one."""
        if depth > 8:
            return None
        value = self.resolve(value)
        kind = value[0]
        if kind in ("this", "in"):
            return value
        if kind == "f":
            obj = self.resolve(value[1])
            if obj[0] == "addr":
                return ("g", (obj[1] + value[2]) & 0xFFFFFFFF)
            cls = self.object_class(obj, depth + 1)
            if cls is not None:
                return ("cf", cls, value[2])
            base = self.canon(obj, depth + 1)
            return ("f", base, value[2]) if base is not None and base[0] != "ret" else None
        if kind in ("g", "ret", "p", "pout", "cf"):
            return value
        return None

    def object_class(self, value: tuple, depth: int = 0) -> int | None:
        """The class (a vtable, its hierarchy's root) of the object value points to, when known."""
        if value is UNKNOWN or value[0] in ("t", "sa", "m", "imp", "vt", "fa", "addr", "cvt", "dm"):
            return None
        if value[0] == "o":
            roots = {self.facts.find(v) for v in value[1]}
            return next(iter(roots)) if len(roots) == 1 else None
        value = self.resolve(value)
        if value[0] == "this" and value[1][0] == "class":
            return self.facts.find(value[1][1])
        return self.facts.class_of(self.canon(value, depth + 1))

    def type_of(self, value: tuple | None) -> str | None:
        if not value or value is UNKNOWN:
            return None
        if value[0] == "t":
            return value[1]
        return self.facts.type(self.canon(value))

    def how(self, value: tuple) -> str:
        if value[0] == "t":
            return value[2]
        key = self.canon(value) or value
        return describe(key)

    def concrete(self, value: tuple) -> frozenset | None:
        """The vtables an object value may have: a constructor's in this function, or the one a
        place was first given."""
        if value[0] == "o":
            return value[1]
        if value is UNKNOWN or value[0] in ("t", "sa", "m", "imp", "vt", "fa", "addr", "cvt", "dm"):
            return None
        found = self.facts.classes.get(self.canon(value))
        return frozenset({found}) if isinstance(found, int) else None

    def class_fact(self, value: tuple) -> int | None:
        """The vtable to record for a place value is stored to: the concrete one when the value
        has exactly one, else its class's root."""
        found = self.concrete(value)
        if found and len(found) == 1:
            return next(iter(found))
        return self.object_class(value)

    def join(self, a: tuple, b: tuple) -> tuple | None:
        """Two paths with objects of known classes in one place: one of those classes."""
        ca, cb = self.concrete(a), self.concrete(b)
        if ca and cb and len(ca | cb) <= 16:
            return ("o", ca | cb)
        return None

    def global_value(self, va: int) -> tuple:
        row = self.iat.get(va)
        return ("imp", row) if row is not None else ("g", va)

    def load(self, op: tuple, state: State) -> tuple:
        _mem, base, index, disp = op
        if index:
            return UNKNOWN
        if base is None:
            return self.global_value(disp & 0xFFFFFFFF)
        bv, disp = field_base(state.regs.get(base, UNKNOWN), disp)
        kind = bv[0]
        if kind == "sa":
            at = bv[1] + disp
            if at in state.slots:
                return state.slots[at]
            return ("p", self.function, (at - 4) // 4) if at >= 4 and at % 4 == 0 else UNKNOWN
        if kind == "vt":
            if disp % 4 or disp < 0 or self.slots.method(bv[1], disp // 4) is None:
                self.facts.reject(bv[3])  # no such slot: the place holds something else
                return UNKNOWN
            return ("m", bv[1], disp // 4, bv[2])
        if kind == "o" and disp == 0:
            return ("cvt", bv[1])
        if kind == "cvt":  # a slot of known vtables: the call is a direct one to each
            if disp % 4:
                return UNKNOWN
            targets = set()
            for vtable in bv[1]:
                slots = self.vtables.get(vtable, [])
                if not 0 <= disp // 4 < len(slots):
                    return UNKNOWN
                targets.add(slots[disp // 4])
            return ("dm", frozenset(targets))
        if kind == "addr":
            return self.global_value((bv[1] + disp) & 0xFFFFFFFF)
        if kind in ("?", "m", "imp", "fa", "dm"):
            return UNKNOWN
        interface = self.type_of(bv)
        if interface and disp == 0:
            return ("vt", interface, self.how(bv), self.canon(bv))
        if kind == "t":
            return UNKNOWN
        return ("f", bv, disp)

    def address_of(self, op: tuple, state: State) -> tuple:
        _mem, base, index, disp = op
        if index:
            return UNKNOWN
        if base is None:
            return ("addr", disp & 0xFFFFFFFF)
        bv, disp = field_base(state.regs.get(base, UNKNOWN), disp)
        if bv[0] == "sa":
            return ("sa", bv[1] + disp)
        if bv[0] == "addr":
            return ("addr", (bv[1] + disp) & 0xFFFFFFFF)
        if bv is UNKNOWN or bv[0] in ("m", "imp", "vt", "t", "cvt", "dm"):
            return UNKNOWN
        return bv if disp == 0 else ("fa", bv, disp)

    def store(self, op: tuple, value: tuple, state: State) -> None:
        _mem, base, index, disp = op
        if index:
            return
        if base is not None:
            bv, disp = field_base(state.regs.get(base, UNKNOWN), disp)
            if bv[0] == "sa":
                state.slots[bv[1] + disp] = value
                return
            if bv is UNKNOWN or bv[0] in ("m", "imp", "vt", "t", "cvt", "dm"):
                return
            if disp == 0 and value[0] == "addr" and bv[0] != "addr" and self.vtable(value[1]):
                self.construct(bv, value[1], state)
                return
            key = (
                self.canon(("f", bv, disp))
                if bv[0] != "addr"
                else ("g", (bv[1] + disp) & 0xFFFFFFFF)
            )
        else:
            key = ("g", disp & 0xFFFFFFFF)
        interface = self.type_of(value)
        if interface:
            self.facts.set_type(key, interface)
        cls = self.class_fact(value)
        if cls is not None and key is not None:
            self.facts.set_class(key, cls)

    def construct(self, obj: tuple, vtable: int, state: State) -> None:
        """A constructor (or destructor) setting the object's vtable: the object's class, and in
        this function a concrete object, whose virtual calls are direct ones."""
        cls = self.object_class(obj)
        if cls is not None:
            self.facts.union(cls, vtable)
        elif obj[0] not in ("o",):
            self.facts.set_class(self.canon(obj), vtable)
        concrete = ("o", frozenset({vtable}))
        for reg, v in list(state.regs.items()):
            if v == obj:
                state.regs[reg] = concrete
        for at, v in list(state.slots.items()):
            if v == obj:
                state.slots[at] = concrete

    def write_out(self, target: tuple | None, interface: str, how: str, state: State) -> None:
        """An out-parameter: the place target points at now holds interface."""
        if not target or target is UNKNOWN:
            return
        kind = target[0]
        if kind == "sa":
            state.slots[target[1]] = ("t", interface, how)
        elif kind == "addr":
            self.facts.set_type(("g", target[1]), interface)
        elif kind == "fa":
            self.facts.set_type(self.canon(("f", target[1], target[2])), interface)
        elif kind == "p":
            self.facts.set_type(("pout", target[1], target[2]), interface)
        elif kind in ("g", "f", "this", "ret"):
            # a pointer to the place, kept in a global or a field: the place itself is unknown
            return

    def value(self, op: tuple, state: State) -> tuple:
        kind = op[0]
        if kind == "reg":
            return state.regs.get(op[1], UNKNOWN)
        if kind == "imm":
            return ("addr", op[1] & 0xFFFFFFFF)
        return self.load(op, state)

    # -- the walk --

    def walk(self, start: int) -> None:
        self.function = start
        code = self.decode(start)
        if not code:
            return
        first = code[0]
        if (
            first.mnemonic == "jmp"
            and first.ops
            and first.ops[0][0] == "mem"
            and first.ops[0][1] is None
        ):
            row = self.iat.get(first.ops[0][3] & 0xFFFFFFFF)
            if row is not None:
                self.thunks[start] = row
                return
        regs = {r: ("in", start, r) for r in ENTRY_REGS}
        regs.update({"esp": ("sa", 0), "ecx": self.this_key(start)})
        state: State | None = State(regs)
        pending: dict[int, State] = {}
        end = code[-1].address + code[-1].size
        for n, insn in enumerate(code):
            at = insn.address
            if at in pending:
                state = (
                    pending.pop(at) if state is None else state.merge(pending.pop(at), self.join)
                )
            if state is None:
                continue
            following = code[n + 1] if n + 1 < len(code) else None
            state = self.step(insn, state, following, start, end, pending)

    def branch(
        self, target: int, state: State, start: int, end: int, pending: dict[int, State]
    ) -> None:
        if start <= target < end and target > self.current:
            pending[target] = (
                state.copy() if target not in pending else pending[target].merge(state, self.join)
            )

    def step(
        self, insn: Insn, state: State, following: Insn | None, start: int, end: int, pending: dict
    ) -> State | None:
        m, ops, regs = insn.mnemonic, insn.ops, state.regs
        self.current = insn.address
        self.facts.site = insn.address
        if m == "mov" and len(ops) == 2:
            dst, src = ops
            v = self.value(src, state)
            if dst[0] == "reg":
                if dst[1] in REGS:
                    regs[dst[1]] = v
                else:
                    regs[FAMILY.get(dst[1], dst[1])] = UNKNOWN
            elif dst[0] == "mem":
                self.store(dst, v, state)
            return state
        if m == "lea" and ops[0][0] == "reg":
            regs[FAMILY.get(ops[0][1], ops[0][1])] = self.address_of(ops[1], state)
            return state
        if m == "push":
            esp = regs.get("esp", UNKNOWN)
            v = self.value(ops[0], state) if ops else UNKNOWN
            if esp[0] == "sa":
                regs["esp"] = ("sa", esp[1] - 4)
                state.slots[esp[1] - 4] = v
            state.pending += 1
            return state
        if m == "pop":
            esp = regs.get("esp", UNKNOWN)
            v = state.slots.get(esp[1], UNKNOWN) if esp[0] == "sa" else UNKNOWN
            if ops and ops[0][0] == "reg":
                regs[FAMILY.get(ops[0][1], ops[0][1])] = v
            elif ops and ops[0][0] == "mem":
                self.store(ops[0], v, state)
            if esp[0] == "sa":
                regs["esp"] = ("sa", esp[1] + 4)
            return state
        if m in ("add", "sub") and ops[0] == ("reg", "esp") and ops[1][0] == "imm":
            esp = regs.get("esp", UNKNOWN)
            if esp[0] == "sa":
                delta = ops[1][1] if m == "add" else -ops[1][1]
                regs["esp"] = ("sa", esp[1] + delta)
                if m == "add":
                    state.pending = max(0, state.pending - ops[1][1] // 4)
            return state
        if m == "xor" and len(ops) == 2 and ops[0] == ops[1] and ops[0][0] == "reg":
            regs[FAMILY.get(ops[0][1], ops[0][1])] = ("addr", 0)
            return state
        if m == "leave":
            ebp = regs.get("ebp", UNKNOWN)
            regs["esp"] = ("sa", ebp[1] + 4) if ebp[0] == "sa" else UNKNOWN
            regs["ebp"] = UNKNOWN
            return state
        if m == "call":
            return self.call(insn, state, following, start)
        if m in ("ret", "retf"):
            interface = self.type_of(regs.get("eax"))
            if interface:
                self.facts.set_type(("ret", start), interface)
            cls = self.class_fact(regs.get("eax", UNKNOWN))
            if cls is not None:
                self.facts.set_class(("ret", start), cls)
            self.pops[start] = ops[0][1] if ops and ops[0][0] == "imm" else 0
            return None
        if m == "jmp":
            if ops and ops[0][0] == "imm":
                target = ops[0][1]
                if start <= target < end:
                    self.branch(target, state, start, end, pending)
                    return None
                self.tail(insn, state, start)
                return None
            if ops and ops[0][0] == "mem" and ops[0][2] and ops[0][1] is None:
                for target in self.jump_table(ops[0][3] & 0xFFFFFFFF, start, end):
                    self.branch(target, state, start, end, pending)  # each case starts from here
                return None
            self.indirect_call(insn, state, start, tail=True)
            return None
        if m.startswith(("j", "loop")):
            if ops and ops[0][0] == "imm":
                self.branch(ops[0][1], state, start, end, pending)
            return state
        if m in STOP:
            return None
        for reg in insn.writes:
            if reg == "esp":
                regs["esp"] = UNKNOWN
            elif reg in REGS:
                regs[reg] = UNKNOWN
        if ops and ops[0][0] == "mem" and m not in ("cmp", "test") and not m.startswith("f"):
            self.store(ops[0], UNKNOWN, state)
        return state

    def jump_table(self, table: int, start: int, end: int) -> list[int]:
        """The case addresses of `jmp [reg*4 + table]`: dwords pointing into the function."""
        found = []
        rva = table - self.image.base
        for i in range(512):
            try:
                target = self.image.u32(rva + 4 * i)
            except (ValueError, IndexError, struct.error):
                break
            if not start <= target < end:
                break
            found.append(target)
        return found

    def args(self, state: State, count: int) -> list[tuple]:
        esp = state.regs.get("esp", UNKNOWN)
        if esp[0] != "sa":
            return [UNKNOWN] * count
        return [state.slots.get(esp[1] + 4 * i, UNKNOWN) for i in range(count)]

    def after_call(
        self, state: State, pops: int | None, following: Insn | None, eax: tuple
    ) -> State:
        regs = state.regs
        for reg in CLOBBERED_BY_CALL:
            regs[reg] = UNKNOWN
        regs["eax"] = eax
        esp = regs.get("esp", UNKNOWN)
        if pops is None:  # unknown callee: stdcall pops what was pushed, unless the caller cleans
            cleans = (
                following is not None
                and following.mnemonic == "add"
                and following.ops[:1] == [("reg", "esp")]
            )
            pops = 0 if cleans else 4 * state.pending
        if esp[0] == "sa":
            regs["esp"] = ("sa", esp[1] + pops)
        state.pending = 0
        return state

    def call(self, insn: Insn, state: State, following: Insn | None, start: int) -> State:
        op = insn.ops[0] if insn.ops else ("?",)
        ret = insn.address + insn.size
        if op[0] == "imm":
            target = op[1]
            row = self.thunks.get(target)
            if row is not None:
                return self.import_call(row, insn, state, following, start, ret)
            return self.direct_call(target, state, following)
        target = self.value(op, state)
        if target[0] == "imp":
            return self.import_call(target[1], insn, state, following, start, ret)
        if target[0] == "m":
            return self.method_call(target, insn, state, following, start, ret)
        if target[0] == "dm":
            for function in sorted(target[1])[1:]:
                self.propagate(function, state)
            return self.direct_call(min(target[1]), state, following)
        if op[0] == "reg" or (op[0] == "mem" and op[1] is not None):
            self.indirect[insn.address] = start
        return self.after_call(state, None, following, UNKNOWN)

    def tail(self, insn: Insn, state: State, start: int) -> None:
        row = self.thunks.get(insn.ops[0][1])
        if row is not None:
            self.import_sites[insn.address] = (row, Site(insn.address, None, start, "tail jump"))

    def indirect_call(self, insn: Insn, state: State, start: int, tail: bool) -> None:
        op = insn.ops[0] if insn.ops else ("?",)
        if op[0] not in ("reg", "mem"):
            return
        target = self.value(op, state)
        if target[0] == "m":
            self.record_method(target, insn, None, start)
        elif target[0] == "imp":
            self.import_sites[insn.address] = (
                target[1],
                Site(insn.address, None, start, "tail jump"),
            )
        elif (op[0] == "reg" or op[1] is not None) and not (op[0] == "mem" and op[2]):
            self.indirect[insn.address] = start  # a jump table is no call

    def record_method(
        self, target: tuple, insn: Insn, ret: int | None, start: int
    ) -> census_mod.Method | None:
        _m, interface, slot, how = target
        self.method_sites[insn.address] = (interface, slot, Site(insn.address, ret, start, how))
        self.indirect.pop(insn.address, None)
        return self.slots.method(interface, slot)

    def method_call(
        self, target: tuple, insn: Insn, state: State, following: Insn | None, start: int, ret: int
    ) -> State:
        method = self.record_method(target, insn, ret, start)
        if method is None:
            return self.after_call(state, None, following, UNKNOWN)
        name = f"{method.interface}::{method.name}"
        return self.effects(method, name, state, following, method.pops)

    def import_call(
        self, row, insn: Insn, state: State, following: Insn | None, start: int, ret: int
    ) -> State:
        self.import_sites[insn.address] = (row, Site(insn.address, ret, start, ""))
        f = self.slots.function(row.dll, row.name) if row.name else None
        if f is None:
            return self.after_call(state, None, following, UNKNOWN)
        return self.effects(f, f.name, state, following, 4 * f.args)

    def effects(self, f, name: str, state: State, following: Insn | None, pops: int) -> State:
        need = max(
            [f.args + 1, *(k + 1 for k, _ in f.out), *(max(c[:2]) + 1 for c in f.callbacks)]
            + ([max(f.riid) + 1] if f.riid else [])
        )
        args = self.args(state, need)
        for k, interface in f.out:
            self.write_out(args[k], interface, f"out-parameter of {name}", state)
        if f.riid:
            iid = args[f.riid[0]]
            interface = self.iid_at(iid)
            if interface:
                self.write_out(args[f.riid[1]], interface, f"{name} by IID", state)
        for fn_arg, ctx_arg, param in f.callbacks:
            self.callback(
                args[fn_arg] if fn_arg < len(args) else UNKNOWN,
                args[ctx_arg] if ctx_arg < len(args) else UNKNOWN,
                param,
            )
        eax = ("t", f.returns, f"return of {name}") if f.returns else UNKNOWN
        return self.after_call(state, pops, following, eax)

    def callback(self, function: tuple, context: tuple, param: int) -> None:
        """An enumeration's callback gets the caller's context argument as parameter param."""
        if function[0] != "addr" or not self.image.is_code(function[1] - self.image.base):
            return
        key = ("p", function[1], param)
        interface = self.type_of(context)
        if interface:
            self.facts.set_type(key, interface)
        cls = self.class_fact(context)
        if cls is not None:
            self.facts.set_class(key, cls)

    def iid_at(self, value: tuple) -> str | None:
        if not value or value[0] != "addr":
            return None
        try:
            data = self.image.read(self.image.rva(value[1]), 16)
        except (ValueError, IndexError):
            return None
        return self.slots.iids.get(bytes(data))

    def direct_call(self, target: int, state: State, following: Insn | None) -> State:
        self.propagate(target, state)
        return self.after_call(state, self.pops.get(target), following, ("ret", target))

    def propagate(self, target: int, state: State) -> None:
        """What a direct call tells its callee: its arguments, its entry registers."""
        pops = self.pops.get(target)
        if pops:
            for i, arg in enumerate(self.args(state, pops // 4)):
                interface = self.type_of(arg)
                if interface:
                    self.facts.set_type(("p", target, i), interface)
                cls = self.class_fact(arg)
                if cls is not None:
                    self.facts.set_class(("p", target, i), cls)
            for i, arg in enumerate(self.args(state, pops // 4)):
                interface = self.facts.type(("pout", target, i))
                if interface:
                    self.write_out(arg, interface, f"out-parameter of {target:#x}", state)
        # a register at the callee's entry holds what the caller left in it: `this` in ECX, and
        # with link-time code generation any argument; callee-saved ones are the caller's anyway
        for reg in ("ecx", *ENTRY_REGS):
            key = self.this_key(target) if reg == "ecx" else ("in", target, reg)
            self.pass_register(key, state.regs.get(reg, UNKNOWN))

    def pass_register(self, key: tuple, value: tuple) -> None:
        if value is UNKNOWN or value[0] in ("sa", "m", "imp", "vt", "fa", "cvt", "dm"):
            return
        cls = self.class_fact(value)
        if cls is not None and not (key[0] == "this" and key[1][0] == "class"):
            self.facts.set_class(key, cls)  # the callers agree on the class if not the object
        if (
            key[0] == "this" and key[1][0] != "fn"
        ):  # a class's methods: their callers pass many objects
            interface = self.type_of(value)
            if interface:
                self.facts.set_type(key, interface)
            return
        if value[0] == "addr":  # a global object: the register holds its address
            self.facts.set_alias(key, value)
            return
        interface = self.type_of(value)
        if interface:
            self.facts.set_type(self.canon(key), interface)
            return
        if value[0] != "t":
            source = self.canon(value)
            if source is not None and source != key:
                self.facts.set_alias(key, source)

    # -- passes --

    def run(self, passes: int) -> int:
        entries = self.entries()
        done = 0
        for done in range(1, passes + 1):
            self.facts.changed = False
            self.method_sites.clear()
            self.import_sites.clear()
            self.indirect.clear()
            for start in entries:
                self.walk(start)
            if not self.facts.changed and done > 1:
                break
        return done


def field_base(value: tuple, disp: int) -> tuple[tuple, int]:
    """[reg+disp] where reg holds a field's address (`lea edi, [esi+4]`): the object and the
    field's offset."""
    if value[0] == "fa":
        return value[1], value[2] + disp
    return value, disp


def describe(key: tuple) -> str:
    kind = key[0]
    if kind == "g":
        return f"global {key[1]:#x}"
    if kind == "f":
        return f"field {key[2]:#x} of {describe(key[1])}"
    if kind == "ret":
        return f"return of {key[1]:#x}"
    if kind == "p":
        return f"parameter {key[2]} of {key[1]:#x}"
    if kind == "in":
        return f"{key[2]} at {key[1]:#x}"
    if kind == "cf":
        return f"field {key[2]:#x} of class {key[1]:#x}"
    if kind == "this":
        inner = key[1]
        return f"this of class {inner[1]:#x}" if inner[0] == "class" else f"this of {inner[1]:#x}"
    return str(key)


def compact(insn) -> Insn:
    ops = []
    for op in insn.operands:
        if op.type == X86_OP_REG:
            ops.append(("reg", insn.reg_name(op.reg)))
        elif op.type == X86_OP_IMM:
            ops.append(("imm", op.imm & 0xFFFFFFFF))
        elif op.type == X86_OP_MEM:
            base = insn.reg_name(op.mem.base) if op.mem.base != X86_REG_INVALID else None
            index = insn.reg_name(op.mem.index) if op.mem.index != X86_REG_INVALID else None
            ops.append(("mem", base, index, op.mem.disp))
        else:
            ops.append(("?",))
    try:
        _read, written = insn.regs_access()
        writes = tuple({FAMILY.get(insn.reg_name(r), "") for r in written} - {""})
    except CsError:
        writes = tuple(REGS)
    return Insn(insn.address, insn.size, insn.mnemonic, ops, writes)


def census(
    image: Image,
    slots: census_mod.Slots,
    functions: pefunctions.Functions | None = None,
    unresolved_sites: bool = False,
    passes: int = 12,
    producer: str = "rea-suite pe census",
) -> dict:
    """The rea-census/1 static document of image."""
    if image.pointer_size != 4:
        raise census_mod.CensusError("pe census reads 32-bit x86 images only")
    tracer = Tracer(image, slots, functions or pefunctions.of(image))
    tracer.classes()
    done = tracer.run(passes)
    interfaces: dict[str, dict[int, list[Site]]] = defaultdict(lambda: defaultdict(list))
    for interface, slot, site in tracer.method_sites.values():
        interfaces[interface][slot].append(site)
    imports: dict[tuple[str, str], list[Site]] = defaultdict(list)
    for row, site in tracer.import_sites.values():
        name = row.name if row.name else f"#{row.ordinal}"
        imports[(row.dll.lower(), name)].append(site)
    resolved = len(tracer.method_sites)
    unresolved = len(tracer.indirect)
    doc = {
        "schema": census_mod.SCHEMA,
        "kind": "static",
        "source": source(image),
        "producer": {"name": producer, "passes": done},
        "interfaces": [
            {
                "name": name,
                "sdk": slots.sdk.get(name),
                "methods": [
                    {
                        "slot": slot,
                        "name": (m.name if (m := slots.method(name, slot)) else None),
                        "sites": [site_json(s) for s in sorted(sites, key=lambda s: s.call)],
                    }
                    for slot, sites in sorted(by_slot.items())
                ],
            }
            for name, by_slot in sorted(interfaces.items())
        ],
        "imports": [
            {
                "module": module,
                "name": name,
                "sites": [site_json(s) for s in sorted(sites, key=lambda s: s.call)],
            }
            for (module, name), sites in sorted(imports.items())
        ],
        "coverage": {
            "indirect_calls": resolved + unresolved,
            "resolved": resolved,
            "unresolved": unresolved,
            "functions": len(tracer.entries()),
            "function_source": tracer.functions.source,
            "note": "indirect calls and jumps through a register or [reg+off]; unresolved ones may be "
            "interface methods the census missed, or the game's own virtual calls and function pointers",
        },
    }
    if unresolved_sites:
        doc["coverage"]["unresolved_sites"] = [
            {"call": f"{at:#x}", "function": f"{fn:#x}"}
            for at, fn in sorted(tracer.indirect.items())
        ]
    return doc


def site_json(site: Site) -> dict:
    row = {
        "call": f"{site.call:#x}",
        "return": None if site.ret is None else f"{site.ret:#x}",
        "function": None if site.function is None else f"{site.function:#x}",
    }
    if site.how:
        row["how"] = site.how
    return row


def source(image: Image) -> dict:
    import hashlib

    path = getattr(image, "path", None)
    data = image.data if hasattr(image, "data") else None
    return {
        "name": path.name if path else None,
        "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
        "image_base": f"{image.base:#x}",
    }
