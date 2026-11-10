"""MSVC RTTI from the file alone: every polymorphic class, its vtables and their slots, and its
base classes from the class hierarchy descriptor. x64 and x86 images.

The walk follows Microsoft's layout (the compiler's `_RTTICompleteObjectLocator`,
`_RTTIClassHierarchyDescriptor`, `_RTTIBaseClassDescriptor` and `std::type_info`):

- x64: a complete object locator has signature 1 and holds RVAs, its own included (pSelf), so
  locators are found by scanning read-only data for a 4-aligned 1 whose pSelf is its own RVA.
- x86: a locator has signature 0 and holds VAs. Type descriptors are found by their decorated
  names (`.?AV`, `.?AU`), locators by a VA of one of them, checked through the hierarchy
  descriptor.
- A vtable is the pointer after a pointer-sized slot holding the locator's VA; its slots run
  while they point into executable sections.

compare() then sets each slot against the base class's vtable for the same subobject: a
non-virtual base whose subobject sits at `mdisp` covers the class's vtable at offset `offset`
when the base has a vtable at `offset - mdisp`; the first such base in the hierarchy array is the
nearest one. A slot is `pure` (the CRT's `_purecall`), `inherited` (the base's slot holds the
same function), `overridden`, `new` (past the end of the base's vtable, or no base vtable
covers it) or `unknown` (a vtable no base covers in a class with virtual bases, whose offsets
come from the vbtable and not from RTTI).

Nothing needs base relocations: the image is read at its preferred base, which is how a
fixed-base image (no .reloc) runs anyway.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field

from . import scan
from .pemodel import Image

MAX_SLOTS = 4096
TYPE_NAME = re.compile(rb"\.\?A[VU][\x21-\x7e]{1,4000}?@@\0")
# _RTTIClassHierarchyDescriptor attributes
MULTIPLE, VIRTUAL = 1, 2
# The CRT's pure virtual stub, imported from vcruntime/msvcrt (an x86 name may keep its
# decoration); a statically linked one is given by address (`--purecall`).
PURECALL = {"_purecall", "__purecall"}


@dataclass
class Base:
    name: str
    mangled: str
    contained: int  # numContainedBases
    mdisp: int
    pdisp: int
    vdisp: int
    attributes: int


@dataclass
class Vtable:
    rva: int
    locator: int  # RVA of the complete object locator
    offset: int  # the subobject's offset in the complete object
    slots: list[int] = field(default_factory=list)  # RVAs of the functions
    base: str | None = None  # the base class whose vtable compare() set the slots against
    base_vtable: int | None = None  # RVA of that vtable
    states: list[str] = field(default_factory=list)  # per slot, after compare()

    def as_json(self) -> dict:
        found = {
            "rva": f"{self.rva:#x}",
            "locator": f"{self.locator:#x}",
            "offset": self.offset,
            "slots": [f"{s:#x}" for s in self.slots],
        }
        if self.states:
            found["base"] = self.base
            found["base_vtable"] = None if self.base_vtable is None else f"{self.base_vtable:#x}"
            found["slot_states"] = self.states
        return found


@dataclass
class Class:
    name: str
    mangled: str
    type_descriptor: int  # RVA
    hierarchy: int  # RVA of the class hierarchy descriptor
    attributes: int
    bases: list[Base] = field(default_factory=list)  # the class itself first, as MSVC lists them
    vtables: list[Vtable] = field(default_factory=list)

    def as_json(self) -> dict:
        return {
            "name": self.name,
            "mangled": self.mangled,
            "type_descriptor": f"{self.type_descriptor:#x}",
            "hierarchy": f"{self.hierarchy:#x}",
            "multiple_inheritance": bool(self.attributes & MULTIPLE),
            "virtual_inheritance": bool(self.attributes & VIRTUAL),
            "bases": [
                {
                    "name": b.name,
                    "contained": b.contained,
                    "mdisp": b.mdisp,
                    "pdisp": b.pdisp,
                    "vdisp": b.vdisp,
                    "attributes": f"{b.attributes:#x}",
                }
                for b in self.bases[1:]
            ],
            "vtables": [v.as_json() for v in self.vtables],
        }


def demangle(mangled: str) -> str:
    """`.?AVFoo@ns@@` -> `ns::Foo`; templates and other special names stay as they are (the
    batch through llvm-undname, when installed, names those)."""
    body = mangled[4:-2] if mangled.startswith(".?A") and mangled.endswith("@@") else ""
    if not body or "?" in body or "$" in body:
        return mangled
    return "::".join(reversed(body.split("@")))


def undname(names: list[str]) -> dict[str, str]:
    """llvm-undname (component `build`) for decorated names demangle() leaves as they are."""
    tool = shutil.which("llvm-undname")
    if not tool or not names:
        return {}
    # `??_R0?AV...@8` is the type descriptor's own symbol; llvm-undname spells out its type.
    symbols = [f"??_R0{n[1:]}@8" for n in names]
    try:
        out = subprocess.run(
            [tool],
            check=False,
            input="\n".join(symbols),
            capture_output=True,
            text=True,
            timeout=120,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    # llvm-undname echoes each symbol, then its demangled form, then a blank line.
    by_symbol = dict(zip(symbols, names, strict=True))
    lines = out.splitlines()
    result = {}
    for index, line in enumerate(lines[:-1]):
        name = by_symbol.get(line.strip())
        text = lines[index + 1].strip()
        if name is None or not text.endswith(" `RTTI Type Descriptor'"):
            continue
        text = text[: -len(" `RTTI Type Descriptor'")]
        for prefix in ("class ", "struct "):
            if text.startswith(prefix):
                result[name] = text[len(prefix) :]
    return result


class Walker:
    def __init__(self, image: Image):
        self.image = image
        self.ptr = image.pointer_size
        self.data_sections = [s for s in image.sections if not s.executable and s.raw_size]

    # x64 holds RVAs in the RTTI records, x86 VAs.
    def ref(self, value: int) -> int:
        return value if self.image.x64 else value - self.image.base

    def type_name(self, descriptor: int) -> str | None:
        try:
            name = self.image.string(descriptor + 2 * self.ptr, 4000)
        except (ValueError, UnicodeDecodeError):
            return None
        return name if name.startswith(".?A") else None

    def locator(self, rva: int) -> tuple[int, int, int, int] | None:
        """(offset, type descriptor, hierarchy) of a valid locator at rva, as RVAs."""
        image = self.image
        try:
            if image.x64:
                sig, offset, _, td, chd, own = struct.unpack("<6I", image.read(rva, 24))
                if sig != 1 or own != rva:
                    return None
            else:
                sig, offset, _, td, chd = struct.unpack("<5I", image.read(rva, 20))
                if sig != 0:
                    return None
                td, chd = self.ref(td), self.ref(chd)
            if self.type_name(td) is None or image.u32(chd) != 0:
                return None
        except (ValueError, struct.error):
            return None
        return offset, td, chd, rva

    def locators(self) -> list[tuple[int, int, int, int]]:
        found = []
        image = self.image
        if image.x64:
            for section in self.data_sections:
                data = image.section_bytes(section)
                at = data.find(b"\x01\0\0\0")
                while at >= 0:
                    if at % 4 == 0 and at + 24 <= len(data):
                        own = struct.unpack_from("<I", data, at + 20)[0]
                        if own == section.rva + at and (hit := self.locator(own)):
                            found.append(hit)
                    at = data.find(b"\x01\0\0\0", at + 1)
            return found
        descriptors = set()
        for section in self.data_sections:
            data = image.section_bytes(section)
            for match in TYPE_NAME.finditer(data):
                descriptors.add(section.rva + match.start() - 8)
        wanted = {struct.pack("<I", image.base + td) for td in descriptors}
        for section in self.data_sections:
            data = image.section_bytes(section)
            for at in range(12, len(data) - 8, 4):
                if data[at : at + 4] in wanted and (hit := self.locator(section.rva + at - 12)):
                    found.append(hit)
        return found

    def bases(self, hierarchy: int) -> tuple[int, list[Base]]:
        image = self.image
        _, attributes, count, array = struct.unpack("<4I", image.read(hierarchy, 16))
        array = self.ref(array)
        bases = []
        for index in range(min(count, 1024)):
            descriptor = self.ref(image.u32(array + index * 4))
            td, contained, mdisp, pdisp, vdisp, battr = struct.unpack(
                "<IIiiiI", image.read(descriptor, 24)
            )
            mangled = self.type_name(self.ref(td)) or "?"
            bases.append(Base(demangle(mangled), mangled, contained, mdisp, pdisp, vdisp, battr))
        return attributes, bases

    def slots(self, vtable: int) -> list[int]:
        image, result = self.image, []
        for index in range(MAX_SLOTS):
            try:
                target = image.pointer(vtable + index * self.ptr) - image.base
            except ValueError:
                break
            if not image.is_code(target):
                break
            result.append(target)
        return result

    def vtables(self, locators: dict[int, tuple]) -> list[tuple[int, int]]:
        """(vtable RVA, locator RVA) for every slot holding a locator's VA."""
        image = self.image
        values = {image.base + rva: rva for rva in locators}
        fmt = "<Q" if image.x64 else "<I"
        found = []
        for section in self.data_sections:
            data = image.section_bytes(section)
            for at in range(0, len(data) - self.ptr + 1, self.ptr):
                value = struct.unpack_from(fmt, data, at)[0]
                if value in values:
                    found.append((section.rva + at + self.ptr, values[value]))
        return found

    def walk(self) -> list[Class]:
        located = {hit[3]: hit for hit in self.locators()}
        classes: dict[int, Class] = {}
        for rva, (offset, td, chd, _) in sorted(located.items()):
            if td not in classes:
                mangled = self.type_name(td) or "?"
                try:
                    attributes, bases = self.bases(chd)
                except (ValueError, struct.error):
                    attributes, bases = 0, []
                classes[td] = Class(demangle(mangled), mangled, td, chd, attributes, bases)
        for vtable, locator in self.vtables(located):
            offset, td, _, _ = located[locator]
            classes[td].vtables.append(Vtable(vtable, locator, offset, self.slots(vtable)))
        result = sorted(classes.values(), key=lambda c: c.name)
        for cls in result:
            cls.vtables.sort(key=lambda v: (v.offset, v.rva))
        names = undname(
            sorted({c.mangled for c in result if c.name == c.mangled} | {
                b.mangled for c in result for b in c.bases if b.name == b.mangled and b.mangled != "?"
            })
        )  # fmt: skip
        for cls in result:
            cls.name = names.get(cls.mangled, cls.name)
            for base in cls.bases:
                base.name = names.get(base.mangled, base.name)
        return result


def classes(image: Image) -> list[Class]:
    return Walker(image).walk()


def purecalls(image: Image) -> set[int]:
    """RVAs of the `jmp [slot]` thunks to an imported `_purecall`, which is what a pure
    virtual's vtable slot points to when the CRT is a DLL."""
    slots = {row.slot for row in image.imports if row.name in PURECALL}
    if not slots:
        return set()
    return {rva for rva, kind, _ in scan.slot_sites(image, slots) if kind == "jmp"}


def compare(found: list[Class], pure: set[int]) -> None:
    """Set every vtable's base, base_vtable and per-slot states (see the module's comment).
    `found` is the whole walk: a base is looked up among those classes by its decorated name."""
    by_name = {c.mangled: c for c in found}
    for cls in found:
        bases = cls.bases[1:]
        virtual = any(b.pdisp >= 0 for b in bases)
        for vtable in cls.vtables:
            match = None
            for base in bases:
                other = by_name.get(base.mangled)
                if base.pdisp >= 0 or other is None or other is cls:
                    continue
                at = vtable.offset - base.mdisp
                match = next((v for v in other.vtables if v.offset == at), None)
                if match is not None:
                    vtable.base, vtable.base_vtable = other.name, match.rva
                    break
            vtable.states = [
                slot_state(index, slot, match, pure, virtual)
                for index, slot in enumerate(vtable.slots)
            ]


def slot_state(index: int, slot: int, base: Vtable | None, pure: set[int], virtual: bool) -> str:
    if slot in pure:
        return "pure"
    if base is None:
        return "unknown" if virtual else "new"
    if index >= len(base.slots):
        return "new"
    return "inherited" if base.slots[index] == slot else "overridden"
