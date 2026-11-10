"""A PE image as the suite's scanners read it: a thin layer over pefile.

pefile parses the headers, sections, imports, delay imports, exports, base relocations and the
TLS directory; this layer gives them one shape (RVAs throughout, IAT slots by RVA) and adds what
pefile leaves raw: RVA to file offset over the section table, pointer reads, the x64 unwind table
(RUNTIME_FUNCTION) with chained entries followed to their primary function, which is how a
scanner names the function an address lies in. Relocations are optional: a fixed-base image has
none, and nothing here needs them. x86 (PE32) and x64 (PE32+) images both work; the unwind
table exists only in x64 images.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

import pefile

EXECUTE = 0x20000000  # IMAGE_SCN_MEM_EXECUTE
CODE = 0x20  # IMAGE_SCN_CNT_CODE
WRITE = 0x80000000  # IMAGE_SCN_MEM_WRITE
CHAININFO = 0x4  # UNW_FLAG_CHAININFO


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    size: int  # virtual size
    offset: int  # file offset of the raw data
    raw_size: int
    flags: int

    @property
    def end(self) -> int:
        return self.rva + max(self.size, self.raw_size)

    @property
    def executable(self) -> bool:
        return bool(self.flags & (EXECUTE | CODE))

    @property
    def writable(self) -> bool:
        return bool(self.flags & WRITE)


@dataclass(frozen=True)
class Import:
    dll: str
    name: str | None  # None when imported by ordinal
    ordinal: int | None
    slot: int  # RVA of the IAT slot the loader writes
    delay: bool = False

    @property
    def label(self) -> str:
        return f"{self.dll}!{self.name if self.name else f'#{self.ordinal}'}"


@dataclass(frozen=True)
class Export:
    name: str | None
    ordinal: int
    rva: int
    forwarder: str | None = None


class Image:
    """One PE image, read-only. Addresses are RVAs unless a name says VA."""

    def __init__(self, data: bytes, path: Path | None = None):
        self.data = bytes(data)
        self.path = path
        try:
            self.pe = pefile.PE(data=self.data, fast_load=True)
        except pefile.PEFormatError as exc:
            raise ValueError(f"not a PE image: {exc}") from exc
        header = self.pe.OPTIONAL_HEADER
        self.x64 = header.Magic == 0x20B
        self.machine = self.pe.FILE_HEADER.Machine
        self.base = header.ImageBase
        self.entry = header.AddressOfEntryPoint
        self.size_of_image = header.SizeOfImage
        self.size_of_headers = header.SizeOfHeaders
        self.sections = [
            Section(
                s.Name.rstrip(b"\0").decode("ascii", "replace"),
                s.VirtualAddress,
                s.Misc_VirtualSize,
                s.PointerToRawData,
                s.SizeOfRawData,
                s.Characteristics,
            )
            for s in self.pe.sections
        ]
        self._starts = [s.rva for s in self.sections]

    @classmethod
    def open(cls, path: Path) -> Image:
        return cls(Path(path).read_bytes(), Path(path))

    @property
    def pointer_size(self) -> int:
        return 8 if self.x64 else 4

    def directory(self, index: int) -> tuple[int, int]:
        entries = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if index >= len(entries):
            return 0, 0
        return entries[index].VirtualAddress, entries[index].Size

    # --- addresses -------------------------------------------------------------------------

    def section_at(self, rva: int) -> Section | None:
        index = bisect.bisect_right(self._starts, rva) - 1
        if index >= 0 and rva < self.sections[index].end:
            return self.sections[index]
        return None

    def offset(self, rva: int, size: int = 1) -> int:
        """File offset of size bytes at rva; ValueError when the file does not hold them."""
        if 0 <= rva and rva + size <= self.size_of_headers:
            return rva
        section = self.section_at(rva)
        if section is not None:
            relative = rva - section.rva
            if relative + size <= section.raw_size and section.offset + relative + size <= len(
                self.data
            ):
                return section.offset + relative
        raise ValueError(f"RVA {rva:#x}+{size:#x} is not backed by file bytes")

    def rva_of_offset(self, offset: int) -> int | None:
        if offset < self.size_of_headers:
            return offset
        for s in self.sections:
            if s.offset <= offset < s.offset + s.raw_size:
                return s.rva + offset - s.offset
        return None

    def va(self, rva: int) -> int:
        return self.base + rva

    def rva(self, va: int) -> int:
        return va - self.base

    def address(self, value: int) -> int:
        """An address given by a person: a VA when at or above the image base, else an RVA."""
        return value - self.base if self.base and value >= self.base else value

    # --- reads -----------------------------------------------------------------------------

    def read(self, rva: int, size: int) -> bytes:
        at = self.offset(rva, size)
        return self.data[at : at + size]

    def u16(self, rva: int) -> int:
        return struct.unpack("<H", self.read(rva, 2))[0]

    def u32(self, rva: int) -> int:
        return struct.unpack("<I", self.read(rva, 4))[0]

    def u64(self, rva: int) -> int:
        return struct.unpack("<Q", self.read(rva, 8))[0]

    def pointer(self, rva: int) -> int:
        """A pointer-sized value (a VA as the file holds it)."""
        return self.u64(rva) if self.x64 else self.u32(rva)

    def string(self, rva: int, limit: int = 4096) -> str:
        """A NUL-terminated ASCII string; ValueError when unterminated or not ASCII."""
        at = self.offset(rva)
        end = self.data.find(b"\0", at, at + limit + 1)
        if end < 0:
            raise ValueError(f"no string terminator within {limit} bytes at {rva:#x}")
        return self.data[at:end].decode("ascii")

    def section_bytes(self, section: Section) -> bytes:
        return self.data[section.offset : section.offset + min(section.raw_size, section.end)]

    def code_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable and s.raw_size]

    def is_code(self, rva: int) -> bool:
        section = self.section_at(rva)
        return section is not None and section.executable

    # --- directories -----------------------------------------------------------------------

    def _parse(self, *names: str) -> None:
        wanted = [pefile.DIRECTORY_ENTRY[n] for n in names]
        self.pe.parse_data_directories(directories=wanted)

    @cached_property
    def imports(self) -> list[Import]:
        """Every imported function, the delay-loaded ones too, with its IAT slot."""
        self._parse("IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT")
        result = []
        for attribute, delay in (
            ("DIRECTORY_ENTRY_IMPORT", False),
            ("DIRECTORY_ENTRY_DELAY_IMPORT", True),
        ):
            for entry in getattr(self.pe, attribute, []):
                dll = entry.dll.decode("ascii", "replace")
                for function in entry.imports:
                    name = function.name.decode("ascii", "replace") if function.name else None
                    result.append(
                        Import(dll, name, function.ordinal if not name else None,
                               function.address - self.base, delay)
                    )  # fmt: skip
        return result

    @cached_property
    def iat_slots(self) -> dict[int, Import]:
        return {row.slot: row for row in self.imports}

    @cached_property
    def exports(self) -> list[Export]:
        self._parse("IMAGE_DIRECTORY_ENTRY_EXPORT")
        directory = getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None)
        if directory is None:
            return []
        return [
            Export(
                e.name.decode("ascii", "replace") if e.name else None,
                e.ordinal,
                e.address,
                e.forwarder.decode("ascii", "replace") if e.forwarder else None,
            )
            for e in directory.symbols
        ]

    @cached_property
    def relocations(self) -> dict[int, int]:
        """RVA of every relocated slot and its type; empty for a fixed-base image."""
        if not self.directory(5)[1]:
            return {}
        self._parse("IMAGE_DIRECTORY_ENTRY_BASERELOC")
        result = {}
        for block in getattr(self.pe, "DIRECTORY_ENTRY_BASERELOC", []):
            for entry in block.entries:
                if entry.type:  # type 0 pads a block
                    result[entry.rva] = entry.type
        return result

    @cached_property
    def tls(self) -> dict | None:
        """The TLS directory: template range, index slot and callbacks (as VAs)."""
        if not self.directory(9)[1]:
            return None
        self._parse("IMAGE_DIRECTORY_ENTRY_TLS")
        found = getattr(self.pe, "DIRECTORY_ENTRY_TLS", None)
        if found is None:
            return None
        s = found.struct
        callbacks = []
        if s.AddressOfCallBacks:
            at = s.AddressOfCallBacks - self.base
            for _ in range(256):
                value = self.pointer(at)
                if not value:
                    break
                callbacks.append(value)
                at += self.pointer_size
        return {
            "start": s.StartAddressOfRawData,
            "end": s.EndAddressOfRawData,
            "index": s.AddressOfIndex,
            "zero_fill": s.SizeOfZeroFill,
            "callbacks": callbacks,
        }

    @cached_property
    def runtime_functions(self) -> list[tuple[int, int, int]]:
        """The x64 unwind table: (begin, end, unwind info) RVAs, sorted; empty for x86."""
        rva, size = self.directory(3)
        if not self.x64 or not rva or size < 12:
            return []
        try:
            table = self.read(rva, size - size % 12)
        except ValueError:
            return []
        return sorted(row for row in struct.iter_unpack("<III", table) if row[0] < row[1])

    @cached_property
    def _function_starts(self) -> list[int]:
        return [row[0] for row in self.runtime_functions]

    def function_at(self, rva: int) -> tuple[int, int] | None:
        """The function rva lies in, from the unwind table, with chained parts followed to
        their primary entry: (begin, end) of the primary part. None in x86 images or when no
        entry covers rva (leaf functions without unwind data have none)."""
        rows = self.runtime_functions
        index = bisect.bisect_right(self._function_starts, rva) - 1
        if index < 0 or not rows[index][0] <= rva < rows[index][1]:
            return None
        begin, end, unwind = rows[index]
        for _ in range(32):
            try:
                header = self.read(unwind, 4)
            except ValueError:
                break
            if not (header[0] >> 3) & CHAININFO:
                break
            codes = (header[2] + 1) & ~1
            try:
                begin, end, unwind = struct.unpack("<III", self.read(unwind + 4 + codes * 2, 12))
            except ValueError:
                break
        return begin, end
