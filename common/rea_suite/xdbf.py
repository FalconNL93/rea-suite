"""XDBF, the Xbox 360's database container: a title's SPA (achievements, strings, images, presence)
and a profile's GPD use it.

Layout (big-endian; Xenia's kernel/util/xdbf_utils.h, free60's XDBF page): a 24-byte header
(`XDBF`, version, entry table length, entry count, free table length, free count), the entry
table (namespace u16, id u64, offset u32, length u32), the free table (offset u32, length u32),
then the data, each entry's offset counted from its start. Every offset is checked against the
file, so a damaged or hostile one is refused with XdbfError instead of read past its end.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"XDBF"
HEADER = 24
ENTRY = 18
FREE = 8
# A title's SPA has tens of entries; a profile's GPD a few thousand.
MAX_ENTRIES = 65536

# Namespaces of a title's SPA (a GPD numbers its own differently).
METADATA, IMAGE, STRINGS = 1, 2, 3
NAMESPACES = {METADATA: "metadata", IMAGE: "image", STRINGS: "strings"}


class XdbfError(ValueError):
    """Not an XDBF, or one this reader cannot or will not read."""


class Reader:
    """Big-endian reads that refuse to leave the buffer."""

    def __init__(self, data: bytes, what: str = "XDBF"):
        self.data = data
        self.what = what

    def check(self, offset: int, size: int) -> int:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise XdbfError(
                f"{self.what}: offset 0x{offset:x}+{size} is outside its {len(self.data)} bytes"
            )
        return offset

    def u16(self, offset: int) -> int:
        return struct.unpack_from(">H", self.data, self.check(offset, 2))[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from(">I", self.data, self.check(offset, 4))[0]

    def bytes(self, offset: int, size: int) -> bytes:
        return self.data[self.check(offset, size) : offset + size]


@dataclass(frozen=True)
class Entry:
    """One entry: its namespace, its id and its bytes."""

    namespace: int
    id: int
    data: bytes

    @property
    def magic(self) -> bytes:
        """A metadata entry's id is its section's four-letter name (XACH, XSTC, ...)."""
        return self.id.to_bytes(8, "big")[4:] if self.id < 1 << 32 else b""


@dataclass(frozen=True)
class Xdbf:
    version: int
    entries: list[Entry]

    def find(self, namespace: int, entry_id: int) -> Entry | None:
        return next((e for e in self.entries if (e.namespace, e.id) == (namespace, entry_id)), None)


def read(data: bytes) -> Xdbf:
    """Every entry of an XDBF file, in the order of its entry table."""
    r = Reader(data)
    if r.bytes(0, 4) != MAGIC:
        raise XdbfError("not an XDBF (no XDBF magic)")
    version, table, count, free_table = (r.u32(4 + 4 * k) for k in range(4))
    if count > table or table > MAX_ENTRIES or free_table > MAX_ENTRIES:
        raise XdbfError(f"{count} of {table} entries, {free_table} free (at most {MAX_ENTRIES})")
    start = HEADER + table * ENTRY + free_table * FREE
    r.check(0, start)
    entries = []
    for i in range(count):
        namespace, entry_id, offset, length = struct.unpack(
            ">HQII", r.bytes(HEADER + i * ENTRY, ENTRY)
        )
        entries.append(Entry(namespace, entry_id, r.bytes(start + offset, length)))
    return Xdbf(version, entries)
