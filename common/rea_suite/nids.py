"""NID names for Sony's firmware imports, whatever the console: the interface a name source
implements, and the table built from one. A console module (rea-suite psp, ps3) brings its own
source and its own hash; this module only holds the shape they share.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class NidEntry:
    nid: int
    module: str
    name: str
    kind: str  # "function" or "variable"
    hashed: bool  # the NID is the hash of the name (else only a table lists it)


class NidSource(Protocol):
    """Where NID names come from; each console has one implementation today."""

    def describe(self) -> str: ...

    def entries(self) -> Iterable[NidEntry]: ...


class NidTable:
    """Every name a source gives, by NID; a module narrows the choice where names collide."""

    def __init__(self, source: NidSource):
        self.source = source
        self.by_nid: dict[int, list[NidEntry]] = {}
        for entry in source.entries():
            rows = self.by_nid.setdefault(entry.nid, [])
            if entry not in rows:
                rows.append(entry)

    def __len__(self) -> int:
        return len(self.by_nid)

    def name(self, value: int, module: str | None = None) -> str:
        rows = self.by_nid.get(value, [])
        if module is not None:
            rows = [r for r in rows if r.module == module] or rows
        return rows[0].name if rows else ""
