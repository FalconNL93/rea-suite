"""A CD image's ISO 9660 file listing with each file's LBA: cooked 2048-byte images (.iso), raw
2352-byte ones (.bin, Mode 1 or Mode 2 Form 1, found by the sync pattern) and a .cue's first data
file. What `rea-suite playstation lba-table` matches a game's tables against.

Only the primary volume descriptor's tree is read (no Joliet, no Rock Ridge: a PS1 disc has
neither); directories are walked once each and the listing is capped, so a damaged or crafted
image cannot loop. Names are the target's text: print them through text.printable().
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

SECTOR = 2048
RAW = 2352
SYNC = b"\x00" + b"\xff" * 10 + b"\x00"
MAX_FILES = 200_000


@dataclass(frozen=True)
class DiscFile:
    path: str
    lba: int
    size: int


class SectorImage:
    """2048-byte user data by LBA, whatever the image stores per sector."""

    def __init__(self, path: Path):
        self.path = path
        with path.open("rb") as f:
            head = f.read(16)
        self.raw = head[:12] == SYNC and path.stat().st_size % RAW == 0
        self.stride = RAW if self.raw else SECTOR

    def read(self, lba: int, count: int = 1) -> bytes:
        out = bytearray()
        with self.path.open("rb") as f:
            for n in range(lba, lba + count):
                f.seek(n * self.stride)
                sector = f.read(self.stride)
                if len(sector) < self.stride:
                    raise ValueError(f"sector {n} lies outside {self.path.name}")
                if self.raw:  # Mode 1: data after the 16-byte header; Mode 2: after the subheader
                    sector = sector[16:] if sector[15] == 1 else sector[24:]
                out += sector[:SECTOR]
        return bytes(out)


def cue_data_file(cue: Path) -> Path:
    """The first FILE a .cue names (the data track of a PS1 disc)."""
    for line in cue.read_text(encoding="utf-8", errors="replace").splitlines():
        found = re.match(r'\s*FILE\s+(?:"([^"]+)"|(\S+))', line, re.IGNORECASE)
        if found:
            return cue.parent / (found.group(1) or found.group(2))
    raise ValueError(f"{cue.name}: no FILE line")


def open_image(path: Path) -> SectorImage:
    return SectorImage(cue_data_file(path) if path.suffix.lower() == ".cue" else path)


def records(data: bytes):
    """(name, lba, size, is_directory) of each directory record in a directory's extent."""
    at = 0
    while at < len(data):
        length = data[at]
        if length == 0:  # records do not cross sectors: the rest of this one is padding
            at = (at // SECTOR + 1) * SECTOR
            continue
        if length < 34 or at + length > len(data):
            break
        lba, size = struct.unpack_from("<I4xI", data, at + 2)
        flags, name_len = data[at + 25], data[at + 32]
        name = data[at + 33 : at + 33 + name_len]
        if name not in (b"\0", b"\1"):
            yield name.decode("ascii", "replace").split(";")[0], lba, size, bool(flags & 2)
        at += length


def listing(image: SectorImage, limit: int = MAX_FILES) -> list[DiscFile]:
    """Every file under the root, in path order."""
    pvd = image.read(16)
    if pvd[1:6] != b"CD001":
        raise ValueError(f"{image.path.name}: no ISO 9660 volume descriptor at sector 16")
    root_lba, root_size = struct.unpack_from("<I4xI", pvd, 156 + 2)
    files: list[DiscFile] = []
    seen: set[int] = set()
    pending = [("", root_lba, root_size)]
    while pending:
        prefix, lba, size = pending.pop()
        if lba in seen:
            continue
        seen.add(lba)
        for name, at, length, directory in records(image.read(lba, -(-size // SECTOR))):
            path = f"{prefix}/{name}" if prefix else name
            if directory:
                pending.append((path, at, length))
            else:
                files.append(DiscFile(path, at, length))
                if len(files) > limit:
                    raise ValueError(f"more than {limit} files: not a disc this reads")
    return sorted(files, key=lambda f: f.path)


def read_listing(text: str, origin: str = "listing") -> list[DiscFile]:
    """A listing as `lba-table --list` prints it: `<lba> <size> <path>` a line, `#` comments."""
    files = []
    for number, line in enumerate(text.splitlines(), 1):
        words = line.split("#", 1)[0].split(None, 2)
        if not words:
            continue
        if len(words) != 3:
            raise ValueError(f"{origin}:{number}: expected '<lba> <size> <path>'")
        files.append(DiscFile(words[2].strip(), int(words[0], 0), int(words[1], 0)))
    return files
