"""Read-only game containers behind one interface: a tree of files listed and copied out, whatever
holds them (a ZArchive .zar/.wua, an Xbox XDVDFS disc image, ...).

A reader implements `Container`; `open_container()` picks the reader by the file's own bytes, never by
its name. The shared `listing()` and `extract()` do the rest, so every format lists and extracts the
same way. Names come from the target: a reader keeps only safe path components (`safe_name()`), and
`extract()` checks once more that every target stays under the output folder. Printing goes through
text.printable().
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from rea_suite.text import printable

# Characters no path component may hold on any platform the suite runs on (Windows' set; '/' and NUL
# everywhere). A target's name with one of them is skipped and reported, not rewritten.
_FORBIDDEN = set('/\\:*?"<>|\0')
# Deeper than any game's tree; stops a crafted directory cycle or chain.
MAX_DEPTH = 64
# More than any disc or archive holds; bounds the memory a crafted table can claim.
MAX_ENTRIES = 1_000_000


@dataclass(frozen=True)
class Entry:
    """One file or directory: its path inside the container ('/'-separated, no leading slash)."""

    path: str
    size: int
    is_dir: bool
    # The reader's own locator (an offset, a node index); opaque to everyone else.
    ref: int = 0


@dataclass
class Tree:
    """What a reader found: the entries, and the names it refused with the reason."""

    entries: list[Entry] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


class Container(Protocol):
    """A read-only tree of files. One implementation per format."""

    format: str

    def tree(self) -> Tree: ...

    def read(self, entry: Entry) -> Iterator[bytes]:
        """The file's bytes in chunks, exactly `entry.size` of them."""
        ...

    def describe(self) -> dict:
        """Format details for `info` (offsets, sizes, versions), JSON-ready."""
        ...

    def close(self) -> None: ...


def safe_name(name: str) -> bool:
    """A single path component that cannot climb out of, or reach past, its folder."""
    return bool(name) and name not in (".", "..") and not (_FORBIDDEN & set(name))


def find(tree: Tree, path: str) -> Entry | None:
    """The entry at path, compared without case as both formats' own readers do."""
    want = path.strip("/").replace("\\", "/").lower()
    for entry in tree.entries:
        if entry.path.lower() == want:
            return entry
    return None


def select(tree: Tree, paths: list[str]) -> list[Entry]:
    """The files named, and every entry under a directory named; everything when none is named.
    Directories come along so that an empty one is made too."""
    if not paths:
        return list(tree.entries)
    chosen: dict[str, Entry] = {}
    for path in paths:
        hit = find(tree, path)
        if hit is None:
            raise ValueError(f"not in the container: {printable(path)}")
        if hit.is_dir:
            prefix = hit.path.lower() + "/"
            chosen[hit.path] = hit
            for e in tree.entries:
                if e.path.lower().startswith(prefix):
                    chosen[e.path] = e
        else:
            chosen[hit.path] = hit
    return list(chosen.values())


def listing(tree: Tree) -> str:
    """A TSV: size and path per file, directories with a trailing slash."""
    lines = ["size\tpath"]
    for e in tree.entries:
        lines.append(f"\t{printable(e.path)}/" if e.is_dir else f"{e.size}\t{printable(e.path)}")
    return "\n".join(lines) + "\n"


def target(root: Path, path: str) -> Path:
    """Where path goes under root; refused if it would land anywhere else."""
    parts = path.split("/")
    if not all(safe_name(p) for p in parts):
        raise ValueError(f"unsafe path in the container: {printable(path)}")
    out = root.joinpath(*parts)
    if os.path.commonpath([root.resolve(), out.resolve()]) != str(root.resolve()):
        raise ValueError(f"path leaves the output folder: {printable(path)}")
    return out


def extract(container: Container, entries: list[Entry], root: Path) -> int:
    """Copy the entries under root (created); returns the bytes written."""
    root.mkdir(parents=True, exist_ok=True)
    written = 0
    for entry in entries:
        out = target(root, entry.path)
        if entry.is_dir:
            out.mkdir(parents=True, exist_ok=True)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with out.open("wb") as f:
            for chunk in container.read(entry):
                f.write(chunk)
                size += len(chunk)
        if size != entry.size:
            raise ValueError(f"{printable(entry.path)}: read {size} of {entry.size} bytes")
        written += size
    return written


def summary(container: Container, tree: Tree) -> dict:
    files = [e for e in tree.entries if not e.is_dir]
    info = {
        "format": container.format,
        **container.describe(),
        "files": len(files),
        "directories": len(tree.entries) - len(files),
        "bytes": sum(e.size for e in files),
    }
    if tree.skipped:
        info["skipped"] = tree.skipped
    return info


def emit(args: argparse.Namespace, text: str) -> None:
    if args.output:
        target = (args.caller_cwd / args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    else:
        sys.stdout.write(text)


def run(container: Container, args: argparse.Namespace, extra: dict | None = None) -> int:
    """info, list or extract on an open container; shared with `rea-suite xbox360 disc`."""
    tree = container.tree()
    if args.action == "info":
        emit(args, json.dumps({**summary(container, tree), **(extra or {})}, indent=1))
        if not args.output:
            sys.stdout.write("\n")
    elif args.action == "list":
        emit(args, listing(tree))
    else:
        chosen = select(tree, args.paths)
        root = (args.caller_cwd / args.output).resolve()
        written = extract(container, chosen, root)
        files = sum(1 for e in chosen if not e.is_dir)
        print(f"{root}: {files} file(s), {written} bytes", file=sys.stderr)
    for note in tree.skipped:
        print(f"skipped: {note}", file=sys.stderr)
    return 0


def add_actions(sub, what: str) -> None:
    """The info/list/extract subcommands, the same for every container command."""
    for action, text in (
        ("info", f"the {what}'s format details as JSON"),
        ("list", "size and path of every file (TSV)"),
        ("extract", "files or folders named, or everything, into a folder"),
    ):
        q = sub.add_parser(action, help=text)
        q.add_argument("file", type=Path)
        if action == "extract":
            q.add_argument("paths", nargs="*", help="paths inside (default: everything)")
        q.add_argument("-o", "--output", type=Path, required=action == "extract")
