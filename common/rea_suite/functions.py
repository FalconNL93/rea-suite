"""A port's index of the guest functions it has identified, and the gate that checks it.

  rea-suite functions <config> check          every entry: a function starts there and its
                                              signature matches; exit 1 on a mismatch, 2 when
                                              the index has no entries
  rea-suite functions <config> add <game> <address> <name> <what> [<where>]
                                              a new entry (its signature computed, checked today)
  rea-suite functions <config> find <text>    entries whose name, address, text or place has it
  rea-suite functions <config> convert <game> <legacy.tsv>
                                              rows of an older address/name/hash/what table

The index is a TSV (game, address, name, what, where, signature, checked) and holds no game
bytes: the signature is a truncated SHA-256 over the function's bytes. A JSON config names it
and, per game (a title can have several executables), the executable:

  {"index": "functions.tsv",
   "games": {"sp": {"image": "xex/default.bin", "base": "0x82000000",
                    "partition": "../src/generated/codegen.partition.json"},
             "pc": {"image": "${GAME_DIR:-../game}/Game.exe", "entries": "function_entries.tsv",
                    "signature": "body"}}}

Paths are relative to the config's folder; ${NAME} and ${NAME:-default} take the environment.
With "base" the image is a flat memory image at that address (an Xbox 360 image from
`rea-suite xbox360 extract`); without it, a PE (x86, x64 or any other) mapped through its own
section table at its ImageBase. Function starts come from codegen's "partition" (its
"assignments") or an "entries" TSV (the first column, hex, under a header: `rea-ghidra
functions` output fits); without either, check compares signatures alone. "signature" is "head"
(the default: the first 32 bytes, 12 hex digits) or "body" (from the entry to the next function
start, at most 64 KiB, 16 hex digits; needs the starts). This is the format of the PPC gate in
games/rexglue-sdk (scripts/xbox360/function_index.py), whose configs work here unchanged.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import datetime
import hashlib
import json
import os
import re
from pathlib import Path

import pefile

FIELDS = ["game", "address", "name", "what", "where", "signature", "checked"]
HEAD = 32
MAX_BODY = 0x10000
DIGITS = {"head": 12, "body": 16}
VARIABLE = re.compile(r"\$\{(\w+)(?::-([^}]*))?\}")


class Problem(Exception):
    """A config, image or argument the command cannot use; exits 1 with the message."""


def expand(text: str) -> str:
    def value(m: re.Match) -> str:
        found = os.environ.get(m[1])
        if found:
            return found
        if m[2] is None:
            raise Problem(f"{m[1]} is not set (needed by {text})")
        return m[2]

    return VARIABLE.sub(value, text)


def address(text: str) -> int:
    try:
        return int(text, 16)
    except ValueError:
        raise Problem(f"not a hex address: {text!r}") from None


class Image:
    """The bytes of one game's executable at its virtual addresses."""

    def __init__(self, path: Path, base: int | None):
        if not path.is_file():
            raise Problem(f"{path} is missing: the executable (or its extracted image) is needed")
        self.path = path
        if base is not None:
            self.data, self.base, self.pe = path.read_bytes(), base, None
            return
        try:
            self.pe = pefile.PE(str(path), fast_load=True)
        except pefile.PEFormatError as exc:
            raise Problem(f"{path}: not a PE ({exc}); give a 'base' for a flat image") from None
        self.base = self.pe.OPTIONAL_HEADER.ImageBase

    def read(self, start: int, size: int) -> bytes:
        offset = start - self.base
        if offset < 0:
            return b""
        if self.pe is None:
            return self.data[offset : offset + size]
        try:
            return self.pe.get_data(offset, size)
        except pefile.PEFormatError:
            return b""


class Index:
    def __init__(self, config: Path, images: dict[str, Path] | None = None):
        self.root = config.parent
        try:
            self.config = json.loads(config.read_text(encoding="utf-8"))
            self.path = self.root / self.config["index"]
            self.games = self.config["games"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise Problem(f"{config}: not a function index config ({exc})") from None
        self.overrides = images or {}
        self._images: dict[str, Image] = {}
        self._starts: dict[str, list[int] | None] = {}

    def game(self, name: str) -> dict:
        if name not in self.games:
            raise Problem(f"unknown game {name!r}: the config has {', '.join(sorted(self.games))}")
        return self.games[name]

    def kind(self, name: str) -> str:
        kind = self.game(name).get("signature", "head")
        if kind not in DIGITS:
            raise Problem(f"game {name}: signature is 'head' or 'body', not {kind!r}")
        return kind

    def image(self, name: str) -> Image:
        if name not in self._images:
            g = self.game(name)
            path = self.overrides.get(name) or self.root / expand(g["image"])
            base = address(g["base"]) if "base" in g else None
            self._images[name] = Image(path, base)
        return self._images[name]

    def starts(self, name: str) -> list[int] | None:
        """Sorted function entries of the game, or None when the config gives none here."""
        if name not in self._starts:
            g, found = self.game(name), None
            if (part := g.get("partition")) and (self.root / expand(part)).is_file():
                text = (self.root / expand(part)).read_text(encoding="utf-8")
                found = sorted(address(k) for k in json.loads(text)["assignments"])
            elif (entries := g.get("entries")) and (self.root / expand(entries)).is_file():
                lines = (self.root / expand(entries)).read_text(encoding="utf-8").splitlines()
                found = sorted(address(line.split("\t")[0]) for line in lines[1:] if line.strip())
            self._starts[name] = found
        return self._starts[name]

    def starts_at(self, name: str, at: int) -> bool:
        found = self.starts(name)
        if found is None:
            return True
        i = bisect.bisect_left(found, at)
        return i < len(found) and found[i] == at

    def signature(self, name: str, at: int) -> str:
        """The function's signature, or "" when its bytes are outside the image."""
        image, kind = self.image(name), self.kind(name)
        if kind == "head":
            data = image.read(at, HEAD)
            return hashlib.sha256(data).hexdigest()[:12] if len(data) == HEAD else ""
        found = self.starts(name)
        if found is None:
            raise Problem(f"game {name}: a 'body' signature needs 'entries' or 'partition'")
        i = bisect.bisect_right(found, at)
        end = min(found[i] if i < len(found) else at + MAX_BODY, at + MAX_BODY)
        data = image.read(at, end - at)
        return hashlib.sha256(data).hexdigest()[:16] if data else ""

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f, delimiter="\t"))

    def save(self, rows: list[dict]) -> None:
        rows.sort(key=lambda r: (r["game"], int(r["address"], 16)))
        with self.path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, FIELDS, delimiter="\t", lineterminator="\n")
            w.writeheader()
            w.writerows(rows)


def row(game: str, at: int, name: str, what: str, where: str, sig: str, checked: str) -> dict:
    values = [game, name, what, where]
    if any(c in v for v in values for c in "\t\r\n") or not name.strip() or " " in name:
        raise Problem("the name is one word; no field holds a tab or a line break")
    return {
        "game": game,
        "address": f"0x{at:08X}",
        "name": name,
        "what": what,
        "where": where,
        "signature": sig,
        "checked": checked,
    }


def check(index: Index) -> int:
    rows, bad = index.load(), 0
    if not rows:
        print(f"{index.path}: no entries to check")
        return 2
    for r in rows:
        at = int(r["address"], 16)
        problems = []
        if not index.starts_at(r["game"], at):
            problems.append("no function starts there")
        if index.signature(r["game"], at) != r["signature"]:
            problems.append("signature differs (the function moved or changed)")
        if problems:
            bad += 1
            print(f"FAIL  {r['game']} {r['address']} {r['name']}: {'; '.join(problems)}")
    print(f"{len(rows) - bad}/{len(rows)} entries match")
    return 1 if bad else 0


def add(index: Index, game: str, at_text: str, name: str, what: str, where: str = "") -> int:
    at = address(at_text)
    if not index.starts_at(game, at):
        print(f"{game} {at_text}: no function starts there (the config's function starts)")
        return 1
    sig = index.signature(game, at)
    if not sig:
        print(f"{game} {at_text}: outside the image")
        return 1
    new = row(game, at, name, what, where, sig, datetime.date.today().isoformat())
    rows = [r for r in index.load() if not (r["game"] == game and int(r["address"], 16) == at)]
    index.save([*rows, new])
    print(f"added {game} 0x{at:08X} {name}")
    return 0


def find(index: Index, text: str) -> int:
    t = text.lower()
    for r in index.load():
        if t in " ".join((r["address"], r["name"], r["what"], r["where"])).lower():
            print(f"{r['game']} {r['address']} {r['name']}: {r['what']} ({r['where']})")
    return 0


def convert(index: Index, game: str, legacy: Path) -> int:
    """Rows of a four-column address/name/hash/what table become this game's entries."""
    want = DIGITS[index.kind(game)]
    lines = legacy.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].split("\t")[:3] != ["address", "name", "hash"]:
        raise Problem(f"{legacy}: not an address/name/hash/what table")
    new = []
    for line in lines[1:]:
        if not line.strip():
            continue
        at, name, sig, what = (line.split("\t", 3) + [""])[:4]
        if len(sig) != want:
            kind = index.kind(game)
            raise Problem(f"{legacy}: hash {sig!r} is not a {kind} signature ({want} digits)")
        new.append(row(game, address(at), name, what, "", sig, ""))
    keep = {(game, int(r["address"], 16)) for r in new}
    rows = [r for r in index.load() if (r["game"], int(r["address"], 16)) not in keep]
    index.save(rows + new)
    print(f"converted {len(new)} entries of {legacy.name} into {index.path} as {game}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite functions",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    p.add_argument(
        "--image",
        action="append",
        default=[],
        metavar="GAME=PATH",
        help="this file instead of the config's image for GAME",
    )
    p.add_argument("config", type=Path)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="every entry still matches (exit 1 on a mismatch, 2 for none)")
    a = sub.add_parser("add", help="record a function")
    for name in ("game", "address", "name", "what"):
        a.add_argument(name)
    a.add_argument("where", nargs="?", default="")
    f = sub.add_parser("find", help="entries containing the text")
    f.add_argument("text")
    c = sub.add_parser("convert", help="import an address/name/hash/what table")
    c.add_argument("game")
    c.add_argument("legacy", type=Path)
    args = p.parse_args(argv)
    try:
        images = {}
        for item in args.image:
            game, sep, path = item.partition("=")
            if not sep:
                p.error(f"--image takes GAME=PATH, not {item!r}")
            images[game] = (args.caller_cwd / path).resolve()
        index = Index((args.caller_cwd / args.config).resolve(), images)
        if args.command == "check":
            return check(index)
        if args.command == "add":
            return add(index, args.game, args.address, args.name, args.what, args.where)
        if args.command == "find":
            return find(index, args.text)
        return convert(index, args.game, (args.caller_cwd / args.legacy).resolve())
    except (Problem, OSError, ValueError) as exc:
        p.exit(1, f"functions: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
