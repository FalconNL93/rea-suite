# /// script
# requires-python = ">=3.12"
# ///
"""Put the suite's bin/ on the user's PATH (Linux and macOS shells).

Runs standalone (`uv run common/rea_suite/userpath.py ...`) from bin/rea-suite;
platforms/windows/rea-suite.ps1 does the same in the user's registry PATH.

  add     write the PATH block into the user's shell startup file, once
  check   exit 1 when no startup file puts bin/ on PATH

The block sits between markers and is the only thing this ever writes or replaces;
the rest of the file is left as it is. A startup file that already names bin/ is not
touched. The block itself checks PATH before adding, so a shell never gets it twice.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "bin"
BEGIN, END = "# >>> rea-suite >>>", "# <<< rea-suite <<<"

POSIX_BLOCK = f"""{BEGIN}
# rea-suite entry points (rea-suite, rea, rea-ghidra); `rea-suite setup` keeps this block
case ":$PATH:" in
  *":{BIN}:"*) ;;
  *) export PATH="{BIN}:$PATH" ;;
esac
{END}
"""
FISH_BLOCK = f"""{BEGIN}
# rea-suite entry points (rea-suite, rea, rea-ghidra); `rea-suite setup` keeps this file
contains -- {BIN} $PATH; or set -gx PATH {BIN} $PATH
{END}
"""


def startup_files() -> list[tuple[Path, str]]:
    """The files to write: the login shell's rc file, plus fish when it is configured."""
    home = Path.home()
    shell = Path(os.environ.get("SHELL", "")).name
    files = []
    if shell == "zsh" or (home / ".zshrc").exists():
        files.append((Path(os.environ.get("ZDOTDIR", home)) / ".zshrc", POSIX_BLOCK))
    if shell == "bash" or (home / ".bashrc").exists():
        files.append((home / ".bashrc", POSIX_BLOCK))
    if shell == "fish" or (home / ".config" / "fish" / "config.fish").exists():
        files.append((home / ".config" / "fish" / "conf.d" / "rea-suite.fish", FISH_BLOCK))
    return files or [(home / ".profile", POSIX_BLOCK)]


def update(path: Path, block: str) -> str:
    """Add or refresh the block in one file; returns what happened."""
    text = path.read_text() if path.exists() else ""
    marked = re.compile(rf"{re.escape(BEGIN)}\n.*?{re.escape(END)}\n?", re.DOTALL)
    current = marked.search(text)
    if current and current.group(0).rstrip("\n") == block.rstrip("\n"):
        return "already there"
    if not current and str(BIN) in text:
        return "already names bin/ (left as it is)"
    if current:
        text = marked.sub(lambda _: block, text, count=1)  # checkout moved: our block only
        action = "updated"
    else:
        text += ("" if text.endswith("\n") or not text else "\n") + "\n" + block
        action = "added"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return action


def cmd_add(_: argparse.Namespace) -> None:
    if os.environ.get("REA_SUITE_NO_PATH"):
        print("  PATH: skipped (REA_SUITE_NO_PATH)")
        return
    for path, block in startup_files():
        result = update(path, block)
        print(f"  PATH: {path}: {result}")
        if result in ("added", "updated"):
            print("  open a new shell (or source that file) to use rea-suite from anywhere")


def cmd_check(_: argparse.Namespace) -> None:
    found = [p for p, _ in startup_files() if p.exists() and str(BIN) in p.read_text()]
    print(", ".join(map(str, found)) or "not on PATH")
    sys.exit(0 if found else 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("add").set_defaults(func=cmd_add)
    sub.add_parser("check").set_defaults(func=cmd_check)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
