# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml>=6"]
# ///
"""Optional components (common/components.yml) and their selection in .env.

Runs standalone (`uv run common/rea_suite/components.py ...`) so the bootstrap can
use it before .venv exists, and as `rea-tools components ...`.

  select [--defaults]          interactive menu; writes REA_SUITE_COMPONENTS to .env
  list                         all components, selected ones marked
  adopt                        switch on new default components in .env (setup/update)
  selected                     selected names, one per line
  packages apt|brew|winget     system packages of the selected components
                               (brew: as Brewfile lines)
  uv-args                      `--group X` arguments for uv sync
  values <key>                 a list field of the selected components (e.g. playwright)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS_FILE = ROOT / "common" / "components.yml"
ENV_FILE = ROOT / ".env"
KEY = "REA_SUITE_COMPONENTS"
# Components the user has been offered; a new one with `default: true` is switched on
# once (setup/update say so), one the user switched off stays off.
SEEN_KEY = "REA_SUITE_COMPONENTS_SEEN"
# what existed before SEEN_KEY was written, for an older .env
SEEN_BEFORE = ["build", "angr", "steam", "vm"]


def load() -> dict[str, dict]:
    return yaml.safe_load(COMPONENTS_FILE.read_text())["components"]


def env_file_value(key: str) -> str | None:
    """A KEY=value from .env, for runs outside direnv/activate."""
    if not ENV_FILE.exists():
        return None
    for line in ENV_FILE.read_text().splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip().removeprefix("export ").strip() == key:
            return value.strip().strip("\"'")
    return None


def _read_env_file() -> str | None:
    return env_file_value(KEY)


def configured() -> bool:
    return KEY in os.environ or _read_env_file() is not None


def new_defaults() -> list[str]:
    """Components on by default that a .env selection has not seen yet."""
    if _read_env_file() is None or os.environ.get(KEY, _read_env_file()) != _read_env_file():
        return []  # defaults apply anyway, or the run names its components exactly
    seen = (env_file_value(SEEN_KEY) or " ".join(SEEN_BEFORE)).split()
    return [n for n, spec in load().items() if spec.get("default") and n not in seen]


def selected() -> list[str]:
    components = load()
    raw = os.environ.get(KEY)
    if raw is None:
        raw = _read_env_file()
    if raw is None:
        return [name for name, spec in components.items() if spec.get("default")]
    names = raw.replace(",", " ").split() + new_defaults()
    unknown = [n for n in names if n not in components]
    if unknown:
        print(f"warning: unknown component(s) in {KEY}: {', '.join(unknown)}", file=sys.stderr)
    return [n for n in components if n in names]


def optional_tools() -> set[str]:
    """tools.yml entries that belong to some component."""
    return {t for spec in load().values() for t in spec.get("tools", [])}


def selected_tools() -> set[str]:
    components = load()
    return {t for name in selected() for t in components[name].get("tools", [])}


def write_selection(names: list[str]) -> None:
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    values = {KEY: " ".join(names), SEEN_KEY: " ".join(load())}
    for key, value in values.items():
        line = f'{key}="{value}"'
        for i, existing in enumerate(lines):
            if existing.partition("=")[0].removeprefix("export ").strip() == key:
                lines[i] = line
                break
        else:
            if key == KEY:
                lines.append(
                    "# Optional components (common/components.yml); `rea-suite select` edits this"
                )
            lines.append(line)
    ENV_FILE.write_text("\n".join(lines) + "\n")


def adopt() -> None:
    """Record new default components in .env and say which were switched on."""
    added = new_defaults()
    if not added:
        return
    write_selection(selected())
    print(f"new component(s), on by default: {' '.join(added)} (rea-suite select changes it)")


def menu(components: dict[str, dict], chosen: set[str]) -> list[str]:
    """Numbered toggle menu; works in any terminal (Linux, macOS, Windows, WSL)."""
    names = list(components)
    while True:
        print("\nOptional components (toggle with numbers, Enter to confirm):\n")
        for i, name in enumerate(names, 1):
            mark = "x" if name in chosen else " "
            print(f"  {i}) [{mark}] {name:8} {components[name]['description']}")
        answer = input("\nToggle (e.g. `2 4`), `a` all, `n` none, Enter = done: ").strip().lower()
        if not answer:
            return [n for n in names if n in chosen]
        if answer == "a":
            chosen = set(names)
        elif answer == "n":
            chosen = set()
        for token in answer.replace(",", " ").split():
            if token.isdigit() and 1 <= int(token) <= len(names):
                chosen ^= {names[int(token) - 1]}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="components", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("select")
    p.add_argument("--if-unset", action="store_true", help="only when nothing is configured yet")
    p.add_argument("--defaults", action="store_true", help="write the defaults without asking")
    sub.add_parser("list")
    sub.add_parser("adopt")
    sub.add_parser("selected")
    p = sub.add_parser("packages")
    p.add_argument("manager", choices=["apt", "brew", "winget"])
    sub.add_parser("uv-args")
    p = sub.add_parser("values")
    p.add_argument("key", help="a list field, e.g. playwright")
    args = parser.parse_args(argv)

    components = load()
    if args.command == "select":
        if args.if_unset and configured():
            return
        if args.defaults or not sys.stdin.isatty():
            names = selected()
        else:
            names = menu(components, set(selected()))
        write_selection(names)
        print(f'{KEY}="{" ".join(names)}" written to {ENV_FILE}')
    elif args.command == "adopt":
        adopt()
    elif args.command == "list":
        chosen = set(selected())
        for name, spec in components.items():
            print(f"[{'x' if name in chosen else ' '}] {name:8} {spec['description']}")
    elif args.command == "selected":
        print("\n".join(selected()))
    elif args.command == "packages":
        packages = [p for n in selected() for p in components[n].get(args.manager, [])]
        if args.manager == "brew":
            packages = [
                f'cask "{p.removeprefix("cask:")}"' if p.startswith("cask:") else f'brew "{p}"'
                for p in packages
            ]
        print("\n".join(packages))
    elif args.command == "values":
        print("\n".join(v for n in selected() for v in components[n].get(args.key, [])))
    elif args.command == "uv-args":
        print(
            " ".join(f"--group {g}" for n in selected() for g in components[n].get("uv-groups", []))
        )


if __name__ == "__main__":
    main()
