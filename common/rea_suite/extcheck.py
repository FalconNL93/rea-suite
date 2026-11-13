"""Whether a Ghidra extension is in place for the installed Ghidra, from its files alone.

Used by the console commands' `check` (rea-suite gamecube, rea-suite psp). It does not start
Ghidra: a headless import that proves the loader works goes through the suite's one Ghidra runner.
"""

from __future__ import annotations

import re
from pathlib import Path

from rea_suite.ghidra import ghidra_version
from rea_suite.ghidra_headless import install_dir


def problem(install: Path, directory: str, required: list[str], fix: str) -> str | None:
    """Why Ghidra would not load the extension in Ghidra/Extensions/<directory>; None if in place.

    Ghidra skips an extension whose extension.properties names another Ghidra version, so a
    release built for 12.1 does not load in 12.1.4."""
    ext = install / "Ghidra" / "Extensions" / directory
    props = ext / "extension.properties"
    want = ghidra_version(install)
    if not props.is_file() or not any((ext / "lib").glob("*.jar")):
        return f"{directory} is not installed for Ghidra {want}; {fix}"
    missing = [name for name in required if not (ext / name).is_file()]
    if missing:
        return f"{directory} lacks {', '.join(missing)}; {fix}"
    match = re.search(r"^version=(.+)$", props.read_text(), re.MULTILINE)
    if not match or match[1].strip() != want:
        found = match[1].strip() if match else "none"
        return f"{directory} is built for Ghidra {found}, not {want}; {fix}"
    return None


def check(directory: str, required: list[str], fix: str, what: str) -> int:
    """Print the outcome as doctor shows it; 0 when the extension is in place."""
    try:
        install = install_dir()
        found = problem(install, directory, required, fix)
    except (OSError, ValueError, AttributeError) as exc:  # AttributeError: no application.version
        print(exc)
        return 1
    if found:
        print(found)
        return 1
    print(f"{directory} in place for Ghidra {ghidra_version(install)} ({what}; files only)")
    return 0
