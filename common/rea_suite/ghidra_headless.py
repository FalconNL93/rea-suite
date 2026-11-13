"""The one way the suite runs Ghidra's analyzeHeadless (rea-ghidra, xbox360, xbox, playstation).

Every run is bounded and named:

* a wall-clock limit for the whole process tree (`REA_GHIDRA_IMPORT_TIMEOUT_SECONDS`, default
  below; a command's own `--timeout` wins), stopped cleanly past it (bounded.py);
* the JVM's heap capped by `REA_GHIDRA_MAXMEM` (Ghidra's -Xmx, as `GHIDRA_HEADLESS_MAXMEM`);
* its output in the log the caller names, which every error points to;
* a project path with a component that starts with '.' refused up front, with the reason: Ghidra
  aborts on it ("Path element starting with '.' is not permitted"), the trap of a worktree under
  `.claude/` that CoD1 hit.

The decompiler's limit per function stays `REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS`, read by the
scripts themselves (common/ghidra_scripts/DecompileLimit.java); the environment passes through.

Callers build their argument lists with `command()` and run them with `run()`; `Headless` is the
interface, `AnalyzeHeadless` its one implementation (a stand-in in tests, another engine later).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from rea_suite import bounded

TIMEOUT_SETTING = "REA_GHIDRA_IMPORT_TIMEOUT_SECONDS"
# A 12 MB PE took about 16 minutes to import and analyze (Alan Wake Remastered, 2026-11-10).
DEFAULT_TIMEOUT_SECONDS = 3600
MAXMEM_SETTING = "REA_GHIDRA_MAXMEM"
# Ghidra's own default is 2G, short for a large game; the machine is shared, so not more.
DEFAULT_MAXMEM = "4G"


class GhidraError(ValueError):
    """A run that failed, timed out or was refused; the message names the log."""


def timeout_seconds(environ: Mapping[str, str] | None = None) -> int:
    """The wall-clock limit of one run: the setting, else the default."""
    value = (os.environ if environ is None else environ).get(TIMEOUT_SETTING, "").strip()
    if not value:
        return DEFAULT_TIMEOUT_SECONDS
    if not value.isdigit() or int(value) < 1:
        raise GhidraError(f"{TIMEOUT_SETTING}={value!r}: want a positive number of seconds")
    return int(value)


def maxmem(environ: Mapping[str, str] | None = None) -> str:
    """The JVM's heap limit (Ghidra's MAXMEM syntax: 4G, 6000M)."""
    value = (os.environ if environ is None else environ).get(MAXMEM_SETTING, "").strip()
    return value or DEFAULT_MAXMEM


def dotted_component(project: Path) -> str | None:
    """The first component of the project's absolute path that starts with '.', if any."""
    for part in Path(os.path.abspath(project)).parts:
        if part.startswith(".") and part not in (".", ".."):
            return part
    return None


def check_project(project: Path) -> None:
    part = dotted_component(project)
    if part:
        raise GhidraError(
            f"Ghidra refuses the project folder {project}: its component {part!r} starts with '.'"
            " (Ghidra: \"Path element starting with '.' is not permitted\"). Put the project"
            " elsewhere (--project, or REA_GHIDRA_PROJECTS), e.g. outside a worktree under .claude/"
        )


class Headless(Protocol):
    """Runs Ghidra headless; `AnalyzeHeadless` is the one implementation."""

    def command(self, project: Path, name: str, *arguments: str) -> list[str]:
        """The full command line for a project, its name and analyzeHeadless's arguments."""
        ...

    def run(
        self, command: Sequence[str], log: Path, timeout: float | None = None, check: bool = True
    ) -> int:
        """Runs a command from `command()` into the log, bounded; returns the exit code."""
        ...


class AnalyzeHeadless:
    """Ghidra's support/analyzeHeadless of one install."""

    def __init__(self, install: Path, environ: Mapping[str, str] | None = None) -> None:
        self.install = Path(install)
        self.environ = dict(os.environ if environ is None else environ)

    @property
    def executable(self) -> Path:
        name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        return self.install / "support" / name

    def command(self, project: Path, name: str, *arguments: str) -> list[str]:
        return [str(self.executable), str(project), name, *arguments]

    def run(
        self, command: Sequence[str], log: Path, timeout: float | None = None, check: bool = True
    ) -> int:
        project = Path(command[1])
        check_project(project)
        limit = timeout if timeout is not None else timeout_seconds(self.environ)
        env = {**self.environ, "GHIDRA_HEADLESS_MAXMEM": maxmem(self.environ)}
        project.mkdir(parents=True, exist_ok=True)
        log.parent.mkdir(parents=True, exist_ok=True)
        try:
            with log.open("w") as stream:
                return bounded.run(command, project, stream, limit, env=env)
        except subprocess.TimeoutExpired as exc:
            raise GhidraError(
                f"Ghidra ran past {limit:g}s and was stopped ({TIMEOUT_SETTING} or the command's"
                f" --timeout raise it); see {log}"
            ) from exc
        except subprocess.CalledProcessError as exc:
            if not check:
                return exc.returncode
            raise GhidraError(f"Ghidra exited with {exc.returncode}; see {log}") from exc
        except OSError as exc:
            raise GhidraError(f"Ghidra did not start ({exc}); run rea-suite setup") from exc


def install_dir(environ: Mapping[str, str] | None = None) -> Path:
    value = (os.environ if environ is None else environ).get("GHIDRA_INSTALL_DIR")
    if not value:
        raise GhidraError("GHIDRA_INSTALL_DIR missing; run through rea-suite")
    return Path(value)


def headless(install: Path | None = None) -> Headless:
    """The runner for an install (default: GHIDRA_INSTALL_DIR)."""
    return AnalyzeHeadless(install if install is not None else install_dir())


def run(command: Sequence[str], log: Path, timeout: float | None = None, check: bool = True) -> int:
    """Runs a command whose first element is an install's analyzeHeadless."""
    install = Path(command[0]).parent.parent
    return headless(install).run(command, log, timeout, check)
