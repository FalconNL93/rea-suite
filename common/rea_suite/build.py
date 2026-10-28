"""Source builds for tools without a usable release for this platform (tools.yml `build:`).

Only used when no prebuilt asset exists, and never with REA_TOOLS_NO_BUILD=1. A build
lands in tools/<name>/<version>/ like a download, so it is redone only when the
version (release tag, or commit for `version: head`) changes.

  cargo: <crate>   `cargo install --locked` of that crate at the release version;
                   the Rust toolchain comes from rustup (component `build`) and
                   lives in .runtime/rustup and .runtime/cargo
  cmake: true      configure and build the source with CMake and Ninja (.venv);
                   `bin:` paths are relative to the build directory
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import github
from .archive import extract


class BuildUnavailable(Exception):
    """The build cannot run here (switched off or a toolchain is missing)."""


def check_allowed() -> None:
    if os.environ.get("REA_TOOLS_NO_BUILD"):
        raise BuildUnavailable("no prebuilt release for this platform and source builds are off")


def head_commit(repo: str) -> str:
    """Commit of the default branch, without spending GitHub API requests."""
    out = subprocess.run(
        ["git", "ls-remote", f"https://github.com/{repo}.git", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return out.split()[0]


def source_tarball(repo: str, ref: str) -> str:
    if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return f"https://github.com/{repo}/archive/{ref}.tar.gz"
    return github.source_url(repo, ref)


def _rust_toolchain() -> None:
    if not shutil.which("rustup"):
        raise BuildUnavailable("needs rustup (select component `build`, then rea-suite setup)")
    if subprocess.run(["rustup", "which", "cargo"], capture_output=True, check=False).returncode:
        print("  rust: installing the stable toolchain into .runtime/rustup")
        subprocess.run(
            ["rustup", "toolchain", "install", "stable", "--profile", "minimal"], check=True
        )
        subprocess.run(["rustup", "default", "stable"], check=True)


def cargo(crate: str, version: str, dest: Path) -> None:
    """cargo install <crate>@<version> into dest (binaries in dest/bin)."""
    check_allowed()
    _rust_toolchain()
    print(f"  building {crate} {version} with cargo (only when the version changes)")
    subprocess.run(
        ["cargo", "install", "--locked", "--version", version, "--root", str(dest), crate],
        check=True,
    )
    for leftover in (".crates.toml", ".crates2.json"):
        (dest / leftover).unlink(missing_ok=True)


def cmake(repo: str, ref: str, dest: Path) -> None:
    """Build the source of repo at ref with CMake + Ninja; the build tree becomes dest."""
    check_allowed()
    for tool in ("cmake", "ninja"):
        if not shutil.which(tool):
            raise BuildUnavailable(f"needs {tool} (pyproject.toml; run rea-suite setup)")
    print(f"  building {repo} at {ref[:12]} with CMake (only when it changes)")
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        tarball = Path(tmp) / "source.tar.gz"
        github.download(source_tarball(repo, ref), tarball)
        src = Path(tmp) / "src"
        extract(tarball, src, 1)
        subprocess.run(
            ["cmake", "-S", str(src), "-B", str(dest), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release"],
            check=True,
        )
        subprocess.run(["cmake", "--build", str(dest)], check=True)
