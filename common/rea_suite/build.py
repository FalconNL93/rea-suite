"""Source builds for tools without a usable release for this platform (tools.yml `build:`).

Only used when no prebuilt asset exists, and never with REA_TOOLS_NO_BUILD=1. A build
lands in tools/<name>/<version>/ like a download, so it is redone only when the
version (release tag, or commit for `version: head`) changes. Source and build tree of
the newest build stay in .runtime/build/<name>/<version>/; a newer build replaces them,
`rea-suite clean builds` removes them all.

  cargo: <crate>   `cargo install --locked` of that crate at the release version;
                   the Rust toolchain comes from rustup (component `build`) and
                   lives in .runtime/rustup and .runtime/cargo; where the system has
                   only cargo (RHEL), that one builds
  cmake: true      configure and build the source with CMake and Ninja (.venv);
                   `bin:` paths are relative to the build directory
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from . import github
from .archive import extract

BUILD_ROOT = Path(__file__).resolve().parents[2] / ".runtime" / "build"


def build_dir(name: str, version: str) -> Path:
    """.runtime/build/<name>/<version>/, empty; older versions of name are removed."""
    for old in (BUILD_ROOT / name).glob("*"):
        shutil.rmtree(old) if old.is_dir() else old.unlink()
    path = BUILD_ROOT / name / version
    path.mkdir(parents=True)
    return path


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
    """A cargo to build with: rustup's toolchain in .runtime, else the system's cargo."""
    if not shutil.which("rustup") and shutil.which("rustup-init"):
        # Fedora packages only rustup-init; it installs rustup into CARGO_HOME (.runtime)
        print("  rust: installing rustup into .runtime/cargo")
        subprocess.run(
            ["rustup-init", "-y", "--no-modify-path", "--profile", "minimal"], check=True
        )
        os.environ["PATH"] = f"{os.environ['CARGO_HOME']}/bin{os.pathsep}{os.environ['PATH']}"
    if shutil.which("rustup"):
        if subprocess.run(
            ["rustup", "which", "cargo"], capture_output=True, check=False
        ).returncode:
            print("  rust: installing the stable toolchain into .runtime/rustup")
            subprocess.run(
                ["rustup", "toolchain", "install", "stable", "--profile", "minimal"], check=True
            )
            subprocess.run(["rustup", "default", "stable"], check=True)
    elif not shutil.which("cargo"):
        raise BuildUnavailable("needs rustup or cargo (select component `build`, then setup)")


def cargo(crate: str, version: str, dest: Path) -> None:
    """cargo install <crate>@<version> into dest (binaries in dest/bin).

    The crate source lands in .runtime/cargo/registry, the build tree in .runtime/build.
    """
    check_allowed()
    _rust_toolchain()
    work = build_dir(crate, version)
    print(f"  building {crate} {version} with cargo in {work} (only when the version changes)")
    subprocess.run(
        ["cargo", "install", "--locked", "--version", version, "--root", str(dest)]
        + ["--target-dir", str(work / "target"), crate],
        check=True,
    )
    for leftover in (".crates.toml", ".crates2.json"):
        (dest / leftover).unlink(missing_ok=True)


def cmake(name: str, repo: str, ref: str, dest: Path) -> None:
    """Build repo at ref with CMake + Ninja; source in .runtime/build, build tree = dest."""
    check_allowed()
    for tool in ("cmake", "ninja"):
        if not shutil.which(tool):
            raise BuildUnavailable(f"needs {tool} (pyproject.toml; run rea-suite setup)")
    work = build_dir(name, ref[:12])
    print(f"  building {repo} at {ref[:12]} with CMake in {work} (only when it changes)")
    tarball = work / "source.tar.gz"
    github.download(source_tarball(repo, ref), tarball)
    src = work / "src"
    extract(tarball, src, 1)
    tarball.unlink()
    subprocess.run(
        ["cmake", "-S", str(src), "-B", str(dest), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release"],
        check=True,
    )
    subprocess.run(["cmake", "--build", str(dest)], check=True)
