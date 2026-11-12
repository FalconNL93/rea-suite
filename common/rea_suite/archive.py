"""Archive extraction that keeps Unix permissions and refuses path traversal."""

from __future__ import annotations

import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.xz",
    ".txz",
    ".tar.bz2",
    ".dmg",
    ".7z",
)


def _stripped(name: str, strip: int) -> str | None:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if len(parts) <= strip or ".." in parts:
        return None
    return "/".join(parts[strip:])


def extract(archive: Path, dest: Path, strip: int) -> None:
    """Extract into dest (created if missing); non-archives such as .jar are copied as-is."""
    dest.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".xz") and not archive.name.endswith(".tar.xz"):
        # a single compressed file (frida-server-*.xz)
        target = dest / archive.name[:-3]
        with lzma.open(archive) as src, target.open("wb") as out:
            shutil.copyfileobj(src, out)
        target.chmod(0o755)
    elif not archive.name.endswith(ARCHIVE_SUFFIXES):
        shutil.copy2(archive, dest / archive.name)
    elif archive.name.endswith(".dmg"):
        _extract_dmg(archive, dest)
    elif archive.name.endswith(".7z"):
        _extract_7z(archive, dest, strip)
    elif archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                rel = _stripped(info.filename, strip)
                if rel is None:
                    continue
                target = dest / rel
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out)
                # zipfile drops Unix permissions; restore them (executables!)
                mode = info.external_attr >> 16
                if mode & 0o777:
                    target.chmod(mode & 0o777)
    else:
        with tarfile.open(archive) as tf:
            members = []
            for member in tf.getmembers():
                rel = _stripped(member.name, strip)
                if rel is None:
                    continue
                member.name = rel
                members.append(member)
            tf.extractall(dest, members=members, filter="tar")


def seven_zip() -> str | None:
    """7-Zip of the base suite (apt `7zip`, winget `7zip.7zip`; not on PATH on Windows)."""
    found = next((p for n in ("7zz", "7z", "7za") if (p := shutil.which(n))), None)
    if not found and os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "7-Zip/7z.exe"
        found = str(candidate) if candidate.is_file() else None
    return found


def _extract_7z(archive: Path, dest: Path, strip: int) -> None:
    """7-Zip archives (PCSX2's Windows release); Python has no reader of its own."""
    tool = seven_zip()
    if not tool:
        raise LookupError(f"{archive.name}: 7-Zip is needed; run rea-suite setup")
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        subprocess.run([tool, "x", "-y", "-bso0", "-bsp0", f"-o{tmp}", str(archive)], check=True)
        root = Path(tmp).resolve()
        for path in sorted(root.rglob("*")):
            if path.is_symlink() and not path.resolve().is_relative_to(root):
                raise LookupError(f"{archive.name}: link outside the archive: {path.name}")
            rel = _stripped(path.relative_to(root).as_posix(), strip)
            if rel is None or path.is_dir():
                continue
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(path, target)


def _extract_dmg(archive: Path, dest: Path) -> None:
    """Copy the .app bundles out of a macOS disk image (hdiutil, macOS only)."""
    with tempfile.TemporaryDirectory() as mountpoint:
        subprocess.run(
            [
                "hdiutil",
                "attach",
                "-nobrowse",
                "-readonly",
                "-quiet",
                "-mountpoint",
                mountpoint,
                str(archive),
            ],
            check=True,
        )
        try:
            apps = list(Path(mountpoint).glob("*.app"))
            if not apps:
                raise LookupError(f"{archive.name} contains no .app")
            for app in apps:
                # ditto keeps symlinks, permissions and code signatures inside the bundle
                subprocess.run(["ditto", str(app), str(dest / app.name)], check=True)
        finally:
            subprocess.run(["hdiutil", "detach", "-quiet", mountpoint], check=True)
