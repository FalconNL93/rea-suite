"""Archive extraction that keeps Unix permissions and refuses path traversal."""

from __future__ import annotations

import shutil
import tarfile
import zipfile
from pathlib import Path

ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2")


def _stripped(name: str, strip: int) -> str | None:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if len(parts) <= strip or ".." in parts:
        return None
    return "/".join(parts[strip:])


def extract(archive: Path, dest: Path, strip: int) -> None:
    """Extract into dest (created); non-archives such as .jar are copied as-is."""
    dest.mkdir(parents=True)
    if not archive.name.endswith(ARCHIVE_SUFFIXES):
        shutil.copy2(archive, dest / archive.name)
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
