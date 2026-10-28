"""Ghidra extensions, kept in step with the installed Ghidra version.

Extensions are version-locked to Ghidra. For every Ghidra install they are
resolved again: a prebuilt release zip for that exact Ghidra version is used
when one exists, otherwise (with `build: true`) the release's source is built
with Ghidra's own Gradle wrapper. Results land in <ghidra>/Ghidra/Extensions,
which Ghidra treats as installed for both the GUI and analyzeHeadless.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import build, github
from .archive import extract

MARKER = ".rea-suite.json"


def ghidra_version(install: Path) -> str:
    props = (install / "Ghidra" / "application.properties").read_text()
    return re.search(r"^application\.version=(.+)$", props, re.MULTILINE).group(1).strip()


def extensions_dir(install: Path) -> Path:
    return install / "Ghidra" / "Extensions"


def installed(install: Path) -> dict[str, dict]:
    """Extensions managed by rea-suite in this Ghidra install: name -> marker."""
    result = {}
    for marker in extensions_dir(install).glob(f"*/{MARKER}"):
        result[marker.parent.name] = json.loads(marker.read_text())
    return result


def native_decompiler(install: Path, platform: str = "mac_arm_64") -> Path | None:
    """The decompiler binary for a platform, shipped (os/) or built (build/os/)."""
    feature = install / "Ghidra" / "Features" / "Decompiler"
    for path in (feature / "os" / platform, feature / "build" / "os" / platform):
        if (path / "decompile").is_file():
            return path / "decompile"
    return None


def build_natives(install: Path) -> bool:
    """Build the macOS natives (decompiler, demanglers) in place; the release zip has none."""
    if native_decompiler(install):
        print("  ghidra natives: mac_arm_64 present")
        return True
    if os.environ.get("REA_TOOLS_NO_BUILD"):
        print("  warning: ghidra natives: none for mac_arm_64 and source builds are off")
        return False
    print("  ghidra natives: building for mac_arm_64 (gradlew buildNatives)")
    gradlew = install / "support" / "gradle" / "gradlew"
    try:
        subprocess.run(
            [str(gradlew), "--no-daemon", "--quiet", "buildNatives"], cwd=gradlew.parent, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"  warning: ghidra natives: build FAILED ({exc})")
        return False
    return True


def sync(install: Path, specs: dict[str, dict], force: bool = False) -> list[str]:
    """Install/update the configured extensions; returns names that failed."""
    version = ghidra_version(install)
    target_root = extensions_dir(install)
    target_root.mkdir(parents=True, exist_ok=True)
    current = installed(install)

    for name in set(current) - set(specs):
        print(f"  ghidra extension {name}: no longer configured, removing")
        shutil.rmtree(target_root / name)

    failed = []
    for name, spec in specs.items():
        try:
            _sync_one(install, version, name, spec, current.get(name), force)
        except (OSError, subprocess.CalledProcessError, LookupError) as exc:
            print(f"  ghidra extension {name}: FAILED ({exc})")
            failed.append(name)
    return failed


def _sync_one(
    install: Path, version: str, name: str, spec: dict, marker: dict | None, force: bool
) -> None:
    repo = spec["github"]
    pinned = str(spec.get("version", "latest"))
    pattern = re.compile(spec["asset"].replace("{ghidra}", re.escape(version)))
    candidates = [github.release(repo, pinned)] if pinned != "latest" else github.releases(repo)

    # Newest release that ships a build for this exact Ghidra version.
    newest, tag, asset = None, None, None
    for release in candidates:
        newest = newest or release
        matches = sorted(a["name"] for a in release["assets"] if pattern.search(a["name"]))
        if matches:
            tag = release["tag_name"]
            asset = next(a for a in release["assets"] if a["name"] == matches[-1])
            break
    if asset is None:
        if marker and marker["ghidra"] == version and os.environ.get("REA_TOOLS_NO_BUILD"):
            print(
                f"  ghidra extension {name}: {marker['tag']} kept (built earlier; builds are off)"
            )
            return
        if not spec.get("build") or os.environ.get("REA_TOOLS_NO_BUILD"):
            raise LookupError(f"no release has a build for Ghidra {version} (source build off)")
        tag = newest["tag_name"]
    source = "release" if asset else "built"

    up_to_date = marker and (marker["tag"], marker["ghidra"], marker["source"]) == (
        tag,
        version,
        source,
    )
    if up_to_date and not force:
        print(f"  ghidra extension {name}: {tag} ({source}) is up to date")
        return

    with tempfile.TemporaryDirectory(dir=extensions_dir(install)) as tmp:
        work = Path(tmp)
        if asset:
            print(f"  ghidra extension {name}: installing {tag} for Ghidra {version}")
            archive = work / asset["name"]
            github.download(asset["browser_download_url"], archive)
        else:
            print(f"  ghidra extension {name}: no build for Ghidra {version}, building {tag}")
            archive = _build(install, repo, tag, spec, work)

        extract(archive, work / "unpacked", 0)
        props = next((work / "unpacked").rglob("extension.properties"), None)
        if props is None:
            raise LookupError(f"{archive.name} contains no extension.properties")
        dest = extensions_dir(install) / name
        if dest.exists():
            shutil.rmtree(dest)
        props.parent.rename(dest)
        if source == "built":
            # Built against this Ghidra; some sources hardcode another version,
            # which Ghidra would reject.
            props = dest / "extension.properties"
            text = re.sub(
                r"^version=.*$", f"version={version}", props.read_text(), flags=re.MULTILINE
            )
            props.write_text(text)
        marker = {"tag": tag, "ghidra": version, "source": source, "repo": repo}
        (dest / MARKER).write_text(json.dumps(marker, indent=2) + "\n")


def _build(install: Path, repo: str, tag: str, spec: dict, work: Path) -> Path:
    # Source and build tree stay in .runtime/build/ghidra-<repo>/<tag>-<ghidra>/.
    repo_name = repo.rsplit("/", 1)[1]
    work = build.build_dir(f"ghidra-{repo_name}", f"{tag}-{ghidra_version(install)}")
    tarball = work / "source.tar.gz"
    github.download(github.source_url(repo, tag), tarball)
    # Gradle names the extension after the project directory, so use the repo name.
    project = work / "src" / repo_name
    extract(tarball, project, 1)
    tarball.unlink()
    project = project / spec.get("subdir", "")
    gradlew = install / "support" / "gradle" / ("gradlew.bat" if os.name == "nt" else "gradlew")
    subprocess.run(
        [str(gradlew), "--no-daemon", "--quiet", f"-PGHIDRA_INSTALL_DIR={install.resolve()}"],
        cwd=project,
        check=True,
        env={**os.environ, "GHIDRA_INSTALL_DIR": str(install.resolve())},
    )
    built = sorted((project / "dist").glob("*.zip"))
    if not built:
        raise LookupError("Gradle build produced no dist/*.zip")
    return built[-1]
