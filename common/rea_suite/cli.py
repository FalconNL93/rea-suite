"""Install and update the tools listed in common/tools.yml."""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "common" / "tools.yml"
TOOLS_DIR = ROOT / "tools"
BIN_DIR = TOOLS_DIR / "bin"
STATE_FILE = TOOLS_DIR / "state.json"
PLATFORM = "windows" if os.name == "nt" else "linux"


@dataclass
class Tool:
    name: str
    version: str = "latest"
    github: str | None = None
    dotnet_tool: str | None = None
    assets: dict[str, str] = field(default_factory=dict)
    strip: int = 0
    bin: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def from_manifest(cls, name: str, spec: dict) -> Tool:
        return cls(
            name=name,
            version=str(spec.get("version", "latest")),
            github=spec.get("github"),
            dotnet_tool=spec.get("dotnet-tool"),
            assets=spec.get("assets", {}),
            strip=int(spec.get("strip", 0)),
            bin=spec.get("bin", {}),
        )

    @property
    def supported(self) -> bool:
        return self.dotnet_tool is not None or PLATFORM in self.assets


def load_tools() -> dict[str, Tool]:
    data = yaml.safe_load(MANIFEST.read_text())
    return {name: Tool.from_manifest(name, spec) for name, spec in data["tools"].items()}


def load_state() -> dict[str, str]:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def save_state(state: dict[str, str]) -> None:
    TOOLS_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# --- GitHub releases ---------------------------------------------------------


def github_api(path: str) -> dict:
    req = urllib.request.Request(f"https://api.github.com/{path}")
    req.add_header("Accept", "application/vnd.github+json")
    if token := os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def github_release(tool: Tool) -> dict:
    if tool.version == "latest":
        return github_api(f"repos/{tool.github}/releases/latest")
    return github_api(f"repos/{tool.github}/releases/tags/{tool.version}")


def pick_asset(tool: Tool, release: dict) -> dict:
    pattern = re.compile(tool.assets[PLATFORM])
    matches = [a for a in release["assets"] if pattern.search(a["name"])]
    if len(matches) != 1:
        names = ", ".join(a["name"] for a in release["assets"])
        raise SystemExit(
            f"{tool.name}: expected one asset matching {pattern.pattern!r} in "
            f"{release['tag_name']}, found {len(matches)}. Available: {names}"
        )
    return matches[0]


def download(url: str, dest: Path) -> None:
    print(f"  downloading {url}")
    with urllib.request.urlopen(url, timeout=60) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out, length=1 << 20)


def _stripped(name: str, strip: int) -> str | None:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if len(parts) <= strip or ".." in parts:
        return None
    return "/".join(parts[strip:])


def extract(archive: Path, dest: Path, strip: int) -> None:
    dest.mkdir(parents=True)
    if archive.name.endswith(".zip"):
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


def install_github(tool: Tool, state: dict[str, str], force_latest: bool) -> None:
    if force_latest and tool.version != "latest":
        print(f"{tool.name}: pinned to {tool.version}")
    release = github_release(tool)
    tag = release["tag_name"]
    tool_dir = TOOLS_DIR / tool.name
    dest = tool_dir / tag
    if state.get(tool.name) == tag and dest.exists():
        print(f"{tool.name}: {tag} is up to date")
        link_tool(tool, dest)
        return

    asset = pick_asset(tool, release)
    print(f"{tool.name}: installing {tag} ({asset['name']})")
    tool_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tool_dir) as tmp:
        archive = Path(tmp) / asset["name"]
        download(asset["browser_download_url"], archive)
        staging = Path(tmp) / "extract"
        extract(archive, staging, tool.strip)
        if dest.exists():
            shutil.rmtree(dest)
        staging.rename(dest)

    previous = state.get(tool.name)
    state[tool.name] = tag
    save_state(state)
    link_tool(tool, dest)
    if previous and previous != tag and (tool_dir / previous).exists():
        print(f"  previous version kept at {tool_dir / previous} (rea-suite prune removes it)")


# --- dotnet tools ------------------------------------------------------------


def install_dotnet(tool: Tool, state: dict[str, str], force_latest: bool) -> None:
    if not shutil.which("dotnet"):
        print(f"{tool.name}: skipped, dotnet SDK not found")
        return
    tool_path = TOOLS_DIR / tool.name
    installed = (tool_path / ".store" / tool.dotnet_tool.lower()).exists()
    if installed and not force_latest and tool.version == "latest":
        print(f"{tool.name}: already installed")
    else:
        action = "update" if installed else "install"
        cmd = ["dotnet", "tool", action, "--tool-path", str(tool_path), tool.dotnet_tool]
        if tool.version != "latest":
            cmd += ["--version", tool.version]
        print(f"{tool.name}: dotnet tool {action}")
        subprocess.run(cmd, check=True)
    exe = tool.dotnet_tool + (".exe" if PLATFORM == "windows" else "")
    state[tool.name] = "dotnet-tool"
    save_state(state)
    write_launcher(tool.name, tool_path / exe, {}, tool_path)


# --- launchers ---------------------------------------------------------------


def link_tool(tool: Tool, dest: Path) -> None:
    current = TOOLS_DIR / tool.name / "current"
    try:
        if current.is_symlink() or current.exists():
            current.unlink()
        current.symlink_to(dest.name, target_is_directory=True)
        base = current
    except OSError:
        base = dest  # no symlink privilege on Windows
    for name, spec in tool.bin.get(PLATFORM, {}).items():
        if isinstance(spec, str):
            spec = {"path": spec}
        matches = sorted(glob.glob(str(dest / spec["path"]), recursive=True))
        if not matches:
            print(f"  warning: {spec['path']} not found in {dest}")
            continue
        target = base / Path(matches[-1]).relative_to(dest)
        write_launcher(name, target, spec.get("env", {}), base)


def write_launcher(name: str, target: Path, env: dict[str, str], tool_dir: Path) -> None:
    """Write tools/bin/<name>; paths are relative so the tree survives being moved/mounted."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    rel_target = os.path.relpath(target, BIN_DIR)
    rel_dir = os.path.relpath(tool_dir, BIN_DIR)
    if PLATFORM == "windows":
        here = "%~dp0"
        lines = ["@echo off", "setlocal"]
        lines += [f'set "{k}={v.replace("{dir}", here + rel_dir)};%{k}%"' for k, v in env.items()]
        lines.append(f'call "{here}{rel_target}" %*')
        (BIN_DIR / f"{name}.cmd").write_text("\r\n".join(lines) + "\r\n")
        return
    if not target.is_dir():
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    here = '$(dirname -- "$0")'
    lines = ["#!/bin/sh", "# generated by rea-suite; do not edit"]
    for k, v in env.items():
        value = v.replace("{dir}", f"{here}/{rel_dir}")
        lines.append(f'export {k}="{value}${{{k}:+:${k}}}"')
    lines.append(f'exec "{here}/{rel_target}" "$@"')
    launcher = BIN_DIR / name
    launcher.write_text("\n".join(lines) + "\n")
    launcher.chmod(0o755)


# --- commands ----------------------------------------------------------------


def select(tools: dict[str, Tool], names: list[str]) -> list[Tool]:
    unknown = [n for n in names if n not in tools]
    if unknown:
        raise SystemExit(f"unknown tool(s): {', '.join(unknown)}; see {MANIFEST}")
    chosen = [tools[n] for n in names] if names else list(tools.values())
    for tool in chosen:
        if names and not tool.supported:
            print(f"{tool.name}: not available on {PLATFORM}")
    return [t for t in chosen if t.supported]


def cmd_install(args: argparse.Namespace, force_latest: bool = False) -> None:
    state = load_state()
    tools = load_tools()
    for tool in select(tools, args.tools):
        if tool.dotnet_tool:
            install_dotnet(tool, state, force_latest)
        elif force_latest or not (TOOLS_DIR / tool.name / state.get(tool.name, "?")).is_dir():
            install_github(tool, state, force_latest)
        else:
            print(f"{tool.name}: {state[tool.name]} installed (use `update` for newer releases)")
            link_tool(tool, TOOLS_DIR / tool.name / state[tool.name])


def cmd_update(args: argparse.Namespace) -> None:
    cmd_install(args, force_latest=True)


def cmd_status(args: argparse.Namespace) -> None:
    state = load_state()
    for tool in select(load_tools(), args.tools):
        installed = state.get(tool.name, "-")
        latest = "-"
        if tool.github:
            try:
                latest = github_release(tool)["tag_name"]
            except OSError as exc:
                latest = f"? ({exc})"
        marker = "" if latest in ("-", installed) else "  <- update available"
        print(f"{tool.name:10} installed={installed:28} release={latest}{marker}")


def cmd_prune(args: argparse.Namespace) -> None:
    state = load_state()
    for tool in select(load_tools(), args.tools):
        tool_dir = TOOLS_DIR / tool.name
        if not tool.github or not tool_dir.is_dir():
            continue
        for entry in tool_dir.iterdir():
            if entry.name in ("current", state.get(tool.name)) or not entry.is_dir():
                continue
            print(f"removing {entry}")
            shutil.rmtree(entry)


def cmd_asset(args: argparse.Namespace) -> None:
    """Print `<tag> <url>` of the latest release asset matching a regex (for shell scripts)."""
    tool = Tool(name=args.repo, github=args.repo, assets={PLATFORM: args.pattern})
    release = github_release(tool)
    print(release["tag_name"], pick_asset(tool, release)["browser_download_url"])


def main() -> None:
    parser = argparse.ArgumentParser(prog="rea-suite", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func, help_text in [
        ("install", cmd_install, "install missing tools"),
        ("update", cmd_update, "update tools to the newest (or pinned) release"),
        ("status", cmd_status, "show installed and released versions"),
        ("prune", cmd_prune, "remove inactive versions"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("tools", nargs="*", help="tool names (default: all)")
        p.set_defaults(func=func)
    p = sub.add_parser("asset", help="print tag and URL of the latest matching release asset")
    p.add_argument("repo", help="GitHub owner/repo")
    p.add_argument("pattern", help="regex for the asset name")
    p.set_defaults(func=cmd_asset)
    sys.stdout.reconfigure(line_buffering=True)
    args = parser.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)


if __name__ == "__main__":
    main()
