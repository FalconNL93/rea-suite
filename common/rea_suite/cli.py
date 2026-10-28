"""Install and update the tools listed in common/tools.yml."""

from __future__ import annotations

import argparse
import glob
import importlib.metadata
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import build, components, ghidra, github
from .archive import extract

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "common" / "tools.yml"
TOOLS_DIR = ROOT / "tools"
BIN_DIR = TOOLS_DIR / "bin"
STATE_FILE = TOOLS_DIR / "state.json"
PLATFORM = {"nt": "windows"}.get(os.name) or ("macos" if sys.platform == "darwin" else "linux")


@dataclass
class Tool:
    name: str
    version: str = "latest"
    github: str | None = None
    dotnet_tool: str | None = None
    url: dict[str, str] = field(default_factory=dict)
    assets: dict[str, str] = field(default_factory=dict)
    strip: int = 0
    bin: dict[str, dict] = field(default_factory=dict)
    ghidra_extensions: dict[str, dict] = field(default_factory=dict)
    plugins: dict[str, dict] = field(default_factory=dict)
    build: dict = field(default_factory=dict)
    follows_pip: bool = False

    @classmethod
    def from_manifest(cls, name: str, spec: dict) -> Tool:
        version = str(spec.get("version", "latest"))
        return cls(
            name=name,
            version=resolve_version(version),
            follows_pip=version.startswith("pip:"),
            build=spec.get("build") or {},
            github=spec.get("github"),
            dotnet_tool=spec.get("dotnet-tool"),
            url=spec.get("url") or {},
            assets=spec.get("assets", {}),
            strip=int(spec.get("strip", 0)),
            bin=spec.get("bin", {}),
            ghidra_extensions=spec.get("ghidra-extensions") or {},
            plugins=spec.get("plugins") or {},
        )

    @property
    def supported(self) -> bool:
        return (
            self.dotnet_tool is not None
            or PLATFORM in self.assets
            or "any" in self.assets
            or PLATFORM in self.url
            or bool(self.build)
        )

    @property
    def needs_build(self) -> bool:
        """No prebuilt asset for this platform: built from source (tools.yml `build:`)."""
        return bool(self.build) and PLATFORM not in self.assets and "any" not in self.assets


def resolve_version(version: str) -> str:
    """`pip:<package>`: the installed version of that package in .venv, else latest."""
    if not version.startswith("pip:"):
        return version
    try:
        return importlib.metadata.version(version[4:])
    except importlib.metadata.PackageNotFoundError:
        return "latest"


def load_tools() -> dict[str, Tool]:
    data = yaml.safe_load(MANIFEST.read_text())
    return {name: Tool.from_manifest(name, spec) for name, spec in data["tools"].items()}


def load_state() -> dict[str, str]:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def save_state(state: dict[str, str]) -> None:
    TOOLS_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# --- GitHub release tools ----------------------------------------------------


def pick_assets(tool: Tool, release: dict) -> list[dict]:
    patterns = tool.assets.get(PLATFORM) or tool.assets["any"]
    picked = []
    for pattern in [patterns] if isinstance(patterns, str) else patterns:
        regex = re.compile(pattern)
        matches = [a for a in release["assets"] if regex.search(a["name"])]
        if len(matches) != 1:
            names = ", ".join(a["name"] for a in release["assets"])
            raise SystemExit(
                f"{tool.name}: expected one asset matching {pattern!r} in "
                f"{release['tag_name']}, found {len(matches)}. Available: {names}"
            )
        picked.append(matches[0])
    return picked


def install_github(tool: Tool, state: dict[str, str], force_latest: bool) -> None:
    if force_latest and tool.version not in ("latest", "head"):
        print(f"{tool.name}: pinned to {tool.version}")
    if tool.version == "head":
        commit = build.head_commit(tool.github)
        release, tag = {"tag_name": commit}, commit[:12]
    else:
        release = github.release(tool.github, tool.version)
        tag = release["tag_name"]
    tool_dir = TOOLS_DIR / tool.name
    dest = tool_dir / tag
    if state.get(tool.name) == tag and dest.exists():
        print(f"{tool.name}: {tag} is up to date")
        activate(tool, dest)
        return

    tool_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tool_dir) as tmp:
        staging = Path(tmp) / "extract"
        if tool.needs_build:
            print(f"{tool.name}: no prebuilt {tag} for {PLATFORM}, building from source")
            try:
                if "cargo" in tool.build:
                    build.cargo(tool.build["cargo"], tag.removeprefix("v"), staging)
                else:
                    build.cmake(tool.name, tool.github, release["tag_name"], staging)
            except build.BuildUnavailable as exc:
                print(f"  skipped: {exc}")
                return
        else:
            assets = pick_assets(tool, release)
            print(f"{tool.name}: installing {tag} ({', '.join(a['name'] for a in assets)})")
            for asset in assets:
                archive = Path(tmp) / asset["name"]
                github.download(asset["browser_download_url"], archive)
                extract(archive, staging, tool.strip)
        if dest.exists():
            shutil.rmtree(dest)
        staging.rename(dest)

    previous = state.get(tool.name)
    state[tool.name] = tag
    save_state(state)
    activate(tool, dest)
    if previous and previous != tag and (tool_dir / previous).exists():
        print(
            f"  previous version kept at {tool_dir / previous} "
            f"(`rea-tools use {tool.name} {previous}` rolls back, `rea-tools prune` removes it)"
        )


# --- direct downloads (self-updating tools such as steamcmd) --------------------


def install_url(tool: Tool, state: dict[str, str], force: bool) -> None:
    dest = TOOLS_DIR / tool.name / tool.version
    if dest.is_dir() and not force:
        print(f"{tool.name}: {tool.version} installed")
        activate(tool, dest)
        return
    if dest.is_dir():
        print(
            f"{tool.name}: {tool.version} updates itself; `rea-tools reinstall {tool.name}` refetches"
        )
        activate(tool, dest)
        return
    url = tool.url[PLATFORM]
    print(f"{tool.name}: installing from {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        archive = Path(tmp) / url.rsplit("/", 1)[1]
        github.download(url, archive)
        extract(archive, Path(tmp) / "x", tool.strip)
        (Path(tmp) / "x").rename(dest)
    state[tool.name] = tool.version
    save_state(state)
    activate(tool, dest)


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


# --- activation: current link, launchers, Ghidra extensions -------------------


def activate(tool: Tool, dest: Path, force_extensions: bool = False) -> None:
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
        write_launcher(name, target, spec.get("env", {}), base, jar=spec.get("jar", False))
    if tool.name == "ghidra" and PLATFORM == "macos":
        ghidra.build_natives(dest)
    if tool.ghidra_extensions:
        failed = ghidra.sync(dest, tool.ghidra_extensions, force=force_extensions)
        if failed:
            print(f"  warning: Ghidra extension(s) not installed: {', '.join(failed)}")
    if tool.plugins:
        sync_plugins(dest, tool.plugins)


def sync_plugins(dest: Path, specs: dict[str, dict]) -> None:
    """Copy files from plugin releases into a tool's install dir (e.g. x64dbg plugins)."""
    marker_file = dest / ".rea-suite-plugins.json"
    markers = json.loads(marker_file.read_text()) if marker_file.exists() else {}
    for name, spec in specs.items():
        release = github.release(spec["github"], str(spec.get("version", "latest")))
        tag = release["tag_name"]
        if markers.get(name) == tag:
            print(f"  plugin {name}: {tag} is up to date")
            continue
        pattern = re.compile(spec["asset"])
        asset = next((a for a in release["assets"] if pattern.search(a["name"])), None)
        if asset is None:
            print(f"  warning: plugin {name}: no asset matching {spec['asset']!r} in {tag}")
            continue
        print(f"  plugin {name}: installing {tag}")
        with tempfile.TemporaryDirectory(dir=dest) as tmp:
            archive = Path(tmp) / asset["name"]
            github.download(asset["browser_download_url"], archive)
            extract(archive, Path(tmp) / "x", 0)
            for source_glob, target in spec["copy"].items():
                files = glob.glob(str(Path(tmp) / "x" / source_glob), recursive=True)
                if not files:
                    print(f"  warning: plugin {name}: {source_glob} matched nothing")
                (dest / target).mkdir(parents=True, exist_ok=True)
                for f in files:
                    if Path(f).is_file():
                        shutil.copy2(f, dest / target / Path(f).name)
        markers[name] = tag
        marker_file.write_text(json.dumps(markers, indent=2) + "\n")


def write_launcher(
    name: str, target: Path, env: dict[str, str], tool_dir: Path, jar: bool = False
) -> None:
    """Write tools/bin/<name>; paths are relative so the tree survives being moved/mounted."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    rel_target = os.path.relpath(target, BIN_DIR)
    rel_dir = os.path.relpath(tool_dir, BIN_DIR)
    if PLATFORM == "windows":
        here = "%~dp0"
        lines = ["@echo off", "setlocal"]
        for k, v in env.items():
            value = v.replace("{dir}", here + rel_dir)
            lines.append(f'set "{k}={value};%{k}%"' if k.endswith("PATH") else f'set "{k}={value}"')
        prefix = "java -jar " if jar else "call "
        lines.append(f'{prefix}"{here}{rel_target}" %*')
        (BIN_DIR / f"{name}.cmd").write_text("\r\n".join(lines) + "\r\n")
        return
    if not jar and not target.is_dir():
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    here = '$(dirname -- "$0")'
    lines = ["#!/bin/sh", "# generated by rea-suite; do not edit"]
    for k, v in env.items():
        value = v.replace("{dir}", f"{here}/{rel_dir}")
        suffix = f"${{{k}:+:${k}}}" if k.endswith("PATH") else ""  # prepend to *PATH lists
        lines.append(f'export {k}="{value}{suffix}"')
    prefix = "java -jar " if jar else ""
    lines.append(f'exec {prefix}"{here}/{rel_target}" "$@"')
    launcher = BIN_DIR / name
    launcher.write_text("\n".join(lines) + "\n")
    launcher.chmod(0o755)


# --- commands ----------------------------------------------------------------


def select(tools: dict[str, Tool], names: list[str]) -> list[Tool]:
    unknown = [n for n in names if n not in tools]
    if unknown:
        raise SystemExit(f"unknown tool(s): {', '.join(unknown)}; see {MANIFEST}")
    if names:
        chosen = [tools[n] for n in names]  # explicitly named: regardless of components
    else:
        skip = components.optional_tools() - components.selected_tools()
        chosen = [t for t in tools.values() if t.name not in skip]
    for tool in chosen:
        if names and not tool.supported:
            print(f"{tool.name}: not available on {PLATFORM}")
    return [t for t in chosen if t.supported]


# --- WSL: Windows-only tools of the Windows checkout, through interop ----------------


def in_wsl() -> bool:
    return PLATFORM == "linux" and Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()


def windows_root() -> Path | None:
    """The Windows checkout: REA_SUITE_WINDOWS_ROOT, else rea-suite.cmd on the Windows PATH."""
    if configured := os.environ.get("REA_SUITE_WINDOWS_ROOT"):
        return Path(configured)
    try:
        found = subprocess.run(
            ["cmd.exe", "/c", "where", "rea-suite.cmd"],
            capture_output=True,
            text=True,
            check=False,
            cwd="/mnt/c",  # cmd.exe refuses a WSL working directory
            timeout=20,
        ).stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not found:
        return None
    path = subprocess.run(
        ["wslpath", "-u", found[0].strip()], capture_output=True, text=True, check=False
    ).stdout.strip()
    return Path(path).parent.parent if path else None


INTEROP_LAUNCHER = """#!/bin/sh
# generated by rea-suite: {name} from the Windows checkout, through WSL interop
win='{target}'
for a in "$@"; do  # existing Linux paths become Windows paths
  if [ -e "$a" ]; then a="$(wslpath -w "$a")"; fi
  set -- "$@" "$a"; shift
done
cd /mnt/c && exec cmd.exe /c "$win" "$@"
"""


def wsl_bridge(tools: dict[str, Tool], quiet: bool = False) -> list[str]:
    """Write tools/bin launchers for the Windows checkout's Windows-only tools."""
    if not in_wsl():
        return []
    root = windows_root()
    if root is None or not (root / "tools" / "bin").is_dir():
        if not quiet:
            print("wsl: no Windows checkout found (set REA_SUITE_WINDOWS_ROOT in .env)")
        return []
    bridged = []
    for tool in tools.values():
        if "linux" in tool.assets or "any" in tool.assets or "windows" not in tool.bin:
            continue
        for name in tool.bin["windows"]:
            cmd = root / "tools" / "bin" / f"{name}.cmd"
            if not cmd.is_file():
                continue
            target = subprocess.run(
                ["wslpath", "-w", str(cmd)], capture_output=True, text=True, check=True
            ).stdout.strip()
            launcher = BIN_DIR / name
            BIN_DIR.mkdir(parents=True, exist_ok=True)
            launcher.write_text(INTEROP_LAUNCHER.format(name=name, target=target))
            launcher.chmod(0o755)
            bridged.append(name)
    if bridged and not quiet:
        print(f"wsl: Windows tools from {root}: {', '.join(bridged)}")
    return bridged


def cmd_wsl_bridge(args: argparse.Namespace) -> None:
    if not in_wsl():
        raise SystemExit("not running in WSL")
    if not wsl_bridge(load_tools()):
        sys.exit(1)


def cmd_install(args: argparse.Namespace, force_latest: bool = False) -> None:
    state = load_state()
    tools = load_tools()
    for tool in select(tools, args.tools):
        if tool.dotnet_tool:
            install_dotnet(tool, state, force_latest)
        elif tool.url:
            install_url(tool, state, force_latest)
        elif (
            force_latest
            or not (TOOLS_DIR / tool.name / state.get(tool.name, "?")).is_dir()
            or (tool.follows_pip and state.get(tool.name) != tool.version)
        ):
            install_github(tool, state, force_latest)
        else:
            print(f"{tool.name}: {state[tool.name]} installed (use `update` for newer releases)")
            activate(tool, TOOLS_DIR / tool.name / state[tool.name])
    if not args.tools:
        wsl_bridge(tools)


def cmd_update(args: argparse.Namespace) -> None:
    cmd_install(args, force_latest=True)


def cmd_status(args: argparse.Namespace) -> None:
    state = load_state()
    for tool in select(load_tools(), args.tools):
        installed = state.get(tool.name, "-")
        latest = "-"
        if tool.github:
            try:
                if tool.version == "head":
                    latest = build.head_commit(tool.github)[:12]
                else:
                    latest = github.release(tool.github)["tag_name"]
            except (OSError, subprocess.CalledProcessError) as exc:
                latest = f"? ({exc})"
        if tool.follows_pip:
            marker = f"  (follows the Python package: {tool.version})"
        elif tool.version not in ("latest", "head"):
            marker = f"  (pinned to {tool.version})"
        else:
            marker = "" if latest in ("-", installed) else "  <- update available"
        print(f"{tool.name:18} installed={installed:22} release={latest}{marker}")
        dest = TOOLS_DIR / tool.name / installed
        if tool.ghidra_extensions and dest.is_dir():
            present = ghidra.installed(dest)
            for name in tool.ghidra_extensions:
                info = present.get(name)
                text = f"{info['tag']} ({info['source']})" if info else "MISSING"
                print(f"  + {name:16} {text}")


def cmd_check(args: argparse.Namespace) -> None:
    """Offline health check: installed versions, launchers, Ghidra extensions."""
    state, problems = load_state(), 0
    for tool in select(load_tools(), args.tools):
        version = state.get(tool.name)
        dest = TOOLS_DIR / tool.name / (version or "?")
        if tool.dotnet_tool:
            dest = TOOLS_DIR / tool.name
        if not version or not dest.is_dir():
            if tool.needs_build:
                print(
                    f"  info  {tool.name:18} not installed; needs a source build "
                    "(component `build`, then rea-suite setup)"
                )
                continue
            print(f"  FAIL  {tool.name:18} not installed (rea-tools install {tool.name})")
            problems += 1
            continue
        if tool.follows_pip and version != tool.version:
            print(f"  FAIL  {tool.name:18} {version}, but the Python package is {tool.version}")
            problems += 1
            continue
        names = list(tool.bin.get(PLATFORM, {})) or ([tool.name] if tool.dotnet_tool else [])
        suffix = ".cmd" if PLATFORM == "windows" else ""
        absent = [n for n in names if not (BIN_DIR / f"{n}{suffix}").exists()]
        if tool.ghidra_extensions:
            present = ghidra.installed(dest)
            absent += [f"extension:{n}" for n in tool.ghidra_extensions if n not in present]
        if tool.name == "ghidra" and PLATFORM == "macos" and not ghidra.native_decompiler(dest):
            absent.append("natives (rea-tools reinstall ghidra)")
        if absent:
            print(f"  FAIL  {tool.name:18} {version}; missing {', '.join(absent)}")
            problems += 1
        else:
            print(f"  ok    {tool.name:18} {version}")
    if problems:
        sys.exit(1)


def cmd_use(args: argparse.Namespace) -> None:
    tools = load_tools()
    tool = select(tools, [args.tool])[0]
    dest = TOOLS_DIR / tool.name / args.version
    if not dest.is_dir():
        available = sorted(
            p.name for p in (TOOLS_DIR / tool.name).iterdir() if p.is_dir() and not p.is_symlink()
        )
        raise SystemExit(f"{tool.name}: {args.version} not installed; have: {', '.join(available)}")
    state = load_state()
    state[tool.name] = args.version
    save_state(state)
    activate(tool, dest)
    print(f"{tool.name}: now using {args.version} (pin `version:` in tools.yml to keep it)")


def cmd_remove(args: argparse.Namespace) -> None:
    if not args.tools:
        raise SystemExit("name the tool(s) to remove")
    state = load_state()
    for tool in select(load_tools(), args.tools):
        for name in tool.bin.get(PLATFORM, {}) or [tool.name]:
            for launcher in (BIN_DIR / name, BIN_DIR / f"{name}.cmd"):
                launcher.unlink(missing_ok=True)
        if (TOOLS_DIR / tool.name).exists():
            print(f"{tool.name}: removing {TOOLS_DIR / tool.name}")
            shutil.rmtree(TOOLS_DIR / tool.name)
        state.pop(tool.name, None)
    save_state(state)


def cmd_reinstall(args: argparse.Namespace) -> None:
    if not args.tools:
        args.tools = [t.name for t in select(load_tools(), [])]
    cmd_remove(args)
    cmd_install(args)


def cmd_prune(args: argparse.Namespace) -> None:
    state = load_state()
    for tool in select(load_tools(), args.tools):
        tool_dir = TOOLS_DIR / tool.name
        if not tool.github or not tool_dir.is_dir():
            continue
        for entry in tool_dir.iterdir():
            if entry.name in ("current", state.get(tool.name)) or not entry.is_dir():
                continue
            if args.dry_run:
                print(f"  {tool.name:18} {entry.name}")
                continue
            print(f"removing {entry}")
            shutil.rmtree(entry)


REA_GHIDRA_POLICY = (
    ROOT / "node_modules" / "rea-agents" / "dist" / "ghidra" / "GhidraReleasePolicy.js"
)


def cmd_rea_pins(args: argparse.Namespace) -> None:
    """Compare the Ghidra pin and the JDK with the versions the installed REA verifies."""
    if not REA_GHIDRA_POLICY.exists():
        raise SystemExit(f"  FAIL  rea pins           {REA_GHIDRA_POLICY} missing; run setup")
    policy = REA_GHIDRA_POLICY.read_text()
    ghidra = re.search(r'SUPPORTED_GHIDRA_VERSION = "([^"]+)"', policy)
    java = re.search(r"SUPPORTED_GHIDRA_JAVA_MAJOR = (\d+)", policy)
    if not (ghidra and java):
        raise SystemExit(
            f"  FAIL  rea pins           versions not found in {REA_GHIDRA_POLICY.name}"
        )
    problems = 0

    want = f"Ghidra_{ghidra[1]}_build"
    pinned = load_tools()["ghidra"].version
    if pinned == want:
        print(f"  ok    ghidra pin         {pinned} (REA verifies {ghidra[1]})")
    else:
        print(
            f"  FAIL  ghidra pin         {pinned}; REA verifies {ghidra[1]}: set `version: {want}`"
        )
        print(
            "                           for ghidra in common/tools.yml, then rea-tools update ghidra"
        )
        problems += 1

    release = Path(os.environ.get("JAVA_HOME", "")) / "release"
    found = (
        re.search(r'^JAVA_VERSION="(\d+)', release.read_text(), re.MULTILINE)
        if release.is_file()
        else None
    )
    if found and found[1] == java[1]:
        print(f"  ok    jdk                {found[1]} (REA verifies {java[1]})")
    else:
        have = found[1] if found else "none"
        print(f"  FAIL  jdk                {have}; REA verifies {java[1]}: set the JDK major in")
        print("                           platforms/*/bootstrap*, then bootstrap --update")
        problems += 1
    if problems:
        sys.exit(1)


ANDROID_ABI = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}


def cmd_frida_server(args: argparse.Namespace) -> None:
    """Push the frida-server matching the frida package to the connected Android device."""
    adb, *serial = adb_command(args.serial)

    def shell(*cmd: str) -> str:
        out = subprocess.run(
            [adb, *serial, "shell", *cmd], check=False, capture_output=True, text=True
        )
        if out.returncode:
            raise SystemExit(f"adb shell {' '.join(cmd)} failed: {out.stderr.strip()}")
        return out.stdout.strip()

    version = load_state().get("frida-server")
    abi = shell("getprop", "ro.product.cpu.abi")
    arch = ANDROID_ABI.get(abi)
    server = TOOLS_DIR / "frida-server" / str(version) / f"frida-server-{version}-android-{arch}"
    if not version or not server.is_file():
        raise SystemExit(f"no frida-server for {abi}; run `rea-tools install frida-server`")
    remote = "/data/local/tmp/frida-server"
    subprocess.run([adb, *serial, "push", str(server), remote], check=True)
    shell("chmod", "755", remote)
    print(f"frida-server {version} ({arch}) is at {remote}")
    if args.start:
        # needs root; -D daemonizes so adb returns
        shell("su", "-c", f"{remote} -D")
        print("started; check with `frida-ps -U`")
    else:
        print(f"start it as root: adb shell su -c '{remote} -D' (or rerun with --start)")


def adb_command(serial: str | None) -> list[str]:
    adb = os.environ.get("REA_ADB_PATH") or shutil.which("adb")
    if not adb:
        raise SystemExit("adb not found; install the suite's system packages (rea-suite setup)")
    return [adb, *(["-s", serial] if serial else [])]


def cmd_mitm_ca(args: argparse.Namespace) -> None:
    """Put mitmproxy's CA certificate on the connected Android device."""
    from mitmproxy.certs import CertStore  # .venv; creates ~/.mitmproxy on first use

    confdir = Path.home() / ".mitmproxy"
    CertStore.from_store(confdir, "mitmproxy", 2048)
    cert = confdir / "mitmproxy-ca-cert.cer"
    adb = adb_command(args.serial)
    if not args.system:
        subprocess.run(
            [*adb, "push", str(cert), "/sdcard/Download/mitmproxy-ca-cert.cer"], check=True
        )
        print(
            "pushed to Download/. Install it on the device: Settings > Security > Encryption & "
            "credentials > Install a certificate > CA certificate.\n"
            "Apps trust user CAs only when they opt in; apk-mitm <apk> patches an app to do so, "
            "or use --system on a rooted device."
        )
        return
    # System store: <subject hash>.0; Android 14+ reads it from the conscrypt APEX, so
    # mount a copy over that directory as well (both last until reboot).
    from cryptography import x509

    pem = cert.read_bytes()
    name = x509.load_pem_x509_certificate(pem).subject
    subject_hash = subprocess.run(
        ["openssl", "x509", "-noout", "-subject_hash_old", "-in", str(cert)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    remote = f"/data/local/tmp/{subject_hash}.0"
    subprocess.run([*adb, "push", str(cert), remote], check=True)
    script = f"""
set -e
for d in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; do
  [ -d "$d" ] || continue
  t=/data/local/tmp/cacerts-$(echo $d | tr / _)
  rm -rf "$t"; mkdir -p "$t"; cp "$d"/* "$t"/; cp {remote} "$t"/
  chmod 644 "$t"/*; chcon u:object_r:system_security_cacerts_file:s0 "$t"/* 2>/dev/null || true
  mount -t tmpfs tmpfs "$d" && cp "$t"/* "$d"/ && chcon u:object_r:system_security_cacerts_file:s0 "$d"/* 2>/dev/null || true
done
"""
    subprocess.run([*adb, "shell", "su", "-c", script], check=True)
    print(f"{name.rfc4514_string()} is a system CA until the device reboots (rerun after a reboot)")


def cmd_asset(args: argparse.Namespace) -> None:
    """Print `<tag> <url>` of the latest release asset matching a regex (for shell scripts)."""
    tool = Tool(name=args.repo, github=args.repo, assets={PLATFORM: args.pattern})
    release = github.release(args.repo)
    print(release["tag_name"], pick_assets(tool, release)[0]["browser_download_url"])


def main() -> None:
    parser = argparse.ArgumentParser(prog="rea-tools", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func, help_text in [
        ("install", cmd_install, "install missing tools (and Ghidra extensions)"),
        ("update", cmd_update, "update tools to the newest (or pinned) release"),
        ("status", cmd_status, "show installed and released versions"),
        ("reinstall", cmd_reinstall, "remove and install again"),
        ("remove", cmd_remove, "remove tools (e.g. after deselecting a component)"),
        ("prune", cmd_prune, "remove inactive versions"),
        ("check", cmd_check, "offline check of installs, launchers and extensions"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("tools", nargs="*", help="tool names (default: all)")
        p.add_argument(
            "--no-build",
            action="store_true",
            help="never build Ghidra extensions or macOS natives (also: REA_TOOLS_NO_BUILD=1)",
        )
        if name == "prune":
            p.add_argument("--dry-run", action="store_true", help="only list what would go")
        p.set_defaults(func=func)
    p = sub.add_parser("use", help="switch a tool to another installed version (rollback)")
    p.add_argument("tool")
    p.add_argument("version", help="directory name under tools/<tool>/")
    p.add_argument("--no-build", action="store_true", help="never build Ghidra extensions")
    p.set_defaults(func=cmd_use)
    p = sub.add_parser("components", help="optional components (see components --help)")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p.set_defaults(func=lambda a: components.main(a.rest))
    p = sub.add_parser("rea-pins", help="check Ghidra pin and JDK against what REA verifies")
    p.set_defaults(func=cmd_rea_pins)
    p = sub.add_parser(
        "wsl-bridge", help="WSL: launchers for the Windows checkout's Windows-only tools"
    )
    p.set_defaults(func=cmd_wsl_bridge)
    p = sub.add_parser("frida-server", help="push frida-server to the connected Android device")
    p.add_argument("--start", action="store_true", help="start it as root after pushing")
    p.add_argument("-s", "--serial", help="device serial (adb devices) when several are connected")
    p.set_defaults(func=cmd_frida_server)
    p = sub.add_parser("mitm-ca", help="put mitmproxy's CA certificate on the Android device")
    p.add_argument("--system", action="store_true", help="system store on a rooted device")
    p.add_argument("-s", "--serial", help="device serial (adb devices) when several are connected")
    p.set_defaults(func=cmd_mitm_ca)
    p = sub.add_parser("asset", help="print tag and URL of the latest matching release asset")
    p.add_argument("repo", help="GitHub owner/repo")
    p.add_argument("pattern", help="regex for the asset name")
    p.set_defaults(func=cmd_asset)
    sys.stdout.reconfigure(line_buffering=True)
    args = parser.parse_args()
    if getattr(args, "no_build", False):
        os.environ["REA_TOOLS_NO_BUILD"] = "1"
    try:
        args.func(args)
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)


if __name__ == "__main__":
    main()
