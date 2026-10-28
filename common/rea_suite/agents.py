# /// script
# requires-python = ">=3.12"
# ///
"""Agents on this machine and their REA setup: the rea MCP server and the REA skill.

Runs standalone (`uv run common/rea_suite/agents.py ...`) from bin/rea-suite and
platforms/windows/rea-suite.ps1, with the suite environment loaded.

  list                 detected agents: name, state (ok | missing | foreign), command
  register [agent...]  point the rea MCP server at the suite launcher and refresh the
                       REA skill; default: every detected agent
  skills               refresh the REA skill for every detected agent
  launch <prompt>      start an interactive agent session with that prompt: REA_SUITE_AGENT
                       (any command; the prompt is appended), else the first CLI found in
                       AGENT_CLIS; without one, print the prompt to paste into any agent

Which agents exist and where their configuration lives comes from rea-agents
(`rea setup --dry-run`), so a client it learns about is picked up here too. The
registered command is the suite launcher (bin/rea, platforms/windows/rea.ps1), not
node_modules/.bin/rea as `rea setup` writes it: the launcher loads the suite
environment (Ghidra, JDK, tools) for every agent.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = sys.platform == "win32"

if WINDOWS:
    REA = ["node", str(ROOT / "node_modules" / "rea-agents" / "scripts" / "rea.mjs")]
    LAUNCHER = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ROOT / "platforms" / "windows" / "rea.ps1"),
        "mcp",
    ]
else:
    REA = [str(ROOT / "bin" / "rea")]
    LAUNCHER = [str(ROOT / "bin" / "rea"), "mcp"]

# Agent CLIs that take a first prompt and stay interactive, in order of preference; the
# prompt replaces {prompt}. Another agent works through REA_SUITE_AGENT.
AGENT_CLIS = [
    ["claude", "{prompt}"],
    ["codex", "{prompt}"],
    ["copilot", "-i", "{prompt}"],
    ["opencode", "--prompt", "{prompt}"],
    ["gemini", "-i", "{prompt}"],
]

# what rea setup gives Codex (rea-agents mcpStartupPolicy); Ghidra starts slowly
CODEX_TIMEOUTS = "startup_timeout_sec = 30\ntool_timeout_sec = 450\n"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def plan() -> dict:
    """rea setup's plan for every detected agent; changes nothing."""
    out = run(*REA, "setup", "--all-detected", "--dry-run", "--format", "json").stdout
    return json.loads(out)


def agents() -> list[dict]:
    """Detected agents with their rea registration (command [] when there is none)."""
    p = plan()
    registrations = {r["client"]: r for r in p["doctor"]["identity"]["registrations"]}
    found = []
    for state in p["clientStates"]:
        if not state["detected"]:
            continue
        client = state["client"]
        reg = registrations.get(client["name"], {})
        found.append(
            {
                "name": client["name"],
                "display": client["displayName"],
                "config": reg.get("config_path") or client["configPath"],
                "command": reg.get("command") or [],
                "quit_first": bool(client.get("quitBeforeSetup")),
            }
        )
    return found


def state(agent: dict) -> str:
    if not agent["command"]:
        return "missing"
    return "ok" if agent["command"] == LAUNCHER else "foreign"


def step(msg: str) -> None:
    print(f"\n\033[1;34m==> {msg}\033[0m", flush=True)


def rewrite_command(agent: dict, old: list[str]) -> bool:
    """Replace the rea command in the agent's configuration, keeping its format.

    rea setup writes [launcher, "mcp"] on Linux/macOS; only that shape is rewritten.
    """
    if WINDOWS or len(old) != 2 or old[1] != "mcp":
        return False
    path = Path(agent["config"])
    text = path.read_text()
    # the path appears as a JSON/TOML string; / needs no escaping in either
    quoted = json.dumps(old[0])
    if text.count(quoted) != 1:
        return False
    path.write_text(text.replace(quoted, json.dumps(LAUNCHER[0])))
    return True


def register_cli(agent: dict) -> None:
    """Claude Code and Codex: through their own CLI."""
    name = agent["name"]
    if name == "claude_code":
        run("claude", "mcp", "remove", "--scope", "user", "rea", check=False)
        run("claude", "mcp", "add", "--scope", "user", "rea", "--", *LAUNCHER)
        return
    run("codex", "mcp", "remove", "rea", check=False)
    run("codex", "mcp", "add", "rea", "--", *LAUNCHER)
    config = Path(agent["config"])
    text = config.read_text()
    head = "[mcp_servers.rea]\n"
    section = re.search(r"^\[mcp_servers\.rea\]\n(?:(?!\[).*\n?)*", text, re.MULTILINE)
    if section and "startup_timeout_sec" not in section.group(0):
        config.write_text(text.replace(head, head + CODEX_TIMEOUTS, 1))


CLI = {"claude_code": "claude", "codex": "codex"}


def register(agent: dict, named: bool) -> str | None:
    """Register rea for one agent; returns a note when it needs the user."""
    if state(agent) == "ok":
        print(f"  {agent['name']}: already on the suite launcher")
        return None
    if agent["quit_first"] and not named:
        return f"{agent['display']}: quit it fully, then run rea-suite agents {agent['name']}"
    cli = CLI.get(agent["name"])
    if cli and shutil.which(cli):
        register_cli(agent)
    else:
        if state(agent) == "missing":
            # rea writes the entry in the agent's own format; then point it at the launcher
            run(*REA, "setup", "--yes", "--client", agent["name"], "--format", "json")
            agent = next(a for a in agents() if a["name"] == agent["name"])
        if not rewrite_command(agent, agent["command"]):
            return (
                f"{agent['display']}: set the rea MCP command in {agent['config']} "
                f"to {' '.join(LAUNCHER)}"
            )
    print(f"  {agent['name']}: rea now starts {' '.join(LAUNCHER)}")
    if agent["quit_first"]:
        return f"{agent['display']}: restart it to load rea"
    return None


def skills(names: list[str]) -> None:
    if not names:
        return
    step(f"REA skill for {' '.join(names)}")
    flags = [arg for name in names for arg in ("--skill-client", name)]
    out = run(*REA, "setup", "--yes", *flags, "--format", "json").stdout
    print(f"  {json.loads(out)['status']}")


def cmd_list(_: argparse.Namespace) -> None:
    for agent in agents():
        print(agent["name"], state(agent), " ".join(agent["command"]) or "-", sep="\t")


def cmd_register(args: argparse.Namespace) -> None:
    found = {a["name"]: a for a in agents()}
    names = args.agents or list(found)
    if not names:
        sys.exit("no agent found; name one (rea setup --help lists them)")
    unknown = [n for n in names if n not in found]
    if unknown:
        sys.exit(f"not detected on this machine: {' '.join(unknown)}")
    step(f"rea MCP server for {' '.join(names)}")
    notes = [n for n in (register(found[name], bool(args.agents)) for name in names) if n]
    skills(names)
    for note in notes:
        print(f"\033[33mnote:\033[0m {note}")


def cmd_skills(_: argparse.Namespace) -> None:
    skills([a["name"] for a in agents()])


def cmd_launch(args: argparse.Namespace) -> None:
    custom = os.environ.get("REA_SUITE_AGENT")
    if custom:
        command = [*shlex.split(custom, posix=not WINDOWS), args.prompt]
    else:
        found = next((cli for cli in AGENT_CLIS if shutil.which(cli[0])), None)
        if found is None:
            print("No agent CLI found; give this to your agent (or set REA_SUITE_AGENT):\n")
            print(args.prompt)
            return
        command = [arg.replace("{prompt}", args.prompt) for arg in found]
    print(f"starting {command[0]} (REA_SUITE_AGENT picks another agent)", flush=True)
    executable = shutil.which(command[0]) or command[0]
    sys.exit(subprocess.run([executable, *command[1:]], check=False).returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    p = sub.add_parser("register")
    p.add_argument("agents", nargs="*")
    p.set_defaults(func=cmd_register)
    sub.add_parser("skills").set_defaults(func=cmd_skills)
    p = sub.add_parser("launch")
    p.add_argument("prompt")
    p.set_defaults(func=cmd_launch)
    args = parser.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as e:
        sys.exit(f"{' '.join(e.cmd)} failed ({e.returncode}):\n{e.stderr or e.stdout}")


if __name__ == "__main__":
    main()
