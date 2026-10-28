# rea-suite: rules for contributors and agents

A personal reverse engineering workbench: REA (CLI + MCP server) and the analysis tools around it,
installed and updated from one checkout on Linux/WSL, macOS (Apple Silicon) and Windows. Start with
`README.md` (layout, setup, what each tool is for); `rea-suite doctor` shows the state of an
installation.

## Ground rules

* **Self-contained.** What can live in the checkout lives there: runtimes and caches in `.runtime/`,
  Python packages in `.venv/`, clashing CLI tools in `.runtime/uv-tools/`, npm packages in
  `node_modules/`, analysis tools in `tools/`. System packages are the exception, each with a reason:
  only what needs root, a driver, a shell hook or a system library. On macOS the scripts run on
  Homebrew's bash and GNU userland (`common/env.sh` puts `gnubin` first), so Linux shell code
  works there unchanged. Source builds keep their source and build tree in `.runtime/build/`.
* **Any agent.** The suite works the same with Claude Code, Codex, Copilot, OpenCode, Gemini or no
  agent at all. Rules live in this file (`CLAUDE.md` only imports it), process skills in
  `.agents/skills/` (`.claude/skills` links there), agent detection and launching in
  `common/rea_suite/agents.py`. Agent-specific code is limited to the per-agent entries there.
* **One source per tool, updatable by the suite.** Every tool comes from exactly one of:
  `pyproject.toml` (uv), `common/uv-tools.txt`, `package.json`, `common/tools.yml` (GitHub release,
  direct URL or dotnet tool), `platforms/linux/apt-packages.txt` (Debian names; Fedora/RHEL
  names that differ go in `platforms/linux/dnf-names.txt`), `platforms/macos/Brewfile`,
  `platforms/windows/winget.json`, or a component in `common/components.yml`. Prefer them in that
  order. Nothing is installed by a one-off download or `curl | sh`.
* **Every platform.** A change to one platform's script has its counterparts: `bin/rea-suite`
  (Linux and macOS) and `platforms/windows/rea-suite.ps1`; `platforms/linux/bootstrap.sh`,
  `platforms/macos/bootstrap.sh` and `bootstrap.ps1`; `common/env.sh` and `env.ps1`; a tool in
  `tools.yml` gets `linux`, `macos` and `windows` assets where upstream publishes them. Where a
  platform cannot have it, the README says so.
* **Verified by running, or not verified.** Say what ran (command and result) and what did not.
  The Windows scripts are untested until someone runs them on Windows; say so.
* **Samples, captures and analysis output never go into git.** They live in `work/` (ignored).
* **Secrets never go into git.** gitleaks checks every commit and push (`.githooks`, enabled by
  `rea-suite setup`) and every push on the server (`.forgejo/workflows/gitleaks.yml`). Tokens go in
  `.env`. A false positive gets an allowlist entry with its reason in `.gitleaks.toml`; the hooks
  are not skipped.
* **Third-party code is built only when the user runs it or agrees.** Ghidra extension source
  builds and the macOS Ghidra natives (`buildNatives`) run Gradle on code from other
  repositories; use `--no-build` / `REA_TOOLS_NO_BUILD=1` otherwise.
* **Pinned versions say why.** A pin in `tools.yml` (`ghidra`, `jadx-headless-mcp`, `kuna`,
  `pwndbg`) is there because REA verifies that version; the comment names it. The Ghidra pin and
  the JDK major in the bootstraps follow rea-agents' `GhidraReleasePolicy.js`; `rea-tools rea-pins`
  (run by `update` and `doctor`) says when a new rea-agents moves them.

## Adding a tool

1. Pick the source by the order above. A tool whose dependencies clash with the main environment
   goes to `common/uv-tools.txt` (unblob versus angr is the example).
2. Optional or large (over a few hundred MB, a niche use)? Make it part of a component in
   `common/components.yml` rather than the default install.
3. If REA can drive it, export its absolute path (`REA_*`) in `common/env.sh` and `env.ps1`; the
   variable names are in `rea doctor` and `node_modules/rea-agents/dist/config/environment.js`.
4. Add a row to the README's tool table: what it is for, in one line, and where it comes from.
5. Run `rea-suite setup` and `rea-suite doctor`; check the tool starts (`<tool> --version`).

## Where things go

| Path | Holds |
|---|---|
| `bin/` | Entry points: `rea-suite` (setup/update/doctor), `rea` (REA with the suite environment), `rea-ghidra` (headless Ghidra). |
| `common/` | Cross-platform: `env.sh`, `tools.yml`, `components.yml`, `uv-tools.txt`, `rea_suite/` (Python: `rea-tools`, `diec`, components, agents), `ghidra_scripts/`. |
| `platforms/linux/`, `platforms/macos/`, `platforms/windows/` | Bootstrap, system package lists (apt, Brewfile, winget), Windows equivalents of the shell scripts. |
| `.agents/skills/` | Process skills (see its README). |
| `work/` | Targets, captures, Ghidra projects (`rea-ghidra` uses `work/ghidra/`). Ignored. |

## Python and shell

* Python runs through uv (`uv run`); `ruff check` and `ruff format` are clean.
* Shell scripts start with `set -euo pipefail` and pass `shellcheck`; PowerShell keeps
  `$ErrorActionPreference = 'Stop'` and parses in `pwsh`.
* `rea-suite lint` checks all of the above; the pre-commit hook runs it on staged files.
* Generated files (`tools/bin/*` launchers, `tools/state.json`) are never edited by hand.

## Reverse engineering with the suite

* REA is the agent's front door (`rea-suite agents` registers it); its skill covers the workflow.
* For scripted Ghidra work use `rea-ghidra` (analyze once, then `decomp`, `xrefs`, `functions`);
  add new headless scripts to `common/ghidra_scripts/` with a usage line at the top.
* Findings about a target belong to that target's own project, not to this repository.

## Git

* Commits read like a person wrote them: a short imperative subject (72 characters at most), a body
  only when there is something to explain. No references to AI tools, no `Co-Authored-By` or
  "Generated with" lines, no emoji.
* One commit per finished change, files staged by name. A red tree is not committed: say what failed.
* Lockfile changes from `rea-suite update` (`uv.lock`, `package-lock.json`) are committed on their own.
