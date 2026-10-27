# rea-suite

Personal reverse engineering workbench: [REA](https://github.com/morluto/rea)
(CLI + MCP server) plus the analysis tools around it, installed so that
everything stays updatable from one place.

## Layout

```
.envrc                  direnv entry point -> common/env.sh
.node-version           Node for fnm (rea-agents has a strict engines range)
.python-version         Python for uv
pyproject.toml/uv.lock  Python tools & libraries (uv)
package.json            rea-agents (npm)
bin/rea                 rea wrapper with the suite environment (use this in MCP configs)
common/
  env.sh                shared environment (PATH, JAVA_HOME, GHIDRA_INSTALL_DIR, REA_*)
  tools.yml             tools fetched from GitHub releases / dotnet tool
  rea_suite/            `rea-suite` installer CLI
platforms/
  linux/                apt package list + bootstrap.sh (Debian/Ubuntu/WSL)
  windows/              winget import file + bootstrap.ps1 + env.ps1
.devcontainer/          Ubuntu 26.04 container with the Linux toolset
tools/                  (ignored) downloaded tools; launchers in tools/bin
work/                   (ignored) targets, captures, Ghidra projects
```

## Setup

Requirements: [uv](https://docs.astral.sh/uv/), [fnm](https://github.com/Schniz/fnm),
[direnv](https://direnv.net/), a JDK 21+ (Ghidra/JADX) and the .NET SDK (ilspycmd).

```sh
platforms/linux/bootstrap.sh            # apt packages, uv sync, npm ci, tools.yml, DIE
platforms/linux/bootstrap.sh --angr     # ... including angr
direnv allow
rea doctor
```

Windows (PowerShell): `platforms\windows\bootstrap.ps1`, then
`. .\platforms\windows\env.ps1`.

## Updating

```sh
platforms/linux/bootstrap.sh --update   # everything below at once
uv lock --upgrade && uv sync            # Python packages
npm update                              # rea-agents
uv run rea-suite status                 # compare tools.yml tools with latest releases
uv run rea-suite update [tool...]       # install newer releases
uv run rea-suite prune                  # drop inactive versions
```

Pin a tool by setting `version:` in `common/tools.yml` to a release tag.
`uv sync` removes angr unless `--group angr` is passed again.

## Tools

| Tool | Source | Commands |
| --- | --- | --- |
| REA | npm `rea-agents` | `rea` |
| Ghidra | tools.yml | `ghidra`, `analyzeHeadless`, `pyghidraRun` |
| Rizin | tools.yml (static build) | `rizin`, `rz-bin`, `rz-asm`, ... |
| JADX | tools.yml | `jadx`, `jadx-gui` |
| YARA-X | tools.yml (CLI), pip (`yara_x`) | `yr` |
| ILSpy | dotnet tool `ilspycmd` (GUI via winget on Windows) | `ilspycmd` |
| Detect It Easy | official .deb (Linux), portable zip (Windows), pip `die-python` | `diec`, `die` |
| Frida | pip `frida-tools` | `frida`, `frida-ps`, `frida-trace`, ... |
| FLOSS | pip `flare-floss` | `floss` |
| mitmproxy | pip | `mitmproxy`, `mitmdump`, `mitmweb` |
| LIEF, pefile | pip | Python libraries |
| angr | pip (optional group) | Python library |
| LLDB | apt `lldb` / winget `LLVM.LLVM` | `lldb` |
| Wireshark | apt `tshark` + `wireshark` / winget | `tshark`, `wireshark` |
| binwalk | apt | `binwalk` |
| xxd, ripgrep | apt / winget (xxd ships with Git for Windows) | `xxd`, `rg` |

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

## Using REA from an agent

Register `bin/rea` (not `npx rea-agents`) so the MCP server gets the pinned Node,
Ghidra and tool paths without depending on the calling shell:

```sh
claude mcp add rea -- "$PWD/bin/rea" --mcp
```
