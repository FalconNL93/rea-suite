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
bin/rea-suite           setup / update / reinstall / status for the whole suite
bin/rea                 rea wrapper with the suite environment (used for MCP)
common/
  env.sh                shared environment (PATH, JAVA_HOME, GHIDRA_INSTALL_DIR, REA_*)
  tools.yml             tools fetched from GitHub releases / dotnet tool
  rea_suite/            `rea-tools`: installer for tools.yml
platforms/
  linux/                apt package list
  windows/              winget import file, rea-suite.ps1, env.ps1
.devcontainer/          Ubuntu 26.04 container with the Linux toolset
tools/                  (ignored) downloaded tools; launchers in tools/bin
work/                   (ignored) targets, captures, Ghidra projects
```

## Setup

Requirements: [uv](https://docs.astral.sh/uv/), [fnm](https://github.com/Schniz/fnm),
[direnv](https://direnv.net/), a JDK 21+ (Ghidra, JADX, apktool) and the .NET SDK (ilspycmd).

```sh
bin/rea-suite setup            # apt packages, uv sync, npm ci, tools.yml, Detect It Easy
bin/rea-suite setup --angr     # ... including angr (kept on later runs)
direnv allow
rea-suite agents               # register rea (MCP via bin/rea) + REA skill for Claude Code
```

Windows (PowerShell): `platforms\windows\rea-suite.ps1 setup`, then
`. .\platforms\windows\env.ps1`.

## Updating and repairing

```sh
rea-suite update               # apt packages, DIE, uv.lock, rea-agents@latest, tools.yml, REA skill
rea-suite update --no-apt      # same without sudo
rea-suite status               # versions, outdated packages, failing `rea doctor` checks
rea-suite reinstall python     # or: node | tools | system | all | <tool from tools.yml>
rea-suite tools prune          # drop old tool versions kept after an update
```

`update` rewrites `uv.lock`, `package.json` and `package-lock.json`; commit them to
record the versions. Pin a tool by setting `version:` in `common/tools.yml` to a
release tag. `jadx-headless-mcp` and `kuna` are pinned to the versions REA verifies.

tools.yml lookups use the GitHub API (60 requests/hour anonymously). Put
`export GITHUB_TOKEN=...` in `.envrc.local` (ignored by git) to lift that limit;
a fine-grained token without any permissions is enough.

## Tools

| Tool | Source | Commands |
| --- | --- | --- |
| REA | npm `rea-agents` | `rea` |
| Ghidra | tools.yml | `ghidra`, `analyzeHeadless`, `pyghidraRun` |
| Kuna | tools.yml (REA decompiler engine) | `kuna` |
| Rizin | tools.yml (static build) | `rizin`, `rz-bin`, `rz-asm`, ... |
| JADX, jadx-headless-mcp | tools.yml (REA's JADX provider uses the MCP jar) | `jadx`, `jadx-gui` |
| Apktool | tools.yml | `apktool` |
| wakaru | tools.yml (JavaScript bundle decompiler) | `wakaru` |
| WABT | tools.yml (WebAssembly) | `wasm2wat`, `wasm-objdump`, ... |
| YARA-X | tools.yml (CLI), pip (`yara_x`) | `yr` |
| ILSpy | dotnet tool `ilspycmd` (GUI via winget on Windows) | `ilspycmd` |
| Detect It Easy | official .deb (Linux), portable zip (Windows), pip `die-python` | `diec`, `die` |
| Frida | pip `frida-tools` (+ npm `frida` via rea) | `frida`, `frida-ps`, `frida-trace`, ... |
| FLOSS, capa | pip `flare-floss`, `flare-capa` | `floss`, `capa` |
| mitmproxy | pip | `mitmproxy`, `mitmdump`, `mitmweb` |
| unblob | pip (recursive extraction, next to binwalk) | `unblob` |
| pwntools | pip | `pwn`, Python library |
| LIEF, pefile | pip | Python libraries |
| angr | pip (optional group) | Python library |
| LLDB | apt `lldb` / winget `LLVM.LLVM` | `lldb` |
| Wireshark | apt `tshark` + `wireshark` / winget | `tshark`, `wireshark` |
| binwalk, adb | apt | `binwalk`, `adb` |
| xxd, ripgrep | apt / winget (xxd ships with Git for Windows) | `xxd`, `rg` |

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

`common/env.sh` exports the absolute paths REA expects (`REA_KUNA_COMMAND`,
`REA_JADX_MCP_JAR`, `REA_WABT_BIN_DIRECTORY`, ...) for every tool it finds, so
`rea doctor` picks them up through `bin/rea`.

## Not included (candidates)

- **pwndbg**: GDB/LLDB plugin, supported by REA via `REA_PWNDBG_*`; needs `gdb`.
- **ImHex**: hex editor with a pattern language; GUI, `.deb`/AppImage per release.
- **Cutter**: Rizin GUI; REA ships a Cutter bridge.
- **ghidra-nativeaot**: Ghidra plugin for .NET Native AOT binaries (`REA_GHIDRA_NATIVEAOT_JAR`).
- **Windows only**: x64dbg, dnSpyEx, Sysinternals.
- **Commercial**: IDA Pro (REA via `REA_IDA_MCP_CONFIG`), Binary Ninja, Hopper.
