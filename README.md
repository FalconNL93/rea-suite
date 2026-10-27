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

tools.yml lookups use the GitHub API (60 requests/hour anonymously) and fall back
to the github.com release pages once that is exhausted. Put `export GITHUB_TOKEN=...`
in `.envrc.local` (ignored by git) to avoid the fallback; a fine-grained token
without any permissions is enough.

## Ghidra and its extensions

Ghidra extensions only load in the exact Ghidra version they were built for, so
`rea-tools` resolves them again for every Ghidra install (`ghidra-extensions` in
`common/tools.yml`):

1. the newest extension release with a zip for that Ghidra version, else
2. with `build: true`: the newest release's source, built with Ghidra's own Gradle
   wrapper (`support/gradle/gradlew`), else
3. a warning; the extension is missing for that version (see `rea-tools status ghidra`).

They are installed into `<ghidra>/Ghidra/Extensions`, which Ghidra treats as
installed for the GUI and `analyzeHeadless`. An update keeps the previous Ghidra
(with its extensions) next to the new one:

```sh
rea-suite tools update ghidra                   # new Ghidra + extensions
rea-suite tools use ghidra Ghidra_12.1.4_build  # roll back
rea-suite tools status ghidra                   # which extensions each source provided
REA_TOOLS_NO_BUILD=1 rea-suite update           # only prebuilt extensions, no source builds
```

Projects opened in a newer Ghidra are upgraded and no longer open in older ones.

| Extension | Purpose | Source |
| --- | --- | --- |
| FindCrypt | crypto constants | prebuilt per Ghidra version |
| Kaiju (CERT/CC) | function hashing, OOAnalyzer C++ classes | prebuilt only (native build) |
| XEXLoaderWV | Xbox 360 XEX loader | prebuilt or built |
| ghidra-firmware-utils | UEFI, option ROMs, firmware images | prebuilt or built |
| ghidra-nativeaot | .NET Native AOT; REA loads its jar | prebuilt or built |

## Tools

| Tool | Source | Commands |
| --- | --- | --- |
| REA | npm `rea-agents` | `rea` |
| Ghidra (+ extensions) | tools.yml | `ghidra`, `analyzeHeadless`, `pyghidraRun` |
| ghidriff | pip (diffing via pyghidra) | `ghidriff` |
| Kuna | tools.yml (REA decompiler engine) | `kuna` |
| Rizin, Cutter | tools.yml (static CLI; Cutter AppImage bundles rz-ghidra) / winget | `rizin`, `rz-bin`, ..., `cutter` |
| JADX, jadx-headless-mcp | tools.yml (REA's JADX provider uses the MCP jar) | `jadx`, `jadx-gui` |
| Apktool | tools.yml | `apktool` |
| wakaru | tools.yml (JavaScript bundle decompiler) | `wakaru` |
| WABT | tools.yml (WebAssembly) | `wasm2wat`, `wasm-objdump`, ... |
| ImHex | tools.yml (AppImage) / winget | `imhex` |
| YARA-X | tools.yml (CLI), pip (`yara_x`) | `yr` |
| ILSpy | dotnet tool `ilspycmd` (GUI via winget on Windows) | `ilspycmd` |
| Detect It Easy | official .deb (Linux), portable zip (Windows), pip `die-python` | `diec`, `die` |
| Frida, objection | pip `frida-tools`, `objection` (+ npm `frida` via rea) | `frida`, `frida-trace`, `objection`, ... |
| FLOSS, capa | pip `flare-floss`, `flare-capa` | `floss`, `capa` |
| mitmproxy | pip | `mitmproxy`, `mitmdump`, `mitmweb` |
| unblob | pip, Linux (recursive extraction, next to binwalk) | `unblob` |
| pwntools | pip, Linux | `pwn`, Python library |
| LIEF, pefile | pip | Python libraries |
| angr | pip (optional group) | Python library |
| gdb, pwndbg | apt `gdb`; tools.yml pwndbg portable (pinned to REA's version) | `gdb`, `pwndbg` |
| LLDB | apt `lldb` / winget `LLVM.LLVM` | `lldb` |
| Wireshark | apt `tshark` + `wireshark` / winget | `tshark`, `wireshark` |
| binwalk, adb | apt | `binwalk`, `adb` |
| xxd, ripgrep | apt / winget (xxd ships with Git for Windows) | `xxd`, `rg` |

Windows only: x64dbg + ScyllaHide (tools.yml, so plugins land in a known
directory), and via winget dnSpyEx, PE-bear, Sysinternals Suite, System Informer
and 7-Zip.

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

`common/env.sh` exports the absolute paths REA expects (`REA_KUNA_COMMAND`,
`REA_JADX_MCP_JAR`, `REA_PWNDBG_*`, `REA_GHIDRA_NATIVEAOT_JAR`, ...) for every
tool it finds, so `rea doctor` picks them up through `bin/rea`.

## Not included

- **Ghidra MCP plugins** (GhidraMCP, ghidra-mcp, GhidrAssistMCP), **jadx-ai-mcp**:
  overlap with REA; pick at most one if needed.
- **BinExport/BinDiff**: last binary releases target old Ghidra; ghidriff covers diffing.
- **Ghidrathon** (archived; PyGhidra is built in), **efiSeek** (gone; firmware-utils),
  **frida-dexdump**, **fridump**, **de4dot**, **API Monitor**: unmaintained.
- **rz-ghidra for the rizin CLI**: needs a shared Rizin build; Cutter bundles it.
- **x64dbg-automate**: plugin must be built with MSVC.
- **Commercial**: IDA Pro (REA via `REA_IDA_MCP_CONFIG`), Binary Ninja, Hopper.
