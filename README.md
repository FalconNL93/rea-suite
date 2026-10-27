# rea-suite

Personal reverse engineering workbench: [REA](https://github.com/morluto/rea)
(CLI + MCP server) plus the analysis tools around it, installed so that
everything stays updatable from one place.

## Layout

```
activate, activate.ps1  load the environment without direnv
.envrc                  direnv entry point -> common/env.sh
.node-version           Node for fnm (rea-agents has a strict engines range)
.python-version         Python for uv
pyproject.toml/uv.lock  Python tools & libraries (uv)
package.json            rea-agents (npm)
bin/rea-suite           setup / update / doctor / reinstall / status (Linux)
bin/rea                 rea wrapper with the suite environment (used for MCP)
common/
  env.sh                shared environment (runtimes, PATH, GHIDRA_INSTALL_DIR, REA_*)
  tools.yml             tools fetched from GitHub releases / dotnet tool
  rea_suite/            `rea-tools` (tools.yml installer) and `diec`
platforms/
  linux/                bootstrap.sh, apt package list
  windows/              bootstrap.ps1, rea-suite.ps1, env.ps1, winget list
.devcontainer/          Ubuntu 26.04 container running the Linux bootstrap
.runtime/               (ignored) uv, fnm + Node, Python, JDK, .NET SDK and caches
tools/                  (ignored) downloaded tools; launchers in tools/bin
work/                   (ignored) targets, captures, Ghidra projects
```

## Self-contained

Everything that can live inside the checkout does: runtimes and their caches in
`.runtime/` (uv, fnm/Node, uv-managed Python, Temurin JDK, .NET SDK, npm/NuGet/Gradle
caches), Python packages in `.venv/`, CLI tools whose dependencies clash with the
main environment in `.runtime/uv-tools/` (`common/uv-tools.txt`), npm packages in
`node_modules/`, analysis tools in `tools/`. Deleting those directories removes the installation; nothing in `~`
or `/usr` is required.

What stays system-wide, because it needs root, drivers or a shell hook:

- Linux: `platforms/linux/apt-packages.txt` (compilers and build tools, LLDB + Python
  bindings, Wireshark/tshark with capture permissions, qemu-user, binwalk, innoextract,
  adb, xxd, Qt runtime library, base utilities).
- Windows: `platforms/windows/winget.json` (Git, Wireshark + Npcap, LLVM/LLDB,
  MinGW-w64, NASM, innoextract, Sysinternals, System Informer, 7-Zip, Android
  platform tools).
- [direnv](https://direnv.net/) with its shell hook (optional; `source ./activate` works too).
- Agent registration (`rea-suite agents` writes to the agent's own config) and
  per-user tool settings such as `~/.config/ghidra` and `~/.mitmproxy`.

## Setup

Linux / WSL (Debian/Ubuntu, x86_64):

```sh
platforms/linux/bootstrap.sh           # base packages, .runtime/, then `rea-suite setup`
platforms/linux/bootstrap.sh --angr    # ... including angr (kept on later runs)
platforms/linux/bootstrap.sh --no-apt  # never use sudo; `doctor` lists what is missing
direnv allow                           # or: source ./activate
rea-suite doctor
rea-suite agents                       # register rea (MCP via bin/rea) + REA skill
```

Windows (PowerShell; untested so far):

```powershell
.\platforms\windowsootstrap.ps1      # winget packages, .runtime\, then setup
. .ctivate.ps1
.\platforms\windows
ea-suite.ps1 doctor
```

## Updating and repairing

```sh
rea-suite update               # runtimes, apt, uv.lock, rea-agents@latest, tools.yml, REA skill
rea-suite update --no-apt      # same without sudo
rea-suite doctor               # check everything; exit 1 on problems
rea-suite status               # versions and available updates
rea-suite reinstall python     # or: runtime | node | tools | system | all | <tool from tools.yml>
rea-suite tools prune          # drop old tool versions kept after an update
```

Windows: the same commands through `platforms\windows\rea-suite.ps1`.

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
| Rizin, Cutter | tools.yml (static CLI; Cutter bundles rz-ghidra) | `rizin`, `rz-bin`, ..., `cutter` |
| JADX, jadx-headless-mcp | tools.yml (REA's JADX provider uses the MCP jar) | `jadx`, `jadx-gui` |
| Apktool | tools.yml | `apktool` |
| wakaru | tools.yml (JavaScript bundle decompiler) | `wakaru` |
| WABT | tools.yml (WebAssembly) | `wasm2wat`, `wasm-objdump`, ... |
| ImHex | tools.yml (AppImage / portable zip) | `imhex` |
| YARA-X | tools.yml (CLI), pip (`yara_x`) | `yr` |
| ILSpy | dotnet tool `ilspycmd`; GUI from tools.yml | `ilspycmd`, `ilspy` |
| Detect It Easy | tools.yml (AppImage / portable zip), pip `die-python` for `diec` on Linux | `diec`, `die` |
| Frida, objection | pip `frida-tools`, `objection` (+ npm `frida` via rea) | `frida`, `frida-trace`, `objection`, ... |
| FLOSS, capa | pip `flare-floss`, `flare-capa` | `floss`, `capa` |
| mitmproxy | pip | `mitmproxy`, `mitmdump`, `mitmweb` |
| unblob | `uv tool` (own environment; clashes with angr), Linux | `unblob` |
| innoextract | apt / winget (Inno Setup installers) | `innoextract` |
| gitleaks | tools.yml (secrets in extracted apps/firmware) | `gitleaks` |
| capstone, unicorn, keystone | pip (disassembler / emulator / assembler engines) | Python libraries |
| pwntools | pip, Linux | `pwn`, Python library |
| LIEF, pefile | pip | Python libraries |
| angr | pip (optional group) | Python library |
| gdb, pwndbg | tools.yml pwndbg portable (GDB 17; pinned to REA's version) | `gdb`, `pwndbg` |
| LLDB | apt `lldb` / winget `LLVM.LLVM` | `lldb` |
| Wireshark | apt `tshark` + `wireshark` / winget | `tshark`, `wireshark` |
| binwalk, adb | apt; adb via winget on Windows | `binwalk`, `adb` |
| ripgrep | tools.yml | `rg` |
| xxd | apt (ships with Git for Windows) | `xxd` |

Windows only: x64dbg + ScyllaHide, dnSpyEx and PE-bear (tools.yml, portable), and
via winget Sysinternals Suite and System Informer.

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

`common/env.sh` exports the absolute paths REA expects (`REA_KUNA_COMMAND`,
`REA_JADX_MCP_JAR`, `REA_PWNDBG_*`, `REA_GHIDRA_NATIVEAOT_JAR`, ...) for every
tool it finds, so `rea doctor` picks them up through `bin/rea`.

## Build toolchains

For building targets, patches, loaders and plugins:

| | Linux (apt) | Windows |
| --- | --- | --- |
| C/C++ | build-essential, gcc/g++-multilib (32-bit), clang, lld, llvm | MSVC (Visual Studio / Build Tools, not managed here), LLVM (winget) |
| Windows targets | mingw-w64 (`x86_64-w64-mingw32-gcc`, i686) | WinLibs MinGW-w64 GCC (winget) |
| Assembler | nasm | NASM (winget) |
| Build systems | cmake, ninja, meson from uv (`.venv`); autoconf, automake, libtool, bison, flex, pkgconf, ccache from apt | cmake, ninja, meson from uv |
| Other architectures | binutils-multiarch, gdb-multiarch, qemu-user + binfmt (run ARM/MIPS/... userland binaries directly) | – |

MSVC is checked, not installed: it needs the Visual Studio installer with the
"Desktop development with C++" workload.

## Windows and WSL together

The suite runs natively on both sides; use whichever side fits the job and call
across where it helps. Use one checkout per side: `.runtime/`, `.venv/` and `tools/`
hold platform-specific binaries. Put the Linux checkout on the WSL filesystem
(`~/...`, not `/mnt/c`) for speed.

| Task | Where |
| --- | --- |
| pwndbg/gdb, unblob, pwntools, REA NativeAOT and pwndbg core contexts, binwalk | Linux/WSL only |
| x64dbg + ScyllaHide, dnSpyEx, PE-bear, Sysinternals, System Informer, debugging Windows processes | Windows only |
| Ghidra, Rizin/Cutter, ImHex, JADX, ILSpy, DIE, Frida, FLOSS, capa, YARA-X, mitmproxy, REA | both |

From Windows into WSL (paths relative to your WSL home):

```powershell
wsl -- bash -lc "~/Dev/rea/bin/rea-suite doctor"
wsl -- bash -lc "~/Dev/rea/tools/bin/pwndbg"          # Linux-only tool on a Windows box
wsl -- bash -lc "cd ~/Dev/rea && source ./activate && unblob -e work/out work/firmware.bin"
# WSL files for Explorer / Windows tools: \\wsl.localhost\Ubuntu\home\<user>\Dev\rea\work
```

From WSL into Windows (needs WSL interop; check `cat /proc/sys/fs/binfmt_misc/WSLInterop`,
it is controlled by `[interop] enabled` in `/etc/wsl.conf`):

```sh
cmd.exe /c 'C:\Users\<user>\rea-suite\tools\bin\x64dbg.cmd' "$(wslpath -w work/sample.exe)"
powershell.exe -File 'C:\Users\<user>\rea-suite\platforms\windows\rea-suite.ps1' doctor
wslpath -w work/sample.exe        # Linux path -> Windows path (and `wslpath -u` back)
```

Notes:

- Frida/LLDB/x64dbg attach only to processes on their own side; to instrument a
  Windows process, run the Windows install.
- mitmproxy in WSL can intercept Windows traffic by pointing the Windows proxy at
  WSL's address (`localhost` with WSL's mirrored networking mode).
- Agents (REA MCP) can be registered on either side with `rea-suite agents` /
  the Windows equivalent; each registration uses that side's `bin/rea`.
- GUI tools from WSL appear on the Windows desktop through WSLg.

## Not included

- **Ghidra MCP plugins** (GhidraMCP, ghidra-mcp, GhidrAssistMCP), **jadx-ai-mcp**:
  overlap with REA; pick at most one if needed.
- **BinExport/BinDiff**: last binary releases target old Ghidra; ghidriff covers diffing.
- **Ghidrathon** (archived; PyGhidra is built in), **efiSeek** (gone; firmware-utils),
  **frida-dexdump**, **fridump**, **de4dot**, **API Monitor**: unmaintained.
- **rz-ghidra for the rizin CLI**: needs a shared Rizin build; Cutter bundles it.
- **x64dbg-automate**: plugin must be built with MSVC.
- **Commercial**: IDA Pro (REA via `REA_IDA_MCP_CONFIG`), Binary Ninja, Hopper.
