# rea-suite

Personal reverse engineering workbench: [REA](https://github.com/morluto/rea)
(CLI + MCP server) plus the analysis tools around it, installed from one checkout
on Linux/WSL, macOS (Apple Silicon) and Windows so that everything stays updatable
from one place.
Rules for contributors and agents: `CLAUDE.md`.

## Layout

```
activate, activate.ps1  load the environment without direnv
.envrc                  direnv entry point -> common/env.sh (+ .env)
.githooks/              gitleaks pre-commit and pre-push hooks (.gitleaks.toml)
.forgejo/workflows/     server-side gitleaks scan
.env.example            copy to .env: component selection, GITHUB_TOKEN
.node-version           Node for fnm (rea-agents has a strict engines range)
.python-version         Python for uv
pyproject.toml/uv.lock  Python tools & libraries (uv)
package.json            rea-agents (npm)
bin/rea-suite           setup / select / update / doctor / reinstall / status (Linux, macOS)
bin/rea                 REA with the suite environment (used for MCP)
bin/rea-ghidra          headless Ghidra: analyze once, decompile, xrefs, function list
common/
  env.sh                shared environment (runtimes, PATH, GHIDRA_INSTALL_DIR, REA_*)
  tools.yml             tools from GitHub releases, direct URLs and dotnet tools
  components.yml        optional components (build, angr, steam, vm)
  uv-tools.txt          CLI tools in their own uv environments
  rea_suite/            `rea-tools` (tools.yml installer), components, `diec`
  ghidra_scripts/       headless Ghidra scripts used by rea-ghidra
platforms/
  linux/                bootstrap.sh, apt package list
  macos/                bootstrap.sh, Brewfile
  windows/              bootstrap.ps1, rea-suite.ps1, env.ps1, winget list
.claude/skills/         process skills for agents working on this repository
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
`node_modules/`, analysis tools in `tools/`. Deleting those directories removes the
installation; nothing in `~` or `/usr` is required.

What stays system-wide, because it needs root, drivers or a shell hook:

- Linux: `platforms/linux/apt-packages.txt` and the apt packages of the selected
  components (compilers, LLDB + Python bindings, Wireshark/tshark with capture
  permissions, qemu, binwalk, innoextract, adb, xxd, Qt runtime library, base utilities).
- macOS: `platforms/macos/Brewfile` and the brew packages of the selected components
  (bash and GNU coreutils/sed/grep/find/tar/awk for the scripts, Wireshark with ChmodBPF,
  rizin, binwalk, innoextract, 7-Zip, Android platform tools, compilers, QEMU/UTM), plus
  the Xcode Command Line Tools (clang, LLDB, git).
- Windows: `platforms/windows/winget.json` and the winget packages of the selected
  components (Git, Wireshark + Npcap, LLVM/LLDB, MinGW-w64, NASM, VirtualBox,
  innoextract, Sysinternals, System Informer, 7-Zip, Android platform tools).
- [direnv](https://direnv.net/) with its shell hook (optional; `source ./activate` works too).
- Agent registration (`rea-suite agents` writes to the agent's own config) and
  per-user tool settings such as `~/.config/ghidra`, `~/.mitmproxy` and SteamCMD's `~/.steam`.

## Setup

Linux / WSL (Debian/Ubuntu, x86_64):

```sh
cp .env.example .env                    # optional: preselect components, add GITHUB_TOKEN
platforms/linux/bootstrap.sh            # base packages, .runtime/, component menu, setup
platforms/linux/bootstrap.sh --no-apt   # never use sudo; `doctor` lists what is missing
direnv allow                            # or: source ./activate
rea-suite doctor
rea-suite agents                        # register REA (MCP via bin/rea) + REA skill
```

macOS (Apple Silicon; Xcode Command Line Tools and [Homebrew](https://brew.sh) first):

```sh
cp .env.example .env                    # optional, as above
platforms/macos/bootstrap.sh            # Homebrew bash + GNU tools, .runtime/, component menu, setup
platforms/macos/bootstrap.sh --no-brew  # never call brew; `doctor` lists what is missing
direnv allow                            # or: source ./activate
rea-suite doctor
rea-suite agents
```

The scripts run on Homebrew's bash (macOS ships bash 3.2; `bin/` re-executes itself
with `/opt/homebrew/bin/bash`) and `common/env.sh` puts the GNU `gnubin` directories
ahead of the BSD tools, so the shell code is the same as on Linux. Intel Macs are not
supported: the `macos` assets in `tools.yml` are arm64 builds.

Windows (PowerShell; untested so far):

```powershell
Copy-Item .env.example .env             # optional, as above
.\platforms\windows\bootstrap.ps1       # .runtime\, component menu, winget, setup
. .\activate.ps1
.\platforms\windows\rea-suite.ps1 doctor
```

## Optional components

`common/components.yml` lists the optional parts; the rest is always installed.
The bootstrap shows a menu on the first run and stores the choice in `.env`:

```
REA_SUITE_COMPONENTS="build steam"
```

| Component | Default | Brings |
| --- | --- | --- |
| `build` | yes | compilers and build tools, foreign-architecture binutils/gdb/qemu-user ([Build toolchains](#build-toolchains)) |
| `angr` | no | the angr framework (~1 GB) |
| `steam` | no | SteamCMD and Steamless (Windows) |
| `vm` | no | QEMU + OVMF (Linux) or VirtualBox (Windows); UTM on macOS |

Change it with `rea-suite select` (menu, then setup), by editing `.env`, or per run
with `REA_SUITE_COMPONENTS="..." rea-suite setup`. Deselecting stops installing and
checking a component; `uv sync` drops its Python group, `rea-tools remove <tool>`
removes its tools, apt/winget packages stay.

## Updating and repairing

```sh
rea-suite update               # runtimes, apt, uv.lock, uv tools, rea-agents@latest, tools.yml, REA skill
rea-suite update --no-apt      # same without sudo (macOS: --no-brew skips Homebrew)
rea-suite doctor               # check everything; exit 1 on problems
rea-suite status               # versions and available updates
rea-suite reinstall python     # or: runtime | node | tools | system | all | <tool from tools.yml>
rea-suite tools prune          # drop old tool versions kept after an update
```

Windows: the same commands through `platforms\windows\rea-suite.ps1`.

`update` rewrites `uv.lock`, `package.json` and `package-lock.json`; commit them to
record the versions. Pin a tool by setting `version:` in `common/tools.yml` to a
release tag. `jadx-headless-mcp`, `kuna` and `pwndbg` are pinned to the versions REA verifies.

tools.yml lookups use the GitHub API (60 requests/hour anonymously) and fall back
to the github.com release pages once that is exhausted. `GITHUB_TOKEN` in `.env`
avoids the fallback; a fine-grained token without any permissions is enough.

## Tools by task

### Agent front door

| Tool | What it is for | Source |
| --- | --- | --- |
| REA (`rea`) | One CLI and MCP server that lets an agent drive the tools below (Ghidra, Kuna, JADX, ILSpy, tshark, mitmproxy, pwndbg, ...) and report evidence | npm `rea-agents` |

### Static analysis: disassemble, decompile, inspect

| Tool | What it is for | Source |
| --- | --- | --- |
| Ghidra (`ghidra`, `analyzeHeadless`, `pyghidraRun`) | Main disassembler/decompiler for native code of most architectures; scriptable in Java/Python | tools.yml (+ extensions, below) |
| `rea-ghidra` | Headless Ghidra from the shell: analyze a binary once, then decompile addresses, find functions by string, list functions | this repo |
| ghidriff | Diff two versions of a binary (what a patch changed), on top of Ghidra | pip |
| Kuna | Agent-oriented decompiler ported from Ghidra; REA uses it as an engine | tools.yml |
| Rizin (`rizin`, `rz-bin`, `rz-asm`, ...) | Fast command-line disassembly, binary info, patching and scripting | tools.yml (brew on macOS) |
| Cutter | Rizin's GUI, with the Ghidra decompiler (rz-ghidra) built in | tools.yml |
| ImHex | Hex editor with a pattern language for decoding file formats and structures | tools.yml |
| Detect It Easy (`die`, `diec`) | Identify file type, compiler, packer and protector before you start (not on macOS: no arm64 build) | tools.yml, pip `die-python` |
| FLOSS | Extract strings, including obfuscated and stack strings, from executables | pip |
| capa | Name what an executable can do (network, crypto, persistence, ...) from its code | pip |
| YARA-X (`yr`) | Match binaries against YARA rules (signatures, families, your own patterns) | tools.yml, pip `yara_x` |
| LIEF, pefile | Parse and modify ELF/PE/Mach-O/DEX (LIEF) and PE (pefile) from Python | pip |
| capstone, unicorn, keystone | Disassembler, CPU emulator and assembler engines for your own scripts | pip |
| angr | Symbolic execution and CFG recovery: solve inputs, explore paths (component `angr`) | pip group |
| ripgrep (`rg`) | Fast search through extracted trees, dumps and decompiler output | tools.yml |
| xxd | Quick hex dumps and reverse hex-to-binary | apt (macOS, Git for Windows: built in) |

### Managed code: .NET, Java/Android, JavaScript, WebAssembly

| Tool | What it is for | Source |
| --- | --- | --- |
| ILSpy (`ilspy`, `ilspycmd`) | Decompile .NET assemblies to C# (GUI and command line; REA uses `ilspycmd`) | tools.yml, dotnet tool |
| dnSpyEx (`dnspy`) | Debug and edit .NET assemblies while they run (Windows) | tools.yml |
| JADX (`jadx`, `jadx-gui`) | Decompile Android APK/DEX to Java | tools.yml |
| jadx-headless-mcp | JADX engine REA drives for Android analysis | tools.yml |
| Apktool | Decode APK resources/smali and rebuild modified APKs | tools.yml |
| wakaru | Unpack and decompile bundled/minified JavaScript (webpack, Electron apps) | tools.yml |
| WABT (`wasm2wat`, `wasm-objdump`, ...) | Read and disassemble WebAssembly modules | tools.yml |

### Dynamic analysis: debug, instrument, emulate

| Tool | What it is for | Source |
| --- | --- | --- |
| Frida (`frida`, `frida-trace`, `frida-ps`, ...) | Hook and trace functions in running processes (desktop and mobile) | pip |
| objection | Frida-based mobile toolkit: SSL pinning bypass, runtime exploration | pip |
| gdb, pwndbg | Debug Linux processes and core dumps; pwndbg adds memory/heap views (REA uses it for core contexts) | tools.yml (pwndbg portable) |
| LLDB | Debugger for Linux/macOS/Windows, scriptable in Python | apt / Xcode CLT / winget LLVM |
| x64dbg (`x64dbg`, `x32dbg`) + ScyllaHide | Windows user-mode debugger; ScyllaHide hides it from anti-debug checks | tools.yml (Windows) |
| pwntools | Script interactions with binaries and exploits; REA uses its Python | pip (Linux, macOS) |
| qemu-user, gdb-multiarch, binutils-multiarch | Run, debug and disassemble ARM/MIPS/... userland binaries on x86 (component `build`) | apt |
| QEMU + OVMF / VirtualBox | Virtual machines to run untrusted samples away from your system (component `vm`; UTM on macOS) | apt / brew / winget |
| Sysinternals, System Informer | Watch processes, handles, registry and file activity of a running program (Windows) | winget |

### Network

| Tool | What it is for | Source |
| --- | --- | --- |
| mitmproxy (`mitmproxy`, `mitmdump`, `mitmweb`) | Intercept and modify HTTP(S) traffic of an app; REA reads its captures | pip |
| Wireshark, tshark | Capture and dissect any network traffic; REA analyzes captures with tshark | apt / brew cask / winget |

### Firmware, installers, containers, secrets

| Tool | What it is for | Source |
| --- | --- | --- |
| binwalk | Find and carve embedded files and file systems in firmware images | apt / brew |
| unblob | Recursively extract firmware and containers (more formats than binwalk) | uv tool (Linux) |
| innoextract | Unpack Inno Setup installers without running them | apt / brew / winget |
| gitleaks | Find keys, tokens and passwords in extracted apps, bundles and firmware trees | tools.yml |
| PE-bear | Inspect and fix PE headers, sections and imports (Windows) | tools.yml |
| adb | Talk to Android devices: install, pull APKs, push frida-server | apt / brew cask / winget |

### Games

| Tool | What it is for | Source |
| --- | --- | --- |
| SteamCMD | Download game builds and specific depots/versions from Steam (component `steam`) | Valve download |
| Steamless | Strip SteamStub DRM from executables before analysis (Windows; component `steam`) | tools.yml |

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

`common/env.sh` exports the absolute paths REA expects (`REA_KUNA_COMMAND`,
`REA_JADX_MCP_JAR`, `REA_PWNDBG_*`, `REA_GHIDRA_NATIVEAOT_JAR`, ...) for every
tool it finds, so `rea doctor` picks them up through `bin/rea`.

## Keeping secrets out of the repository

gitleaks (from `tools.yml`) runs in three places with the same config (`.gitleaks.toml`):

- `.githooks/pre-commit`: refuses a commit whose staged changes contain a secret.
- `.githooks/pre-push`: refuses a push whose new commits contain one (also commits made with `--no-verify`).
- `.forgejo/workflows/gitleaks.yml`: scans the full history on every push and pull request on the server.

`rea-suite setup` enables the hooks (`git config core.hooksPath .githooks`); `rea-suite doctor`
checks that they are on. Findings are shown redacted (rule, file, line). Tokens belong in `.env`
(ignored); a false positive gets an allowlist entry with its reason in `.gitleaks.toml`.

## Ghidra and its extensions

| Extension | What it is for | Source |
| --- | --- | --- |
| FindCrypt | Label crypto constants (AES S-boxes, hash IVs, ...) during analysis | prebuilt per Ghidra version |
| Kaiju (CERT/CC) | Function hashing across binaries, OOAnalyzer C++ class recovery | prebuilt only (native build) |
| XEXLoaderWV | Load Xbox 360 XEX executables | prebuilt or built |
| ghidra-firmware-utils | Load UEFI images, PCI option ROMs and other firmware formats | prebuilt or built |
| ghidra-nativeaot | Recover .NET Native AOT binaries; REA loads its jar | prebuilt or built |

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

### Headless Ghidra from the shell

```sh
rea-ghidra analyze   work/target.exe                # import + analysis, once (--force redoes it)
rea-ghidra functions work/target.exe > funcs.tsv    # entry, size, name, thunk, callers
rea-ghidra decomp    work/target.exe 0x401000 0x4020a0 > out.c
rea-ghidra xrefs     work/target.exe "license" "serial" > out.c
```

Projects live in `work/ghidra/<binary name>/`, logs in its `logs/`. The scripts are in
`common/ghidra_scripts/` (taken over from the rogue-spear port).

## Build toolchains

Component `build` (on by default), for building targets, patches, loaders and plugins:

| | Linux (apt) | macOS (brew) | Windows |
| --- | --- | --- | --- |
| C/C++ | build-essential, gcc/g++-multilib (32-bit), clang, lld, llvm | clang (Xcode CLT), llvm, lld | MSVC (Visual Studio / Build Tools, not managed here), LLVM (winget) |
| Windows targets | mingw-w64 (`x86_64-w64-mingw32-gcc`, i686) | mingw-w64 | WinLibs MinGW-w64 GCC (winget) |
| Assembler | nasm | nasm | NASM (winget) |
| Build systems | cmake, ninja, meson from uv (`.venv`, always); autoconf, automake, libtool, bison, flex, pkgconf, ccache from apt | same, from brew | cmake, ninja, meson from uv |
| Other architectures | binutils-multiarch, gdb-multiarch, qemu-user + binfmt (run ARM/MIPS/... userland binaries directly) | – (no qemu-user on macOS) | – |

MSVC is checked, not installed: it needs the Visual Studio installer with the
"Desktop development with C++" workload.

## macOS

Same commands as on Linux (`bin/rea-suite`, `bin/rea`, `rea-ghidra`); system packages
come from `platforms/macos/Brewfile` instead of apt. Differences:

- Ghidra's release zip has no macOS natives, so the decompiler is missing until they
  are built in the install: `cd tools/ghidra/current/support/gradle && ./gradlew buildNatives`
  (Xcode CLT and the JDK Ghidra asks for). `rea doctor` reports it as `native_decompiler`.
- Not available: Detect It Easy (only a .pkg installer for Apple Silicon, no die-python
  wheel), unblob, qemu-user, gdb-multiarch, x86 multilib.
- gdb (pwndbg) cannot debug native macOS processes; it works on core files and remote
  targets. Use LLDB (Xcode CLT) for local processes.
- Rizin comes from Homebrew (upstream ships only a .pkg); Cutter, ImHex and ILSpy are
  the `.app` bundles from the release `.dmg`/zip, started through `tools/bin`.
- Wireshark's cask installs ChmodBPF for capture permissions; it asks for your password
  once.

## Windows and WSL together

The suite runs natively on both sides; use whichever side fits the job and call
across where it helps. Use one checkout per side: `.runtime/`, `.venv/` and `tools/`
hold platform-specific binaries. Put the Linux checkout on the WSL filesystem
(`~/...`, not `/mnt/c`) for speed.

| Task | Where |
| --- | --- |
| pwndbg/gdb, unblob, pwntools, REA NativeAOT and pwndbg core contexts, binwalk, qemu-user | Linux/WSL only |
| x64dbg + ScyllaHide, dnSpyEx, PE-bear, Steamless, Sysinternals, System Informer, debugging Windows processes | Windows only |
| Ghidra, Rizin/Cutter, ImHex, JADX, ILSpy, DIE, Frida, FLOSS, capa, YARA-X, mitmproxy, SteamCMD, REA | both |

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
