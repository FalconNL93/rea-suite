# rea-suite

Personal reverse engineering workbench: [REA](https://github.com/morluto/rea)
(CLI + MCP server) plus the analysis tools around it, installed from one checkout
on Linux/WSL, macOS (Apple Silicon) and Windows so that everything stays updatable
from one place.
Rules for contributors and agents: `AGENTS.md`.

## Layout

```
activate, activate.ps1  load the environment without direnv
.envrc                  direnv entry point -> common/env.sh (+ .env)
.githooks/              pre-commit (lint + gitleaks) and pre-push (gitleaks) hooks, lint.sh
.forgejo/workflows/     server-side gitleaks scan and lint
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
  components.yml        optional components (build, angr, steam, porting, vm, ...)
  uv-tools.txt          CLI tools in their own uv environments
  rea_suite/            `rea-tools` (tools.yml installer), components, `diec`
  ghidra_scripts/       headless Ghidra scripts used by rea-ghidra
platforms/
  linux/                bootstrap.sh, apt package list
  macos/                bootstrap.sh, Brewfile
  windows/              bootstrap.ps1, rea-suite.ps1, rea.ps1 (= bin/rea), env.ps1, winget list
AGENTS.md               rules for contributors and agents (CLAUDE.md imports it)
TODO.md                 tools still to add, each with why
.agents/skills/         process skills for agents working on this repository
                        (.claude/skills links here for Claude Code)
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

- Linux: `platforms/linux/apt-packages.txt` and the packages of the selected components
  (compilers, LLDB + Python bindings, Wireshark/tshark with capture permissions, qemu,
  binwalk, innoextract, adb, xxd, Qt runtime library, base utilities). The lists use Debian
  names; on Fedora/RHEL `platforms/linux/dnf-names.txt` translates the ones that differ and
  `platforms/linux/packages.sh` installs them with apt or dnf. RHEL lacks a few even with
  EPEL (binwalk, unshield, diffoscope, qemu-user, scrcpy, sigrok-cli): `doctor` lists them
  as not packaged there, everything else works.
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

Linux / WSL (x86_64): Debian/Ubuntu (apt), Fedora, and RHEL with its rebuilds such as
Rocky and Alma (dnf; the bootstrap enables EPEL and CRB there):

```sh
cp .env.example .env                    # optional: settings (components, builds, PATH, agent, REA, token)
platforms/linux/bootstrap.sh            # base packages, .runtime/, component menu, setup
platforms/linux/bootstrap.sh --no-apt   # never use sudo (--no-dnf is the same); `doctor` lists what is missing
direnv allow                            # or: source ./activate
rea-suite doctor
rea-suite agents                        # REA skill for every detected agent, MCP via bin/rea
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

`setup` also puts `bin/` on your PATH, so `rea-suite`, `rea` and `rea-ghidra` work from
any directory: a marked block in `~/.zshrc` / `~/.bashrc` (fish: `conf.d/rea-suite.fish`),
written once and only replaced by itself; on Windows `<checkout>\bin` (with `rea-suite.cmd`
and `rea.cmd`) appended to the user PATH. Existing entries are never removed, and a file that
already names `bin/` is left alone. `REA_SUITE_NO_PATH=1` skips it.

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
| `build` | yes | compilers and build tools, Rust, foreign-architecture binutils/gdb/qemu-user, and the tools that only exist as source ([Build toolchains](#build-toolchains)) |
| `browser` | yes | Chromium for REA's browser captures and web module tracing (~300 MB) |
| `mobile` | no | scrcpy, apkeep, uber-apk-signer (adb, Frida and frida-server are always there) |
| `hardware` | no | sigrok-cli for logic analyzer recordings (Linux, macOS) |
| `angr` | no | the angr framework (~1 GB) |
| `steam` | no | SteamCMD and Steamless (Windows) |
| `porting` | no | porting old Windows games: Wine + winedbg, rr, perf + hotspot (Linux), Tracy, WinDbg (Windows) ([Porting old games](#porting-old-games); Wine is over 1 GB) |
| `vm` | no | QEMU + OVMF (Linux) or VirtualBox (Windows); UTM on macOS |

Change it with `rea-suite select` (menu, then setup), by editing `.env`, or per run
with `REA_SUITE_COMPONENTS="..." rea-suite setup`. Deselecting stops installing and
checking a component; `uv sync` drops its Python group, `rea-tools remove <tool>`
removes its tools, apt/winget packages stay.

A component added to the suite later with default `yes` is switched on once by the
next `setup` or `update`, which says so; one you switched off stays off
(`REA_SUITE_COMPONENTS_SEEN` in `.env` records what you have been offered).

## Updating and repairing

```sh
rea-suite update               # runtimes, apt, uv.lock, uv tools, rea-agents@latest, tools.yml, REA skill
rea-suite update --ai          # same parts, planned by an agent: compatibility first, then your approval
rea-suite update --no-apt      # same without sudo (macOS: --no-brew skips Homebrew)
rea-suite agents               # repair agent setup: rea MCP back on bin/rea, REA skill refreshed
rea-suite doctor               # check everything; exit 1 on problems
rea-suite status               # versions and available updates
rea-suite reinstall python     # or: runtime | node | tools | system | all | <tool from tools.yml>
rea-suite tools prune          # drop old tool versions kept after an update
rea-suite clean                # sizes of the download caches, source builds and inactive tool versions
rea-suite clean caches         # or: builds | tools | all; caches refill on the next setup or build
```

`update` takes every newest release (pins in `tools.yml` excepted). `update --ai` starts
an agent with the `updating-the-suite` skill (`.agents/skills/`): the first of `claude`,
`codex`, `copilot`, `opencode`, `gemini` it finds, or any command in `REA_SUITE_AGENT`
(the prompt is appended, e.g. `REA_SUITE_AGENT="codex -m <model>"`); without one it prints
the prompt to give to whatever agent you use. The agent reads what the newer rea-agents
verifies (Ghidra, JDK, Kuna, JADX bridge, pwndbg, Node), checks Ghidra extensions and
release notes, and shows a plan of what goes to which version and what is held back and
why. Nothing changes until you approve; afterwards it runs `doctor` and commits as
`AGENTS.md` says.

`rea doctor` (rea-agents' own) calls the bin/rea registration stale and suggests
`rea setup`, which registers node_modules/.bin/rea without the suite environment (Ghidra,
the JDK, the tools on PATH). Use `rea-suite doctor` instead: it reads rea doctor's
failures and judges the registrations itself. A `rea setup` run through bin/rea points
the agents back at it afterwards.

The caches (uv, npm, NuGet, Gradle) live in `.runtime/cache/` and only speed up the next
install; `clean caches` is always safe. `clean builds` removes the sources and build trees of
source-built tools and Ghidra extensions (`.runtime/build/`; each tool keeps only its newest
build anyway). `clean tools` removes the versions `rea-tools use` could roll back to.

Windows: the same commands through `platforms\windows\rea-suite.ps1`.

`update` rewrites `uv.lock`, `package.json` and `package-lock.json`; commit them to
record the versions. Pin a tool by setting `version:` in `common/tools.yml` to a
release tag. `ghidra`, `jadx-headless-mcp`, `kuna` and `pwndbg` are pinned to the versions
REA verifies. For Ghidra and its JDK, `update` and `doctor` compare the pin and the installed
JDK with what the installed rea-agents verifies (`rea-tools rea-pins`) and say what to change.

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
| capa | Name what an executable can do (network, crypto, persistence, ...) from its code | tools.yml (standalone, rules built in) |
| GoReSym (`goresym`) | Recover function names, types and build info from stripped Go binaries (macOS: x86_64 build, runs under Rosetta 2) | tools.yml |
| UPX (`upx`) | Unpack UPX-packed executables (`upx -d`) | tools.yml (brew on macOS) |
| YARA-X (`yr`) | Match binaries against YARA rules (signatures, families, your own patterns) | tools.yml, pip `yara_x` |
| YARA Forge rules | Community YARA rules, low false-positive set: `yr scan tools/yara-forge/current/packages/core/yara-rules-core.yar <file>` | tools.yml |
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
| uber-apk-signer | Sign, zipalign and verify APKs after changing them | tools.yml |
| apk-mitm | Patch an APK so mitmproxy can intercept its HTTPS (certificate pinning, network security config) | npm |
| scrcpy | Mirror and control an Android device screen (component `mobile`) | apt / brew / winget |
| apkeep | Download APKs (Google Play, APKPure, F-Droid) without a phone | tools.yml (macOS: built with cargo) |
| wakaru | Unpack and decompile bundled/minified JavaScript (webpack, Electron apps) | tools.yml |
| webcrack | Deobfuscate and unpack JavaScript (obfuscator.io string arrays, webpack bundles) | npm |
| asar | List and extract Electron `app.asar` archives | npm `@electron/asar` |
| pyinstxtractor-ng | Unpack PyInstaller executables into their .pyc files | uv tool |
| pycdc, pycdas | Decompile and disassemble Python bytecode (.pyc) | tools.yml, built from source (component `build`) |
| WABT (`wasm2wat`, `wasm-objdump`, ...) | Read and disassemble WebAssembly modules | tools.yml |

### Dynamic analysis: debug, instrument, emulate

| Tool | What it is for | Source |
| --- | --- | --- |
| Frida (`frida`, `frida-trace`, `frida-ps`, ...) | Hook and trace functions in running processes (desktop and mobile) | pip |
| objection | Frida-based mobile toolkit: SSL pinning bypass, runtime exploration | pip |
| frida-server | Frida for Android devices, always the version of the frida package; `rea-tools frida-server [--start]` pushes the right one for the device | tools.yml |
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
| mitmproxy (`mitmproxy`, `mitmdump`, `mitmweb`) | Intercept and modify HTTP(S) traffic of an app; REA reads its captures; `rea-tools mitm-ca [--system]` puts its CA on an Android device | pip |
| Wireshark, tshark | Capture and dissect any network traffic; REA analyzes captures with tshark | apt / brew cask / winget |
| sigrok-cli | Decode logic analyzer and signal recordings; REA uses it (component `hardware`, Linux/macOS) | apt / brew |
| Chromium (Playwright) | Browser REA drives for web captures and module tracing; the build rea-agents' playwright-core expects (component `browser`) | rea-agents' playwright-core |

### Firmware, installers, containers, secrets

| Tool | What it is for | Source |
| --- | --- | --- |
| binwalk | Find and carve embedded files and file systems in firmware images | apt / brew |
| unblob | Recursively extract firmware and containers (more formats than binwalk) | uv tool (Linux) |
| innoextract | Unpack Inno Setup installers without running them | apt / brew / winget |
| unshield, cabextract, msitools / lessmsi | Unpack InstallShield, CAB and MSI installers (Windows: lessmsi; 7-Zip opens CABs) | apt / brew / winget |
| diffoscope | Compare two versions of a package, installer or archive in depth (not on Windows) | apt (`diffoscope-minimal`) / brew |
| ipsw | Apple firmware and dyld_shared_cache: download, extract, class-dump, Mach-O info | tools.yml |
| gitleaks | Find keys, tokens and passwords in extracted apps, bundles and firmware trees | tools.yml |
| PE-bear | Inspect and fix PE headers, sections and imports (Windows) | tools.yml |
| adb | Talk to Android devices: install, pull APKs, push frida-server | apt / brew cask / winget |

### Games

| Tool | What it is for | Source |
| --- | --- | --- |
| SteamCMD | Download game builds and specific depots/versions from Steam (component `steam`) | Valve download |
| Steamless | Strip SteamStub DRM from executables before analysis (Windows; component `steam`) | tools.yml |
| Wine, winedbg | Run the original Windows game on Linux and trace its API calls, file and registry access (`WINEDEBUG=+relay`); 32-bit games run through Wine's WoW64, no i386 multiarch needed (component `porting`; not on macOS, see [Porting old games](#porting-old-games)) | apt |
| Process Monitor (`Procmon64`) | File, registry and process activity of the original game on Windows; part of the Sysinternals Suite | winget (Sysinternals) |
| WinDbg (Time Travel Debugging) | Record a Windows run and step it backwards: the Windows counterpart of rr (component `porting`) | winget |
| rr | Record a run once, replay it deterministically under gdb, also backwards (Linux only; component `porting`) | apt |
| perf | Sampling profiles of a slow interpreted or translated game (Linux only; component `porting`) | apt (`linux-perf`) |
| hotspot | View perf recordings: flame graphs, callers and callees, timeline (Linux; component `porting`) | tools.yml (AppImage) |
| Tracy (`tracy-profiler`, `tracy-capture`) | Frame profiler for code you instrument: the native rewrite or the recompiled game (component `porting`) | tools.yml |
| Ghidra FunctionID for old MSVC | Names the C runtime's functions in old games; Ghidra ships Visual C++ 4.2 and 2003-2010, VC6 you build from your own copy ([below](#functionid-for-visual-c-60)) | Ghidra (built in) |

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

`common/env.sh` exports the absolute paths REA expects (`REA_KUNA_COMMAND`,
`REA_JADX_MCP_JAR`, `REA_PWNDBG_*`, `REA_GHIDRA_NATIVEAOT_JAR`, ...) for every
tool it finds, so `rea doctor` picks them up through `bin/rea`.

## Porting old games

Component `porting` (`rea-suite select`) brings the tools for running, tracing and
profiling an original Windows game while you recompile, interpret or rewrite it.

### Tracing the original binary

Wine runs the game on Linux and logs every call into its DLLs. Use a prefix of your
own per game in `work/`, so traces and settings stay apart:

```sh
export WINEPREFIX=$PWD/work/wine/rogue-spear                   # created on the first run
WINEDEBUG=+relay,+seh wine RogueSpear.exe 2> work/relay.log      # every API call and return
WINEDEBUG=+file,+reg wine RogueSpear.exe 2> work/files.log       # file and registry access
WINEDEBUG=+loaddll,+module wine RogueSpear.exe                  # which DLLs load from where
winedbg RogueSpear.exe                                          # Wine's debugger (gdb-like)
winedbg --gdb RogueSpear.exe                                    # or drive it from gdb/pwndbg
```

`+relay` is large; leave out the noisy functions with `RelayExclude` (and `RelayInclude`)
under `HKCU\Software\Wine\Debug` (`wine regedit`), e.g.
`ntdll.RtlEnterCriticalSection;ntdll.RtlLeaveCriticalSection`. On Windows, Process
Monitor (`Procmon64`, from the Sysinternals Suite) shows the same file, registry and
process activity of the real thing; filter on the process name and save as CSV or PML.

### Record, replay and profile

```sh
rr record ./my-port               # record once (a Wine run too; not checked here yet)
rr replay                         # replay the last recording under gdb; reverse-continue works
perf record -g -- ./my-port       # sampling profile of the translated/interpreted game
hotspot perf.data                 # flame graph, callers/callees, timeline
```

rr and perf need hardware performance counters. With `kernel.perf_event_paranoid` at 2
(Ubuntu's default) both work for your own processes, user-space only; perf needs 1 or
lower (`sudo sysctl kernel.perf_event_paranoid=1`) to see kernel time, and kernel symbols
need `kernel.kptr_restrict=0`.

WSL2 (checked on kernel 6.18.54.1-microsoft-standard-WSL2, AMD Ryzen 9 5950X): perf
counts and samples user space (`perf stat`, `perf record -g`) and hotspot reads the
result; `rr record` and `rr replay` of `/bin/true`, `ls` and Python succeeded. rr warns
that on AMD Zen CPUs it is unreliable unless the SpecLockMap optimization is switched
off; that workaround writes a CPU MSR, which a WSL2 guest cannot do, so on Zen under WSL2
longer recordings may diverge on replay. Intel CPUs need no workaround. Ubuntu's
`linux-tools-generic` does not fit a WSL kernel (its `perf` wrapper looks for the running
kernel's version); `linux-perf` is a perf binary that works with any kernel.

Tracy is for code you instrument yourself: build the native rewrite with Tracy's client
(its source at the same tag as `tracy-profiler`), then connect `tracy-profiler` or record
with `tracy-capture -o run.tracy`.

### Other platforms

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Run and trace the original | Wine, winedbg | – (see below) | the game itself, Process Monitor, x64dbg |
| Record and replay | rr | – (none exists) | WinDbg Time Travel Debugging |
| Sampling profiles | perf + hotspot | Instruments (full Xcode, not managed here) | Windows Performance Analyzer (Windows ADK, not managed here) |
| Instrumented profiles | Tracy | Tracy | Tracy |

macOS has no Wine in the suite: Homebrew disabled its Wine casks on 2026-09-01 because
they fail the Gatekeeper check, and the remaining builds (Gcenx's, CrossOver) are
unsigned or commercial. rr is Linux-only (it relies on Linux's perf events and ptrace),
and hotspot reads Linux perf data only.

### FunctionID for Visual C++ 6.0

Ghidra's Function ID analyzer names statically linked runtime functions by hash. Ghidra
12.1.4 ships these x86 databases (`Ghidra/Features/FunctionID/data/`, active by default):
Visual Studio 2012, 2015, 2017 and 2019 in their own files, and `vsOlder_x86.fidbf` with
"1998", 2003, 2005, 2008 and 2010 (Debug and Release). The "1998" set is built from
Visual C++ **4.2** (its records come from `VC42/.../MSDEV/lib`), not from VC6; 2003 is
Visual C++ 7.1. Visual C++ 6.0 and 7.0 (2002) are not covered, and no public set with a
license covers them (threatrack's ghidra-fidb-repo has glibc, OpenSSL and similar, no
MSVC; others have no license). The runtime libraries are Microsoft's, so the suite does
not ship a VC6 set: build one from your own Visual C++ 6.0 installation:

1. In a Ghidra project (say `work/fid/`), File > Batch Import the `.lib` files of
   `VC98/LIB` (`LIBC.LIB`, `LIBCMT.LIB`, `MSVCRT.LIB` and the debug `...D.LIB`, plus
   `MFC/LIB` when the game uses MFC). Batch Import opens the archives and imports each
   `.obj`; put release and debug libraries in separate folders. `ImportMSLibs.java`
   (FunctionID's scripts) does the same for a whole installation.
2. Analyze them all (the default analyzers are enough).
3. Tools > Function ID > Create new empty FidDb (`work/fid/vc6_x86.fidb`), then
   Populate FidDb from programs: family `Visual Studio`, version `6.0`, variant `Release`
   or `Debug`, the folder of that variant, language `x86:LE:32:default`, and as Common
   Symbols File `Ghidra/Features/FunctionID/data/common_symbols_win32.txt` (as Ghidra's
   own sets were built; `building_fid.txt` there). Headless: `CreateEmptyFidDatabase.java`
   and `CreateMultipleLibraries.java`.
4. Tools > Function ID > Attach existing FidDb picks it up for the GUI; it stays attached
   for that Ghidra version. In an analyzed program, run Analysis > One Shot > Function ID.

Keep the `.fidb` in `work/` (ignored): it is derived from Microsoft's libraries and does
not go into git.

## Linting the suite's own code

`.githooks/lint.sh` runs ruff (format and lint) on the Python, shellcheck on every shell
script and, where `pwsh` is installed, a parse check on the PowerShell scripts. Both
linters come from the `dev` group in `pyproject.toml` (`shellcheck-py` ships the shellcheck
binary), so `uv.lock` pins them. It runs in three places:

- `.githooks/pre-commit`: on the staged files, before the secret scan.
- `rea-suite lint [file...]`: by hand, on every tracked file or the ones given.
- `.forgejo/workflows/lint.yml`: on every push and pull request on the server (no `pwsh` there).

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
| Kaiju (CERT/CC) | Function hashing across binaries, OOAnalyzer C++ class recovery | prebuilt or built (Z3 from its release, as upstream's CI does) |
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
| Rust | rustup (toolchain in `.runtime/rustup`, `.runtime/cargo`) | rustup | Rustlang.Rustup (winget) |
| Other architectures | binutils-multiarch, gdb-multiarch, qemu-user + binfmt (run ARM/MIPS/... userland binaries directly) | – (no qemu-user on macOS) | – |

MSVC is checked, not installed: it needs the Visual Studio installer with the
"Desktop development with C++" workload.

The same component builds tools that have no release for the platform (`build:` in
`common/tools.yml`): apkeep on macOS (cargo), pycdc everywhere (CMake, no upstream
releases). A build lands in `tools/<name>/<version>/` like a download, so
`rea-suite update` builds again only when there is a new release or commit;
`REA_TOOLS_NO_BUILD=1` skips builds, and `doctor` then reports those tools as info.

## macOS

Same commands as on Linux (`bin/rea-suite`, `bin/rea`, `rea-ghidra`); system packages
come from `platforms/macos/Brewfile` instead of apt. Differences:

- Ghidra's release zip has no macOS natives (decompiler, demanglers), so `rea-tools`
  builds them in every new Ghidra install with Ghidra's own `gradlew buildNatives`
  (Xcode CLT, ~15 s). With `--no-build` / `REA_TOOLS_NO_BUILD=1` they are skipped and
  `rea-tools check` reports them missing.
- Not available: Detect It Easy (only a .pkg installer for Apple Silicon, no die-python
  wheel), unblob, qemu-user, gdb-multiarch, x86 multilib; from component `porting`
  Wine, rr, perf and hotspot ([Porting old games](#porting-old-games)).
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
| pwndbg/gdb, unblob, pwntools, REA NativeAOT and pwndbg core contexts, binwalk, qemu-user, Wine, rr, perf + hotspot | Linux/WSL only |
| x64dbg + ScyllaHide, dnSpyEx, PE-bear, Steamless, Sysinternals (Process Monitor), System Informer, WinDbg, debugging Windows processes | Windows only |
| Ghidra, Rizin/Cutter, ImHex, JADX, ILSpy, DIE, Frida, FLOSS, capa, YARA-X, mitmproxy, SteamCMD, Tracy, REA | both |

From Windows into WSL (paths relative to your WSL home):

```powershell
wsl -- bash -lc "~/Dev/rea/bin/rea-suite doctor"
wsl -- bash -lc "~/Dev/rea/tools/bin/pwndbg"          # Linux-only tool on a Windows box
wsl -- bash -lc "cd ~/Dev/rea && source ./activate && unblob -e work/out work/firmware.bin"
# WSL files for Explorer / Windows tools: \\wsl.localhost\Ubuntu\home\<user>\Dev\rea\work
```

From WSL into Windows (needs WSL interop; check `cat /proc/sys/fs/binfmt_misc/WSLInterop`,
it is controlled by `[interop] enabled` in `/etc/wsl.conf`). With a Windows checkout set up
as well, `rea-suite setup` in WSL writes launchers in `tools/bin` for its Windows-only
tools (x64dbg/x32dbg, dnSpy, PE-bear, Steamless): `x64dbg work/sample.exe` then starts
the Windows x64dbg, with existing Linux paths in the arguments turned into Windows paths.
That is how REA and agents in WSL reach them too. The Windows checkout is found through
`rea-suite.cmd` on the Windows PATH (setup puts it there), or set `REA_SUITE_WINDOWS_ROOT`
in `.env`; `rea-tools wsl-bridge` writes the launchers again. Windows programs on the
Windows PATH (Sysinternals, `notepad.exe`) work from WSL without any of this.

```sh
x64dbg work/sample.exe            # interop launcher (see above)
cmd.exe /c 'C:\Users\<user>\rea-suite\tools\bin\x64dbg.cmd' "$(wslpath -w work/sample.exe)"  # by hand
powershell.exe -File 'C:\Users\<user>\rea-suite\platforms\windows\rea-suite.ps1' doctor
wslpath -w work/sample.exe        # Linux path -> Windows path (and `wslpath -u` back)
```

Notes:

- Frida/LLDB/x64dbg attach only to processes on their own side; to instrument a
  Windows process, run the Windows install.
- mitmproxy in WSL can intercept Windows traffic by pointing the Windows proxy at
  WSL's address (`localhost` with WSL's mirrored networking mode).
- `.claude/skills` is a symlink; a Windows checkout gets it only with symlinks enabled
  (Developer Mode and `git config --global core.symlinks true` before cloning). Agents that
  read `.agents/skills` need neither.
- Agents (REA MCP) can be registered on either side with `rea-suite agents` /
  the Windows equivalent; each registration uses that side's `bin/rea`.
- GUI tools from WSL appear on the Windows desktop through WSLg.

## Not included

- **Ghidra MCP plugins** (GhidraMCP, ghidra-mcp, GhidrAssistMCP), **jadx-ai-mcp**:
  overlap with REA; pick at most one if needed.
- **BinExport/BinDiff**: last binary releases target old Ghidra; ghidriff covers diffing
  for now (see `TODO.md`).
- **Ghidrathon** (archived; PyGhidra is built in), **efiSeek** (gone; firmware-utils),
  **frida-dexdump**, **fridump**, **de4dot**, **API Monitor**: unmaintained.
- **rz-ghidra for the rizin CLI**: needs a shared Rizin build; Cutter bundles it.
- **x64dbg-automate**: plugin must be built with MSVC.
- **Commercial**: IDA Pro (REA via `REA_IDA_MCP_CONFIG`), Binary Ninja, Hopper.
