# rea-suite

Personal reverse engineering workbench: [REA](https://github.com/morluto/rea)
(CLI + MCP server) plus the analysis tools around it, installed from one checkout
on Linux/WSL, macOS (Apple Silicon) and Windows so that everything stays updatable
from one place.
Rules for contributors and agents: `AGENTS.md`.
Every document, one line each: [docs/README.md](docs/README.md).

## Layout

```
activate, activate.ps1  load the environment without direnv
.envrc                  direnv entry point -> common/env.sh (+ .env)
.githooks/              pre-commit (lint + gitleaks), commit-msg (commit style), pre-push (gitleaks), lint.sh
.forgejo/workflows/     server-side gitleaks scan and lint
.env.example            copy to .env: component selection, GITHUB_TOKEN
.node-version           Node for fnm (rea-agents has a strict engines range; 24 because the Playwright
                        1.58 that rea-agents 6.8 pins hangs downloading Chromium on Node 26)
.python-version         Python for uv
pyproject.toml/uv.lock  Python tools & libraries (uv)
package.json            rea-agents (npm)
.npmrc                  npm installs only releases a week old (rea-agents exempt)
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
  frida/                Frida scripts for `rea-suite frida`: passive observer, write guard
platforms/
  linux/                bootstrap.sh, apt package list
  macos/                bootstrap.sh, Brewfile
  windows/              bootstrap.ps1, rea-suite.ps1, rea.ps1 (= bin/rea), env.ps1, winget list,
                        run-harness.ps1 (the engine of `rea-suite run`)
AGENTS.md               rules for contributors and agents (CLAUDE.md imports it)
TODO.md                 points to the work queue (Forgejo issues, mirrored in docs/work/)
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
  names; on Fedora/RHEL and Arch `platforms/linux/dnf-names.txt` and `pacman-names.txt`
  translate the ones that differ and `platforms/linux/packages.sh` installs them with apt,
  dnf or pacman. RHEL lacks a few even with EPEL (binwalk, unshield, diffoscope, qemu-user,
  scrcpy, sigrok-cli): `doctor` lists them as not packaged there, everything else works.
  Arch has everything but rr (AUR only) and cross binutils for ARM Linux, MIPS and PowerPC.
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
Rocky and Alma (dnf; the bootstrap enables EPEL and CRB there), and Arch (pacman; it runs
`pacman -Syu` before installing, since Arch does not support partial upgrades). Immutable
systems such as the Steam Deck: see [below](#immutable-systems-steam-deck-fedora-atomic).

```sh
cp .env.example .env                    # optional: settings (components, builds, PATH, agent, REA, token)
platforms/linux/bootstrap.sh            # base packages, .runtime/, component menu, setup
platforms/linux/bootstrap.sh --no-apt   # never use sudo (--no-dnf, --no-pacman: the same); `doctor` lists what is missing
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

### Immutable systems (Steam Deck, Fedora Atomic)

SteamOS, Fedora Silverblue/Kinoite, Bazzite and other image-based systems have a read-only
root, so the suite goes into a [distrobox](https://distrobox.it) (preinstalled on SteamOS
3.5+, Bazzite and Fedora Atomic). The bootstrap notices such a host, creates the box
`rea-suite` (Arch; `REA_SUITE_DISTROBOX_IMAGE` picks another image, such as
`docker.io/library/ubuntu:24.04`), records it in `.env` as `REA_SUITE_DISTROBOX` and goes
on inside it:

```sh
platforms/linux/bootstrap.sh            # on the host: creates the box, installs inside it
```

The box shares your home directory, so the checkout, `.runtime/`, `tools/` and the agents'
configurations are the same inside and out. `bin/rea`, `bin/rea-suite` and `bin/rea-ghidra`
started on the host continue inside the box (`common/box.sh`), so an agent running on the
host starts REA's MCP server there, with the box's lldb, tshark and adb. The tools in
`tools/bin` and the system packages are only on the box's PATH: `distrobox enter rea-suite`
for a shell there. Setting `REA_SUITE_DISTROBOX` on any other Linux uses a box there too.
With the `porting` component, Arch's wine pulls in a kernel package (for its NTSYNC
module), which does nothing in a box.

`setup` also puts `bin/` on your PATH, so `rea-suite`, `rea` and `rea-ghidra` work from
any directory: a marked block in `~/.zshrc` / `~/.bashrc` (fish: `conf.d/rea-suite.fish`),
written once and only replaced by itself; on Windows `<checkout>\bin` (with `rea-suite.cmd`
and `rea.cmd`) appended to the user PATH. Existing entries are never removed, and a file that
already names `bin/` is left alone. `REA_SUITE_NO_PATH=1` skips it.

The scripts run on Homebrew's bash (macOS ships bash 3.2; `bin/` re-executes itself
with `/opt/homebrew/bin/bash`) and `common/env.sh` puts the GNU `gnubin` directories
ahead of the BSD tools, so the shell code is the same as on Linux. Intel Macs are not
supported: the `macos` assets in `tools.yml` are arm64 builds.

Windows (untested so far) needs PowerShell 7 (`pwsh`), not the Windows PowerShell 5.1
that ships with Windows; the scripts refuse to start in 5.1. Install it once, then run
the rest from `pwsh` (winget keeps it up to date from then on):

```powershell
winget install --id Microsoft.PowerShell --source winget
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
| `porting` | no | porting old Windows games: Wine + winedbg, rr, perf + hotspot (Linux), Tracy, WinDbg and the ViGEmBus driver (Windows) ([Porting old games](#porting-old-games); Wine is over 1 GB) |
| `dos` | no | DOS games: DOSBox-X with its debugger for `rea-suite dosbox`; built from source on Linux (with component `build`), the release on macOS and Windows ([port tools](docs/PORT-TOOLS.md#dos-programs-rea-suite-dosbox)) |
| `playstation` | no | PS1/PS2 disc preparation, chdman, Ghidra console loaders, jPSXdec, the PCSX-Redux and PCSX2 emulators ([tools](docs/PLAYSTATION.md), routes for [PS1](docs/PS1.md) and [PS2](docs/PS2.md)) |
| `decomp` | no | decompilation projects: splat (split MIPS executables) and objdiff (match objects against the original) |
| `game-archives` | no | extract-xiso, ZArchive; Windows also XGDTool and QuickBMS ([platform limits](docs/GAME-ARCHIVES.md)) |
| `xbox` | no | original Xbox games: xemu with QEMU's GDB stub, extract-xiso ([route](docs/XBOX-CLASSIC.md)) |
| `ps3` | no | PS3 games: RPCS3 (debugger, GDB stub, decryption for `rea-suite ps3`), RPCS3's source for the NID names, ps3recomp's pipeline, Ps3GhidraScripts ([route](docs/PS3.md)) |
| `gamecube` | no | GameCube and Wii games: Dolphin with its GDB stub, dtk, nod-rs for `rea-suite gamecube`, the GameCube loader for Ghidra (built from source) ([route](docs/GAMECUBE-WII.md)) |
| `psp` | no | PSP games: PPSSPP with its WebSocket debugger, its source's HLE tables to name NIDs, ghidra-allegrex, which REA's PSP profile uses ([route](docs/PSP.md)) |
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
rea-suite doctor               # check everything; exit 1 on problems, each with the smallest fix
rea-suite status               # versions and available updates
rea-suite reinstall python     # or: runtime | node | tools | system | all | <tool from tools.yml>
rea-suite tools prune          # drop old tool versions kept after an update
rea-suite clean                # sizes of the download caches, source builds and inactive tool versions
rea-suite clean caches         # or: builds | tools | all; caches refill on the next setup or build
```

`setup` installs only the system packages that are missing, so with all of them in place it
needs no sudo; `update` on apt passes them all, so they are upgraded.
`update` takes every newest release (pins in `tools.yml` excepted). `update --ai` starts
an agent with the `updating-the-suite` skill (`.agents/skills/`): the first of `claude`,
`codex`, `copilot`, `opencode`, `gemini` it finds, or any command in `REA_SUITE_AGENT`
(the prompt is appended, e.g. `REA_SUITE_AGENT="codex -m <model>"`); without one it prints
the prompt to give to whatever agent you use. The agent reads what the newer rea-agents
verifies (Ghidra, JDK, Kuna, JADX bridge, pwndbg, Node), checks Ghidra extensions and
release notes, and shows a plan of what goes to which version and what is held back and
why. Nothing changes until you approve; afterwards it runs `doctor` and commits as
`AGENTS.md` says.

Each `update --ai` run also researches the offline analysis workflow against current official
documentation and the installed/target tool versions. It reviews presets, CLI contracts,
better approaches, limitations, the short game examples, and the
[self-hosted model guide](docs/LOCAL-MODELS.md) (VRAM, fit and practical usefulness), then includes proposed code
and documentation changes in the same update plan. Checks and unresolved gaps are recorded
in `work/update/workflow-review.md`, including when no package upgrade is needed.

`rea doctor` (rea-agents' own) calls the bin/rea registration stale and suggests
`rea setup`, which registers node_modules/.bin/rea without the suite environment (Ghidra,
the JDK, the tools on PATH). Use `rea-suite doctor` instead: it reads rea doctor's
failures and judges the registrations itself. A `rea setup` run through bin/rea points
the agents back at it afterwards.

`rea-suite agents` checks the complete registration against the suite launcher, including
provider paths, client settings and Codex timeouts. It repairs missing or outdated settings
through REA's configuration writer, preserving unrelated settings and creating recovery
backups. A second run leaves current registrations unchanged. Upstream `rea doctor` can
still report the suite launcher as stale; that alone does not mean it needs repair.
Claude Desktop must be fully quit before running `rea-suite agents claude_desktop`.

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

## Self-hosted models

See [local models by VRAM](docs/LOCAL-MODELS.md) for model/quant candidates, memory estimates,
practical cutoffs, and REA integration requirements. Recommendations are researched, not locally
benchmarked. `update --ai` reviews them on every run.

## Console games and disc images

PlayStation: `rea-suite playstation game.cue --project work/game --ghidra` extracts the image, resolves
its boot program and creates an editable Ghidra project with initial exports. Enable the optional
`playstation` component first. This uses Ghidra directly; REA's console profiles remain limited.
The routes from a disc to a port, a decompilation or a recompilation are [PS1](docs/PS1.md) and
[PS2](docs/PS2.md); the tools and what the communities use that the suite lacks are in
[PLAYSTATION.md](docs/PLAYSTATION.md). [Game archive tools](docs/GAME-ARCHIVES.md) cover Xbox images,
ZAR/WUA and QuickBMS.

PS3: [the route](docs/PS3.md) from the disc or PKG to a recompilation, with component `ps3` (RPCS3,
ps3recomp, the NID names from RPCS3's source). Without Ghidra or a key:

```sh
rea-suite ps3 info EBOOT.BIN              # SELF headers: program type, segments, encryption, NPDRM license
rea-suite ps3 decrypt EBOOT.BIN -o plain  # your RPCS3 decrypts (its keys, your firmware and licenses)
rea-suite ps3 info plain/EBOOT.elf        # ELF/PRX: sections, module, imports and exports, NIDs named
rea-suite ps3 imports plain/EBOOT.elf     # TSV: library, kind, NID, slot, stub, name
rea-suite ps3 census plain/EBOOT.elf      # libraries, syscalls, SPU images, Cell-only VMX (JSON)
rea-suite ps3 analyze plain/EBOOT.elf --project re/ghidra   # Ghidra project: 32-bit addresses,
                                          # r2 set, stubs, exports and OPD functions named
rea-suite ps3 nids 0x8b72cda1 cellPadGetData   # NID to name and name to NID
rea-suite ps3 info PS3_GAME/PARAM.SFO     # title id, title, versions
rea-suite ps3 check                       # RPCS3's build and the NID source (doctor runs it with the component)
```

`decrypt` runs `rpcs3 --decrypt` headless on a copy; `--data DIR` uses another RPCS3 profile (Linux,
Windows), `--klic` gives an NPDRM title's key; `analyze` does the same for a SELF first. RPCS3 is
pinned; `REA_RPCS3_BUILD=latest` (or a build's tag) in `.env` chooses another build for
`rea-suite tools install rpcs3`. Tests: `uv run --no-sync python -m unittest
rea_suite.test_ps3` in `common/` (synthetic SELF, ELF, PRX and SFO; a fake RPCS3); opt-in
`REA_PS3_SAMPLE=<file>` with `REA_PS3_NID_SOURCE=<RPCS3 source>` (a real file, read-only).

Original Xbox (2001): [the route](docs/XBOX-CLASSIC.md) from the disc image to what a recompilation needs.
What the static recompilers, decompilation projects and engine reimplementations already solved, per
platform: [RECOMPILATION.md](docs/RECOMPILATION.md).
Ghidra loads an XBE through the ghidra-xbe extension (`rea-ghidra analyze default.xbe --project ...`),
which names the kernel imports and, with XbSymbolDatabase, the XDK's statically linked library
functions. Without Ghidra (REA itself does not open an XBE):

```sh
rea-suite xbox info default.xbe        # build kind (retail, debug, Chihiro), entry, sections, title, XDK libraries
rea-suite xbox imports default.xbe     # kernel thunks: address, ordinal, name (pyxbe's export table)
rea-suite xbox image default.xbe -o flat.bin   # the image as loaded, at its base, to load raw
rea-suite xbox symbols default.xbe     # XDK library functions by XbSymbolDatabase, as TSV
rea-suite xbox check                   # ghidra-xbe installed and loading (doctor runs it)
```

Component `xbox` adds xemu, whose GDB stub (`-gdb tcp:127.0.0.1:1234 -S`) debugs the original; it needs the
owner's MCPX boot ROM, BIOS and an HDD image. Tests: `uv run --no-sync python -m unittest rea_suite.test_xbox`
in `common/` (synthetic XBEs); opt-in `REA_XBOX_SAMPLE=<default.xbe>` (a real executable, read-only).

GameCube and Wii: [the route](docs/GAMECUBE-WII.md); PSP: [the route](docs/PSP.md). Without Ghidra:

```sh
rea-suite gamecube info game.rvz     # header, region, apploader date, main DOL, file table (RVZ: component gamecube)
rea-suite gamecube info main.dol     # sections, entry, bss, SDK banners; a .rel gives its sections and imports
rea-suite psp info EBOOT.PBP         # sections, PARAM.SFO, the module: info, imports and exports by NID
rea-suite psp info game.iso --names names.txt   # a UMD (ISO or CSO); NIDs named from PPSSPP's tables and your list
rea-suite psp nid sceCtrlReadBufferPositive     # a NID is the SHA-1 prefix of the name
```

Encrypted PSP modules show their outer header only; decrypt your own copy first ([PSP.md](docs/PSP.md),
step 2). `check` (both commands; doctor runs it with the component) checks the Ghidra extension's files.
Tests: `uv run --no-sync python -m unittest rea_suite.test_gamecube rea_suite.test_psp` in `common/`
(synthetic DOL, REL, ISO, PBP, PRX and CSO); opt-in `REA_GAMECUBE_SAMPLE` and `REA_PSP_SAMPLE` (a real
file, read-only).

Xbox 360: [the route](docs/XBOX360.md) from the disc image to a recompilation, with `rea-suite xbox360`.

## Offline analysis projects

`rea-suite analyze` drives the installed tools without an agent or remote model. It accepts
several files or directories, keeps an incremental research project, and prepares results
to read from an IDE. It performs static analysis; it does not launch, inject into, or patch
the supplied application. `rea-suite analyze --help` lists switches, and `--examples` shows
complete workflows. On Windows use `rea-suite.cmd analyze` or `rea-suite.ps1 analyze`.
For short copy-and-run recipes using CoD1, R6BO and ETLegacy files (paths differ per host), see
[game examples (Dutch)](docs/ANALYZE-EXAMPLES.md).

```sh
# First inspect the selected targets and tool commands; creates no project/output.
rea-suite analyze ./game.exe ./plugins ./another-game --project ./research --plan

# Analyze matching binaries recursively; repeat/add inputs to extend the same project.
rea-suite analyze ./game.exe ./plugins --project ./research

# Follow a literal string or symbol through native references, then inspect one function.
rea-suite analyze --project ./research --select game.exe --query ServerList
rea-suite analyze --project ./research --select game.exe --function 0x401230

# Local report/source search, without starting a decompiler.
rea-suite analyze --project ./research --search connect
rea-suite analyze --project ./research --list

# Explicit, bounded pseudocode export, with optional capability/string tools.
rea-suite analyze ./game.exe --project ./research --preset decompile --max-functions 200
rea-suite analyze ./game.exe --project ./research --preset triage --extra capa --extra floss

# An extracted JavaScript/Electron application is an application root, not a binary tree.
rea-suite analyze ./extracted-app --kind javascript --project ./app-research
```

Paths are resolved from the calling directory, even though the suite loads its own environment.
Choose a separate output directory, not the input directory. Without `--project`, output goes
under the suite's ignored `work/analysis/default/`. Directory scans skip `.git`, `.venv`,
`node_modules`, `.runtime`, output directories and nested symbolic links. `--max-files`
bounds the inventory and fails rather than silently truncating it. Auto detection reads
headers: native PE/ELF/Mach-O, PE/CLI assemblies, APK/DEX/JAR and ASAR are supported lanes.
Use `--kind` to select a format explicitly. `--plan` shows the targets actually selected.
Mach-O metadata in `triage` uses REA's macOS inspector on macOS and Rizin elsewhere.

| Preset | Work performed |
| --- | --- |
| `triage` | Literal strings with original file offsets, format-appropriate metadata/imports/exports; no native auto-analysis |
| `analyze` (default) | REA native overview, managed member metadata, archive metadata or JavaScript application analysis |
| `decompile` | Above, plus resumable native pseudocode export, ILSpy C# export or JADX Java export |

Native analysis selects Ghidra explicitly; `--provider kuna` opts into Kuna for ELF and thin
Mach-O only (no PE, no Windows host). With REA 6.8.0 Kuna cannot answer `--query`; use Ghidra
for literal traces. Kuna and Ghidra can report different addresses for the same function. `--query` and
`--function` are repeatable native selectors; they are literal text/names/addresses, not
natural-language questions. A function dossier retains pseudocode, assembly, calls and
references supplied by the selected engine; `.c` and `.asm` views are written next to it.
For managed/Android projects, use `--preset decompile` followed by saved `--search` instead.
Capability matches from `--extra capa` can suggest areas to investigate; FLOSS can recover
some obfuscated strings. Tool/target limitations and failures remain visible.

Open `REPORT.md` in your IDE. `project.json` records target hashes, exact tool commands,
stage exit codes and report digests; `artifacts/<sha256>/` retains original tool JSON,
stderr, snapshots and exported code. Different files with the same basename stay separate.
Successful stages are reused only when inputs, settings, tool fingerprints and saved
report digests match. `--refresh` reruns selected stages, retaining earlier reports.
Directory/application analyses are always rerun because a path is not a content digest.
Native export resumes verified files under a tool-specific export directory. ILSpy/JADX
use fresh export directories so an existing export is never overwritten; a JADX/ILSpy run that
reports decompilation errors after writing output is recorded as partial, with its errors in the
stderr file, and the run still exits 1. Saved `--search` reads only the newest usable export per
decompiler and prints `path:line:column`. Skipped stages and REA error messages appear in `REPORT.md`.

The string preview examines at most 8 MiB and retains at most 5,000 literal strings, with
per-string display capped at 2,000 characters; `triage.json` records this coverage. Native
export attempts at most `--max-functions` per run, in address order (so the first ones are often
import stubs); repeating it continues the matching export. Neither a successful command nor reaching that limit means the whole program was
recovered. Work on your implementation separately from generated analysis output.

### Workflow and research notes

The pipeline follows REA's existing CLI rather than implementing another decompiler:
inventory, inspect identity, collect a focused result, follow references, retain Evidence,
then implement and test your changes separately. REA documents that CLI and MCP use the
[same workflows](https://github.com/morluto/rea#how-rea-works). Its
[noninteractive analysis example](https://github.com/morluto/rea/blob/main/docs/ci-analysis.md)
retains JSON, diagnostics and exit statuses, and distinguishes success from full coverage.
Faults found in REA's own tools, with their workarounds, are in
[known issues](docs/REA-KNOWN-ISSUES.md).

- Start with triage and a concrete question; decompile selected functions before requesting
  a full export. Prefer existing extension/plugin APIs when the application exposes them.
- Keep original bytes, hashes, tool versions/settings and raw evidence. Treat names/types
  inferred by a decompiler as hypotheses; check callers, instructions and runtime behavior.
- Preserve hand-written names/comments/types. REA
  [snapshots cache exact answers, not provider databases](https://github.com/morluto/rea/blob/main/docs/cli.md#save-and-reuse-analysis-snapshots).
  This command creates research workspaces; it does not attach to an existing `.gpr`/Cutter
  database or import its annotations. For that, Ghidra's
  [headless `-process`, `-noanalysis`, `-readOnly` workflow](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md)
  is the appropriate next integration; importing again with `-overwrite` can discard work.
- A useful static cross-reference is a candidate for investigation, not a verified hook
  location. Distinguish file offset, image-relative address and runtime address/ASLR.
  `rea address-to-file-offset <file> <address> --provider ghidra --json` maps one analysis
  address to its original file byte; it does not prove a whole table is contiguous, and loader
  fixups can make analysis bytes differ from file bytes.
  Verify instruction boundaries, moved instructions, ABI, stack alignment and register
  preservation. Microsoft's
  [Detours usage](https://github.com/microsoft/Detours/wiki/Using-Detours) requires matching
  signatures/calling conventions; its
  [interception description](https://github.com/microsoft/Detours/wiki/OverviewInterception)
  explains why displaced instructions need a trampoline. Those Windows rules do not imply
  that the same patch bytes work on another architecture or OS.
- Static evidence shows that code exists, not that it runs. An import is no call: C++ vtables
  import base-class methods the program never calls. A static call graph ends at every virtual
  or computed call. "No callers" in Ghidra is no proof either, since its import can leave code
  that is never made into a function (a key handler, a start-up's `system()` call); cross-check
  with a scan of the bytes themselves (`rea-suite pe callers` and `pe refs` for PE, `rea-suite le
  services` for LE, which decodes the code outside Ghidra's functions too). A check found by its strings and calls may sit behind a function
  compiled to `xor al,al; ret`, so read the guard around it before mapping it. Narrow statically,
  then confirm with a runtime trace (Wine's `+relay`, `rea-suite frida`, `rea-suite dosbox`)
  before declaring something unused or live.
- Keep absent observations and unsupported formats explicit. For example,
  [capa documents limitations](https://github.com/mandiant/capa/blob/master/doc/limitations.md)
  for packed applications and wrapper functions; no match does not establish no capability.
  [JADX likewise documents incomplete decompilation](https://github.com/skylot/jadx#readme).
- For a new build, re-check identities and function correspondence rather than copying old
  addresses. The installed [ghidriff](https://github.com/clearbluejar/ghidriff) (release 1.0.0
  targets Ghidra 11.4; a two-binary diff ran with the suite's 12.1.4 on Linux, 2026-11-03) can
  compare functions and produce JSON/Markdown reports. A second copy of an extension in
  `~/.config/ghidra/<version>/Extensions/` stops it from starting. Automatic transfer of
  annotations or patches is not part of this first pipeline.

Verification: unit tests use `uv run --no-sync python -m unittest rea_suite.test_analyze`.
Opt into real local JavaScript/Ghidra smoke tests with `REA_ANALYZE_INTEGRATION=1`; they
build a benign fixture but never execute the analyzed target. Native smoke tests have
been run on macOS arm64 and Linux x86_64 (WSL2, 2026-11-03); Windows execution remains unverified.

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
| dumpsxiso, mkpsxiso | Extract/rebuild PS1 and PS2 CD images with layout XML (component `playstation`) | tools.yml, release binaries |
| jPSXdec | PS1 media indexing/conversion, CLI and GUI (component `playstation`) | tools.yml, Java JAR |
| chdman | CHD disc images to CUE/BIN or ISO (component `playstation`; not on Windows, [why](docs/PLAYSTATION.md#install)) | apt `mame-tools` / brew `rom-tools` |
| PCSX-Redux (`pcsx-redux`) | PS1 emulator with a debugger, GDB server, Lua and a web API; starts without a Sony BIOS (component `playstation`) | tools.yml, distrib.app builds |
| PCSX2 (`pcsx2`) | PS2 emulator with its EE/IOP debugger and PINE (component `playstation`) | tools.yml, release binaries |
| splat (`splat`) | Split a PS1/PS2 (and N64, PSP) executable into assembly, data and a linker script for a decompilation (component `decomp`) | PyPI `splat64[mips]`, own uv environment |
| objdiff (`objdiff`, `objdiff-cli`) | Match a decompilation's compiled objects against the original, function by function (component `decomp`) | tools.yml, release binaries |
| Dolphin (`dolphin`; Linux `dolphin-emu`, `dolphin-emu-nogui`, `dolphin-tool`) | GameCube and Wii emulator with a debugger, a GDB stub (`-C Dolphin.General.GDBPort=2345`) and DolphinTool; headless on Linux (component `gamecube`; [route](docs/GAMECUBE-WII.md)) | apt `dolphin-emu` on Linux; tools.yml, release 2609b on macOS and Windows |
| dtk (decomp-toolkit) | Split a GameCube or Wii DOL and its RELs into objects for a decompilation, with Metrowerks and SDK signatures; disc images in every format; RARC, U8, Yaz0 (component `gamecube`) | tools.yml, release binaries |
| PPSSPP (`ppsspp`) | PSP emulator with a debugger, a WebSocket debugger API and `.sym` symbol files; decrypts modules on load (component `psp`; [route](docs/PSP.md)) | tools.yml, release v1.20.4 |
| extract-xiso | List/extract/create Xbox XISO images, also a whole Redump image (components `game-archives`, `xbox`) | tools.yml, release binaries |
| ZArchive | Read/create ZAR/WUA (component `game-archives`) | tools.yml; source build with zstd on Linux/macOS, EXE on Windows |
| XGDTool | Xbox/360 disc format conversion (component `game-archives`) | tools.yml, Windows CLI only |
| QuickBMS | Script-driven game archive extraction/reimport (component `game-archives`) | tools.yml, author's Windows ZIP; scripts selected separately |
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
| xemu | Original Xbox emulator (QEMU with the console's hardware); QEMU's GDB stub and monitor debug the original game (component `xbox`; [route](docs/XBOX-CLASSIC.md)) | tools.yml (AppImage, universal macOS app, Windows zip) |
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
| Internet Archive CLI (`ia`) | Search archive.org and fetch preserved game builds, manuals and patches (`ia search`, `ia metadata`, `ia download`; `upload` too). `ia configure` stores your archive.org credentials in your own config (`~/.config/internetarchive/ia.ini`, `%APPDATA%` on Windows), never in this repository; downloads go in `work/` | pip `internetarchive` |
| SteamCMD | Download game builds and specific depots/versions from Steam (component `steam`) | Valve download |
| Steamless | Strip SteamStub DRM from executables before analysis (Windows; component `steam`) | tools.yml |
| Wine, winedbg | Run the original Windows game on Linux and trace its API calls, file and registry access (`WINEDEBUG=+relay`); 32-bit games run through Wine's WoW64, no i386 multiarch needed (component `porting`; not on macOS, see [Porting old games](#porting-old-games)) | apt |
| Process Monitor (`Procmon64`) | File, registry and process activity of the original game on Windows; part of the Sysinternals Suite | winget (Sysinternals) |
| WinDbg (Time Travel Debugging) | Record a Windows run and step it backwards: the Windows counterpart of rr (component `porting`) | winget |
| rr | Record a run once, replay it deterministically under gdb, also backwards (Linux only; component `porting`) | apt |
| perf | Sampling profiles of a slow interpreted or translated game (Linux only; component `porting`) | apt (`linux-perf`) |
| hotspot | View perf recordings: flame graphs, callers and callees, timeline (Linux; component `porting`) | tools.yml (AppImage) |
| Tracy (`tracy-profiler`, `tracy-capture`) | Frame profiler for code you instrument: the native rewrite or the recompiled game (component `porting`) | tools.yml |
| DOSBox-X | Run DOS games and their installers, with its debugger (breakpoints on interrupts, memory, CPU logs); `rea-suite dosbox` drives it (component `dos`) | tools.yml (release on macOS and Windows; built from the release's source on Linux, whose packages lack the debugger) |
| Ghidra FunctionID for old MSVC | Names the C runtime's functions in old games; Ghidra ships Visual C++ 4.2 and 2003-2010, VC6 you build from your own copy ([below](#functionid-for-visual-c-60)) | Ghidra (built in) |
| `rea-suite functions` | A port's index of identified functions (no game bytes) and the gate that checks the executable still matches it; x86/x64 PE and Xbox 360 images ([below](#function-index-and-gate)) | this repo |
| `rea-suite steamstub` | Detect Steam's DRM wrapper before analysis; Steamless removes it ([below](#steamstub)) | this repo |
| `rea-suite frida` | Run a Frida script on a process and log it as JSON lines; a passive observer for exports, addresses and IAT slots (pad state, raw input, call counts per caller); a write guard that keeps a Windows game's file changes inside allowed folders ([port tools](docs/PORT-TOOLS.md#frida-rea-suite-frida)) | this repo |
| `rea-suite dosbox` | A DOS program in DOSBox-X, headless: the INT 21h, 31h (DPMI), 33h and 10h calls it makes with registers, mode and decoded arguments (file names, DPMI real-mode calls), entries into real-mode callbacks, and DOSBox-X's own log (INT 21h, file operations, port E9h text) as JSON lines; memory dumps and pokes at a trigger (an interrupt, a file open, a time, an input item, the exit) and scripted keys, mouse positions and clicks for unattended runs; named memory regions at sync points as a sequence file, and `compare`, which finds the first difference from a port's run of the same input ([port tools](docs/PORT-TOOLS.md#dos-programs-rea-suite-dosbox)) | this repo |
| RPCS3 | PS3 emulator and debugger: GDB stub (PPU threads), PINE memory access, logs per module, LLE/HLE per library, RSX captures, `--decrypt` (component `ps3`) | tools.yml (pinned build per platform) |
| ps3recomp | PS3 static recompilation: Python pipeline (ELF/fSELF, PPU and SPU disassemblers and lifters, SPU images, NIDs) and runtime library (component `ps3`) | tools.yml (release bundle) |
| `rea-suite ps3` | PS3 files from the file alone: SELF headers without a key, ELF/PRX module tables with NIDs named from RPCS3's source, PARAM.SFO; decryption handed to your RPCS3 ([route](docs/PS3.md)) | this repo |
| `rea-suite xbox` | Original Xbox XBEs from the file alone: headers, title, XDK library versions, kernel imports by name, the flat image as loaded, the XDK functions XbSymbolDatabase finds ([route](docs/XBOX-CLASSIC.md)) | this repo |
| `rea-suite gamecube` | GameCube and Wii files from the file alone: a DOL's sections, entry and SDK banners, a REL's sections and imported modules, a disc image's header, main DOL and file table (ISO here; RVZ, WIA, WBFS, CISO, GCZ and Wii partitions through nod-rs, component `gamecube`) ([route](docs/GAMECUBE-WII.md)) | this repo |
| `rea-suite psp` | PSP files from the file alone: EBOOT.PBP sections and PARAM.SFO, a PRX's or ELF's module info with its imports and exports by NID (named from PPSSPP's HLE tables, tool `ppsspp-source`, and your own list), an encrypted module's outer header, the same from an ISO or CSO ([route](docs/PSP.md)) | this repo |
| `rea-suite pad` | A virtual Xbox 360 pad pressing buttons on a schedule, for testing a game's pad input without a person (ViGEm; Windows only, component `porting` for the driver) ([port tools](docs/PORT-TOOLS.md#virtual-pad-rea-suite-pad-windows)) | this repo |
| `rea-suite run` | One bounded, observed run of a Windows program or game: arguments, environment and working folder, a script of steps (waits, scan-code keys, clicks, text, pad presses, captures) sent only while its window is verified in front, captures (PrintWindow, the screen as fallback), message boxes recorded and answered, modules, child processes and endpoints sampled, the install folder proven unchanged, WM_CLOSE then a kill of the whole job, a JSON report (Windows, and WSL through pwsh.exe) ([port tools](docs/PORT-TOOLS.md#run-harness-rea-suite-run-windows)) | this repo |
| `rea-suite pe` | PE scans from the file alone, no project: the image's directories; a port's declared patch sites checked by hash and bytes; MSVC RTTI classes with vtables, slots and bases; references to an address or string; callers; strings a code range loads; every call site of an import DLL's functions; a game's option registry; disassembly with imports and names noted, a mnemonic histogram; resources decoded (dialogs, menus, strings, version) and icons exported; containing functions on x86 from a function table or heuristics ([port tools](docs/PORT-TOOLS.md)) | this repo |
| `rea-suite pe match` | A known build's functions and data found in a later build of the same code (moved, partly changed, stripped): by normalized instructions, string sets and the calls of matched pairs; a TSV map and a port's address header rewritten with candidates; x86 and x64 ([port tools](docs/PORT-TOOLS.md#a-later-build-match)) | this repo |
| `rea-suite rmdp` | Remedy packages (`.bin` index and `.rmdp` data: Alan Wake, Remastered, American Nightmare, Quantum Break, Control), read only: list, extract, search the bytes, and unpack Alan Wake's level containers ([port tools](docs/PORT-TOOLS.md)) | this repo |
| `rea-suite yetibig` | YETI engine archives (`Yeti.big`: Lost: Via Domus on PC and Xbox 360), read only: header and class histogram, resources by key with their copies, unpacked (LZO1X through liblzo2 when the system has it, else pure Python), two archives compared by key, the reference graph of the resources' key lists, and a full coverage proof ([port tools](docs/PORT-TOOLS.md#yeti-engine-archives-rea-suite-yetibig)) | this repo |
| `rea-suite le` | LE/LX executables (Watcom DOS/4GW and other DOS extenders, VxDs, OS/2) from the file alone: the stub and its extender, header, objects, fixup counts, entry point, imports; an object or the whole image dumped with its internal fixups applied, to load raw; the DOS services the code uses (INT n with AH/AX, DPMI, I/O ports, segment loads, far and 16-bit code) ([port tools](docs/PORT-TOOLS.md#linear-executables-rea-suite-le)) | this repo |

radare2 is deliberately left out: Rizin is its fork with the same feature set,
and REA integrates Rizin (`REA_RIZIN_COMMAND`, Cutter bridge).

`common/env.sh` exports the absolute paths REA expects (`REA_KUNA_COMMAND`,
`REA_JADX_MCP_JAR`, `REA_PWNDBG_*`, ...) for every
tool it finds, so `rea doctor` picks them up through `bin/rea`.

`REA_GHIDRA_NATIVEAOT_JAR` is explicitly opt-in through `.env` or the launch environment.
REA's optional adapter requires its own facade JAR and a supported Linux/x64 target;
the installed upstream Ghidra extension is not that adapter. Automatically enabling it
would block ordinary native analysis on unsupported hosts/targets.

## Porting old games

Component `porting` (`rea-suite select`) brings the tools for running, tracing and
profiling an original Windows game while you recompile, interpret or rewrite it. Which approach fits
which platform, and what the existing recompilers and reimplementations teach:
[RECOMPILATION.md](docs/RECOMPILATION.md).

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

For a periodic hitch, look at CPU per thread first (`top -H -p <pid>`, or each thread's
`/proc/<pid>/task/<tid>/stat`): it tells a busy game thread from a polling or worker thread
before any profile. Then profile the thread that bursts with `perf record --call-graph dwarf -p
<pid>`, which unwinds without frame pointers; a release binary that keeps its symbols is enough.

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

### Function index and gate

A port keeps the functions it has identified in a table of its own: game, address, name, what
it does, where the port uses it, a signature and the date it was checked. The signature is a
truncated SHA-256 over the function's bytes, so the table holds no game bytes; the gate says
whether the executable in front of it still has those functions there.

```sh
rea-suite functions re/functions.json add pc 0x0040b980 QuitGame "ends the game" src/app.cpp
rea-suite functions re/functions.json find quit
rea-suite functions re/functions.json check     # exit 1 on a mismatch, 2 when the table is empty
rea-suite functions re/functions.json convert pc re/old-functions.tsv   # address/name/hash/what
```

The JSON config is the one of the Xbox 360 gate in games/rexglue-sdk
(`scripts/xbox360/function_index.py`); its configs work unchanged, and both write the same table:

```json
{"index": "functions.tsv",
 "games": {"pc": {"image": "${GAME_DIR:-../game}/Game.exe", "signature": "body",
                  "entries": "function_entries.tsv"},
           "sp": {"image": "xex/default.bin", "base": "0x82000000",
                  "partition": "../src/generated/codegen.partition.json"}}}
```

Paths are relative to the config, `${NAME:-default}` takes the environment, and `--image
GAME=PATH` overrides one. With `base` the image is a flat memory image (`rea-suite xbox360
extract`); without it a PE (x86, x64), read through its section table. The function starts come
from codegen's `partition` or an `entries` TSV (first column; `rea-ghidra functions` output
fits), and `check` then also says when no function starts at an entry. `signature` is `head`
(default: the first 32 bytes, 12 hex digits) or `body` (from the entry to the next function
start, at most 64 KiB, 16 hex digits; it notices a change anywhere in the function). Tests:
`uv run --no-sync python -m unittest rea_suite.test_functions` in `common/` (synthetic images).

### Imports by ordinal (MFC42 and others)

REA's Ghidra sessions name an import `<DLL>::<function>`: `KERNEL32.DLL::CreateFileA`,
`MFC42.DLL::CDialog::OnInitDialog`. An import by ordinal carries no name; Ghidra names it from
its ordinal tables in `$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/data/symbols/win32/` (MFC 4.2 to
14.0 in `mfc*.exports`, both ANSI and Unicode) and from the user's tables in
`~/.config/ghidra/<version>/symbols/win32/`. For a DLL in neither it shows `Ordinal_<n>`
(`OLDLIB.DLL::Ordinal_4710`). To name those:

- One ordinal by hand: `grep 'ORDINAL="4710"' "$GHIDRA_INSTALL_DIR"/Ghidra/Features/Base/data/symbols/win32/mfc42.exports`,
  and `llvm-undname '<the NAME>'` (component `build`) for the C++ signature.
- A DLL that exports by name too (the game's own engine DLLs): import it once without analysis
  and let Ghidra write its table, then analyze the executable again (a fresh REA session, or a
  new `rea-ghidra` project: names come from the tables at import):

  ```sh
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" work/exports dlls -import game/Engine.dll \
    -noanalysis -readOnly -postScript CreateExportFileForDLL.java
  ```

  The script prints the `.exports` file it wrote under `~/.config/ghidra/`.
- A DLL that exports by ordinal only (MFC42 exports all of its functions so): the names are in
  the import library's `.DEF` (Visual C++ 6.0's `MFC42.DEF`, from your own copy) or Ghidra's
  table; use them to cross-check, they cannot come from the DLL.

Checked 2026-11-03 with Ghidra 12.1.4 and synthetic executables importing `MFC42.DLL` and an
unknown DLL by ordinal: REA gave `MFC42.DLL::AfxWinMain` and `Ordinal_4710`, and after
`CreateExportFileForDLL.java` on that DLL, Ghidra gave its name.

### SteamStub

Steam's DRM wrapper encrypts the code and moves the entry point into a stub, so analysis of
the wrapped file sees nothing useful. Check first, from the file alone:

```sh
rea-suite steamstub game/Game.exe          # exit 0 none, 1 SteamStub or possibly, 2 not a PE
```

It reports a `.bind` section (where the stub lives), the entry point in it, a code section near
random (entropy over 7.2 bits a byte: encrypted), and a header timestamp in the future or
different from the debug directory's (the file was rewritten after linking; on its own this is no proof, patched
retail executables show it too), with the file's SHA-256. `.bind` with the entry point in it is
SteamStub. Tests: `uv run --no-sync python -m unittest rea_suite.test_steamstub` in `common/`.

Removing it is Steamless (component `steam`, Windows; from WSL through the interop launcher):

```sh
steamless-cli --quiet game/Game.exe        # writes game/Game.exe.unpacked.exe; Game.exe stays
rea-suite steamstub game/Game.exe.unpacked.exe   # none: .bind gone, code readable
sha256sum game/Game.exe game/Game.exe.unpacked.exe
```

Unwrapping a game's executable needs the owner's permission, per game, each time a new
executable is unwrapped. Record in the port, next to the files: the wrapped file's SHA-256 and
version, the Steamless version (or its commit), the date of the permission, and the unwrapped
file's SHA-256, which the port's build then checks. Steamless rebuilds the headers, so the
result is not byte-identical to a retail executable even when its code is. Steamless names
the variant (SteamStub 1.0 to 3.1) in its log.

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

Steps 1 and 2 run headless too, which suits a whole installation. With your copy in
`~/Dev/libs/vc6` (any folder holding `VC98/`), one folder per variant in the project:

```sh
vc6=~/Dev/libs/vc6/VC98 fid=work/fid headless="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
mkdir -p "$fid"
for lib in LIBC LIBCMT MSVCRT; do       # the release libraries; ...D for Debug, MFC/LIB/*.LIB for MFC
  "$headless" "$fid" vc6/VisualStudio/6.0/Release -import "$vc6/Lib/$lib.LIB" -recursive -noanalysis \
    > "$fid/import-$lib.log" 2>&1
done
"$headless" "$fid" vc6 -process -recursive > "$fid/analyze.log" 2>&1   # analyzes every .obj
```

`-recursive` opens each archive and imports its members (`LIBC.LIB` gives about a thousand
`.obj`), under the folder after the project name. That folder layout (family, version, variant)
is the one `CreateMultipleLibraries.java` expects at depth 3; step 3 then picks the project's
root. Checked 2026-11-03 with Ghidra 12.1.4 on `LIBC.LIB`: 1,076 objects imported and analyzed
in about 3 minutes, no errors. Steps 3 and 4 were not run here.

Keep the `.fidb` and the project in `work/` (ignored): they are derived from Microsoft's
libraries and do not go into git.

## Linting and testing the suite's own code

`.githooks/lint.sh` runs ruff (format and lint) on the Python, shellcheck on every shell
script and, where `pwsh` is installed, a parse check on the PowerShell scripts. Both
linters come from the `dev` group in `pyproject.toml` (`shellcheck-py` ships the shellcheck
binary), so `uv.lock` pins them. It runs in three places:

- `.githooks/pre-commit`: on the staged files, before the secret scan.
- `rea-suite lint [file...]`: by hand, on every tracked file or the ones given.
- `rea-suite check`: lint, then every unit test: `unittest discover` over
  `common/rea_suite/test_*.py` and `node --test` over `common/*.test.mjs`. The opt-in
  integration tests (`REA_*_INTEGRATION`, `REA_*_SAMPLE`) skip unless their switch is set. It
  is the gate before a push, with `rea-suite doctor`.
- `.forgejo/workflows/check.yml`: `rea-suite check` on every pull request and every push but
  one of docs alone (no `pwsh` there). It installs Python's `dev` and `test` groups only
  (`uv sync --only-group dev --only-group test`): the `test` group lists what the tests import
  beyond the standard library, so a test that needs another package adds it there.

## Keeping secrets out of the repository

gitleaks (from `tools.yml`) runs in three places with the same config (`.gitleaks.toml`):

- `.githooks/pre-commit`: refuses a commit whose staged changes contain a secret.
- `.githooks/pre-push`: refuses a push whose new commits contain one (also commits made with `--no-verify`).
- `.forgejo/workflows/gitleaks.yml`: scans the full history on every push and pull request on the server.

`rea-suite setup` enables the hooks (`git config core.hooksPath .githooks`); `rea-suite doctor`
checks that they are on. Findings are shown redacted (rule, file, line). Tokens belong in `.env`
(ignored); a false positive gets an allowlist entry with its reason in `.gitleaks.toml`.

## Commit messages

`.githooks/commit-msg` holds every commit to the platform's shared style: a Conventional Commits
subject (`type(scope): imperative description`, at most 72 characters), a blank line before the
body, no AI attribution, no emoji, US English. It is a byte copy of games/ci-images'
`.githooks/commit-msg`, the one every game repository copies; a change goes there first and is
copied here. The same `core.hooksPath` enables it beside the gitleaks hooks, which it does not
replace: they run on their own hooks (`pre-commit`, `pre-push`).

## Ghidra and its extensions

Setup preserves upstream module/JAR directory names so Java loaders are discoverable. Existing
suite aliases are migrated in place, retaining their versions and logical status IDs. Custom
absolute paths to extension JARs must follow the preserved module directory.

| Extension | What it is for | Source |
| --- | --- | --- |
| FindCrypt | Label crypto constants (AES S-boxes, hash IVs, ...) during analysis | prebuilt per Ghidra version |
| Kaiju (CERT/CC) | Function hashing across binaries, OOAnalyzer C++ class recovery | prebuilt or built (Z3 from its release, as upstream's CI does) |
| ghidra_psx_ldr | PS-X EXE and PSX GTE support (component `playstation`) | exact-version prebuilt |
| Emotion Engine: Reloaded | PS2 R5900/MMI/VU0 macro support (component `playstation`) | exact-version prebuilt |
| GameCube loader | GameCube and Wii DOL, REL, apploader and RAM dumps; the Gekko/Broadway language with paired singles (component `gamecube`; checked by doctor) | built from a pinned commit (no release builds for 12.1.4, and 1.3.1's build needs the old Gradle) |
| ghidra-allegrex | PSP Allegrex with the VFPU and PSP relocations; REA's PSP profile uses it (component `psp`; checked by doctor) | exact-version prebuilt (v21.4 for 12.1.4) |
| XEXLoaderWV | Load Xbox 360 XEX executables (`rea-suite xbox360`; pinned, checked by doctor) | prebuilt or built |
| ghidra-xbe | Load original Xbox XBE executables: kernel imports by ordinal, XDK library functions named by its XbSymbolDatabase CLI (`rea-ghidra`, `rea-suite xbox`; checked by doctor) | prebuilt only (no license file upstream; its build fetches its own Ghidra) |
| Ps3GhidraScripts | PS3 ELF/PRX: import and export tables named by NID, the TOC from the OPDs, LV2 syscalls (component `ps3`; [route](docs/PS3.md)) | built (no 12.1.4 release; `--no-build` skips it; no license file upstream) |
| ghidra-firmware-utils | Load UEFI images, PCI option ROMs and other firmware formats | prebuilt or built |
| ghidra-lx-loader | Load LE/LX executables (DOS/4GW and DOS/16 LE, DOS32A, OS/2 LX, VxD) with their objects at their bases and every fixup applied (`rea-ghidra analyze`; REA's open_binary still refuses LE before Ghidra sees it) | built from a pinned commit |
| ghidra-nativeaot | Recover .NET Native AOT binaries in Ghidra; REA's optional adapter is configured separately | prebuilt or built |

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
rea-suite setup --no-build                      # the same for setup and update
```

Projects opened in a newer Ghidra are upgraded and no longer open in older ones.

Ghidra 12.2 (2026-10-22) needs JDK 25 and saves programs that "may not be usable by an earlier Ghidra
version" (its WhatsNew.md). The owner's decision (2026-11-13): stay on 12.1.4 until REA pins 12.2 (6.9.0
still pins 12.1.4) and the Xbox loaders have 12.2 builds (ghidra-xbe and XEXLoaderWV had none on
2026-11-13; ghidra_psx_ldr 2026.11.08 and Emotion Engine: Reloaded v2.1.39 do), then move every port's
project at once.

### Headless Ghidra from the shell

```sh
rea-ghidra analyze   work/target.exe                # import + analysis, once
rea-ghidra functions work/target.exe > funcs.tsv    # entry, size, name, thunk, callers
rea-ghidra decomp    work/target.exe 0x401000 0x4020a0 > out.c
rea-ghidra xrefs     work/target.exe "license" "serial" > out.c
```

On Windows the same commands run as `bin\rea-ghidra.cmd` (`platforms\windows\rea-ghidra.ps1`).
Projects live in `work/ghidra/<binary name>/`, logs in its `logs/`. The scripts are in
`common/ghidra_scripts/` (taken over from the rogue-spear port). A port keeps its own project
with `--project DIR` (and `--name`, default the folder's one `.gpr`); the queries then take the
program's name alone, open the project read-only and write to `-o FILE` when given:

```sh
rea-ghidra analyze   --project ~/Games/port/ghidra --name port game/Game.exe   # once
rea-ghidra decomp    --project ~/Games/port/ghidra Game.exe 0x0068a380 -o out.c
rea-ghidra xrefs     --project ~/Games/port/ghidra Game.exe -o out.c -- "-server"
rea-ghidra functions --project ~/Games/port/ghidra Game.exe | cut -f1 > re/function_entries.tsv
```

`analyze --force` runs the auto-analysis again on the program already in the project; it never
imports over it, so names, types and comments made there stay. To start from nothing, delete the
project folder. This is the x86/x64 PE counterpart of `rea-suite xbox360 analyze|decomp|xrefs|functions`.

- **Decompile the addresses the question needs**, in one batch, not the whole program: a
  whole-program decompile of a game ran past 25 minutes on decompiler timeouts.
- **Alignment over variables hangs the decompiler; `analyze` clears it.** Kaiju's "Disassembly
  Improvements" analyzer types each run of zero bytes after a data item as Alignment, and Ghidra's
  decompiler never finishes a function that indexes into one, whatever the function's size. Where
  zero-filled variables are initialized memory (an LE's data object holds its bss), that is most
  of them: in Theme Park's `MAIN.EXE` 356 items over 110 KB, and 31 of 1000 functions, from 91
  bytes up, ran into a 60 s limit while every other one took under 1.3 s (checked 2026-11-11).
  `analyze` (and `analyze --force`, for a project analyzed before) ends with
  `ClearDataAlignment.java`, which clears Alignment that follows data and keeps the padding between
  functions; then all 1000 decompiled, the slowest in 4.3 s. Kaiju stays on: without it Ghidra
  found 879 of the 1000 functions. Each function still gets `REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS`
  (default in `common/env.sh`), which also bounds REA, otherwise without a limit; a function past
  it says so in the output. A program REA analyzed itself keeps the Alignment
  ([known issues](docs/REA-KNOWN-ISSUES.md), item 15): decompile those functions with `rea-ghidra`.
- **Every run is bounded** (`common/rea_suite/ghidra_headless.py`, which `rea-suite xbox360`, `xbox`
  and `playstation` use too): `REA_GHIDRA_IMPORT_TIMEOUT_SECONDS` (default 3600) limits one
  `analyzeHeadless` run, after which it and its children are stopped and the error names the log;
  `REA_GHIDRA_MAXMEM` (default 4G) caps Ghidra's heap. Ghidra refuses a project path with a
  component that starts with `.` ("Path element starting with '.' is not permitted"), so a
  project in a worktree under `.claude/` is refused up front: use `--project` elsewhere or
  `REA_GHIDRA_PROJECTS`.
- **One process per project.** Ghidra locks a project for a whole run, so a second agent's
  read-only queries fail with "locked by another process". Give parallel agents a copy of the
  project each, or a route that needs none (`rea-suite pe`, or `rea-suite le dump-image` and Rizin).
- **zsh does not split `$VAR`**: `rea-ghidra decomp game.exe $addrs` passes one argument and
  decompiles nothing. Use an array (`"${addrs[@]}"`) or `${=addrs}`.
REA's own Ghidra provider gives up on a first import after 330 s by default, too short for a large
game; raise `REA_GHIDRA_STARTUP_TIMEOUT_MS` first ([known issues](docs/REA-KNOWN-ISSUES.md), item 9).
Tests: `uv run --no-sync python -m unittest rea_suite.test_rea_ghidra rea_suite.test_ghidra_headless`
in `common/` (a stand-in for `analyzeHeadless`).

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
- Ghidra refuses a universal Mach-O (x86_64 and arm64e, as `/usr/bin/true`); thin it first
  (`lipo /usr/bin/true -thin x86_64 -output work/true`) and open it in REA with
  `provider_id=ghidra`, since without one the choice between providers is ambiguous.
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
pwsh.exe -File 'C:\Users\<user>\rea-suite\platforms\windows\rea-suite.ps1' doctor
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
  for now (issue [#4](https://git.falcon-net.nl/FalconNL93/rea-suite/issues/4)).
- **Ghidrathon** (archived; PyGhidra is built in), **efiSeek** (gone; firmware-utils),
  **frida-dexdump**, **fridump**, **de4dot**, **API Monitor**: unmaintained.
- **rz-ghidra for the rizin CLI**: needs a shared Rizin build; Cutter bundles it.
- **x64dbg-automate**: plugin must be built with MSVC.
- **Commercial**: IDA Pro (REA via `REA_IDA_MCP_CONFIG`), Binary Ninja, Hopper.
