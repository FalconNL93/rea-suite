# PS1 / PS2: tools and the `playstation` command

The tool reference for PlayStation work: what the suite installs, the `rea-suite playstation` command,
and what the reverse-engineering and decompilation communities use that the suite has or lacks. The
routes from a disc to a port, a decompilation or a recompilation are [PS1.md](PS1.md) and
[PS2.md](PS2.md).

Checked: **2026-11-12** (tools, releases and the table of what the communities use).

## Install

Run `rea-suite select`, enable **playstation** (and **decomp** for a decompilation), and keep your other
components selected. Selection runs setup.

| Tool | Purpose | Component | Linux x86_64 / macOS ARM / Windows x64 |
|---|---|---|---|
| dumpsxiso / mkpsxiso | Extract 2352-byte CD BIN/CUE; keep an XML layout to rebuild the CD | playstation | release binaries |
| chdman | CHD images to CUE/BIN (CD) or ISO (DVD) | playstation | apt `mame-tools`, brew `rom-tools`; **not on Windows** (MAME's winget installer needs an install location; its release `mame*b_x64.exe` holds `chdman.exe`) |
| ghidra_psx_ldr | PS-X EXE loader, PSX processor with GTE, PsyQ library signatures | playstation | exact-version Ghidra extension |
| Emotion Engine: Reloaded | PS2 EE R5900/MMI/VU0 macro instructions, STABS from `.mdebug` (bundled x86_64 `stdump`), PCSX2 savestate import | playstation | exact-version Ghidra extension |
| jPSXdec | PS1 audio/video and supported image assets; CLI and GUI | playstation | Java JAR; current release is beta and has non-commercial terms |
| PCSX-Redux (`pcsx-redux`) | PS1 emulator for RE: debugger, memory editor, GDB server, web API, Lua; OpenBIOS, so no Sony BIOS is needed | playstation | newest distrib.app build per platform (no GitHub releases); Windows also `psyq-obj-parser` |
| PCSX2 (`pcsx2`) | PS2 emulator with its debugger (EE and IOP), symbols from the ELF, PINE for scripted memory access; needs your console's BIOS | playstation | release AppImage, `.app`, Windows `.7z` |
| splat (`splat`) | Split a PS-X EXE or a PS2 ELF into assembly, data and a linker script; `splat create_config` writes the first YAML | decomp | PyPI `splat64[mips]`, its own uv environment |
| objdiff (`objdiff`, `objdiff-cli`) | Match compiled objects against the original, function by function (GUI and CLI) | decomp | release binaries |
| 7-Zip | Extract ordinary 2048-byte ISO9660 images, PS2 DVDs included | base suite | |

Loaders use prebuilt releases matching the installed Ghidra; there is no source fallback (the PSX
source lacks its PsyQ signature submodule). Without a matching release, setup reports the loader as
FAILED. Deselecting a component stops updates and checks; installed tools and loaders remain. After
setup: `rea-suite tools check ghidra mkpsxiso jpsxdec pcsx-redux pcsx2 objdiff`.

On Linux both emulators are AppImages run without FUSE: the first start unpacks each into
`$TMPDIR/appimage_extracted_<hash>` (about 200 MB each), which later starts reuse and nothing removes.
On WSL `/tmp` is memory: delete those folders when done, or start the emulator with `TMPDIR` set to
a folder in `work/`. `pcsx-redux -cli` runs without a window (Lua and the GDB server stay); PCSX2
has no headless mode (`-nogui` hides only its main window).

## `rea-suite playstation`: prepare a project

One image, directory, or executable per invocation. Use a new output directory each time.
Paths are relative to your terminal's current directory. On Windows use `rea-suite.cmd`.

| Goal | Command |
|---|---|
| Inspect the plan without writing files | `rea-suite playstation game.cue --project work/game --plan` |
| Extract a PS1 CD and import its boot executable | `rea-suite playstation game.cue --project work/game --ghidra` |
| Extract a PS2 DVD ISO and import its EE executable | `rea-suite playstation game.iso --project work/game --ghidra` |
| Use an already extracted game | `rea-suite playstation /path/to/extracted --project work/game --ghidra` |
| Supply a boot path when SYSTEM.CNF is missing | `rea-suite playstation /path/to/extracted --boot SLUS_000.00 --project work/game --ghidra` |
| Prepare without Ghidra | `rea-suite playstation game.iso --project work/game` |

The boot name above is illustrative. Use the actual `BOOT` / `BOOT2` path in `SYSTEM.CNF`.
For split BIN tracks, pass the CUE and keep its referenced files inside the same directory tree.
Raw BIN without a CUE can lose audio-track information. ISO9660 ISO files take the 7-Zip route;
2352-byte CD images take the dumpsxiso route, regardless of filename extension. A CHD is refused:
convert it first (`chdman extractcd -i game.chd -o game.cue` for a CD, `chdman extractdvd -i
game.chd -o game.iso` for a DVD).

| Output | Contents |
|---|---|
| `project.json` | Source/CUE-track SHA-256, file inventory, executable hashes/headers (`ps1-exe`, `ps2-ee`, `ps2-irx` for IOP modules, `mips-elf`), resolved boot, commands, errors |
| `disc/`, `disc.xml` | Extracted files; layout XML for raw CDs only |
| `ghidra/playstation.gpr` | Editable project when `--ghidra` is used |
| `analysis/functions.tsv`, `analysis/entry.c` | Function inventory and entrypoint pseudocode when available |
| `logs/`, `notes/`, `patches/` | Tool logs and space for your findings/changes |

Extracted-directory inputs stay in place; the project refers to them rather than copying them.
Existing output directories are refused. Failed runs retain `status: incomplete` and their logs.
Extraction/analysis limits default to 600 seconds; use `--timeout` to change them
(Ghidra gets another 120 seconds for import/export overhead). `--max-files` bounds the
inventory, not extracted byte size. Allow space for a full uncompressed image.
Ghidra analyzer errors and unavailable entrypoint pseudocode produce explicit warnings.
`--ghidra` imports the boot program only, and refuses a non-R5900 MIPS ELF as an EE boot.
Check assembly and logs; a saved project does not establish complete or correct analysis.
The project's Ghidra folder takes `rea-ghidra`'s queries: `rea-ghidra functions --project
work/game/ghidra <program>`, and `decomp` and `xrefs` the same way.

## What the communities use, and what the suite has

Checked 2026-11-12 against the upstream repositories and release pages linked. The Ghidra pin is
12.1.4 (`common/tools.yml`, the version REA verifies).

| Tool | Used for | In the suite |
|---|---|---|
| [ghidra_psx_ldr](https://github.com/lab313ru/ghidra_psx_ldr) | PS-X EXE, GTE, overlays, PsyQ signatures | yes. Its newest release (2026.11.08) is built for Ghidra 12.2 only; the suite takes 2026.10.03, the newest with a 12.1.4 build |
| [psx_psyq_signatures](https://github.com/lab313ru/psx_psyq_signatures) | PsyQ library signatures by SDK version | yes, inside the loader's release |
| [ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded) | R5900, MMI, VU0 macro, STABS, PCSX2 savestates | yes, v2.1.39 (12.1.4 build) |
| ghidra-ps2sdk (abelbriggs1) | PS2 SDK library analyzer and type databases on top of EE Reloaded | **no**: its GitHub repository answers 404 (2026-11-12); no other source found |
| [splat](https://github.com/ethteck/splat) | split PSX/PS2/N64/PSP executables for a decompilation | yes (component `decomp`) |
| [objdiff](https://github.com/encounter/objdiff) | per-function match against the original | yes (component `decomp`) |
| [maspsx](https://github.com/mkst/maspsx) | makes GCC's assembly assemble as PsyQ's ASPSX did, for matching PS1 code | no: maspsx itself has no release or package (its one release tag, `aspsx`, 2026-10-13, holds the original ASPSX binaries and a `psyq-obj-parser` build, not maspsx; checked 2026-11-13); decompilation projects carry it as a submodule |
| [asm-differ](https://github.com/simonlindholm/asm-differ), [m2c](https://github.com/matt-kempster/m2c) | assembly diff; MIPS assembly to a C draft | no: no release (the PyPI name `m2c` belongs to another project); projects carry them as submodules, [decomp.me](https://decomp.me) runs both online |
| [decompals/old-gcc](https://github.com/decompals/old-gcc) | the GCC 2.x builds PsyQ shipped, for matching | no: a project's own toolchain, downloaded by its build (Linux x86_64 releases) |
| [psy-q-splitter](https://github.com/sozud/psy-q-splitter), [psyz](https://github.com/Xeeynamo/psyz) | splitting the PsyQ libraries; replacing them with native code for a PC build | no: source only, niche |
| [PCSX-Redux](https://github.com/pcsx-redux/pcsx-redux) | PS1 debugger, GDB server, Lua, psyq-obj-parser | yes |
| [DuckStation](https://github.com/stenzek/duckstation) | accurate PS1 emulation, debugger | no: PCSX-Redux covers RE. DuckStation has a GDB server (`src/core/gdb_server.cpp`, settings `GDBServer` and `GDBServerPort`, checked 2026-11-13), so it could be a second oracle; its license is CC BY-NC-ND 4.0, which allows running it unmodified |
| [PCSX2](https://github.com/PCSX2/pcsx2) | PS2 debugger (EE/IOP), symbol import, PINE | yes. It has **no GDB stub** (none in its source tree, 2026-11-12) |
| [mkpsxiso](https://github.com/Lameguy64/mkpsxiso) | PS1 CD extract and rebuild | yes |
| [jPSXdec](https://github.com/m35/jpsxdec) | PS1 video, audio, images | yes |
| [chdman](https://docs.mamedev.org/tools/chdman.html) | CHD to CUE/BIN or ISO | yes, Linux and macOS |
| [armips](https://github.com/Kingcom/armips) | assemble patches into an executable | no: its newest release, v0.11.0 (2020-05-10), has one asset, a 32-bit Windows build; no Linux or macOS build exists (checked 2026-11-13) |
| [psxrecomp](https://github.com/RetroPortingToolKit/psxrecomp), [RecompOne](https://github.com/BlackLabelHQ/RecompOne) | PS1 static recompilation (to C/C++; to C#) | no: a port takes one as its own dependency. psxrecomp (PolyForm Noncommercial) now has releases: v0.3.7-alpha (2026-11-07) with a Windows x86_64 CLI, a source zip and SHA256SUMS, plus nightlies. RecompOne (MIT) has none. Both moved; the old URLs redirect (checked 2026-11-13) |
| [PS2Recomp](https://github.com/ran-j/PS2Recomp) | PS2 static recompilation (R5900 to C++, a runtime, IOP modules) | no: pre-release tags v0.2 to v0.4 (newest 2026-04-05) with no binaries, so in practice source only (CMake, submodules, tested mainly with MSVC), GPL; a port's own dependency (checked 2026-11-13) |
| PS2 DVD rebuild | a patched PS2 DVD with the original file order | no: no maintained tool found; see [PS2.md](PS2.md) |

## REA

Installed REA **6.8.0** has no verified PS-X EXE or PS2 EE profile. REA 6.9.0 was published on 2026-11-12 (npm `rea-agents`); it still pins Ghidra 12.1.4 and ships a `GhidraMipsProfile.js`. Whether it opens these formats is checked after `rea-suite update` moves to it, not here. Its generic MIPS policy rejects
R5900 machine variants. The `playstation` command uses Ghidra directly; it does not add MCP tools or
make `rea-suite analyze` support these formats. Track [REA #6746](https://github.com/morluto/rea/issues/6746).

## Verification

2026-11-12, Linux x86_64 (WSL2), in a worktree: `setup --no-apt` of the `playstation` and `decomp`
components with source builds off. `lint` passed; `doctor` found the new tools and splat in order
and failed only on what the worktree lacked (`mame-tools` not installed without sudo, extensions that
need source builds, a runtime shared with the main checkout).
Started: `objdiff-cli --version` (3.8.3), `splat --version` (0.50.1), `pcsx2 -version` (v2.8.2),
`dumpsxiso --help` (2.30), `jpsxdec -?` (v2.1 beta), and PCSX-Redux headless (`-cli -exec`, booted
OpenBIOS, ran Lua, quit). Synthetic PS-X EXE and R5900 ELF through `rea-suite playstation --ghidra`
(PSX and EE loaders chosen, projects saved), `rea-ghidra functions` and `decomp` on those projects,
`splat create_config` on the PS-X EXE, and a synthetic IRX (ELF type 0xFF80) imported by Ghidra's ELF
loader. Not verified: chdman (its package needs sudo, which the run did not have), the GUIs (objdiff,
PCSX-Redux, PCSX2: no windows were opened), the emulators with a game, macOS and Windows installs of
the new tools, and the `.7z` extraction on Windows (PCSX2's asset; tested on Linux with a synthetic
archive).
2026-11-03, macOS ARM: real release installers in an isolated work directory; synthetic PS1 CD and
PS2-style ISO extraction; actual Ghidra 12.1.4 imports with console languages; function/pseudocode
exports; jPSXdec CLI startup and synthetic-disc indexing. Console imports disable CERT Kaiju Function
Hashing, which throws on these processors; other analyzer/script errors remain explicit warnings.
The EE STABS analyzer's `stdump` is x86_64-only (macOS ARM relies on Rosetta 2; unverified).
Commercial games, dual-layer DVDs and mixed-mode audio roundtrips are **not tested**.
`update --ai` rechecks this page, compatibility, and these limitations.
