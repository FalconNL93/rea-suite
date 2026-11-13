# PS3 games: the route

How to take a PlayStation 3 game from the player's disc or PKG to what a static recompilation or a
port needs, with the suite's tools in the order they are used. Each step says what its output decides
and feeds next. No port has taken this route yet (2026-11-13). The steps were checked on RPCS3's own
test programs (ps3autotests, GPL-2: fake-signed SELFs and their ELFs) and on synthetic files, not on a
retail game. The traps come from the tools' source and the recompilation projects' documents; the
first port adds its own. Nothing about one game belongs on this page.

What lies around this page:

- The Xbox 360 lane, the closest relative (PowerPC too): the README's "Console games and disc images"
  (`rea-suite xbox360`).
- The PS1 and PS2 routes: [PS1.md](PS1.md), [PS2.md](PS2.md); their tools: [PLAYSTATION.md](PLAYSTATION.md).
- What ps3recomp and the other static recompilers solved, and how: [RECOMPILATION.md](RECOMPILATION.md).
- The port's platform work (the master, the SDK, the port checklist): master-server's docs/PORTING.md.

Install: component `ps3` (`rea-suite select`, then `rea-suite setup`). It brings RPCS3, RPCS3's source
at the same commit (the NID names), ps3recomp's pipeline, and the Ps3GhidraScripts extension for
Ghidra (a source build: see step 3). `rea-suite doctor` runs `rea-suite ps3 check` when the component
is selected.

## The machine, in short

What a port has to answer, and where each part lives:

| Part | What it is | Where a port meets it |
|---|---|---|
| PPU | 64-bit PowerPC, big-endian, VMX (AltiVec), two hardware threads. Games run with 32-bit addresses: pointers are 32-bit, the ELF is ELF64 | the game's main code; ELFv1 ABI with function descriptors (OPD) and a TOC in `r2` |
| SPUs | six usable Synergistic Processor Units (one more is the OS's), each with 256 KiB local store, 128 registers of 128 bits, its own instruction set, and DMA (the MFC) to main memory; mailboxes and signals through channels | SPU programs embedded in the ELF or PRX, started by `sys_spu_thread_*` or by SPURS (libsre: tasks, jobs, workloads) |
| RSX | the GPU, NVIDIA G70/NV47 class: a command buffer (FIFO) of methods of the NV4097 class, vertex and fragment programs compiled from Cg | `cellGcmSys` writes the command buffer; shaders ship as Cg binaries (`.vpo`, `.fpo`) or inside the ELF |
| LV2 | the game OS (kernel). Syscalls by `sc` with the number in `r11`, about 1024 slots | mostly through `sysPrxForUser` (liblv2), which wraps them |
| PRX | the system libraries in firmware (`/dev_flash/sys/external/*.sprx`): `cellGcmSys`, `cellSpurs`, `cellAudio`, `cellFs`, `cellPad`, `cellSysutil`, `sys_net`, `sceNp`, ... | imported by library name and **NID**: a 32-bit id per function or variable, the first four bytes of SHA-1(name + a fixed 16-byte suffix), read little-endian |

The NID is why a stripped game still names its system calls: hash the names you know and match.

## 1. The disc or PKG, as data

```sh
mkdir -p ~/Games/<game>/disc
# a disc dump: a decrypted ISO (mount or 7z x) or the folder tree from the console
sha256sum game.iso
rea-suite ps3 info ~/Games/<game>/disc/PS3_GAME/PARAM.SFO    # title id, title, versions, category
```

- A disc holds `PS3_DISC.SFB`, `PS3_GAME/PARAM.SFO` (title id such as `BLUS30443`), `PS3_GAME/USRDIR/`
  with `EBOOT.BIN` (the game), often `*.sprx` and `*.self` (the game's own modules and programs), and
  `PS3_UPDATE/PS3UPDAT.PUP` (a firmware update, not the game).
- A disc dumped from a console's drive is encrypted per sector; the dump tools write the disc key
  beside it (`.dkey`, or an IRD file). RPCS3 reads decrypted ISOs and folder trees.
- A PSN title is a `PKG` plus its license (`.rap`). `rea-suite ps3 info` names a PKG; install it into
  RPCS3 (`rpcs3 --installpkg game.pkg`), then work on the installed files in RPCS3's
  `dev_hdd0/game/<title id>/`. Its license goes in `dev_hdd0/home/00000001/exdata/`.
- Record the hashes of the image, `EBOOT.BIN` and each module in the port's docs.

*Feeds:* `EBOOT.BIN` and the modules for step 2, the title id for RPCS3 in step 6.

## 2. Identify and decrypt the executables

```sh
rea-suite ps3 info EBOOT.BIN -o work/game/eboot-self.json          # SELF headers, no key needed
rea-suite ps3 decrypt EBOOT.BIN USRDIR/*.sprx -o work/game/plain    # your RPCS3 does it
rea-suite ps3 info work/game/plain/EBOOT.elf -o work/game/eboot.json
```

`info` reads a SELF's plain headers: the SCE header and key revision, the program's authority id and
type (application, NPDRM application, ...), the ELF header and program headers it carries, whether
each segment is compressed and encrypted, and the NPDRM block (license: network, local or free;
content id). A fake-signed SELF (key revision bit 15: debug and prototype builds, homebrew) is not
encrypted at all.

`decrypt` hands each file to RPCS3's own `--decrypt` (headless, no window), which uses RPCS3's keys,
the firmware you installed into it and the licenses in its data folder. It works on a copy, so the
disc tree stays untouched, and moves the result to `-o`: `EBOOT.BIN` gives `EBOOT.elf`, a `.sprx`
gives a `.prx`, an EDAT gives `.unedat`.

- **Your RPCS3 profile**: by default RPCS3's own data folder (`~/.config/rpcs3` on Linux,
  `~/Library/Application Support/rpcs3` on macOS, beside `rpcs3.exe` on Windows), where your firmware
  and licenses are. `--data DIR` points it at another profile (Linux and Windows); `--rpcs3 PATH` (or
  `REA_RPCS3`) at another RPCS3 install.
- **Firmware**: decrypting a SELF needs none (checked: a fresh profile decrypted ps3autotests'
  SELFs byte for byte). Running a game needs it: `rpcs3 --installfw PS3UPDAT.PUP` with your
  firmware file.
- **NPDRM**: a title with a local or network license needs its `.rap` in the profile's
  `dev_hdd0/home/00000001/exdata/`, or its KLIC (`--klic <32 hex digits>`; RPCS3 logs it when the
  game runs). Free titles need neither.
- `ps3recomp`'s `unfself.py` rebuilds the ELF of a fake-signed SELF without RPCS3, and also recovers
  the symbol and DWARF sections a debug build keeps in its tail
  (`uv run python tools/ps3recomp/current/tools/unfself.py EBOOT.BIN -o EBOOT.elf`).

The decrypted ELF is then read with `info` (module tables, sections, the SDK version from
`sys_process_param`) and `imports`:

```sh
rea-suite ps3 imports work/game/plain/EBOOT.elf -o work/game/imports.tsv   # library, NID, slot, name
rea-suite ps3 nids 0x8b72cda1 cellPadGetData                               # either way round
```

- An executable finds its tables through `sys_proc_prx_param` (program header type `0x60000002`); a
  PRX (`e_type` 0xFFA4) keeps its module info at the file offset in the first program header's
  `p_paddr`, with the module's name, version, TOC and table ranges.
- Names come from RPCS3's source at the build's commit: every name its modules register (6589 entries,
  5515 distinct NIDs over 139 modules at `9b8974d3`), plus the NIDs its tables list without a name
  that hashes to them. `nids` says how it knows: `known` (in the source), `listed` (a table gives it),
  `computed` (a name the source lacks, hashed all the same), `unknown`.
- A NID without a name is either a function RPCS3 never needed or one Sony obfuscated; look it up in
  psdevwiki's NID pages or in RPCS3's issues.

*Feeds:* the import census for step 4, the decrypted ELF and PRXs for step 3.

## 3. Ghidra

```sh
analyzeHeadless work/game/ghidra game -import work/game/plain/EBOOT.elf \
  -processor PowerPC:BE:64:A2ALT-32addr -cspec default
rea-ghidra functions --project work/game/ghidra EBOOT.elf -o work/game/functions.tsv
rea-ghidra decomp    --project work/game/ghidra EBOOT.elf 0x10200
```

- **Pick the language yourself.** Ghidra's ELF loader picks `PowerPC:BE:64:A2ALT` (64-bit addresses)
  for a PS3 ELF; the game's pointers are 32-bit, so import with `PowerPC:BE:64:A2ALT-32addr` (Power ISA
  with AltiVec, 32-bit addressing), the same language as the Xbox 360 lane. Checked on ps3autotests'
  `basic.ppu.elf`: import, analysis, `rea-ghidra functions` (138 functions) and `decomp`.
- **The TOC.** Every function reads globals through `r2`. Ghidra's `ppu_64_32.cspec` does not list
  `r2` as preserved across calls, so the decompiler loses it after a call; Ps3GhidraScripts' README
  adds `<register name="r2"/>` to `<unaffected>` in that file (a change to your Ghidra install, which
  `rea-suite tools reinstall ghidra` undoes). Its `AssignPs3R2FromOpd` sets `r2` per function from
  the OPDs.
- **Imports**: Ps3GhidraScripts' `AnalyzePs3Binary` (run before auto-analysis) defines the import
  and export tables and names them from its own NID list, then `DefinePS3Syscalls` names the `sc`
  call sites. Without it, `rea-suite ps3 imports` gives the slot address of every import with its name.
- **Cell-specific VMX loads and stores** (`lvlx`, `lvrx`, `stvlx`, `stvrx`) are not decoded by
  Ghidra's PowerPC language; decompilation stops at them (Ps3GhidraScripts' README). The rest of the
  PPU's VMX is standard AltiVec, which Ghidra decodes: unlike the 360's VMX128, there is no hole there.
- **SPU code**: Ghidra has no SPU language. [GhidraSPU](https://github.com/aerosoul94/GhidraSPU)
  (Apache-2.0, 2023, "work in progress") is one; its SLEIGH compiles with Ghidra 12.1.4 (checked), its
  Java relocation handler is written for Ghidra 9.2 and was not built. ps3-cell-re-tools'
  `spu-sleigh` generates a lane-correct model on top of it. ps3recomp's `spu_disasm.py` disassembles
  SPU code without Ghidra.
- REA does not open a PS3 ELF as a PS3 program (its PowerPC lane is ELF32); use `rea-ghidra`.

*Feeds:* names and function boundaries for the recompiler, the map of each unit a change lives in.

## 4. The census

`imports.tsv` decides where the port's layer answers the game. Count, per library, the functions the
game imports, and mark the ones that decide the shape of the port:

- **Graphics**: `cellGcmSys` (the command buffer, `cellGcmSetFlip*`, tiles, the IO mapping),
  `cellResc`, `cellVideoOut`. Either the port runs the RSX command stream (as ps3recomp and RPCS3 do)
  or the game's own renderer is replaced above it.
- **SPU use**: `cellSpurs*`, `cellSpursJq`, `sys_spu_*` imports, and SPU ELFs embedded in the game
  (`extract_spu_images.py` in ps3recomp lists them; debug builds name them by their `_binary_*`
  symbols). A game whose SPUs only mix audio is a much smaller job than one whose physics, animation
  or decompression run there.
- **Media**: `cellAdec`, `cellVdec`, `cellDmux`, `cellPamf`, `cellSail` (the video player); the
  middleware's own (Bink, CRI) is often linked in instead.
- **The rest**: `cellFs` and `cellGame` (files, the game's folder), `cellSaveData`, `cellPad`,
  `cellAudio`, `cellSysutil` (the system menu's callbacks, which a game must keep answering),
  `sceNp*` and `sys_net` (online), `cellSysmodule` (which modules it loads later).
- **LV2 syscalls** made directly (`sc` outside the system libraries) are rare; Ps3GhidraScripts names
  them.

*Feeds:* the layer's service list, the order of work, and whether the SPU work is a lift or a
replacement.

## 5. The data

- Game archives and formats need a parser of the port's own: ImHex patterns, QuickBMS scripts where
  one exists ([GAME-ARCHIVES.md](GAME-ARCHIVES.md)), and the code that reads them (step 3).
- Textures are usually RSX layouts (DXT, swizzled or linear, described by `CellGcmTexture`);
  shaders are Cg binaries. Kalmarv's [dx](https://github.com/Kalmarv/dx) (GPL-3.0, Rust, source only)
  reads `CgBinaryProgram` containers and decodes RSX vertex and fragment microcode; RPCS3's
  `Emu/RSX/Program/` decompiles them to GLSL (reference only).
- Video is often PAMF (`.pam`: AVC with ATRAC3plus) or the middleware's own; audio ATRAC3plus (`.at3`)
  or MSF. The suite has no converter for them; ffmpeg reads ATRAC3plus.

## 6. Observe the original: RPCS3

```sh
rpcs3 --installfw ~/firmware/PS3UPDAT.PUP          # once: your firmware
rpcs3 --no-gui ~/Games/<game>/disc/PS3_GAME/USRDIR/EBOOT.BIN
```

What RPCS3 gives a port (from its source at `9b8974d3` and the runs noted):

- **A GDB stub** on `127.0.0.1:2345` (`config.yml`, Miscellaneous, "GDB Server"): registers, memory,
  breakpoints and stepping on **PPU threads only** (SPU threads are commented out in `Emu/GDB.cpp`).
  ps3recomp's `tools/rpcs3_probe/rsp.py` is a dependency-free client used as an oracle against it.
- **PINE (IPC)**: memory reads and writes by address over a socket, off by default (`ipc.yml`:
  "IPC Server enabled", port 28012), the same protocol PCSX2 speaks. This is the base of an oracle like
  the DOS route's: read named memory regions at sync points and compare them with the port's.
- **Logs**: `RPCS3.log` in the cache folder, with a level per channel (one per module: `cellGcmSys`,
  `sys_fs`, ...); at trace level the HLE functions and syscalls log their calls and arguments.
  `TTY.log` holds what the game prints. The log shows which modules a game loads
  (`cellSysmoduleLoadModule`), which calls are unimplemented, and the SPU thread groups it starts.
- **The debugger window** (GUI): PPU and SPU threads, disassembly, memory viewer, breakpoints.
- **LLE or HLE per library** (`config.yml`, Core, "Libraries Control"): run Sony's own PRX from your
  firmware, or RPCS3's reimplementation. A difference between the two runs points at the library.
- **RSX captures**: frames of the command stream saved from the running game, replayed with
  `--rsx-capture <file>`; the frame's draws and state, without the game.
- **Savestates** (`--savestate`) put a run back at a known point.

Traps (checked on Linux/WSL2, RPCS3 0.0.43-20583, 2026-11-13):

- **Booting anything needs firmware**, homebrew test programs included: without it RPCS3 logs
  "Firmware is missing" and, in headless mode, does not exit after the failure. Give every run a time
  limit.
- **Headless mode needs the null renderer** (`--headless`; `config.yml`, Video, "Renderer: Null"),
  else it stops with an error when the game starts (`headless_application.cpp`). For real frames run
  `--no-gui` under a virtual display.
- **RPCS3 writes to your home folder** on the first start of any command (`~/.config/rpcs3` and
  `~/.cache/rpcs3` on Linux). To keep a port's runs apart, set `XDG_CONFIG_HOME` and `XDG_CACHE_HOME`
  (Linux) or `RPCS3_CONFIG_DIR` (Windows) to its work folder, as `decrypt --data` does; that profile
  then needs its own firmware.
- **The AppImage** is run without FUSE (the suite's launcher sets `APPIMAGE_EXTRACT_AND_RUN`): each
  start unpacks it under `$TMPDIR`, which on WSL is memory. The runs here removed it at exit; a killed
  run leaves an `appimage_extracted_*` folder behind, so delete those after a time limit hit.
- **Accuracy settings** change what an oracle sees: the PPU and SPU recompilers (LLVM) are the
  defaults; the interpreters, "Accurate SPU DMA" and the reservation settings are slower and closer
  to the hardware. Record the settings with every run you compare against.

*Feeds:* the modules loaded and the calls up to the first frame, the SPU workloads that matter,
memory at sync points, the frames a port's renderer is compared with.

## 7. The recompilation

What a static recompilation of a PS3 game needs, whichever toolkit:

- **The PPU code**: the decrypted ELF and every PRX the game loads, the function list (step 3, or the
  symbols of a debug build: ps3recomp's `elf_symbols.py`), jump tables (`mtctr`/`bctr`, as on the
  360), the OPDs and the TOC.
- **The import edge**: each import slot routed to the layer by NID (ps3recomp generates the NID to
  handler table, `gen_hle_nids.py`), each unknown NID stopping with its library and name.
- **The SPU code**, the hard part: each SPU image extracted, disassembled and lifted to C on its own
  (local store as an array, DMA as copies, channels as queues), or a hand-written PPU replacement for
  a job (ps3recomp's SPU fallback registry). SPURS adds a scheduler (the SPURS kernel and policy
  modules come from libsre, so the firmware's SPU code runs too).
- **The machine**: LV2's threads, mutexes, events, memory; `cellFs` over a game folder; the RSX
  command stream on a host API; `cellAudio`'s ports; the pads.

[ps3recomp](https://github.com/sp00nznet/ps3recomp) (MIT, v0.19.0) is the toolkit for all of it: a
Python pipeline (ELF and fSELF readers, PPU and SPU disassemblers and lifters, SPU image extraction,
NID tools, a Ghidra export script) and a C/C++ runtime with HLE modules, D3D12, Metal and Vulkan
renderers on one draw engine, and SPU execution. Its own status table (2026-11-06): the runtime builds
and its tests pass on Windows, macOS and Linux; a recompiled game runs **in its tree on Windows
only**, while ports outside it run on Linux, macOS and under Proton with fixes still on their way
upstream. The suite installs its release bundle (`tools/ps3recomp/current/`); a port builds the
runtime from source as its own dependency. Read its `docs/GAME_PORTING_GUIDE.md` (12 phases, the flOw
case study), `SPU_LIFTER.md`, `SPU_FALLBACK.md` and `PROTO_BUILDS.md` before starting.

RPCS3's PPU and SPU recompilers (LLVM, GPL-2.0) are the reference for the semantics of every
instruction and syscall; ps3recomp reads them and writes its own, and so should a port that is not
GPL.

Traps the projects record:

- **The lifter must turn import stubs into calls to the layer** (`ppu_lifter.py --hle-stubs`); without
  it the first import call crashes.
- **SPU programs overlap in local store**: a SPURS kernel, a policy module and a job can all sit at the
  same local-store addresses, so lifted SPU code is dispatched per image, not per address (ps3recomp's
  `image_id`).
- **Stubbed SPU jobs fail quietly**: a decompressor or mixer that reports success without running
  leaves the PPU reading garbage (ps3recomp's SPU_FALLBACK.md).
- **A game is a better first target when RPCS3 runs it well**, its SPU use is audio only and its
  import coverage in the layer is high (ps3recomp's porting guide, phase 1).
- **Debug and prototype builds are ground truth**: fake-signed, unstripped, with DWARF. When one of the
  game exists, start there and carry the names over to the retail build (PROTO_BUILDS.md).

## 8. Patching and rebuilding

- Patch the decrypted ELF at the file offset of its segment, and test it in RPCS3 as a patch
  (`patches/` in its profile, by address) before touching any file.
- RPCS3 runs a decrypted `EBOOT.elf` in place of the SELF; a console does not. A recompiled port
  replaces the whole executable, so it never needs a signed one.

## Outputs, kept where they belong

| Output | Where |
|---|---|
| disc image, extracted tree, decrypted ELFs and PRXs, RPCS3 profiles, captures | the port's work folder (never git) |
| hashes, `info` JSON, the import census, the SPU image list, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project |
| firmware, licenses (`.rap`), KLICs | your RPCS3 profile only, never a repository |
| tool fixes and generic traps | this suite (this page) |

## What is still missing

- **A retail game through this route**, and the Ghidra steps with Ps3GhidraScripts built (its source
  build was not run here).
- **An RPCS3 oracle command** like `rea-suite dosbox`: named regions read over PINE at sync points,
  and module calls from the trace log, as JSON lines (TODO.md).
- **An SPU language for Ghidra** that builds with the pinned Ghidra (TODO.md).
- **A PPU language with the Cell-specific VMX loads and stores**, and `r2` preserved in the PS3
  compiler spec, without editing the Ghidra install.

## Existing PS3 recompilations and decompilations

Found on GitHub on 2026-11-13; each is a game's port on top of ps3recomp unless noted. Licenses as
GitHub reports them ("none" means no license file).

| Project | Game | License | State (its README, last push) |
|---|---|---|---|
| [ps3recomp](https://github.com/sp00nznet/ps3recomp) | toolkit and runtime | MIT | v0.19.0, 2026-11-06 |
| [gow-ascension-pc](https://github.com/arnaldolima1/gow-ascension-pc) | God of War: Ascension | MIT | an experiment, 2026-11-12 |
| [dod3-recomp](https://github.com/soyjxck/dod3-recomp) | Drakengard 3 | custom | 2026-11-03 |
| [demons-souls-recomp](https://github.com/timboat/demons-souls-recomp) | Demon's Souls (BLUS-30443) | custom | native Windows port, 2026-11-13 |
| [ratchet-tod-recomp](https://github.com/Re-TeRo17/ratchet-tod-recomp) | Ratchet & Clank: Tools of Destruction | custom | 2026-11-08 |
| [project-pyrrhus](https://github.com/undecuple/project-pyrrhus) | Killzone 2 | MIT | partly playable, 2026-11-11 |
| [project-helghast](https://github.com/undecuple/project-helghast) | Killzone 3 | MIT | partly playable, 2026-11-12 |
| [infamous2-recomp](https://github.com/bhuiyah/infamous2-recomp) | inFamous 2 | custom | Windows port with a launcher, 2026-11-13 |
| [RE-Code-Veronica-PS3-HD-Recomp-PC](https://github.com/kastieloficial/RE-Code-Veronica-PS3-HD-Recomp-PC) | Resident Evil Code: Veronica X HD | MIT | hobby, 2026-11-13 |

ps3recomp's README also names ports of Twisted Metal, LittleBigPlanet, Yakuza: Dead Souls, God of War
II HD, Ben 10 Omniverse and DBZ Budokai HD. No matching decompilation of a PS3 game turned up.

## Verification

2026-11-13, Linux x86_64 (WSL2), in a worktree:

- `rea-tools install rpcs3 rpcs3-source ps3recomp` from the new `common/tools.yml` entries (Linux
  assets), then `rea-suite ps3 check` (6589 names for 5515 NIDs) and `doctor` with the component
  (its `ps3` line ok; its other failures are the worktree's missing runtimes).
- `rea-suite ps3 decrypt` of ps3autotests' `basic.ppu.self` through the installed launcher, into a
  fresh RPCS3 profile in `work/`: the ELF came out byte for byte, nothing was written to the home
  folder. ps3recomp's `unfself.py` gave the same ELF.
- `info` on its 15 SELFs (fake-signed, not encrypted, application) and `imports` on its 33 ELFs: every
  import named.
- Ghidra 12.1.4: import with `PowerPC:BE:64:A2ALT-32addr`, analysis, `rea-ghidra functions` and
  `decomp`; GhidraSPU's SLEIGH compiled.
- `rea-suite lint`, the common unit tests (`test_ps3`: synthetic SELF, executable, PRX and SFO, a fake
  RPCS3) and the Node tests.

Not verified: the macOS and Windows assets (their archives were listed: `RPCS3.app/Contents/MacOS/rpcs3`,
`rpcs3.exe`) and the Windows script; the Ps3GhidraScripts source build; an encrypted retail or NPDRM
title; booting any program (no firmware here), so the GDB stub, PINE and the logs at run time are from
the source, not from a run.

## Sources (checked 2026-11-13)

- RPCS3: [RPCS3/rpcs3](https://github.com/RPCS3/rpcs3) (GPL-2.0) at
  `9b8974d32e73c897a5fcd6bdf69413ca7e436b01` (2026-11-12), the build the suite pins. Read:
  `rpcs3/rpcs3.cpp` (the command line: `--headless`, `--no-gui`, `--decrypt`, `--installfw`,
  `--installpkg`, `--rsx-capture`, `--savestate`), `rpcs3/Crypto/decrypt_binaries.cpp` (output names,
  the KLIC prompt), `rpcs3/Crypto/unself.h` and `unself.cpp` (SCE, extended, program, segment and
  supplemental headers; bit 15 of the key revision for fake-signed SELFs; the NPDRM license types),
  `rpcs3/Crypto/unedat.h` (the NPD header), `rpcs3/Crypto/key_vault.h` (program types),
  `rpcs3/Emu/Cell/PPUModule.cpp` (`ppu_generate_id`, the module info, `sys_process_param`,
  `sys_proc_prx_param`, import and export tables), `PPUModule.h` (`REG_FUNC`, `REG_FNID`),
  `PPUFunction.cpp` (NIDs listed by library), `rpcs3/Emu/GDB.cpp` and `system_config.h` (the GDB
  stub, PPU only, 127.0.0.1:2345), `rpcs3/Emu/IPC_config.h` and `3rdparty/pine/pine_server.h` (PINE),
  `rpcs3/headless_application.cpp` (the null renderer), `Utilities/File.cpp` (the config folders).
  Builds: the per-platform binary repositories `RPCS3/rpcs3-binaries-{linux,mac-arm64,win}`, build
  `9b8974d3` (2026-11-12). rpcs3.net and its wiki answered 403 to automated reads.
- ps3autotests: [RPCS3/ps3autotests](https://github.com/RPCS3/ps3autotests) (GPL-2.0), `b5cff06`:
  15 fake-signed SELFs with their ELFs, used for every run above (in `work/`, never in git).
- ps3recomp: [sp00nznet/ps3recomp](https://github.com/sp00nznet/ps3recomp) (MIT) at `de4f090`
  (2026-11-06) and release v0.19.0 (`ps3recomp-v0.19.0-{linux-x64,mac-arm64,win-x64}.zip`): README,
  `docs/GAME_PORTING_GUIDE.md`, `SPU_FALLBACK.md`, `PROTO_BUILDS.md`, `FAQ.md`,
  `tools/nid_database.py` (the same NID hash), `tools/unfself.py`, `tools/rpcs3_probe/rsp.py`.
- Ps3GhidraScripts: [clienthax/Ps3GhidraScripts](https://github.com/clienthax/Ps3GhidraScripts),
  release 1.0111 (2026-07-12, Ghidra 11.2 to 12.1.2); README (language, the `r2` change, unsupported
  Cell instructions); no license file.
- GhidraSPU: [aerosoul94/GhidraSPU](https://github.com/aerosoul94/GhidraSPU) (Apache-2.0), `b85076d`
  (2023-07-07); its `spu.slaspec` compiled with Ghidra 12.1.4's `support/sleigh`.
- ps3-cell-re-tools: [eth-man/ps3-cell-re-tools](https://github.com/eth-man/ps3-cell-re-tools)
  (GPL-2.0), `33251f8`: the anergistic SPU emulator fork and `spu-sleigh`.
- dx: [Kalmarv/dx](https://github.com/Kalmarv/dx) (GPL-3.0-or-later), 0.12.0: `rsx-reader`.
- Ghidra 12.1.4: `Ghidra/Processors/PowerPC/data/languages/ppc.ldefs` (the `A2ALT-32addr` language)
  and `ppc_64_32.cspec`.
- Other IDA-side tools seen, not used: [aerosoul94/ida_gel](https://github.com/aerosoul94/ida_gel)
  (an IDA loader with a NID XML), [kakaroto/ps3ida](https://github.com/kakaroto/ps3ida) (IDC scripts
  and an FNID list, 2012), [Goatman13/spu2c](https://github.com/Goatman13/spu2c) (SPU to C for IDA);
  none has a license file.
- Not reachable for this page: psdevwiki (403 to automated reads). Its SELF, NID and syscall pages
  are the community's reference; the layouts here come from RPCS3's source instead.
- The Cell itself: IBM's *Cell Broadband Engine Programming Handbook* and the *Cell Broadband Engine
  Architecture* specification (local store, MFC, channels); not re-read for this page.
