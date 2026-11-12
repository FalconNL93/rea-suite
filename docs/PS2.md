# PS2 games: the route

How to take a PlayStation 2 game from its disc image to what a port, a decompilation or a static
recompilation needs, with the suite's tools in the order they are used. Each step says what its
output decides and feeds next. The tools, the `rea-suite playstation` command and what the community
uses that the suite lacks are in [PLAYSTATION.md](PLAYSTATION.md); this page links them and does not
repeat them. No port has taken this route yet (2026-11-12): the traps below come from the tools'
documentation and the decompilation projects, and the first port adds its own.

Components: `playstation`, and `decomp` for steps 6 and 7 (`rea-suite select`).

## 1. The disc, as data

```sh
chdman extractdvd -i game.chd -o work/game-src/game.iso     # a DVD in CHD (extractcd for a CD title)
sha1sum work/game-src/game.iso                              # compare with the Redump entry
rea-suite playstation work/game-src/game.iso --project work/game --ghidra
```

- Most PS2 games are DVDs (2048-byte sectors, ISO9660 with UDF); 7-Zip extracts them. Early titles
  are CDs (2352-byte sectors, often a CUE with audio tracks); the command sends those to dumpsxiso.
- Dual-layer DVDs are untested with the command; compare the extracted tree's file count and sizes
  with the ISO's own listing (`7z l`).
- `SYSTEM.CNF` names the EE boot program (`BOOT2 = cdrom0:\SLUS_200.00;1`) and the video mode.
- Record the image hash and the boot ELF's hash in the port's docs.

*Feeds:* `project.json` (the hashes, the inventory with each ELF's kind), the Ghidra project of the EE
program for step 3.

## 2. What is on the disc

```sh
jq '[.executables[] | {path, kind, entry}]' work/game/project.json
```

The code of a PS2 game lives in several places, and each is its own import:

- **The EE program** (`ps2-ee`): the boot ELF, R5900 code. Some games ship further EE ELFs or
  relocatable overlays (`.ERX` and the like) loaded by the game.
- **IOP modules** (`ps2-irx`): IRX files for the I/O processor, R3000 code in an ELF of type 0xFF80
  (sound, CD/DVD, pad, memory card, often Sony's `SIO2MAN`, `PADMAN`, `LIBSD`, and the game's own).
  A module the game ships names what the game drives on the IOP; Sony's standard ones are matched by
  name and version string, not reverse engineered.
- **VU microprograms**: VU1 (and VU0 micro mode) code is uploaded by the EE as data, often from inside
  the ELF. Ghidra has no VU micro-mode language; PCSX2's debugger disassembles VU code.
- **STABS symbols**: many retail ELFs kept an `.mdebug` section with functions, types and globals.
  Emotion Engine: Reloaded's STABS analyzer applies them at import; a game with them is a different
  job from a stripped one. [RetroReversing's list](https://retroreversing.com/ps2-unstripped) names
  known unstripped games.

*Feeds:* the list of imports for step 3; whether symbols exist.

## 3. Ghidra

```sh
rea-ghidra functions --project work/game/ghidra SLUS_200.00 -o work/game/analysis/functions.tsv
rea-ghidra decomp    --project work/game/ghidra SLUS_200.00 0x00123456 -o out.c
rea-ghidra xrefs     --project work/game/ghidra SLUS_200.00 -o out.c -- "cdrom0:"
```

- Emotion Engine: Reloaded decodes MMI (128-bit multimedia) and VU0 macro instructions, which plain
  MIPS leaves undecoded, and its MIPS-R5900 Constant Reference Analyzer fixes references to globals. If a function does not decompile, its README suggests turning off
  the "Decompiler Parameter ID" analyzer.
- Its STABS analyzer runs a bundled x86_64 `stdump`; on macOS ARM that needs Rosetta 2.
- **No SDK signatures.** The PS2 SDK libraries (`libkernl`, `libgraph`, `libpad`, `libcdvd`, ...)
  are named by hand in a stripped game: their syscall stubs (`syscall` with the number in `v1`), the
  strings they print, and the SIF RPC calls to IOP modules by their server ids. ghidra-ps2sdk, which
  named them, is gone ([PLAYSTATION.md](PLAYSTATION.md#what-the-communities-use-and-what-the-suite-has)).
- IOP modules: import an IRX on its own into the same Ghidra project with the MIPS little-endian
  32-bit language (`MIPS:LE:32:default`); Ghidra's ELF loader takes the type (checked with a synthetic
  module, 2026-11-12; a real module's relocations are not yet checked). Its export and import tables
  (the `iopmod` section and the stub tables) name the libraries it links.
- REA does not open R5900 ELFs ([PLAYSTATION.md](PLAYSTATION.md#rea)): use `rea-ghidra` and the GUI.

*Feeds:* names and function boundaries for splat and a recompiler, the SDK edge a port answers.

## 4. Observe the original: PCSX2

```sh
pcsx2 -datapath work/game/pcsx2 -debugger -- work/game-src/game.iso   # debugger, stopped at the entry
pcsx2 -datapath work/game/pcsx2 -batch -logfile work/game/pcsx2.log -- work/game-src/game.iso
```

- PCSX2 needs a BIOS dumped from your own console (its setup wizard asks for the folder); there is no
  free replacement.
- `-datapath` keeps settings, memory cards and save states with the game's project, out of your home
  folder.
- The debugger shows EE and IOP code, memory, breakpoints and the threads, and reads the symbols of
  the ELF it booted. There is **no GDB stub**: scripted access goes through PINE (Settings, Advanced,
  enable PINE; a socket for memory reads and writes and the emulator's state).
- A save state imports into Ghidra through Emotion Engine: Reloaded (all memory as it was, overlays
  and uploaded VU code included). PCSX2 2.1.178 and later compress states with zstd, which Ghidra
  cannot read: set Settings, Advanced, Savestate Settings, Compression Method to Deflate64 first.
- **What a run settles**: the IOP modules actually loaded and in which order, the SIF RPC servers the
  EE calls, the files read up to the first frame, the overlays and their addresses.

*Feeds:* the module list and the first-frame call list, which bound a port's first work; memory
images for code that is not in the ELF.

## 5. The data

- Game archives and formats need a parser of the port's own: ImHex patterns, QuickBMS scripts where
  one exists ([GAME-ARCHIVES.md](GAME-ARCHIVES.md)), and the code that reads them (step 3).
- Video is usually PSS (MPEG-2 with ADPCM audio) or a middleware format; audio is VAG/VAB (SPU2 ADPCM).
  Neither has a converter in the suite; ffmpeg reads many PSS files.

## 6. Decompilation: splat and objdiff

```sh
cd <decomp project>
splat create_config --objcopy objcopy SLUS_200.00   # a first YAML; objcopy makes its code image
splat split slus_200.00.yaml
objdiff                                   # per-function match of the build against the original
```

- `create_config` reads the ELF's sections and makes a "rom" of the code with `objcopy`. Without
  `--objcopy` it looks for `mips-linux-gnu-objcopy` or `mipsel-linux-gnu-objcopy` only; the `build`
  component's `binutils-multiarch` (Linux) gives an `objcopy` that reads MIPS ELFs.
- The compilers are the project's own: EE GCC 2.95/2.96/3.x builds and Metrowerks CodeWarrior for PS2,
  as decomp.me offers them. Projects carry them, and m2c and asm-differ, as their own toolchain.

*Feeds:* source that builds back to the original, function by function.

## 7. Static recompilation

What a recompilation of a PS2 game needs, whichever recompiler is used:

- **The code**: the EE ELF and every overlay at its address, the function list from Ghidra (or the
  STABS symbols), jump tables, the MMI and VU0 macro instructions the code uses.
- **The machine**: the EE kernel's syscalls, DMA to the GS (the graphics synthesizer's packets), the
  VUs' microprograms (interpreted or translated separately), the IOP with its modules (high-level
  emulation of the standard ones, SIF RPC), the SPU2, the CD/DVD driver, the pads and memory cards.
- **Recompiler**: [PS2Recomp](https://github.com/ran-j/PS2Recomp) translates R5900 code to C++
  with a runtime for memory, syscalls and IOP modules; stubs and patches are set in a TOML file, and
  SDK functions are bound by name or by address in a stripped game. It is source only (CMake,
  submodules, GPL), so a port takes it as its own dependency; the suite does not build it.
- How PS2Recomp runs the IOP and the VUs, and how OpenGOAL rewrote each VU1 microprogram as a PC
  renderer: [RECOMPILATION.md](RECOMPILATION.md).

## 8. Patching and rebuilding

- Patch code in the ELF at the file offset of its segment (the program headers map addresses to
  offsets), or as PCSX2 patches (`.pnach`, by address) while testing.
- No suite tool rebuilds a PS2 DVD with its original layout. Games that read files by sector need the
  file order and positions kept; a generic ISO writer does not keep them. Prefer loading changed files
  from the port's own folder over rebuilding the disc.

## Outputs, kept where they belong

| Output | Where |
|---|---|
| images, extracted tree, project, emulator data folder, save states, dumps | the port's work folder (never git) |
| hashes, module list, overlay table, first-frame list, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project; splat's symbol files in a decompilation |
| tool fixes and generic traps | this suite (PLAYSTATION.md, this page) |

## Still missing

- PS2 SDK library signatures for Ghidra (ghidra-ps2sdk is gone); see TODO.md.
- A VU microcode disassembler or Ghidra language.
- A PS2 profile in REA: [REA #6746](https://github.com/morluto/rea/issues/6746).
- A PS2 DVD rebuild that keeps the layout.
