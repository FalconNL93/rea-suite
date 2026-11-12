# PS1 games: the route

How to take a PlayStation game from its disc image to what a port, a decompilation or a static
recompilation needs, with the suite's tools in the order they are used. Each step says what its
output decides and feeds next. The tools, the `rea-suite playstation` command and what the community
uses that the suite lacks are in [PLAYSTATION.md](PLAYSTATION.md); this page links them and does not
repeat them. No port has taken this route yet (2026-11-12): the traps below come from the tools'
documentation and the decompilation projects, and the first port adds its own.

Components: `playstation`, and `decomp` for steps 6 and 7 (`rea-suite select`).

## 1. The disc, as data

```sh
chdman extractcd -i game.chd -o work/game-src/game.cue     # only for a CHD
sha1sum work/game-src/*.bin                                 # compare with the Redump entry
rea-suite playstation work/game-src/game.cue --project work/game --plan
rea-suite playstation work/game-src/game.cue --project work/game --ghidra
```

- A PS1 disc is a 2352-byte-sector CD: Mode 2 data, often XA audio and video sectors interleaved in
  files, and CD audio tracks. Keep the CUE with every BIN track; a raw BIN alone loses the tracks.
- Compare the track hashes with the [Redump](http://redump.org) entry before anything else, and record
  them in the port's docs. A bad dump makes every later step lie.
- `SYSTEM.CNF` names the boot executable (`BOOT = cdrom:\SLUS_000.00;1`), the stack and the thread
  counts. Without it the BIOS boots `PSX.EXE`; pass `--boot` then.
- Multi-disc games: one project per disc; the executables are often identical, check their hashes.

*Feeds:* `project.json` (the hashes, the inventory, the boot executable), `disc/` and `disc.xml` (the
layout a rebuild needs), the Ghidra project for step 3.

## 2. Identify the executable and its overlays

```sh
jq '.boot_executable, [.executables[] | {path, kind, load, size: .payload_size}]' work/game/project.json
strings -a work/game/disc/SLUS_000.00 | rg -i 'psy-?q|sony computer|lib[a-z]+ ver'
```

- The PS-X EXE header gives the load address, the entry, `gp` and the payload size; the payload starts
  at file offset 0x800. Runtime addresses, executable offsets and disc sectors are three coordinates;
  keep them apart in notes.
- The PsyQ SDK version decides which library signatures apply. Its libraries leave version strings, and
  ghidra_psx_ldr asks for the version at import (Program Information, "PsyQ Version").
- **Overlays.** Most larger games load more code at run time over a fixed region: other PS-X EXEs or
  plain `.BIN`/`.OVL` files on the disc, loaded by the game's own loader. `project.json` lists only the
  files with a PS-X EXE header; the others are found by the code that reads them (step 4 shows the
  load address). Each overlay is a separate import, at its load address.

*Feeds:* the SDK version for step 3, the list of code that is not in the boot executable.

## 3. Ghidra

```sh
rea-ghidra functions --project work/game/ghidra SLUS_000.00 -o work/game/analysis/functions.tsv
rea-ghidra decomp    --project work/game/ghidra SLUS_000.00 0x80012345 -o out.c
rea-ghidra xrefs     --project work/game/ghidra SLUS_000.00 -o out.c -- "MEMCARD"
```

- ghidra_psx_ldr loads the EXE at its address, names the hardware registers, decompiles GTE (the
  geometry coprocessor) instructions through its macro segment, and applies the PsyQ signatures of the
  version found; library functions come out named. Check a few names against their behavior before
  trusting the set: a wrong version names the wrong functions.
- Overlays: add each one as an overlay memory block at its load address (the loader's
  [video tutorial](https://youtu.be/fpijiL1x3Pc)). Ghidra keeps blocks at the same addresses apart.
- `rea-suite playstation --ghidra` disables CERT Kaiju's Function Hashing for the import, which throws
  on this processor; other analyzer errors stay as warnings in `logs/ghidra.log`.
- REA does not open PS-X EXEs (its MIPS policy, [PLAYSTATION.md](PLAYSTATION.md#rea)): use
  `rea-ghidra` and the Ghidra GUI.

*Feeds:* names and function boundaries for splat (step 6) and a recompiler (step 7), the library
functions a port answers at their API edge.

## 4. Observe the original: PCSX-Redux

```sh
pcsx-redux -portable work/game/redux -iso work/game-src/game.cue -run -gdb -gdb-port 3333
gdb-multiarch -ex 'set architecture mips:3000' -ex 'set endian little' \
  -ex 'target remote :3333'                                  # breakpoints, memory, registers
pcsx-redux -portable work/game/redux -cli -iso work/game-src/game.cue -run -dofile trace.lua
```

- Run with `-portable <dir>` in the work folder so settings, memory cards and save states stay with
  the game's project and out of your home folder.
- PCSX-Redux boots with OpenBIOS when no BIOS is configured. That is enough to observe most games;
  for timing or BIOS-call fidelity give your console's BIOS dump with `-bios`.
- The GDB server (`-gdb`), the web server's REST API (`-webserver`) and Lua (`-dofile`, `-exec`) are
  the scripted routes: breakpoints on a file read show where an overlay is loaded, a memory dump after
  it gives the overlay as loaded, a write watch finds who changes a value.
- **What a run settles**: the order of CD reads up to the first frame, the overlays and their load
  addresses, the BIOS and PsyQ calls actually made, and the frame pacing (VSync callbacks, root
  counters). Those bound the first work of a port.
- `gdb-multiarch` comes with the `build` component on Linux; PCSX-Redux's own debugger windows need
  no GDB.

*Feeds:* overlay load addresses for step 3, the first-frame call list, and the oracle for comparing
the port's runs.

## 5. The media

```sh
jpsxdec -f work/game-src/game.bin -x work/game/media.idx    # index video (STR), XA audio, TIM images
jpsxdec -x work/game/media.idx -a video -dir work/game/media
```

- jPSXdec reads the original sectors, so give it the image, not the extracted files: XA and STR data
  live in Mode 2 Form 2 sectors that a file copy loses.
- Formats the game invents (archives, models, levels) need a parser of the port's own; ImHex patterns
  and the code that reads them (step 3) are the route.

*Feeds:* assets the port loads or converts, the formats it must parse.

## 6. Decompilation: splat and objdiff

```sh
cd <decomp project>
splat create_config SLUS_000.00          # a first splat YAML for the PS-X EXE
splat split slus_000.00.yaml              # assembly, data and a linker script
objdiff                                   # GUI: per-function match of the build against the original
```

- `create_config` writes the segments it can infer, with comments on what it could not (the maspsx
  workaround for `INCLUDE_ASM` reordering among them); refine it with the function list from step 3.
- A matching PS1 decompilation needs the compiler the game was built with: one of the GCC 2.x builds
  PsyQ shipped ([decompals/old-gcc](https://github.com/decompals/old-gcc)) and
  [maspsx](https://github.com/mkst/maspsx) in place of PsyQ's ASPSX assembler, plus GNU binutils for
  `mipsel` (`binutils-mipsel-linux-gnu` on Debian). Projects carry these as their own toolchain and
  submodules, as they carry m2c and asm-differ; the suite does not install them
  ([PLAYSTATION.md](PLAYSTATION.md#what-the-communities-use-and-what-the-suite-has)).
- [decomp.me](https://decomp.me) has the PsyQ compiler presets for one function at a time.
- PsyQ library code is linked from the original objects in most projects; [psyz](https://github.com/Fancy2209/psyz)
  is a matching decompilation of the libraries.

*Feeds:* source that builds back to the original, function by function, which a port compiles natively.

## 7. Static recompilation

What a recompilation of a PS1 executable needs, whichever recompiler is used:

- **The code**: the boot executable and every overlay at its load address (steps 2 to 4), the
  function list from Ghidra or splat as seeds, jump tables found.
- **The hardware the code touches**: GPU (GP0/GP1 command lists), SPU, CD-ROM controller, GTE, DMA,
  root counters, interrupts. A port answers them at a layer, or answers the PsyQ libraries at their
  API edge (`libgpu`, `libcd`, `libspu`) so the hardware is never reached; the signatures of step 3
  name that edge.
- **Recompilers**: [psxrecomp](https://github.com/mstan/psxrecomp) (to C, PolyForm Noncommercial) and
  [RecompOne](https://github.com/flafmg/RecompOne) (to C#, MIT). Both are source only and are taken by
  a port as its own dependency; the suite does not build them.

## 8. Patching and rebuilding the CD

```sh
mkpsxiso work/game/disc.xml -o work/patched.bin -c work/patched.cue
```

- `disc.xml` keeps the file order and LBAs of the original; changing a file's size moves those after it.
  Check the LBAs the game reads directly (some read sectors, not files), XA and CD audio, and compare
  the rebuilt image's unchanged files with the original hashes.
- Patch code by assembling into the executable at its file offset (load address minus the header's
  address, plus 0x800). armips is not in the suite ([PLAYSTATION.md](PLAYSTATION.md#what-the-communities-use-and-what-the-suite-has)).

## Outputs, kept where they belong

| Output | Where |
|---|---|
| images, extracted tree, project, emulator portable folder, dumps, media | the port's work folder (never git) |
| hashes, overlay table, first-frame list, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project; splat's `symbol_addrs.txt` in a decompilation |
| tool fixes and generic traps | this suite (PLAYSTATION.md, this page) |

## Still missing

- A PS1 profile in REA (open_binary refuses PS-X EXEs): [REA #6746](https://github.com/morluto/rea/issues/6746).
- An overlay import in `rea-suite playstation` (each overlay at a given load address into the same
  Ghidra project); today it imports the boot executable only.
- armips, maspsx, m2c and asm-differ as installed tools: none has a release; see TODO.md.
