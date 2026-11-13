# GameCube and Wii games: the route

How to take a GameCube or Wii game from your disc image to what a port, a decompilation or a static
recompilation needs, with the suite's tools in the order they are used. Each step says what its output
decides and feeds next. No port has taken this route yet (2026-11-13). The steps were checked on
synthetic files, not on a retail game; the first port adds its own traps. Nothing about a particular
game belongs on this page.

Install: component `gamecube` (`rea-suite select`, then `rea-suite setup`). It brings Dolphin (Linux:
the distribution's `dolphin-emu`; macOS and Windows: release 2609b), dtk (decomp-toolkit), the nod-rs
Python bindings for `rea-suite gamecube`, and the GameCube loader for Ghidra. Add component `decomp` for
objdiff in step 6.

What lies around this page:

- The other console routes: [PS2.md](PS2.md), [XBOX-CLASSIC.md](XBOX-CLASSIC.md); the Xbox 360 lane
  (also PowerPC, also big-endian) in the README's "Console games and disc images".
- What the recompilers already solved: [RECOMPILATION.md](RECOMPILATION.md).

## The platform, in short

| Part | GameCube (2001) | Wii (2006) |
|---|---|---|
| CPU | Gekko, an IBM PowerPC 750 (G3) derivative, 486 MHz | Broadway, the same core at 729 MHz |
| Memory | 24 MB MEM1 at `0x80000000` (cached) and `0xC0000000` (uncached); 16 MB ARAM for audio | MEM1 as the GameCube, plus 64 MB MEM2 at `0x90000000`; no ARAM |
| Graphics | Flipper, programmed through the SDK's GX library | Hollywood, Flipper's design, same GX |
| Audio | a 16-bit DSP running microcode the game uploads | the same DSP |
| System | none: the SDK ("Dolphin OS") is linked into the game | IOS on a separate ARM core (Starlet); the PowerPC asks it for disc, NAND, USB, network and Bluetooth through IPC |

- **Paired singles.** Gekko added 64-bit floating-point registers that hold two 32-bit floats, with
  `ps_*` instructions working on both halves, and quantized loads and stores (`psq_l`, `psq_st`) that
  convert 8- and 16-bit integers to floats through eight GQR registers. Games use them for vectors,
  matrices and vertex data. Stock PowerPC decoders do not know them.
- **Big-endian.** As on the Xbox 360, every multi-byte value in memory and on disc is big-endian.
- **Small data.** The Metrowerks EABI keeps two small-data areas reached through `r13` (`_SDA_BASE_`)
  and `r2` (`_SDA2_BASE_`), set once by the startup code. A reference such as `lwz r3,-0x7f30(r13)` is
  a global; without the register values it looks like nothing.
- **Compilers.** Most games were built with Metrowerks CodeWarrior (`mwcceppc`); some with GCC
  (ProDG). A matching decompilation needs the exact compiler build; decomp.me offers them.

## 1. The disc, as data

```sh
mkdir -p ~/Games/<game>
sha1sum game.rvz                                   # compare with the Redump entry if you can
rea-suite gamecube info game.rvz -o ~/Games/<game>/disc.json
dtk disc extract game.rvz ~/Games/<game>/disc     # every file, sys/main.dol and sys/apploader.img
```

- Images come as plain ISO/GCM (a GameCube disc is 1.4 GB), or in containers: RVZ and WIA (Dolphin's
  compressed formats), WBFS (USB loaders), CISO, GCZ, NKit. `rea-suite gamecube info` reads a plain
  GameCube ISO itself and every other format through nod-rs; dtk uses the same Rust library (nod) for
  `disc info`, `extract`, `convert` and `verify`. DolphinTool (`dolphin-tool` on Linux, `DolphinTool.exe`
  on Windows; the macOS app has none) converts and verifies too.
- **Wii partitions are encrypted** (AES-128 with a title key under the console's common key). nod-rs,
  dtk and Dolphin decrypt them themselves. Without nod-rs, `info` shows a Wii disc's header and partition
  table only. Your image and your console's keys are your responsibility; none go into git.
- `info` gives the game id (`GALE01`: system, game, region, maker), the title, disc number and revision,
  the region, the apploader's build date, the main DOL's header and the file table. Record the image's
  hash, the game id and revision, and the main DOL's hash in the port's docs.

*Feeds:* `main.dol` and the RELs for step 2, the data tree the port's file layer serves.

## 2. What is on the disc

```sh
rea-suite gamecube info ~/Games/<game>/disc/sys/main.dol      # sections, entry, bss, SDK banners
rea-suite gamecube info ~/Games/<game>/disc/files/rels/a.rel  # module id, sections, imports
dtk dol info ~/Games/<game>/disc/sys/main.dol
dtk rel info ~/Games/<game>/disc/files/<module>.rel
```

The code of a GameCube or Wii game lives in up to three kinds of file:

- **The DOL** (`sys/main.dol`): the executable. A 256-byte header, then up to 7 text and 11 data
  sections, each loaded at its own address, a bss range and an entry point. There is no magic number
  and no import table: everything the game calls is linked in.
- **RELs** (`.rel`): relocatable modules loaded at run time, the GameCube's DLLs. Each has a module id,
  sections without addresses, and relocations grouped by the module they point into (0 is the DOL).
  `info` counts the relocations per imported module. Many games keep a `.str` file of module names.
- **RSOs** (`.rso`, some later Wii games): relocatable modules with named exports and imports. `dtk rso
  info` reads them; `rea-suite gamecube` does not.

- **SDK banners**: the SDK's libraries register strings such as `<< Dolphin SDK - OS release build: ... >>`
  (`RVL_SDK` on the Wii). `info` lists them under `sdk`: the build dates say which SDK the game linked,
  which decides how well signatures match.
- **Symbol maps on the disc**: some games shipped a linker `.map` file, or a debug build of the DOL.
  Look for them in the file list (`"files"` in `info`'s output) first; a map is a different job from a
  stripped game.
- **Wii homebrew** is often an ELF (devkitPPC); retail Wii games are DOLs like the GameCube's.

*Feeds:* the list of executables for step 3; whether symbols exist; the SDK version.

## 3. Ghidra, and REA

```sh
rea-ghidra analyze --project <port>/re/ghidra --name <port> ~/Games/<game>/disc/sys/main.dol
rea-ghidra functions --project <port>/re/ghidra main.dol > functions.tsv
rea-ghidra decomp --project <port>/re/ghidra main.dol 0x80003100
```

- **The GameCube loader** (Cuyler36/Ghidra-GameCube-Loader, Apache-2.0) loads DOLs, RELs, apploaders
  and RAM dumps, adds the `PowerPC:BE:32:Gekko_Broadway` language with the paired-single instructions,
  imports symbol maps and demangles CodeWarrior names. Its newest release (1.3.1, 2026-05-24) is built for
  Ghidra 12.1, and Ghidra 12.1.4 refuses an extension built for another version. The suite builds it from
  the release's source for the installed Ghidra (tools.yml, `build: true`). `rea-suite gamecube check`
  (doctor runs it when the component is selected) checks the files are in place; that build has not run
  here yet.
- **REA** opens a DOL itself since 6.8.0, when told the format: `open_binary` with `format:
  "gamecube-dol"` (a DOL is never detected on its own). It maps the text and data sections at their
  addresses with stock Ghidra `PowerPC:BE:32:default`, so paired singles are not decoded unless
  `REA_GHIDRA_LANGUAGE_ID=PowerPC:BE:32:Gekko_Broadway` selects the loader's language. REA does not open
  RELs or disc images (read in rea-agents 6.8.0's `dist/ghidra/GhidraDolProfile.js` and
  `GhidraProviderClient.js`, 2026-11-13).
- **Paired singles in Ghidra**: with stock PowerPC, `ps_*` and `psq_*` show as bad instructions and stop
  disassembly, so whole functions go missing. Use the Gekko_Broadway language from the start; changing
  the language later needs a fresh import.
- **`r2` and `r13`**: if references through them stay raw offsets, set both registers over the whole
  program to the values the startup code loads (`__init_registers` in a symbolized game).
- **RELs**: import each REL into the same project. A REL's references into the DOL and into other RELs
  only resolve when the loader knows where each module sits; load them at the addresses a Dolphin run
  shows (step 4), or let dtk do the linking (step 6).
- **No SDK signatures in Ghidra.** dtk's analyzer has a built-in signature database for Metrowerks
  runtime and SDK functions; `dtk dol split` names them. Dolphin's debugger (Symbols menu) generates
  symbols from a signature database and applies Dolphin signature files, CSV signature files and
  WiiTools MEGA files (`DolphinQt/MenuBar.cpp` at 2609b).

*Feeds:* names and function boundaries for dtk and a recompiler; the SDK edge a port answers.

## 4. Observe the original: Dolphin

```sh
# Linux, no window: the GDB stub on port 2345, a user folder of the port's own, the null video backend
dolphin-emu-nogui -p headless -u ~/Games/<game>/dolphin -v Null \
  -C Dolphin.General.GDBPort=2345 -e ~/Games/<game>/game.rvz
gdb-multiarch -ex 'set architecture powerpc:750' -ex 'target remote 127.0.0.1:2345'
```

- `-C <System>.<Section>.<Key>=<Value>` sets any option for that run; `General.GDBPort` (default -1, off)
  starts Dolphin's GDB stub, `General.GDBSocket` a Unix socket instead (read in `Source/Core/Core/Core.cpp`
  and `Config/MainSettings.cpp` at tag 2609b). The stub does not start in RetroAchievements hardcore mode.
- `dolphin-emu-nogui` is the Linux build without a user interface (`-p headless`). On Windows and macOS
  use the GUI app; `--batch` runs it without its main window, `-d` shows the debugger.
- `-u` keeps settings, memory cards, NAND and save states with the game's project, out of your home.
- The debugger (GUI, `-d`) shows code with symbols, memory, breakpoints, memory checks and the JIT's
  blocks; it loads and saves `.map` symbol maps, so names move between Ghidra, dtk and Dolphin.
- **What a run settles**: which RELs load and at which addresses, the files read up to the first frame,
  the DSP microcode the game uploads, the IOS devices a Wii game opens.
- The GDB stub's behavior with a real game has not been checked here; only its source was read.

*Feeds:* the REL load addresses for step 3, the first-frame call list that bounds a port's first work.

## 5. The data

- Archives: RARC and U8 (`dtk rarc`, `dtk u8`), Yaz0 and Yay0 compression (`dtk yaz0`, `dtk yay0`), Wii
  WADs (`dtk wad`). Game formats need a parser of the port's own ([GAME-ARCHIVES.md](GAME-ARCHIVES.md)).
- Audio is DSP ADPCM (`.dsp`, `.brstm` on the Wii) or streamed ADP; textures are GX formats (TPL, BTI).
  The suite has no converter for either yet.

## 6. Decompilation: dtk and objdiff

```sh
dtk dol config sys/main.dol files/rels/*.rel -o config.yml   # a first project configuration
dtk dol split config.yml build                               # objects, symbols and splits
objdiff                                                      # per-function match against the original
```

- dtk finds function boundaries, rebuilds relocations, names Metrowerks and SDK functions by signature,
  splits the DOL and RELs into objects and writes the linker script for `mwldeppc.exe`.
  [dtk-template](https://github.com/encounter/dtk-template) (CC0-1.0) is the project layout every
  current decompilation starts from.
- The famous decompilations are the references for project layout, compiler flags and SDK names:
  [Melee](https://github.com/doldecomp/melee), [Twilight Princess](https://github.com/zeldaret/tp),
  [Super Mario Sunshine](https://github.com/doldecomp/sms), [Animal
  Crossing](https://github.com/ACreTeam/ac-decomp) (all active in 2026-11; decomp.dev tracks the rest).
- The compilers are the project's own: CodeWarrior builds for Windows, which dtk-template runs on Linux
  through [wibo](https://github.com/decompals/wibo), a minimal Win32 wrapper.

*Feeds:* source that builds back to the original, function by function.

## 7. Static recompilation

What a recompilation of a GameCube or Wii game needs, whichever recompiler is used:

- **The code**: the DOL and every REL with its relocations, the function list (dtk or Ghidra), jump
  tables, the paired-single and quantized instructions with the GQR state.
- **The machine**: the SDK's libraries, either recompiled with the game or replaced by name (GX onto a
  modern graphics API, DVD onto files, PAD and WPAD onto the host's pads, CARD onto save files); the
  hardware registers the SDK writes; the DSP microcode (high-level emulation, as Dolphin's HLE audio);
  on the Wii, the IOS devices behind IPC.
- **Recompilers**: [DolRecomp](https://github.com/ExpansionPak/DolRecomp) (GPL-3.0) translates GameCube
  and Wii DOLs and RELs (folders of RELs with imports between them) to C or LLVM; it does the CPU only,
  and the runtime is up to the port. [WiiCompiled](https://github.com/patchzyy/WiiCompiled) (GPL-3.0) is
  a native PC port of Mario Kart Wii by static recompilation, on
  [aurora](https://github.com/encounter/aurora), a source-level GameCube and Wii compatibility layer for
  GX. Both are source only for a port; the suite builds neither.
- How the other recompilers split the CPU from the runtime: [RECOMPILATION.md](RECOMPILATION.md).

## 8. Patching and rebuilding

- Patch the DOL at the file offset of its section (`info` gives each section's address and file offset).
  While testing, Dolphin's Gecko and AR codes patch memory by address.
- Prefer loading changed files from the port's own folder over rebuilding the disc. A rebuilt Wii image
  needs its partitions encrypted and hashed again; dtk and nod convert formats but this page has not
  checked a rebuild.

## Traps

- **Paired singles**: decode with Gekko_Broadway from the first import (step 3).
- **REL relocation**: a REL's addresses are only known at run time, and its relocations point into named
  modules. Disassembling a REL alone gives references to nothing; load it with the DOL (step 3) or let dtk
  link them (step 6).
- **The SDK's OS calls are ordinary functions.** The GameCube has no kernel and no syscall: `OSInit`,
  `DVDRead`, `GXBegin` are code in the DOL like the game's own, and they write hardware registers at
  `0xCC000000` directly. The edge a port answers is the SDK's function list, found by signature (dtk) or
  by the SDK banners' versions, not an import table. On the Wii the SDK's calls end in IPC requests to IOS
  (`IOS_Open`, `IOS_Ioctl` on `/dev/...` paths), which give a second, narrower edge.
- **MEM2 and caches**: Wii code may sit in MEM2 (`0x90000000`); `info` reports `uses_mem2`. The same
  memory appears cached and uncached at two addresses.

## Outputs, kept where they belong

| Output | Where |
|---|---|
| images, extracted tree, Dolphin user folder, save states, dumps | the port's work folder (never git) |
| hashes, game id and revision, REL load table, first-frame list, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project; dtk's symbol files in a decompilation; `.map` files for Dolphin |
| tool fixes and generic traps | this suite (this page) |

## Still missing

- A built GameCube loader verified in the suite's Ghidra (needs the source build, step 3).
- A GDB back end for the suite's oracle format, for Dolphin and the other GDB stubs.
- An RSO reader in `rea-suite gamecube`; dtk covers it today.
- DSP ADPCM and GX texture converters.

## Sources (read 2026-11-13)

- Ghidra-GameCube-Loader: GitHub releases (1.3.1, 2026-05-24, asset built for Ghidra 12.1) and its
  README (formats, building).
- decomp-toolkit: README (commands, analyzer features), release v1.8.4 (2026-09-09).
- nod (encounter/nod, Apache-2.0 or MIT): README (formats); nod-rs 2.0.0a12 on PyPI (2026-09-16), its
  type stubs (`DiscReader`, `PartitionMeta`).
- Dolphin 2609b: `Source/Core/Core/Core.cpp`, `Config/MainSettings.cpp`, `PowerPC/GDBStub.cpp`,
  `UICommon/CommandLineParse.cpp`, `DolphinNoGUI/MainNoGUI.cpp`, `DolphinTool/ToolMain.cpp`; the release
  archives' contents; Debian's `dolphin-emu` file list (`dolphin-emu-nogui`, `dolphin-tool`).
- rea-agents 6.8.0 and 6.9.0: `dist/ghidra/GhidraDolProfile.js` (unchanged between them),
  `GhidraProviderClient.js`, `mcp-catalog.json` (`open_binary`'s `format`).
- DolRecomp and WiiCompiled: READMEs and licenses (GitHub, last pushed 2026-10-10 and 2026-11-12).
- The audit that ranked this route: [audits/2026-11-13-platform-check.md](audits/2026-11-13-platform-check.md).
