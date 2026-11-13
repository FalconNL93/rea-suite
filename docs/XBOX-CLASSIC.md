# Original Xbox games: the route

How to take an original Xbox game (2001-2005, "Xbox Classic": a 32-bit x86 executable, `default.xbe`,
on an XDVDFS disc) from its disc image to what a port or a static recompilation needs, with the suite's
tools in the order they are used. Each step says what its output decides and feeds next. No port has
taken this route yet: the steps were checked on the homebrew sample that ghidra-xbe ships (nxdk's
`triangle.xbe`) and on synthetic XBEs, not on a retail game (2026-11-12). The first port fills in the
traps; nothing about a particular game belongs on this page.

What lies around this page:

- The Xbox 360 route, for comparison: [XBOX360.md](XBOX360.md) (`rea-suite xbox360`)
  and [GAME-ARCHIVES.md](GAME-ARCHIVES.md) (extract-xiso, XGDTool).
- The DOS route, [DOS-GAMES.md](DOS-GAMES.md): the same shape for another x86 target, recompiled onto
  the same runtime.
- The port's platform work (the master, the SDK, the port checklist): master-server's docs/PORTING.md.
- What xboxrecomp, Microsoft's own Xbox recompiler and the other recompilers solved, and how:
  [RECOMPILATION.md](RECOMPILATION.md).
- The runtime an x86 game is recompiled onto: winrt's core (games/winrt: `recomp/image.h`, the
  interpreter and static recompiler in `src/cpu/`, the Direct3D 8 layer in `docs/d3d8.md`).

Install: component `xbox` (`rea-suite select`, then `rea-suite setup`) brings xemu and extract-xiso.
The XBE loader for Ghidra, ghidra-xbe with its XbSymbolDatabase CLI, is always installed with Ghidra;
`rea-suite doctor` checks that it loads (`rea-suite xbox check`).

## 1. The disc image, unpacked as data

```sh
mkdir -p ~/Games/<game>/disc
sha256sum game.iso
extract-xiso -l game.iso | head                         # the file list; options go before the file
extract-xiso -x -d ~/Games/<game>/disc game.iso
sha256sum ~/Games/<game>/disc/default.xbe
```

- A Redump image is the whole disc (XGD1: a video partition, then the game). extract-xiso finds the
  XDVDFS partition by itself (it tries the known offsets, XGD1's 0x18300000 among them), so the same
  command takes a Redump image or a trimmed XISO.
- The disc holds `default.xbe` (the game; some games boot further XBEs, look for every `*.xbe`), the data
  files, often `media/` and `*.xmv` movies. Treat the tree as untrusted data in its own folder.
- Record the image's hash and each XBE's hash in the port's docs; the port's loader checks the XBE.

*Feeds:* `default.xbe` for steps 2 and 3, the data tree the port's file layer serves.

## 2. Identify the executable

```sh
rea-suite xbox info default.xbe -o xbe.json     # build kind, entry, sections, title, XDK libraries
rea-suite xbox imports default.xbe -o kernel.tsv # kernel thunks: address, ordinal, name
rea-suite xbox image default.xbe -o flat.bin    # the image as loaded, at its base (0x00010000)
```

- `info` says the build kind (retail, debug or Chihiro, the arcade board: the entry point and the kernel
  thunk table are stored XORed with a key per kind; the command tries all three), the title and its id
  as on the box (`MS-004`), regions and media, the sections with their flags, and the XDK libraries the
  linker recorded with their versions (`D3D8 1.0.5849`). The library versions are the XDK build, which
  decides how well step 3's signatures match.
- XBEs import nothing but the kernel, `xboxkrnl.exe`, and only by ordinal (1-378). Everything else of the
  XDK (Direct3D 8, DirectSound, XAPI, networking) is linked into the executable, in sections named after
  the library (`D3D`, `DSOUND`, `XPP`, ...). `imports` names each thunk from pyxbe's table of the kernel's
  exports; ordinals 367-373 exist only in debug and profiling kernels and stay unnamed.
- `image` gives one flat file to load raw anywhere (Rizin, Unicorn, a recompiler) at the printed base:
  headers and sections at their addresses, bss and TLS zero, the thunk table still holding ordinals
  (`0x8000xxxx`) until a loader resolves them.

*Feeds:* the size of the job (how many kernel functions, which XDK libraries and versions), the image for
step 3 and for the recompiler.

## 3. Ghidra

```sh
rea-ghidra analyze --project <port>/re/ghidra --name <port> ~/Games/<game>/disc/default.xbe
rea-ghidra functions --project <port>/re/ghidra default.xbe > functions.tsv
rea-ghidra decomp --project <port>/re/ghidra default.xbe 0x... 0x...
rea-suite xbox symbols default.xbe -o xdk-symbols.tsv    # the same library names, without Ghidra
```

- Ghidra picks ghidra-xbe's loader by the `XBEH` magic ("Xbox Executable Format (XBE)",
  `x86:LE:32:default`, compiler spec `windows`): sections at their addresses, the kernel imports as
  `xboxkrnl.exe::<name>` external references, and during analysis its "Xbox Symbol Database Analyzer"
  labels the XDK functions XbSymbolDatabase recognizes, in a namespace per library (`D3D8::...`).
- REA does not open an XBE (REA 6.8.0: "unsupported binary format", checked 2026-11-12): use
  `rea-ghidra` and the `rea-suite xbox` commands. REA 6.9.0 (2026-11-12) is out and not yet checked here.
- **Library names come from XbSymbolDatabase's patterns** (Cxbx-Reloaded's OOVPA signatures, per XDK
  build), not from Ghidra's FunctionID. Ghidra's own `vsOlder_x86` set names some of the statically
  linked C runtime (xboxrecomp's ghidra_naming measured 134 names on Burnout 3); there is no XDK
  FunctionID set. TGP482/XboxXBERecomp's `xbe_symbols` has the shape of one: per XDK build
  (`xdk/<build>/signatures.toml`), the lengths and hashes of the library functions with their addresses
  masked, never the library code (its README, 2026-11-13).
- **Types**: mborgerson's [xbox-includes](https://github.com/mborgerson/xbox-includes) (GPL-2.0) holds
  the kernel and library headers: File > Parse C Source on `xbox.h`, then Apply Function Datatypes
  (ghidra-xbe's README). Keep the parsed archive in the port's project, not in git of a non-GPL port.
- Traps:
  - **XbSymbolDatabase crashes on an XBE without XDK libraries** (v3.1.160 segfaults on nxdk's homebrew
    `triangle.xbe`), and the analyzer ignores the exit, so the log says nothing and no names appear.
    `rea-suite xbox symbols` reports the crash. On a retail game, check that `D3D8::`/`XAPILIB::`
    names exist after analysis; if not, run `symbols` to see why.
  - **macOS**: ghidra-xbe bundles the CLI for macOS x86_64 only; Ghidra on Apple Silicon falls back to
    it, so it runs under Rosetta 2 (not checked here).
  - Decompile targeted addresses; keep the port's own project (`--project`) so its names survive.

*Feeds:* names and function boundaries for the recompiler (the function list as seeds) and the map of
each unit a change lives in.

## 4. The kernel and library census

`kernel.tsv` and `xdk-symbols.tsv` decide where the port's layer answers the game: the edge the game
calls is either the kernel or an XDK library, never the hardware, if the port is to run without an
emulator.

- **The kernel**: every ordinal the game imports gets a host function (files, threads, events, memory,
  `Hal*`, `Av*` video mode, `Xe*` for the loader). `kernel.tsv` is the complete list; one not written
  yet refuses with its ordinal and name where the game first calls it.
- **The XDK libraries**, linked into the game: Direct3D 8 writes NV2A push buffers itself, DirectSound
  drives the APU, XAPI wraps the kernel and the pads (XInput's ancestor, `XGetDevices`/`XInputGetState`).
  Answering them at their entry points (the high-level way, as Cxbx-Reloaded does with the same
  XbSymbolDatabase) means the hardware never needs to exist; answering the hardware instead (the
  low-level way, as xemu does: NV2A, APU, the real kernel) needs an emulator inside the port.
- Traps (from the tools' own files; not yet checked by a port of ours):
  - **Link-time code generation**: a game linked against `D3D8LTCG` has Direct3D compiled into its own
    code, where entry points may be inlined or given other calling conventions. XbSymbolDatabase keeps a
    separate, much smaller pattern set for it (`d3d8ltcg.def`: 1.3 KB of names against 13.5 KB for
    `d3d8.def`, v3.1.160), so expect fewer names, and an edge partly at the push buffer.
  - **An XDK build the database does not know** matches fewer functions. Run the bundled CLI with
    `-verbose` on the XBE (`$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-xbe/os/<platform>/XbSymbolDatabaseCLI`)
    to see which libraries it scanned.
  - **Kernel data exports**: some ordinals are variables (`KeTickCount`, `LaunchDataPage`, `XboxHardwareInfo`, ...),
    read through the thunk as a pointer; they need memory, not a function.

*Feeds:* the layer's service list (kernel ordinals, library functions), the decision between answering
libraries and emulating hardware, which the runtime's owner needs first.

## 5. Observe the original: xemu with its GDB stub

xemu is QEMU with the Xbox's hardware; extra arguments go to QEMU. It needs files from the owner's own
console: the MCPX boot ROM (`mcpx_1.0.bin`, MD5 `d49c52a4102f6df7bcf8d0617ac475ed`), a flash BIOS that
boots unsigned code (a debug or modded retail BIOS; xemu's docs name "COMPLEX 4627"), and a hard disk
image (xemu-dashboard publishes a free one, `xbox_hdd.qcow2`). They live in the work folder, never in
git.

```sh
mkdir -p work/xemu
cat > work/xemu/xemu.toml <<EOF
[perf]
cache_shaders = false
[sys.files]
bootrom_path = '$PWD/work/xemu/mcpx_1.0.bin'
flashrom_path = '$PWD/work/xemu/bios.bin'
eeprom_path = '$PWD/work/xemu/eeprom.bin'
hdd_path = '$PWD/work/xemu/xbox_hdd.qcow2'
EOF
XDG_DATA_HOME=$PWD/work/xemu/data xemu -config_path work/xemu/xemu.toml -dvd_path game.iso \
  -snapshot -gdb tcp:127.0.0.1:1234 -S &
gdb -q -ex 'set architecture i386' -ex 'target remote 127.0.0.1:1234'
```

- `-S` holds the machine at the reset vector until gdb continues it; `-snapshot` throws away the HDD's
  writes at exit, so every run starts from the same disk.
- In gdb, the game's addresses are its XBE addresses (base 0x00010000). Once the kernel has loaded the
  game, the thunk table holds the kernel functions' addresses (`0x80xxxxxx`): a breakpoint there, or on
  each thunk's target, logs the kernel calls with their arguments, the run's counterpart of step 4.
- xemu's monitor (the backtick key, or Debug > Monitor) answers `info registers`, `x/20i <address>` and
  `trace-event <name> on` (`nv2a_pgraph_*` for graphics) without gdb.

Traps and what fixed them (checked on Linux/WSL2 with xemu 0.8.139, 2026-11-12, without the console
files, so the machine stopped at the reset vector):

- **`-s` listens on every interface** (QEMU's default, `tcp::1234`): anyone on the network may attach.
  Use `-gdb tcp:127.0.0.1:1234`.
- **xemu writes to your home folder**: its settings and EEPROM go to `~/.local/share/xemu/xemu/`
  unless `-config_path` names a file whose `[sys.files]` paths point elsewhere, and its shader cache goes
  there even then. `XDG_DATA_HOME` moves that base folder (Linux); `cache_shaders = false` keeps it empty.
- **Headless**: `xvfb-run -a xemu ...` (with `WAYLAND_DISPLAY` unset under WSLg) runs it without a
  window; the GDB stub answered there. Rendering then goes through llvmpipe and is slow.
- **The AppImage's extraction**: xemu restarts itself from the extracted AppImage, so the runtime never
  removes it (47 MB per run in `/tmp`, which is memory on WSL). The suite's launcher sets `TMPDIR` to
  xemu's install folder, so it is reused there.
- **A retail BIOS does not boot games** in xemu; it needs a debug or a modded one (xemu's docs).

*Feeds:* the kernel calls up to the first frame, the order the game reads its files, the oracle the
port's runs are compared with.

## 6. What the recompilation needs

The XBE is plain 32-bit x86 compiled by the XDK's Microsoft C++, so it fits the same core as the PC
ports: winrt's static recompiler and interpreter (no emulator):

- **A loader of the port's own** on `recomp/image.h`: the image of step 2 (`rea-suite xbox image`, or
  the same mapping from the XBE's section table), the kernel thunk table filled with host thunks by
  ordinal, the TLS directory honored, entries from the entry point and the function list of step 3 as
  seeds, the generated code installed only for the same file hash and base.
- **The layer** (the port's): the kernel ordinals of step 4 over the game folder and a user folder
  (read-only original), and the XDK libraries answered at their entry points by the names of step 3
  (Direct3D 8 onto winrt's `src/dx/d3d8/`, DirectSound, XAPI's pads onto the host's), each refusing the
  unknown with its name and its caller.
- **The fastest way to the first frame**, as on the DOS route: a headless runner and a layer that stops
  on each unknown kernel ordinal or library call with its name, fixed one at a time against the xemu run
  of step 5.

[xboxrecomp](https://github.com/sp00nznet/xboxrecomp) (MIT, Python with Capstone and a C runtime) is one
of two public references for this whole route: an XBE parser, disassembly, library identification, ABI
recovery, lifting to C, and a runtime with all 371 kernel ordinals routed to Win32, Direct3D 8 onto Direct3D 11 or
OpenGL, the APU and an NV2A push-buffer executor; v0.17.0 lists about a dozen games as playable. It is
source only, cloned into a port's own project and built there, so the suite does not install it. Read its
`docs/formats/kernel-exports.md` and kernel bridge before writing a port's own.

The second is [XboxXBERecomp](https://github.com/TGP482/XboxXBERecomp) (TGP482, MIT, last commit
2026-11-08): an SDK that recompiles an XBE's code to C++, with Direct3D 8 on Direct3D 12 and XAudio2,
Windows x64 only (Clang and Ninja). Its README names its author's ports of Splinter Cell: Double Agent,
BLACK, 007: From Russia With Love, 007: Nightfire and Red Dead Revolver; the recompiled-games list adds
others' (Darkwatch, The Warriors, MVP Baseball 2005; checked 2026-11-13). A release ships no game code: it
builds the recompiled code on the player's PC from the player's own XBE. Read it beside xboxrecomp;
like it, it is a port's own dependency.

## What is still missing

- **A retail game through this route.** Every step above ran on homebrew or synthetic files only; the
  first port checks XbSymbolDatabase's yield on a retail XBE and replaces step 4's traps with its own.
- **A kernel-call log from xemu**, the counterpart of `rea-suite dosbox`'s interrupt log: gdb breakpoints
  on the thunks, written as JSON lines (TODO.md).
- **An XDK FunctionID set** built from the owner's own XDK libraries, as the README's Visual C++ 6.0
  recipe does for the PC runtime (TODO.md). XboxXBERecomp's masked signatures per XDK build are the
  format to follow.
- **Cxbx-Reloaded** (GPL-2.0, Windows; Wine on Linux), the high-level emulator whose library patches
  are the model for step 4's layer: its builds are GitHub pre-releases only (`CI-<commit>`), which the
  suite's `latest` lookup skips, so it is not installed (TODO.md). Low priority now: its newest
  pre-release and last commit are from 2026-04-19, XbSymbolDatabase's last commit from 2025-08-23, and
  xboxrecomp and XboxXBERecomp model the layer better (checked 2026-11-13).
- REA cannot open an XBE (TODO.md, "Upstream wishes").

## Outputs, kept where they belong

| Output | Where |
|---|---|
| disc image, extracted tree, flat image, xemu files and runs | the port's work folder (never git) |
| hashes, `info` JSON, kernel and library census, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project (`rea-ghidra --project`) |
| engine facts | master-server's ENGINES-*.md |
| tool fixes and generic traps | this suite (this page, PORT-TOOLS.md) |

## Sources (checked 2026-11-12)

- ghidra-xbe: [XboxDev/ghidra-xbe](https://github.com/XboxDev/ghidra-xbe), release
  `build-202610161023` for Ghidra 12.1.4 (the suite's pin); bundles XbSymbolDatabaseCLI v3.1.160
  (`build.sh`); the repository has no license file.
- XbSymbolDatabase: [Cxbx-Reloaded/XbSymbolDatabase](https://github.com/Cxbx-Reloaded/XbSymbolDatabase)
  (MIT), v3.1.160 the newest release (v4.0.166 a pre-release); the CLI's output format is
  `src/cli/main.c` (`LIBRARY__name = 0xaddress`).
- pyxbe: [XboxDev/pyxbe](https://github.com/XboxDev/pyxbe) (MIT; moved from mborgerson/pyxbe, which
  redirects; GitHub release v1.0.4 of 2026-06-08, checked 2026-11-13), 1.0.4 on PyPI; the kernel
  export table and the XBE structures.
- xemu: [xemu-project/xemu](https://github.com/xemu-project/xemu) v0.8.139;
  [guest debugging](https://xemu.app/docs/dev/debug/guest/) (`-s`, `-S`, port 1234, the monitor),
  [command line](https://xemu.app/docs/cli/) (extra arguments go to QEMU),
  [required files](https://xemu.app/docs/required-files/), `config_spec.yml` (the `sys.files` keys).
- extract-xiso: [XboxDev/extract-xiso](https://github.com/XboxDev/extract-xiso) `build-202609111233`;
  `extract-xiso.c` (the XGD1 and XGD3 partition offsets).
- Cxbx-Reloaded: [README](https://github.com/Cxbx-Reloaded/Cxbx-Reloaded) (Windows 7+ x64, or Wine;
  pre-release builds only; GPL-2.0).
- xboxrecomp: [sp00nznet/xboxrecomp](https://github.com/sp00nznet/xboxrecomp) README v0.17.0 (MIT;
  pipeline, runtime, kernel coverage, games) and `tools/ghidra_naming/README.md` (FunctionID yield).
- Kernel exports: [xboxdevwiki, Kernel](https://xboxdevwiki.net/Kernel) (ordinals 1-378; 367-369
  unused, 370-373 profiling builds).
- Other efforts seen, not used here: [halo-re/halo](https://github.com/halo-re/halo) (a decompilation
  patched back into the XBE), Anybox (a static recompiler to macOS arm64 apps, known only from its
  author's [article](https://levelup.gitconnected.com/building-anybox-9be69b13e9e5)),
  [OXDK](https://github.com/MrMilenko/OXDK) (builds XBEs with modern clang),
  [xdvdfs](https://github.com/antangelo/xdvdfs) (MIT, an XISO tool in Rust; releases for Linux and
  Windows only, so extract-xiso stays the suite's).
