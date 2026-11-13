# Xbox 360 games: the route

How to take an Xbox 360 game (2005-2013: a big-endian PowerPC executable, `default.xex`, on an XGD2 or
XGD3 disc) from its disc image to what a static recompilation needs, with the suite's tools in the order
they are used. Each step says what its output decides and feeds next. Call of Duty 3 took this route
first (games/cod3, 2026-10 to 2026-11); its lessons are in the steps, and the detail stays in its own
repository and in the fork games/rexglue-sdk (`docs/xbox360-titles.md`).

What lies around this page:

- The original Xbox, for comparison: [XBOX-CLASSIC.md](XBOX-CLASSIC.md) (x86, so it goes onto winrt
  instead).
- Disc and container tools: [GAME-ARCHIVES.md](GAME-ARCHIVES.md) (extract-xiso, XGDTool, ZArchive).
- What XenonRecomp, Unleashed Recompiled and rexglue-sdk solved, and how:
  [RECOMPILATION.md](RECOMPILATION.md).
- The port's platform work (the master, the SDK, the port checklist): master-server's docs/PORTING.md,
  whose "Lessons" keep the Xbox 360 entries short and point here.

Install: XEXLoaderWV, the XEX loader for Ghidra, is always installed with Ghidra (pinned in
`common/tools.yml`, built from source for 12.1.4); `rea-suite doctor` checks that it loads
(`rea-suite xbox360 check`). Component `game-archives` brings extract-xiso.

## 1. The disc image, unpacked as data

```sh
mkdir -p ~/Games/<game>/disc
sha256sum game.iso
extract-xiso -x -d ~/Games/<game>/disc game.iso
sha256sum ~/Games/<game>/disc/default.xex
```

- extract-xiso finds the game partition by itself: it tries the XGD2 offset (0x0FD90000), then XGD3's
  (0x02080000), then XGD1's (`extract-xiso.c`).
- A Games on Demand package or another container needs XGDTool first (Windows only, dormant upstream;
  [GAME-ARCHIVES.md](GAME-ARCHIVES.md)). Project 1944's launcher also takes a GoD folder
  (`415607E1\00007000` for CoD3).
- The disc holds `default.xex`, often further executables (CoD3: `codmp_xenonf.xex` for multiplayer) and
  DLLs (CoD3: 15 level DLLs under `sp/`), the data, movies and `$SystemUpdate/`, which a port ignores.
  Look for every `*.xex` and `*.dll`.
- Record the image's hash and each executable's hash in the port's docs.

*Feeds:* the executables for steps 2 and 3, the data tree the port's file layer serves.

## 2. Identify the executable

Without Ghidra, on an XEX, its extracted image or a raw dump (`--base`, default 0x82000000):

| Command | Gives |
| --- | --- |
| `info <xex>` | the XEX2 headers as JSON: format, execution info, libraries, resources, security info |
| `extract <xex> -o image.bin` | the decrypted (retail or devkit key) image as loaded; basic compression only |
| `imports <xex>` | import thunks with their names (Xenia's export tables, `common/rea_suite/data/`) |
| `icon <xex> -o title.png\|.ico` | the dashboard title image from the title's XDBF resource |
| `pdata <image> [address...]` | the `.pdata` function table, or the functions containing the addresses |
| `callers <image> <address>...` | `b`/`bl` instructions to the addresses |
| `refs <image> <text\|0xaddr>...` | `lis` + `addi`/load/store pairs building the address of a string or value, which Ghidra often leaves unresolved on 360 code |
| `rtti <image> <Class>...` | MSVC RTTI: type descriptor, complete object locators, vtables |
| `helpers <image>` | the save/restore helpers' first entries, as XenonRecomp's config keys |
| `disasm <image> <address> [count]` | Capstone disassembly; undecoded words are marked (VMX128) |

All are `rea-suite xbox360 <command>`. `extract` refuses LZX-compressed XEX files (normal and delta
compression) with that reason; step 3's `analyze` reads them through XEXLoaderWV.

- `info` gives the title id (CoD3: `415607E1`), the image base and size, the entry point, TLS, and the
  XDK libraries with their build (CoD3: XDK 2.0.3424 for D3D9, XAPILIB, XONLINE, XMEDIA and the rest).
- `.pdata` lists every function with a stack frame (CoD3: about 22,000), the recompiler's first seeds.
- Extra executable sections are worth a note (CoD3's single player has seven `.embsec_` sections; the
  multiplayer executable has none).

*Feeds:* the size of the job, the image for step 3 and the recompiler, the helper addresses for its
config.

## Achievements, strings and presence: the SPA

`rea-suite xbox360 spa <default.xex | .spa | XDBF> [--out DIR] [--format json|declarations] [--lang en-US]`
reads the title's SPA: the XDBF resource the XEX names after its title id (an LZX-compressed XEX is
refused, as `extract` refuses it; give the SPA itself then). It reads, by section:

| Section | Gives |
| --- | --- |
| XTHD, XSTC, string 0x8000 | title id, type and version; the default language; the title's name |
| XACH | achievements: id, name and description string ids, image id, gamerscore, type, secret |
| XSTR (namespace 3) | every string by id, per language |
| images (namespace 2), XITB | every PNG by id; their source file names |
| XCXT, XPRP, XRPT, XPBM, XMAT | contexts and their highest value, properties, the presence modes with the contexts and properties each uses, matchmaking |
| XVC2 | stats views: the count and their property bags; the rest is kept as hex, not decoded |
| XSRC | the embedded XLAST (gzip, XML): saved, and the source of what the binary sections leave out |

The binary sections hold no presence templates, no context value strings and no friendly names;
the XLAST does, so presence is complete only when the SPA embeds it. It is also compared with the
binary sections (achievements, strings, contexts, properties, mode count) and every difference is
printed. A section, namespace or XLAST element the tool does not read is listed, never dropped.

- `--format json` (default): `spa.json` (everything above, ids kept), `images/<id>.png` and
  `xlast.xml` as the SPA holds it (UTF-16 in shipped titles).
- `--format declarations`: master-sdk's `achievements.json` (`gm-achievements-v1`) and
  `presence.json` (`gm-presence-v1`) in `--lang` (a missing text falls back to the default language,
  said), with the 360's achievement ids, types (the numbers are the same) and pictures as base64
  PNG. A presence mode becomes an entry (its friendly name in snake case), `{cN}` a choice token on
  a list of the context's values, `{pN}` a number or name token. Text is folded to printable ASCII
  (accents dropped, line breaks joined with ` - ` in templates), each change printed; a text over a
  limit stops the run with its place. A picture over 256x256 or 64 KiB is scaled down, said. The
  result goes through master-sdk's `sdk/tools/declarations.py check` when the checkout is at
  `~/Dev/Falcon/master-sdk` (or `--sdk`, `REA_MASTER_SDK`); its limits come from its `limits.json`.

Checked on Lost: Via Domus (2026-11-13): 30 achievements, 1000 G, 17 secret, 3 presence modes, 3 XLAST
contexts with 58 values, 13 XLAST properties (18 in XPRP: the 5 system ones have no string), 5
languages of 145 strings, 4 pictures and the title image, no cross-check difference. XPRP stores a
string property's size as 2 where the XLAST says 0. Code: `common/rea_suite/xdbf.py` (the container),
`spa.py` (one parser per section, the XLAST), `spa_out.py` (one writer per format).

## 3. Ghidra

`rea-suite xbox360` runs the suite's Ghidra headless on an XEX (by its `XEX2` magic, through the
XEXLoaderWV extension) or on the PE image extracted from one (COFF machine 0x01f2), both as
`PowerPC:BE:64:A2ALT-32addr` (big-endian 64-bit with Altivec, 32-bit addresses). REA itself does not
open either (its PowerPC lane is ELF32 only; REA 6.8.0, not rechecked with 6.9.0). The Ghidra project is
yours: pass its folder; the suite keeps nothing in `work/`.

```sh
rea-suite xbox360 analyze game/default.xex --project re/ghidra-project --name game  # once
rea-suite xbox360 decomp --project re/ghidra-project -o out.c 0x82514710 0x8234e2e8
rea-suite xbox360 xrefs --project re/ghidra-project "connect"   # functions using strings
rea-suite xbox360 functions --project re/ghidra-project -o functions.tsv
rea-suite xbox360 names --project re/ghidra-project --program mp --from re/functions.tsv --where game=mp
rea-suite xbox360 check                     # XEXLoaderWV installed and loading (doctor runs it)
```

`names` writes a port's map into the project (the porting rule "map the whole unit once": the names in the
port's docs and in its Ghidra project): a TSV whose header names `address` and `name`, `what` or `comment` the
plate comment, filtered by `--where column=value`. A name Ghidra gave (`FUN_...`) is replaced; one a person or an
import gave, and a different plate comment, are kept and reported (`kept`), so running it again changes nothing
(`same`); `-o` writes the per-entry report. It needs `--program` when the project holds several. `--functions`
says the map lists functions: where Ghidra found none and the code disassembles, one is created before it is
named (reported `created`), else the name goes on a label. Not read-only, it also saves the helpers' repair (as `analyze` does).
The queries open the project read-only and take `--program` when it holds more than one; Ghidra's
logs go to `<project>/logs/`.

- **The save/restore helpers.** `common/ghidra_scripts/XenonHelpers.java` runs before analysis and
  before every query: it finds the register save/restore helpers (`__savegprlr_*`, `__restgprlr_*`,
  `__savefpr_*`, `__restfpr_*`, `__savevmx_*`, `__restvmx_*`) by their instruction pattern, names them
  and gives them a call-fixup without effect, so Ghidra's "Non-Returning Functions - Discovered"
  analyzer leaves them alone. Without it they are marked non-returning and every caller is cut off after
  its prologue; projects analyzed before are repaired in memory.
- **An extracted image** is laid out as loaded while its section table still gives the linker's file
  offsets: `analyze` imports a copy whose section table matches.
- **VMX128.** Each command ends with `Limit:` lines: instructions Ghidra cannot decode (VMX128 is
  missing from Ghidra's PowerPC language; disassembly and decompiles stop there; about 1,400 per CoD3
  image), and for a PE image the XEX import names it lacks. The recompiler's generated code keeps the
  exact disassembly as comments: trust it over a decompile for those spans.
- **Never `analyze --force` on a port's project**: it imports again and loses the names given in it
  (CoD3's rule).

*Feeds:* names and function boundaries, the RTTI class map, the units a change lives in.

## 4. The kernel and XAM census

`imports` lists the edge the game calls: the kernel (`xboxkrnl.exe`) and XAM (`xam.xex`), by ordinal.
CoD3's single player imports 136 kernel functions, 43 XAM functions and 10 kernel variables. Group them
(threads and sync, memory, files, `Vd*` graphics, `XMA*` audio, XAM input, content, profile, sign-in and
UI, `NetDll_*` sockets, `Xex*` module loading) and note which the runtime already answers.

- **Direct3D is linked into the game.** The XDK's D3D9 is static and writes PM4 packets straight into
  the GPU ring buffer (`VdInitializeRingBuffer`, `VdSwap`). The edge is then either the GPU's command
  stream (rexglue's Xenos emulation) or the game's own Direct3D functions found and replaced by address
  (Unleashed's way, one renderer per game). CoD3 took the command stream: replacing hundreds of inlined
  D3D routines was the larger job.
- **Audio**: XMA contexts and `XAudio*`; middleware sits on top (CoD3: FMOD Ex 4.04.18). rexglue decodes
  XMA through FFmpeg.
- **`XamLoaderLaunchTitle`** in the list means the game reboots itself to change mission or mode
  (step 6).

*Feeds:* the runtime's work list and the choice of the graphics edge.

## 5. Observe the original: Xenia Canary

Xenia Canary is the oracle: its master branch has had no commit since 2026-02-18, while Canary builds
daily (checked 2026-11-13). The suite does not install it, and its debugger was not checked here.
Compare the port with a Canary run of the same build: kernel and XAM calls, the files read, the first
frames. The CoD3 port's prior-art notes (2026-10-14) record CoD3 as "Playable" in Canary's compatibility
list, with GPU readback issues.

*Feeds:* the expected behavior where the recompiled game diverges.

## 6. The recompilation

The live tool is [rexglue-sdk](https://github.com/rexglue/rexglue-sdk) (BSD-3-Clause, Xenia's runtime
under it); our ports use the fork games/rexglue-sdk (branch `games`) and pin it.
[XenonRecomp](https://github.com/hedge-dev/XenonRecomp) is the reference design, not the maintained tool
(no commit since 2025-08-04). On CoD3 plain XenonRecomp stopped at 2,300 unimplemented VMX instructions
and more than 60 jump tables escaping their functions; rexglue's analyzer needed two boundaries by hand.

Lessons from CoD3 (the fork's `docs/xbox360-titles.md` has each fix):

- **DLLs that share a base address** (CoD3's level DLLs all at 0x89000000) need codegen per module, or
  each analysis reads another module's bytes.
- **Entries only data points to** (a vtable or a callback table, right after an unconditional branch)
  are merged into the function before them; the run stops at "Call to invalid or unregistered
  function". The fork's `find_data_entrypoints.py` lists them (CoD3: 40 in the title, 6 to 13 per level).
- **A module load reset the title's heap** (`XexModule::ReadImage`), fixed in the fork.
- **setjmp/longjmp coroutines**: script threads that copy the guest stack and jump back into a
  suspended call chain cannot resume in translated code. The port runs each on a host fiber.
- **A guest thread's fiber released on another thread** cleared that thread's current fiber, a crash
  seen only in Release builds. Reproduce a crash only the shipped build shows with that build.
- **Title relaunch**: `XamLoaderLaunchTitle` only exits in the runtime. The port writes the launch data
  to a file and starts itself again with it; that file is also a test fixture that boots straight into a
  mission. A test install that lacks it makes a relaunch fail: count such a run as invalid, not red.
- **System Link over plain IPv4 and IPv6**: XNet and XSocket needed byte-order and broadcast fixes, a
  non-zero XNADDR "MAC", and IPv6 peers mapped to virtual IPv4 addresses.
- **No audio device**: a null driver, and a 16th of the real-time mix rate for a dedicated server.
- **The GPU**: Xenos co-issued scalar operands (CoD3's grass drew as stretched strips).
- **Windows builds with llvm-mingw**: `setjmp` without a frame, no Control Flow Guard or CET yet, each
  guest `jmp_buf` in its own allocation.

*Feeds:* the port.

## Other CoD3 ports

The recompiled-games list (2026-11-12) has two more CoD3 ports, and the CoD3 port's own
`docs/02-prior-art.md` two others. They are a map, not code to copy, unless the license allows it.

| Project | License (checked 2026-11-13) | What it is |
|---|---|---|
| [CoD3Recomp](https://github.com/FrankHUN88453/CoD3Recomp) | none (no license file: all rights reserved) | XenonRecomp with its own Direct3D 11 renderer; all 15 levels load, campaign only; release 0.5.0 (2026-10-21) |
| [Project 1944](https://github.com/zenit2893-cmyk/Call-of-Duty-3-PC-Editon) | BSD-3-Clause | rexglue and Direct3D 12, 15 level DLLs, Xenia-derived kernel and graphics; multiplayer with system link in v2.0 by the tracker; its README says only the first mission was verified. Moved from `zenit2893-cmyk/project-1944` (redirects) |
| [cod3_REcomp_](https://github.com/SirCarls/cod3_REcomp_) | MIT | rexglue with llvm-mingw; claims system link and split screen; not verified |
| [cod3pc](https://github.com/alekszverr-jpg/cod3pc) | none | rexglue 0.10.0 |

## Tests

`uv run --no-sync python -m unittest rea_suite.test_xex rea_suite.test_xbox360 rea_suite.test_spa` in
`common/` (synthetic samples); opt-in with Ghidra: `REA_XBOX360_INTEGRATION=1` (a synthetic PE) and
`REA_XBOX360_SAMPLE=<file>` with `REA_XBOX360_ADDRESS=<hex>` (a real executable, read-only).
XEXLoaderWV is pinned in `common/tools.yml`; `rea-suite tools reinstall ghidra` puts it back when doctor
reports it missing. Its newest release is built for Ghidra 12.1.3 and none exists for 12.2 yet
(2026-11-13); the README's "Ghidra and its extensions" has the 12.2 plan.

## What is still missing

- An `xbox360 info`-style identify step shared with the other platforms, and a census in one schema
  (the platform check of 2026-11-13, Part 3).
- An oracle runner with sync points for Xenia Canary.
- An audio converter for XMA in the suite (vgmstream reads it; not installed).
- REA cannot open an XEX.

## Outputs, kept where they belong

| Output | Where |
|---|---|
| disc image, extracted tree, images, generated code, runs | the port's work folder (never git) |
| hashes, `info` JSON, the import census, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project (`--project`) |
| runtime fixes | the fork games/rexglue-sdk and its `docs/xbox360-titles.md` |
| tool fixes and generic traps | this suite (this page) |

## Sources (checked 2026-11-13)

- CoD3: `~/Dev/reverse-engineering/cod3/port` docs `00-overview.md`, `01-binary-analysis.md`,
  `02-prior-art.md`; the fork's `docs/xbox360-titles.md`; master-server's docs/PORTING.md, "Lessons".
- extract-xiso: `extract-xiso.c` at HEAD (the XGD1, XGD2 and XGD3 offsets).
- XenonRecomp and rexglue-sdk: their `commits.atom` and `releases.atom` feeds.
- Xenia: `xenia-project/xenia` and `xenia-canary/xenia-canary` `commits.atom`.
- The CoD3 ports: their READMEs, LICENSE files and the GitHub API's license field;
  [recompiled-games-list](https://github.com/wangxiaoxiang5599/recompiled-games-list) README.
