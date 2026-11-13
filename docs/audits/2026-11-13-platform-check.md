# Platform coverage check, 2026-11-13

What the suite's platform routes claim, checked against the primary sources today; which platforms it
does not cover yet, and what a route for each would take; and what every route needs but only some have.
Research only: nothing was installed or run except HTTP reads of release feeds, raw source files and
READMEs. PS3 is out of scope (another session is building it on branch `ps3`), and so are process and
tool gaps in general (`2026-11-13-gap-analysis.md`).

Owner's decision (2026-11-13, relayed by the orchestrator): the suite gets **no legal section**. Keys,
firmware, BIOS files and game copies are the user's responsibility. No platform below is ranked down for
being legally sensitive. Where a route needs such a file, this report only notes the practical need (a
file at a path) and that it never goes into git.

## Summary, ranked

### Stale or wrong: fix these

| # | Where | What the doc says | What is true today (source) |
|---|---|---|---|
| 1 | PLAYSTATION.md, table row DuckStation | "DuckStation's source tree has no GDB server any more (2026-11-12)" | **Wrong.** `src/core/gdb_server.cpp` is at HEAD (1554 lines, last changed 2026-11-10), with settings `EnableGDBServer` / `GDBServerPort` in `src/core/settings.cpp`. The license claim (CC BY-NC-ND 4.0) is right. |
| 2 | PLAYSTATION.md, PS1.md §7, RECOMPILATION.md (table, §psxrecomp, Sources) | psxrecomp at `github.com/mstan/psxrecomp`, "source only, no releases" | Moved to **RetroPortingToolKit/psxrecomp** (the old URL redirects). It now has releases: v0.3.7-alpha (2026-11-07) with `psxrecomp-cli-windows-x86_64.zip`, a source zip and SHA256SUMS, plus nightlies (newest 2026-11-11). The license is still PolyForm Noncommercial 1.0.0. |
| 3 | PLAYSTATION.md, PS1.md, RECOMPILATION.md | RecompOne at `github.com/flafmg/RecompOne` | Moved to **BlackLabelHQ/RecompOne** (redirect). Still MIT and still without releases (last commit 2026-11-07). |
| 4 | PLAYSTATION.md, armips row; PS1.md §8 | "its only release (v0.11.0, 2019) is a 32-bit Windows build" | Three releases exist (v0.9, v0.10.0, v0.11.0). The newest, v0.11.0, was published **2020-05-10**, and its only asset is `armips-v0.11.0-windows-x86.7z`. The conclusion holds: there is no Linux or macOS build. |
| 5 | PLAYSTATION.md, maspsx row | "no release or package" | It has one release tag, `aspsx` (2026-10-13), which holds `aspsx-binaries.tar.gz` (the original ASPSX) and a `psyq-obj-parser` build. maspsx itself is still not released, so the conclusion holds. Reword so a reader does not find the release and doubt the page. |
| 6 | PLAYSTATION.md, PS2.md §7, RECOMPILATION.md | PS2Recomp "source only" | It has tagged pre-releases v0.2 to v0.4 (newest 2026-04-05) with no binary assets, and its last commit was 2026-10-23. In practice it is still source only; say "pre-release tags, no binaries". |
| 7 | XBOX-CLASSIC.md, Sources | pyxbe at `github.com/mborgerson/pyxbe` | Moved to **XboxDev/pyxbe** (redirect). GitHub release v1.0.4 is dated 2026-06-08. PyPI 1.0.4 still names the old URL. |
| 8 | PLAYSTATION.md "REA", XBOX-CLASSIC.md §3, TODO.md | "Installed REA **6.8.0**" | **REA 6.9.0 was published 2026-11-12** (npm `rea-agents`, latest). It still pins Ghidra 12.1.4 (`SUPPORTED_GHIDRA_VERSION`) and still has the PSP profile that wants ghidra-allegrex. Update the suite, then check again whether it opens PS-X EXE, R5900, XBE and LE files (6.9.0's `dist/ghidra/` has a `GhidraMipsProfile.js`; not run here). |
| 9 | RECOMPILATION.md, Sources | rexglue-sdk read at v0.10.0 | The newest release is **v0.10.1**, with nightlies 0.11.0-dev up to 2026-11-11. Our fork's pin is CoD3's business; the page should name the version it was read at, and that version is now behind. |
| 10 | Every page that says "Ghidra pin 12.1.4" | that it is current | **Ghidra 12.2 was released on 2026-10-22.** It needs JDK 25 at minimum, and "programs … created or modified in 12.2 may not be usable by an earlier Ghidra version" (WhatsNew.md). The pin stays at 12.1.4 because REA 6.9.0 still requires it. See the 12.2 readiness table below: it is a one-way door for every port's shared Ghidra project. |
| 11 | RECOMPILATION.md (XenonRecomp section), the 360 lane | XenonRecomp presented as a live line | XenonRecomp's last commit was **2025-08-04**, and Unleashed's last release was v1.0.3 (2025-04-05). The live line is rexglue: the tracker counts most new Xbox 360 ports as ReXGlue-based. Mark XenonRecomp as the reference design, not the maintained tool. |
| 12 | GAME-ARCHIVES.md | "Checked: 2026-11-03" | The versions are still current (extract-xiso build-202609111233, ZArchive v0.1.2, XGDTool v1.0.0, QuickBMS 0.12.0 on the mirror page). XGDTool has had no commit since 2024-08-13, and ZArchive none since 2025-08-30. Mark XGDTool as dormant. Re-date the page. |
| 13 | XBOX-CLASSIC.md, "Other efforts seen" and "What is still missing" | xboxrecomp is "the public reference for this whole route"; an XDK FunctionID set is wanted | A second, game-proven XBE recompiler now exists: **TGP482/XboxXBERecomp** (MIT, last commit 2026-11-08). The recompiled-games tracker lists games made with it as working: Splinter Cell Double Agent, BLACK and 007 From Russia with Love (Nightfire and Red Dead Revolver are named in its README). Its `xbe_symbols` writes XDK signatures as "lengths and hashes of the functions with addresses masked, never library code", per XDK build (`xdk/<build>/signatures.toml`). That is the shape of the missing XDK FunctionID set. It only outputs Windows x64 (Clang and Ninja, D3D12, XAudio2). |
| 14 | XBOX-CLASSIC.md, Cxbx-Reloaded | the TODO to pin a pre-release | Its newest CI pre-releases are from 2026-04-19 (also its last commit), and XbSymbolDatabase's last commit was 2025-08-23. Both are slowing down. The TODO's priority should drop: TGP482's tool and xboxrecomp now model the layer better. |

Checked and still true (no change needed): ghidra-emotionengine-reloaded v2.1.39 (it now also ships a 12.2
build); ghidra_psx_ldr 2026.11.08 is 12.2-only, and 2026.10.03 is the newest 12.1.4 build; ghidra-ps2sdk
answers 404 and no fork turned up in a search; PCSX2's stable release is v2.8.2 (the v2.9.x builds are
nightlies), and there is still no GDB stub (`pcsx2/` has `PINE.cpp`, but no gdb file);
PCSX-Redux has no GitHub releases; splat 0.50.1; objdiff v3.8.3; mkpsxiso v2.30; jPSXdec v2.1 beta;
xemu v0.8.139 is the newest stable; ghidra-xbe build-202610161023; extract-xiso build-202609111233;
xboxrecomp v0.17.0; XEXLoaderWV's newest release is for Ghidra 12.1.3; DOSBox-X 2026.10.01; the
ghidra-lx-loader pin `60bae519…` is still its newest commit; the tracker's figure of 277 static
recompilations (378 projects, 2026-11-12) matches RECOMPILATION.md.

### New tools worth adopting

1. **TGP482/XboxXBERecomp** (MIT): read it beside xboxrecomp for the Xbox route. Its signature format
   (masked function hashes per XDK build) is the XDK FunctionID set the route lacks. It does not join
   the suite: a port carries it as `sdk/`.
2. **DuckStation's GDB server**: a second PS1 oracle with a GDB stub, next to PCSX-Redux. Its CC BY-NC-ND
   license only allows running it unmodified, which is all an oracle needs. **Owner's decision**: add it
   as an optional tool, or keep only PCSX-Redux.
3. **vgmstream** (r2168, 2026-10-25): one decoder for console audio (XMA and XMA2 for the 360, VAG for
   PS1 and PS2, ADX for the Dreamcast, DSP for the GameCube and Wii). The suite has no audio converter;
   PS2.md says so. It helps every console route, CoD3's XMA included.
4. **ghidra-allegrex** (now v21.6, 12.2 only; v21.4 has the 12.1.4 build): already in TODO.md. REA 6.9.0's
   PSP profile still expects it. It is the cheapest new platform (see PSP below).
5. **Recompilers for platforms the suite does not cover**, as references for RECOMPILATION.md:
   DolRecomp (ExpansionPak, GameCube and Wii PowerPC to C, CPU only, GPL-3.0), WiiCompiled (patchzyy,
   v0.9.4 2026-11-10, GPL-3.0), RebrewU (Wii U, via SplatPC), psprecomp (sp00nznet, v0.5.0, MIT),
   snesrecomp and ndsrecomp (RetroPortingToolKit, custom licenses), and for the Switch nx, kirikae and
   Suyu's recompiler mode (unverified, from secondary sources).
6. **PC x86 static recompilations** missing from RECOMPILATION.md "Others": cricket07-browser and
   nfsu2-web (Win32 to WebGPU), NFSU2Recomp (x86 to ARM64, D3D9 to Metal), Skyrim_Android (x86 to arm64,
   D3D9 to Vulkan) and portal2-recomp (Linux x86 ELF to ARM64). These are winrt's direct peers.
7. **RetroPortingToolKit's shared layer** (MIT): Retro-Runtime, recomp-net with recomp-net-server
   (lobby and signaling), rbengine (rollback) and Retro-Launcher. It is a community platform layer for
   recompiled games, close to what master-server and master-sdk do. **Owner's decision**: study it for
   the SDK's netplay and lobby design, or ignore it.

### Missing platforms, in order (effort S: a route page and a pinned loader or emulator, days; M: also a suite command and an oracle backend, one to two weeks; L: new CPU classes, encrypted containers or several processors)

| Rank | Platform | Effort | Why this rank |
|---|---|---|---|
| 1 | **Win9x and Win16 specifics** on the PC route | S | This is the owner's core. 32-bit Win9x games fit winrt, but the route has no page for what is particular to that era: 16-bit installers and thunks, CD audio, DirectDraw and D3D 3-7, Glide. |
| 2 | **GameCube and Wii** | M | The strongest tooling of any platform the suite lacks: dtk, objdiff (already installed), Dolphin's GDB stub, Ghidra-GameCube-Loader, DolRecomp, WiiCompiled, 23 tracker projects. Console-only CoD entries are among its games (Finest Hour, Big Red One, CoD3 on Wii). |
| 3 | **PSP** | S | REA already has a PSP profile; ghidra-allegrex, splat and PPSSPP's WebSocket debugger exist. CoD: Roads to Victory was PSP-only. |
| 4 | Nintendo DS | M | NTRGhidra, melonDS's GDB stub, ndsrecomp; CoD had DS-only entries. ARM9 and ARM7. |
| 5 | Linux-native old games | S | Ghidra and REA open ELF; the work is old glibc and SDL 1.2 runtimes. Cheap but rarely needed. |
| 6 | Wii U | M | Cemu has a GDB stub; ZArchive and WUA are already in the suite; RebrewU. Its games mostly have PC versions. |
| 7 | N64 | M | The best recompiler (N64Recomp) and N64LoaderWV. Low relevance to the owner's catalog. |
| 8 | Old Android and iOS | S | Mostly covered already (jadx, apktool, adb, Frida, ipsw, REA). Only a route page is missing. |
| 9 | Dreamcast | M | Ghidra has SH-4 built in and flycast has a GDB server. Almost no recompilation work exists. |
| 10 | 3DS | M-L | Azahar has a GDB stub; one recompilation (TriAevum). Encrypted containers need the user's key file. |
| 11 | Switch | L | Ghidra-Switch-Loader exists; the recompilers are young; it needs a key file. Its games mostly have PC versions. |
| 12 | PS Vita | M | VitaLoaderRedux and Vita3K's GDB stub. Low relevance. |
| 13 | GBA and SNES | S-M | mGBA's GDB stub, Mesen2, ares, snesrecomp. The Ghidra loaders are stale (GhidraGBA 2021, ghidra-65816 2019). |
| 14 | Flash and Shockwave | S | JPEXS FFDec, Ruffle, ProjectorRays, dirplayer-rs. Not native code. |
| 15 | Java ME | S | jadx is in the suite already; freej2me and J2ME-Loader. |
| 16 | Classic Mac (68k and PPC) | M-L | Ghidra's PEF loader and 68k, resource_dasm, QEMU q800 with GDB. Basilisk II and SheepShaver have no stub. |
| 17 | Saturn | L | Two SH-2 CPUs plus VDP1 and VDP2; weak tooling (Yabause dead since 2018, Kronos alive). |

## Part 1: the existing routes, in detail

Every version and date below was read today (2026-11-13), from each GitHub repository's `releases.atom`
and `commits.atom`, from redirects of `/releases/latest`, from raw files at HEAD, and from npm's registry.

### DOS (DOS-GAMES.md)

- DOSBox-X 2026.10.01 is the newest release (2026-10-02; the last commit is 2026-11-12, so a newer
  release is likely soon). The ghidra-lx-loader pin is still its newest commit (upstream release 12.0.1,
  2026-01-29). innoextract's newest release is still 1.9 (2020): it is old but not abandoned (last commit
  2025-02-06).
- pcrecomp (no releases, last commit 2026-11-11) is still active; the claims about its DOS32 host were
  not re-read.
- Nothing stale on the page. One gap: it names no Watcom FunctionID source. None exists upstream; it is
  already in TODO.md.

### PS1 and PS2 (PS1.md, PS2.md, PLAYSTATION.md)

Corrections 1 to 6 above. The rest:

- decompals/old-gcc has releases (0.17, 2026-05-13) with Linux x86_64 builds, as the page says.
- psyz has a release named "Requirements" (2026-01-27) and is active (2026-11-07). It is still niche.
- The PS2.md claim "A VU microcode disassembler … none found" needs nuance: PCSX2's source has
  `DisVU0Micro.cpp` and `DisVU1Micro.cpp`, and its debugger uses them. They are not a standalone tool,
  but they are the GPL source to take one from.

### Original Xbox (XBOX-CLASSIC.md)

Corrections 7, 13 and 14 above. xemu's newest stable is v0.8.139 (2026-10-21); development builds come
daily. ghidra-xbe has no Ghidra 12.2 build yet (its newest build is from 2026-10-16, before 12.2).
The tracker lists 41 original Xbox projects, built mostly on xboxrecomp and XboxXBERecomp.

### Xbox 360 (README.md "Console games and disc images", `rea-suite xbox360`)

- **There is no route page.** The 360 lane exists only as a README section (the commands and tests)
  plus RECOMPILATION.md's recompiler notes. Every other platform has a numbered route (disc, identify,
  Ghidra, census, oracle, recompilation, outputs). CoD3 and Lost: Via Domus (Yeti.big) have the
  lessons for one. Proposal: `docs/XBOX-360.md` in the same shape.
- XEXLoaderWV: its newest release is "Extension for Ghidra 12.1.3" (2026-09-20). The suite builds it
  from source for 12.1.4, as the pin's comment says, and it has nothing for 12.2 yet.
- Xenia's master branch has had no commit since 2026-02-18. Xenia Canary is active, with builds daily
  (2026-11-12). The oracle column in RECOMPILATION.md should name Canary first.
- The tracker has 77 Xbox 360 projects, among them **two CoD3 ports**: CoD3Recomp (XenonRecomp, its own
  D3D11 renderer, campaign only) and Project 1944 (ReXGlue, D3D12, multiplayer with system link). The
  CoD3 port should know about them. They are a map, not code to copy; their licenses were not checked.

### RECOMPILATION.md

Corrections 2, 3, 6, 9 and 11 above. It is missing GameCube, Wii, Wii U, PSP, NDS, SNES and Switch
recompilers (new tool 5) and the PC peers (new tool 6). Its "Which approach for which platform" table
has a row for N64 but none for the platforms in Part 2. Add rows when a route starts, not before.

### GAME-ARCHIVES.md

Correction 12. It also says "This source-build path has not been executed on any host" for ZArchive.
That is still true, as far as the repository shows.

### PORT-TOOLS.md

PORT-TOOLS.md documents the suite's own commands (`pe`, `rmdp`, `yetibig`, `le`, `frida`, `dosbox`,
`pad`, `run`), so no upstream freshness applies. Out of scope here (the gap analysis covers it).

### PC Win32, as the ports use it (winrt, the suite, master-server docs/PORTING.md "The route")

- The route is spread over three places: PORTING.md "The route" (the port's process), the suite's README
  "Porting old games" and "FunctionID for Visual C++ 6.0", and PORT-TOOLS.md's `pe` commands. It has no
  page of the DOS-GAMES.md shape: installer, identify (`pe info`, DIE), Ghidra with VC6 FunctionID, the
  import census (`pe imports`), the oracle (Wine `+relay`, Frida, `run`), then winrt. The most used route
  is the only one without a route page. Proposal: `docs/PC-WIN32.md`.
- DIE's database is current (2026-11-12). rizin v0.9.1, ImHex nightlies and capa v10 are all current.
- BinExport's newest release targets Ghidra 11.0.3 (2024-04-17), though it has commits up to 2026-10-27.
  The TODO's "BinDiff … target old Ghidra versions" still holds.
- Kaitai Struct compiler 0.11 (2025-09-07) is current. Its TODO entry is still valid.

### Ghidra 12.2 readiness (for when REA moves its pin)

| Extension | 12.1.4 build | 12.2 build |
|---|---|---|
| REA itself (6.9.0) | required | no |
| ghidra_psx_ldr | 2026.10.03 | 2026.11.08 (12.2 only) |
| emotionengine-reloaded | v2.1.39 | v2.1.39 |
| ghidra-xbe | build-202610161023 | none yet |
| XEXLoaderWV | source build (12.1.3 release) | none yet (source build likely works; unverified) |
| ghidra-lx-loader | commit pin, built here | built here (unverified) |
| ghidra-allegrex (not installed) | v21.4 | v21.5 and v21.6 |

Moving to 12.2 is one-way for every port's Ghidra project (programs saved by 12.2 may not open in
12.1.x) and needs JDK 25. **Owner's decision when REA moves**: move every port at once, or keep a 12.1.4
copy for old projects.

## Part 2: missing platforms, in detail

Weighting: the owner ports PC and console games to modern PC (Linux, Windows, macOS, Steam Deck). The
current ports are CoD1 and United Offensive (PC), CoD3 (Xbox 360), Rogue Spear, Alan Wake and Alan Wake 2
(PC), Theme Park (DOS) and Lost: Via Domus (PC); C&C/RA2 and Max Payne are paused. So PC comes first, then
consoles that hold games never released on PC, CoD's console-only entries above all (Finest Hour and Big
Red One on PS2, Xbox and GameCube; CoD3 on Wii and PS2; Roads to Victory on PSP; World at War: Final
Fronts on PS2; the DS entries). These titles are examples from public knowledge; which ones matter is the
**owner's decision**.

Route needs that apply everywhere: a BIOS, firmware or key file the user supplies at a path in the
work folder, checked by `doctor` where the route needs one, and never in git.

### 1. Win9x and Win16 specifics: S

- **Is Win32 on winrt enough?** For 32-bit PE games of the Win9x era, mostly yes. What the route lacks
  is a page for that era's traps:
  - 16-bit setup programs and thunks (an NE `SETUP.EXE` in front of a 32-bit game);
  - CD audio tracks, which need the CUE/BIN like PS1;
  - DirectDraw and D3D 3-7 (winrt has research on these);
  - Glide (3dfx);
  - DirectPlay lobbies;
  - SmartHeap and other allocators.
- **Win16 (NE) games**: Ghidra has an NE loader built in, and pcrecomp lifts NE programs. For running
  them, winevdm/otvdm (v0.9.0, 2023, last commit 2026-10-24) runs Win16 on 64-bit Windows. Wine's new
  WoW64 mode, which the suite's Wine relies on, is reported to have gained 16-bit support in 10.16, with
  open bugs (e.g. Wine bug 58760). Check it on the suite's Wine before relying on it.
- **Route work**: one `PC-WIN32.md` with a Win9x section (see Part 1), plus an NE line in a shared
  identify command (Part 3). No new runtime.

### 2. GameCube and Wii: M

- **Decompilation**: decomp-toolkit (dtk) v1.8.4 (2026-09-09), with objdiff already installed. Matching
  decompilations exist for Melee, Twilight Princess, Metroid Prime, Sunshine and Animal Crossing (the
  tracker lists 15 GameCube projects).
- **Recompilation**: DolRecomp (ExpansionPak, GPL-3.0; CPU only, no runtime, DOL and REL load) and
  WiiCompiled (v0.9.4, GPL-3.0; 8 Wii ports).
- **Ghidra**: Cuyler36/Ghidra-GameCube-Loader (DOL, REL, RSO; latest 1.3.1, last commit 2026-11-11).
- **Oracle**: Dolphin (2609b, 2026-11-08) has `Source/Core/Core/PowerPC/GDBStub.cpp`, and
  dolphin-memory-engine (2026.06.25) reads its memory.
- **Route**: a `gamecube` component (the loader, Dolphin, dtk), a disc step (GCM/ISO, RVZ through
  Dolphin's tool), and a GDB-backend oracle. The PowerPC lessons from the 360 carry over.

### 3. PSP: S

- REA 6.9.0's PSP profile (`GhidraPspProfile.js`, `GhidraPspExtension.js`) expects ghidra-allegrex under
  `GHIDRA_INSTALL_DIR/Ghidra/Extensions` ("REA does not install it"). Install it and REA opens PSP ELF
  and PRX files: the only console here where REA itself works.
- splat splits PSP executables. psprecomp (MIT, v0.5.0, early) and the PSPRecomp ports (LCS Recomp,
  gow-psp-recomp) show recompilation works.
- **Oracle**: PPSSPP v1.20.4 has a WebSocket debugger API (`Core/Debugger/WebSocket.cpp`), not GDB.
  It needs a small backend of its own.
- Encrypted EBOOTs need decryption first, which PPSSPP does on load.

### 4. Nintendo DS: M

- NTRGhidra v1.5.1 (for Ghidra 12.0.4; no 12.1.4 build, so it needs a source build or waits).
- melonDS 1.1 has a GDB stub (`src/debug/GdbStub.cpp`).
- ndsrecomp (RetroPortingToolKit, "early research … source-only", its own license). Ports: Metroid Prime
  Hunters, Mario Kart DS, Chrono Trigger (Egg of Time).
- Two CPUs (ARM9 and ARM7) and overlays (`y9.bin`). The PS1 overlay work carries over.

### 5. Linux-native old games: S

Loki-era i386 ELF builds. Ghidra and REA open ELF. The work is the runtime: old glibc, SDL 1.2, OSS
audio. portal2-recomp shows Linux x86 to ARM64 static recompilation. A short section in PC-WIN32.md or
its own small page is enough.

### 6. Wii U: M

- Cemu 2.6 has a GDB stub (`src/Cafe/HW/Espresso/Debugger/GDBStub.cpp`). ZArchive (WUA) is already in
  component `game-archives`. RPX and RPL are ELF variants (Ghidra loader projects exist; not checked).
- RebrewU (SplatPC) and ZeldaWWHDRecomp exist; the tracker lists 5 Wii U projects.
- Most Wii U games of interest also came out on PC or the 360.

### 7. N64: M

N64Recomp (MIT, active, a "Mod Tool" release) and N64ModernRuntime, N64LoaderWV (Ghidra 12.1.3),
ido-static-recomp v1.2, ares (GDB server in `nall/gdb`), and splat already installed. This is the best
tooled platform overall, but the owner's catalog has little here.

### 8. Old Android and iOS: S

The suite and REA already cover APK and IPA analysis (jadx, apktool, adb, Frida, ipsw, REA's Android
and Apple graph tools). What is missing is a route page for porting an old mobile game to PC: native
`.so` and Mach-O game code, the Android layer, as Jetpack Joyride and Plague Inc. on Switch and Vita did,
and the iOS decompilations in the tracker.

### 9. Dreamcast: M

Ghidra has SuperH4 built in. flycast v2.7 has a GDB server (`core/debug/gdb_server.h`). Static
recompilation is a single project (a Street Fighter Alpha 3 recompilation, from search results only).
WinCE-based games (the Dreamcast's Windows CE option) would fit the PE tools. No Dreamcast Ghidra loader
was found (the guessed repository names answered 404).

### 10. 3DS: M-L

Azahar (2127.0 RC3, 2026-11-12) has a GDB stub (`src/core/gdbstub/gdbstub.cpp`). TriAevum (Ocarina of
Time 3D) shows recompilation. Encrypted CIA and CCI files need the user's key file at a path. A Ghidra
loader for 3DS was not checked.

### 11. Switch: L

Adubbz/Ghidra-Switch-Loader (built for Ghidra 12.1.2, 2026-11-02). There are 40 tracker projects, many
"game-specific runtimes" (nxnative) and young static recompilers (nx, kirikae, Suyu's mode;
bgyss/SwitchRecomp is a spec only). It needs the user's `prod.keys` at a path. Ryujinx's fork moved off
GitHub (git.ryujinx.app); its debugger was not checked. Most interesting Switch games have PC versions.

### 12. PS Vita: M

VitaLoaderRedux 1.09 (2026-09-03) and Vita3K (CI builds daily) with a GDB stub
(`vita3k/gdbstub/src/gdb.cpp`). ARMv7 code fits Ghidra. Low relevance.

### 13. GBA and SNES: S-M

- GBA: mGBA 0.10.5 has a GDB stub (`src/debugger/gdb-stub.c`); GhidraGBA was last updated in 2021.
- SNES: Mesen2 2.1.1 (the best SNES and GBA debugger, with Lua), ares, snesrecomp (RetroPortingToolKit;
  Super Mario World, Super Metroid, A Link to the Past, Mega Man X); ghidra-65816 was last released in
  2019.
- Rogue Spear had a GBA version; the PC original makes it moot.

### 14. Flash and Shockwave: S

JPEXS FFDec 26.4.0 (2026-10-19; SWF decompiler and AS1-3 editor), Ruffle (nightly; the oracle and a
runtime), ProjectorRays v0.2.0 (Director decompiler; last commit 2025-11-13) and dirplayer-rs v0.8.1
(a Shockwave player). This is a route of tools rather than recompilation: the "port" is often Ruffle
embedded in a native shell.

### 15. Java ME: S

jadx (in the suite) decompiles MIDlet classes. freej2me (last commit 2026-10-04) and J2ME-Loader (CI
builds) run them. Low relevance.

### 16. Classic Mac (68k and PPC): M-L

Ghidra has a PEF loader and the 68000 and PowerPC processors. resource_dasm (fuzziqersoftware, v2026-09-03)
decodes resource forks: CODE resources, PICT, snd and the rest. For the oracle: Basilisk II and
SheepShaver (kanjitalk755/macemu, active) have no GDB stub; QEMU's q800 machine does. CODE-segment
jump tables and A-line traps are new work. Relevant only if a Mac-only original matters.

### 17. Saturn: L

Two SH-2 CPUs, an SH-2 and 68000 sound pair, and VDP1 and VDP2. Yabause has had no commit since 2018;
Kronos 2.7.0 is alive; MAME and ares cover it with their debuggers. Ghidra has the SH-2 processor. No
recompilation exists.

## Part 3: what every route needs, and which have it

| Need | DOS | PS1 | PS2 | Xbox | Xbox 360 | PC Win32 |
|---|---|---|---|---|---|---|
| A route page in the shared shape | yes | yes | yes | yes | **no** (README only) | **no** (three places) |
| "Identify the binary" command | `le info` | `project.json` | `project.json` | `xbox info` | **no** `xbox360 info` | `pe info` |
| Census of the edge the port answers | `le services --json` | **no** (PsyQ calls by signature only) | **no** (syscalls, SIF RPC) | `kernel.tsv` and `xdk-symbols.tsv` (TSV) | **no** documented (kernel and XAM imports) | `pe imports` |
| Oracle runner with sync points | `dosbox run --regions`, `compare`, OPL | **no** (GDB, Lua by hand) | **no** (PINE by hand) | **no** (TODO: kernel-call log) | **no** | **no** (Wine `+relay`, Frida, `run`) |
| More than one image in one project (overlays, IRX, further XBEs and XEXs) | n/a | **no** | **no** | **no** | partial (`--program`) | yes (DLLs) |
| Test fixture of the platform | Theme Park (real game) | synthetic | synthetic | nxdk homebrew, synthetic | CoD3 (opt-in) | real ports |
| REA opens the format | **no** (LE) | **no** | **no** | **no** | **no** | yes |

Proposals, each one owner per capability:

1. **One identify step**: `rea-suite identify <file>` dispatching by magic (MZ, LE, NE, PE, XBE `XBEH`,
   XEX `XEX2`, PS-X EXE, R5900 ELF, IRX, later DOL, PSP ELF and NSO). It writes one JSON with the
   same keys everywhere: hashes, kind, base, entry, sections, imports or edge, and the SDK or compiler
   version found. The existing `le info`, `xbox info`, `pe info` and `playstation` stay the per-format
   back ends. That also gives the 360 its missing `info`.
2. **One oracle format**: DOS's regions file and the sequence JSONL, with `compare`, as the format for
   every platform. Each emulator gets a back end, and most share one: a generic GDB RSP back end covers
   xemu, PCSX-Redux, DuckStation, Dolphin, Cemu, melonDS, flycast, Azahar, mGBA, ares and Vita3K. Only
   PCSX2 (PINE), PPSSPP (WebSocket) and DOSBox-X (its debugger, done) need their own. The Xbox route's
   "kernel-call log" TODO is then this back end plus thunk breakpoints.
3. **One census schema**: edge kind (interrupt, ordinal, syscall, import, SDK function), id, name,
   static call sites, first seen in a run. Today there are three formats: DOS JSON, Xbox TSV, PE TSV.
4. **Firmware and keys, practically**: a suite convention for where a route's user-supplied files live
   (one folder per platform in `work/`), each route naming the file and what checks it (the MCPX ROM's
   MD5 is already on the Xbox page), `doctor` reporting a missing one, and a lint check that no such file
   is tracked by git. No legal text (the owner's decision).
5. **Multi-image import**: one `--image FILE@BASE` option shared by `playstation`, `xbox` and `xbox360`,
   for overlays, IRX and ERX modules and further executables. PS1.md, PS2.md and TODO.md each ask for
   their own version of it.
6. **Fixtures per platform**: a small homebrew sample per platform (PSn00bSDK for PS1, ps2sdk for PS2,
   nxdk for Xbox, a libxenon-built XEX for the 360) with expected outputs, run by the tests without the
   owner's games. Opt-in real-game variables as `REA_XBOX360_SAMPLE` does.
7. **REA format refusals in one upstream request**: LE, XBE, PS-X EXE, R5900 and XEX are all loaded by
   Ghidra extensions the suite installs, and all refused by REA's own format check. One issue asking
   REA to hand a format to the Ghidra provider when the matching loader is installed. Recheck with 6.9.0
   first.
8. **Machine-checkable sources**: this check found three moved repositories by hand (psxrecomp,
   RecompOne, pyxbe) and one wrong "no longer exists" claim. A list of each page's sources (URL and the
   version claimed) that `update --ai` or lint checks for redirects, 404s and newer releases would catch
   these between manual checks.
9. **A media decoder**: vgmstream (new tool 3) for audio on every console route. ffmpeg covers most
   video.

## Sources (all read 2026-11-13)

- GitHub `releases.atom`, `commits.atom` and `/releases/latest` redirects for each repository named
  above; release asset lists from `/releases/expanded_assets/<tag>`.
- DuckStation: `raw.githubusercontent.com/stenzek/duckstation/HEAD/src/core/gdb_server.cpp`, `src/core/settings.cpp`, `LICENSE`.
- PCSX2: the tree listing of `pcsx2/` at master (`PINE.cpp`, `DisVU0Micro.cpp`; no gdb file).
- GDB stubs at HEAD: Dolphin `Source/Core/Core/PowerPC/GDBStub.cpp`, Cemu
  `src/Cafe/HW/Espresso/Debugger/GDBStub.cpp`, melonDS `src/debug/GdbStub.cpp`, Azahar
  `src/core/gdbstub/gdbstub.cpp`, mGBA `src/debugger/gdb-stub.c`, flycast `core/debug/gdb_server.h`, ares
  `nall/nall/gdb/server.cpp`, Vita3K `vita3k/gdbstub/src/gdb.cpp`; PPSSPP `Core/Debugger/WebSocket.cpp`.
- psxrecomp README and LICENSE at RetroPortingToolKit/psxrecomp; RetroPortingToolKit's repository list
  (github.com/orgs/RetroPortingToolKit/repositories).
- TGP482/XboxXBERecomp README and LICENSE.
- REA: `registry.npmjs.org/rea-agents` (6.9.0, 2026-11-12); the 6.9.0 package's
  `dist/ghidra/GhidraReleasePolicy.js` and `GhidraPspExtension.js`.
- Ghidra 12.2: `Ghidra/Configurations/Public_Release/src/global/docs/WhatsNew.md` at tag Ghidra_12.2_build.
- Recompiled games list: `raw.githubusercontent.com/wangxiaoxiang5599/recompiled-games-list/HEAD/README.md`
  (378 projects, checked by its maintainer 2026-11-12).
- DolRecomp: [gbatemp](https://gbatemp.net/posts/10875919/) and
  [steamdeckhq](https://steamdeckhq.com/news/we-may-see-more-gamecube-wii-pc-ports-soon/) (secondary;
  repository ExpansionPak/DolRecomp, LICENSE GPL-3.0 read).
- Switch recompilers: [heldgames](https://heldgames.com/guides/switchrecomp-static-recompiler),
  [korben.info](https://korben.info/en/suyu-bows-out-recompilation-mode-switch-games.html) (secondary,
  unverified).
- Wine 16-bit in WoW64: [Wine bug 58760](https://list.winehq.org/hyperkitty/list/wine-bugs@list.winehq.org/thread/LEB5T37DQX6ESGOVEDABHF2OLXNWGDY5/)
  and a [Wine 10.16 report](https://en.linuxadictos.com/Wine-10-16-arrives-with-support-for-16-bit-apps-in-the-new-wow64-mode-and-nearly-400-changes..html)
  (secondary).
- QuickBMS: mirror.aluigi.org/quickbms.htm (0.12.0 is still the newest named).

Not verified: the GDB stubs' behavior (only that their sources exist), Ghidra loaders for Wii U, 3DS and
the Dreamcast, Ryujinx's fork's debugger, Xenia Canary's debugger, the licenses of the CoD3 ports in the
tracker, and anything about running a tool.
