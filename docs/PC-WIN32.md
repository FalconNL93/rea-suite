# 32-bit Windows games on winrt: the route

How to take a 32-bit Windows game (a PE32 for i386, about 1997-2010) from its installer to a native
port on winrt, the owner's runtime that runs the game's own executable on Linux, macOS and Windows
without Wine: an x86 interpreter and static recompiler, Win32 and DirectX answered in host code, SDL3
underneath. Each step says what its output decides and feeds next. Rogue Spear (games/rogue-spear,
R6BO) took this route first, then Yuri's Revenge (games/cnc); Lost: Via Domus is on it now. The traps
particular to Windows 95 and 98 games, and to 16-bit Windows, are on their own page:
[WIN9X-WIN16.md](WIN9X-WIN16.md).

This page is the route only. Detail has one owner elsewhere, and this page links to it:

- The port's process (the checklist, starting a session, research first, the SDK, releases, achievements,
  and every port's lessons): master-server's `docs/PORTING.md`, "The route" and "Lessons".
- The runtime, what it answers and how to embed it: winrt's `README.md` and `docs/` (Direct3D 8 in
  `d3d8.md`, MFC 4.2 in `mfc42.md`, PhysX 2.x in `physx.md`, a game's launcher dialog in `launchers.md`,
  render backends, content layers, and the dated research pages).
- The suite's tools: the README's [Porting old games](../README.md#porting-old-games) (Wine, rr, perf,
  Tracy), [FunctionID for Visual C++ 6.0](../README.md#functionid-for-visual-c-60),
  [Imports by ordinal](../README.md#imports-by-ordinal-mfc42-and-others),
  [SteamStub](../README.md#steamstub), and [PORT-TOOLS.md](PORT-TOOLS.md) (`rea-suite pe`, `frida`,
  `run`, `pad`).
- Other Win32 recompilations and what they solved: [RECOMPILATION.md](RECOMPILATION.md), "Static
  recompilers for x86 PC and DOS".

## 1. The installer, unpacked as data

```sh
mkdir -p ~/Games/<game>/installer ~/Games/<game>/extract
cd ~/Games/<game>/extract && innoextract -s -d . ../installer/setup_<game>.exe   # Inno Setup (GOG)
unshield x ../installer/data1.cab                                                  # InstallShield 5 and later
```

- Unpack without running the installer, into an empty folder of its own; treat the result as untrusted
  data. The README's "Tools by task" lists innoextract, unshield, cabextract and msitools.
- A retail disc's 16-bit `SETUP.EXE`: [WIN9X-WIN16.md](WIN9X-WIN16.md), "Installers".
- A Steam executable may be wrapped by SteamStub: check first, and unwrap only with the owner's permission
  (the README's "SteamStub").
- Record the installer's hash and each executable's and DLL's hash in the port's docs. The game's folder
  stays read-only for the port.

*Feeds:* the executable and the DLLs the game ships, for step 2.

## 2. Identify the executable

```sh
diec game/Game.exe                                   # compiler, linker, packer, protector
rea-suite pe info game/Game.exe --imports --exports  # base, relocations, entry, sections, imports, TLS
```

- The compiler decides the FunctionID set and the runtime: MSVC 6 for most games around 2000 (Rogue
  Spear), MSVC 8 for Lost: Via Domus (2008), whose C runtime comes from `MSVCR80.DLL`.
- A fixed base without relocations loads where it was linked, which winrt's loader expects.
- A packer or protector (SafeDisc, SecuROM, SteamStub) stops the route here until it is removed; see
  [WIN9X-WIN16.md](WIN9X-WIN16.md), "Copy protection".

*Feeds:* the size of the job, the FunctionID set for step 3.

## 3. Ghidra

```sh
rea-ghidra analyze --project <port>/re/ghidra --name <port> game/Game.exe
rea-ghidra functions --project <port>/re/ghidra Game.exe > functions.tsv
```

REA opens a PE itself, so its MCP tools work too (`open_binary`, `inspect_pe_imports`, `xrefs`,
`batch_decompile`); a large executable's first import is started deliberately under `heavy run`, as
master-server's PORTING.md says. Attach a Visual C++ 6.0 FunctionID set built from your own copy of the
libraries (the README's recipe) for an MSVC 6 game; Ghidra's own sets cover later compilers. Name what
the census finds in the port's own project, so it survives (`--project`).

*Feeds:* the function list (the recompiler's seeds), names, and the call sites the census counts.

## 4. The census: the whole import gap at once

List every import of the executable and of every DLL the game ships, and compare them with what winrt
registers, all at once rather than one refusal per run:

```sh
rea-suite pe imports game/Game.exe --used > work/imports.txt         # used IAT slots only
rea-suite pe imports game/Game.exe --dll d3d9.dll                    # every call site of one DLL
```

A port on winrt also has its own check against the runtime's registry (Lost's `lost-via-domus --check`).
Order the gap by when the game reaches it: the C runtime's start-up before `main`, the engine's start,
the window and the first frame, input and sound, movies, the first level, and what is never needed
(online services turned off). Lost: Via Domus is the worked example (its `docs/census.md`): 388 imports
from 22 DLLs, 261 not answered on 2026-11-12. Three censuses go beyond the import table:

- **The CPU.** A game built with `/arch:SSE` uses SSE without asking CPUID. Count the instructions by
  mnemonic (`objdump -d` over `.text`): Lost has about 110,000 of 1.08 million using XMM or MMX
  registers, 74 mnemonics, SSE1 and MMX only. That made SSE winrt's largest item for it, ahead of
  Direct3D 9. Rogue Spear, an MSVC 6 game, is x87 only.
- **COM interfaces.** One import (`Direct3DCreate9`) hides hundreds of methods. Count the calls by
  vtable offset through the object the game keeps (Lost: 804 calls on `IDirect3DDevice9` from 147
  functions, constant uploads second only to render states, `SetStreamSourceFreq` meaning instancing).
  The counts decide whether a fixed-function layer is enough; for Lost it was not.
- **Middleware.** PhysX 2.x is a handful of imports and a vtable surface behind them: Lost's physics
  module makes 111 virtual calls at 48 offsets, plus the character controller. The PhysX 2.6.4 headers
  give the layout (a reference copy in the work folder, never in git); winrt's `docs/physx.md` owns the
  layer.

Declare an import "never called" only with evidence: xrefs to its thunk, or a trace. A guest C runtime
and MFC bring hundreds of imports the game never calls.

*Feeds:* winrt's work list in the order the game needs it, and the decisions only the owner makes
(which runtime piece, which engine behind it).

## 5. The first stop, and the next

Run the game on winrt headless, with a trace switch for the calls it makes, on a runtime that stops at
each unknown import or method with its name and its caller. Fix the stops one at a time against a run
of the original (step 6). Theme Park on winrt's core reached its title screen through 13 such stops,
each a matter of minutes. An MSVC game also needs its C++ exceptions to work through guest frames
(`RaiseException`/`RtlUnwind`) and its faults handed to its own `__try` handlers: Rogue Spear has 13
`__try` frames and about 2,400 C++ ones (its `docs/00-overview.md`).

*Feeds:* the first frame, then the menu, then a level.

## 6. The oracle: the original under Wine, or on Windows

- **Wine on Linux** runs the original and logs every call into its DLLs (`WINEDEBUG=+relay,+seh`), file
  and registry access (`+file,+reg`) and which DLLs load (`+loaddll`): the README's "Tracing the
  original binary". Use a Wine prefix per game in `work/`. The suite's Wine runs 32-bit games through
  its new WoW64 mode, no i386 multiarch.
- **Windows** runs the real thing: Process Monitor, `rea-suite run` (a scripted, bounded run with
  captures), `rea-suite frida` (passive observers of import and COM calls), `rea-suite pad`
  (PORT-TOOLS.md).
- **The CPU's semantics** have their own oracle in winrt: instructions recorded on a real x86 CPU
  (`tools/x86_oracle/`), checked by its tests, x87 under six control words. A new instruction family
  (Lost's SSE) gets recorded cases before the interpreter and the recompiler implement it.
- **A fault in generated code**: winrt's per-function switch runs functions interpreted or recompiled
  and compares state that ignores timing (master-server's PORTING.md, "Lessons").

*Feeds:* what each stop should have answered.

## 7. Per-port lessons

Short pointers; each port's repository keeps the detail.

- **Rogue Spear** (MSVC 6, DirectDraw 4 and Direct3D 3, x87): the static recompiler made the main menu
  come up in 8 s instead of 18 and the game run at 40 fps instead of 12 on an M4 Pro (2026-10-19);
  writing out the hot x87 instructions took a level from 28 to 94 fps on Windows. Options through hooks
  on the game's own options wrapper, not an emulated registry key. Its traps from the Win9x era (CD
  music, timers, DirectDraw) are on [WIN9X-WIN16.md](WIN9X-WIN16.md). Its docs `03-recompiler.md` and
  `05-running.md`.
- **Lost: Via Domus** (MSVC 8, Direct3D 9 with shader model 3, PhysX 2.6.4, SSE): the census above.
  Owner's decisions: PhysX 2.x is winrt's layer for every game, on Jolt Physics behind winrt's own
  interface; the Xbox 360 release is only a reference for achievements and presence. Its docs
  `census.md` and `research/2026-11-12-route.md`; winrt's `docs/2026-11-12-d3d9-shaders.md`.
- **Alan Wake II and Alan Wake Remastered** are 64-bit and not on winrt: a verified copy of the original
  with the port's code linked in and the game's DLLs loaded from the player's folder. Their lesson for
  any Direct3D 12 game is the SDK's attach: the port hands `gm_d3d12_attach` the game's
  `CreateDXGIFactory1` (Alan Wake II) or `CreateDXGIFactory` (Remastered) import slot before the swap
  chain exists, and the SDK hooks the chain's present and resize (master-sdk's `sdk/docs/INTEGRATION.md`,
  "Attach"). The factory was made on the render thread before the first tick, so the attach had to come
  at start-up. Remove EOS by master-server's `docs/PORTING-EOS.md`.
- **Max Payne** (paused): SteamStub; a menu that reads keys only through a `WH_KEYBOARD` hook
  (master-server's PORTING.md, "Lessons").

## Outputs, kept where they belong

| Output | Where |
|---|---|
| installer, extracted tree, traces, runs, generated code | the port's work folder (never git) |
| hashes, the census, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project or REA session |
| runtime behavior (Win32, DirectX, CRT, PhysX) | winrt |
| engine facts | master-server's ENGINES-*.md |
| tool fixes and generic traps | this suite (this page, PORT-TOOLS.md) |

## Sources (read 2026-11-13)

- master-server `docs/PORTING.md` ("The route", "Starting a port", "Lessons").
- winrt `README.md`, `docs/physx.md`, `docs/2026-11-04-gap-research.md`.
- rogue-spear `docs/00-overview.md`, `03-recompiler.md`, `05-running.md`.
- lost-via-domus `docs/00-overview.md`, `census.md`, `research/2026-11-12-route.md`.
- alan-wakeii `docs/11-sdk-runtime.md`; alan-wake-rm `docs/00-overview.md`,
  `research/2026-11-11-runs.md`; master-sdk `sdk/docs/INTEGRATION.md`.
