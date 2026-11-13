# Recompilation, decompilation and reimplementation: the route

What the community has already built for turning an old game into a native program, and what to take
from it. Static recompilers, decompilation toolchains, engine reimplementations and dynamic translators,
each with the patterns worth borrowing (never code we cannot license), the traps their documents record,
and links. Everything was read in the projects' own repositories and documents on 2026-11-12; licenses
are from their LICENSE or COPYING files. Nothing about one of our ports belongs on this page: a port's
findings go to its own repository.

What lies around this page:

- The routes from an original to what a recompilation needs: [DOS-GAMES.md](DOS-GAMES.md),
  [XBOX-CLASSIC.md](XBOX-CLASSIC.md), [PS1.md](PS1.md), [PS2.md](PS2.md), [XBOX360.md](XBOX360.md).
- The suite's port tools: [PORT-TOOLS.md](PORT-TOOLS.md).
- The runtime our x86 ports are recompiled onto: winrt (games/winrt), and its research on x87 in other
  translators (`docs/2026-11-05-x87-translation-research.md`) and on what other runtimes have
  (`docs/2026-11-04-gap-research.md`).

## Which approach for which platform

| Original | Start from | The edge the port answers | Oracle to compare with |
|---|---|---|---|
| DOS, 32-bit LE (Watcom, DOS/4GW) | winrt's core; [pcrecomp](https://github.com/sp00nznet/pcrecomp)'s `dos32` as the public model | INT 21h, DPMI, BIOS, VGA/VESA ports, the PIT; the sound library at its API (HMI SOS, MSS) | DOSBox-X (`rea-suite dosbox`) |
| DOS, 16-bit MZ | pcrecomp's `recomp16`; OpenDUNE as the model of converting to C | the same, plus segments everywhere | DOSBox-X |
| Windows 9x, 32-bit PE (MSVC 4-7) | winrt; pcrecomp `lift32`; Fallout-NV-MacOS for the P-code lifter | Win32 and DirectX at the import table; MFC and the CRT either recompiled or kept | Windows or Wine; Unicorn per function |
| Original Xbox (x86 XBE) | [xboxrecomp](https://github.com/sp00nznet/xboxrecomp) | kernel ordinals; the XDK's Direct3D 8, DirectSound and XAPI at their entry points, or the NV2A push buffer | xemu |
| Xbox 360 (PowerPC XEX) | [rexglue-sdk](https://github.com/rexglue/rexglue-sdk) (our fork: games/rexglue-sdk); [XenonRecomp](https://github.com/hedge-dev/XenonRecomp) as the reference design | kernel and XAM in HLE; the GPU either emulated (Xenos, rexglue) or replaced at the game's Direct3D (Unleashed) | Xenia Canary (Xenia's master branch has had no commit since 2026-02) |
| N64 (MIPS) | [N64Recomp](https://github.com/N64Recomp/N64Recomp) and N64ModernRuntime | libultra (threads, messages, VI, audio), RSP microcode recompiled, a renderer (RT64) | a decompilation's ELF, an emulator |
| PS1 (R3000A) | [psxrecomp](https://github.com/RetroPortingToolKit/psxrecomp) (noncommercial license), [RecompOne](https://github.com/BlackLabelHQ/RecompOne) (MIT, C#) | the BIOS (recompiled, with an HLE tier), GPU, SPU, CD-ROM; or the PsyQ libraries | PCSX-Redux, Beetle |
| PS2 (R5900 EE, IOP, VUs) | [PS2Recomp](https://github.com/ran-j/PS2Recomp) | EE syscalls and SDK functions bound by name or address; IOP modules run; VU1 interpreted | PCSX2 |
| Any, with the source wanted | a matching decompilation (splat, objdiff, decomp.me), then a port of it | the SDK (libultra, PsyQ, the XDK) or the graphics library | the original, function by function |
| An engine with a documented data format | a reimplementation (OpenTTD, OpenMW, CorsixTH) | the original's data files only | the original, by eye and by save files |

How to choose:

- **Static recompilation** when the binary is all there is and the goal is the whole game as it was.
  It needs no understanding of most of the code. It cannot read code that does not exist at build
  time (streamed overlays, generated code): those need an interpreter or a capture-and-compile tier.
- **Matching decompilation** when the source itself is the goal (a port to many platforms, deep mods).
  It takes years and needs the original compiler. It is the norm for consoles with GCC or IDO builds
  and rare for MSVC games.
- **Incremental replacement** (hooks into the original executable, one function at a time) when a
  reimplementation is the goal but the game must stay playable throughout.
- **Reimplementation** of the engine when the data formats are the contract and the code is not wanted.
- **Dynamic translation** (box64, FEX, Rosetta 2) when nothing about the program may be known
  ahead of time. It is the contrast: everything it solves at run time, a recompiler solves once.

## The hard parts, and who solved them how

| Hard part | How the projects solve it |
|---|---|
| Finding every function | Seeds from symbols (a decompilation's ELF for N64Recomp, `.pdata` on the 360, a Ghidra export for PS2Recomp), then recursive descent and a gap-fill pass (rexglue's `phase_gapfill`). pcrecomp scores its catalog against a linker map or PDB before lifting. Microsoft's Xbox recompiler avoids the question: an entry for almost every guest byte. |
| Indirect calls | A table from guest address to host function, consulted at run time. Forms: a flat array indexed by address (Microsoft, XenonRecomp past the image), a sorted table with binary search (xboxrecomp), an overlay-aware lookup (N64Recomp's `LOOKUP_FUNC`). A miss must stop loudly, not return zero. |
| Jump tables | Pattern-matched per compiler: `lui`/`addiu`/`jr` on MIPS (N64Recomp), `mtctr`/`bctr` on PowerPC (XenonAnalyse), bounded by the next table and the function's extent. They become `switch` statements. Unknown shapes are listed in the config by hand. |
| Code that is not in the file | PS1 overlays: capture the bytes when the game loads them, recompile, cache by content hash, interpret until then (psxrecomp). N64 relocatable overlays: emit relocation macros the runtime resolves (N64Recomp). Self-modifying code: an interpreter tier (psxrecomp, Microsoft's `Fb` tier); dynamic translators use page protection (FEX `mtrack`, box64). |
| x87 | `double` with 53-bit precision control, which matches what the MSVC CRT sets (Fallout-NV-MacOS, xboxrecomp); transcendentals differ from the hardware in the last bits and are compared with a named tolerance. Pop-count bugs, not arithmetic, are the usual defect (xboxrecomp). winrt's research covers keeping the stack in registers. |
| SIMD | VMX128: x86 intrinsics, SIMD Everywhere for ARM64; vectors held byte-reversed; denormals flushed per instruction kind (XenonRecomp). MMI and VU0 macro mode: SSE/AVX (PS2Recomp). VU1 microcode: interpreted at run time (PS2Recomp). RSP microcode: recompiled like the main CPU (N64Recomp's RSPRecomp). |
| The OS layer | At the kernel or SDK edge, never the hardware where avoidable: Xbox kernel ordinals routed to host functions (xboxrecomp), Xbox 360 kernel and XAM in C++ (Unleashed, rexglue from Xenia), libultra reimplemented (ultramodern), PS2 SDK functions bound by name (PS2Recomp). psxrecomp is the exception: it recompiles the BIOS itself and lays an optional HLE tier over it. |
| Graphics | Two edges. The graphics library at its entry points (Unleashed hooks the game's statically linked Direct3D functions; xboxrecomp answers Direct3D 8 on Direct3D 11 or OpenGL) or the GPU's command stream (rexglue keeps Xenia's Xenos emulation; RT64 consumes N64 display lists; xboxrecomp has an NV2A push-buffer executor for titles whose Direct3D is compiled in). |
| Timing and frame rate | Interpolate in the renderer and leave the game's tick alone (RT64 for Zelda64Recomp; psxrecomp's presenter between guest VBlanks). Raising a game's own frame rate breaks gameplay that counts frames (Unleashed's documented glitches). DOS games often have no limiter at all: pace at a call every loop makes (pcrecomp `dos32`). |
| Threads and waits | Guest threads on host threads, kernel waits on host primitives (`std::atomic::wait` in Unleashed). Guest busy-wait loops burn a core; interrupt and preemption points at loop back-edges (Microsoft, pcrecomp `dos32`, winrt). |
| Saves and paths | The player's own copy, verified by hash before anything runs (Unleashed's installer, psxrecomp's disc identity, max-payne-recomp). Saves and settings in the platform's user folder, a `portable.txt` beside the program to keep them there (Zelda64Recomp). Case-blind path matching on Linux (pcrecomp `dos32`). |
| Patches and hooks | Replace a whole function by linking a new one first (N64Recomp's single-file mode; XenonRecomp's weak `PPC_FUNC`). Insert a call at one instruction with chosen registers and a return or jump (XenonRecomp's `[[midasm_hook]]`, also in rexglue). Per-build overrides keyed by the executable's hash (PS2Recomp's game overrides). |
| Proving the translation | Run the original bytes and the lifted code from the same random state and compare every register, flag and byte (Fallout-NV-MacOS and pcrecomp with Unicorn; xboxrecomp on the host CPU, assembled by MSVC so the bytes cannot drift). Recompile an emulator's CPU test ROMs (XenonRecomp runs Xenia's PPC tests). |

## Static recompilers for consoles

Each one is a translator plus a runtime. The translator is small; the runtime is where the years go.

### N64Recomp (N64)

[N64Recomp](https://github.com/N64Recomp/N64Recomp) (MIT), [N64ModernRuntime](https://github.com/N64Recomp/N64ModernRuntime)
(GPL-3.0), [Zelda64Recomp](https://github.com/Zelda64Recomp/Zelda64Recomp) (GPL-3.0), [RT64](https://github.com/rt64/rt64) (MIT).
The model the others copied.

- **Literal translation.** One C function per guest function, one statement per instruction, the
  CPU state passed as an argument. No attempt at readable code. Delay slots are handled by
  duplicating instructions. `jal` becomes a C call; a `j` it can prove is a tail call does too.
- **Metadata from an ELF**: the symbols come from a decompilation or disassembly project's ELF, so
  splat's work feeds the recompiler directly.
- **Jump tables**: tracked from the `lui`/`addiu` that builds the address, sized by the next table and
  by the function's extent. A table it cannot size stops the run with the address.
- **Overlays**: `jalr` becomes `LOOKUP_FUNC(addr)`, which the runtime answers from the sections loaded
  now. Relocatable overlays get `RELOC_HI16`/`RELOC_LO16` macros the runtime resolves at load.
- **Patches**: "single file output" compiles patched functions into one file that the linker sees
  before the original output, so a patched function wins without regenerating everything.
- **The runtime splits in two**: `ultramodern` reimplements libultra (threads, message queues, timers,
  VI timing, audio) on host primitives; `librecomp` bridges generated code to it and handles overlays,
  ROM reads and EEPROM/SRAM/flash saves.
- **Frame rate without touching the game**: RT64 matches display lists across frames and draws
  in-between frames; the game's tick stays at its original rate ("changing framerate has no effect on
  gameplay").
- **Mods** are recompiled functions loaded at run time, with hooks and events (`librecomp/src/mod_*`).
- Saves go to `%LOCALAPPDATA%`, `~/.config` or `~/Library/Application Support`; `portable.txt` beside the
  executable keeps them there.

### XenonRecomp and Unleashed Recompiled (Xbox 360)

[XenonRecomp](https://github.com/hedge-dev/XenonRecomp) (MIT), [XenosRecomp](https://github.com/hedge-dev/XenosRecomp)
(MIT, shaders to HLSL), [Unleashed Recompiled](https://github.com/hedge-dev/UnleashedRecomp) (GPL-3.0). The
best-written document on a console recompiler; read its README whole. Read it as the reference design, not
the maintained tool: XenonRecomp's last commit was 2025-08-04 and Unleashed's last release v1.0.3
(2025-04-05). The live line is rexglue-sdk below, which the recompiled-games list counts under most new
Xbox 360 ports (checked 2026-11-13).

- **Endianness**: values are little-endian in registers; loads and stores swap. Loads and stores are
  `volatile` so clang cannot reorder them. Vector registers are reversed as a whole 16 bytes, so lane
  order flips (dot products use WZY, pack instructions take reversed arguments).
- **Denormals**: the FPU keeps them, VMX flushes them; the flush mode is set per instruction kind
  from state in the CPU struct.
- **Indirect calls**: function pointers live in a table placed after the image in the guest address
  space, indexed by guest address. An earlier 8 GB reservation cost too much memory.
- **Jump tables**: XenonAnalyse finds the `mtctr r0`/`bctr` shapes of one compiler build; other games
  need new patterns. Its function analyzer treats a jump table as a tail call; boundaries can be given
  by hand.
- **Function boundaries** come from `.pdata` for every function with a stack frame, the rest from
  `bl` targets.
- **The register save and restore helpers** (`__savegprlr_14` and the rest) must be located and named
  in the config; the README gives their byte patterns.
- **`setjmp`/`longjmp`** go to native ones. **Exceptions are not supported.**
- **Optimizations**: CTR, XER, CR, non-volatile and non-argument registers as C locals. In Unleashed
  this cut about 20 MB of code and several milliseconds per frame. Turn them on only after the game
  runs.
- **Hooks**: every function is weak and aliased to an `__imp__` body, so a project overrides it and
  can still call the original. `[[midasm_hook]]` inserts a call at one instruction, with the registers
  it needs and an optional return or jump. winrt's research named this the shape for instruction hooks.
- **Tests**: Xenia's PPC instruction tests are recompiled and run (XenonTests).
- **Unleashed's runtime answers Direct3D, not the GPU**: the game's statically linked Direct3D functions
  are replaced by address (`GUEST_FUNCTION_HOOK(sub_..., CreateDevice)`), drawn with a new D3D12/Vulkan
  renderer. Pipelines are compiled while assets load, not at first draw, so there is no shader stutter.
- **Unleashed's traps**: raising the frame rate exposed gameplay bugs that depend on the frame time;
  some appear only when the frame rate is too stable. Spikes of 10 ms from synchronous loading are
  invisible at 30 fps and obvious at 120. Original bugs are kept on purpose; a report needs footage
  from real hardware.
- The installer checks every file's hash and refuses modified ones; mods load from a separate folder.

### rexglue-sdk (Xbox 360)

[rexglue-sdk](https://github.com/rexglue/rexglue-sdk) (BSD-3-Clause, with Xenia's BSD code); our ports use
the fork games/rexglue-sdk. Read at v0.10.0; the newest release is v0.10.1 (2026-11-06), with nightlies
0.11.0-dev up to 2026-11-11 (checked 2026-11-13). The fork's pin is the port's business.

- XenonRecomp's translation ideas inside Xenia's runtime: the kernel, XAM and XBDM in C++, and Xenia's
  GPU emulation (the Xenos command processor, D3D12 and Vulkan back ends) kept. The game's own Direct3D
  runs as recompiled code and drives the emulated GPU. That makes it general (no per-game renderer) and
  costs what an emulator's GPU costs.
- Codegen runs in phases (`src/codegen/phase_*.cpp`): discover, scan, gap-fill, merge, register,
  validate, with a vtable scanner and a signature scanner. Gap-fill registers code no other phase
  reached and recognizes SEH scope tables by the `__C_specific_handler` pointer.
- Hooks: `REX_HOOK(sub, function)` marshals registers to a plain C++ function; `[[midasm_hook]]` as in
  XenonRecomp.
- Settings are cvars, also on the command line.

### xboxrecomp (original Xbox)

[xboxrecomp](https://github.com/sp00nznet/xboxrecomp) (MIT; its APU and NV2A parts come from xemu,
LGPL-2.1+). The route in [XBOX-CLASSIC.md](XBOX-CLASSIC.md) already links it. Its `docs/technical/` is the
best x86 recompilation diary in public; the files worth reading first:

- `lessons-learned.md`: memory mirrors need real aliases (`CreateFileMapping` views, or `mmap` of one
  file twice), not copies; a bump allocator is enough for a console heap; one crash at a time; build
  memory-write tracing and indirect-call diagnostics on day one; classify every function (game, CRT,
  engine, SDK) early, so whole libraries are stubbed at once.
- `indirect-calls.md`: the three-tier lookup and why it is the hardest 10%. Objects whose constructors
  were stubbed carry garbage vtables, and every call through one is a crash or a wrong call.
- `ms-fusion-recompiler.md`: a study of Microsoft's own Xbox recompiler, as shipped in Xbox backward
  compatibility on Windows, from the retail binaries. Guest registers map 1:1 to host registers, guest
  memory is one addressing mode off a base register, and there is a translation entry for almost every
  guest byte, so function boundaries are never needed. A precise per-instruction fallback tier (`Fb`)
  backs the fast tier (`Pri`). Interrupt and preemption polls sit at loop back-edges. Indirect targets
  seen at run time are logged and fed into the next build ("enlightenments"). The HLE line is the
  kernel only; the game's Direct3D is recompiled and the GPU emulated at register level.
- `conformance-testing.md`: the lifter checked by executing both sides. MSVC assembles the test
  sequence, so the bytes cannot drift; inputs sit on width boundaries (`0x7F`, `0x80`, `0xFF`,
  `0x8000`, `0x80000000`); x87 compares stack depth too; SSE compares all 16 bytes of every register.
  Every bug it found had passed a test that compared emitted text.
- `seh-handling.md`, `register-model.md`, `d3d-translation.md`, `kernel-replacement.md`,
  `pushbuffer-executor.md`, `rtti-recovery.md`.

Traps it records:

- Push the real guest return address, not a dummy: `__SEH_prolog`, `_alloca` probes and any code that
  reads `[esp]` depend on it.
- A failed indirect call must pop what the call pushed, or the stack leaks 4 bytes per failure.
- Do not catch division by zero in a vectored handler: the game's own `__except` relies on it.
- Direct3D's fixed-function states are many; implement the combinations the game uses, as it uses them.

### psxrecomp (PS1)

[psxrecomp](https://github.com/RetroPortingToolKit/psxrecomp) (moved from mstan/psxrecomp), PolyForm
Noncommercial 1.0.0: read for ideas, take no code into a port that might be sold. It ships alpha releases
now (v0.3.7-alpha, 2026-11-07: a Windows x86_64 CLI, a source zip, SHA256SUMS) and nightlies. A dozen games in its README, each its own repository with the
framework as a submodule.

- **Three tiers**: the executable and the BIOS recompiled ahead of time; overlays captured when the
  game loads them, recompiled with the same recompiler (by TinyCC in shipped builds), cached by content
  hash and selected by byte guards; a MIPS interpreter for everything not yet native. The interpreter
  is meant to be compiled away as captures accumulate.
- **The BIOS is recompiled (LLE) and is the oracle**; an HLE tier on top skips the boot and answers
  some calls, and is opt-out. Anything it lacks falls through to the recompiled BIOS.
- **`psxrecomp-analyze`** reports only what it proved from the file and prints the gap ("132 indirect
  transfers have no proven target set").
- **Frame rate** (`docs/FRAME_RATE.md`): the presenter runs above the guest's VBlank and blends frames;
  the guest's VBlank, timers and CD stay at their rate. Never speed up the guest's VBlank.
- **Disc identity** (`docs/ORIGINAL_DISC_POLICY.md`): a SHA-256 of the decoded data track and a
  fingerprint of the track layout, so a renamed CUE or a cooked ISO does not pass.
- `docs/` holds about a hundred design notes (widescreen, netplay, overlays, texture packs).

### RecompOne (PS1, to C#)

[RecompOne](https://github.com/BlackLabelHQ/RecompOne) (MIT; moved from flafmg/RecompOne, no releases). MIPS to C# against a `CpuContext` and a memory
interface, with a runtime that answers BIOS calls, MMIO, GPU commands and CD-ROM without Sony files.
Small and readable; the wiki has the port guide.

### PS2Recomp (PS2)

[PS2Recomp](https://github.com/ran-j/PS2Recomp) (GPL-3.0). See [PS2.md](PS2.md), step 7.

- **Ghidra first**: `ExportPS2Functions.java` exports the function map the recompiler reads; its
  own analyzer is the fallback.
- **Stubs by name or address**: `sceCdRead@0x00123456` binds a stripped function to a runtime
  handler; `ret0`, `ret1`, `reta0` are temporary answers to find out which calls matter.
- **Syscalls** dispatch by the encoded number, then by `$v1`.
- **The IOP runs the game's own IRX modules** in an R3000A interpreter on a virtual IOP kernel; generic
  HLE services answer only where no loaded module serves the RPC id. Unknown modules fail to load.
- **VU1 is interpreted** (`ps2xRuntime/src/lib/vu/`); MMI and VU0 macro instructions go to SSE/AVX.
- **Per-build overrides** register by ELF name and CRC32, apart from the global stubs.
- Its iteration loop: minimal config, fix hard stops first, temporary returns only to classify, promote
  them to real implementations, move per-game hacks into overrides, retest from a cold boot.
- `.recomp.json` at a project's root describes it to trackers.

### XboxXBERecomp (original Xbox)

[XboxXBERecomp](https://github.com/TGP482/XboxXBERecomp) (TGP482, MIT, no releases, last commit
2026-11-08). The second XBE recompiler beside xboxrecomp, proven on several retail games (see
[XBOX-CLASSIC.md](XBOX-CLASSIC.md), step 6). x86 to C++ ahead of time; the kernel and the XDK libraries
(Direct3D 8, DirectSound, XAPI, XNet) answered at their API on Windows; Direct3D 12 and XAudio2; Windows
x64 only.

- **XDK signatures per build** (`xbe_symbols`): lengths and hashes of the library functions with their
  addresses masked, never library code, kept per XDK build in `xdk/<build>/signatures.toml`. A miss is
  listed and becomes a trapping stub. This is the shape an XDK FunctionID set should have.
- **No game code in a release**: the recompiled code is built on the player's PC from the player's own
  XBE, with a bundled recompiler, Clang and LLD.

### Recompilers for platforms without a route here

Read as references when a route for their platform starts. Status and licenses checked 2026-11-13
(releases, last commits and LICENSE files at HEAD).

| Recompiler | Platform | License | Status |
|---|---|---|---|
| [DolRecomp](https://github.com/ExpansionPak/DolRecomp) | GameCube, Wii; Wii U RPX early | GPL-3.0 | no releases, last commit 2026-10-10. CPU only (DOL, REL, RPX to C or LLVM); the runtime is the host's (ModernGekko-Template). Eternal Darkness, Sunshine and Wind Waker ports use it |
| [WiiCompiled](https://github.com/patchzyy/Wiicompiled) | Wii | GPL-3.0 | v0.9.4 (2026-11-10), Windows, Linux and macOS builds. The translation runs locally against the user's disc; Mario Kart Wii first, several Wii ports since |
| [psprecomp](https://github.com/sp00nznet/psprecomp) | PSP (Allegrex) | MIT | v0.5.0 (2026-10-23), early: no game renders on it yet (the tracker) |
| [snesrecomp](https://github.com/RetroPortingToolKit/snesrecomp) | SNES (65816) | PolyForm Noncommercial 1.0.0 | v0.3.0-alpha (2026-10-14), beta by its README; PPU and audio still emulated. Super Mario World, Super Metroid, A Link to the Past and Mega Man X ports |
| [ndsrecomp](https://github.com/RetroPortingToolKit/ndsrecomp) | Nintendo DS (ARM9, ARM7) | its own scope notice: PolyForm Noncommercial for most of it, MIT for the runner and oracle trees | v0.6.11 (2026-11-01), "very early pre-alpha" by its README. Metroid Prime Hunters port |

psxrecomp, snesrecomp and ndsrecomp are RetroPortingToolKit's (mstan's projects, joined into one group);
its shared runtime, netplay and launcher pieces are not covered here.

## Static recompilers for x86 PC and DOS

The same problems as xboxrecomp, without a console's fixed hardware and with the whole of Win32 or DOS
to answer.

### pcrecomp, and its DOS host

[pcrecomp](https://github.com/sp00nznet/pcrecomp) (MIT). Python tools and C runtimes for 16-bit DOS (MZ),
Win16 (NE), 32-bit DOS extenders (LE), Win32 and Win64 PE, from about thirty projects. Its documents
are the nearest public match to winrt's work.

- **`docs/DOS32.md`**: a DOS/4GW host for lifted LE programs, with Theme Park as the first title
  ([themepark-recomp](https://github.com/sp00nznet/themepark-recomp), MIT). The LE is re-wrapped as a PE so
  the Win32 disassembler and lifter run unchanged. In DOS mode the lifter turns `int n`, `in`/`out`,
  `cli`/`sti`/`hlt`, `iretd` and segment loads into host calls. A `ret` to an address the caller did
  not push is a dispatch (Watcom's `int386x` jumps into `int n; ret` stubs that way), and a call to a
  function that starts with `pop r32` is a jump that hands over its return address.
- IRQs are delivered only where lifted code calls the host: loop back-edges (every 256th), `int`,
  port reads, `sti`, `hlt`. A timer that falls behind drops ticks rather than delivering a storm.
- A virtual clock makes headless runs repeatable: guest time moves by the host's command, plus a
  sliver per read so a program spinning on the tick count still sees it move.
- Save states of the whole machine load only where they were saved, because lifted code runs on the
  host's stack; the load checks the hook, the host stack depth and the guest stack pointer.
- gcc needs `-foptimize-sibling-calls`: a guest `jmp` to another function is a C tail call, and
  without it the host stack grows for as long as the program runs.
- Its stated ceilings: `ds` assumed flat, no unchained VGA (mode X), no sound hardware (sound belongs
  at the program's sound library), no real-mode code.
- **`docs/HYBRID.md`**: keeping MFC or the CRT as real code beside lifted code. Two lifter bugs any
  x86 lifter should check for: an absolute displacement in a memory operand with a base register
  (`[ecx + 0x56d902]`) needs relocating too, and the `.reloc` table says which; an indirect call must
  read its target before pushing the return address (`call [esp+0x18]` reads the pre-push `esp`;
  12,703 such sites in one binary).
- **`docs/PHILOSOPHY.md`**, "A tool you have not scored": the disassembler missed 7,331 functions
  (tail-called methods no `call` named) on a dozen projects before anyone scored it against a linker
  map. Score function recovery against a map, a PDB or IDA before lifting.
- Diagnostics that paid off: the return address on the guest stack names the failing call site; a
  ring buffer of recent indirect targets, not a "last" variable; a heap check after each dispatched
  call while hunting corruption; log and answer the program's message boxes; log the registry and INI
  keys it reads.

### Fallout-NV-MacOS (Win32 to arm64)

[Fallout-NV-MacOS](https://github.com/thetheoryofR/Fallout-NV-MacOS) (MIT). 93,500 functions translated to
arm64, Direct3D 9 on Metal.

- **The lifter is Ghidra's P-code**: Sleigh already models each flag as a register, SSE lanes as
  sub-registers and the x87 stack by explicit shifts. What P-code leaves out (x87 TOP, NaN rules,
  80-bit precision) is listed in `docs/DESIGN.md` with how the runtime restores it.
- **Every function differential-tested** in Unicorn from identical random state (registers, flags, XMM,
  a pointer-rich heap, the writable sections); a trial where the original faults is invalid, not
  failed; one process per worker so a crash names its function. Sanity check: change one generated
  function and confirm the test fails.
- x87 as `double` matches the hardware because the MSVC CRT sets 53-bit precision.

### max-payne-recomp (Win32 to arm64)

[max-payne-recomp](https://github.com/aldotoa/max-payne-recomp) (MIT). Every module (the executable, the
engine DLLs, the Direct3D 8 driver, the MSVC runtime) translated; the emulator kept only as an offline
oracle (`docs/m6-emu-removal.md`). Its census documents (`docs/d3d8-usage.md`, `dshow-usage.md`,
`dsound-usage.md`) record each COM method the game calls, from an emulated run. What stopped its lifter
on the runtime DLLs: `fprem`, `fscale`, `frndint`, `fnsave`, `xlatb`, the delay-load stubs' `jmp eax`, and
the exception machinery (`_EH_prolog`, `__CxxFrameHandler`, `_except_handler3`).

### Others

- [rexdex/recompiler](https://github.com/rexdex/recompiler) (MIT): the first public Xbox 360 recompiler
  (2017), credited by rexglue.
- [ps3recomp](https://github.com/sp00nznet/ps3recomp) (MIT): PS3 runtime libraries; xboxrecomp's
  conformance method comes from it (check the decoder against the SDK's objdump, check the lifter by
  compiling a C corpus, running both sides and requiring bit-exact results).
- **Win32 peers of winrt** (checked 2026-11-13; game-specific, so maps rather than tools):
  [cricket07-browser](https://github.com/Dhaiwat10/cricket07-browser) (MIT, no releases): EA Sports
  Cricket 07, every x86 function to C, then WebAssembly, Direct3D 8 on WebGPU.
  [nfsu2-web](https://github.com/th0mk/nfsu2-web) (MIT, no releases): NFS Underground 2 to WebAssembly,
  Direct3D 9 on WebGPU, built on NFSU2Recomp.
  [NFSU2Recomp](https://github.com/TalhaMudo/NFSU2Recomp) (all rights reserved, v2.6-2026.11.08): x86
  to ARM64 for Apple silicon, Direct3D 9 on Metal.
  [nfsu2-recompiled](https://github.com/codepdbh/nfsu2-recompiled) (no license file, v0.14.14,
  2026-11-10): a pcrecomp fork, x86 to C for Android, DXVK on Vulkan.
  [Skyrim_Android](https://github.com/ttom795/Skyrim_Android) (no license file, 0.30.6, 2026-11-05):
  TESV.exe x86 to arm64, Direct3D 9 on Vulkan.
  [source-recomp](https://github.com/kanapitsas/source-recomp) (GPL-3.0, no releases; was
  portal2-recomp, which redirects): Portal 2's Linux x86 ELF to ARM64 for macOS and iOS.
- Trackers: [recompiled-games-list](https://github.com/wangxiaoxiang5599/recompiled-games-list) (CC BY 4.0,
  JSON and CSV, checked daily; 277 static recompilations on 2026-11-11), [recomp.fyi](https://recomp.fyi).

## Dynamic translators, as contrast

They solve at run time what a recompiler solves once, and their settings name the trade-offs.
winrt's `docs/2026-11-05-x87-translation-research.md` covers their x87 handling in depth.

| Project | License | Code that changes | Memory order | x87 |
|---|---|---|---|---|
| [box64](https://github.com/ptitSeb/box64) | MIT | blocks protected; `BOX64_DYNAREC_DIRTY` keeps running a dirty block (faster loads, may crash) | `BOX64_DYNAREC_STRONGMEM` off by default | `double`, `float` when possible; fast NaN and rounding by default |
| [FEX](https://github.com/FEX-Emu/FEX) | MIT | `SMCChecks`: `mtrack` (page tracking, default), `full` (validate before every run), `none` | TSO on by default ("highly likely to break any multithreaded application if disabled") | 80-bit; `X87ReducedPrecision` optional |
| Rosetta 2 | Apple | translates ahead of time at install, JIT for generated code | the M-series hardware TSO mode ([Dougall Johnson](https://dougallj.wordpress.com/2022/11/09/why-is-rosetta-2-fast/)) | 80-bit in software |

What carries over: per-game settings files (box64's rc files) instead of special cases in the
translator; and that the choice between exact and fast x87 is a setting, made per game.

## Decompilation: the toolchain and how projects are built

A matching decompilation rebuilds the original byte for byte from C, function by function. The suite
installs splat and objdiff (component `decomp`, [PLAYSTATION.md](PLAYSTATION.md)); the rest a project
carries as its own submodules.

| Tool | License | What it does, and what to take |
|---|---|---|
| [decomp.me](https://github.com/decompme/decomp.me) | MIT | One function at a time against the original compiler, shared as a link. Presets include MSVC 4.0 to 8.0 (6.0 to 6.6 among them), Watcom 10.0a to 11.0 for DOS, PsyQ, EE-GCC, Metrowerks for PS2, and MSVC for the Xbox 360; Windows compilers run through wibo. Types have to be pasted in as context. |
| [splat](https://github.com/ethteck/splat) | MIT | Splits N64, PS1, PS2 and PSP executables by a YAML of segments; `INCLUDE_ASM` lets C and assembly mix; `vram_classes` describe overlays that share addresses. Its rodata-to-text pairing is a heuristic: one text segment owns one rodata segment. |
| [objdiff](https://github.com/encounter/objdiff) | MIT or Apache-2.0 | Diffs relocatable objects per function and per data symbol, MIPS, PPC, ARM and x86 (COFF read). `objdiff.json`, generated by the build and git-ignored, lists units and progress categories. Needs the original split into objects first. |
| [asm-differ](https://github.com/simonlindholm/asm-differ) | Unlicense | Live assembly diff in a terminal; x86 only "to a limited extent". |
| [m2c](https://github.com/matt-kempster/m2c) | GPL-3.0 | Assembly to a C draft aimed at matching: MIPS (IDO, GCC, EE), PPC, ARM, SH; no x86. Jump tables become one `switch`. |
| [decomp-permuter](https://github.com/simonlindholm/decomp-permuter) | MIT | Rewrites a function at random until register allocation matches. MIPS, PPC, ARM32, C only. |
| [decomp-toolkit](https://github.com/encounter/decomp-toolkit) (dtk) | MIT or Apache-2.0 | GameCube and Wii: function boundaries, relocations rebuilt, objects split without an assembler. A project keeps `config.yml`, `splits.txt` and `symbols.txt` in git and regenerates the rest. `.ctors`, `extab` and `extabindex` must stay in their function's object. |
| [ido-static-recomp](https://github.com/decompals/ido-static-recomp) | no license file | The IRIX compiler, statically recompiled to C so N64 projects run it on Linux and macOS. Jump tables by exact instruction patterns, read from `.rodata`, emitted as `switch`; an unmatched `jr` stops it. libc answered by wrappers over guest memory, paths redirected. |
| [wibo](https://github.com/decompals/wibo) | MIT | A minimal Win32 loader for 32-bit command-line compilers on Linux and macOS. Unknown imports get valid pointers and stop only when called, so a shim is written only for a call actually seen; behavior is checked against Wine first. |
| [reccmp](https://github.com/isledecomp/reccmp) | AGPL-3.0 | Matching for MSVC x86 PE games. Source comments map code to the original (`// FUNCTION: LEGO1 0x100b12c0`, `STUB`, `SYNTHETIC`, `LIBRARY`, `VTABLE`, `GLOBAL`); the whole linked binary compared through its PDB; tools for vtables, data and stack layout; names pushed into Ghidra. Best with MSVC 4.20. |

How the projects are laid out:

- **Only human decisions in git**: splat YAMLs, dtk's `splits.txt` and `symbols.txt`, a checksum file
  per version. Everything derived is regenerated; hand-edited disassembly cannot be reproduced (dtk's
  `docs/other_approaches.md`).
- **One tree for every version**, by conditional compilation (oot, tp, melee, sotn-decomp).
- **Always a running game**: functions not yet matched link from their split assembly (sly1), or
  each rewritten function has a switch back to the original (re3, gta-reversed's `RH_Install` with
  `reversed=false`).
- **The original compiler, pinned**: IDO through ido-static-recomp (oot), PsyQ GCC with maspsx
  (sotn-decomp), ProDG under Wine or wibo (sly1), MSVC 4.2 under Wine or Docker with a byte-for-byte
  rebuild in CI (isle).
- **`NON_MATCHING` with `AVOID_UB`** fixes undefined behavior that worked on the console and breaks on a
  host (sm64, oot).

Examples: [sotn-decomp](https://github.com/Xeeynamo/sotn-decomp) (PS1 and PSP, AGPL-3.0, a PC build in the
same tree), [sly1](https://github.com/TheOnlyZac/sly1) (PS2), [oot](https://github.com/zeldaret/oot) and
[sm64](https://github.com/n64decomp/sm64) (N64), [tp](https://github.com/zeldaret/tp) and
[melee](https://github.com/doldecomp/melee) (GameCube), [isle](https://github.com/isledecomp/isle) (LEGO
Island, MSVC, LGPL-3.0), [devilution](https://github.com/diasurgical/devilution) (Diablo, MSVC; its own
license, read it before reuse).

Traps the projects record:

- **The Rich header names the exact compiler and linker** (devilution: VC6 SP5 with the Processor Pack,
  linked with the VC5 SP3 linker). Read it before choosing a compiler preset.
- **Leftover symbols elsewhere**: devilution used the Japanese PS1 port's `.SYM` file, a debug build
  hidden in the game's archive, and unoptimized beta builds; many PS2 games kept STABS
  ([PS2.md](PS2.md)).
- **Toolchain quirks**: EGCS crashes on array members past offset 0x8000; Windows line endings break
  IDO (oot).
- **JIT code in a game's DLL** that is not marked executable needs DEP off (devilution's Storm.dll).

### OpenGOAL (PS2): a decompiler and a port in one

[jak-project](https://github.com/open-goal/jak-project) (ISC). A decompiler for Naughty Dog's GOAL Lisp, a
new compiler for it, and a C++ runtime. The C kernel stays as close to the original as possible, with
every difference commented; Sony's libraries, the IOP driver (OVERLORD) and the sound library are
reimplemented. **Each VU1 microprogram is written again as a PC renderer** (Tie, Tfrag, Merc, Generic,
Sky, Shadow) instead of emulating the VU. That is the reference for any PS2 game whose drawing lives in
VU microcode.

## From a decompilation to a PC port

| Port | From | License | The layer it adds |
|---|---|---|---|
| [sm64ex](https://github.com/sm64pc/sm64ex) | sm64 | not stated | Fast3D display lists on OpenGL, D3D11, D3D12; saves in the user folder (`--savepath`), reads big- and little-endian saves so emulator saves import |
| [Ship of Harkinian](https://github.com/HarbourMasters/Shipwright) | oot | see its repository | [libultraship](https://github.com/Kenix3/libultraship) (MIT): libultra reimplemented, a Fast3D renderer (DX11, OpenGL, Metal), SDL3; assets extracted from the player's ROM into archives, ROMs accepted by hash, mods as override archives |
| [Dusklight](https://github.com/TwilitRealm/dusklight) | tp | CC0 | [Aurora](https://github.com/encounter/aurora) (MIT): GX on WebGPU (D3D12, Vulkan, Metal); every disc image type; memory card saves compatible with Dolphin's |
| [isle-portable](https://github.com/isledecomp/isle-portable) | isle | LGPL-3.0 | every Windows dependency replaced: SDL3 for windows, files, threads, input and DirectDraw; miniaudio for DirectSound; Direct3D through SDL GPU; an INI file for the registry |
| [devilutionX](https://github.com/diasurgical/devilutionX) | devilution | its own | SDL, its own MPQ reader, a headless mode, tests that replay recorded games |
| [psyz](https://github.com/Xeeynamo/psyz) | for PS1 decompilations | see its repository | the PsyQ libraries reimplemented natively, GPU and SPU emulated behind MMIO endpoints; "compatibility rather than accuracy" |

Every one of them answers the SDK at its API (libultra, GX, PsyQ, Win32 and DirectX), translates graphics
at the command list, swaps big-endian data at load, moves saves to the user folder, and keeps reading
the original's save format.

## Engine reimplementations and replacing code a piece at a time

Two families: projects that started from the original's code (relinked disassembly, an injected
DLL, converted output) and replaced it while the game kept running, and clean reimplementations that
read the original's data and nothing else.

### From the original's code

| Project | License | How it got from the binary to its code | What to take |
|---|---|---|---|
| [swars](https://github.com/swfans/swars) (Syndicate Wars, Watcom LE) | GPL-3.0 | [le_disasm](https://github.com/mefistotelis/le_disasm) turned the whole LE into one GNU assembler file, reassembled and linked natively for i386 with SDL and OpenAL; C replaces it a function at a time | Generated bridges between Watcom's register convention and cdecl, from one config line per function (`util/mkwrappers`, `conf/wrappers_*.conf`). Miles AIL reimplemented over OpenAL (`bfsoundlib`). [bfgameport](https://github.com/mefistotelis/bfgameport) is the same method as a template for other Bullfrog games. |
| [KeeperFX](https://github.com/dkfans/keeperfx) (Dungeon Keeper) | GPL-2.0 | the executable converted into a DLL in 2008; a new executable called what was not yet rewritten and shared its globals; the DLL left in 2022 | Use the original as a library while replacing it. Names first: its author moved from Syndicate Wars to Dungeon Keeper because the latter had debug information. |
| [remc2](https://github.com/turican0/remc2) (Magic Carpet 2, DOS) | GPL-3.0 | IDA's decompiler output fixed until it compiled; names keep the original addresses | **The oracle**: a DOSBox-X fork writes named memory regions at sync points, the port compares the same names in order and stops at the first difference (`remc2-regression-test/`, `engine/Compare.cpp`). Its wiki puts the work at 1% disassembly, 10% compiling, 15% system interfaces, 45% verification against DOSBox, 30% clean-up. |
| [OpenDUNE](https://github.com/OpenDUNE/OpenDUNE) (Dune II, 16-bit Borland C) | GPL-2.0 | its own decompiler of 16-bit code to C, run while the game ran, because overlays are only in memory then | Tables dumped as C files instead of fixing pointers at run time. 16-bit pointers to real pointers was the hard part. It worked because a compiler made the code; hand-written assembly (TTD) did not convert this way. |
| [OpenRCT2](https://github.com/OpenRCT2/OpenRCT2) (RollerCoaster Tycoon 2) | GPL-3.0 | in 2014 a DLL added to the original executable's import table, reading its memory and calling its procedures; all original code gone by the end of 2016 | Ship playable at every step. |
| [gta-reversed](https://github.com/gta-reversed/gta-reversed) (GTA San Andreas) | no license file | an injected DLL; each class installs its hooks by address, `.reversed = false` for those not done | **A switch per function** between original and replacement at run time (`reversiblehooks/`), so a fault is bisected one function at a time. **Fixes of original bugs are named switches**, off by default (`reversiblebugfixes/`). Needs one exact executable. |
| [devilution](https://github.com/diasurgical/devilution) and [devilutionX](https://github.com/diasurgical/devilutionX) (Diablo, MSVC) | Sustainable Use License | a matching decompilation, then an SDL port | Names from a PS1 symbol file and a debug executable hidden in the data archive. `comparer-config/*.toml` holds every function's address and size for a byte comparison. devilutionX replays recorded input as a regression test. |

Traps they record:

- **Watcom's C library keeps ECX and EDX callee-saved** (the swars write-up). A host function that
  stands in for a Watcom routine must preserve them as well as EBX, ESI, EDI and EBP.
- A jump table can look like a vtable (swars).
- A linear sweep over an LE gave a listing of over a million lines that would not reassemble;
  following control flow fixed it (swars).
- A stubbed or free-running timer makes a DOS game run flat out (swars, pcrecomp `dos32`).
- A crash can be the original's own bug, avoided by a switch in its batch file (swars: `/g`). Start
  the original the way its batch file did.
- Matching against Open Watcom's C library source named about 95% of the runtime in swars; the suite
  has no Watcom FunctionID ([DOS-GAMES.md](DOS-GAMES.md), step 3).
- A 64-bit build needs pointer-size clean-up in structures read from files (remc2, OpenDUNE).
- Code generated at run time needs executable pages (Diablo's Storm.dll).

Source documents: [The tale of the Syndicate Wars port](https://arhackde.spritesmind.net/files/dos/The%20tale%20of%20Syndicate%20Wars%20Port.html),
[remc2's wiki](https://github.com/turican0/remc2/wiki), [KeeperFX's history](https://keeperfx.net/history),
[OpenDUNE's project news](https://forums.cncnet.org/topic/925-opendune-project-news/),
[a DS port of Frontier's JJFFE](https://despairlabs.com/posts/2008-07-17-some-assembly-required) (JJFFE
itself: no repository or license found).

### Clean reimplementations over the original data

| Project | License | What to take |
|---|---|---|
| [CorsixTH](https://github.com/CorsixTH/CorsixTH) (Theme Hospital) | MIT | Reads the player's CD image directly (`Src/iso_fs.cpp`) and Bullfrog's RNC packer; the sprite and palette formats are Bullfrog's shared ones. |
| [OpenTTD](https://github.com/OpenTTD/OpenTTD) | GPL-2.0 | Began as a conversion of TTD's assembly to C (2003-04); still loads the original game's saves (`saveload/oldloader.cpp`). |
| [ioquake3](https://github.com/ioquake/ioq3) | GPL-2.0 | The install stays read-only and user data goes to a home path; a new network protocol runs beside the original one (`com_protocol`, `com_legacyprotocol`); frame caps, IPv6. The model for an id Tech 3 game. |
| [ScummVM](https://github.com/scummvm/scummvm) | GPL-3.0 | One platform layer under many engines; editions detected by the hashes of their data files. |
| [OpenMW](https://github.com/OpenMW/openmw) | GPL-3.0 | Its own save format, with an importer for the original's. |
| [OpenRA](https://github.com/OpenRA/OpenRA), [OpenXcom](https://github.com/OpenXcom/OpenXcom), [fheroes2](https://github.com/ihhub/fheroes2) | GPL-3.0, GPL-3.0, GPL-2.0 | Original data, rules as editable files, the original behavior kept as an option where it was changed. |

## What carries over to every port

- **Verify the player's copy first**: a hash of the executable or the disc's data, before anything runs.
- **An oracle from the first day**: the original in an emulator, compared function by function
  (Unicorn, the host CPU) and run by run (named memory at sync points). Score function recovery
  against a map or PDB before lifting.
- **Stop loudly on the unknown**: an unresolved indirect target, an unmatched jump table, an unknown
  service names its address and its caller. A silent zero costs days.
- **Answer the SDK, not the hardware**, where the SDK is linked in and recognizable; emulate the
  hardware only where the game bypasses its SDK.
- **Leave the game's tick alone**: pace where the original's hardware paced, and make the display
  smoother in the presenter, not in the simulation.
- **Keep only decisions in git** (configs, symbol lists, hook lists) and regenerate the rest; never
  commit generated code from a game.
- **A switch per function** between recompiled, interpreted and replaced code, and a named switch per
  fix of an original bug.

## Sources

Read on 2026-11-12, in the repositories at their default branch unless a version is named. Licenses as
in the tables above.

| Source | What was read |
|---|---|
| [N64Recomp](https://github.com/N64Recomp/N64Recomp), [N64ModernRuntime](https://github.com/N64Recomp/N64ModernRuntime), [Zelda64Recomp](https://github.com/Zelda64Recomp/Zelda64Recomp) | READMEs, `src/analysis.cpp`, `src/config.cpp`, the runtime's source layout |
| [XenonRecomp](https://github.com/hedge-dev/XenonRecomp), [UnleashedRecomp](https://github.com/hedge-dev/UnleashedRecomp) | READMEs; Unleashed's `kernel/imports.cpp`, `gpu/video.cpp`, `install/` |
| [rexglue-sdk](https://github.com/rexglue/rexglue-sdk) v0.10.0 (v0.10.1 is newest, 2026-11-13) | README, LICENSE, `src/codegen/`, `include/rex/hook.h` |
| [xboxrecomp](https://github.com/sp00nznet/xboxrecomp) v0.17.0 | README, `docs/technical/` |
| [psxrecomp](https://github.com/RetroPortingToolKit/psxrecomp) | README, `docs/EXECUTION_MODEL.md`, `FUNCTION_DISCOVERY.md`, `FRAME_RATE.md`, `ORIGINAL_DISC_POLICY.md` |
| [RecompOne](https://github.com/BlackLabelHQ/RecompOne), [PS2Recomp](https://github.com/ran-j/PS2Recomp) | READMEs; PS2Recomp's `ps2xIOP/README.md`, `ps2xRuntime/` |
| [pcrecomp](https://github.com/sp00nznet/pcrecomp), [themepark-recomp](https://github.com/sp00nznet/themepark-recomp) | READMEs, `docs/DOS32.md`, `HYBRID.md`, `PHILOSOPHY.md`, `PROJECTS.md`; themepark's `docs/pacing.md` |
| [Fallout-NV-MacOS](https://github.com/thetheoryofR/Fallout-NV-MacOS), [max-payne-recomp](https://github.com/aldotoa/max-payne-recomp) | READMEs, `docs/DESIGN.md`, `docs/m6-emu-removal.md` |
| [box64](https://github.com/ptitSeb/box64), [FEX](https://github.com/FEX-Emu/FEX) | `docs/USAGE.md`; `FEXCore/Source/Interface/Config/Config.json.in` |
| decompilation tools and projects | READMEs and docs of each repository linked in its table |
| reimplementations | READMEs, LICENSE files and the source documents linked under them |

Not verified: Ship of Harkinian's and sm64ex's licenses (no LICENSE file found at the expected path),
psyz's and sly1's licenses, re3 (its repository answers HTTP 451), and the internals of ScummVM, OpenMW
and OpenXcom beyond their licenses.
