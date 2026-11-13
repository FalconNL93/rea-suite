# PSP games: the route

How to take a PlayStation Portable game from your UMD image or EBOOT.PBP to what a port, a
decompilation or a static recompilation needs, with the suite's tools in the order they are used. Each
step says what its output decides and feeds next. No port has taken this route yet (2026-11-13). The
steps were checked on synthetic files, and ghidra-allegrex on a synthetic PRX, not on a retail game.
The first port adds its own traps.

Install: component `psp` (`rea-suite select`, then `rea-suite setup`). It brings PPSSPP v1.20.4, its source's HLE
tables (tool `ppsspp-source`, data only) for naming NIDs, and the ghidra-allegrex extension. Add component `decomp` for splat and objdiff in step 6.

What lies around this page: the PS1 and PS2 routes ([PS1.md](PS1.md), [PS2.md](PS2.md)), the
recompilers ([RECOMPILATION.md](RECOMPILATION.md)).

## The platform, in short

- **CPU: Allegrex**, a 32-bit little-endian MIPS core (MIPS II with some MIPS32 additions such as
  `ext`, `ins`, `seb`, `wsbh`, `min`, `max`), 1 to 333 MHz, with a single-precision FPU.
- **VFPU**: a vector unit with 128 single-precision registers, addressed as 8 matrices of 4x4, rows,
  columns or single values. Prefix instructions (`vpfxs`, `vpfxt`, `vpfxd`) swizzle, negate or clamp the
  operands of the next instruction.
- **Media Engine**: a second Allegrex-like core that runs Sony's codecs; games reach it through the
  firmware's libraries, not directly.
- **Graphics**: the GE, fed display lists, usually built through the SDK's `sceGu` library; 2 MB of VRAM.
- **Memory**: 32 MB (PSP-1000) or 64 MB. User code loads from `0x08800000`; games usually at
  `0x08804000`.
- **Firmware**: a real kernel. Games call it through **imports by NID**, filled in at load time.

## 1. The image, as data

```sh
mkdir -p ~/Games/<game>
sha1sum game.iso
rea-suite psp info game.iso -o ~/Games/<game>/umd.json     # PARAM.SFO, EBOOT.BIN, BOOT.BIN
rea-suite psp info game.cso                                # the same from a CSO
7z x -o"$HOME/Games/<game>/umd" game.iso                    # the tree, as data
```

- A UMD image is ISO 9660: `PSP_GAME/PARAM.SFO` (title, disc id, firmware version), `PSP_GAME/SYSDIR/
  EBOOT.BIN` (the game, encrypted), `BOOT.BIN` (sometimes a plain copy, on many discs all zeros),
  `USRDIR/` (the data, often with more PRX modules), `SYSDIR/UPDATE/` (a firmware update, not the game).
- CSO is a compressed ISO (CISO v1: deflated blocks with an index). `rea-suite psp` reads CSO v1; CSO v2
  and ZSO (LZ4) are not read here. PPSSPP plays ISO and CSO.
- Downloaded games and homebrew come as `EBOOT.PBP`: a container of PARAM.SFO, icons, sound and
  `DATA.PSP` (the module). `info` lists the sections. A PS1 classic's PBP has a disc image in `DATA.PSAR`
  instead (POPS); that is the PS1 route.
- Record the image's hash and the disc id (`ULUS10000`) in the port's docs.

*Feeds:* the module to decrypt in step 2 and the tree the port's file layer serves.

## 2. Decrypt your own copy

```sh
rea-suite psp info EBOOT.BIN        # "kind": "encrypted": name, version, sizes, decrypt mode, tag
```

Retail modules are encrypted (`~PSP` header). `rea-suite psp` shows the outer header only and says
so. Get a plain ELF or PRX from your own copy:

- **PPSSPP** decrypts every module when it loads it. Turn on dumping the decrypted files (in its developer
  settings; `DumpFileTypes` in `ppsspp.ini`, EBOOT and PRX) and boot the game once. The
  dumped `EBOOT.BIN` and PRXs are plain ELF files (read in `Core/HLE/sceKernelModule.cpp`, which calls
  `DumpFileIfEnabled` after decryption, and `Core/Config.cpp` at v1.20.4). Where it writes them is in
  PPSSPP's log; this has not been run here.
- On a real PSP, PRXdecrypter and similar homebrew do the same.
- Keys and decryption are your responsibility; no decrypted game file goes into git.

*Feeds:* a plain `EBOOT.BIN` (ELF or PRX) for steps 3 and 4.

## 3. What the module imports and exports

```sh
rea-suite psp info EBOOT.elf                          # module info, exports and imports by NID
rea-suite psp info EBOOT.elf --names names.txt        # NIDs named from candidate function names
rea-suite psp nid sceCtrlReadBufferPositive           # 0x1f803938
```

- An ELF has type 2 (`ET_EXEC`, older games, at a fixed address) or `0xFFA0` (a PRX, relocatable).
- **Module info** (`.rodata.sceModuleInfo`, or at the file offset in the first program header's
  `p_paddr` when sections are stripped) names the module and points at two tables: the **exports**
  (libent: the module's own `module_start`, `module_info`, and any library it offers) and the
  **imports** (libstub: one entry per firmware library, `sceCtrl`, `sceGe_user`, `IoFileMgrForUser`,
  each with a list of NIDs and an 8-byte stub per function that the loader fills in).
- **NIDs**: a NID is the first four bytes of the SHA-1 of the function's name, little endian
  (`module_start` is `0xD632ACDB`). `info` names imports from PPSSPP's HLE tables: tool `ppsspp-source`
  (component `psp`) is PPSSPP's source at the same tag as the emulator, read as data from
  `Core/HLE/*.cpp`, never built. At v1.20.4 that is 1,619 NIDs in 103 libraries, 1,714 of the 1,874 rows
  the SHA-1 of their name; the rest are randomized NIDs only a table can name. `--nid-source DIR` or
  `REA_PSP_NID_SOURCE` points at another tree. `--names` adds a file of candidate names, one per line,
  hashed and preferred over the table. The output's `nid_names` says which source named them.
- `unnamed_imports` in the output is the number of imported functions still without a name: the size of
  the firmware edge a port answers.

*Feeds:* the import list (the edge), the module's layout for step 4.

## 4. Ghidra, and REA

```sh
rea-ghidra analyze --project <port>/re/ghidra --name <port> ~/Games/<game>/EBOOT.elf
rea-ghidra decomp --project <port>/re/ghidra EBOOT.elf 0x08804000
```

- **ghidra-allegrex** (kotcrab, Apache-2.0) adds the Allegrex language with the VFPU, a "PSP Executable
  (ELF)" loader with PSP relocations (type A and B), the PSP calling convention, and scripts that import
  and export PPSSPP `.sym` files. Release v21.4 is the newest with a Ghidra 12.1.4 build; v21.5 and v21.6
  are for Ghidra 12.2 only. Checked 2026-11-13: the suite's Ghidra 12.1.4 with v21.4 imports a synthetic
  PRX and a synthetic static ELF with "Using Loader: PSP Executable (ELF)" and `Allegrex:LE:32:default`.
- Set the image base to `0x08804000` when importing a PRX (the loader's Options), so addresses match
  PPSSPP's.
- VFPU decompilation is basic: most vector operations become calls such as `vadd_q(...)`, and the prefix
  instructions are not modeled. Check vector code against PPSSPP.
- **REA's PSP profile** (rea-agents 6.8.0, which the suite has, and 6.9.0, unchanged) uses
  ghidra-allegrex from `GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-allegrex`, the folder component
  `psp` installs to, and checks its name and Ghidra version. It accepts only Linux x64, and only a static
  `ET_EXEC` ELF with the PSPDEV toolchain's flags (`0x10a23001`) and a MIPS ABI flags record. So REA
  opens homebrew built with today's PSPDEV, and refuses PRXs, PBPs, ISOs and retail games (built with
  Sony's toolchain, without that record). For a game, use `rea-ghidra`. Not run through REA here.
- PPSSPP's own function detection is often better at first: save a `.sym` from PPSSPP (Debug menu) and
  import it with `PpssppImportSymFile` after the first analysis.

*Feeds:* names and function boundaries for splat and a recompiler.

## 5. Observe the original: PPSSPP

```sh
ppsspp ~/Games/<game>/game.iso       # the GUI debugger: Debug menu, disassembly, memory, breakpoints
```

- PPSSPP has **no GDB stub** (none in the v1.20.4 tree). Scripted access is its **WebSocket debugger
  API**: turn on "Allow remote debugger" (`RemoteDebuggerOnStartup` in `ppsspp.ini`), connect to
  `ws://127.0.0.1:<port>/debugger` with the subprotocol `debugger.ppsspp.org`, send `{"event":
  "version"}` first, then JSON events: `cpu.stepping`, `cpu.resume`, `cpu.getAllRegs`,
  `cpu.breakpoint.add`, `memory.breakpoint.add`, `memory.read`, `memory.write`, `hle.module.list`,
  `hle.func.list`, `hle.thread.list`, `hle.backtrace`, `game.reset` (each file under
  `Core/Debugger/WebSocket/` documents its events). The port is `RemoteISOPort`; 0 picks a free one,
  which PPSSPP logs.
- **Privacy trap**: while that web server runs, PPSSPP reports your local IP address and port to
  `report.ppsspp.org` every nine minutes (`RegisterServer` in `Core/WebServer.cpp`), so its phone apps
  can find it. No setting turns that off in v1.20.4: the call is unconditional once the server starts
  (`ReportingHost` only governs compatibility reports). So the suite does not start PPSSPP with the
  debugger on: today it does not start PPSSPP at all, and the WebSocket back end to come keeps
  `RemoteDebuggerOnStartup` off and needs your choice to turn it on. When you turn it on, block
  `report.ppsspp.org` at your firewall or hosts file if that matters to you.
- **Headless**: `PPSSPPHeadless` (the `headless/` target) runs without a window and takes
  `--debugger=PORT`, `--timeout`, `--screenshot`, `--root`; it is a source build only, not in the
  releases.
- **What a run settles**: the PRX modules the game loads from `USRDIR` and at which addresses
  (`hle.module.list`), the firmware functions it calls before the first frame, the decrypted modules.

*Feeds:* module addresses, the first-frame call list, `.sym` names for Ghidra.

## 6. Decompilation: splat and objdiff

- splat (component `decomp`) splits a PSP ELF as it does a PS2 one (`create_config` on the decrypted
  ELF); objdiff matches. The compilers are Sony's SNC and the PSP GCC builds; decomp.me offers some.
- No PSP decompilation was read for this page; look at decomp.dev for current projects.

## 7. Static recompilation

What a recompilation of a PSP game needs:

- **The code**: the decrypted EBOOT and every PRX it loads, at their addresses, with their relocations;
  the VFPU instructions with their prefixes.
- **The machine**: the imported firmware functions by NID (threads, files, `sceGu`/`sceGe` display lists,
  audio, controls, the Media Engine's codecs), answered by the runtime; the GE's display lists rendered.
- **Recompilers**: [psprecomp](https://github.com/sp00nznet/psprecomp) (MIT; C11; v0.5.0, early) uses
  emulators only as an oracle. Its README lists the other PSP recompilers, each a separate codebase:
  [sal063/PSP-recompilation-project](https://github.com/sal063/PSP-recompilation-project) (mixed
  licenses, parts from PPSSPP's GPL code), [jessicanataliagta/PSPRecomp](https://github.com/jessicanataliagta/PSPRecomp)
  (MIT, C++20, per-game profiles) and [wizardengineer/psprecomp](https://github.com/wizardengineer/psprecomp)
  (GPL-2.0, Rust). Source only; the suite builds none.

## 8. Patching

- Patch the decrypted ELF at the file offset of its segment, and run it in PPSSPP as a plain EBOOT; or
  patch memory by address with PPSSPP's cheats while testing.
- Load changed files from the port's own folder rather than rebuilding the UMD image.

## Traps

- **Encryption**: an encrypted module looks like noise. Check `info`'s `kind` before anything else.
- **REA and retail modules**: REA's PSP profile refuses them (step 4); that is the profile, not a broken
  file.
- **VFPU prefixes** change the next instruction's operands; decompiled vector code ignores them.
- **Kernel modules** (attribute `0x1000`) load at `0x88000000`; some need the type B relocation option on
  import (ghidra-allegrex's README).
- **PPSSPP's web server talks to report.ppsspp.org**, and no setting stops it (step 5).

## Outputs, kept where they belong

| Output | Where |
|---|---|
| images, decrypted modules, PPSSPP data, save states | the port's work folder (never git) |
| hashes, disc id, module and import list, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project; `.sym` files for PPSSPP |
| tool fixes and generic traps | this suite (this page) |

## Still missing

- A WebSocket back end for the suite's oracle format (PPSSPP has no GDB stub).
- CSO v2 and ZSO in `rea-suite psp`.
- A run of REA's PSP profile on a PSPDEV-built ELF with the extension installed.

## Sources (read 2026-11-13)

- ghidra-allegrex: GitHub releases (v21.4, 2026-08-25, with a 12.1.4 build dated 2026-10-25; v21.6,
  2026-10-31, 12.2 only), its README and CHANGES.md from the release zip.
- PPSSPP v1.20.4 (2026-05-16): release assets; `Core/Debugger/WebSocket.cpp` and
  `Core/Debugger/WebSocket/*.cpp` (events), `Core/WebServer.cpp`, `Core/Config.cpp`,
  `Core/ELF/PrxDecrypter.h` (the `~PSP` header), `Core/ELF/ElfReader.cpp` (where module info is),
  `Core/HLE/sceKernelModule.cpp` (the library tables, the module's own NIDs, dumping),
  `headless/Headless.cpp`; the tree has no GDB stub.
- rea-agents 6.8.0 and 6.9.0: `dist/ghidra/GhidraPspProfile.js` (identical) and `GhidraPspExtension.js`.
- psprecomp: README (GitHub, last pushed 2026-10-24).
- The NID formula: checked against PPSSPP's named NIDs and three firmware imports in its HLE tables
  (`sceCtrl.cpp`, `sceKernel.cpp`, `sceDisplay.cpp`): `sceCtrlReadBufferPositive` `0x1F803938`,
  `sceKernelExitGame` `0x05572A5F`, `sceDisplaySetMode` `0x0E20F177`.
- The audit that ranked this route: [audits/2026-11-13-platform-check.md](audits/2026-11-13-platform-check.md).
