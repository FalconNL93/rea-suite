# DOS protected-mode games: the route

How to take a 32-bit DOS game (Watcom C, an LE executable, DOS/4GW or a similar extender) from its
installer to what a static recompilation needs, with the suite's tools in the order they are used.
Each step says what its output decides and feeds next. The worked example is the Theme Park port
(games/theme-park: its docs/executables.md, docs/original.md and docs/TODO.md hold the findings);
nothing about a particular game belongs on this page.

What lies around this page:

- The tools' own references: [PORT-TOOLS.md](PORT-TOOLS.md), "Linear executables: `rea-suite le`"
  and "DOS programs: `rea-suite dosbox`". This page links them and does not repeat them.
- Engine facts (Bullfrog's DOS engine, its libraries and data formats): master-server's
  docs/ENGINES-BULLFROG.md, and an ENGINES-*.md page of the master's for any other engine.
- The port's platform work (the master, the SDK, the port checklist): master-server's docs/PORTING.md.
- The runtime the code is recompiled onto: winrt's core (games/winrt: `recomp/image.h`,
  `cpu/hooks.h`, `cpu/segments.h`, `guest/call.h`).

## 1. The installer, unpacked as data

```sh
mkdir -p ~/Games/<game>/installer ~/Games/<game>/extract
cp setup_<game>.exe ~/Games/<game>/installer/
cd ~/Games/<game>/extract && innoextract -s -d . ../installer/setup_<game>.exe
sha256sum ../installer/setup_<game>.exe
```

- A GOG release is an Inno Setup installer wrapping DOSBox. `innoextract` unpacks it without running
  anything. Put it in an empty folder of its own and treat the result as untrusted data.
- Leave out the installer's own folders (`tmp`, `__redist`, `__support`, `commonappdata`) and GOG's
  `DOSBOX/`. What is left is the game's DOS tree (`GAME/`, often a folder standing in for the CD,
  `CONFIG/` with the sound setup), plus `goggame-<id>.info` with the GOG id and build id.
- Record the installer's hash and each executable's hash in the port's docs. GOG's batch files
  (`THEME.BAT`-style, its DOSBox `.conf` files) show the exact command line the game starts with,
  and that becomes the run in step 5.

*Feeds:* the executables for step 2, the command line for step 5, the hashes the port's loader
checks.

## 2. Identify the binary

```sh
rea-suite le info GAME/MAIN.EXE            # stub, extender, objects, fixups, entry
diec GAME/MAIN.EXE                         # compiler and linker, where DIE knows them
strings -a GAME/MAIN.EXE | rg -i 'watcom|dos/4g|pmode|causeway|phar'
```

- The stub names the extender. `DOS4GPATH` means the stub runs a separate `DOS4GW.EXE`; a bound
  extender sits in front of the LE.
- Watcom's copyright string dates the compiler. A plain 32-bit image has no 16-bit objects, no
  selector fixups and only internal 32-bit offset fixups, the easy case. Anything else (16:16
  alias objects, selector fixups, imports) is the extender's business and makes the port bigger:
  find out before going on. Theme Park's two executables were the easy case.
- `le dump-image` with `--json-map` gives one flat file to load raw anywhere (Rizin, objdump,
  Unicorn) at the printed base.

*Feeds:* the size of the job, the image for step 3, the object table for the loader.

## 3. Ghidra

```sh
rea-ghidra analyze GAME/MAIN.EXE --project <port>/re/ghidra   # the lxloader extension: objects at their bases
rea-ghidra functions MAIN.EXE --project <port>/re/ghidra > functions.tsv
rea-ghidra decomp MAIN.EXE 0x... 0x... --project <port>/re/ghidra
```

- The suite's `lxloader` (yetmorecode/ghidra-lx-loader, pinned in `common/tools.yml`) loads the LE
  whole, with every fixup applied and Watcom's register calling convention.
- Keep the port's own project (`--project`) so its names survive a reanalysis.
- The function list feeds the recompiler as seeds.
- There is no Watcom FunctionID database in Ghidra or in the suite. The C runtime (cstrt386, the
  heap, int386x, the stdio layer) and an HMI SOS sound library are named by hand, by their strings,
  their INT 21h and DPMI calls, and the `int n; ret` stub table that int386x calls through. A
  reimplementation project's function list (OpenPark counts its Watcom and HMI functions) is a map
  to confirm, not evidence.
- Decompile the addresses the question needs. An LE's data object holds its bss as zeros, which Kaiju
  types as Alignment and which hangs the decompiler; `rea-ghidra analyze` clears it (the suite's README,
  "Headless Ghidra from the shell").
- In zsh, pass address lists as arrays: `rea-ghidra decomp $addrs` decompiles nothing.

*Feeds:* names and function boundaries for the recompiler and the map of each unit a change lives
in.

## 4. The services census

```sh
rea-suite le services GAME/MAIN.EXE --json > census.json
```

The census decides what the host layer answers and what the CPU core needs
([PORT-TOOLS.md](PORT-TOOLS.md#linear-executables-rea-suite-le) has the method):

- **Interrupts and DPMI**: the DOS, DPMI, BIOS video, mouse and multiplex functions the code issues.
  Each is answered by the layer or refused where first seen. If there is no DPMI 0303h, no real-mode
  callback is ever needed. If there is no 0200h-0205h, the game never touches the real-mode or
  protected-mode vectors directly. INT 21h 25h/35h means its own handlers (the timer, at INT 8).
- **Ports**: PIC, PIT, VGA DAC and status, often OPL or Sound Blaster. These are the devices the
  layer models.
- **Segment loads**: Watcom programs build far 16:32 pointers at run time even in a flat image, so
  expect hundreds of `lgs`/`les`. A selector the DPMI host hands out (0000h, or 0100h's selector
  for DOS memory, whose base is segment x 16) then becomes a segment base in the CPU.
- **Far transfers and IRET**: the callbacks the host calls into (a mouse handler set with INT 33h
  000Ch ends in `retf`; a timer handler in `iretd`), and far calls through tables.

Traps:

- **Data decoded as code.** Gap decoding reads strings and tables as instructions. Theme Park's
  seven `ins`/`outs` sites were all text and bytes after a jump. Look at each surprising site before
  asking the core for it.
- **Far calls through tables that are zero in the file**, filled when a sound driver (`HMI*.386`)
  is loaded at run time: that code is not in the executable, cannot be recompiled, and is replaced
  by answering the sound library at its API edge. The calls then never run.
- **Watcom's start-up stores DS into the code object** and `__GETDS` reads it back through CS. Data
  in a code object is allowed; the core's code-write stop must not trip on it.
- **Extender detection**: Watcom's start-up asks INT 21h AH=30h with EBX='PHAR' (Phar Lap) and
  AX=FF00h DX=0078h (DOS/4G answers AL not 0, "4G" in EAX's high word). The layer answers as
  DOS/4GW does, or the start-up takes another extender's path.
- **An HMI bug**: an INT 31h AX=2508h that meant INT 21h AX=2508h. Refuse it as unsupported DPMI.

*Feeds:* the layer's service list, and the core's scope (segment bases, INT and port hooks, far
frames), which the runtime's owner needs first.

## 5. Observe the original: DOSBox-X runs

`rea-suite dosbox` needs the optional `dos` component (`rea-suite select`, then `rea-suite setup`; on Linux
DOSBox-X is built from source and needs the `build` component too).

```sh
rea-suite dosbox info
rea-suite dosbox run --mount <copy of the game tree> --returns --seconds 240 \
  --ints 10,33,31:00,31:03,31:06 --set "dosbox memsize=64" --log run.jsonl --quiet \
  <copy>/GAME/MAIN.EXE <the game's own arguments>
```

- Always run on a copy of the game tree in the work folder. The game may write saves and settings.
- The game's own code is the calls with its flat code selector in `regs.cs` (protected mode `pm`).
  DOS/4GW's loader and its real-mode reflections are the rest, and they are most of the log.
- **What a run settles**: the order of calls up to the first frame (memory, data files, mouse,
  video mode), where the extender put each object, the selectors the program starts with (PSP in
  ES, flat code and data), the callbacks actually installed, and the files actually opened (with
  their case and separators).

Traps and what fixed them:

- **The debugger makes loading slow.** Each traced interrupt stops the emulation (about 20 ms).
  DOS/4GW's own loading under the default `--ints 21,31,33,10` took Theme Park 2 to 4 minutes
  before the game's first call. Leave INT 21h to DOSBox-X's log (`file` and `dos-int` records) and
  narrow INT 31h to the functions that matter (`31:00` descriptors, `31:03` real-mode calls, `31:06`
  lock): the menu then came within 140 s.
- **Memory probes walk down in small steps.** Watcom's heap asks DPMI 0501h for a large block and
  retries 4 KiB smaller after each failure, and DOS memory (0100h) likewise. With DOSBox-X's
  default memory that took thousands of calls. `--set "dosbox memsize=64"` ends the walk at once;
  the port's host answers the first request.
- **An extender need not keep an LE image's object distances.** DOS/4GW placed Theme Park's
  objects at distances different from their LE bases. Measure each object's base from a run: dump
  the code object at a call of the game's own, subtract each fixup's target offset from the value
  it holds, then build the image with those bases (`le dump-object --object-base`) and compare it
  byte for byte with the run's memory. The only differences should be the start-up's own stores.
- **A `--dump` on a time trigger may stop in real mode** inside the extender, and then refuses a
  high linear address ("no 32-bit selector covers it"). Trigger on the game's own call
  (`open:<file>`, `int21:3D`) to stop in protected mode, or give `SEL:OFF`.
- **Scripted clicks are timing-sensitive.** Doubling each click made runs reliable. Two DOSBox-X
  instances at once broke one of them: run one at a time.
- **Ports are not traced.** The debugger traces interrupts. Port use comes from the census and from
  the code.

*Feeds:* the object bases the loader uses, the first-frame call list (which bounds the core's
first work and the layer's first services), and the oracle for comparing the port's runs.

## 6. What the recompilation needs

The LE is recompiled onto winrt's core (its static recompiler and CPU, no PC emulator):

- **A loader of the port's own** on `recomp/image.h` (`LoadImage`): every object at the base
  measured in step 5, fixups applied, the code object as the generated code's table, the data
  objects scanned for code pointers, entries from the entry point and the known callbacks, the
  Ghidra function list as seeds (`seed_delta` maps LE addresses to loaded ones). The run maps the
  image through the same function, registers it (`guest/images.h`), and installs the generated
  code only for the same file hash, base and size. Theme Park's `src/game/image_map.h` is the
  example.
- **The core's DOS work**, from the census and the first-frame list:
  - `cpu/hooks.h` (INT n and IN/OUT to the layer, a refusal stopping the game at the
    instruction);
  - `cpu/segments.h` (segment bases through a selector table the layer fills, an unknown
    selector stopping the game);
  - far and interrupt frames for host-to-guest calls (`guest/call.h`: the mouse callback's RETF,
    the timer's IRETD);
  - `GameConfig::segments` for the generated code;
  - the code-write stop that spares data in a code object.

  Far CALL and JMP are needed only if the game's own code makes them; the census and the run say
  whether it does.
- **The layer** (the port's): DOS (INT 21h over the game folder, the CD folder and the user folder,
  read-only original), DPMI memory and selectors, VGA (mode set, DAC, retrace), the INT 33h mouse,
  the PIT at the rate the game programs, the sound library answered at its API edge. It is tested
  service by service on its own registers, apart from the CPU, and adapted to the core's hooks in
  one file.
- **The layer's traps** (Theme Park's first frame, 2026-11-11):
  - Watcom's `_chain_intr` jumps by `retf` to the vector INT 21h 35h returned, so every default vector the
    layer hands out is a host thunk that returns as the BIOS would; otherwise the first chained timer tick
    lands nowhere.
  - Watcom's heap takes all linear memory in 16 MB chunks, then walks down 4 KB after each refusal: cap
    what DPMI 0501h grants (and 0100h), or the start-up makes thousands of calls.
  - Pace what the hardware paced: a host runs a DOS idle loop out in milliseconds. The VGA retrace follows
    real time (70 Hz), and an input poll that finds nothing waits a minimum interval; Theme Park's menu
    otherwise ran its 3,000-poll idle timeout out at once and started the demo. Measure against the original's
    known waits (a run of step 5).
  - Deliver input where the game reads it: a host key goes into the BIOS buffer at the game's next INT 16h
    poll. A game that checks INT 16h and then drains DOS's buffer loses a key that arrives between the two.
  - A game waits on flags its interrupt handlers set, in loops with no system call or port access, so input
    and timer delivery at the hooks alone never reaches it: the CPU needs asynchronous interrupt points
    (winrt's core, from Theme Park's "Buy Land" stop, 2026-11-12).
- **The fastest way to the first frame** is a headless runner (snapshots to files, a trace switch for the DOS
  calls) and a layer that refuses each unknown service with its number and its caller, then fixing the stops
  one at a time against the run of step 5: Theme Park's title screen took 13 stops (STI, INT 21h 48h, port
  3C6h, INT 16h, ...), each a matter of minutes because the refusal named the service.

## Outputs, kept where they belong

| Output | Where |
|---|---|
| installer, extracted tree, census JSON, flat image, run logs | the port's work folder (never git) |
| hashes, layouts, the first-frame list, decisions with evidence | the port's docs/ (no game bytes) |
| names | the port's Ghidra project and REA session (export the evidence before `close_binary`) |
| engine facts | master-server's ENGINES-*.md |
| tool fixes and generic traps | this suite (PORT-TOOLS.md, this page) |
