# Port investigation tools

Tools that came out of the game ports (first the Alan Wake II port, 2026-11) and work for any
Windows game: scans of the executable from the file alone, passive Frida observers, a virtual
pad and a window harness for testing input. A game's addresses, names and switches never live
here: they come in as arguments or a file of the port's own.

What REA already does is not repeated: `search_strings`, `xrefs`, `find_xrefs_to_name` and the
call graph come from an analyzed provider session (Ghidra for a PE), and `inspect_pe_imports`,
`inspect_pe_load_config`, `inspect_pe_resources` and `inspect_pe_certificates` read the PE
directories without one. The tools below fill what those leave: answers in a second from the
bytes, for an executable too large to analyze in a hurry (a large game outlasts REA's default
Ghidra startup deadline, see [known issues](REA-KNOWN-ISSUES.md)), and
the MSVC RTTI walk, which REA has no tool for (Ghidra's own RTTI analyzer names `vftable`s
inside a full analysis only).

## PE scans: `rea-suite pe`

One command over a PE image (x86 or x64), with `--json` everywhere. Addresses are hexadecimal:
at or above the image base a VA, below it an RVA. Every hit is a byte pattern confirmed by
decoding the instruction with Capstone; a linear scan sees code a decompiler would not reach
and misses references computed at run time, so treat a hit as a lead and an empty answer as no
proof. Where the x64 unwind table covers an address, the result names the function it lies in
(chained unwind entries followed to their primary function). Every JSON row of `refs`,
`callers`, `strings` and `imports` carries `function` (that address, or `null`) and
`function_known` (`false` in x86 images and for code without an unwind entry, such as leaf
functions and thunks), so rows sort with a key like
`(not r["function_known"], int(r["function"] or "0", 16))`.

### The image: `info`

```sh
rea-suite pe info game/Game.exe                  # machine, base, entry, sections, directory counts
rea-suite pe info game/Game.exe --imports --json # every import with its IAT slot, delay-loaded ones too
```

The model under every `pe` command (`common/rea_suite/pemodel.py`) is a thin layer over pefile,
which the suite already has (REA's `inspect_pe_imports` uses it too): sections with RVA to file
offset, imports and delay imports with their IAT slots, exports, base relocations (optional: a
fixed-base image has none and nothing needs them), the TLS directory with its callbacks, and the
x64 unwind table with chained entries followed to their primary function. For a port's own
scripts: `from rea_suite.pemodel import Image`. LIEF, also in the suite, is the choice for
rewriting an image; this model only reads.

### A port's declared sites: `sites`

A port that patches or hooks an executable keeps every address it uses in one declaration, and
checks it against the executable before using it: the file by SHA-256 and size, then every
site's bytes and placement.

```sh
rea-suite pe sites game/Game.exe --init > re/sites.json   # a new declaration: the source block
rea-suite pe sites game/Game.exe re/sites.json            # exit 0 all agree, 1 differences, 2 invalid
```

The format (`"schema": "rea-image-sites-v1"`) has seven kinds: `call` (a 5-byte E8 or 6-byte
FF 15 call the port redirects, with its `target`), `edit` (bytes replaced by a `replacement` of
the same length), `function` (a function's first bytes), `iat` (an import slot, with the
`import` it must hold), `data` (a global outside code; `writable` when it must be), `range` (code
the port scans, inside one code section) and `offset` (a structure offset: no address). Every
site but an offset names its `evidence`; any other member is the port's own. The full description
is at the top of `common/rea_suite/sites.py`. The checker reports every difference rather than
the first. It is the suite's general version for investigating and validating; a port keeps its
own reader of its declaration as its build gate.

Checked 2026-11-10 on a 61 MB x64 retail executable with a port's 56 declared sites (12 calls,
10 edits, 15 functions, 4 IAT slots, 10 globals, 2 ranges, 3 offsets), converted to this format:
all agree.

### MSVC RTTI: classes, vtables, slots, bases

```sh
rea-suite pe rtti game/Game.exe                       # every class: vtables and slot counts, bases
rea-suite pe rtti game/Game.exe --class 'Renderer$' --slots   # one class, every slot's target
rea-suite pe rtti game/Game.exe --slots --purecall 0x140a1b2c0   # a statically linked _purecall
rea-suite pe rtti game/Game.exe --json > work/game-rtti.json
```

For x64 it finds the complete object locators by their self-reference (signature 1, pSelf),
for x86 the type descriptors by their decorated names (`.?AV`, `.?AU`) and the locators that
point to them; a vtable is the slot after a pointer to its locator, its slots run while they
point into code. Bases come from the class hierarchy descriptor, the class itself first (the
JSON leaves it out), with each base's `mdisp`/`pdisp`/`vdisp`. A class with multiple inheritance
has one vtable per base subobject, each with its `offset`. Relocations are not needed, so a
fixed-base image (no `.reloc`) works the same. Names demangle without a tool when simple
(`.?AVWidget@ui@@` is `ui::Widget`); templates go through `llvm-undname` when it is on PATH
(component `build`), otherwise they stay decorated.

Each vtable is set against its base's: the first non-virtual base in the hierarchy array whose
own vtables include one at the vtable's `offset` minus the base's `mdisp` (so with multiple
inheritance each vtable finds the base of its own subobject). `--slots` marks every slot, and
the JSON always carries `base`, `base_vtable` and `slot_states` (one per slot):

| State | Meaning |
|---|---|
| `pure` | the slot is the CRT's `_purecall`: the thunk to the import found by itself, a statically linked stub given with `--purecall` (repeatable) |
| `inherited` | the base's vtable holds the same function at that index |
| `overridden` | it holds another one |
| `new` | past the end of the base's vtable, or no base vtable covers this one (a root class, or a base with no RTTI in the image) |
| `unknown` | no base covers it and the class has virtual bases, whose offsets live in the vbtable rather than in RTTI |

Identical functions folded by the linker (`/OPT:ICF`) share an address, so an override that
compiles to the base's code reads as `inherited`. Checked 2026-11-10 on a 61 MB x64 retail
executable: 3,148 of 5,132 vtables matched a base, 715 pure slots through one `_purecall`
thunk, in under two seconds.

Checked 2026-11-10 on a 61 MB x64 retail executable: 5,112 classes with their vtables in under a
second; and on a 12 MB fixed-base x64 executable (no `.reloc`): 1,313 classes, 13,342 slots, 95
classes with several vtables whose offsets match their bases' `mdisp`. x86 is covered by the
tests only.

### References, callers, strings

```sh
rea-suite pe refs game/Game.exe --string skipintro          # where the string is, and who loads it
rea-suite pe refs game/Game.exe 0x1406f2340                 # instructions naming an address
rea-suite pe callers game/Game.exe 0x4a8f20                 # E8 calls and E9 jumps to a function
rea-suite pe callers game/Game.exe 0x4a8f20 --no-jumps
rea-suite pe strings game/Game.exe 0x2a1000 0x400           # strings the code in a range loads
```

`refs` covers x64 RIP-relative operands (`lea`, `mov`, `cmp` with an immediate after the
displacement) and x86 absolute addresses (operands and immediates, `push offset`). `--string`
matches the whole NUL-terminated string, ASCII or UTF-16LE. `callers` finds direct rel32 calls
and jumps only; calls through a register or a vtable need `rea-suite pe rtti` or a decompiler.

### Every call site of an import DLL

```sh
rea-suite pe imports game/Game.exe --dll steam_api64.dll            # each function: sites, functions
rea-suite pe imports game/Game.exe --function CreateFileW --json
rea-suite pe imports game/Game.exe --used > work/game-imports.txt     # the whole IAT, used slots only
```

For each imported function (delay-loaded ones too) it lists every instruction that goes through
its IAT slot: `call [slot]`, `jmp [slot]` (a thunk) and `mov reg, [slot]` (the pointer loaded
for a later call), plus the rel32 calls to such a thunk (`via-thunk`), each with the function it
lies in. That is the map of where a game talks to a DLL it is about to lose or replace. Calls
through a pointer the game stored elsewhere (`GetProcAddress`, a table it filled) are not
seen; Frida's observers below catch those at run time.

Checked 2026-11-10 on a 61 MB x64 retail executable: 1,089 imports, 43,209 sites, in under a
second; for its 42 EOS imports the sites agree exactly with the call map that port had built by
hand with REA and Rizin.

### A game's option registry

Many engines register their settings (command-line switches, config keys, console variables)
in long straight-line blocks: per setting, the strings are loaded, then a registrar function for
the setting's type is called. `registry` reads such blocks back: per call to a registrar in the
given ranges, the strings loaded since the previous call, named by the fields you give in load
order (the last strings count), and with `--stack-byte` the byte stored to `[rsp+OFF]` before the
call (some engines pass a bool's default there; a register's name when it is not an immediate).

```sh
rea-suite pe registry game/Game.exe --range 0x2a1000:0x400 --range 0x2b8000:0x2000 \
  --registrar 0x5d3100=bool:description,name \
  --registrar 0x5d3200=string:default,hint,description,name \
  --stack-byte 0x30 --markdown > work/options.md
rea-suite pe registry game/Game.exe --config re/option-registry.json --json
```

The config holds the same: `{"ranges": [["0x2a1000", "0x400"]], "registrars": {"0x5d3100":
{"type": "bool", "fields": ["description", "name"]}}, "stack_byte": "0x30"}`. Find the registrar
by one setting's name (`refs --string`), the call after it, and the blocks around it. The port
keeps its addresses and what it tested; this gives the table.

Checked 2026-11-10 on a 61 MB x64 retail executable: the 97 options of its two blocks, with the
same names, types, sites and string defaults as the table that port generated with its own tool.

Tests: `uv run --no-sync python -m unittest rea_suite.test_pe` in `common/` (synthetic x64 and
x86 programs from `samples.py`, no game bytes).

## Remedy packages: `rea-suite rmdp`

Remedy's games keep their data in packages: an index (`.bin`, a tree of folders and files) and a data file
(`.rmdp`, the files' bytes back to back, uncompressed). `rmdp` reads them without writing anything:

```sh
rea-suite rmdp list game/data/ep999-000.bin --glob 'messages/*'          # path, size, offset, CRC-32
rea-suite rmdp extract game/data/ep999-000.bin 'messages/*' --out work/x --check
rea-suite rmdp find game/data/ep999-000.bin --text UnlockAchievement --glob 'worlds/*' --inner
rea-suite rmdp inner game/data/ep999-000.bin 'worlds/*/level_01/root.bin' --out work/x
```

- **Versions.** 2 (Alan Wake: big-endian, 32-bit links, packed records; Alan Wake Remastered: the same version with
  64-bit links and records aligned as a C compiler lays them out, told apart by which layout gives a root with null
  links), 7 (American Nightmare, little-endian) and 8/9 (Quantum Break, Control).
- **Checks.** Every name is checked against its CRC-32 (lowercase ASCII), and every link must lead to a record once.
  `--check` compares each extracted file with its stored CRC-32, which is little-endian in every package.
- **Level containers.** Alan Wake's level `.bin` files hold a little-endian table (count, then per entry a name length,
  the name and a size; 32-bit in Alan Wake, 64-bit in Remastered) and one zlib stream with the entries back to back.
  `find --inner` searches inside them, and `inner` extracts their entries (`cid_*` object data, `dp_*` parameter pools:
  the script bytecode's strings are in `dp_bytecodeparameters.bin`).
- **Output.** Extraction refuses a folder inside the package's own folder, so a game installation is never written.
  Names that file systems cannot hold are escaped as `%XX`.

Written from the format's description in [GrzybDev/NorthlightTools](https://github.com/GrzybDev/NorthlightTools)
(`docs/rmdp.md`, read at f8ccb3f) and [OpenAWE-Project/OpenAWE](https://github.com/OpenAWE-Project/OpenAWE)
(`src/awe/binarchive.cpp`, read at 3ad7807). Both are GPL-3.0 and were read as references only; no code of theirs is
in this tool. Checked 2026-11-11 against Alan Wake Remastered's packages (`ep999-000`: 28 809 files, every name
checksum matching; `ep999-001`; the English pack), and by `common/rea_suite/test_rmdp.py` on packages built in three
layouts.

## Linear executables: `rea-suite le`

DOS games built with Watcom C and a DOS extender (DOS/4GW, PMODE/W, DOS/32A, CauseWay) are LE
executables: a real-mode MZ stub that starts the extender, then a 32-bit flat module in pages with a
fixup table. VxDs are LE too, and OS/2's 32-bit programs LX. Ghidra and REA read neither format
directly; `le` reads them from the file alone, without writing anything:

```sh
rea-suite le info game/MAIN.EXE [--json]       # stub, header, objects, fixup counts, entry, imports
rea-suite le dump-object game/MAIN.EXE 1 --base 0x10000 --out work/tp/obj1.bin
rea-suite le dump-object game/MAIN.EXE 3 --base 0x400000 --object-base 1=0x10000 --out work/tp/obj3.bin
```

- **Header.** Found at the MZ header's `e_lfanew` (0x3C), as a 4GW stub has it, or after the MZ
  image, as an extender bound in front of the program has it. The extender is named from strings in
  the stub (`DOS4GPATH` for the stub that starts `DOS4GW.EXE`, `DOS/32A`, `PMODE/W`, ...), or "not
  identified". Watcom marks DOS/4GW programs with OS type 1 (OS/2); that is what the header says.
- **Objects.** Number (from 1, as fixups count them), relocation base, virtual size, 16 or 32-bit
  (the BIG flag, 0x2000), `rwx`, the pages it takes in the page table and the other flags by name.
  An object with no pages (a bss) is zeros at load.
- **Pages.** LE keeps a 24-bit page number (high byte first) and a flags byte per page, the pages in
  the file back to back from the data pages offset (counted from the start of the file), the last one
  shorter; LX keeps an offset (shifted by the page shift) and a size per page.
- **Fixups.** Counted by source type and target kind, one per source offset (a record with a source
  list counts each). A fixup crossing a page boundary is listed under both pages, the second time
  with a negative offset.
- **Entry point.** EIP object and offset, and the address at the object's relocation base.
- **dump-object.** The object's pages, zero-filled pages as zeros, padded to its virtual size, with
  every internal 32-bit offset, 32-bit self-relative and 16:32 pointer's offset fixup written for the
  chosen bases. `--base` places the dumped object (default: its relocation base); the other objects
  move by the same amount, so the module keeps its layout, unless `--object-base N=ADDR` places one.
  Load the output raw at `--base` in Ghidra, Rizin or Unicorn, and each other object at its own base.
  Ghidra itself needs no dump: the ghidra-lx-loader extension loads the executable whole
  (`rea-ghidra analyze game/MAIN.EXE`), every object at its base and every fixup applied.
  Left as they are, and counted on stderr: imports, selectors, 16-bit offsets, 8-bit and alias fixups.
  Iterated, compressed and invalid pages are left as zeros, with a warning.

Written from IBM's [LX - Linear eXecutable Module Format Description](https://www.edm2.com/index.php/LX_-_Linear_eXecutable_Module_Format_Description)
(1992, EDM2's reprint: the header, object table, page table, fixup records and entry table) and the
LE/LX structures in Open Watcom's
[`bld/watcom/h/exeflat.h`](https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h)
(LE's `le_map_entry` and the `OSF_*` constants; Sybase Open Watcom Public License), read as
references; no code of either is in this tool. Checked 2026-11-11 against Theme Park's `MAIN.EXE`
(DOS/4GW stub, three objects, 162 pages ending exactly at the end of the file, 19 746 internal
32-bit offset fixups, all applied; the entry point lands on Watcom's startup and its stores address
the data object), and by `common/rea_suite/test_le.py` on a module built in the test (`uv run
--no-sync python -m unittest rea_suite.test_le` in `common/`).

## Frida: `rea-suite frida`

`rea-suite frida <script.js>` attaches a Frida script to a process (`--pid`, `--name`) or starts
one (`--spawn PROGRAM ARGS...`), hands the script its config through its `configure` RPC export
(`--config FILE` or `--config-json TEXT`), and writes everything the script sends as JSON lines
(stdout, and `--log FILE`), each with `t`, the seconds since the runner started. A spawned
process is resumed only after the script loaded and accepted its config, so nothing runs
unobserved, and is killed instead when either failed. It ends after `--seconds`, when the
process ends, or on Ctrl+C; a spawned process keeps running unless `--kill`. Exit 0 when it ran,
1 on a script error, 2 when there is no such process. The scripts live in `common/frida/`.

### Passive observer

`common/frida/observer.js` logs calls of chosen functions without changing them. A target is an
export (`"xinput1_4.dll!XInputGetState"`, or a list of alternatives), an address in a module
(`"rva"`, with `"module"`, default the main one) or an IAT slot (`"iat"`: the function the slot
points to, picked up once the loader has bound it). Targets in a module that is not loaded yet
are hooked when it loads. Per target:

- `mode`: `call` logs every call, `change` only when the values in `key` change (per value of
  `group`, say per pad index), `count` counts calls per caller and reports every `interval_ms`.
- `args` (log arg0..argN-1 as pointers), `reads` (typed values: an argument or the result itself,
  or memory at it plus `offset`, read on enter or leave; arrays with a count from an argument),
  `caller` (the return address as `module+offset`), `only_from` (only calls returning into this
  module), `format` (a text line, `{name}` from the values), `limit` (most messages, default 10,000).

The full config format is at the top of the script. Two examples are in `common/frida/examples/`:

```sh
# Pad state changes per pad index, with the caller; the game started by the runner
rea-suite frida common/frida/observer.js --config common/frida/examples/xinput.json \
  --log work/xinput.jsonl --spawn game/Game.exe
# Raw input registrations (usage page, usage, flags), attached to a running game
rea-suite frida common/frida/observer.js --config common/frida/examples/raw-input.json --name Game.exe
# Calls through two IAT slots of the main module, counted per caller every 2 s
rea-suite frida common/frida/observer.js --name Game.exe --config-json \
  '{"targets": [{"name": "Initialize", "iat": "0x6c2010", "mode": "count"},
                {"name": "Tick", "iat": "0x6c2018", "mode": "count", "only_from": "Game.exe"}]}'
```

Checked 2026-11-10 on Linux (frida 17.24.3): a spawned Python's `getenv` calls with argument and
result strings, change mode per group, counts per caller and `only_from`; the opt-in test runs
it (`REA_FRIDA_INTEGRATION=1 uv run --no-sync python -m unittest rea_suite.test_frida_run` in
`common/`). On Windows 11 (frida 17.26.2), both examples together on a spawned Python that
calls `XInputGetState` for pads 0 and 1 three times (no pad: result 1167, one message per pad)
and registers two raw input devices: the XInput hook waited for `xinput1_4.dll` to load, and
the registration came out as `[{page 1, usage 5}, {page 1, usage 4}]`. Not yet run against a game.

### Write guard (Windows)

`common/frida/write-guard.js` lets a Windows process change files only under the folders you
allow: for running an original game, or a port's copy of it, without it writing into its install
folder, the user's profile or anywhere else. It works at the native API (ntdll), below every
library the game uses:

- `NtCreateFile` and `NtOpenFile` for writing, deleting, changing attributes, creating or
  delete-on-close are refused (`STATUS_ACCESS_DENIED`) unless the path is allowed. The path is
  resolved through the kernel at its nearest existing ancestor, so a junction or symlink inside
  an allowed folder does not reach out of it.
- Renames (`NtSetInformationFile`) are checked by their destination; hard links are refused, since
  one would alias an original file under an allowed folder. The information classes are filtered
  in a CModule, so Frida's own I/O never reenters the script.
- Starting child processes (`NtCreateUserProcess`: launchers, crash reporters) is refused unless
  `"deny_children": false`.

```sh
rea-suite frida common/frida/write-guard.js --log work/guard.jsonl \
  --config-json '{"allow": ["D:\\work\\run", "D:\\work\\saves"]}' --spawn 'D:\work\run\Game.exe'
```

Kernel objects that are no disk files (pipes, sockets, the console, HID and GPU devices) pass;
`allow_devices` replaces that list of regexes. Every refusal is logged (`write-denied` with the
path as asked and as resolved, `rename-check`, `hardlink-denied`, `child-process-denied`).
Leave out `--seconds`, or add `--kill`: when the runner stops before the process does, it
unloads the script and the process runs on unguarded.

Checked 2026-11-10 on Windows 11 x64 (frida 17.26.2) with a spawned Python and the folder
`allowed` allowed: a new file there and a rename within it worked; reading a file outside
worked; writing, appending to, deleting or renaming into a file outside, a hard link to an
outside file, a write through a junction from `allowed` to the outside folder and starting
`cmd.exe` were all refused, and the outside file was unchanged. Not yet run against a game, and
not on x86 (the offsets follow the pointer size; untested).

## Virtual pad: `rea-suite pad` (Windows)

A virtual Xbox 360 pad that presses buttons on a schedule, for testing a game's pad input
without a person at the controller. It drives ViGEm through `ViGEmClient.dll` with ctypes (no
Python package between): plug in a pad, wait for each press's time in seconds from the moment it
was plugged in, hold, release, and unplug `--tail` seconds after the last press.

```powershell
.\platforms\windows\rea-suite.ps1 pad --check --dll D:\tools\ViGEmClient.dll     # the driver answers
.\platforms\windows\rea-suite.ps1 pad --presses 30:DOWN,33:DOWN,36:A --idle-pad  # with REA_VIGEMCLIENT_DLL set
.\platforms\windows\rea-suite.ps1 pad --presses "5:A+B:0.5,8:LT,9:LX-" --hold 0.2 --tail 10
rea-suite pad --presses 30:DOWN,33:A --dry-run                                  # any platform: the schedule
```

A press is `TIME:BUTTON[+BUTTON][:HOLD]`: `A B X Y`, `UP DOWN LEFT RIGHT`, `START BACK`, `LB RB`,
`LS RS`, `GUIDE`, `LT RT` (full trigger), `LX+ LX- LY+ LY- RX+ RX- RY+ RY-` (full deflection).
`--idle-pad` plugs in a pad that never moves first, so the scripted one gets the second XInput
slot: what a remote-play or streaming host leaves behind, and a common cause of "the game ignores
my pad". Every event is a JSON line with `t` from the plug-in (`plugged` with the XInput user
index, `press`, `unplugged`), which the window harness below lines its captures up with.

What it needs:

- The ViGEmBus driver: winget `ViGEm.ViGEmBus` (component `porting`). Its project is retired
  upstream; version 1.22.0 is the one used here (Windows 11, 2026-11-10).
- `ViGEmClient.dll`, x64, from your own copy (`--dll`, or `REA_VIGEMCLIENT_DLL` in `.env`):
  nefarius/ViGEmClient publishes source only, so build it, or take the one a tool you trust
  ships. The suite does not download it.

Linux and macOS have no ViGEm; there `--dry-run` checks a schedule, and Linux's `uinput` would be
the counterpart (not part of the suite). Checked 2026-11-10: the schedule and reports
(`uv run --no-sync python -m unittest rea_suite.test_vigem_pad` in `common/`), and the exports it
binds against a ViGEmClient.dll (x64) with `rea-suite pe`. The pad itself was not run from the
suite yet; the Alan Wake II port's original of this script drove that game with the same DLL and
calls on 2026-11-10.

## Window harness: `platforms/windows/window-oracle.ps1` (Windows)

Watches one process's window while an input driver plays a schedule, and keeps what it saw:
the answer to "did the game react to that press?" without a person watching. It launches the
program (`-Exe`) or waits for a running one (`-ProcessName`, `-ProcessId`), starts the input
driver (`-Pad`: `rea-suite pad` with the same schedule; or any `-InputCommand`), and times every
capture from the driver's start (for the pad, its `plugged` line). For each input at time T it
saves `before<i>.png` at T - `Before` (0.6 s) and `after<i>.png` at T + `After` (1.2 s), then
`final.png`; inputs closer together than Before + After get their captures late. Captures use
`PrintWindow` on the process's main window only, so other windows, notifications and the desktop
never appear in them. It focuses the window once, four seconds before the first input, unless
`-NoFocus`. `events.jsonl` logs each step with `t` on the driver's clock; `report.json` holds the
process, its loaded modules (path, base, version), its TCP connections and UDP endpoints, and the
DNS client cache (system-wide, so it shows names the process may have looked up).

```powershell
# Launch the game, press DOWN three times and A with a virtual pad, capture around each press
.\platforms\windows\window-oracle.ps1 -Exe D:\work\run\Game.exe -Schedule 30:DOWN,33:DOWN,36:DOWN,39:A `
  -Pad -PadArguments --idle-pad -Seconds 50 -Close -Out work\pad-idle
# The game is started some other way (a launcher): wait for it, then watch
.\platforms\windows\window-oracle.ps1 -ProcessName Game -Schedule 20:START -Pad -NoFocus
```

Output goes to `-Out` (default `work\window-oracle\<time>`, ignored by git). Captures need an
unlocked desktop; a full-screen exclusive game may come out black (run it windowed).

Checked 2026-11-10 on Windows 11 with PowerShell 7 against a process without a window (`PING.EXE`)
and a stand-in input driver: launch, the timeline from the driver's start (each before/after at
its time to within 0.1 s), the skipped captures logged, the report (modules) written, the driver
stopped. Captures of a real window were not run here (no visible windows in automated checks);
the Alan Wake II port's original of this harness took them with the same `PrintWindow` call.
