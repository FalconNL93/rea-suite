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
(chained unwind entries followed to their primary function).

### MSVC RTTI: classes, vtables, slots, bases

```sh
rea-suite pe rtti game/Game.exe                       # every class: vtables and slot counts, bases
rea-suite pe rtti game/Game.exe --class 'Renderer$' --slots   # one class, every slot's target
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

Checked 2026-11-10 on a 61 MB x64 retail executable: 5,112 classes with their vtables in under a
second.

### References, callers, strings

```sh
rea-suite pe refs game/Game.exe --string skipsplashscreen   # where the string is, and who loads it
rea-suite pe refs game/Game.exe 0x14032d15d8                # instructions naming an address
rea-suite pe callers game/Game.exe 0x21581a0                # E8 calls and E9 jumps to a function
rea-suite pe callers game/Game.exe 0x21581a0 --no-jumps
rea-suite pe strings game/Game.exe 0x1ee300 0x500           # strings the code in a range loads
```

`refs` covers x64 RIP-relative operands (`lea`, `mov`, `cmp` with an immediate after the
displacement) and x86 absolute addresses (operands and immediates, `push offset`). `--string`
matches the whole NUL-terminated string, ASCII or UTF-16LE. `callers` finds direct rel32 calls
and jumps only; calls through a register or a vtable need `rea-suite pe rtti` or a decompiler.

### Every call site of an import DLL

```sh
rea-suite pe imports game/Game.exe --dll EOSSDK-Win64-Shipping.dll   # each function: sites, functions
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

Tests: `uv run --no-sync python -m unittest rea_suite.test_pe` in `common/` (synthetic x64 and
x86 programs from `samples.py`, no game bytes).

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
  '{"targets": [{"name": "Initialize", "iat": "0x26130a8", "mode": "count"},
                {"name": "Tick", "iat": "0x26130d8", "mode": "count", "only_from": "Game.exe"}]}'
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
