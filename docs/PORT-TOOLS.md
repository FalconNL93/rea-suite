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

Tests: `uv run --no-sync python -m unittest rea_suite.test_pe` in `common/` (synthetic x64 and
x86 programs from `samples.py`, no game bytes).
