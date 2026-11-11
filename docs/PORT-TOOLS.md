# Port investigation tools

Tools that came out of the game ports (first the Alan Wake II port, 2026-11) and work for any
Windows game: scans of the executable from the file alone, passive Frida observers, a virtual
pad and a run harness that drives and watches a game; for DOS games, LE executables and a DOSBox-X
run that logs the interrupts a game makes. A game's addresses, names and switches never live
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
proof. Every hit names the function it lies in (next section). Every JSON row of `refs`,
`callers`, `strings`, `imports` and `registry` carries `function` (its start, or `null`),
`function_name`, `function_source` (`table`, `unwind`, `heuristic` or `null`) and
`function_known` (true for a start from a table or the unwind table only), so rows sort with a
key like `(not r["function_known"], int(r["function"] or "0", 16))`.

### The containing function, x86 too: `--functions`

Every `pe` command takes `--functions TSV` (repeatable) and `--game NAME`. One source answers:

| Source | When | What |
|---|---|---|
| `table` | `--functions` given | the TSVs' starts and names: `rea-ghidra functions` output, a port's `function_entries.tsv` (starts only) or `functions.tsv` (with a `game` column, picked by `--game`); the address column is the first of `entry`, `address`, `va`, `rva`, `start`, else the first column; `name` and `size` are read when present. Tables merge, so one can give the starts and another the names |
| `unwind` | an x64 image with an unwind table | the RUNTIME_FUNCTION entries, chained entries followed to their primary function |
| `heuristic` | neither (x86, or x64 without `.pdata`) | the entry point, exports, TLS callbacks, rel32 call targets (two callers, or one after padding or a `ret`), `push ebp; mov ebp, esp` after padding or a `ret`, and the first byte after a `ret` followed by int3/nop padding |

With a table or the heuristic the function is the nearest start at or below the address in the
same section; a table's `size` (Ghidra's body in bytes) bounds it, so an address past it lies in
no function rather than the wrong one. A partial table (named functions only) gives code between
two names to the one before it: give the whole entry list with the names. Text output marks a
heuristic start with `~` (`in ~0x41d2d8`); JSON says `"function_source": "heuristic"` and
`"function_known": false`. A heuristic start can be missing (a function reached only through a
pointer, without a frame) or extra (bytes in data that look like a `ret` and padding).

```sh
rea-suite pe imports game/Game.exe --dll DINPUT.dll \
  --functions re/function_entries.tsv --functions re/functions.tsv --game sp
rea-suite pe refs game/Game.exe --string cfg --json      # x86 without a table: heuristic starts
```

Checked 2026-11-11 on a 4.7 MB MSVC 6 x86 executable against its port's Ghidra entry list (33,947
starts): the heuristic found 22,779 starts in 0.4 s, and named the same function as the list for
546 of the 618 import call sites; of the other 72, half split a function the list keeps whole
(the `jmp [slot]` thunks, `call; jmp` initializers) and half missed a start. With the list and
the port's names, `imports` and `refs` name every site.

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

### Disassembly: `disasm`

```sh
rea-suite pe disasm game/Game.exe 0x4a8f20                      # 24 instructions from there
rea-suite pe disasm game/Game.exe Renderer_Draw --count 40 --functions re/functions.tsv
rea-suite pe disasm game/Game.exe 0x4a8f37 --function           # the whole function it lies in
rea-suite pe disasm game/Game.exe 0x4a8f20 --to 0x4a8f80 --json
rea-suite pe disasm game/Game.exe --histogram                   # mnemonics over every code section
rea-suite pe disasm game/Game.exe 0x4a8f20 --function --histogram
```

Capstone, linear, from the given address (a VA, an RVA, or a name from `--functions` or the
exports). Each instruction is noted with what its addresses are: an import (`; KERNEL32.dll!Sleep`
for `call [slot]`), a named function, a string. A function start from the function map is a
label line (`Name:`, `sub_401000:` for an unnamed table start, `~sub_401000:` for a heuristic
one). `--function` runs from the containing function's start to the next start (or its unwind
entry's end, or the table's size; at most 64 KiB) and leaves out the padding after it. An
undecodable byte is a `db` row. `--histogram` counts mnemonics over the selection, or over every
code section (up to their virtual size, so the file's alignment padding is not counted) when no
address is given; undecodable bytes are counted apart.

### Resources: `resources`

```sh
rea-suite pe resources game/Launcher.exe                         # every resource, decoded briefly
rea-suite pe resources game/Launcher.exe --type DIALOG --name 101 --json
rea-suite pe resources game/Game.exe --type GROUP_ICON --extract work/game-res
```

pefile walks the resource directory; the resources are read by their documented layouts:

| Type | Decoded |
|---|---|
| `DIALOG` | DLGTEMPLATE and DLGTEMPLATEEX: style, size, title, font; each control's id (IDC_STATIC as `-1`), class (`Button`, `Edit`, ... or a registered name), text, style and position; creation data as hex |
| `MENU` | MENU and MENUEX: the item tree with ids, separators, popups |
| `STRING` | each block's strings with their ids (block - 1) * 16 + index |
| `ACCELERATOR` | key with modifiers (`Ctrl+O`, `F1`) and command id |
| `VERSION` | the fixed file and product versions, every string table, the translations |
| `MESSAGETABLE` | message ids and texts |
| `GROUP_ICON`, `GROUP_CURSOR`, `ICON`, `CURSOR`, `BITMAP` | sizes and bit depths (PNG or DIB) |
| `MANIFEST` | its text (JSON) |
| others | size and the first 16 bytes (JSON `head`) |

The text output is a few lines per resource (single icon and cursor images are left out unless
`--type` asks for them); `--json` holds everything, and `--type` (a name or number, repeatable) and
`--name` narrow either. A resource a reader cannot decode gets an `error` member; the walk goes
on. `--extract DIR` writes `resources.json` and per type a folder: each icon or cursor group as
an `.ico` or `.cur` plus a `.png` per image (stored PNGs as they are; 1, 4, 8, 24 and 32-bit
DIBs converted, transparency from the alpha channel or the AND mask), bitmaps as `.bmp`
(the file header added), manifests as `.xml`, the rest raw (`.bin`). A name in several languages
gets the language in its file name. The executable's own folder is refused as `DIR`, so a game
installation is never written.

Checked 2026-11-11 on Windows binaries: a resource DLL with 76 resources (19 dialogs, 6 menus,
string tables, accelerators) in 0.1 s with no errors; an icon group of 13 images (4, 8 and 32
bits, one PNG) converted and viewed; and a game's icon group exported byte for byte the same as
that port's own `extract_icon.py` produced.

### Port scripts these replace

| Port script | Now |
|---|---|
| CoD1 `tools/x86dis.py` (disassemble `ADDR:COUNT`) | `pe disasm <exe> ADDR --count N` |
| CoD1 `tools/mnem_hist.py` (mnemonic histogram of `.text`) | `pe disasm <exe> --histogram` |
| CoD1 `tools/peinfo.py` | `pe info --imports --exports` |
| CoD1 `tools/extract_icon.py` (icon group to `.ico`) | `pe resources <exe> --type GROUP_ICON --extract DIR` (same bytes); the port keeps its copy while its build embeds the icon |
| Rogue Spear's pefile script for menus, dialogs and string tables, and `inspect_pe_resources` ([known issue 7](REA-KNOWN-ISSUES.md)) | `pe resources` |
| Rogue Spear's objdump and `resolve_containing_procedure` per `xrefs` hit | `pe refs`/`callers`/`imports` with `--functions re/function_entries.tsv`, `pe disasm` |

Tests: `uv run --no-sync python -m unittest rea_suite.test_pe` in `common/` (synthetic x64 and
x86 programs and a resource section of every decoded kind, built in `samples.py`; no game bytes).

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
rea-suite le dump-image game/MAIN.EXE --out work/tp/main.bin --json-map work/tp/main.json
rea-suite le services game/MAIN.EXE [--json]   # INT n, DPMI, I/O ports, segment loads, far, 16-bit
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
- **dump-image.** Every object at its base in one flat file, from the lowest object base to the
  highest object end, the gaps zeros, with the same fixups applied: load it raw at the printed base
  (REA, Ghidra, Rizin map one file at one address) and the code's references into the data objects
  resolve. `--base` moves the lowest object and the rest with it; `--json-map` writes the objects'
  bases, image offsets and the entry point, which stderr prints too.
- **services.** What a host layer that runs the program must provide (`common/rea_suite/le_services.py`),
  from the code objects decoded with Capstone after fixups at the relocation bases:
  - **Decoding.** By flow from the entry point, exported entries and internal fixup targets in code
    (function pointers), following direct jumps and calls, never across a fixup that is not an
    instruction's displacement or immediate (a jump or function table is pointers, not code). Then
    each stretch nothing reached is decoded the same way from its first byte past nop padding:
    functions called only through a computed pointer, dead code and data that happens to decode.
    Every site says how it was reached (`found_by` `flow` or `gap`, `gap` in the text). A linear
    sweep or a byte search for `CD ??` finds `int` in data and inside other instructions.
  - **Interrupts.** Every `int n` with AH, AL, BH, BL set before it in its basic block, the function
    (AH, or AX for DPMI 31h, mouse 33h, multiplex 2Fh, VDS 4Bh) and the subfunction where one picks
    it (INT 21h AH=25h/35h AL is the vector, DPMI 0200h-0205h and 0300h BL the interrupt) named from
    tables; DPMI functions also by group (descriptors, DOS memory, interrupt vectors, real-mode calls,
    real-mode callbacks, ...). A run of `int n; ret` stubs for consecutive n (a runtime that calls
    `table + 3n` to issue an interrupt chosen at run time) is listed once as a table.
  - **Ports.** `in`/`out`/`ins`/`outs` with the port, an immediate or DX followed back through
    `mov`, `inc`, `dec`, `add`, `sub`, named (PIC, PIT, keyboard, VGA, Sound Blaster, OPL, ...).
  - **Segment loads.** `mov sreg`, `pop sreg`, `lds`/`les`/`lfs`/`lgs`/`lss`, with the value where
    the block shows it: a constant, a copy of another segment register (`mov ax, ds` or the
    `push ds` the pop takes), an object's selector (a selector fixup on the `mov`); else the source
    (memory, a far pointer in memory, the stack, a register).
  - **Far and 16-bit.** Far calls, jumps and returns and `iret` by opcode; 16-bit code objects, the
    address-size prefix in 32-bit code, selector and 16:16 fixups in code.
  - **Limits.** A value counts only when the same basic block sets it: one loaded from memory,
    passed by a caller or set before a branch target is unresolved, and the summary counts those.
    The containing function is the nearest direct-call target (or gap start) at or before the
    site, a heuristic since LE has no function table.

Written from IBM's [LX - Linear eXecutable Module Format Description](https://www.edm2.com/index.php/LX_-_Linear_eXecutable_Module_Format_Description)
(1992, EDM2's reprint: the header, object table, page table, fixup records and entry table) and the
LE/LX structures in Open Watcom's
[`bld/watcom/h/exeflat.h`](https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h)
(LE's `le_map_entry` and the `OSF_*` constants; Sybase Open Watcom Public License), read as
references; no code of either is in this tool. Checked 2026-11-11 against Theme Park's `MAIN.EXE`
(DOS/4GW stub, three objects, 162 pages ending exactly at the end of the file, 19 746 internal
32-bit offset fixups, all applied; the entry point lands on Watcom's startup and its stores address
the data object), and by `common/rea_suite/test_le.py` on a module built in the test (`uv run
--no-sync python -m unittest rea_suite.test_le rea_suite.test_le_services` in `common/`). `dump-image`
and `services` were checked 2026-11-11 on the same file: one image of 0xd2340 bytes at 0x10000 with
the three objects; 156 430 instructions over 540 929 of 544 235 code bytes in about six seconds
(4 257 of them from gaps), 111 interrupt sites and a table of 256 `int n; ret` stubs, among them
12 INT 31h functions (descriptors: allocate, get/set base, set limit; DOS memory; 0300h; and
AX=2508h), 114 port sites (PIC, PIT, VGA CRTC and DAC) and 886 segment register loads, 563 of them
GS, 449 by `lgs` (Watcom far pointers); the synthetic module in `test_le_services.py` holds a known
sequence of each.

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

## DOS programs: `rea-suite dosbox`

`rea-suite dosbox run PROGRAM [ARG...]` runs a DOS program in DOSBox-X (component `dos`) and writes
what it asks of DOS, the DPMI host, the mouse driver and the video BIOS as JSON lines (stdout, and
`--log FILE`), the way `rea-suite frida` logs a Windows game: for a comparison run of the original
next to a port. The program's folder is drive C: (`--mount DIR` for a folder above it), DOSBox-X runs
headless (SDL's `dummy` video and audio drivers, no MIDI; `--window` shows it) and quits when the
program ends or after `--seconds`. Options come before the program; everything after it is its
arguments.

```sh
rea-suite dosbox info                                        # the binary, its version, debugger: yes/no
rea-suite dosbox run --dpmi --log work/tp.jsonl --seconds 300 work/tp/THEME/MAIN.EXE
rea-suite dosbox run --ints 21:3d,21:3f,31 --returns game/GAME.EXE  # opens, reads, DPMI; results
rea-suite dosbox run --ints '' game/GAME.EXE                 # DOSBox-X's log only (any build)
rea-suite dosbox parse work/dosbox/<run>/dosbox-x.log --program MAIN.EXE  # a log taken elsewhere
```

Records have `t` (seconds since the start) and `kind`:

- **`int`** (the debugger): a call of a traced interrupt (`--ints`, default `21,31,33,10`;
  `INT[:AH[:AL]]` in hex narrows one to a function), with every register, the CPU mode (`rm`, `pm`,
  `v86`), `at` (CS:EIP of the `int`), the service named from `le services`' tables (`function`,
  `service`, DPMI's `group`, the subfunction register) and decoded arguments: the path at DS:DX of
  INT 21h opens, creates, finds, renames and EXEC (DS:SI for 6Ch), the `$` string of 09h, the
  real-mode registers of DPMI 0300h-0302h (`real_mode`, BL the interrupt for 0300h), the handler of
  DPMI 0303h and INT 33h 000Ch. `call` numbers them. A call made from BIOS code (the ROM area,
  DOSBox-X's callbacks at F000h, as when DOS writes a string through INT 10h) is left out unless
  `--nested`. Calls a protected-mode program makes appear in `pm`; an `int` its DPMI host or
  extender then executes in real mode on its behalf appears too, in `rm` at the host's address (a
  host that reflects through the interrupt table without an `int`, as CWSDPMI does, shows none).
- **`return`** (`--returns`): the registers a call returns with (`carry` the CF flag), by `call`.
- **`callback`**: an entry into a real-mode callback, with its registers: the address DPMI 0303h
  returned (`via` `dpmi 0303`, with the protected-mode `handler`) and the handler INT 33h 000Ch
  installed (`mouse 000C`; under DOS/4GW the extender's real-mode call carries the callback it made).
- **`dos-int`, `file`, `log`, `e9`, `message`** (DOSBox-X's log): `dos-int` is each INT 21h that
  reaches DOS (AH, AL) when the debugger does not trace them; `file` the opens, creates, reads,
  writes, seeks and closes by name (`[log] fileio`); `log` any other line (group, severity, text; the
  groups at debug level are `--groups`, default `files,dosmisc,exec,mouse,int10`); `e9` text written
  to port E9h (a program or a patched build can mark its phases there); `message` DOSBox-X's own.
  They carry `cycle`, DOSBox-X's instruction counter, and only the program's part of the log is kept
  (from the DOS open of its file to the shell going back to AUTOEXEC.BAT; `--all` keeps everything).
- **`start`**, **`exit`** (`code`, `timed_out`), **`error`**.

Exit 0 when it ran, 1 when DOSBox-X failed or `--seconds` ended it, 2 when there is no DOSBox-X or
the build has no debugger for `--ints`. The binary is `--dosbox PATH`, else `REA_DOSBOX_X`, else
the one tools.yml installed, else one on PATH. `--dpmi` loads DOSBox-X's built-in CWSDPMI (`Z:\BIN`) first,
for programs that need a DPMI host and bring none (DOS/4GW programs bring their own). `--set
'section key=value'` and `--conf FILE` pass DOSBox-X settings through (`cpu cycles=max`, `dos
ems=false`, ...). The run's folder (`--workdir`, default `work/dosbox/<time>-<program>/`) keeps
DOSBox-X's log and the command line used.

### How it works

Only DOSBox-X's own facilities, nothing patched:

- **The log.** `[log] logfile=` gets every message; `int21=true` adds a line per INT 21h with AH and
  AL (`DOS_21Handler`, src/dos/dos.cpp), `fileio=true` the file operations by name, and each group
  (`files`, `dosmisc`, `mouse`, ...) its messages from the chosen level. The release builds have all
  of it, debugger or not. A line is `%10u%s %s:%s`: the instruction counter, the severity, the
  group, the text (`LOG::operator()`, src/debug/debug_gui.cpp). `bochs debug port e9=true` logs what
  is written to port E9h a line at a time.
- **The debugger.** The program starts under `DEBUGBOX`, which stops at its first instruction. An
  interrupt breakpoint (`BPINT nn`) per traced interrupt then stops before every `int nn`, in real,
  protected and V86 mode (the normal core checks them at the `int` instruction, so the runner sets
  `cpu core=normal`; the dynamic core does not). `BP seg:off` stops at the instruction after a call
  (`--returns`, and for DPMI 0303h, whose result is the callback's address) and at a callback.
- **The control channel.** DOSBox-X's debugger takes commands over TCP: with `[dosbox]
  mcp_server=PORT` it connects to 127.0.0.1:PORT (src/debug/debug_mcp.cpp, SDL_net) and answers
  `REQ <id> EXEC <debugger command>` with `BEGIN <id> OK`, the command's output, `END <id>`. Its
  network thread sends an answer only on its next turn, which comes with the next incoming line or
  after 50 ms, so the runner sends a PING every 2 ms while it waits (and sets TCP_NODELAY on its side;
  without both a round trip costs 40 to 50 ms). A round trip is then about 3 ms.
- **A stop.** The runner reads the registers (`EV EAX EBX ... CR0`) until two reads in a row agree:
  while the emulation runs, each read is answered at a later emulated millisecond (the channel is
  polled from a timer tick), so the state moves; stopped, it stays. The code at CS:EIP
  (`MEMDUMPBIN` to a file in the run's folder) then says what it was: `int nn` for a traced nn a
  call, a return or callback address one of those, `hlt` a CPU waiting while running (no stop). The
  `RUN` that resumes executes the first instruction without checking interrupt breakpoints, so an
  `int nn` right where a return or callback lands is logged at that stop. When the program ends
  (INT 21h 00h, 31h or 4Ch with the program's own PSP) the breakpoints are deleted and the rest runs
  at full speed. A stop costs about 15 ms; the emulated clock stops with it, so the program's own
  timing is unaffected, but the run takes longer (each character DOS prints through INT 10h is two
  stops, if 10h is traced).
- **The terminal.** On Linux and macOS DOSBox-X opens its debugger only with a terminal on stdin,
  stdout and stderr (`isatty`, src/debug/debug.cpp), so it runs on a pseudo-terminal whose output
  (the debugger's curses screen) is read and dropped. On Windows it opens a console of its own; the
  runner starts it in a hidden one.

Limits: a real-mode callback's breakpoint is placed at the next stop in real or V86 mode (in
protected mode the debugger reads BP's segment as a selector), so an entry that comes before any
real-mode stop is missed; the DOS/4GW mouse path is not affected, since the extender's real-mode
INT 33h 000Ch call names the callback. Interrupts a program raises without an `int` instruction
(a DPMI host simulating one through the IVT, as CWSDPMI does for 0300h and for INT 21h from protected
mode) are not seen as calls of their own; 0300h's `real_mode` shows what it asked. Records from the
log and from the debugger are interleaved by when they were read, not by the instruction counter.

### Builds and platforms

| | DOSBox-X | debugger | control channel | checked |
| --- | --- | --- | --- | --- |
| Linux | built from the release's source by `rea-tools` (`platforms/linux/build-dosbox-x.sh`, about 6 minutes on 32 cores): `--enable-debug=heavy`, SDL2 and SDL2_net from its own tree, no FFmpeg or FluidSynth | heavy | yes | 2026-11-11, Ubuntu 26.04 under WSL2 |
| macOS | release zip, the SDL2 app (`dosbox-x-macosx-arm64-*.zip`, `dosbox-x-sdl2/dosbox-x.app`) | heavy (upstream's `build-macos-sdl2`) | expected (SDL2_net) | not run yet |
| Windows | release zip, the Visual Studio SDL2 build (`dosbox-x-vsbuild-win64-*-portable.zip`) | heavy (`vs/config.h`) | expected (`C_SDL_NET`) | not run yet |

The distributions' packages (Ubuntu 26.04's `dosbox-x` 2026.01.02) and the Flathub build are made
without the debugger (no `BPINT` in the binary; Flathub's manifest passes only `--enable-sdl2`), so
`--ints ''` is all they can do. `rea-suite dosbox info` reads the binary for both (the debugger's
and the control channel's strings).

Researched 2026-11-11 against DOSBox-X v2026.10.01's source (github.com/joncampbell123/dosbox-x):
logging in `src/debug/debug_gui.cpp` (`LOG::Init`, `LOG::SetupConfigSection`, `DEBUG_ShowMsg`) and
`include/logging.h`; INT 21h logging in `src/dos/dos.cpp`; file logging in `src/dos/dos_files.cpp`;
the debugger's commands, breakpoints and `DEBUGBOX` in `src/debug/debug.cpp` and
`src/shell/shell_cmds.cpp`; the interrupt breakpoint check in `src/cpu/core_normal/prefix_none.h`;
the control channel in `src/debug/debug_mcp.cpp` and its `mcp_server` setting in `src/dosbox.cpp`;
the build flags in `build-sdl2`, `build-macos-sdl2`, `vs/config.h` and `.github/workflows/linux.yml`;
the release assets from the GitHub releases API; Flathub's `com.dosbox_x.DOSBox-X.yaml`. Its
Windows-only JSON-RPC agent (`docs/rpc-agent-usage.md`, `--enable-dosbox_agent`) is not in release
builds. Two traps found on the way: DOSBox-X's default MIDI device tries a TiMidity server on
127.0.0.1:7777 and can hang in `connect` at startup (the runner sets `mididevice=none`), and with a
program still running a quit asks in a dialog (`quit warning=false`). Checked 2026-11-11 on Linux by
`common/rea_suite/test_dosbox.py`: the log lines, the debugger's answers, the stop handling against a
stand-in debugger, and (opt-in, `REA_DOSBOX_INTEGRATION=1`, nasm and DOSBox-X needed) two programs
the test assembles: a .COM making INT 21h, 10h and 33h calls and writing to port E9h, and a 32-bit
DPMI client under CWSDPMI making INT 31h 0400h, 0300h (INT 21h 09h), 0303h, 0301h into real-mode
code that calls the callback, 0304h and exiting from protected mode (`uv run --no-sync python -m
unittest rea_suite.test_dosbox` in `common/`). Not yet run against a DOS/4GW game.

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
index, `press`, `unplugged`). With `--stdin` it takes its presses live, one a line
(`A+B:0.5`), and unplugs `--tail` seconds after stdin closes: that is how `rea-suite run` below
presses, only while the game's window is in front.

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

## Run harness: `rea-suite run` (Windows)

One bounded, observed run of a Windows program, driven by a script, so a port does not write its
own harness. It starts the program with its arguments, environment and working folder, runs the
script's steps, keeps watching, ends it and writes a report; `--attach NAME|PID` watches a
program started some other way (a launcher) and leaves it running unless `--close`. Under WSL
the front end (`common/rea_suite/run_harness.py`) translates the paths and runs the engine
(`platforms/windows/run-harness.ps1`) in Windows' PowerShell 7 (`pwsh.exe`); on Windows it is
`.\platforms\windows\rea-suite.ps1 run`.

```sh
# 4 minutes of the game, a capture every 30 s, the install proven unchanged
rea-suite run --seconds 240 --capture-every 30 --snapshot /mnt/d/Games/Game \
  --env GAME_DATA=D:\\work\\run1\\data --out /mnt/d/work/run1/observe --start /mnt/d/work/run1/Game.exe -windowed
# a script, message boxes answered, the display taken first where heavy exists
heavy run --display --name "game menu" -- rea-suite run --script menu.steps --answer 'minimum spec=OK' \
  --start 'D:\Games\Game\Game.exe'
rea-suite run --script menu.steps --dry-run --start Game.exe    # any platform: check the script
```

On Windows, quote a program argument that starts with one dash (`'-windowed'`), or PowerShell
takes it for one of its own parameters. `--start` comes last: everything after it is the
program's.

The script, one step a line (`--script FILE`, or `--steps 'wait 5; key ENTER'`), `#` comments:

| Step | Does |
|---|---|
| `wait SECONDS` | pause |
| `at SECONDS` | wait until this long after the start |
| `wait-window [SECONDS]` | until the program has a window (60); fails after |
| `focus` | bring the window to the front; fails when it does not come |
| `key CHORD [hold S]` | keys joined by `+` (`ENTER`, `ctrl+shift+F6`, `GRAVE`, `sc:0x29`, `sc:0xE01C`), held 0.1 s, released in reverse |
| `text "STRING"` | characters (`KEYEVENTF_UNICODE`): for menus and consoles that read characters |
| `click X Y [left\|right\|middle] [hold S]` | at the window's client coordinates, the pixels of a capture |
| `move X Y` | the mouse to client coordinates |
| `pad BUTTONS [hold S]` | a press of `rea-suite pad`'s buttons (`A`, `A+B`, `DOWN`, `LT`, `LX-`); `--pad-dll`, `--idle-pad` |
| `capture [NAME]` | a capture now (`captures/NAME.png`) |
| `close` | end the run now |

What it keeps to, and why (the ports' lessons):

- **Input only into the game.** Keys go out by `SendInput` with scan codes (`KEYEVENTF_SCANCODE`,
  the extended flag for arrows, Insert, Delete and the like): what a game reading raw input or
  DirectInput sees. Before every key down, click and pad press the engine checks that the
  program's window is the foreground window (one focus attempt first); otherwise the step is
  `refused` and the report names the window that was in front. A click also checks that no
  other window covers its point. Alan Wake II found virtual-key-only and posted keys unreliable
  while real foreground mouse input worked, and a stray key once landed in a Game Bar bar.
- **The window stays in front** for the whole run (`--no-keep-front` to leave it): some engines
  only tick while active, and their captures stay black until then (Alan Wake Remastered). Every
  time another program takes the front, the report has a `focus-lost` with that program's name,
  title and window class. The program's own dialogs are left in front.
- **Captures**: `PrintWindow` of the client area first (only the window, whatever covers it), on
  its own thread with a deadline (`--capture-timeout`, 2 s), since it blocks while some games
  load; when it blocks, fails or comes out black and the window is in front, the window's area of
  the screen instead. Each capture records its method, size and whether it is black. Periodic
  (`--capture-every`), on `capture` steps and a `final.png`. The engine is per-monitor DPI aware.
- **Message boxes** (`#32770`) of any process in the program's tree are recorded with title,
  text and buttons, and answered by `--answer BUTTON` or `--answer 'REGEX=BUTTON'` (matched against
  title and text, first rule wins): a button by its text or a standard name (OK, Cancel, Yes, No,
  Retry, Continue, ...), clicked with a posted `BN_CLICKED`, so a hung dialog cannot block the
  engine. A task dialog's text is not readable from outside; it gets `TDM_CLICK_BUTTON`.
- **Samples** every `--sample-every` seconds (5) to `samples.jsonl`: the process tree (children by
  parent id and the job's members), the modules of every process in it (added and removed since
  the last sample; a 32-bit game's own modules too, through `EnumProcessModulesEx`), and its TCP
  connections and UDP endpoints (IPv4 and IPv6).
- **The install unchanged**: `--snapshot DIR` (repeatable) records every file's size and
  modification time and a SHA-256 of executables and DLLs (`.exe .dll .sys .asi .ocx .drv .cpl
  .scr .com`) before and after, links recorded and not followed (`install-before.json`,
  `install-after.json`); any change is an error.
- **Nothing left running.** The program starts suspended inside a job object that kills
  everything in it when the job closes, even when the engine itself dies, and resumes only once
  it is inside. The end is the `close` step, `--seconds` (120) or the program's own exit: the
  window gets `WM_CLOSE` first (the player's way out, so the game and its services end as they
  would), and after `--close-grace` (15 s) the job and every process seen in the tree are killed.
  A process still alive after that is an error (`left-running`).

`--out` (default `work/run/<time>`) holds `plan.json` (what the front end parsed), `events.jsonl`
(every step, capture, dialog, focus change, with `t` in seconds from the start), `samples.jsonl`,
`captures/`, `pad.jsonl` and `pad.err`, and `report.json` (`"format": "rea-suite-run/1"`): the
program, argument list, working folder and the environment's names (never its values), the pid,
exit code (also as hex, an NTSTATUS for a crash), how it ended (`exit`, `wm_close`, `killed`,
`left-running`) and why, timings (start, window after, ended after), the steps with their
status (`done`, `refused`, `failed`, `not-run`), captures, dialogs, focus changes, window titles,
the processes, modules and endpoints seen, the install's changes, and `findings`, worst first.
Exit 0: the run went as scripted; 1: an error finding (a step refused or failed, the install
changed, something left running); 2: a bad script or arguments, no Windows, or the program did
not start.

**The display.** A run with a window needs a connected, unlocked desktop, and it takes the
keyboard, the mouse and the front window. On the shared development machine run it under
`heavy run --display` where `heavy` exists (ci-images): the report says whether the display lock
was held (`display_lock`, from `FALCON_HEAVY_DISPLAY_PID`), and nothing depends on it.

### What it replaces in the Alan Wake ports

| Port script | Now |
|---|---|
| AW2 `focus-owned.ps1` | the `focus` step; the window kept in front for the whole run |
| AW2 `capture-owned.ps1` (PrintWindow) | `capture`, `--capture-every` (PrintWindow first) |
| AW2 `capture-owned-screen.ps1` | the same: the screen area is the fallback while the window is in front |
| AW2 `click-owned-real.ps1` | `click X Y` (SendInput, front verified, the point not covered) |
| AW2 `click-owned.ps1`, `key-owned.ps1` (posted messages) | none: posted input proved unreliable; `click` and `key` |
| AW2 `send-owned-key.ps1` (virtual key) | `key NAME` (scan codes instead) |
| AW2 `send-owned-key-scan.ps1`, `send-owned-enter-scan.ps1` | `key NAME`, `key ENTER` |
| AW2 `hold-owned-key.ps1` | `key NAME hold SECONDS` |
| AW2 `stop-owned-loader-controller.ps1` | none needed: the job object ends everything the run started |
| AWR `run-harness.ps1` | `rea-suite run --seconds 240 --capture-every 30 --sample-every 5 --answer OK --snapshot <install> --env ... --start awr.exe ...`; its `-Pad` schedule as `pad` steps after `at`, its `-Keys` as `key` and `text` steps |

AWR's port-specific parts stay with the port: its environment (`--env AWR_DATA_DIR=... --env
GM_SDK_HOME=...`) and its watch for Epic processes (in the report, any process in the game's tree
is listed; a service started outside the tree is not). The earlier `window-oracle.ps1` is gone:
its pad schedule with captures around each press is `pad` and `capture` steps.

Checked 2026-11-11 from WSL against Windows 11 (PowerShell 7.6, pwsh.exe), with windowless
programs only (`cmd.exe` running `PING.EXE`): the start with arguments, environment and working
folder, the job (the child `PING.EXE` ended with it), samples of the tree and its modules, the
end by timeout with the kill, the program's own early exit (later steps `not-run`), a `key` step
refused without a window, an install change found (exit 1), and `--attach` with `--close`. The
C# compiles under PowerShell 7.6 (.NET 10). Not run here: anything with a visible window (focus,
keys, clicks, text, pad presses, captures, message boxes), since automated checks open no windows
on the shared display; the Win32 calls are the ones the Alan Wake ports' scripts used, except the
PNG writer and the GDI capture, which replace System.Drawing. The step parser, the report and
the snapshot diff are unit tested (`uv run --no-sync python -m unittest rea_suite.test_run_harness`
in `common/`).
