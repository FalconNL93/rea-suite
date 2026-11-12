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
| `table` | `--functions` given | the TSVs' starts and names: `rea-ghidra functions` output, a port's `function_entries.tsv` (starts only) or `functions.tsv` (with a `game` column, picked by `--game`); the address column is the first of `entry`, `address`, `va`, `rva`, `start`, else the first column; `name` and `size` are read when present; a Ghidra control-flow export ([`match`](#a-later-build-match)) too, with each body's ranges. Tables merge, so one can give the starts and another the names |
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

### A later build: `match`

```sh
rea-suite pe match old/Game.exe new/Game.exe \
  --functions re/cfg/Game.exe.cfg.txt --functions-new re/cfg/GameNew.exe.cfg.txt > work/map.tsv
rea-suite pe match old/Game.exe new/Game.exe --functions old.tsv --functions-new new.tsv \
  --header src/addrs.h --header-out work/addrs_new.h --names work/new-names.tsv
rea-suite pe match old/Game.exe new/Game.exe --functions old.tsv --functions-new new.tsv --json
```

Finds the functions and data of a build a port knows in a later build of the same code (a
patch, an expansion, the other of a single and multiplayer pair), x86 or x64. Every function of
both becomes its normalized instructions: mnemonic and operands, with an operand that is an
address inside the image (x64: RIP-relative too) replaced by `A`, so moved code and moved
globals read the same; padding after the last instruction is left out. Then:

1. `same code`: a sequence of four instructions or more that occurs exactly once in each build;
2. `same strings`: a function whose set of referenced strings (four printable characters or
   more) occurs exactly once in each build, which survives code changed around the same messages;
3. `called from`: until nothing new, a matched pair of the same length, or matched by its
   strings, pairs its direct call targets in order when both have as many; a pair of the same
   length pairs its data addresses in order, and each old data address takes the new one most
   of those pairs voted for (`2 of 3 references, UNCERTAIN` when they disagree).

Each side's functions come from `--functions` and `--functions-new` (repeatable, `--game` and
`--game-new` for a `game` column), in the formats of the section above, or from a Ghidra
control-flow export (`F <entry> <name> ...` with `R <first> <last>` body ranges under it, the
`re/cfg/<binary>.cfg.txt` a port's Ghidra script writes), which every `pe` command reads too and whose ranges
give the bodies exactly, chunks elsewhere included. Without a table the unwind table (x64) or
the heuristic gives the starts, and a body runs to the next start: more functions, more of them
guessed. The output is a TSV on stdout: `kind` (`func` or `data`), the old VA, the new VA, how
it was found, and the old table's name; `--json` gives `{"summary", "map"}`, the counts on
stderr. `--header H --header-out F` rewrites each `#define NAME 0x...` of a header for the old
build with its candidate (a comment says function or data and why), a value outside the old
image copied and marked `same: a constant`, and `// NAME: ? (...)` where nothing matched.
`--names F` writes the old table's names (not Ghidra's `FUN_...`) at their new addresses (`address`, `name`, `old`), a
table `--functions` reads for the new build. Exit 0 when a function matched, 1 when none did, 2
on bad input.

A match is a candidate, as the header's are: two functions with the same strings, or a caller
whose callees changed order, can hand a sibling the wrong address. Check what you use in the new
build's code before relying on it. REA's `match_native_functions` pairs two `list_procedures`
inventories by unique exact symbol names and then identical bytes, which suits builds with
symbols or unchanged code; for a stripped later build where code and data moved and functions
changed, use `match`. ghidriff answers the opposite question (what changed between two builds)
and needs both analyzed in Ghidra.

Checked 2026-11-12 against `funcmatch.py`, the port script this came from, on that port's
Ghidra control-flow exports of two pairs of 32-bit MSVC builds (a game and its expansion,
multiplayer and single player): 2,075 of 3,264 functions matched in 13 s (`funcmatch.py`:
2,049) and 2,067 of 3,290 (2,028). No pair differed; of the script's pairs, one was not found,
and both header translations came out the same. The difference is in the strings:
`funcmatch.py` read the bytes at branch targets as strings (a `push imm32` reads as `hPbV`),
which set a few functions apart by chance (the one not found has a twin with the same strings)
and kept others from matching; `match` takes strings from data references only, CR and UTF-16
allowed. Its data map is smaller for the same reason (5,429 pairs against 13,077, nearly all of
the rest branch targets).

### Port scripts these replace

| Port script | Now |
|---|---|
| CoD1 `tools/x86dis.py` (disassemble `ADDR:COUNT`) | `pe disasm <exe> ADDR --count N` |
| CoD1 `tools/mnem_hist.py` (mnemonic histogram of `.text`) | `pe disasm <exe> --histogram` |
| CoD1 `tools/peinfo.py` | `pe info --imports --exports` |
| CoD1 `tools/funcmatch.py` (a known build's addresses in a later one) | `pe match` with the same `re/cfg/*.cfg.txt` exports and header |
| CoD1 `tools/extract_icon.py` (icon group to `.ico`) | `pe resources <exe> --type GROUP_ICON --extract DIR` (same bytes); the port keeps its copy while its build embeds the icon |
| Rogue Spear's pefile script for menus, dialogs and string tables, and `inspect_pe_resources` ([known issue 7](REA-KNOWN-ISSUES.md)) | `pe resources` |
| Rogue Spear's objdump and `resolve_containing_procedure` per `xrefs` hit | `pe refs`/`callers`/`imports` with `--functions re/function_entries.tsv`, `pe disasm` |

Tests: `uv run --no-sync python -m unittest rea_suite.test_pe` in `common/` (synthetic x64 and
x86 programs, two builds of one program for `match`, and a resource section of every decoded
kind, built in `samples.py`; no game bytes).

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

The route for a whole DOS game, from its installer to what a recompilation needs, is
[DOS-GAMES.md](DOS-GAMES.md); this section is the tool's reference.

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
rea-suite dosbox run --ints 21:3d --dump 0:400@exit --dump 1A2B30:0x8000@open:DATA/MAP.DAT \
  --input 't=8:ENTER t=12:mouse:160,100 t=12.5:click' game/GAME.EXE   # memory and input, below
rea-suite dosbox parse work/dosbox/<run>/dosbox-x.log --program MAIN.EXE  # a log taken elsewhere
rea-suite dosbox run --ints '' --regions tp.toml --input-file tp.keys game/GAME.EXE  # the oracle
rea-suite dosbox compare work/dosbox/<run>/regions.jsonl port.jsonl --regions tp.toml   # below
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
- **`dump`**, **`poke`**, **`input`**: what `--dump`, `--poke` and `--input` did (below).
- **`sync`**: a sync point of `--regions` (`sync`, `index`, `hit`, `trigger`, `mode`, `at`, the
  `regions` read, `errors` when some could not be; below).
- A `dump`, `poke` or `sync` that waited for the program's own protected-mode code has `wanted`,
  and when its first stop was elsewhere `moved` (`from`, that stop's CS:EIP, its `mode`, the `stops`
  passed over and the seconds `waited`) and, if it waited in vain, `gave_up` (below).
- **`start`**, **`exit`** (`code`, `timed_out`), **`error`**.

Exit 0 when it ran, 1 when DOSBox-X failed or `--seconds` ended it, 2 when there is no DOSBox-X or
the build has no debugger for `--ints`. The binary is `--dosbox PATH`, else `REA_DOSBOX_X`, else
the one tools.yml installed, else one on PATH. `--dpmi` loads DOSBox-X's built-in CWSDPMI (`Z:\BIN`) first,
for programs that need a DPMI host and bring none (DOS/4GW programs bring their own). `--set
'section key=value'` and `--conf FILE` pass DOSBox-X settings through (`cpu cycles=max`, `dos
ems=false`, ...). The run's folder (`--workdir`, default `work/dosbox/<time>-<program>/`) keeps
DOSBox-X's log and the command line used.

### Memory dumps, pokes and scripted input

For a run with nobody at the keyboard: memory written to files at a trigger, bytes written into
memory, and keys, mouse positions and clicks at times. All three go through the debugger (a build
with it; `--ints ''` keeps tracing off and still opens the channel for them).

Found on Theme Park (DOS/4GW, 2026-11-11): a game without a frame limiter runs its idle timeouts in
frames, so on a fast host an attract demo can start within seconds of a menu; a script acts within a
second there. Its driver space may differ from the picture (640x400 against 320x200): positions are in
the driver's space. Inline `--input` items are separated by white space or `;`.

- **`--dump ADDR:LEN@TRIGGER`** (repeatable) writes LEN bytes (decimal, or `0x` hex) from ADDR into
  `dump-NN-<trigger>.bin` in the run's folder, once, the first time TRIGGER comes, and a record:

  ```json
  {"t": 0.455, "kind": "dump", "addr": "90000", "linear": "00090000", "len": 16, "trigger": "int16", "mode": "pm", "at": "00A7:00000199", "file": "work/dosbox/<run>/dump-01-int16.bin", "sha256": "db44570f..."}
  ```

  ADDR is a linear address in hex (`1A2B30`) or `SEL:OFF` (a selector in protected mode, a segment
  in real and V86 mode: `0168:00012345`, `9000:0010`). `obj<N>+off` (an LE object's runtime base)
  is not supported: under DOS/4GW the objects' bases are decided at load, so take them from the
  trace (the CS:EIP of the program's calls) or `rea-suite le info`. A record whose memory ended
  early has `short` with the bytes read.
- **`--poke ADDR=BYTES@TRIGGER`** (repeatable) writes the bytes (hex: `CA FE`, `cafe`) at ADDR,
  once, before the dumps of the same trigger, with a `poke` record. For a port to set a game's own
  variables (a cheat flag, a level number, a mouse variable a game keeps itself) at a known point.
- **Triggers**: `intNN[:AH[:AL]]` (hex, `int21:3D`) at the program's call of that interrupt, before
  it runs; `open:NAME` at its INT 21h 3Dh or 6Ch open of a file (no case, either slash; the name
  whole or as the path's tail, so `open:data/map.dat` matches `C:\GAME\DATA\MAP.DAT`), before DOS
  opens it, and the record carries the `path`; `t=SECONDS` at that time on the records' clock (the
  same `t`); `input:N` once item N of the `--input` script (counted from 1, in the script's order)
  has been delivered whole, a key's release included, at the next stop (a BREAK); `start` at the
  program's first instruction; `exit` at its INT 21h 00h, 31h or 4Ch, or,
  when `--seconds` ends the run first, at that moment (the record then has `"ended": "seconds"`).
  An interrupt or open trigger adds the breakpoint it needs without logging those calls unless
  `--ints` asks for them. Times are the host's clock, not the emulated one: each traced call
  stops the emulation for about 15 ms, so a run driven by times traces narrowly (`--ints 21:3d`, or
  `--ints ''`) and leaves margins.
- **Where a time or input trigger acts in a protected-mode program.** A BREAK stops wherever the
  CPU is, and in a DPMI program that can be its extender's real-mode side (a key just delivered runs
  the extender's keyboard path there). In real and V86 mode the debugger reads no further than
  10FFEFh and takes a selector for a segment, so a high linear address cannot be read and `SEL:OFF`
  reads the wrong memory. So once the program has run in protected mode (seen in the register
  reads the runner makes while it runs), `t=` and `input:` actions wait for a stop in the program's
  own protected-mode code: its code selector (that of its own last traced call) or, before one is
  known, a 32-bit code segment (DOS/4GW's own code and CWSDPMI's are 16-bit). Until then the
  runner BREAKs again every 50 ms and stops at the program's own INT 21h, 31h, 33h, 16h and 10h
  calls (breakpoints set for the wait; their real-mode reflections are run past), and holds the
  rest of the `--input` script back, so the action never sees input that comes after its moment
  (the script moves back by as much, as for a late item). After 5 seconds without such a stop it
  takes the next stop as it is, and says so (`gave_up`). Any input waits likewise until the actions
  due before it are taken, in any program. A real-mode program's actions act at the first stop.
  A sync point can ask otherwise with `mode` (below).
- **`--input SCRIPT`** (also `--keys`), or `--input-file FILE` (an item a line, `#` comments): items
  `t=SECONDS:ACTION`, on the records' clock, delivered once the program has started (an earlier
  time comes at its start). An item that comes late (`late` in its record) moves the rest of the
  script back by as much, so holds, clicks and the gaps between items keep their length:

  | Action | What |
  | --- | --- |
  | `ENTER`, `ctrl+F6`, `sc:0x29` | a key or a chord, pressed and released after 0.05 s; names as `rea-suite run` takes them |
  | `RIGHT*2` | held for 2 seconds |
  | `"Theme Park"` | typed, a character every 0.08 s (US layout; SHIFT for capitals and symbols) |
  | `mouse:X,Y` | the pointer to X,Y, in the driver's coordinates (what INT 33h 0003h returns) |
  | `move:DX,DY` | the pointer moved by DX,DY from where the driver has it |
  | `click`, `click:right` | a button pressed and released after 0.05 s (left, right, middle) |
  | `down:left`, `up:left` | a button pressed, released (drags: `down`, `mouse`, `up`) |

  Each delivery is an `input` record (`bytes` for keys, `button` and `pressed`, `x` and `y` with
  `at`, the position the driver then reports).

How the input gets in, and why this way:

- **Keys and buttons: DOSBox-X's integration device.** With `[cpu] integration device=true` (set
  when there is input) DOSBox-X has an I/O device at ports 28h-2Ah (src/ints/bios.cpp, registers in
  include/iglib.h) whose register 00804200h puts a byte into the keyboard controller's buffer as
  the keyboard would (set 1 scan codes, what port 60h gives a DOS program, so INT 9 handlers and
  INT 16h see a real key) and presses or releases a mouse button through the INT 33h driver's own
  event path (a polling game sees the button, an event handler gets its event). The runner writes it
  with the debugger's `OUTB`/`OUTD`, so the program is not touched and timing is the runner's.
- **The pointer: the driver's own INT 33h 0004h, run from the debugger.** The same device's mouse
  moves do nothing headless: with `mouse_emulation` at its default the driver puts the pointer where
  the host's pointer is, and the setting only takes effect at an SDL motion event, which SDL's dummy
  video driver never makes (`user_cursor_emulation` in src/gui/sdlmain.cpp, Mouse_CursorMoved in
  src/ints/mouse.cpp; it also drops moves while the debugger is stopped). So at a stop in the
  program's own code (a BREAK, repeated until it lands there: in protected mode the code selector of
  the program's own last call, in real mode its memory, never the extender, the DPMI host, DOS or
  the BIOS) the runner sets AX, CX, DX, has the CPU take INT 33h with the debugger's `INT 33`
  command (an interrupt taken there, with a one-time breakpoint where it returns), and puts the
  registers back: as if the program had called INT 33h 0004h itself, through its DOS extender in
  protected mode. When a position is due the runner stops once (a BREAK) to set an INT 33h
  breakpoint (unless `--ints` traces 33h already; one set while the CPU runs takes effect only at
  the next stop), since a program's own INT 33h call is the best such place: a game that polls the
  mouse gets its position within a frame (about 30 ms in the tests). After half a second without
  one it BREAKs every 50 ms until a stop lands in the program's code (back to back, BREAKs leave
  the program one instruction between them). Absolute and exact (the driver clamps to its range and granularity: multiples of
  8 in text modes), and `move` reads the position with 0003h first. Limits: the driver's mickey
  counters (000Bh) do not change and no movement event reaches an 000Ch handler, so a game that
  reads relative motion does not see a move (the next button event carries the new position);
  for such a game `--poke` its own variables. Placing the pointer can come a second late when the
  program spends its time in the extender (a program that never calls INT 33h itself and runs mostly in its DPMI host).
- **Not used, and why.** `AUTOTYPE` (src/dos/dos_programs.cpp, the mapper's Typer in
  src/gui/sdl_mapper.cpp) types mapper key names from a host thread on the wall clock, with one pace
  for all, and has to start from the shell before the program; it has no mouse. Mapper events have
  no command to fire them. The integration device's moves need the SDL motion event above.
  Changing registers at each INT 33h 0003h return would cost a stop per poll and miss handler games.

Researched 2026-11-11 against DOSBox-X v2026.10.01's source: the integration device in
src/ints/bios.cpp (`dosbox_integration_trigger_write`, `DOSBOX_ID_REG_8042_KB_INJECT`, ports 28h-2Ah,
the `[cpu] integration device` setting in src/dosbox.cpp), include/iglib.h, `KEYBOARD_AddBuffer` in
src/hardware/keyboard.cpp, the INT 33h driver in src/ints/mouse.cpp (`Mouse_CursorMoved`,
`Mouse_ButtonPressed`, functions 0003h and 0004h), the debugger's `MEMDUMPBIN` (`SaveMemoryBin`: one
byte at a time through `GetAddress`, no length limit; offsets wrap at 64 KiB in 16-bit segments, and
the current CS gets its cached base without a limit check, which is how a linear address is read in
protected mode), `SM`, `SMV`, `SR`, `OUTB`/`OUTD`, `SELINFO` and `INT` in src/debug/debug.cpp, the
control channel's `BREAK` and its 1024-line queues in src/debug/debug_mcp.cpp (the runner sends at
most 200 commands before waiting for their answers), and `mouse_emulation` in src/gui/sdlmain.cpp.
Checked 2026-11-11 on Linux by `test_dosbox.py`: the parsing and the trigger handling against the
stand-in debugger, and (opt-in) two programs it assembles, a real-mode .COM and a 32-bit protected-mode
one under CWSDPMI, each writing a pattern at 9000:0000, waiting for a key, resetting the mouse and
polling it until the left button is down: the dumps hold the pattern, the key, the placed position
and the poked bytes, and the scripted click ends the program.

### Named regions at sync points: the oracle (`--regions`, `compare`)

An oracle for a port's game tests: the same scripted input runs in DOSBox-X and in the port, both
read the same named memory regions at the same sync points, in order, and `compare` reports the
first place they part. remc2 (Magic Carpet 2) does this with a DOSBox-X fork
([RECOMPILATION.md](RECOMPILATION.md)); here the runner's debugger reads the memory, so any DOSBox-X
build with the debugger will do.

```sh
rea-suite dosbox run --ints '' --regions tp.toml --input-file tp.keys --seconds 300 \
  --mount work/tp work/tp/THEME/MAIN.EXE        # writes regions.jsonl in the run's folder
rea-suite dosbox compare work/dosbox/<run>/regions.jsonl port.jsonl --regions tp.toml
```

**The regions file** (TOML; JSON with the same keys when its name ends in `.json`) names the regions
and the sync points:

```toml
[regions.money]                 # a name: [A-Za-z0-9_-] reads best, any TOML key works
addr = "0168:0001A2B0"          # as --dump takes it: linear hex, or SEL:OFF (SEG:OFF in real mode)
len = 4                         # decimal, or "0x40"
type = "i32"                    # optional, for display: bytes (default), ascii, u8, i8, u16, i16, u32, i32

[regions.map]
addr = "1A2B30"
len = "0x4000"
ignore = ["0x10:4"]             # optional: OFFSET:LEN ranges `compare --regions` skips (a frame counter)

[[sync]]
name = "level"                  # unique
at = "open:DATA/LEVEL.DAT"      # a trigger, as --dump takes them (intNN[:AH[:AL]], open:, t=, input:N, start, exit)
regions = ["money", "map"]      # optional: every region, in the file's order
repeat = true                   # optional: every call or open is a sync point, not the first only (int and open triggers)
mode = "pm"                     # optional: where its regions are read: auto (default), pm or any (below)

[[sync]]
name = "end"
at = "exit"
regions = ["money"]
```

A run with `--regions` reads each sync point's regions, in the listed order, when its trigger comes,
and appends them to the **sequence file** (`--sequence FILE`, default `regions.jsonl` in the run's
folder), with a `sync` record in the run's log. At one trigger, pokes come first, then dumps, then sync
points.

**`mode`** says where a sync point's regions may be read. `auto` (the default): a `t=` or `input:`
sync point in a program that has run in protected mode waits for a stop in its own protected-mode
code (as dumps do: "Where a time or input trigger acts" above), anything else reads where its
trigger stops. `pm`: always that, from the program's start (a time or input stop moves on to the
next such stop; a call made in real or V86 mode, as the extender's reflection of the program's own
call, is passed over and the program's protected-mode call taken). `any`: where the trigger stops,
as it lands. `start` and `exit` take no `pm`. Each region's line records the stop it was read at
(`mode`, `at`) and how it got there (`wanted`, `moved`, `gave_up`).

**The sequence file** is what a port writes from its own run, so it is specified here. JSON lines,
UTF-8, one object a line:

- **Line 1, the header**: `{"format": "rea-regions", "version": 1}`, plus optional `producer` (who
  wrote it) and `sidecar` (the file name, relative to the sequence file, of the binary sidecar).
  A reader refuses any other format or version.
- **Then a line per region read**, in the order read:

  | Key | | What |
  | --- | --- | --- |
  | `index` | required | the sync point's place in the run, from 0, one more for each sync point; every line of one sync point has the same index |
  | `sync` | required | the sync point's name (the regions file's `name`) |
  | `region` | required | the region's name; once per sync point |
  | `len` | required | the region's length in bytes |
  | `hex` | one of three | the bytes, as lowercase or uppercase hex |
  | `offset` | one of three | where the bytes start in the sidecar (`len` bytes from there); the runner uses this above 4096 bytes |
  | `error` | one of three | the region could not be read (text); `compare` counts it as a difference |
  | `sha256` | optional | of the bytes, lowercase hex; checked when present |
  | `hit` | optional | how many times this sync point has come, this one included (for `repeat`) |
  | `type` | optional | the region's type, for display when `compare` has no regions file |
  | anything else | optional | ignored by `compare`: the runner adds `addr`, `linear`, `mode`, `at` (the stop the region was read at), and `wanted`, `moved`, `gave_up` as in the `sync` record |

  ```json
  {"format": "rea-regions", "version": 1, "producer": "rea-suite dosbox", "sidecar": "regions.bin"}
  {"index": 0, "sync": "level", "hit": 1, "region": "money", "len": 4, "type": "i32", "sha256": "b6c2...", "hex": "10270000", "addr": "0168:0001A2B0", "mode": "pm", "at": "0168:0002F3C1"}
  {"index": 0, "sync": "level", "hit": 1, "region": "map", "len": 16384, "sha256": "4f1a...", "offset": 0, "addr": "1A2B30", "linear": "001A2B30", "mode": "pm", "at": "0168:0002F3C1"}
  ```

A port writes the minimum: the header, then for each sync point, in order, a line per region with
`index`, `sync`, `region`, `len` and `hex`. It reads the same memory its own way (the guest's linear
address in a recompilation, a structure's fields in a rewrite), at the same events: its own handling
of the same INT 21h open, the same INT 16h poll, the same script item.

**`compare A B [--regions FILE] [--context N]`** walks both sequences a sync point at a time and
stops at the first difference: a sync point named differently, a region one side lacks, a region that
could not be read, or differing bytes, outside the `ignore` ranges. It prints the sync point (index,
name and hit), the region, the first differing offset, how many bytes differ, the element of a typed
region that holds it, and N bytes (default 16) each side as hex rows with the first differing byte in
brackets. A sequence that ends early is a difference too. With `--regions` only that file's regions
are compared, with its types and `ignore` ranges. Exit 0 when equal, 1 on a difference, 2 on bad input
(a file missing, not JSON, without the header, a line without its required keys, hex of the wrong
length, a `sha256` that does not match).

```text
1 sync point(s) equal, then:
sync point 1 (end #1), region 'state': offset 0x4 (4), 1 byte(s) differ
 A: u16 [2] = 104
  00000000  0d 1c ff ff[68]00 30 00
 B: u16 [2] = 105
  00000000  0d 1c ff ff[69]00 30 00
```

What makes a good sync point:

- **The program's own calls** (`open:NAME`, `int21:3D`, `int16`, with `repeat`) stop at the same
  instruction in every run, so the memory is comparable byte for byte; they are the oracle's
  backbone. A protected-mode program's own call also stops in protected mode, where a linear `addr`
  reads.
- **`t=SECONDS` and `input:N`** stop wherever a BREAK lands, a few milliseconds of the host's clock
  after the moment (in a protected-mode program, the first such stop in its own code: tens of
  milliseconds, `moved` says how far), and that need not be the same place in two runs; they fit a
  region that holds still (a level's map between moves), not a counter. Found on Theme Park
  (DOS/4GW, 2026-11-12): `input:9` stopped at 0C5D:10B5, in DOS/4GW's real-mode keyboard path, and
  every region failed with "29143C: above what real mode addresses (10FFEFh)", which is why such
  sync points now wait for the program's own code. A `gave_up` line means the program never came
  back to its own code within 5 seconds; sync on a call instead.
- **Keep tracing narrow** (`--ints ''`): each stop costs about 15 ms and DOS/4GW's loading under the
  debugger is slow (DOS-GAMES.md, step 5). A sync point's own triggers set the breakpoints they need.
- **Volatile fields** (a frame counter, a random seed the port seeds differently on purpose) go in
  `ignore` instead of out of the region.

Checked 2026-11-12 on Linux by `test_dosbox_regions.py` (the regions file, the sequence file written
and read, the sidecar, `compare` on synthetic sequences: equal, a difference in the middle, a missing
sync point and region, an unreadable region, types and `ignore`, bad input; the tracer's sync points
against the stand-in debugger, and the wait for protected mode: Theme Park's real-mode stop passed
over for the program's code, input held meanwhile, the program's own calls as stops, a 16-bit
selector refused, giving up, `mode` `any` and `pm`, a call's reflection passed over) and, opt-in,
`test_dosbox.py`'s `RealRun`: the real-mode program above with sync points at its INT 16h call and
its exit, compared with a sequence written for it (equal), then with one byte of the mouse position
changed (exit 1, offset 4); and the 32-bit DPMI program
under CWSDPMI with a sync point at `input:1` reading a block DPMI 0501h placed at linear 400000h:
its first BREAK lands in CWSDPMI's real mode (0824:xxxx), the sync point waits (about 50 ms) and
reads the block in the program's own code (selector A7h). With `mode = "any"` the same sync point
was read where its BREAK landed and failed in both of two runs: in CWSDPMI's 16-bit protected-mode
code (0018:3EDF, "no 32-bit selector covers it") and in its real mode (0824:4059, "above what real
mode addresses").

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

Limits: a linear `--dump` address in protected mode needs a 32-bit CS (a DOS extender's flat
code; otherwise give `SEL:OFF`), and in real and V86 mode reaches 10FFEFh at most: the reads whose
output the control channel returns (`MEMDUMPBIN`, `MEMDUMP`) go through `GetAddress`, which there
is the segment times 16 plus a 16-bit offset; the linear and physical data views (`DV`, `DP`) draw
only into the curses window; `MEMFIND`, the one unbounded read, starts from such an address and
lists a line per byte; and with CR0.PG clear in real mode no page tables are in use to translate a
protected-mode linear address anyway (src/debug/debug.cpp, v2026.10.01, read 2026-11-12). Hence
the wait for protected mode above rather than a read through the paging translation. A real-mode callback's breakpoint is placed at the next stop in real or V86 mode (in
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
