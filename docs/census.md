# The interface census: rea-census/1

A game on winrt calls far more than its import table lists: `Direct3DCreate9` is one import and hands
out hundreds of methods through vtables, and PhysX 2.x does the same for its classes. A port learned of
each missing method when the game stopped on it, one at a time. The census lists them up front, from
two sides, in one JSON shape:

| Kind | Written by | Says |
|---|---|---|
| `static` | `rea-suite pe census <exe>` | every interface method and import the executable's code calls, with the call sites, and how many indirect calls it could not resolve |
| `runtime` | winrt's census mode (`src/guest/census.h`) | the methods and imports one run reached, with counts per return address and what winrt answered |
| `answers` | winrt (`census::AnswersJson`) | every method and import winrt has a thunk for, and whether it has a host function |

`rea-suite census diff` joins them: what the game calls (static, runtime or both) that the answers leave
missing or stubbed, by interface. The static side covers paths a run never reached; the runtime side
checks the static side's coverage and catches what it missed.

## The shape

```json
{
  "schema": "rea-census/1",
  "kind": "static",
  "source": {"name": "Yeti_Final_Win32.exe", "sha256": "…", "image_base": "0x400000"},
  "producer": {"name": "rea-suite pe census", "version": "89b717e"},
  "interfaces": [
    {"name": "IDirect3DDevice9", "sdk": "d3d9", "methods": [
      {"slot": 118, "name": "CreateQuery",
       "sites": [{"call": "0x5a1b2c", "return": "0x5a1b2f", "function": "0x5a1a00", "how": "global 0x9f3c10"}]}
    ]}
  ],
  "imports": [
    {"module": "d3d9.dll", "name": "Direct3DCreate9",
     "sites": [{"call": "0x4f0010", "return": "0x4f0016", "function": "0x4effa0"}]}
  ],
  "coverage": {"indirect_calls": 21034, "resolved": 1830, "unresolved": 19204, "note": "…"}
}
```

The rules:

- **Keys.** A method is `(interface, slot)`; an import is `(module, name)`. Names and the other members
  are for people, the diff joins on keys only.
  - `interface`: the SDK's class name as its header spells it (`IDirect3DDevice9`, `ID3DXEffect`,
    `IDirectInputDevice8A`, `NxScene`, `NxActor`). An ANSI and a wide interface are two interfaces.
  - `slot`: the vtable index counted from 0 including the base classes' slots (`QueryInterface` is 0,
    `IDirect3DDevice9::CreateQuery` 118). A call `call [reg+off]` is slot `off / 4`.
  - `module`: the DLL's file name in lower case (`d3d9.dll`). `name`: the export name, or `#<ordinal>`
    (decimal) for an import by ordinal (`dsound.dll` `#11`).
- **`sdk`** names the header the slots come from (`d3d9`, `d3dx9`, `dinput8`, `dsound`, `physx-2.6.4`).
  An interface whose layout changed between SDK versions has one table per version; the diff warns when
  the two sides name different ones. Optional: winrt's runtime and answers files don't carry it yet.
- **Addresses** are `"0x"` strings, VAs in the game's image. `return` is the address after the call
  instruction: the return address winrt sees. `function` is the start of the function the call lies in,
  or null.
- **Kind `static`**: a site is a call instruction. `how` says what tied the object to its interface (a
  global, a field, a function's return value, a parameter, an out-parameter of a factory). `coverage`
  counts the image's `call [reg+off]` instructions, those resolved to an interface, and the rest; the
  census lists only what it resolved, so `unresolved` is how much it may have missed.
- **Kind `runtime`**: a site is a return address with a `count`; the first call's site has
  `"first": true`. Each method and import carries `answer`, what winrt did when the game called it:
  `implemented` (a host function ran), `stub` (it failed on purpose, as `DIERR_UNSUPPORTED`) or `missing`
  (no host function; census mode returned a failure). A run in census mode may take paths Windows would
  not, after such a failure: its list is what the run reached. Census mode can return from a missing
  method only when winrt knows its argument count; a slot without one still stops the run. The suite's
  slot tables (`common/rea_suite/data/census/*.json`, `args` per method, from the SDK headers) give
  those counts.
- **Kind `answers`**: no sites. Each method and import carries `answer`: `implemented`, `stub` or
  `missing` (a thunk without a host function). A method that isn't listed has no thunk, and the diff
  counts it as missing too. `source` names the runtime (`{"name": "winrt"}`, with `"commit"` when the
  build knows its own).
- **Extra members** are allowed anywhere and kept by readers that don't know them. winrt's files carry
  `calls` (an entry's total), `image` and `offset` on a site, `images` (`name`, `base`, `size`) in a
  runtime's `source`, and `game` in `producer`. A reader refuses a
  `schema` other than `rea-census/1`; a change that breaks a reader takes `rea-census/2`.

## Commands

```sh
rea-suite pe census game/Game.exe --functions re/functions.tsv --out work/census.static.json
rea-suite pe census game/Game.exe --functions re/functions.tsv --seed work/game.runtime.json \
    --out work/census.seeded.json                  # the run's calls type their objects too
rea-suite pe census game/Game.exe --unresolved ... # coverage lists the unresolved calls
rea-suite census diff work/game.runtime.json.answers.json work/game.runtime.json work/census.static.json
```

`pe census` runs on the file alone (Capstone, no disassembler project), with the function starts of
`--functions` when given (see [PORT-TOOLS.md](PORT-TOOLS.md)), on 32-bit x86 images. Its seeds are
the factory imports (`Direct3DCreate9`, the `D3DXCreate*` family, `DirectInput8Create`,
`DirectSoundCreate8`, `NxCreatePhysicsSDK`), and per interface the methods that hand out another
interface (`IDirect3D9::CreateDevice` -> `IDirect3DDevice9`, `NxScene::createActor` -> `NxActor`),
from the suite's slot tables. From each seed it follows the pointer through registers, stack slots,
globals, object fields, function returns, parameters and registers passed by link-time code
generation; it learns the game's own classes from the vtables their constructors store and makes
their virtual calls direct ones. Every `call [reg+off]` on an object it tied to an interface is a
site. The module's description (`common/rea_suite/pecensus.py`) says how, and what it misses.

On Windows, the original's own run gives a runtime census of the imports it reached:
`rea-suite frida common/frida/observer.js` with an `imports` config, then `rea-suite census
from-frida <log> --exe <Game.exe>` ([PORT-TOOLS.md](PORT-TOOLS.md#passive-observer)). Its sites are
return addresses at the executable's preferred base, its answers `implemented` (Windows answered).

`census diff` takes the answers first, then any static and runtime censuses. Per interface and per
import it lists what the game calls and the answers leave `missing` or `stub` (`--all`: the answered
ones too; `--json`). An import of a DLL the runtime loaded as the game's own code (Lost's
`binkw32.dll`) counts as answered by it. With a static and a runtime census it adds the static
side's coverage: how many of the run's interface calls from the executable the static census found,
and any it put on another interface. When the answers carry `args` (and `returns_float`) per method and
import, as winrt's do from 604436e, the diff checks each against the slot tables and
`win32-imports.json` and lists every one that differs: a runtime that returns from a missing method
or import by a wrong count pops the wrong number of bytes.

### The slot tables

`common/rea_suite/data/census/{d3d9,d3dx9,dinput8,dsound,physx-2.6.4}.json` (schema
`rea-census-slots/1`), generated by `common/rea_suite/census_slots.py`, never edited by hand:

```sh
uv run python -m rea_suite.census_slots com /usr/i686-w64-mingw32/include      # MinGW-w64's headers
uv run python -m rea_suite.census_slots physx <PhysX_2.6.4_SDK_Core/SDKs> --sdk physx-2.6.4
```

Per interface, in vtable order: each method's name, its argument count without `this` (a PhysX
method returning a class by value counts MSVC's hidden pointer, as winrt's tables do), whether it
returns a float, the interface it returns, the ones it hands out through out-parameters,
QueryInterface's IID and out arguments, and an enumeration's callback and context arguments. The
PhysX headers are preprocessed as a Win32 build (`g++ -E`), and their vtables follow MSVC's layout
(one slot for a virtual destructor, overloads grouped in reverse order). They agree with winrt's
PhysX tables on every slot of its 13 classes and on all 244 argument counts winrt had on 2026-11-15.
The PhysX SDK itself is not in git; the tables carry its headers' SHA-256.

### The Win32 imports table

`common/rea_suite/data/census/win32-imports.json` (`"kind": "imports"`) gives winrt's census mode
what it needs to return from an import it has no answer for: per `module!Name` the argument count
and calling convention, and `returns_float` where a header declares FLOAT or double. Every named
export is listed again as `module!#ordinal`, for games that import by ordinal (wsock32 `#101`,
dsound `#6`). winrt reads it at run time (`<GAME>_CENSUS_IMPORTS`); the static census does not use it.

```sh
uv run python -m rea_suite.census_slots imports /usr/i686-w64-mingw32/lib \
  --dlls /mnt/c/Windows/SysWOW64 --extra <a game's mss32.dll> --include /usr/i686-w64-mingw32/include
```

Counts come from MinGW-w64's i686 import libraries: `_CreateFileA@28` is stdcall with 7 arguments;
an undecorated name is cdecl, its `args` null (the caller cleans). Ordinals come from Windows' own
32-bit DLLs (Windows 11's, read through WSL), Miles's `mss32.dll` from its decorated exports (Call
of Duty's copy; another Miles version may differ). 31,917 entries on 2026-11-15.

## The pilot: Lost: Via Domus (2026-11-15)

`Yeti_Final_Win32.exe` (MSVC 8 with link-time code generation, 187 classes with RTTI and most
engine classes without), with Ghidra's 11,553 function starts (`functions.tsv`), against winrt's
census-mode run from the main menu to the first loading screen (winrt 4fc4de5: 401 interface calls
from the executable, 114 methods):

| | Static | Seeded by the run |
|---|---|---|
| Interface methods found | 123 | 171 |
| Methods the run did not reach | 42 | 61 |
| Indirect calls resolved | 2,048 of 9,724 | 2,194 of 9,724 |
| The run's calls found | 290 of 401 | 365 of 401 (its own sites included) |
| On another interface than the run's | 0 | 0 |

About 2 minutes and 90 MB a run. Of the three methods the port stopped on one at a time:

- `IDirect3DDevice9::CreateQuery` (slot 118): found statically, 2 sites. The device is field 0x10 of
  the renderer behind global 0x8b9108, which `IDirect3D9::CreateDevice` writes through EDI; 1,818
  device calls in 50 methods, `SetRenderState` first (657), the shader constants next.
- `IDirectInputDevice8W::GetObjectInfo` (slot 14): found with the run's seeds, 2 sites. Statically the
  census follows `IDirectInput8W` through `EnumDevices`' callback into the device wrapper's
  `CreateDevice`, which writes `this+0x414`; the wrapper method that calls `GetObjectInfo` reads that
  field through a `this` no vtable the census found ties to the first one.
- `NxActor::createShape` (slot 17): not found. Its call sites use actors kept in game objects
  (`(*(this+0x14))->createShape(desc)`) reached through containers, and the run stopped before
  gameplay. A run that reaches the first level seeds it.

The limit is the game's own classes without RTTI: an object whose class the census cannot tell
(read from an array or a container, passed by callers that disagree) hides the interfaces in its
fields. The static census and the run cover each other: run both, seed the static census with the
run, and diff all three.
