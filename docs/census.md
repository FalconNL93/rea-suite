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
rea-suite pe census game/Yeti_Final_Win32.exe --functions re/functions.tsv > work/census.static.json
rea-suite census diff work/census.static.json winrt-answers.json [work/census.runtime.json]
```

`pe census` runs on the file alone (Capstone, no disassembler project), with the function starts of
`--functions` when given (see [PORT-TOOLS.md](PORT-TOOLS.md)). Its seeds are the factory imports
(`Direct3DCreate9`, the `D3DXCreate*` family, `DirectInput8Create`, `DirectSoundCreate8`,
`NxCreatePhysicsSDK`), and per interface the methods that hand out another interface
(`IDirect3D9::CreateDevice` -> `IDirect3DDevice9`, `NxScene::createActor` -> `NxActor`), from the
suite's slot tables (`common/rea_suite/data/census/`). From each seed it follows the pointer through
registers, stack slots, globals, object fields, function returns and parameters, and files every
`call [reg+off]` on an object it tied to an interface.
