# To do

Tools still to add to the suite, each with why. An entry moves into the README's tool
tables when it is added (following `AGENTS.md`, "Adding a tool"), or into "Not included"
with the reason when it is dropped.

## Porting old games

- **`pe registry` with integer and object arguments**: today it captures only string arguments of a registrar's
  calls. Capturing a constant integer register argument (the type, as `r8d` in Remedy's tweakable registrar) and the
  `rcx` object would cover registrars like Alan Wake Remastered's 1097 tweakables; the port's own scan
  (`~/Games/awr/tools/tweakables.py`) is the starting point (2026-11-10).
- **BinExport + BinDiff, or Ghidra's Version Tracking documented**: diff two builds or
  patch levels of a game function by function; ghidriff covers single patches, and
  BinDiff's last releases target old Ghidra versions (check again before adding).
- **apitrace and RenderDoc**: graphics traces of the original and the port. RenderDoc
  covers modern APIs only (D3D11/12, Vulkan, OpenGL); DirectDraw and D3D7 games need
  apitrace, or a trace taken after Wine's translation to OpenGL/Vulkan.
- **Kaitai Struct (compiler and visualizer)**: describe a game's file formats once and get
  parsers and a structure viewer from the description.
- **Upstream wishes for REA (rea-agents, not changed from here)**, both found by the Theme Park port
  (2026-11-11):
  - open_binary for LE/LX: REA's own format check refuses an MZ image with an LE header before any
    provider sees it ("unsupported LE executable in MZ image", provider_id=ghidra too), though Ghidra
    loads it through ghidra-lx-loader. Wanted: hand LE/LX to the Ghidra provider when the loader is
    installed. Workaround: `rea-ghidra analyze`, or `rea-suite le dump-image` loaded raw.
  - export_evidence_bundle overwrites an existing file of the same name without asking, and an agent
    lost evidence that way. Wanted: refuse an existing path unless `overwrite` is set, as close_binary
    does. Workaround: a new bundle file name per session.

- **DOS games, from the Theme Park port** (2026-11-11; the route is docs/DOS-GAMES.md):
  - `rea-suite dosbox --profile dos4gw`: skip the extender's own calls, leave INT 21h to DOSBox-X's log,
    narrow INT 31h and set `memsize=64`. Under the debugger DOS/4GW's loading took 2 to 4 minutes at about
    20 ms a stop.
  - A filter or a field for the program's own calls (its flat CS against the extender's), so a log needs no
    post-filtering.
  - An `IN`/`OUT` log for a set of ports (the VGA DAC, the PIT), the last gap between a run and the census.
  - `le services`: a confidence mark on a gap-decoded site (inside a printable run, after an unconditional
    jump). Theme Park's seven `ins`/`outs` sites were all text.
  - A Watcom C runtime FunctionID set (or signatures) for Ghidra, so cstrt386, the heap, int386x and stdio
    are named without doing it by hand.

## Console games

- **PlayStation, from the PS1/PS2 routes** (2026-11-12; docs/PS1.md, docs/PS2.md):
  - PS2 SDK library signatures for Ghidra: ghidra-ps2sdk (abelbriggs1), the analyzer and type databases
    on top of Emotion Engine: Reloaded, answers 404 on GitHub. Look for a fork or another source; a
    FunctionID set built from the open-source ps2sdk would not match Sony's libraries.
  - `rea-suite playstation --overlay FILE@ADDRESS`: import a PS1 overlay or a PS2 IRX/ERX into the same
    Ghidra project at its load address; today only the boot program is imported.
  - armips, maspsx, m2c, asm-differ: none has a release (armips's last is a 2019 32-bit Windows build);
    decompilation projects carry them as submodules. Add one if a port wants it outside a project.
  - psxrecomp, RecompOne (PS1) and PS2Recomp: source-only static recompilers, taken by a port as its own
    dependency. If the suite should build one, it becomes an optional component whose build runs only
    with the user's consent (PS2Recomp needs its submodules, which the suite's source builds do not fetch).
  - A VU microcode disassembler (or Ghidra language) and a PS2 DVD rebuild that keeps the file layout:
    none found.
  - chdman on Windows: MAME's winget package needs an install location the suite's winget list cannot
    give; its release (`mame*b_x64.exe`, a 7-Zip self-extractor) holds `chdman.exe`.

- **ghidra-allegrex (PSP)**: REA 6.8.0 has a PSP Allegrex profile that expects this Ghidra
  extension; kotcrab/ghidra-allegrex publishes exact-version builds (12.1.4 in v21.4). Needs a
  check of its license and REA's expectations before it joins a component.

## Upstream in REA (rea-agents)

rea-agents is REA's npm package from github.com/morluto/rea, not the owner's; the suite installs it
unpatched (one source per tool), so these go upstream as issues or pull requests there.

- **Ghidra startup deadline for large images**: the default 330 s (`DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS`,
  `dist/domain/analysisResourceLimits.js`) is too short for a 12 MB PE, and the CLI's error says only
  "Provider startup deadline elapsed". Upstream: a default that grows with the image's size, or the
  CLI naming `REA_GHIDRA_STARTUP_TIMEOUT_MS` as the MCP error does. Workaround meanwhile:
  [known issues](docs/REA-KNOWN-ISSUES.md), item 9.

- **Keep the analyzed program in a snapshot** (Alan Wake Remastered port, 2026-11-10): a CLI `--snapshot` of a long
  Ghidra import (about 16 minutes for a 12 MB PE) does not save the analysis, so opening it in the MCP session imports
  again from scratch. A snapshot that keeps the analyzed program (or the Ghidra project) would make a big import a
  one-time cost.

- **`pe rtti --slots`: mark shared stubs** (Alan Wake Remastered port, 2026-11-10): when one address fills many slots
  across classes (an ICF-folded one-line stub answering a base's pure virtual), mark the slot `shared-stub` with the
  count, so real overrides stand apart; AWR had 28 such slots among 47 overrides.

- **`rmdp object`: Remedy object data** (Alan Wake Remastered port, 2026-11-11): `rmdp inner` unpacks a level's
  `cid_*`/`dp_*` entries, but reading a script instance's members (its variables) needs Remastered's object model,
  which OpenAWE's 2010 description does not cover. AWR stopped there, having identified its scripted achievement
  calls as level completions (`docs/research/2026-11-11-achievement-unlocks.md` in alan-wake-rm). Worth building
  when another Remedy title needs it.
