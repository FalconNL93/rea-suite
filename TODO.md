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
- **objdiff**: per-function match of recompiled code against the original object code,
  the way decompilation projects check progress.
- **apitrace and RenderDoc**: graphics traces of the original and the port. RenderDoc
  covers modern APIs only (D3D11/12, Vulkan, OpenGL); DirectDraw and D3D7 games need
  apitrace, or a trace taken after Wine's translation to OpenGL/Vulkan.
- **Kaitai Struct (compiler and visualizer)**: describe a game's file formats once and get
  parsers and a structure viewer from the description.
- **DOSBox-X with its debugger**: run and debug DOS-era games and their installers.
- **`rea-suite dosbox`**: a wrapper around DOSBox-X's debugger as an analysis aid for DOS games: log
  the INT calls (DOS, DPMI, the extender's) and real-mode callbacks of a run as JSON lines, the way
  `rea-suite frida` logs a Windows game. Wanted by the Theme Park port (2026-11-11).
- **REA's open_binary for LE/LX**: Ghidra loads LE through ghidra-lx-loader (`rea-ghidra analyze`), but
  REA's own format check refuses an MZ image with an LE header before any provider sees it
  ("unsupported LE executable in MZ image", provider_id=ghidra too, 2026-11-11). Wanted in rea-agents:
  pass LE/LX to the Ghidra provider when the loader is installed, so MCP sessions open DOS/4GW games.

## Console games

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
