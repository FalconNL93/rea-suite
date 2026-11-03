# PS1 / PS2 workflow

Checked: **2026-11-03**. Static preparation; games and emulators are not started.

## Install

Run `rea-suite select`, enable **playstation**, and keep your other components selected.
Selection runs setup. The component adds:

| Tool | Purpose | Linux x86_64 / macOS ARM / Windows x64 |
|---|---|---|
| dumpsxiso / mkpsxiso | Extract 2352-byte CD BIN/CUE; preserve an XML layout for rebuilding | Release binaries |
| ghidra_psx_ldr | PS-X EXE loader, PSX processor/GTE support, PsyQ recognition | Exact-version Ghidra extension |
| Emotion Engine: Reloaded | PS2 EE R5900/MMI/VU0 macro instructions, STABS (bundled x86_64 `stdump`), PCSX2 savestate import | Exact-version Ghidra extension |
| jPSXdec | PS1 audio/video and supported image assets; CLI and GUI | Java JAR; current release is beta and has non-commercial terms |
| 7-Zip | Extract ordinary 2048-byte ISO9660 images, including PS2 DVD data | Already in the base suite |

Loaders use prebuilt releases matching the installed Ghidra; there is no source fallback (the PSX
source lacks its PsyQ signature submodule). Without a matching release, setup reports the loader as FAILED.
Setup preserves upstream module directory names and migrates previously renamed suite extensions.
Deselecting the component stops updates/checks; already installed tools and loaders remain.
Use `rea-suite tools check ghidra mkpsxiso jpsxdec` after setup.

## Prepare a project

One image, directory, or executable per invocation. Use a new output directory each time.
Paths are relative to your terminal's current directory. On Windows use `rea-suite.cmd`.

| Goal | Command |
|---|---|
| Inspect the plan without writing files | `rea-suite playstation game.cue --project work/game --plan` |
| Extract a PS1 CD and import its boot executable | `rea-suite playstation game.cue --project work/game --ghidra` |
| Extract a PS2 DVD ISO and import its EE executable | `rea-suite playstation game.iso --project work/game --ghidra` |
| Use an already extracted game | `rea-suite playstation /path/to/extracted --project work/game --ghidra` |
| Supply a boot path when SYSTEM.CNF is missing | `rea-suite playstation /path/to/extracted --boot SLUS_000.00 --project work/game --ghidra` |
| Prepare without Ghidra | `rea-suite playstation game.iso --project work/game` |

The boot name above is illustrative. Use the actual `BOOT` / `BOOT2` path in `SYSTEM.CNF`.
For split BIN tracks, pass the CUE and keep its referenced files inside the same directory tree.
Raw BIN without a CUE can lose audio-track information. ISO9660 ISO files take the 7-Zip route;
2352-byte CD images take the dumpsxiso route, regardless of filename extension.

| Output | Contents |
|---|---|
| `project.json` | Source/CUE-track SHA-256, file inventory, executable hashes/headers, resolved boot, commands, errors |
| `disc/`, `disc.xml` | Extracted files; layout XML for raw CDs only |
| `ghidra/playstation.gpr` | Editable project when `--ghidra` is used |
| `analysis/functions.tsv`, `analysis/entry.c` | Function inventory and entrypoint pseudocode when available |
| `logs/`, `notes/`, `patches/` | Tool logs and space for your findings/changes |

Extracted-directory inputs stay in place; the project refers to them rather than copying them.
Existing output directories are refused. Failed runs retain `status: incomplete` and their logs.
Extraction/analysis limits default to 600 seconds; use `--timeout` to change them
(Ghidra gets another 120 seconds for import/export overhead). `--max-files` bounds the
inventory, not extracted byte size. Allow space for a full uncompressed image.
Ghidra analyzer errors and unavailable entrypoint pseudocode produce explicit warnings.
Check assembly and logs; a saved project does not establish complete or correct analysis.

## Next steps

- Open the `.gpr` in Ghidra. Follow strings, xrefs, callers, and the entrypoint export.
- Keep EE, IOP/IRX, overlays, and VU microprograms separate. `--ghidra` imports the boot
  program only; it refuses non-R5900 MIPS ELF as an EE boot import. Assets need format-specific parsers.
- PS1 addresses come from the EXE header; PS2 addresses come from ELF mappings. Runtime
  addresses, executable offsets, and disc sectors are different coordinates.
- For PS1 media, index the original BIN with `jpsxdec -f game.bin -x work/game/media.idx`.
- Rebuild a **CD copy** from its layout: `mkpsxiso work/game/disc.xml -o work/patched.bin -c work/patched.cue`.
  Validate LBAs, XA/CDDA, file sizes, and original hashes. This is not a PS2 DVD rebuild command.

For CHD, use an existing [chdman](https://docs.mamedev.org/tools/chdman.html) first:
`chdman extractcd -i game.chd -o game.cue` for CD media, or
`chdman extractdvd -i game.chd -o game.iso` for DVD media. CHD conversion is not installed or automated here.

## REA and remaining tools

Installed REA **6.8.0** has no verified PS-X EXE or PS2 EE profile. Its generic MIPS policy
rejects R5900 machine variants. This command uses Ghidra directly; it does not add MCP tools
or make `rea-suite analyze` support these formats. Track [REA #6746](https://github.com/morluto/rea/issues/6746).

| Candidate | Use next | Integration status |
|---|---|---|
| [PCSX-Redux](https://github.com/pcsx-redux/pcsx-redux) | PS1 breakpoints, RAM, GPU/debugging, runtime validation | External; not installed or launched |
| [PCSX2](https://github.com/PCSX2/pcsx2) | PS2 runtime debugging and savestates | External; not installed or launched; save states for the EE importer must use Deflate64 (PCSX2 2.1.178+ defaults to zstd) |
| [splat](https://github.com/ethteck/splat) | Split PSX/PS2 code/data into a decompilation project | External; needs per-game configuration and a suitable compiler/linker |
| [armips](https://github.com/Kingcom/armips) | Assemble console-specific patches | External; patch layout and ABI remain project-specific |

## Verification and sources

macOS ARM: real release installers in an isolated work directory; synthetic PS1 CD and PS2-style
ISO extraction; actual Ghidra 12.1.4 imports with console languages; function/pseudocode exports;
jPSXdec CLI startup and synthetic-disc indexing. Console imports disable CERT Kaiju Function Hashing, which throws on these processors;
other analyzer/script errors remain explicit warnings.
Linux x86_64 (WSL2, 2026-11-03): unit tests only; the component was not provisioned and no tool or
loader ran. The EE STABS analyzer's `stdump` is x86_64-only (macOS ARM relies on Rosetta 2; unverified).
Linux/Windows tool execution, commercial games, dual-layer DVDs, mixed-mode audio roundtrips, and
emulator integration are **not tested**. The active tool installation was left unchanged.

Upstream: [mkpsxiso](https://github.com/Lameguy64/mkpsxiso),
[PSX loader](https://github.com/lab313ru/ghidra_psx_ldr),
[Emotion Engine: Reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded),
[jPSXdec](https://github.com/m35/jpsxdec).
`update --ai` rechecks this workflow, compatibility, and these limitations.
