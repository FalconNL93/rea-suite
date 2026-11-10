# Known issues in REA (rea-agents)

Faults found while using REA's MCP tools on real targets, kept here instead of reported upstream
(github.com/morluto/rea) for now. They live in the `rea-agents` npm package, not in the suite: the
suite does not patch `node_modules` (one source per tool), so each entry has a workaround. Check an
entry against a newer rea-agents before relying on it, and remove it once it is fixed there.

Found with rea-agents 6.8.0 (the latest on npm on 2026-11-06) and the pinned Ghidra, by the Rogue Spear
port on `R6BO.exe` and `R6BOEditor.exe` (2026-11-05/06).

## Reproduced

Reproduced with a 15 KB i686 PE built with mingw, by asking for a procedure at an address in `.data`
(`bin/rea decompile t.exe 0x403010 --provider ghidra --format json`).

1. **The wrong error code for an address that is not a function.** `procedure_pseudo_code` at an
   address with no function returns `invalid_request` instead of `not_found`. The Ghidra bridge does
   raise `not_found`; `dist/ghidra/GhidraProviderClient.js` (about lines 612-616) turns a remote
   `invalid_request`, `not_found` or `ambiguous` into `AnalysisInputError`, which is reported as
   `invalid_request`.
2. **A virtual address is reread as a file offset.** In the same case, `resolveDecompileProcedure` in
   `ReaGhidraBridge.java` (about lines 973-1025) falls back from a bare `0x` value that is not a
   procedure to reading it as a file offset, so the message says "File offset 0x684c20 has no loaded
   source mapping" when the caller meant a virtual address. `resolveProcedure` already has the right
   `not_found` message; this fallback hides it.
3. **The whole Ghidra log in the error.** The error's `details.diagnostics.stdout.text` and
   `stderr.text` carry the entire headless log: 1.85 MB on `R6BO.exe`, all of it in the agent's
   context. They come from `ghidraDiagnosticStream` in `dist/ghidra/GhidraDiagnostics.js`, whose
   budget is `GHIDRA_PROCESS_DIAGNOSTIC_BYTES` (8 MiB). No setting bounds it. `ghidra_log_path` and
   `script_log_path` are already in the details, so a short tail and those paths would be enough.

**Workaround:** call `resolve_containing_procedure` first, then decompile the procedure it returns
(`batch_decompile`); never ask for pseudocode at a bare address that may not be a function start.

## Reported, not yet reproduced

4. **`batch_decompile` has no `document` parameter**, so with several binaries open it cannot say
   which one it means.
5. **Opening a second binary replaces Ghidra's active program.** A later call with
   `document=R6BO.exe` failed with "Unknown Ghidra Program identity ... active program:
   target-<hash>.exe", again with about 600 KB of log in the error (item 3).
6. **`close_binary` takes no `document`**, so an agent cannot close only its own binary.
7. **`inspect_pe_resources` is too large and too shallow:** its output is very large, and it does not
   decode menus, dialogs or string tables (pefile does).
8. **Ghidra's string list misses three-letter strings**, such as file extensions.

**Workaround:** one binary per REA session (one agent each), or `rea-ghidra --project <project>` for
headless Ghidra directly, and `objdump` / pefile for PE resources and short strings. Both worked on
Rogue Spear.

## Large images outlast the Ghidra startup deadline

Found with rea-agents 6.8.0 by the Alan Wake Remastered port (2026-11-10): opening an 11.9 MB PE in
REA's Ghidra provider, and earlier a 5 MB statically linked executable on a loaded machine, failed
after REA's default Ghidra startup deadline of 330 s (`DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS` in
`dist/domain/analysisResourceLimits.js`): the import and auto-analysis count as startup. The MCP
error names the remedy; the CLI says only "Provider startup deadline elapsed".

9. **The default deadline does not grow with the image, and the CLI does not name the setting.**

**Workaround:** raise the deadline before the first open of a large image, and keep the analysis
so it is paid once:

- CLI and a newly started MCP server: `REA_GHIDRA_STARTUP_TIMEOUT_MS` in the environment (`.env`, or
  for one run `REA_GHIDRA_STARTUP_TIMEOUT_MS=3600000 rea ...`, an hour).
- A running MCP server: `update_analysis_settings` with `ghidra.startup_timeout_ms`; it applies at the
  next provider startup, so close the binary (`close_binary`) and open it again.
- On a shared machine, run the first, heavy import through its heavy-run gate (`heavy run`, from
  games/ci-images, where installed) and keep a snapshot, so later calls reuse its answers:
  `heavy run --name rea-ghidra -- rea analyze game/Game.exe --provider ghidra --snapshot work/game.snapshot`
  (REA snapshots cache answers, not the Ghidra database).
- For scripted work on a big image, `rea-ghidra analyze` (no deadline) keeps a Ghidra project
  that later queries open read-only; `rea-suite pe` answers RTTI, reference and caller questions
  from the bytes without any analysis ([port tools](PORT-TOOLS.md)).
