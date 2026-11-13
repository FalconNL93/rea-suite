# The suite's documents

Every page in `docs/`, one line each. The main [README](../README.md) covers setup, the tools and the
commands; [AGENTS.md](../AGENTS.md) the rules for working on the suite.

## Routes, per platform

From an original game to what a port, a decompilation or a recompilation needs.

- [PC-WIN32.md](PC-WIN32.md): a 32-bit Windows game onto winrt, from the installer to the first frame.
- [WIN9X-WIN16.md](WIN9X-WIN16.md): the Windows 95, 98 and 16-bit era's traps (installers, CD audio,
  DirectDraw, Glide, palettes, timers, copy protection).
- [DOS-GAMES.md](DOS-GAMES.md): a DOS protected-mode game (Watcom, LE, DOS/4GW), with DOSBox-X as the
  oracle.
- [XBOX-CLASSIC.md](XBOX-CLASSIC.md): an original Xbox game (x86 XBE).
- [XBOX360.md](XBOX360.md): an Xbox 360 game (PowerPC XEX), with Call of Duty 3's lessons.
- [PS1.md](PS1.md): a PlayStation game (R3000A, PS-X EXE and overlays).
- [PS2.md](PS2.md): a PlayStation 2 game (R5900 EE, IOP modules, VUs).

## Tools

- [PORT-TOOLS.md](PORT-TOOLS.md): the suite's own port commands (`pe`, `rmdp`, `yetibig`, `le`,
  `frida`, `dosbox`, `pad`, `run`).
- [PLAYSTATION.md](PLAYSTATION.md): the PlayStation tools, the `playstation` command, and what the
  communities use.
- [GAME-ARCHIVES.md](GAME-ARCHIVES.md): Xbox disc images, ZAR and WUA archives, QuickBMS.
- [EPIC-TOOLS.md](EPIC-TOOLS.md): a plan for `rea-suite epic`, an analyzer for Epic Games Store games
  (not built).
- [ANALYZE-EXAMPLES.md](ANALYZE-EXAMPLES.md): `rea-suite analyze` examples on the owner's games (in
  Dutch).
- [LOCAL-MODELS.md](LOCAL-MODELS.md): local models for reverse engineering, a shortlist.
- [REA-KNOWN-ISSUES.md](REA-KNOWN-ISSUES.md): faults found in REA's tools, with their workarounds.

## Research

- [RECOMPILATION.md](RECOMPILATION.md): what static recompilers, decompilations and reimplementations
  already solved, per platform, and what carries over.

## Audits

Dated reports of checks over the whole suite.

- [audits/2026-11-13-gap-analysis.md](audits/2026-11-13-gap-analysis.md): what the suite is missing,
  against the platform's other repositories.
- [audits/2026-11-13-platform-check.md](audits/2026-11-13-platform-check.md): the routes' claims
  checked against their sources, and the platforms not covered yet.
