---
name: diagnosing-bugs
description: Diagnosis loop for hard bugs in rea-suite: a failing install, update or tool, a broken launcher or environment, a slow step. Use when the user says "diagnose"/"debug this", or reports something broken, failing, missing or slow.
---

# Diagnosing bugs

A discipline for hard bugs. Skip phases only when explicitly justified.

Read `CLAUDE.md` and the README section of the area first (layout, setup, Ghidra extensions,
Windows and WSL). The environment every tool sees is `common/env.sh` (`platforms/windows/env.ps1`).

## Redact

Tokens (`GITHUB_TOKEN`, agent and service keys) never appear in what you show: write
`<REDACTED>`. Quote only the log lines that carry the signal.

## Phase 1: Build a feedback loop

**This is the skill.** Everything else is mechanical. With a **tight** pass/fail signal that goes
red on _this_ bug, bisection, hypothesis testing and instrumentation all just consume it. Without
one, no amount of reading code will find it.

Spend disproportionate effort here. **Be aggressive. Be creative. Refuse to give up.**

### Ways to build one here, roughly in this order

1. **The failing command itself**, as the user ran it, with its exit code and the exact error:
   `rea-suite setup --no-apt`, `rea-tools install <tool>`, `<tool> --version`, `bin/rea doctor`.
2. **The suite's own checks**: `rea-suite doctor` (exit 1 on problems), `rea-tools check [tool]`
   (offline), `uv sync --check`, `npm ls`. Each names the failing part.
3. **A clean environment**, when it works for you but not elsewhere: the command under
   `env -i HOME=$HOME PATH=/usr/bin:/bin` (what an agent's MCP launch sees), a fresh shell with
   `source ./activate` instead of direnv, or the devcontainer (`.devcontainer/`, a first run from zero).
4. **A differential loop**: the same command on two configurations and a diff: an older tool
   version (`rea-tools use <tool> <version>`), Linux/WSL versus Windows, with and without a
   component (`REA_SUITE_COMPONENTS=...`), the API versus the github.com fallback (`GITHUB_TOKEN`).
5. **A bisection harness**: a script that runs the check and exits 0/1; then `git bisect run` it
   over the suite's commits, or step through tool versions with `rea-tools use`.
6. **Replay**: a saved release page, asset list or archive fed to the code path on its own
   (`rea_suite.github`, `rea_suite.archive`) instead of the network.
7. **A human-in-the-loop script**, last resort: when a person must look (a GUI tool, a Windows
   machine), drive them with `scripts/hitl-loop.template.sh` so the loop is still structured.

Build the right loop, and the bug is 90% fixed.

### Tighten the loop

- Faster: the one tool or step (`rea-tools install <tool>`, a single `uv sync`), not the whole setup.
- Sharper: assert on the exact symptom (this exit code, this log line, this missing file), not
  "did not crash".
- More deterministic: pinned versions (`version:` in `common/tools.yml`), a saved release page
  instead of the live one, an explicit `REA_SUITE_COMPONENTS`.

### Non-deterministic bugs

The goal is a **higher reproduction rate**, not a clean repro: loop the trigger, add load, narrow
the timing. A 50% bug is debuggable; 1% is not yet.

### When you cannot build a loop

Stop and say so. List what you tried. Ask for access to the machine or platform that shows it, a
log or capture, or permission to add temporary instrumentation. Do **not** hypothesise without a
loop.

### Done when: a tight loop that goes red

You can name **one command** you have **already run** (show it and its output), and it is:

- **Red-capable**: it drives the real code path and checks the user's exact symptom.
- **Deterministic**: the same verdict every run (or a pinned high rate for a flaky bug).
- **Fast**: seconds to a minute, not many minutes.
- **Runnable without you**: unattended; a person only through the template script.

Reading code to build a theory before this command exists is the failure this skill prevents.

## Phase 2: Reproduce and minimize

Run the loop and watch it go red. Confirm it is the failure the **user** described, reproducible,
with the exact symptom captured. Then cut the scenario down one element at a time (setting, level,
step, input) until every remaining element is needed: removing any one makes it green.

## Phase 3: Hypothesise

Write **3 to 5 ranked hypotheses** before testing any. Each is falsifiable: "If X is the cause,
then changing Y makes the bug disappear / changing Z makes it worse." A hypothesis without a
prediction is discarded or sharpened.

Show the ranked list to the user before testing; they may rule some out at once. Do not block on
it.

Record each one you rule out and how (the test that falsified it): it is the evidence for the
others, and it goes in the report or the doc so nobody repeats it.

## Phase 4: Instrument

Each probe maps to one prediction. **Change one variable at a time.**

1. The tool's own verbosity: `bash -x` for the shell scripts, `uv -v`, `npm --loglevel verbose`,
   `analyzeHeadless` logs (`rea-ghidra` writes them to `<project>/logs/`), Gradle `--info`.
2. Targeted prints at the boundary that separates hypotheses (the resolved release, the matched
   asset, the launcher's target path, the PATH a process really gets).
3. Never "log everything and grep".

**Tag every temporary log** with a unique prefix, e.g. `[DEBUG-a4f2]`, so cleanup is one grep.

**Performance:** measure first (`time` the step before and after, warm and cold caches), then
find where the time goes, then change one thing and measure again.

## Phase 5: Fix and regression test

Write the check **before the fix**, at the seam that would have caught it: a test in `doctor` or
`rea-tools check` when the fault is a broken installation, an assertion in the installer when it is
a bad download or layout. If no seam fits, the Phase 1 command is the check: say that the seam is
missing.

Then: watch it fail, apply the fix, watch it pass, re-run the original un-minimised scenario, and
on every platform the fix touches (say which ones were not run).

## Phase 6: Clean up

- The original repro no longer reproduces.
- The regression test or scripted check passes.
- Every `[DEBUG-...]` line and throwaway file is gone.
- The cause that turned out right, and the ones ruled out, are in the commit message (plain
  sentences) and, when it is a lasting gotcha, in `CLAUDE.md` or the README.
