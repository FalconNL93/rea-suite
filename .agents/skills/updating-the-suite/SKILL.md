---
name: updating-the-suite
description: Planned update of rea-suite: check compatibility first, propose which version each part goes to and what holds back, apply after approval. Use when asked to update the suite or its tools, or when started by `rea-suite update --ai`.
---

# Updating the suite

`rea-suite update` moves everything to the newest release blindly. This is the careful variant: a
**plan** first, grounded in evidence, approved by the user, then a targeted update that leaves the
tree green. Read `AGENTS.md` (pins, lockfiles, platforms) before starting. Scratch files go in
`work/update/` (ignored).

On Windows every `rea-suite <cmd>` below is `.\platforms\windows\rea-suite.ps1 <cmd>`; on macOS
`--no-apt` is `--no-brew`.

## 1. Baseline

Run `rea-suite doctor` and `rea-suite status`, and keep both outputs in `work/update/before.txt`.

Done when you have an **inventory**: every part that has a newer version (rea-agents, other npm
packages, Python packages, uv tools, `tools.yml` tools and Ghidra extensions, system packages,
runtimes), each with its current and newest version, plus the list of checks that fail *before*
any change. A failure in the baseline is not caused by the update: report it, keep it apart.

## 2. Compatibility

For every inventory item, decide **update**, **update to an older target** or **hold**, and
collect the evidence behind the decision: release notes, changelogs, the rules below. Done when
every item has a decision with a source a reader can open.

### rea-agents leads

REA verifies exact versions of several engines; the suite follows what the *new* rea-agents
verifies, so look at that version before deciding the rest:

- `npm view rea-agents versions` and the release notes (`npm view rea-agents repository`,
  GitHub releases) from the installed version up to the target; a major bump needs a reason to
  take it now.
- Unpack the target without installing it: `npm pack rea-agents@<v> --pack-destination
  work/update`, then extract. Compare with `node_modules/rea-agents/dist`:
  - `application/GhidraReleasePolicy.js` (`SUPPORTED_GHIDRA_VERSION`, `SUPPORTED_GHIDRA_JAVA_MAJOR`)
    gives the Ghidra pin in `tools.yml` and the JDK major in the three bootstraps.
  - `android/JadxRelease.js` (jadx-headless-mcp), `kuna/KunaRelease.js`
    (`KUNA_VERIFIED_VERSION`); pwndbg and pwntools are named in the tool contracts (grep the
    current pin, e.g. `2026.09.15`, to find the line).
  - `domain/runtimeVersion.js` (`SUPPORTED_NODE_VERSION_RANGE`) against `.node-version`.
  - `package.json` `dependencies` (playwright-core decides the Chromium build; component
    `browser` follows it on its own).

A pinned tool moves to exactly the version the target rea-agents verifies, never further.

### The other parts

- **Ghidra**: a new Ghidra version needs every extension in `tools.yml` (`ghidra-extensions`)
  released for it, or buildable (`build: true`). Check each extension's releases; one that would
  go missing holds Ghidra back, unless the user accepts losing it.
- **Python**: `uv lock --upgrade --dry-run` shows what moves. Watch majors of the packages REA
  drives (pwntools, mitmproxy, frida-tools/objection) and the angr group's pins. frida-server
  follows the frida package by itself (`version: pip:frida`).
- **tools.yml `latest` tools**: a new release can rename its assets; check that each `assets`
  regex still matches exactly one asset of the new release (`rea-tools status` lists the
  versions). Source-built tools (`build:`) rebuild when their version changes: name them in
  the plan, a build takes time.
- **npm, uv tools, system packages, runtimes**: majors and release notes only; minor updates
  go ahead without research.

## 3. Plan

Write `work/update/plan.md` and show it as a table: part, current, target, decision, reason
(with the source). Every hold names what unblocks it ("Ghidra 12.2 once kaiju has a release for
it"). End with the exact commands you will run, in order.

**Stop here.** Done when the user has approved the plan or changed it; apply what they approved,
nothing more.

## 4. Apply

Run the approved parts one by one, each with its own command, so a failure points at one part:

- pins: edit `version:` in `common/tools.yml` with the comment naming what REA verifies, then
  `rea-tools update <tool>`; JDK major: the bootstraps, then `<bootstrap> --runtimes-only --update`
- rea-agents: `npm install rea-agents@<v>`; other npm packages: `npm install <pkg>@<v>`
- Python: `uv lock --upgrade-package <pkg>[==<v>]` per package, then `uv sync` with the
  component groups (`uv run --quiet common/rea_suite/components.py uv-args`)
- uv tools: `uv tool install --upgrade <spec>`; `tools.yml`: `rea-tools update <tool>`
- system packages and runtimes: `rea-suite update` does these together; run it only when the
  plan updates everything in it, otherwise the package manager's own command per package
- afterwards always `rea-suite agents` (the REA skill of the new rea-agents)

A step that fails: stop, report it, and go back to the plan with the user instead of improvising
around it.

## 5. Verify

Run `rea-suite doctor` again. Done when every check that passed in the baseline still passes, each
updated tool starts (`<tool> --version`), and `rea-tools rea-pins` is green. A new failure is
fixed or rolled back (`rea-tools use <tool> <old>`, `git checkout` of the lockfile) before you
report.

## 6. Report and commit

Report per part: from, to, verified by what (command and result); what was held and why.
Commit as `AGENTS.md` says: lockfile changes (`uv.lock`, `package-lock.json`) on their own, pin
changes in `tools.yml` and the bootstraps with the reason in the body. Ask before pushing.
