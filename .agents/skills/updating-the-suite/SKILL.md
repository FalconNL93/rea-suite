---
name: updating-the-suite
description: "Planned update and workflow maintenance of rea-suite: research compatibility, offline analysis methods and local models, propose tool/code/documentation changes, apply after approval. Use for suite updates, analysis-workflow or local-model upkeep, or `rea-suite update --ai`."
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

### Offline analysis workflow

Review this on every run, including when no package has a newer version. Read
`common/rea_suite/analyze.py`, its tests, the README's offline analysis section and
`docs/ANALYZE-EXAMPLES.md`; inspect `rea-suite analyze --help` and `--examples`.
Use the implementation and installed command schemas to establish current behavior.

Research current official REA documentation, workflow instructions and release notes, then
relevant Ghidra, Kuna, Rizin/Cutter, capa, FLOSS, ILSpy and JADX documentation. Compare the
installed version and proposed target separately; upstream main can describe features the
installed release does not have. Revisit the README's research links and look for simpler
supported methods, new capabilities, deprecated flags/APIs and changed platform limits.
Consider new automation tools or upstream workflows; compare their concrete benefit,
platform support and integration/maintenance cost before proposing adoption.

Write `work/update/workflow-review.md`: checked date, installed/target versions, sources,
and one decision per area: retain, improve, replace, or hold with the missing evidence.
Cover:

- Presets and format routing; literal queries, function dossiers and IDE-readable output.
- CLI/Evidence contracts, optional engine settings, target identity, cache invalidation,
  export resume, resource bounds, failure/partial-result reporting and annotation preservation.
- Current advice for patch investigation: address spaces/file offsets, ABI, instruction
  boundaries and runtime verification; distinguish static candidates from validated behavior.
- All documented format/provider lanes and host claims. Verify support on the actual host;
  analyzing another platform's file does not verify execution on that platform.
- Short game recipes: validate available paths and CLI syntax, preserve one goal and one
  command per example, and update the checked date only for paths actually rechecked.
  Use `--plan` for recipe validation; full game analysis needs the user's requested scope.

Done when every area has a source-backed decision and every stale claim has a proposed
correction or an explicit unresolved gap. Put actionable changes in the update plan even
when they require no package upgrade; retain an existing working path when it still fits.

### Self-hosted models

On every run, also read `docs/LOCAL-MODELS.md` and review its recommendations against current
original model cards, release notes, runtime documentation, and quant publishers' file listings.
Record findings in a local-model section of `work/update/workflow-review.md`, even when no
package update is needed. Cover:

- New candidates and retired recommendations for RE interpretation, tool use, and repository edits.
- ChatGPT/Claude reference names, availability and task roles from official provider documentation;
  keep approximate task overlap separate from measured capability or claims of local equivalence.
- Exact publisher, revision, quant filename, combined shard size, and original/derivative licenses.
- Architecture support, chat/reasoning templates, tool parsers, context/KV-cache costs, and host limits.
- Every VRAM row: weight size versus total allocation, initial context, practical usefulness, and
  whether setup effort is justified. Preserve the distinction between loading and completing tasks.
- Evidence quality: publisher benchmarks, calculated fit estimates, and actual local task results
  stay labeled separately. Coding scores alone do not establish reverse-engineering accuracy.

Done when each row and alternative has a retain/change/hold decision with current primary sources.
Update checked dates only for claims actually rechecked; include stale claims and evidence gaps
in the plan. Keep the guide in concise US English. Downloading weights or running hardware
benchmarks needs user-authorized scope; a documentation review does not require either.

## 3. Plan

Write `work/update/plan.md` and show it as a table: part, current, target, decision, reason
(with the source). Every hold names what unblocks it ("Ghidra 12.2 once kaiju has a release for
it"). Include the workflow review's proposed preset, implementation, test and documentation changes.
End with the exact commands you will run, in order.

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

For workflow changes, run `rea-suite lint` and
`uv run --no-sync python -m unittest rea_suite.test_analyze`. When an analysis engine,
command contract, cache or export behavior changes, also run the applicable real-provider
smoke tests with benign fixtures: on Linux/macOS run
`REA_ANALYZE_INTEGRATION=1 uv run --no-sync python -m unittest rea_suite.test_analyze`.
Exercise first export and resume, queries, function output and saved search; keep fixtures in
`work/` and leave the analyzed programs unexecuted. For REA upgrades, also check the
registration adapter's imported APIs with `node --test common/agent-registration.test.mjs`
and `uv run --no-sync python -m unittest rea_suite.test_agents`.

Update the README and short recipes to match verified behavior. Record untested provider
lanes/hosts and failed checks in the workflow review; preserve those limitations in user
documentation. Done when approved changes pass their checks and the review accounts for
every proposed correction, alternative and remaining gap.

## 6. Report and commit

Report per part: from, to, verified by what (command and result); what was held and why.
Summarize workflow and documentation corrections, alternatives considered and unresolved
coverage from `work/update/workflow-review.md`.
Commit as `AGENTS.md` says: lockfile changes (`uv.lock`, `package-lock.json`) on their own, pin
changes in `tools.yml` and the bootstraps with the reason in the body. Ask before pushing.
