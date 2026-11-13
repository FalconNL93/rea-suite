# Skills

Process skills for this repository. Codex and other agents that follow the `.agents/skills`
convention load them from here, Claude Code through the `.claude/skills` link; an agent without
skill support can be pointed at a `SKILL.md` by path. Taken over from the
rogue-spear port (`~/Dev/rogue-spear/.claude/skills`, 2026-10-27), which took them from the Call of
Duty 3 port.

| Skill | Use it for |
|---|---|
| `diagnosing-bugs` | A failing install, update, tool or launcher: build a loop that goes red first, then hypotheses. |
| `grilling` | Stress-testing a plan or design through rounds of questions. |
| `updating-the-suite` | Planned updates, offline workflows and local-model advice: research compatibility/methods, review examples, console/archive workflows and VRAM recommendations, approve the plan, apply and verify (`rea-suite update --ai`). Written for this suite, not taken over. |
| `writing-for-agents` | Writing or editing `CLAUDE.md`, `AGENTS.md` or a skill. |
| `codebase-design`, `tdd`, `research`, `handoff` | Deep modules and seams, test-first work (`rea-suite check` as the gate), research with sources, a handoff to the next session: templates from games/ci-images, adapted here. |
| `git-guardrails` | The hook that refuses destructive git commands in a shared checkout (`.claude/settings.json`). |
| `work-queue` | Taking this repository's issues (rea-suite, `./ci work`) as the platform's sessions do. |
| `security-audit`, `sharp-edges`, `modern-cpp`, `harness-writing`, `libfuzzer` | The platform's verbatim tier: a security review, footgun APIs, C++ idioms and fuzzing harnesses, for a target's code or the suite's own parsers. |

`diagnosing-bugs`, `grilling` and `writing-for-agents` were adapted by the CoD3 port from Matt
Pocock's [skills](https://github.com/mattpocock/skills) (commit 49dd158), MIT license: see
`LICENSE-mattpocock-skills`. Here `diagnosing-bugs` has this suite's feedback loops (doctor, clean
environments, version rollbacks) instead of a game's, and the other two point at this repository's
files. The verbatim tier and the templates come from games/ci-images' `skills/` (`./ci skills sync
<this checkout> --apply`, with their licenses beside them); `./ci skills status <this checkout>`
says which are behind. ci-images' tool writes through `.claude/skills`, which links here.

Reverse engineering itself is covered by REA's own skill (`reverse-engineer-anything`), which
`rea-suite agents` installs into the agent; it is not duplicated here.
