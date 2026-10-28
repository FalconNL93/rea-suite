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
| `updating-the-suite` | A planned update: compatibility first, a plan the user approves, then a targeted update (`rea-suite update --ai` starts it). Written for this suite, not taken over. |
| `writing-for-agents` | Writing or editing `CLAUDE.md`, `AGENTS.md` or a skill. |

All three were adapted by the CoD3 port from Matt Pocock's [skills](https://github.com/mattpocock/skills)
(commit 49dd158), MIT license: see `LICENSE-mattpocock-skills`. Here `diagnosing-bugs` has this
suite's feedback loops (doctor, clean environments, version rollbacks) instead of a game's, and the
other two point at this repository's files.

Reverse engineering itself is covered by REA's own skill (`reverse-engineer-anything`), which
`rea-suite agents` installs into the agent; it is not duplicated here.

Not taken over: the C++, fuzzing and security-audit skills (this repository has no C++ or network
code) and the port-specific ones.
