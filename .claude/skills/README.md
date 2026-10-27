# Skills

Process skills for this repository, loaded by Claude Code from this folder. Taken over from the
rogue-spear port (`~/Dev/rogue-spear/.claude/skills`, 2026-10-27), which took them from the Call of
Duty 3 port.

| Skill | Use it for |
|---|---|
| `diagnosing-bugs` | A failing install, update, tool or launcher: build a loop that goes red first, then hypotheses. |
| `grilling` | Stress-testing a plan or design through rounds of questions. |
| `writing-for-agents` | Writing or editing `CLAUDE.md`, `AGENTS.md` or a skill. |

All three were adapted by the CoD3 port from Matt Pocock's [skills](https://github.com/mattpocock/skills)
(commit 49dd158), MIT license: see `LICENSE-mattpocock-skills`. Here `diagnosing-bugs` has this
suite's feedback loops (doctor, clean environments, version rollbacks) instead of a game's, and the
other two point at this repository's files.

Reverse engineering itself is covered by REA's own skill (`reverse-engineer-anything`), which
`rea-suite agents` installs into the agent; it is not duplicated here.

Not taken over: the C++, fuzzing and security-audit skills (this repository has no C++ or network
code) and the port-specific ones.
