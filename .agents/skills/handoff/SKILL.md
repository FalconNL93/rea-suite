---
name: handoff
description: Compact the current session into a handoff document for the next session to pick up.
argument-hint: "What will the next session be used for?"
disable-model-invocation: true
metadata:
  shared-template: handoff@4b471674db9f
---

Write a handoff document that lets a fresh session continue this one's work without reading its
conversation. Save it outside the repository's tracked files: the session's scratchpad folder when
the harness gives one, else the system's temporary folder (`$TMPDIR`, else `/tmp`; `%TEMP%` on
Windows). Print its full path at the end.

It holds:

- **The goal** and where it stands: done, in progress, not started.
- **The state of the checkout**: the branch and worktree, what is committed, pushed or only staged,
  what was left uncommitted on purpose. Several sessions share these checkouts: name the files this
  session changed.
- **The proof so far**: the commands run and their decisive output lines (the gate, the tests),
  and what could not be run and why.
- **What was ruled out**, and how, so the next session does not repeat it.
- **What is running** that this session started (a server, a game, a container), or that it was
  stopped.
- **Open questions and the next step**, the first command to run.
- **Suggested skills**: which skills the next session should load (`.claude/skills/`).

Point at what other artifacts already hold (the plan, the rea-suite issues (`./ci work list --repo FalconNL93/rea-suite`, mirrored in `docs/work/`), commits, a pull request, a doc) by
path or URL instead of repeating it.

Redact every secret (player and master keys, tokens, passwords): write `<REDACTED>`.

If the user passed arguments, they say what the next session will focus on: tailor the document to
that.
