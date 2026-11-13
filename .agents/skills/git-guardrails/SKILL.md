---
name: git-guardrails
description: Set up a Claude Code hook that blocks destructive git commands (reset --hard, clean -f, discarding checkout or restore, branch -D of unmerged work, force push, stash pop/clear) before they run. Use when adding git safety hooks or preventing destructive git operations in a shared checkout.
metadata:
  shared-template: git-guardrails@370351ec0115
---

# Git guardrails

Installs a PreToolUse hook that refuses destructive git commands before Claude runs them. Several
sessions and their agents share these checkouts, their index and their stash stack: one session's
`git reset --hard` or `git stash pop` destroys or steals another's work in progress.

## What is refused

- `git reset --hard`
- `git clean -f` in any form (`-fd`, `-xdf`, `--force`), unless a dry run (`-n`)
- a checkout, restore or switch that discards changes: `git checkout -- <path>`, `git checkout .`,
  `git checkout <file>`, `git checkout -f` / `-B`, `git restore <path>` (not `--staged` alone),
  `git switch -f` / `--discard-changes` / `-C`
- `git branch -D` (or `-d --force`) of a branch not merged into HEAD or origin's default branch
- any force push: `--force`, `-f`, `--force-with-lease`, `--force-if-includes`, `--mirror`, a
  `+refspec`
- `git stash pop`, `git stash clear`, and `git stash drop` without naming an entry (`git stash drop stash@{n}` of
  your own entry is allowed)

A plain `git push` (to master too) is allowed: the owner allows pushing. Refused, Claude sees the
reason and the safe alternative, and asks the user when the command must run anyway.

It reads the command as the shell splits it (also after `cd`, inside `bash -c` and `eval`, in
`$(...)`), so `git commit -m "undo the reset --hard"` passes. It is a guardrail against mistakes,
not a security boundary: what a script does inside is not seen.

## Steps

### 1. The hook script

The script is [scripts/block-dangerous-git.py](scripts/block-dangerous-git.py) (Python 3, standard
library only). It runs from this skill's folder: nothing to copy.

### 2. The hook in `.claude/settings.json`

The guardrails are on in every repository, through the committed `.claude/settings.json`, so every
session in the checkout gets them. `./ci skills sync <repo> --apply` (games/ci-images) merges this entry
into the file's `hooks.PreToolUse`, creating the file when it is missing and keeping every other setting;
`./ci skills status` reports "guardrails hook not wired" while it is absent. By hand:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I \"$CLAUDE_PROJECT_DIR/.claude/skills/git-guardrails/scripts/block-dangerous-git.py\""
          }
        ]
      }
    ]
  }
}
```

The path is the repository's own (`$CLAUDE_PROJECT_DIR` is its root), never a machine's.

### 3. Adapt it

Add a refusal the repository needs (a command of its own that discards work) to `check_git` in the
script, with its reason and alternative; never refuse a plain push.

### 4. Verify

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | python3 -I .claude/skills/git-guardrails/scripts/block-dangerous-git.py; echo "exit $?"
echo '{"tool_name":"Bash","tool_input":{"command":"git push origin master"}}' | python3 -I .claude/skills/git-guardrails/scripts/block-dangerous-git.py; echo "exit $?"
```

The first prints a BLOCKED line and exits 2; the second exits 0. Done when both hold and the hook is
in the committed `.claude/settings.json`.
