---
name: work-queue
description: Use at the start of every session, before starting a task, when finishing or blocking one, when a question for the owner comes up, when new work is found, and when running a task through agents. The shared work queue on Forgejo issues (`ci work`), its mirror in docs/work/ for when the forge is away, and running a task with fresh agents and reviews.
---

# Work queue

Every session (the orchestrator, the port sessions) and every agent works from one list: Forgejo issues in the
repository that owns the task, labeled `status/*`, `kind/*` and `session/*`. The issue is the ledger: what was
decided, done and asked lives on it, not in a session's memory.

Run the queue from your own checkout, with your session's name set once:

```sh
export WORK_SESSION=<your session>            # orchestrator, master-sdk, cod1, cod3, rslegacy, theme-park, aw-remastered, aw2, winrt
ci=~/Dev/Falcon/ci-images/ci                   # games/ci-images' checkout, on master
```

## The loop

1. **Start of a session:** `$ci work list --all-repos --session $WORK_SESSION --status doing,ready`. Resume a
   `doing` issue before taking a new one; `$ci work show REPO#N` reads one with its comments, and
   `$ci work comment REPO#N "text"` adds a note (`-` reads it from standard input).
2. **Take before starting:** `$ci work take REPO#N`. Never work on an issue another session is doing; when two
   take it at once, the first wins and the other's `take` exits 1 naming the winner.
3. **Finish with the commits:** `$ci work done REPO#N "what changed, what is left" --commit <sha> ...` (default:
   your checkout's HEAD). `$ci work review REPO#N "what to look at"` when someone should look first.
4. **Blocked:** `$ci work block REPO#N "on what, and what unblocks it"`.
5. **A question for the owner** goes on the issue, not into a message:
   `$ci work ask-owner REPO#N "question; options A, B; I recommend A because ..."`. Then go on with other work.
6. **New work found** goes in as an issue in the repository that owns it, never into your own list or a TODO:
   `$ci work new REPO "title" --body FILE --kind feature|fix|docs|research|chore --session <owner session>`.
   The body says what, why, and when it is done.

`$ci work list --all-repos` is the board: every open issue, grouped by status.

## When the forge is away

Each repository keeps the open issues in `docs/work/<number>.md`, one file per issue (`$ci work sync` writes
them; every `new`, `take`, `done`, `block`, `ask-owner`, `review` and `comment` updates the file of the repository you run
it in). When Forgejo cannot be reached, read those files, and the same commands work on them: a new issue gets
`local-X`, changes are marked pending. Commit the files with your work (docs: no CI run): on a branch only the
files of the issues your work changed, a whole `sync` only on the default branch, since a branch's copies go stale.
Once the forge is back, `$ci work sync` sends the pending changes and renames `local-X`. The forge wins: a pending
change to an issue that changed there is posted as a comment, not applied, and reported as a conflict to look at.

Exit codes: 0 done, 1 refused or a conflict, 2 the forge away and no mirror here, 3 no `FORGEJO_TOKEN`.

## Running a task through agents

When a task splits into parts, run each part through a fresh agent and review it; read
[subagent-driven.md](subagent-driven.md) before the first dispatch. In short:

- **The issue and git are the ledger.** After a compaction, trust the issue's comments and `git log` over memory.
  Write a comment per part done (`Part 2: done, a1b2c3d..e4f5a6b, review clean`) and per ruling.
- **One fresh agent per part**, then a review of that part (spec and quality), then one review of the whole branch.
- **Name the model for every agent**; an omitted one inherits yours.
- **Rule, don't stall.** Decide ambiguities yourself and record each as `Ruling: what, why, the cost if wrong`.
  Stop only for: an irreversible or destructive step, a security-sensitive one, an effect outside the worktree
  that needs asking (a merge, a push to master, a release), or a plan so broken every way forward is a guess.
- **Hand artifacts over as files** (a brief, a report, the diff), not pasted into prompts.
- **Wait in bounded stretches** of five to ten minutes; between them, check every agent and chase one that
  finished without reporting.
