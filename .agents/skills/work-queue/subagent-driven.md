# Running a task through agents

Adapted from obra/superpowers' `subagent-driven-development` (commit 22f0b46, MIT: `LICENSE-obra-superpowers`
beside the shared skills): its loop and lessons, with the issue as the ledger and our own worktree, branch and
merge commands in place of its workspace and menus.

## The ledger

Conversation memory does not survive compaction. The most expensive failure seen is a session that lost its place
and dispatched work again that was already done. So:

- The issue is the ledger. Its comments record each part as it completes (`Part N: done, <base7>..<head7>, review
  clean` or `..., K parked`), each ruling, and each parked finding. Its mirror (`docs/work/<number>.md`) carries the
  latest comment when the forge is away.
- For notes too long for a comment (a brief, a report, a review package), use files under the worktree's build or
  scratch folder (never `/tmp`, a small shared tmpfs here), named by part: `part-2-brief.md`,
  `part-2-report.md`, `part-2-review.md`.
- After a compaction, read the issue (`ci work show REPO#N`) and `git log` before anything else, and trust them over
  what you remember.

## Setup

- Work in a worktree on a branch, never on master: the repository's own commands (master-server:
  `scripts/dev worktrees`, `scripts/dev branches`; a port: its `tools/<game>.sh`, else
  `git worktree add .claude/worktrees/<name> -b <branch>`).
- Read the plan (the issue's body, the design doc it names) once. Note its binding constraints: exact values,
  formats, names, "the same as X". Conflicts inside the plan resolve against the spec it argues from; with no spec,
  say so in a comment, and treat the rulings as provisional.

## Models

Name the model for every agent. An omitted one inherits the session's, usually the most capable and most costly.

| Role | Model |
|---|---|
| a part whose brief holds the complete code (transcription and tests), a one-file mechanical fix | the cheapest (haiku) |
| a part from a prose description, several files, integration, debugging; every reviewer's floor | the middle (sonnet) |
| design judgment, broad understanding of the codebase; the final review of the whole branch | the most capable (opus) |
| a fix that is stuck after three rounds | one tier above the agent that got stuck |

Turns cost more than tokens: the cheapest models take two to three times the turns on multi-step work, so they are
cheaper only when the work is transcription.

## Per part

1. **Record BASE** (`git rev-parse HEAD`) before dispatching: the review's diff starts there, never at `HEAD~1`,
   which drops all but the last commit of a part.
2. **Dispatch one fresh implementer** with: one line on where the part fits; the brief's path ("read this first:
   it is your requirements, with the exact values"); the interfaces and decisions of earlier parts the brief cannot
   know; your ruling on any ambiguity; the report file's path. Exact values live only in the brief. Never paste the
   history of earlier parts or make it read the whole plan. It does not dispatch agents of its own (a reviewer it
   spawns duplicates yours). Implementers work one at a time on one branch, or in separate worktrees on parts that
   share no files.
3. **Its report** goes to the file; it answers only with its status (done, done with concerns, needs context,
   blocked), its commits, a one-line test summary and its concerns. Answer its questions fully before it builds.
4. **Review the part**: a fresh reviewer gets three paths (the brief, the report, the diff `git log --oneline`,
   `git diff --stat` and `git diff -U10` BASE..HEAD in one file) and the binding constraints copied word for word.
   It gives two verdicts, spec compliance and quality; a review missing one is not a review. Do not pre-judge
   ("do not flag", "at most minor"), and do not ask it to rerun the tests the report already ran.
5. **Fix loop** on a spec failure or an important finding: the same implementer fixes, a scoped re-review checks the
   fix. Three rounds, then one round with a stronger model; after that, rule on what is left (park it with a
   ruling) and go on.
6. **Comment the part done** on the issue in the same step as the rest of the bookkeeping.

## The end

When every part is done, one fresh reviewer on the most capable model reviews the whole branch (BASE of the first
part to HEAD) against the plan; its findings get one fix wave and a scoped re-review. Then the branch goes the
repository's way: its gate, then the merge train (finished branches merged onto one integration branch over
origin/master, one full check, then shipped), and `ci work done` with the commits.

## Rulings and stops

Do not pause between parts to ask whether to go on. Decide conflicts, ambiguities, plan defects and caps yourself,
and record each as `Ruling: what you decided, why, what it costs if wrong`. A wrong ruling costs rework the owner
can see and undo; a session parked on a question costs the day. Stop and ask (`ci work ask-owner`, with options
and a recommendation) only for:

- an irreversible or destructive operation;
- a security-sensitive action;
- an effect outside the worktree that is asked for first: a merge, a push to master, a release, a deploy;
- a plan so broken that every way forward is a guess.

## Waiting

Never poll with short timeouts, and never sit in one open-ended wait. While there is local work (the ledger, the
next brief, reading a report), do it. When idle, wait in stretches of five to ten minutes; between them post one
line of status, list the live agents, and chase any that finished without reporting.

## Excuses

| Excuse | Reality |
|---|---|
| "Close enough on the spec" | A spec gap is not done: fix it or rule on it at the cap. |
| "I'll fix it myself, dispatching is overhead" | It fills your context and skips the review. Send it back to the implementer. |
| "One more round will converge" | Past the cap the failure is structural: rule and go on. |
| "The fix was small, skip the re-review" | Unreviewed fixes are how regressions land. |
| "Ledger comments are overhead" | They are what survives compaction. |
