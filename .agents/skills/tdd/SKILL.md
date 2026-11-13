---
name: tdd
description: Test-driven development. Use when building a feature or fixing a bug test-first, when the user mentions "red-green" or "TDD", or when writing integration or game tests.
metadata:
  shared-template: tdd@206721709c9b
---

# Test-driven development

TDD is the **red** → **green** loop. This skill is the reference that makes that loop produce tests
worth keeping: what a good test is, where tests go, the house rules every test here follows, the
anti-patterns, and the rules of the loop. Every section applies on every cycle: consult them before
and during the loop, not after.

Read `CLAUDE.md`'s test rules and `<testing doc>` first, so test names and seams use the
repository's own vocabulary.

## What a good test is

A test verifies behavior through a public interface, not implementation details. The code can
change entirely; the test should not. A good test reads like a specification ("a player with a
banned key is refused at the join") and survives refactors because it does not care about internal
structure. See [tests.md](tests.md) for examples and [mocking.md](mocking.md) for fakes.

## Seams: where tests go, written in the plan

A **seam** is the public interface where you observe behavior without reaching inside. Tests live
at seams, never against internals.

**Test only at seams the plan names.** Before the first test, the plan or design doc of the work
(`docs/...`, or the issue that holds it) lists the seams under test, each with a line on what it catches and what it misses.
That list is the agreement: the owner reads it in the plan, so a session working on its own does not
stop to confirm each test. A seam found during the work goes into the plan first, with its line,
then gets its test. You can't test everything: naming the seams up front puts the effort on the
critical paths and complex logic instead of every edge case.

When the shape of the interface is itself in question (how deep the module is, where the seam
belongs, what it exposes), consult `.claude/skills/codebase-design` for the vocabulary (module,
interface, depth, seam, adapter, leverage, locality).

## The house rules for every test

- **Pass, fail or skip.** A test is a `unittest` case beside the code
  (`common/rea_suite/test_*.py`) or a `node --test` file (`common/*.test.mjs`); it passes or fails.
  One that needs a real tool, a sample or a platform skips with the reason (`skipUnless` on a
  `REA_*_INTEGRATION` or `REA_*_SAMPLE` switch, `skipIf` on the platform), never to hide a failure.
  A stand-in for an external program (as `test_rea_ghidra`'s `analyzeHeadless`) records what it was
  given, so the test checks the call, not the program.
- **A time limit.** Every test is bounded (the runner's per-test limit or the test's own deadline),
  so a hang fails with what it awaited instead of blocking the gate.
- **Wait for events, not for time.** A test waits for the state or the log line it needs, never
  for a fixed sleep: a sleep is too long on a fast machine, too short on a slow one, and adds up
  over every run. What the test needs and the tool cannot report yet is added to its output (a log
  line, a JSON field).
  A sleep whose time is the point (a measuring window, a per-second limit) says so on its line
  (`# timed: <why>`).
- **It can go red.** A test that checks what it just wrote, or loops over nothing, is not a test.
  Expected values come from an independent source: a known literal, a recorded result, the spec.

## Anti-patterns

- **Implementation-coupled**: it fakes internal collaborators, tests private functions, or verifies
  through a side channel (reading a database or guest memory instead of using the interface). The
  tell: it breaks on a refactor when behavior has not changed.
- **Tautological**: the assertion recomputes the expected value the way the code does, so it passes
  by construction and can never disagree with the code.
- **Horizontal slicing**: writing all tests first, then all implementation. Bulk tests verify
  _imagined_ behavior, test the shape of things instead of what a player or caller sees, and fix the
  test structure before you understand the implementation. Work in **vertical slices**: one test,
  one implementation, repeat, each test a **tracer bullet** that answers what the last cycle taught
  you.

## Rules of the loop

- **Red before green.** Write the failing test first and watch it fail for the reason you expect;
  then write only enough code to pass it. Don't anticipate later tests or add speculative features.
- **One slice at a time.** One seam, one test, one minimal implementation per cycle.
- **Refactoring is not part of the loop.** It comes after green, as its own change, with the tests
  unchanged.
- **Done when** every seam the plan names has its test, each was seen red and then green, and the
  repository's gate (`rea-suite check`) passes.
