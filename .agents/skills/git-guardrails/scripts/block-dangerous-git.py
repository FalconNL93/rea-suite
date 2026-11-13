#!/usr/bin/env python3
"""Claude Code PreToolUse hook: refuses a Bash command that would destroy work in a checkout several sessions share.

Refused: git reset --hard; git clean -f (unless a dry run); a checkout, restore or switch that discards changes;
git branch -D (or -d --force) of a branch not merged into HEAD or origin's default branch; any force push (--force,
-f, --force-with-lease, --force-if-includes, --mirror, a +refspec); git stash pop, clear, and drop without naming
an entry. A plain git push, and git stash drop stash@{n} of a session's own entry, are allowed. It reads the
hook's JSON on stdin and exits 2 with the reason on stderr to refuse, 0 to allow.

A guardrail against mistakes, not a security boundary: it reads the command as a shell would split it (also inside
bash -c and eval, after cd), not what a script it runs does. Standard library only.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys

SEPARATORS = {"&&", "||", ";", "|", "&", "(", ")", ";;", "|&", "{", "}", "!"}
WRAPPERS = {"sudo", "command", "env", "nice", "nohup", "time", "exec", "builtin"}
SHELLS = {"bash", "sh", "zsh", "dash"}
# git's global options that take a value as the next word.
GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
SHARED = "several sessions share this checkout and its stash"


def segments(command: str) -> list[list[str]]:
    """The simple commands of a shell line: words split as the shell would, at its operators and newlines."""
    # A newline ends a command; a backtick starts or ends one (inside quotes too: harmless for what is looked for).
    line = command.replace("\n", " ; ").replace("`", " ; ")
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        words = list(lexer)
    except ValueError:  # an unbalanced quote: split on blanks rather than let it through unread
        words = line.split()
    found, current = [], []
    for word in words:
        if word in SEPARATORS or word == "$":  # $( splits into $ and (
            if current:
                found.append(current)
            current = []
        else:
            current.append(word)
    if current:
        found.append(current)
    return found


def git(cwd: str, *args: str) -> bool:
    try:
        done = subprocess.run(["git", "-C", cwd, *args], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def flags(args: list[str]) -> set[str]:
    """The options among args: long ones as written (up to =), short clusters split (-fd: -f, -d)."""
    found = set()
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("--"):
            found.add(arg.split("=", 1)[0])
        elif arg.startswith("-") and len(arg) > 1:
            found.update(f"-{c}" for c in arg[1:])
    return found


def positionals(args: list[str], takes_value: set[str] = frozenset()) -> tuple[list[str], list[str]]:
    """The non-option words before --, and the words after it; an option in takes_value consumes the next word."""
    before, skip = [], False
    for i, arg in enumerate(args):
        if skip:
            skip = False
        elif arg == "--":
            return before, args[i + 1 :]
        elif arg.startswith("-") and len(arg) > 1:
            skip = arg in takes_value
        else:
            before.append(arg)
    return before, []


def merged(cwd: str, branch: str) -> bool:
    """The branch's commit is in HEAD or in origin's default branch."""
    if not git(cwd, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"):
        return True  # no such local branch: git refuses it by itself
    targets = ["HEAD", "refs/remotes/origin/HEAD", "refs/remotes/origin/master", "refs/remotes/origin/main"]
    return any(git(cwd, "merge-base", "--is-ancestor", f"refs/heads/{branch}", t) for t in targets)


def check_git(args: list[str], cwd: str) -> str | None:
    """Why this git command is refused, or None."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            cwd = os.path.join(cwd, args[i + 1])
        i += 2 if args[i] in GIT_VALUE_OPTIONS else 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1 :]
    opts = flags(rest)

    if sub == "reset" and "--hard" in opts:
        return "git reset --hard discards uncommitted changes; use git reset --keep <commit>, which keeps them"
    if sub == "clean" and opts & {"-f", "--force"} and not opts & {"-n", "--dry-run"}:
        return "git clean -f deletes untracked files; list them with git clean -n and remove your own by name"
    named_drop = bool(rest) and rest[0] == "drop" and bool(positionals(rest[1:])[0])
    if sub == "stash" and rest and rest[0] in ("pop", "drop", "clear") and not named_drop:
        return (
            f"git stash {rest[0]} changes the stash stack other sessions use too; "
            "use git stash apply stash@{n} on your own entry, then drop it by name: git stash drop stash@{n}"
        )
    if sub == "push":
        refspecs, _ = positionals(rest, {"--repo", "-o", "--push-option", "--receive-pack", "--exec"})
        if opts & {"-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror"} or any(
            r.startswith("+") for r in refspecs[1:]
        ):
            return "a force push rewrites a shared branch; push a new branch instead"
    forced_delete = "-D" in opts or (opts & {"-d", "--delete"} and opts & {"-f", "--force"})
    if sub == "branch" and forced_delete:
        names, _ = positionals(rest)
        unmerged = [name for name in names if not merged(cwd, name)]
        if unmerged:
            return (
                f"{', '.join(unmerged)} is not merged; git branch -d deletes a merged branch, and a squash-merged one "
                "goes through the repository's branch prune command (master-server: scripts/dev branches prune --apply)"
            )
    if sub == "restore" and (not (opts & {"-S", "--staged"}) or opts & {"-W", "--worktree"}):
        return "git restore discards changes in the working tree; edit the file back, or restore --staged"
    if sub == "switch" and opts & {"-f", "--force", "--discard-changes", "-C", "--force-create"}:
        return "this git switch discards changes or resets a branch; commit first, or switch without forcing"
    if sub == "checkout":
        if opts & {"-f", "--force", "-B"}:
            return "this git checkout discards changes or resets a branch; commit first, or check out without forcing"
        before, paths = positionals(rest, {"-b", "--orphan"})
        if paths or len(before) > 1 or "." in before:
            return "git checkout with paths discards their changes; edit the files back instead"
        if before:  # one word: a branch to switch to, or a path whose changes it would discard
            target = before[0]
            is_ref = git(cwd, "rev-parse", "--verify", "--quiet", f"{target}^{{commit}}")
            if not is_ref and os.path.exists(os.path.join(cwd, target)):
                return f"git checkout {target} discards its changes; edit the file back instead"
    return None


def check(command: str, cwd: str) -> str | None:
    for words in segments(command):
        while words and (("=" in words[0] and not words[0].startswith("=")) or words[0] in WRAPPERS):
            words = words[1:]
        if not words:
            continue
        name = os.path.basename(words[0])
        if name == "cd" and len(words) > 1:
            cwd = os.path.join(cwd, os.path.expanduser(words[1]))
        elif name == "git":
            reason = check_git(words[1:], cwd)
            if reason:
                return reason
        elif name in SHELLS and "-c" in words[1:-1]:
            reason = check(words[words.index("-c", 1) + 1], cwd)
            if reason:
                return reason
        elif name == "eval":
            reason = check(" ".join(words[1:]), cwd)
            if reason:
                return reason
    return None


def script_path(project: str | None = None) -> str:
    """This script as the repository names it (.claude/skills/git-guardrails/scripts/block-dangerous-git.py, from
    the project's root), or its full path outside the project."""
    here = os.path.realpath(__file__)
    root = os.path.realpath(project or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    return os.path.relpath(here, root) if here.startswith(root + os.sep) else here


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    if event.get("tool_name", "Bash") != "Bash":
        return 0
    command = (event.get("tool_input") or {}).get("command") or ""
    reason = check(command, event.get("cwd") or os.getcwd())
    if reason:
        print(f"BLOCKED ({script_path()}): {reason}. It is refused because {SHARED}; "
              "if it must run, ask the user to run it.", file=sys.stderr)  # fmt: skip
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
