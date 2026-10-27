#!/usr/bin/env bash
# Lint this repository's own code: ruff for Python, shellcheck for shell scripts, and a
# parse check for PowerShell where pwsh is installed. Checks the given files, or every
# tracked file without arguments. Used by the pre-commit hook (staged files),
# `rea-suite lint` and the Forgejo workflow; the linters come from the dev group in
# pyproject.toml (.venv).
set -euo pipefail
# macOS: Homebrew's bash (platforms/macos/Brewfile), not the bundled 3.2
((BASH_VERSINFO[0] >= 4)) || exec /opt/homebrew/bin/bash "$0" "$@"

root=$(git rev-parse --show-toplevel)
cd "$root"
venv=.venv/bin
[[ -d "$venv" ]] || venv=.venv/Scripts # Windows (Git Bash)
for linter in ruff shellcheck; do
  [[ -x "$venv/$linter" || -x "$venv/$linter.exe" ]] ||
    { echo "lint: $linter missing; run rea-suite setup" >&2; exit 1; }
done

if (($#)); then files=("$@"); else mapfile -t files < <(git ls-files); fi
py=() sh=() ps=()
for f in "${files[@]}"; do
  [[ -f "$f" ]] || continue
  case "$(basename "$f")" in
    *.py) py+=("$f") ;;
    *.ps1) ps+=("$f") ;;
    *.sh | activate) sh+=("$f") ;;
    *.*) ;;
    *) head -n1 "$f" | grep -qE '^#!.*[/ ](ba)?sh$' && sh+=("$f") ;;
  esac
done

status=0
if ((${#py[@]})); then
  "$venv/ruff" check --quiet "${py[@]}" || status=1
  "$venv/ruff" format --check --quiet "${py[@]}" || status=1
fi
if ((${#sh[@]})); then
  "$venv/shellcheck" "${sh[@]}" || status=1
fi
if ((${#ps[@]})) && command -v pwsh >/dev/null; then
  # shellcheck disable=SC2016 # PowerShell code, expanded by pwsh
  LINT_FILES="$(printf '%s\n' "${ps[@]}")" pwsh -NoProfile -Command '
    $bad = 0
    foreach ($f in $env:LINT_FILES.Trim() -split "`n") {
      $errors = $null
      [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f), [ref]$null, [ref]$errors)
      foreach ($e in $errors) { "${f}:$($e.Extent.StartLineNumber): $($e.Message)"; $bad = 1 }
    }
    exit $bad' || status=1
fi
if ((status)); then echo "lint: problems found (rea-suite lint shows them for every file)" >&2; fi
exit "$status"
