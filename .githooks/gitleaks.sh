#!/usr/bin/env bash
# Shared by the hooks: run the suite's gitleaks (tools.yml) with the repository's config.
# Enabled by `rea-suite setup` (git config core.hooksPath .githooks). Bypass a false positive
# with an allowlist entry in .gitleaks.toml, not with --no-verify.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
gitleaks=""
for candidate in "$root/tools/bin/gitleaks" "$(command -v gitleaks 2>/dev/null || true)" \
  "$root"/tools/gitleaks/*/gitleaks.exe; do
  if [[ -n "$candidate" && -x "$candidate" ]]; then gitleaks="$candidate"; break; fi
done
if [[ -z "$gitleaks" ]]; then
  echo "gitleaks not found; run rea-suite setup (or: rea-tools install gitleaks)" >&2
  exit 1
fi
exec "$gitleaks" git --config "$root/.gitleaks.toml" --redact --no-banner --verbose --log-level warn "$@" "$root"
