#!/usr/bin/env bash
set -euo pipefail

cd "$HOME/Dev/rea"

get_version() {
  node -p "require('./node_modules/rea-agents/package.json').version" 2>/dev/null || echo "none"
}

OLD_VERSION=$(get_version)

echo "[$(date -Is)] Checking REA updates..."
npm install rea-agents@latest --save --no-audit --no-fund

NEW_VERSION=$(get_version)

if [[ "$OLD_VERSION" != "$NEW_VERSION" ]]; then
  echo "[$(date -Is)] REA updated: $OLD_VERSION -> $NEW_VERSION"

  echo "[$(date -Is)] Force updating MCP and skills..."
  ./node_modules/.bin/rea setup \
    --client claude_code \
    --client codex \
    --yes \
    --force

  echo "[$(date -Is)] Update completed."
else
  echo "[$(date -Is)] REA already up to date ($NEW_VERSION). Skipping setup."
fi
