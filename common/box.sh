# shellcheck shell=bash
# On an immutable host (SteamOS, Fedora Atomic, Bazzite) the suite lives in a distrobox,
# named by REA_SUITE_DISTROBOX (platforms/linux/bootstrap.sh writes it to .env). The bin/
# scripts source this before common/env.sh: started on the host, they go on inside the
# box with the same arguments, working directory and environment. distrobox writes its own
# messages to stderr only, so an agent's rea MCP server keeps a clean stdout.
# Needs REA_SUITE_ROOT.

_box="${REA_SUITE_DISTROBOX:-$(sed -n "s/^REA_SUITE_DISTROBOX=[\"']\{0,1\}\([^\"']*\).*/\1/p" \
  "$REA_SUITE_ROOT/.env" 2>/dev/null || true)}"
if [[ -n "$_box" && ! -e /run/.containerenv && ! -e /.dockerenv ]] && command -v distrobox >/dev/null; then
  # a terminal for menus and prompts; none (-T) when an agent pipes stdio
  if [[ -t 0 && -t 1 ]]; then exec distrobox enter -n "$_box" -- "$(readlink -f "$0")" "$@"
  else exec distrobox enter -T -n "$_box" -- "$(readlink -f "$0")" "$@"; fi
fi
unset _box
