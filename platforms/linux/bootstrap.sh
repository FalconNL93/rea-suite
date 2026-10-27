#!/usr/bin/env bash
# Set up rea-suite on Debian/Ubuntu (incl. WSL). Safe to re-run.
#
#   platforms/linux/bootstrap.sh [--update] [--no-apt] [--angr]
#
#   --update   upgrade everything: uv.lock, npm packages and tools.yml tools
#   --no-apt   skip system packages and Detect It Easy (no sudo needed)
#   --angr     also install angr (large; `uv sync --group angr`)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

apt=1
update=0
uv_args=()
for arg in "$@"; do
  case "$arg" in
    --update) update=1 ;;
    --no-apt) apt=0 ;;
    --angr) uv_args+=(--group angr) ;;
    -h | --help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "missing: $1 (install: $2)" >&2; exit 1; }; }

if ((apt)); then
  step "apt packages"
  mapfile -t pkgs < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' platforms/linux/apt-packages.txt)
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
fi

need uv "curl -LsSf https://astral.sh/uv/install.sh | sh"
need fnm "curl -fsSL https://fnm.vercel.app/install | bash"
node_version="$(tr -d '[:space:]' <.node-version)"

step "Python environment (uv)"
((update == 0)) || uv lock --upgrade
uv sync "${uv_args[@]}"

step "Node $node_version + npm packages (fnm)"
fnm install "$node_version"
if ((update)); then
  fnm exec --using="$node_version" -- npm update
else
  fnm exec --using="$node_version" -- npm ci
fi

step "Tools from common/tools.yml"
if ((update)); then uv run rea-suite update; else uv run rea-suite install; fi

if ((apt)); then
  # Official distro .deb (not in the Ubuntu archive); apt resolves its Qt5 deps.
  step "Detect It Easy"
  # shellcheck source=/dev/null
  . /etc/os-release
  read -r die_tag die_url < <(uv run rea-suite asset horsicq/DIE-engine \
    "^die_[\\d.]+_${ID^}_${VERSION_ID}_amd64\\.deb\$")
  if [[ "$(dpkg-query -W -f='${Version}' detectiteasy 2>/dev/null)" == "$die_tag" ]]; then
    echo "detectiteasy $die_tag is up to date"
  else
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/detectiteasy_${die_tag}_amd64.deb" "$die_url"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$tmp/detectiteasy_${die_tag}_amd64.deb"
    rm -rf "$tmp"
  fi
fi

if ! java -version 2>&1 | grep -qE 'version "(2[1-9]|[3-9][0-9])'; then
  echo "warning: no JDK 21+ on PATH; Ghidra and JADX need one (e.g. apt install openjdk-21-jdk)" >&2
fi

step "done"
echo "Run 'direnv allow' in $ROOT to load the environment."
