#!/usr/bin/env bash
# First-time installer for rea-suite on Debian/Ubuntu (incl. WSL), Fedora and RHEL-family
# systems (Rocky, Alma; EPEL is enabled for them). Safe to re-run.
#
#   platforms/linux/bootstrap.sh [--no-apt] [--select] [--update] [--runtimes-only]
#
# 1. base system packages needed to bootstrap (curl, git, python3, ...)
# 2. runtimes into .runtime/: uv, fnm (+ Node), Temurin JDK, .NET SDK;
#    downloads are checksum-verified where upstream publishes checksums
# 3. optional components: a menu on the first run (stored in .env; see
#    .env.example to preselect), then `bin/rea-suite setup`
#
#   --no-apt          never call apt/dnf/sudo (prints what is missing instead; --no-dnf too)
#   --select          show the component menu again
#   --update          also upgrade runtimes that are already installed
#   --runtimes-only   stop after step 2 (used by `rea-suite update`)
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
cd "$ROOT"

JDK_MAJOR=21        # REA verifies Ghidra 12.1 on JDK 21 (rea-tools rea-pins)
DOTNET_CHANNEL=10.0 # LTS; ilspycmd

APT=1 UPDATE=0 RUNTIMES_ONLY=0 SELECT=0
pass=()
for arg in "$@"; do
  case "$arg" in
    --no-apt | --no-dnf) APT=0; pass+=("$arg") ;;
    --select) SELECT=1 ;;
    --update) UPDATE=1 ;;
    --runtimes-only) RUNTIMES_ONLY=1 ;;
    -h | --help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || die "Linux only; on Windows use platforms/windows/bootstrap.ps1"
[[ "$(uname -m)" == x86_64 ]] || die "only x86_64 is supported (tools.yml assets are x86_64)"

mkdir -p .runtime/bin .runtime/cache # before env.sh, so .runtime/bin lands on PATH
# shellcheck source=common/env.sh disable=SC1091
source common/env.sh
# shellcheck source=platforms/linux/packages.sh
source platforms/linux/packages.sh
pkg_manager >/dev/null || die "needs apt (Debian/Ubuntu) or dnf (Fedora/RHEL)"

# --- 1. base packages ------------------------------------------------------------

mapfile -t base < <(printf '%s\n' curl ca-certificates git tar xz-utils unzip python3 | pkg_native)
mapfile -t missing < <(pkg_missing "${base[@]}")
if ((${#missing[@]})); then
  step "base packages: ${missing[*]}"
  ((APT)) || die "missing ${missing[*]}; install them or drop --no-apt"
  pkg_install "${missing[@]}"
fi

# --- 2. runtimes -------------------------------------------------------------------

latest_tag() { # owner/repo -> tag of the latest release (no API, no rate limit)
  curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" |
    sed 's|.*/tag/||'
}

fetch() { # url dest [sha256]
  curl -fL --retry 3 -o "$2" "$1" --progress-bar
  if [[ -n "${3:-}" ]]; then
    echo "$3  $2" | sha256sum -c --quiet - || die "checksum mismatch for $1"
  fi
}

wanted() { # name installed-version latest-version
  if [[ -z "$2" ]]; then return 0; fi
  if ((UPDATE)) && [[ "$2" != "$3" ]]; then return 0; fi
  note "$1 $2 is installed"
  return 1
}

install_uv() {
  step "uv"
  local have tag tmp asset=uv-x86_64-unknown-linux-gnu.tar.gz
  have="$("$REA_RUNTIME/bin/uv" --version 2>/dev/null | awk '{print $2}')" || true
  tag="$(latest_tag astral-sh/uv)"
  wanted uv "$have" "$tag" || return 0
  tmp="$(mktemp -d)"
  local url="https://github.com/astral-sh/uv/releases/download/$tag/$asset"
  fetch "$url" "$tmp/$asset" "$(curl -fsSL "$url.sha256" | awk '{print $1}')"
  tar -xzf "$tmp/$asset" -C "$REA_RUNTIME/bin" --strip-components=1
  rm -rf "$tmp"
  note "uv $tag"
}

install_fnm() {
  step "fnm + Node $(cat .node-version)"
  local have tag tmp
  have="$("$REA_RUNTIME/bin/fnm" --version 2>/dev/null | awk '{print "v"$2}')" || true
  tag="$(latest_tag Schniz/fnm)"
  if wanted fnm "$have" "$tag"; then
    tmp="$(mktemp -d)"
    fetch "https://github.com/Schniz/fnm/releases/download/$tag/fnm-linux.zip" "$tmp/fnm.zip"
    unzip -oq "$tmp/fnm.zip" -d "$REA_RUNTIME/bin"
    chmod +x "$REA_RUNTIME/bin/fnm"
    rm -rf "$tmp"
    note "fnm $tag"
  fi
  "$REA_RUNTIME/bin/fnm" install "$(tr -d '[:space:]' <.node-version)" 2>&1 | grep -v '^warning: Version already installed' || true
}

install_jdk() {
  step "Temurin JDK $JDK_MAJOR"
  local meta name link sum tmp
  meta="$(curl -fsSL "https://api.adoptium.net/v3/assets/latest/$JDK_MAJOR/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse")"
  read -r name link sum < <(python3 -c '
import json, sys
a = json.load(sys.stdin)[0]
p = a["binary"]["package"]
print(a["release_name"], p["link"], p["checksum"])' <<<"$meta")
  if [[ -x "$REA_RUNTIME/jdk/$name/bin/java" ]]; then
    note "$name is installed"
  elif [[ "$(readlink "$REA_RUNTIME/jdk/current" 2>/dev/null)" == "jdk-$JDK_MAJOR"[.+]* ]] && ((UPDATE == 0)); then
    note "$(readlink "$REA_RUNTIME/jdk/current") is installed ($name available; use --update)"
    return 0
  else
    tmp="$(mktemp -d)"
    fetch "$link" "$tmp/jdk.tar.gz" "$sum"
    mkdir -p "$REA_RUNTIME/jdk/$name"
    tar -xzf "$tmp/jdk.tar.gz" -C "$REA_RUNTIME/jdk/$name" --strip-components=1
    rm -rf "$tmp"
    note "$name"
  fi
  ln -sfn "$name" "$REA_RUNTIME/jdk/current"
  find "$REA_RUNTIME/jdk" -mindepth 1 -maxdepth 1 -type d ! -name "$name" -exec rm -rf {} +
}

install_dotnet() {
  step ".NET SDK $DOTNET_CHANNEL"
  if [[ -x "$DOTNET_ROOT/dotnet" ]] && ((UPDATE == 0)); then
    note "$("$DOTNET_ROOT/dotnet" --version) is installed"
    return 0
  fi
  # Microsoft's official installer script; installs only into DOTNET_ROOT.
  fetch https://dot.net/v1/dotnet-install.sh "$REA_RUNTIME/cache/dotnet-install.sh"
  bash "$REA_RUNTIME/cache/dotnet-install.sh" --channel "$DOTNET_CHANNEL" \
    --install-dir "$DOTNET_ROOT" --no-path | tail -2
}

install_uv
install_fnm
install_jdk
install_dotnet

# A .venv built on an interpreter outside .runtime/ would keep pointing there.
if [[ -f .venv/pyvenv.cfg ]] && ! grep -q "^home = $REA_RUNTIME/python" .venv/pyvenv.cfg; then
  step "recreating .venv on the local Python"
  rm -rf .venv
fi

((RUNTIMES_ONLY)) && exit 0

step "optional components"
if ((SELECT)); then
  "$REA_RUNTIME/bin/uv" run --quiet common/rea_suite/components.py select
else
  "$REA_RUNTIME/bin/uv" run --quiet common/rea_suite/components.py select --if-unset
  "$REA_RUNTIME/bin/uv" run --quiet common/rea_suite/components.py list | sed 's/^/    /'
fi
exec bin/rea-suite setup "${pass[@]}"
