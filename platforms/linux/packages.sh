# shellcheck shell=bash
# System packages on Linux, sourced by platforms/linux/bootstrap.sh and bin/rea-suite.
#
# Package lists are written with Debian/Ubuntu names (apt-packages.txt, `apt:` in
# common/components.yml); dnf-names.txt and pacman-names.txt translate the ones that
# differ on Fedora/RHEL-family and Arch systems. One list, so a package is added in one place.
#
#   pkg_manager                 apt | dnf | pacman (exits when there is none)
#   pkg_native < names          the names for this system ('-' dropped, 'a|b' resolved)
#   pkg_missing names...        the ones not installed
#   pkg_available name          whether the system's repositories carry it
#   pkg_install [--reinstall] names...
#   pkg_upgradable names...     the ones with a newer version
#
# On dnf and pacman, packages a system does not have (RHEL lacks some even with EPEL) are
# skipped with a note instead of failing the install; doctor lists them.

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_pkg_root() { if ((EUID == 0)); then "$@"; else sudo "$@"; fi; } # root (containers): no sudo

pkg_manager() {
  if command -v apt-get >/dev/null; then echo apt
  elif command -v dnf >/dev/null; then echo dnf
  elif command -v pacman >/dev/null; then echo pacman
  else
    echo "no apt, dnf or pacman: install the packages in platforms/linux/apt-packages.txt yourself" >&2
    return 1
  fi
}

# RHEL, Rocky, Alma, CentOS Stream, Oracle Linux: EPEL and CRB carry most of the list
pkg_el() {
  # shellcheck disable=SC1091
  (. /etc/os-release && [[ " ${ID_LIKE:-} $ID " == *" rhel "* ]])
}

_pkg_installed() {
  case "$(pkg_manager)" in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed' ;;
    # --whatprovides: curl counts as installed through curl-minimal (RHEL)
    dnf) rpm -q "$1" >/dev/null 2>&1 || rpm -q --whatprovides "$1" >/dev/null 2>&1 ;;
    # -T: satisfied by a package of that name or one that provides it
    pacman) pacman -T "$1" >/dev/null 2>&1 ;;
  esac
}

pkg_available() {
  case "$(pkg_manager)" in
    apt) apt-cache show "$1" >/dev/null 2>&1 ;;
    dnf) dnf -q info "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Si "$1" >/dev/null 2>&1 || pacman -Sg "$1" >/dev/null 2>&1 ;;
  esac
}

pkg_native() {
  local manager name line alt c choice
  manager="$(pkg_manager)"
  if [[ "$manager" == apt ]]; then cat; return; fi
  while read -r name; do
    line="$(awk -v n="$name" '$1 == n { $1 = ""; print; exit }' "$PKG_DIR/$manager-names.txt")"
    [[ -n "$line" ]] || line="$name"
    for alt in $line; do
      [[ "$alt" != - ]] || continue
      if [[ "$alt" == *"|"* ]]; then # the one installed, else the first one available
        choice=""
        for c in ${alt//|/ }; do
          if _pkg_installed "$c"; then choice="$c"; break; fi
        done
        if [[ -z "$choice" ]]; then
          for c in ${alt//|/ }; do
            if pkg_available "$c"; then choice="$c"; break; fi
          done
        fi
        echo "${choice:-${alt%%|*}}"
      else
        echo "$alt"
      fi
    done
  done
}

pkg_missing() {
  local pkg
  for pkg in "$@"; do _pkg_installed "$pkg" || echo "$pkg"; done
}

pkg_install() { # [--reinstall] names...
  local reinstall=0 manager
  [[ "${1:-}" != --reinstall ]] || { reinstall=1; shift; }
  manager="$(pkg_manager)"
  if ((reinstall == 0)) && [[ "$manager" != apt ]]; then
    local wanted
    mapfile -t wanted < <(pkg_missing "$@") # only what is missing (curl vs curl-minimal)
    set -- "${wanted[@]}"
  fi
  (($#)) || return 0
  case "$manager" in
    apt)
      local flags=(-y)
      ((reinstall == 0)) || flags+=(--reinstall)
      _pkg_root apt-get update
      _pkg_root env DEBIAN_FRONTEND=noninteractive apt-get install "${flags[@]}" "$@"
      return
      ;;
    pacman)
      # Arch does not support partial upgrades: sync and upgrade first, then install
      _pkg_root pacman -Syu --noconfirm
      local pkg have=() absent=()
      for pkg in "$@"; do
        if pkg_available "$pkg"; then have+=("$pkg"); else absent+=("$pkg"); fi
      done
      if ((${#have[@]})); then
        if ((reinstall)); then _pkg_root pacman -S --noconfirm "${have[@]}"
        else _pkg_root pacman -S --needed --noconfirm "${have[@]}"; fi
      fi
      ((${#absent[@]} == 0)) || echo "note: not in this system's repositories: ${absent[*]}"
      return
      ;;
  esac
  if pkg_el && ! rpm -q epel-release >/dev/null 2>&1; then
    local major
    # shellcheck disable=SC1091
    major="$(. /etc/os-release && echo "${VERSION_ID%%.*}")"
    _pkg_root dnf install -y epel-release ||
      _pkg_root dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$major.noarch.rpm"
    _pkg_root dnf config-manager --set-enabled crb 2>/dev/null ||
      _pkg_root dnf config-manager --set-enabled powertools 2>/dev/null ||
      echo "note: enable CodeReady Builder (RHEL: subscription-manager repos --enable codeready-builder-for-rhel-$major-$(uname -m)-rpms)"
  fi
  local skip=(--setopt=strict=0) # dnf4
  dnf --version 2>/dev/null | grep -q dnf5 && skip=(--skip-unavailable)
  _pkg_root dnf install -y "${skip[@]}" "$@"
  ((reinstall == 0)) || _pkg_root dnf reinstall -y "${skip[@]}" "$@"
  local missing
  missing="$(pkg_missing "$@" | xargs)"
  [[ -z "$missing" ]] || echo "note: not available on this system: $missing"
}

pkg_upgradable() {
  (($#)) || return 0
  case "$(pkg_manager)" in
    apt) apt list --upgradable 2>/dev/null | grep -E "^($(IFS='|'; echo "$*"))/" || true ;;
    dnf) dnf -q list --upgrades "$@" 2>/dev/null || true ;;
    # checkupdates (pacman-contrib) syncs a copy of the databases; without it, the last sync
    pacman)
      if command -v checkupdates >/dev/null; then
        checkupdates 2>/dev/null | grep -E "^($(IFS='|'; echo "$*")) " || true
      else
        pacman -Qu "$@" 2>/dev/null || true
      fi
      ;;
  esac
}
