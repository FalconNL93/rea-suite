# shellcheck shell=bash
# System packages on Linux, sourced by platforms/linux/bootstrap.sh and bin/rea-suite.
#
# Package lists are written with Debian/Ubuntu names (apt-packages.txt, `apt:` in
# common/components.yml); dnf-names.txt translates the ones that differ on Fedora and
# RHEL-family systems. One list, so a package is added in one place.
#
#   pkg_manager                 apt | dnf (exits when there is neither)
#   pkg_native < names          the names for this system ('-' dropped, 'a|b' resolved)
#   pkg_missing names...        the ones not installed
#   pkg_install [--reinstall] names...
#   pkg_upgradable names...     the ones with a newer version
#
# On dnf, packages a system does not have (RHEL lacks some even with EPEL) are skipped
# with a note instead of failing the install; doctor lists them.

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_pkg_root() { if ((EUID == 0)); then "$@"; else sudo "$@"; fi; } # root (containers): no sudo

pkg_manager() {
  if command -v apt-get >/dev/null; then echo apt
  elif command -v dnf >/dev/null; then echo dnf
  else
    echo "no apt or dnf: install the packages in platforms/linux/apt-packages.txt yourself" >&2
    return 1
  fi
}

# RHEL, Rocky, Alma, CentOS Stream, Oracle Linux: EPEL and CRB carry most of the list
pkg_el() {
  # shellcheck disable=SC1091
  (. /etc/os-release && [[ " ${ID_LIKE:-} $ID " == *" rhel "* ]])
}

pkg_native() {
  local name line alt
  if [[ "$(pkg_manager)" == apt ]]; then cat; return; fi
  while read -r name; do
    line="$(awk -v n="$name" '$1 == n { $1 = ""; print; exit }' "$PKG_DIR/dnf-names.txt")"
    [[ -n "$line" ]] || line="$name"
    for alt in $line; do
      [[ "$alt" != - ]] || continue
      if [[ "$alt" == *"|"* ]]; then # first one this system has
        local choice
        for choice in ${alt//|/ }; do
          if rpm -q --whatprovides "$choice" >/dev/null 2>&1 || dnf -q info "$choice" >/dev/null 2>&1; then
            echo "$choice"
            break
          fi
        done
      else
        echo "$alt"
      fi
    done
  done
}

pkg_missing() {
  local pkg
  for pkg in "$@"; do
    if [[ "$(pkg_manager)" == apt ]]; then
      dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'ok installed' || echo "$pkg"
    else
      # --whatprovides: curl counts as installed through curl-minimal (RHEL)
      rpm -q "$pkg" >/dev/null 2>&1 || rpm -q --whatprovides "$pkg" >/dev/null 2>&1 || echo "$pkg"
    fi
  done
}

pkg_install() { # [--reinstall] names...
  local reinstall=0
  [[ "${1:-}" != --reinstall ]] || { reinstall=1; shift; }
  if ((reinstall == 0)) && [[ "$(pkg_manager)" == dnf ]]; then
    local wanted
    mapfile -t wanted < <(pkg_missing "$@") # only what is missing (curl vs curl-minimal)
    set -- "${wanted[@]}"
  fi
  (($#)) || return 0
  if [[ "$(pkg_manager)" == apt ]]; then
    local flags=(-y)
    ((reinstall == 0)) || flags+=(--reinstall)
    _pkg_root apt-get update
    _pkg_root env DEBIAN_FRONTEND=noninteractive apt-get install "${flags[@]}" "$@"
    return
  fi
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
  if [[ "$(pkg_manager)" == apt ]]; then
    apt list --upgradable 2>/dev/null | grep -E "^($(IFS='|'; echo "$*"))/" || true
  else
    dnf -q list --upgrades "$@" 2>/dev/null || true
  fi
}
