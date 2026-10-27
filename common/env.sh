# Shared environment for rea-suite. Sourced by .envrc (direnv) and by the
# wrappers in bin/, so tools behave the same inside and outside an interactive
# shell (e.g. when an agent launches the rea MCP server).
# shellcheck shell=bash

REA_SUITE_ROOT="${REA_SUITE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export REA_SUITE_ROOT

_rea_path_prepend() {
  [ -d "$1" ] || return 0
  case ":$PATH:" in *":$1:"*) ;; *) PATH="$1:$PATH" ;; esac
}

# Node from .node-version via fnm (rea-agents has a strict engines range).
_rea_node_dir() {
  local fnm version
  fnm="$(command -v fnm || true)"
  [ -n "$fnm" ] || [ ! -x "$HOME/.local/share/fnm/fnm" ] || fnm="$HOME/.local/share/fnm/fnm"
  [ -n "$fnm" ] || return 0
  version="$(tr -d '[:space:]' <"$REA_SUITE_ROOT/.node-version")"
  "$fnm" exec --using="$version" -- node -p 'require("path").dirname(process.execPath)' 2>/dev/null
}
_rea_path_prepend "$(_rea_node_dir)"

# Ghidra 12 needs JDK 21+. Respect an existing JAVA_HOME.
if [ -z "${JAVA_HOME:-}" ]; then
  for _jdk in /usr/lib/jvm/temurin-2[5-9]-jdk* /usr/lib/jvm/temurin-21-jdk* \
              /usr/lib/jvm/java-2[1-9]-openjdk*; do
    if [ -x "$_jdk/bin/java" ]; then export JAVA_HOME="$_jdk"; break; fi
  done
  unset _jdk
fi
[ -z "${JAVA_HOME:-}" ] || _rea_path_prepend "$JAVA_HOME/bin"

_rea_path_prepend "$REA_SUITE_ROOT/node_modules/.bin"
_rea_path_prepend "$REA_SUITE_ROOT/.venv/bin"
_rea_path_prepend "$REA_SUITE_ROOT/tools/bin"
_rea_path_prepend "$REA_SUITE_ROOT/bin"
export PATH

export VIRTUAL_ENV="$REA_SUITE_ROOT/.venv"
export GHIDRA_INSTALL_DIR="$REA_SUITE_ROOT/tools/ghidra/current"
export DOTNET_CLI_TELEMETRY_OPTOUT=1

# rea-agents wants absolute paths for some external engines.
_rea_tool() { # VAR command
  local path
  if path="$(command -v "$2" 2>/dev/null)"; then export "$1=$path"; fi
}
_rea_tool REA_TSHARK_COMMAND tshark
_rea_tool REA_CAPINFOS_COMMAND capinfos
_rea_tool REA_BINWALK_COMMAND binwalk
_rea_tool REA_RIZIN_COMMAND rizin
_rea_tool REA_MITMDUMP_COMMAND mitmdump
_rea_tool REA_ILSPY_CMD_PATH ilspycmd
_rea_tool REA_OBJDUMP_COMMAND objdump
_rea_tool REA_KUNA_COMMAND kuna
_rea_tool REA_APKTOOL_COMMAND apktool
_rea_tool REA_WAKARU_COMMAND wakaru
_rea_tool REA_ADB_PATH adb

for _f in "$REA_SUITE_ROOT"/tools/jadx-headless-mcp/current/*-all.jar; do
  [ -f "$_f" ] && export REA_JADX_MCP_JAR="$_f"
done
[ ! -d "$REA_SUITE_ROOT/tools/wabt/current/bin" ] ||
  export REA_WABT_BIN_DIRECTORY="$REA_SUITE_ROOT/tools/wabt/current/bin"
[ ! -x "$REA_SUITE_ROOT/.venv/bin/python" ] ||
  export REA_PWNTOOLS_PYTHON="$REA_SUITE_ROOT/.venv/bin/python"
for _f in "$GHIDRA_INSTALL_DIR"/Ghidra/Extensions/nativeaot/lib/*.jar; do
  [ -f "$_f" ] && export REA_GHIDRA_NATIVEAOT_JAR="$_f"
done
_pwndbg="$REA_SUITE_ROOT/tools/pwndbg/current"
if [ -x "$_pwndbg/bin/gdb" ]; then
  export REA_PWNDBG_GDB="$_pwndbg/bin/gdb" REA_PWNDBG_VENV_PATH="$_pwndbg"
  for _f in "$_pwndbg"/lib/python3*/site-packages/pwndbginit/gdbinit.py; do
    [ -f "$_f" ] && export REA_PWNDBG_GDBINIT="$_f"
  done
fi
unset _f _pwndbg

unset -f _rea_path_prepend _rea_node_dir _rea_tool
