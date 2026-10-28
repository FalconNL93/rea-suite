# Shared environment for rea-suite. Sourced by .envrc (direnv), ./activate and
# the wrappers in bin/, so tools behave the same inside and outside an
# interactive shell (e.g. when an agent launches the rea MCP server).
#
# Runtimes (uv, fnm/Node, Python, JDK, .NET) and their caches live in .runtime/,
# installed by platforms/<os>/bootstrap.sh; nothing here depends on ~ or /usr
# except the system packages (platforms/linux/apt-packages.txt,
# platforms/macos/Brewfile).
# shellcheck shell=bash

REA_SUITE_ROOT="${REA_SUITE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
REA_RUNTIME="$REA_SUITE_ROOT/.runtime"
export REA_SUITE_ROOT REA_RUNTIME

_rea_path_prepend() {
  [ -d "$1" ] || return 0
  case ":$PATH:" in *":$1:"*) ;; *) PATH="$1:$PATH" ;; esac
}

# macOS: GNU coreutils, sed, grep, find, tar and awk from Homebrew ahead of the
# BSD ones, so scripts behave as on Linux (platforms/macos/Brewfile).
if [ "$(uname -s)" = Darwin ]; then
  for _f in coreutils findutils gawk gnu-sed gnu-tar grep; do
    _rea_path_prepend "/opt/homebrew/opt/$_f/libexec/gnubin"
  done
fi

# --- runtimes in .runtime/ ---------------------------------------------------
export UV_PYTHON_INSTALL_DIR="$REA_RUNTIME/python"
export UV_PYTHON_PREFERENCE=only-managed
export UV_CACHE_DIR="$REA_RUNTIME/cache/uv"
export UV_TOOL_DIR="$REA_RUNTIME/uv-tools"
export UV_TOOL_BIN_DIR="$REA_RUNTIME/uv-tools/bin"
export FNM_DIR="$REA_RUNTIME/fnm"
export npm_config_cache="$REA_RUNTIME/cache/npm"
export DOTNET_ROOT="$REA_RUNTIME/dotnet"
export DOTNET_CLI_HOME="$REA_RUNTIME/dotnet-home"
export NUGET_PACKAGES="$REA_RUNTIME/cache/nuget"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
export GRADLE_USER_HOME="$REA_RUNTIME/cache/gradle"
# Rust toolchain for source builds (rustup from component `build`)
export RUSTUP_HOME="$REA_RUNTIME/rustup" CARGO_HOME="$REA_RUNTIME/cargo"
if [ -x "$REA_RUNTIME/jdk/current/bin/java" ]; then
  export JAVA_HOME="$REA_RUNTIME/jdk/current"
fi

_rea_path_prepend "$UV_TOOL_BIN_DIR"
_rea_path_prepend "$REA_RUNTIME/bin"
_rea_path_prepend "$DOTNET_ROOT"
_rea_path_prepend "$CARGO_HOME/bin"
_rea_path_prepend /opt/homebrew/opt/rustup/bin # keg-only on macOS
[ -z "${JAVA_HOME:-}" ] || _rea_path_prepend "$JAVA_HOME/bin"

# Node from .node-version via fnm (rea-agents has a strict engines range).
_rea_node_dir() {
  command -v fnm >/dev/null || return 0
  fnm exec --using="$(tr -d '[:space:]' <"$REA_SUITE_ROOT/.node-version")" -- \
    node -p 'require("path").dirname(process.execPath)' 2>/dev/null
}
_rea_path_prepend "$(_rea_node_dir)"

# --- project environment -----------------------------------------------------
_rea_path_prepend "$REA_SUITE_ROOT/node_modules/.bin"
_rea_path_prepend "$REA_SUITE_ROOT/.venv/bin"
_rea_path_prepend "$REA_SUITE_ROOT/tools/bin"
_rea_path_prepend "$REA_SUITE_ROOT/bin"
export PATH

export VIRTUAL_ENV="$REA_SUITE_ROOT/.venv"
export GHIDRA_INSTALL_DIR="$REA_SUITE_ROOT/tools/ghidra/current"

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
_rea_tool REA_UNBLOB_COMMAND unblob # Linux; REA's firmware extraction needs it

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
