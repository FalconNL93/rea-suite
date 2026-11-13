# Headless Ghidra for one binary on Windows (counterpart of bin/rea-ghidra): analyze once, then
# decompile, xrefs, functions (rea-ghidra --help). The work is common\rea_suite\rea_ghidra.py.
#   pwsh -NoProfile -ExecutionPolicy Bypass -File platforms\windows\rea-ghidra.ps1 <args>
#Requires -Version 7
$ErrorActionPreference = 'Stop'
$CallerCwd = (Get-Location).Path
. "$PSScriptRoot\env.ps1"
# this checkout's rea_suite, also when its .venv is shared with another checkout
$env:PYTHONPATH = "$env:REA_SUITE_ROOT\common" + $(if ($env:PYTHONPATH) { ";$env:PYTHONPATH" } else { '' })
& uv run --project $env:REA_SUITE_ROOT --offline --no-sync python -m rea_suite.rea_ghidra --caller-cwd $CallerCwd @args
exit $LASTEXITCODE
