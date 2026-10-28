# rea-agents CLI / MCP server with the suite environment (counterpart of bin/rea).
#   powershell -NoProfile -ExecutionPolicy Bypass -File platforms\windows\rea.ps1 <rea args>
# Agents start the MCP server this way (rea-suite.ps1 agents registers it).
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\env.ps1"
& node "$env:REA_SUITE_ROOT\node_modules\rea-agents\scripts\rea.mjs" @args
exit $LASTEXITCODE
