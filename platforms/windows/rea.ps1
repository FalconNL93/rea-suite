# rea-agents CLI / MCP server with the suite environment (counterpart of bin/rea).
#   pwsh -NoProfile -ExecutionPolicy Bypass -File platforms\windows\rea.ps1 <rea args>
# Agents start the MCP server this way (rea-suite.ps1 agents registers it).
#Requires -Version 7
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\env.ps1"
& node "$env:REA_SUITE_ROOT\node_modules\rea-agents\scripts\rea.mjs" @args
$status = $LASTEXITCODE
# rea setup registers node_modules\.bin\rea, without the suite environment, and rea doctor's remediation for this
# launcher's registration says to run it: after a setup (not a dry run), the agents are pointed back here.
if ($args.Count -gt 0 -and $args[0] -eq 'setup' -and $args -notcontains '--dry-run') {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\rea-suite.ps1" agents
}
exit $status
