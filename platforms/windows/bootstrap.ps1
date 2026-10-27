<#
.SYNOPSIS
    Set up rea-suite on Windows. Safe to re-run.
.PARAMETER Update
    Upgrade everything: winget packages, uv.lock, npm packages and tools.yml tools.
.PARAMETER Angr
    Also install angr (large; uv sync --group angr).
.NOTES
    xxd ships with Git for Windows (usr\bin). Launchers land in tools\bin; add
    that, .venv\Scripts and node_modules\.bin to PATH (see env.ps1).
#>
param([switch]$Update, [switch]$Angr)
$ErrorActionPreference = 'Stop'
$Root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $Root

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Blue }
function Invoke-Checked { & $args[0] @($args | Select-Object -Skip 1); if ($LASTEXITCODE) { throw "$($args[0]) failed ($LASTEXITCODE)" } }

Step 'winget packages'
# Without --no-upgrade, import also upgrades the listed (and only those) packages.
$wingetArgs = @('import', '--import-file', "$PSScriptRoot\winget.json", '--accept-package-agreements', '--accept-source-agreements')
if (-not $Update) { $wingetArgs += '--no-upgrade' }
Invoke-Checked winget @wingetArgs
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')

Step 'Python environment (uv)'
if ($Update) { Invoke-Checked uv lock --upgrade }
$uvArgs = @('sync'); if ($Angr) { $uvArgs += '--group', 'angr' }
Invoke-Checked uv @uvArgs

$node = (Get-Content .node-version -Raw).Trim()
Step "Node $node + npm packages (fnm)"
Invoke-Checked fnm install $node
Invoke-Checked fnm exec --using=$node -- npm $(if ($Update) { 'update' } else { 'ci' })

Step 'Tools from common/tools.yml'
Invoke-Checked uv run rea-suite $(if ($Update) { 'update' } else { 'install' })

Step 'done'
Write-Host "Load the environment with: . $Root\platforms\windows\env.ps1"
