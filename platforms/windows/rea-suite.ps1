<#
.SYNOPSIS
    Set up, update and repair rea-suite on Windows (counterpart of bin/rea-suite).
.EXAMPLE
    .\platforms\windows\rea-suite.ps1 setup
    .\platforms\windows\rea-suite.ps1 update
    .\platforms\windows\rea-suite.ps1 reinstall python|node|tools|all|<tool>
    .\platforms\windows\rea-suite.ps1 status
    .\platforms\windows\rea-suite.ps1 tools <rea-tools args>
.NOTES
    Not tested on Windows yet. Load the environment with . .\platforms\windows\env.ps1
#>
param(
    [Parameter(Position = 0)][ValidateSet('setup', 'update', 'reinstall', 'status', 'tools')][string]$Command = 'setup',
    [Parameter(Position = 1, ValueFromRemainingArguments)][string[]]$Rest = @(),
    [switch]$Angr
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $Root
$Node = (Get-Content .node-version -Raw).Trim()
if (Test-Path .venv\Lib\site-packages\angr) { $Angr = $true }

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Blue }
function Invoke-Checked { & $args[0] @($args | Select-Object -Skip 1); if ($LASTEXITCODE) { throw "$($args[0]) failed ($LASTEXITCODE)" } }

function Winget-Packages([switch]$Upgrade) {
    Step 'winget packages'
    # Without --no-upgrade, import also upgrades the listed (and only those) packages.
    $a = @('import', '--import-file', "$PSScriptRoot\winget.json", '--accept-package-agreements', '--accept-source-agreements')
    if (-not $Upgrade) { $a += '--no-upgrade' }
    Invoke-Checked winget @a
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
function Python-Env([switch]$Upgrade) {
    Step 'Python (uv)'
    if ($Upgrade) { Invoke-Checked uv lock --upgrade }
    $a = @('sync'); if ($Angr) { $a += '--group', 'angr' }
    Invoke-Checked uv @a
}
function Node-Env([switch]$Upgrade) {
    Step "Node $Node + rea-agents (fnm/npm)"
    Invoke-Checked fnm install $Node
    if ($Upgrade) { Invoke-Checked fnm exec --using=$Node -- npm install rea-agents@latest }
    else { Invoke-Checked fnm exec --using=$Node -- npm ci }
}
function Suite-Tools([string]$Action) {
    Step 'tools from common/tools.yml'
    Invoke-Checked uv run rea-tools $Action @Rest
}

switch ($Command) {
    'setup' { Winget-Packages; Python-Env; Node-Env; Suite-Tools install }
    'update' { Winget-Packages -Upgrade; Python-Env -Upgrade; Node-Env -Upgrade; Suite-Tools update }
    'reinstall' {
        foreach ($what in $Rest) {
            switch ($what) {
                'python' { Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue; Python-Env }
                'node' { Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue; Node-Env }
                'tools' { Invoke-Checked uv run rea-tools reinstall }
                'all' { Python-Env; Node-Env; Invoke-Checked uv run rea-tools reinstall }
                default { Invoke-Checked uv run rea-tools reinstall $what }
            }
        }
    }
    'status' {
        Step 'Python packages'; uv tree --outdated --depth 1
        Step 'tools.yml'; Invoke-Checked uv run rea-tools status
        Step 'rea'; fnm exec --using=$Node -- npm outdated rea-agents  # exits 1 when outdated
    }
    'tools' { Invoke-Checked uv run rea-tools @Rest }
}
