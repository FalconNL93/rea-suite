<#
.SYNOPSIS
    Set up, update, check and repair rea-suite on Windows (counterpart of bin/rea-suite).
.EXAMPLE
    .\platforms\windows\rea-suite.ps1 setup          # after bootstrap.ps1; safe to re-run
    .\platforms\windows\rea-suite.ps1 select         # choose optional components (.env), then setup
    .\platforms\windows\rea-suite.ps1 winget         # install winget packages (base + components)
    .\platforms\windows\rea-suite.ps1 update         # runtimes, winget, uv.lock, rea-agents, tools.yml
    .\platforms\windows\rea-suite.ps1 doctor         # check the installation
    .\platforms\windows\rea-suite.ps1 reinstall runtime|python|node|tools|all|<tool>
    .\platforms\windows\rea-suite.ps1 status
    .\platforms\windows\rea-suite.ps1 tools <rea-tools args>
    .\platforms\windows\rea-suite.ps1 clean [caches|tools|all]   # no argument: show sizes only
    .\platforms\windows\rea-suite.ps1 lint [file...]             # ruff, shellcheck, PowerShell parse (Git Bash)
.NOTES
    Not tested on Windows yet.
#>
param(
    [Parameter(Position = 0)][ValidateSet('setup', 'select', 'winget', 'update', 'reinstall', 'doctor', 'status', 'tools', 'clean', 'lint')][string]$Command = 'setup',
    [Parameter(Position = 1, ValueFromRemainingArguments)][string[]]$Rest = @()
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $Root
. "$PSScriptRoot\env.ps1"
$Node = (Get-Content .node-version -Raw).Trim()

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Blue }
function Invoke-Checked { & $args[0] @($args | Select-Object -Skip 1); if ($LASTEXITCODE) { throw "$($args[0]) failed ($LASTEXITCODE)" } }
function Components { uv run --quiet common\rea_suite\components.py @args }
function Winget-Ids {
    (Get-Content "$PSScriptRoot\winget.json" -Raw | ConvertFrom-Json).Sources[0].Packages.PackageIdentifier
    Components packages winget
}
function Winget-Packages([switch]$Upgrade) {
    Step 'winget packages (base + components)'
    foreach ($id in Winget-Ids) {
        $a = @('--id', $id, '--exact', '--accept-package-agreements', '--accept-source-agreements')
        # install also upgrades an installed package unless --no-upgrade is given
        if ($Upgrade) { winget install @a } else { winget install @a --no-upgrade }
    }
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + $env:Path
}
function Need($cmd) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd missing; run platforms\windows\bootstrap.ps1" } }

function Python-Env([switch]$Upgrade) {
    Step 'Python (uv)'; Need uv
    if ($Upgrade) { Invoke-Checked uv lock --upgrade }
    $groups = "$(Components uv-args)".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    Invoke-Checked uv sync @groups
}
function Uv-Tools([switch]$Upgrade) {
    Step 'isolated CLI tools (common/uv-tools.txt)'
    foreach ($line in Get-Content "$Root\common\uv-tools.txt") {
        $line = ($line -replace '#.*', '').Trim()
        if (-not $line -or ($line -match ' @(\w+)$' -and $Matches[1] -ne 'windows')) { continue }
        $spec = $line -replace ' @\w+$', ''
        if ($Upgrade) { Invoke-Checked uv tool install --upgrade $spec } else { Invoke-Checked uv tool install $spec }
    }
}
function Node-Env([switch]$Upgrade) {
    Step "Node $Node + rea-agents (fnm/npm)"; Need fnm
    Invoke-Checked fnm install $Node
    if ($Upgrade) { Invoke-Checked fnm exec --using=$Node -- npm install rea-agents@latest }
    else { Invoke-Checked fnm exec --using=$Node -- npm ci }
}
function Suite-Tools([string]$Action) {
    Step 'tools from common/tools.yml'
    . "$PSScriptRoot\env.ps1"
    Invoke-Checked uv run rea-tools $Action
}
function Doctor {
    $problems = 0
    Step 'components'; Components list
    function Ok($n, $m) { Write-Host ('  ok    {0,-18} {1}' -f $n, $m) -ForegroundColor Green }
    function Bad($n, $m) { Write-Host ('  FAIL  {0,-18} {1}' -f $n, $m) -ForegroundColor Red; $script:problems++ }
    Step 'runtimes (.runtime\)'
    foreach ($c in 'uv', 'fnm', 'node', 'java', 'dotnet') {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cmd) { Bad $c 'missing; run platforms\windows\bootstrap.ps1' }
        elseif (-not $cmd.Source.StartsWith($env:REA_RUNTIME)) { Bad $c "$($cmd.Source) is outside .runtime\" }
        else { Ok $c $cmd.Source }
    }
    Step 'project environments'
    $groups = "$(Components uv-args)".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    uv sync --check --quiet @groups 2>$null; if ($LASTEXITCODE) { Bad '.venv' 'out of sync; run rea-suite.ps1 setup' } else { Ok '.venv' 'in sync with uv.lock' }
    npm ls rea-agents --depth=0 *> $null; if ($LASTEXITCODE) { Bad 'node_modules' 'run rea-suite.ps1 setup' } else { Ok 'node_modules' 'rea-agents installed' }
    Step 'tools.yml'
    uv run rea-tools check; if ($LASTEXITCODE) { $script:problems++ }
    uv run rea-tools rea-pins; if ($LASTEXITCODE) { $script:problems++ }
    Step 'system (winget)'
    foreach ($p in Winget-Ids) {
        winget list --id $p --exact --accept-source-agreements *> $null
        if ($LASTEXITCODE) { Bad $p 'not installed; run bootstrap.ps1' } else { Ok $p 'installed' }
    }
    Step 'git'
    if ((git config core.hooksPath) -eq '.githooks') { Ok 'hooks' 'gitleaks runs on commit and push' }
    else { Bad 'hooks' 'not enabled; run rea-suite.ps1 setup' }
    Step 'MSVC'
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = if (Test-Path $vswhere) { & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath }
    if ($vs) { Ok 'MSVC' $vs } else { Write-Host '  info  MSVC               not found; Visual Studio installer -> "Desktop development with C++" workload' -ForegroundColor Yellow }
    Step 'rea doctor'
    rea doctor
    if ($script:problems) { Write-Host "`n$($script:problems) problem(s) found" -ForegroundColor Red; exit 1 }
    Write-Host "`nall checks passed" -ForegroundColor Green
}

switch ($Command) {
    'setup' { Python-Env; Uv-Tools; Node-Env; Suite-Tools install; git config core.hooksPath .githooks }
    'select' { Components select; & $PSCommandPath setup }
    'winget' { Winget-Packages }
    'update' {
        & "$PSScriptRoot\bootstrap.ps1" -RuntimesOnly -Update
        Winget-Packages -Upgrade
        . "$PSScriptRoot\env.ps1"
        Python-Env -Upgrade; Uv-Tools -Upgrade; Node-Env -Upgrade; Suite-Tools update
        Step 'versions REA verifies (Ghidra pin, JDK)'
        uv run rea-tools rea-pins
        if ($LASTEXITCODE) { Write-Warning 'the new rea-agents verifies other versions; follow the hints above' }
        # refresh the REA skill for every agent rea-agents detects (the dry run changes nothing)
        $rea = @('exec', "--using=$Node", '--', 'node', 'node_modules\rea-agents\scripts\rea.mjs', 'setup')
        $plan = & fnm @rea --all-detected --dry-run --format json | ConvertFrom-Json
        $clients = @($plan.clientStates | Where-Object detected | ForEach-Object { $_.client.name })
        if ($clients) {
            Step "REA skill for $($clients -join ' ')"
            $flags = @($clients | ForEach-Object { '--skill-client', $_ })
            Invoke-Checked fnm @rea --yes @flags --filter-output status,appliedActions
        }
    }
    'reinstall' {
        foreach ($what in $Rest) {
            switch ($what) {
                'runtime' { Remove-Item -Recurse -Force .runtime -ErrorAction SilentlyContinue; & "$PSScriptRoot\bootstrap.ps1" -RuntimesOnly -NoWinget }
                'python' { Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue; Python-Env }
                'node' { Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue; Node-Env }
                'tools' { Invoke-Checked uv run rea-tools reinstall }
                'all' { & $PSCommandPath reinstall runtime python node tools }
                default { Invoke-Checked uv run rea-tools reinstall $what }
            }
        }
    }
    'doctor' { Doctor }
    'status' {
        Step 'Python packages'; uv tree --outdated --depth 1
        Step 'tools.yml'; Invoke-Checked uv run rea-tools status
        Step 'rea'; fnm exec --using=$Node -- npm outdated rea-agents  # exits 1 when outdated
    }
    'tools' { Invoke-Checked uv run rea-tools @Rest }
    'lint' { Invoke-Checked bash .githooks/lint.sh @Rest }
    'clean' {
        $caches = 'uv', 'npm', 'nuget', 'gradle' | ForEach-Object { "$env:REA_RUNTIME\cache\$_" }
        if (-not $Rest) {
            Step 'caches (clean caches); refilled on the next setup or build'
            foreach ($dir in $caches | Where-Object { Test-Path $_ }) {
                $mb = [math]::Round((Get-ChildItem $dir -Recurse -File -Force | Measure-Object Length -Sum).Sum / 1MB)
                Write-Host ('  {0,-8} {1,6} MB  {2}' -f (Split-Path $dir -Leaf), $mb, $dir)
            }
            Step "inactive tool versions (clean tools); 'rea-tools use' rolls back to them"
            Invoke-Checked uv run rea-tools prune --dry-run
        }
        if ($Rest -contains 'all') { $Rest = 'caches', 'tools' }
        foreach ($what in $Rest) {
            switch ($what) {
                'caches' {
                    Step 'clean caches'
                    Invoke-Checked uv cache clean
                    Invoke-Checked dotnet nuget locals all --clear
                    # npm's own clean leaves _prebuilds (frida); Gradle has no clean command
                    Remove-Item -Recurse -Force "$env:REA_RUNTIME\cache\npm", "$env:REA_RUNTIME\cache\gradle" -ErrorAction SilentlyContinue
                }
                'tools' { Step 'clean tools'; Invoke-Checked uv run rea-tools prune }
                default { throw "clean what? caches | tools | all" }
            }
        }
    }
}
