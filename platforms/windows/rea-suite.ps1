<#
.SYNOPSIS
    Set up, update, check and repair rea-suite on Windows (counterpart of bin/rea-suite).
.EXAMPLE
    .\platforms\windows\rea-suite.ps1 setup          # after bootstrap.ps1; safe to re-run
    .\platforms\windows\rea-suite.ps1 select         # choose optional components (.env), then setup
    .\platforms\windows\rea-suite.ps1 winget         # install winget packages (base + components)
    .\platforms\windows\rea-suite.ps1 update         # runtimes, winget, uv.lock, rea-agents, tools.yml, REA skill
    .\platforms\windows\rea-suite.ps1 update --ai    # an agent checks compatibility, proposes the plan, applies it
    .\platforms\windows\rea-suite.ps1 agents [agent...]  # rea MCP + REA skill for every detected agent
    .\platforms\windows\rea-suite.ps1 playstation [options]  # prepare PS1/PS2 projects
    .\platforms\windows\rea-suite.ps1 xbox360 <command> [options]  # Xbox 360 XEX/PE in your Ghidra project
    .\platforms\windows\rea-suite.ps1 xbox info|imports|image|symbols|check <xbe>  # original Xbox XBE without Ghidra
    .\platforms\windows\rea-suite.ps1 ps3 info|imports|nids|census|decrypt|analyze|check ...  # PS3 SELF/ELF/PRX, NIDs, your RPCS3, Ghidra
    .\platforms\windows\rea-suite.ps1 gamecube info|check <file>  # GameCube/Wii DOL, REL or disc image without Ghidra
    .\platforms\windows\rea-suite.ps1 psp info|nid|check <file>  # PSP EBOOT.PBP, PRX with NIDs, PARAM.SFO, ISO, CSO
    .\platforms\windows\rea-suite.ps1 functions <config> check|add|find|convert  # a port's function index and gate
    .\platforms\windows\rea-suite.ps1 steamstub <exe>...  # SteamStub DRM signs
    .\platforms\windows\rea-suite.ps1 pe <command> <exe> ...  # PE scans: RTTI, references, callers, strings, disasm, resources
    .\platforms\windows\rea-suite.ps1 rmdp list|extract|find|inner <index.bin> ...  # Remedy packages
    .\platforms\windows\rea-suite.ps1 yetibig info|list|blob|diff|refs|check <Yeti.big> ...  # YETI engine archives (Lost: Via Domus, GRAW)
    .\platforms\windows\rea-suite.ps1 le info|dump-object|dump-image|services <exe> ...  # LE/LX executables (DOS extenders)
    .\platforms\windows\rea-suite.ps1 frida <script.js> --pid|--name|--spawn ...  # Frida script, JSON lines
    .\platforms\windows\rea-suite.ps1 dosbox run|parse|compare|info ...  # a DOS program in DOSBox-X, its INT calls as JSON lines; dumps, input, region sequences
    .\platforms\windows\rea-suite.ps1 pad --presses 30:DOWN,33:A [--idle-pad]  # virtual Xbox 360 pad (ViGEm)
    .\platforms\windows\rea-suite.ps1 run --script steps.txt --start D:\Game\Game.exe  # bounded, observed run of a program
    .\platforms\windows\rea-suite.ps1 analyze [paths...] [options]  # offline analysis; --examples
    .\platforms\windows\rea-suite.ps1 doctor         # check the installation
    .\platforms\windows\rea-suite.ps1 reinstall runtime|python|node|tools|all|<tool>
    .\platforms\windows\rea-suite.ps1 status
    .\platforms\windows\rea-suite.ps1 tools <rea-tools args>
    .\platforms\windows\rea-suite.ps1 clean [caches|builds|tools|all]   # no argument: show sizes only
    .\platforms\windows\rea-suite.ps1 lint [file...]             # ruff, shellcheck, PowerShell parse (Git Bash)
    .\platforms\windows\rea-suite.ps1 check            # lint, then every unit test (Python, Node); the gate before a push
.NOTES
    Not tested on Windows yet.
#>
#Requires -Version 7
param(
    [Parameter(Position = 0)][ValidateSet('setup', 'select', 'winget', 'update', 'reinstall', 'agents', 'analyze', 'playstation', 'xbox', 'xbox360', 'ps3', 'gamecube', 'psp', 'functions', 'steamstub', 'pe', 'rmdp', 'yetibig', 'le', 'frida', 'dosbox', 'pad', 'run', 'doctor', 'status', 'tools', 'clean', 'lint', 'check')][string]$Command = 'setup',
    [Parameter(Position = 1, ValueFromRemainingArguments)][string[]]$Rest = @()
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$CallerCwd = (Get-Location).Path
# --no-build: no source builds of Ghidra extensions (as REA_TOOLS_NO_BUILD=1)
if ($Rest -contains '--no-build') { $env:REA_TOOLS_NO_BUILD = '1'; $Rest = @($Rest | Where-Object { $_ -ne '--no-build' }) }
Set-Location $Root
. "$PSScriptRoot\env.ps1"
# this checkout's rea_suite, also when its .venv is shared with another checkout (counterpart of bin/rea-suite)
$env:PYTHONPATH = "$Root\common" + $(if ($env:PYTHONPATH) { ";$env:PYTHONPATH" } else { '' })
$Node = (Get-Content .node-version -Raw).Trim()

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Blue }
function Invoke-Checked { & $args[0] @($args | Select-Object -Skip 1); if ($LASTEXITCODE) { throw "$($args[0]) failed ($LASTEXITCODE)" } }
function Components { uv run --quiet common\rea_suite\components.py @args }
function Agents { Invoke-Checked uv run --quiet common\rea_suite\agents.py @args }
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
# <root>\bin on the user's PATH (registry), appended once; existing entries stay as they are
# (read unexpanded, so %VAR% references survive). REA_SUITE_NO_PATH=1 skips.
function User-Path([switch]$Check) {
    $bin = "$Root\bin"
    $key = Get-Item 'HKCU:\Environment'
    $raw = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    $entries = @($raw -split ';' | Where-Object { $_ })
    $present = $entries | Where-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $bin }
    if ($Check) { return [bool]$present }
    if ($env:REA_SUITE_NO_PATH) { Write-Host '  PATH: skipped (REA_SUITE_NO_PATH)'; return }
    if ($present) { Write-Host "  PATH: $bin already there"; return }
    Set-ItemProperty 'HKCU:\Environment' -Name Path -Type ExpandString -Value (($entries + $bin) -join ';')
    # tell running programs (Explorer, new terminals) that the environment changed
    Add-Type -Namespace RS -Name Native -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r);'
    $r = [UIntPtr]::Zero
    [void][RS.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$r)
    Write-Host "  PATH: $bin added; new terminals have rea-suite and rea"
}
function Need($cmd) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd missing; run platforms\windows\bootstrap.ps1" } }

function Python-Env([switch]$Upgrade) {
    Step 'Python (uv)'; Need uv
    if ($Upgrade) { Invoke-Checked uv lock --upgrade }
    $groups = "$(Components uv-args)".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    Invoke-Checked uv sync @groups
}
function Uv-Tools([switch]$Upgrade) {
    Step 'isolated CLI tools (common/uv-tools.txt, components)'
    # Launchers used to live in .runtime\uv-tools\bin; recreate them in UV_TOOL_BIN_DIR once.
    $reinstall = Test-Path "$Root\.runtime\uv-tools\bin"
    if ($reinstall) { Remove-Item -Recurse -Force "$Root\.runtime\uv-tools\bin" }
    # common/uv-tools.txt plus the selected components' `uv-tools`
    foreach ($line in @(Get-Content "$Root\common\uv-tools.txt") + @(Components values uv-tools)) {
        $line = ($line -replace '#.*', '').Trim()
        if (-not $line -or ($line -match ' @(\w+)$' -and $Matches[1] -ne 'windows')) { continue }
        $spec = $line -replace ' @\w+$', ''
        if ($reinstall) { Invoke-Checked uv tool install --reinstall $spec }
        elseif ($Upgrade) { Invoke-Checked uv tool install --upgrade $spec } else { Invoke-Checked uv tool install $spec }
    }
}
function Node-Env([switch]$Upgrade) {
    Step "Node $Node + rea-agents (fnm/npm)"; Need fnm
    fnm install $Node 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -notmatch '^warning: Version already installed' }
    if ($LASTEXITCODE) { throw "fnm install failed ($LASTEXITCODE)" }
    if ($Upgrade) {
        Invoke-Checked fnm exec --using=$Node -- npm install rea-agents@latest
        Invoke-Checked fnm exec --using=$Node -- npm update  # the other tools in package.json
    }
    else { Invoke-Checked fnm exec --using=$Node -- npm ci }
    Browsers
}
# Browsers of the selected components, from rea-agents' own playwright-core (counterpart
# of browsers() in bin/rea-suite); env.ps1 reads chromium-path into REA_BROWSER_EXECUTABLE.
function Browsers {
    foreach ($browser in Components values playwright) {
        Step "$browser for REA (Playwright, .runtime\ms-playwright)"
        Invoke-Checked fnm exec --using=$Node -- node node_modules\playwright-core\cli.js install $browser
    }
    $js = 'import("playwright-core").then(({ chromium }) => { const fs = require("fs"), p = chromium.executablePath(); if (fs.existsSync(p)) fs.writeFileSync(process.argv[1], p + "\n"); })'
    Invoke-Checked fnm exec --using=$Node -- node -e $js "$env:REA_RUNTIME\chromium-path"
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
    uv sync --check --quiet @groups 2>$null; if ($LASTEXITCODE) { Bad '.venv' "out of sync with uv.lock; run uv sync --locked$(if ($groups) { ' ' + ($groups -join ' ') })" } else { Ok '.venv' 'in sync with uv.lock' }
    npm ls rea-agents --depth=0 *> $null; if ($LASTEXITCODE) { Bad 'node_modules' 'run rea-suite.ps1 setup' } else { Ok 'node_modules' 'rea-agents installed' }
    $ia = & uv run --offline --no-sync ia --version 2>&1; if ($LASTEXITCODE) { Bad 'ia' 'the Internet Archive CLI does not start; run uv sync --locked' } else { Ok 'ia' "internetarchive $ia" }
    if ((Components values playwright) -contains 'chromium') {
        if ($env:REA_BROWSER_EXECUTABLE -and (Test-Path $env:REA_BROWSER_EXECUTABLE)) { Ok 'chromium' $env:REA_BROWSER_EXECUTABLE }
        else { Bad 'chromium' 'missing (component browser); run rea-suite.ps1 setup' }
    }
    Step 'tools.yml'
    uv run rea-tools check; if ($LASTEXITCODE) { $script:problems++ }
    uv run rea-tools rea-pins; if ($LASTEXITCODE) { $script:problems++ }
    $xex = uv run --offline --no-sync common\rea_suite\xbox360.py check
    if ($LASTEXITCODE) { Bad 'xexloaderwv' "$xex" } else { Ok 'xexloaderwv' "$xex" }
    $xbe = uv run --offline --no-sync common\rea_suite\xbox.py check
    if ($LASTEXITCODE) { Bad 'ghidra-xbe' "$xbe" } else { Ok 'ghidra-xbe' "$xbe" }
    $selected = Components selected
    foreach ($console in 'gamecube', 'psp') {
        if ($selected -notcontains $console) { continue }
        $out = uv run --offline --no-sync common\rea_suite\$console.py check
        if ($LASTEXITCODE) { Bad "$console loader" "$out" } else { Ok "$console loader" "$out" }
    }
    if ((Components selected) -contains 'ps3') {
        $ps3 = (uv run --offline --no-sync common\rea_suite\ps3.py check) -join '; '
        if ($LASTEXITCODE) { Bad 'ps3' "$ps3" } else { Ok 'ps3' "$ps3" }
    }
    Step 'system (winget)'
    foreach ($p in Winget-Ids) {
        winget list --id $p --exact --accept-source-agreements *> $null
        if ($LASTEXITCODE) { Bad $p 'not installed; run bootstrap.ps1' } else { Ok $p 'installed' }
    }
    Step 'git'
    if ((git config core.hooksPath) -eq '.githooks') { Ok 'hooks' 'gitleaks runs on commit and push' }
    else { Bad 'hooks' 'not enabled; run rea-suite.ps1 setup' }
    Step 'agents (rea MCP server; rea-suite.ps1 agents repairs)'
    foreach ($line in uv run --quiet common\rea_suite\agents.py list) {
        $client, $state, $cmd = $line -split "`t", 3
        switch ($state) {
            'ok' { Ok $client 'rea via platforms\windows\rea.ps1' }
            'missing' { Write-Host ('  info  {0,-18} rea not registered; rea-suite.ps1 agents {0}' -f $client) -ForegroundColor Yellow }
            'stale' { Bad $client 'suite registration settings or environment need refresh; run rea-suite.ps1 agents' }
            default { Bad $client "rea starts $cmd, not rea.ps1; run rea-suite.ps1 agents" }
        }
    }
    Step 'PATH'
    if (User-Path -Check) { Ok 'PATH' "$Root\bin (rea-suite, rea from anywhere)" }
    else { Write-Host '  info  PATH               bin\ not on your PATH; run rea-suite.ps1 setup' -ForegroundColor Yellow }
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
    'setup' { Components adopt; Python-Env; Uv-Tools; Node-Env; Suite-Tools install; git config core.hooksPath .githooks; Step 'bin\ on your PATH'; User-Path }
    'select' { Components select; & $PSCommandPath setup }
    'winget' { Winget-Packages }
    'update' {
        if ($Rest -contains '--ai') {
            # an agent plans the update with the updating-the-suite skill (counterpart of bin/rea-suite)
            Agents launch 'Plan and run an update of this rea-suite checkout, including a fresh review of the offline analysis workflow and its examples (Windows: platforms\windows\rea-suite.ps1). Follow .agents/skills/updating-the-suite/SKILL.md step by step; present the plan and wait for my approval before changing anything.'
            exit $LASTEXITCODE
        }
        Components adopt
        & "$PSScriptRoot\bootstrap.ps1" -RuntimesOnly -Update
        Winget-Packages -Upgrade
        . "$PSScriptRoot\env.ps1"
        Python-Env -Upgrade; Uv-Tools -Upgrade; Node-Env -Upgrade; Suite-Tools update
        Step 'versions REA verifies (Ghidra pin, JDK)'
        uv run rea-tools rea-pins
        if ($LASTEXITCODE) { Write-Warning 'the new rea-agents verifies other versions; follow the hints above' }
        Agents skills
    }
    'agents' { Agents register @Rest }
    'playstation' { & uv run --offline --no-sync common\rea_suite\playstation.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'xbox' { & uv run --offline --no-sync common\rea_suite\xbox.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'ps3' { & uv run --offline --no-sync common\rea_suite\ps3.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'xbox360' { & uv run --offline --no-sync common\rea_suite\xbox360.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'gamecube' { & uv run --offline --no-sync common\rea_suite\gamecube.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'psp' { & uv run --offline --no-sync common\rea_suite\psp.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'functions' { & uv run --offline --no-sync common\rea_suite\functions.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'steamstub' { & uv run --offline --no-sync common\rea_suite\steamstub.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'frida' { & uv run --offline --no-sync common\rea_suite\frida_run.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'dosbox' { & uv run --offline --no-sync common\rea_suite\dosbox.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'pad' { & uv run --offline --no-sync common\rea_suite\vigem_pad.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'run' { & uv run --offline --no-sync common\rea_suite\run_harness.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'pe' { & uv run --offline --no-sync common\rea_suite\pe.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'rmdp' { & uv run --offline --no-sync common\rea_suite\rmdp.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'yetibig' { & uv run --offline --no-sync common\rea_suite\yetibig.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'le' { & uv run --offline --no-sync common\rea_suite\le.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'analyze' { & uv run --offline --no-sync common\rea_suite\analyze.py --caller-cwd $CallerCwd @Rest; exit $LASTEXITCODE }
    'reinstall' {
        foreach ($what in $Rest) {
            switch ($what) {
                'runtime' { Remove-Item -Recurse -Force .runtime -ErrorAction SilentlyContinue; & "$PSScriptRoot\bootstrap.ps1" -RuntimesOnly -NoWinget }
                'python' { Remove-Item -Recurse -Force .venv, .runtime\uv-tools, .runtime\uv-tools-bin -ErrorAction SilentlyContinue; Python-Env; Uv-Tools }
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
        Step 'isolated uv tools (common/uv-tools.txt)'; uv tool list --outdated
        Step 'npm packages (package.json; none listed = up to date)'
        fnm exec --using=$Node -- npm outdated  # exits 1 when outdated
        Step 'tools.yml'; Invoke-Checked uv run rea-tools status
        Step 'system packages of the suite with updates'
        foreach ($id in Winget-Ids) { winget list --id $id --exact --upgrade-available --accept-source-agreements 2>$null | Select-String $id }
    }
    'tools' { Invoke-Checked uv run rea-tools @Rest }
    'lint' { Invoke-Checked bash .githooks/lint.sh @Rest }
    'check' {
        # counterpart of bin/rea-suite check: every part runs, the exit says whether any failed
        $failed = @()
        Step 'lint'; bash .githooks/lint.sh; if ($LASTEXITCODE) { $failed += 'lint' }
        Step 'Python unit tests (common/rea_suite/test_*.py)'
        & .venv\Scripts\python.exe -m unittest discover -s common/rea_suite -t common; if ($LASTEXITCODE) { $failed += 'python' }
        Step 'Node unit tests (common/*.test.mjs)'
        fnm exec --using=$Node -- node --test (Get-ChildItem common\*.test.mjs).FullName; if ($LASTEXITCODE) { $failed += 'node' }
        if ($failed) { Write-Host "`ncheck failed: $($failed -join ' ')" -ForegroundColor Red; exit 1 }
        Write-Host "`ncheck passed" -ForegroundColor Green
    }
    'clean' {
        $caches = 'uv', 'npm', 'nuget', 'gradle' | ForEach-Object { "$env:REA_RUNTIME\cache\$_" }
        if (-not $Rest) {
            Step 'caches (clean caches); refilled on the next setup or build'
            foreach ($dir in $caches | Where-Object { Test-Path $_ }) {
                $mb = [math]::Round((Get-ChildItem $dir -Recurse -File -Force | Measure-Object Length -Sum).Sum / 1MB)
                Write-Host ('  {0,-8} {1,6} MB  {2}' -f (Split-Path $dir -Leaf), $mb, $dir)
            }
            Step 'sources and build trees (clean builds); the next build starts afresh'
            Get-ChildItem "$env:REA_RUNTIME\build" -Directory -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName)" }
            Step "inactive tool versions (clean tools); 'rea-tools use' rolls back to them"
            Invoke-Checked uv run rea-tools prune --dry-run
        }
        if ($Rest -contains 'all') { $Rest = 'caches', 'builds', 'tools' }
        foreach ($what in $Rest) {
            switch ($what) {
                'caches' {
                    Step 'clean caches'
                    Invoke-Checked uv cache clean
                    Invoke-Checked dotnet nuget locals all --clear
                    # npm's own clean leaves _prebuilds (frida); Gradle has no clean command
                    Remove-Item -Recurse -Force "$env:REA_RUNTIME\cache\npm", "$env:REA_RUNTIME\cache\gradle", "$env:CARGO_HOME\registry", "$env:CARGO_HOME\git" -ErrorAction SilentlyContinue
                }
                'builds' { Step 'clean builds'; Remove-Item -Recurse -Force "$env:REA_RUNTIME\build" -ErrorAction SilentlyContinue }
                'tools' { Step 'clean tools'; Invoke-Checked uv run rea-tools prune }
                default { throw "clean what? caches | builds | tools | all" }
            }
        }
    }
}
