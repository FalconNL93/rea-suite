# Dot-source to load the rea-suite environment:  . .\platforms\windows\env.ps1
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$env:REA_SUITE_ROOT = $Root
$env:VIRTUAL_ENV = "$Root\.venv"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

$state = Get-Content "$Root\tools\state.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($state.ghidra) { $env:GHIDRA_INSTALL_DIR = "$Root\tools\ghidra\$($state.ghidra)" }
if (-not $env:JAVA_HOME) {
    $jdk = Get-ChildItem 'C:\Program Files\Eclipse Adoptium' -Directory -Filter 'jdk-2*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($jdk) { $env:JAVA_HOME = $jdk.FullName }
}

$node = (Get-Content "$Root\.node-version" -Raw).Trim()
fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression
fnm use $node --silent-if-unchanged

$env:Path = @("$Root\tools\bin", "$Root\.venv\Scripts", "$Root\node_modules\.bin", $env:Path) -join ';'
