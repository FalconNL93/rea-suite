# Load the rea-suite environment (counterpart of common/env.sh):
#   . .\platforms\windows\env.ps1      (or . .\activate.ps1 from the repo root)
# Runtimes and caches live in .runtime\ (platforms\windows\bootstrap.ps1).
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Runtime = "$Root\.runtime"
$env:REA_SUITE_ROOT = $Root
$env:REA_RUNTIME = $Runtime

# Settings: the environment of the run wins, then .env (see .env.example), then the
# defaults below (counterpart of common/env.sh). Defaults computed here are listed in
# REA_SUITE_COMPUTED and computed again on every load.
foreach ($name in "$env:REA_SUITE_COMPUTED".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) { Remove-Item "env:$name" -ErrorAction SilentlyContinue }
$env:REA_SUITE_COMPUTED = ''
foreach ($line in Get-Content "$Root\.env" -ErrorAction SilentlyContinue) {
    if ($line -match '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$' -and -not (Test-Path "env:$($Matches[1])")) {
        Set-Item "env:$($Matches[1])" ($Matches[2].Trim() -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1')
    }
}
function Set-ReaDefault($name, $value) {
    if (Test-Path "env:$name") { return }
    Set-Item "env:$name" $value
    $env:REA_SUITE_COMPUTED = "$env:REA_SUITE_COMPUTED $name"
}

# --- runtimes in .runtime\ -----------------------------------------------------
$env:UV_PYTHON_INSTALL_DIR = "$Runtime\python"
$env:UV_PYTHON_PREFERENCE = 'only-managed'
$env:UV_CACHE_DIR = "$Runtime\cache\uv"
$env:UV_TOOL_DIR = "$Runtime\uv-tools"
$env:UV_TOOL_BIN_DIR = "$Runtime\uv-tools\bin"
$env:FNM_DIR = "$Runtime\fnm"
$env:npm_config_cache = "$Runtime\cache\npm"
$env:DOTNET_ROOT = "$Runtime\dotnet"
$env:DOTNET_CLI_HOME = "$Runtime\dotnet-home"
$env:NUGET_PACKAGES = "$Runtime\cache\nuget"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
$env:GRADLE_USER_HOME = "$Runtime\cache\gradle"
# Browsers for REA (component `browser`; rea-suite.ps1 setup installs them)
$env:PLAYWRIGHT_BROWSERS_PATH = "$Runtime\ms-playwright"
$chromium = Get-Content "$Runtime\chromium-path" -ErrorAction SilentlyContinue
if ($chromium) { Set-ReaDefault REA_BROWSER_EXECUTABLE $chromium.Trim() }
# Rust toolchain for source builds (rustup from component `build`)
$env:RUSTUP_HOME = "$Runtime\rustup"
$env:CARGO_HOME = "$Runtime\cargo"
$jdk = Get-Content "$Runtime\jdk\current.txt" -ErrorAction SilentlyContinue
if ($jdk -and (Test-Path "$Runtime\jdk\$jdk\bin\java.exe")) { $env:JAVA_HOME = "$Runtime\jdk\$jdk" }

$paths = @("$Root\bin", "$Root\tools\bin", "$Root\.venv\Scripts", "$Root\node_modules\.bin", "$Runtime\bin", $env:UV_TOOL_BIN_DIR, $env:DOTNET_ROOT, "$env:CARGO_HOME\bin")
if ($env:JAVA_HOME) { $paths += "$env:JAVA_HOME\bin" }
if (Test-Path "$Runtime\bin\fnm.exe") {
    $node = (Get-Content "$Root\.node-version" -Raw).Trim()
    $nodeDir = & "$Runtime\bin\fnm.exe" exec --using=$node -- node -p 'require("path").dirname(process.execPath)' 2>$null
    if ($nodeDir) { $paths += $nodeDir }
}
$env:Path = (($paths | Where-Object { Test-Path $_ }) + $env:Path) -join ';'

# --- project environment ---------------------------------------------------------
$env:VIRTUAL_ENV = "$Root\.venv"
$state = Get-Content "$Root\tools\state.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($state.ghidra) { Set-ReaDefault GHIDRA_INSTALL_DIR "$Root\tools\ghidra\$($state.ghidra)" }

# Absolute engine paths for rea-agents
$jar = Get-ChildItem "$Root\tools\jadx-headless-mcp" -Recurse -Filter '*-all.jar' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($jar) { Set-ReaDefault REA_JADX_MCP_JAR $jar.FullName }
if (Test-Path "$Root\.venv\Scripts\python.exe") { Set-ReaDefault REA_PWNTOOLS_PYTHON "$Root\.venv\Scripts\python.exe" }
if ($state.wabt) { Set-ReaDefault REA_WABT_BIN_DIRECTORY "$Root\tools\wabt\$($state.wabt)\bin" }
foreach ($pair in @(
        @('REA_RIZIN_COMMAND', 'rizin'), @('REA_KUNA_COMMAND', 'kuna'), @('REA_APKTOOL_COMMAND', 'apktool'),
        @('REA_WAKARU_COMMAND', 'wakaru'), @('REA_ILSPY_CMD_PATH', 'ilspycmd'), @('REA_MITMDUMP_COMMAND', 'mitmdump'),
        @('REA_TSHARK_COMMAND', 'tshark'), @('REA_ADB_PATH', 'adb'), @('REA_SIGROK_COMMAND', 'sigrok-cli'))) {
    $cmd = Get-Command $pair[1] -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { Set-ReaDefault $pair[0] $cmd.Source }
}
