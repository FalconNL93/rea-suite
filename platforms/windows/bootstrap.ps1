<#
.SYNOPSIS
    First-time installer for rea-suite on Windows. Safe to re-run.
.DESCRIPTION
    1. runtimes into .runtime\: uv, fnm (+ Node), Temurin JDK, .NET SDK;
       downloads are checksum-verified where upstream publishes checksums
    2. optional components: a menu on the first run (stored in .env; see
       .env.example to preselect)
    3. system packages via winget (only what needs a driver or system install)
    4. rea-suite.ps1 setup: Python env, npm, tools.yml
    Not tested on Windows yet.
.PARAMETER NoWinget
    Skip winget (step 3).
.PARAMETER Select
    Show the component menu again.
.PARAMETER Update
    Also upgrade runtimes (and winget packages) that are already installed.
.PARAMETER RuntimesOnly
    Stop after step 1 (used by rea-suite.ps1 update).
#>
param([switch]$NoWinget, [switch]$Update, [switch]$RuntimesOnly, [switch]$Select)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # Invoke-WebRequest is very slow with progress
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $Root

$JdkMajor = 21          # REA verifies Ghidra 12.1 on JDK 21 (rea-tools rea-pins)
$DotnetChannel = '10.0' # LTS; ilspycmd
$Runtime = "$Root\.runtime"
New-Item -ItemType Directory -Force "$Runtime\bin", "$Runtime\cache" | Out-Null
. "$PSScriptRoot\env.ps1"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Blue }
function Note($msg) { Write-Host "    $msg" }
function Latest-Tag($repo) {
    # /releases/latest redirects to /releases/tag/<tag>; no API rate limit
    $r = Invoke-WebRequest "https://github.com/$repo/releases/latest" -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
    if (-not $r.Headers.Location) { $r = Invoke-WebRequest "https://github.com/$repo/releases/latest" }
    $loc = if ($r.Headers.Location) { [string]$r.Headers.Location } else { $r.BaseResponse.RequestMessage.RequestUri.AbsoluteUri }
    return ($loc -split '/tag/')[-1]
}
function Fetch($url, $dest, $sha256) {
    Invoke-WebRequest $url -OutFile $dest
    if ($sha256 -and ((Get-FileHash $dest -Algorithm SHA256).Hash -ne $sha256.ToUpper())) {
        throw "checksum mismatch for $url"
    }
}
function Wanted($name, $have, $latest) {
    if (-not $have) { return $true }
    if ($Update -and $have -ne $latest) { return $true }
    Note "$name $have is installed"; return $false
}

# --- 1. runtimes -------------------------------------------------------------
Step 'uv'
$have = if (Test-Path "$Runtime\bin\uv.exe") { (& "$Runtime\bin\uv.exe" --version).Split(' ')[1] }
$tag = Latest-Tag 'astral-sh/uv'
if (Wanted 'uv' $have $tag) {
    $url = "https://github.com/astral-sh/uv/releases/download/$tag/uv-x86_64-pc-windows-msvc.zip"
    $sum = ((Invoke-WebRequest "$url.sha256").Content -split '\s+')[0]
    Fetch $url "$Runtime\cache\uv.zip" $sum
    Expand-Archive "$Runtime\cache\uv.zip" "$Runtime\bin" -Force
    Note "uv $tag"
}

$node = (Get-Content .node-version -Raw).Trim()
Step "fnm + Node $node"
$have = if (Test-Path "$Runtime\bin\fnm.exe") { 'v' + (& "$Runtime\bin\fnm.exe" --version).Split(' ')[1] }
$tag = Latest-Tag 'Schniz/fnm'
if (Wanted 'fnm' $have $tag) {
    Fetch "https://github.com/Schniz/fnm/releases/download/$tag/fnm-windows.zip" "$Runtime\cache\fnm.zip"
    Expand-Archive "$Runtime\cache\fnm.zip" "$Runtime\bin" -Force
    Note "fnm $tag"
}
& "$Runtime\bin\fnm.exe" install $node

Step "Temurin JDK $JdkMajor"
$meta = (Invoke-RestMethod "https://api.adoptium.net/v3/assets/latest/$JdkMajor/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse")[0]
$name = $meta.release_name
$current = Get-Content "$Runtime\jdk\current.txt" -ErrorAction SilentlyContinue
if ($current -eq $name -and (Test-Path "$Runtime\jdk\$name\bin\java.exe")) {
    Note "$name is installed"
} elseif ($current -match "^jdk-$JdkMajor[.+]" -and -not $Update) {
    Note "$current is installed ($name available; use -Update)"
} else {
    Fetch $meta.binary.package.link "$Runtime\cache\jdk.zip" $meta.binary.package.checksum
    $tmp = "$Runtime\cache\jdk-extract"
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Expand-Archive "$Runtime\cache\jdk.zip" $tmp
    Get-ChildItem "$Runtime\jdk" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
    New-Item -ItemType Directory -Force "$Runtime\jdk" | Out-Null
    Move-Item (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName "$Runtime\jdk\$name"
    Set-Content "$Runtime\jdk\current.txt" $name
    Remove-Item -Recurse -Force $tmp
    Note $name
}

Step ".NET SDK $DotnetChannel"
if ((Test-Path "$Runtime\dotnet\dotnet.exe") -and -not $Update) {
    Note "$(& "$Runtime\dotnet\dotnet.exe" --version) is installed"
} else {
    # Microsoft's official installer script; installs only into .runtime\dotnet
    Fetch 'https://dot.net/v1/dotnet-install.ps1' "$Runtime\cache\dotnet-install.ps1"
    & "$Runtime\cache\dotnet-install.ps1" -Channel $DotnetChannel -InstallDir "$Runtime\dotnet" -NoPath
}

# A .venv built on an interpreter outside .runtime\ would keep pointing there.
if ((Test-Path .venv\pyvenv.cfg) -and -not (Select-String -Quiet -SimpleMatch "home = $Runtime\python" .venv\pyvenv.cfg)) {
    Step 'recreating .venv on the local Python'
    Remove-Item -Recurse -Force .venv
}

if ($RuntimesOnly) { return }
. "$PSScriptRoot\env.ps1"

# --- 2. optional components -------------------------------------------------------
Step 'optional components'
if ($Select) { uv run --quiet common\rea_suite\components.py select }
else { uv run --quiet common\rea_suite\components.py select --if-unset }
uv run --quiet common\rea_suite\components.py list

# --- 3. winget ------------------------------------------------------------------
if (-not $NoWinget) {
    Step 'winget packages'
    & "$PSScriptRoot\rea-suite.ps1" winget
}

# --- 4. setup ---------------------------------------------------------------------
& "$PSScriptRoot\rea-suite.ps1" setup
