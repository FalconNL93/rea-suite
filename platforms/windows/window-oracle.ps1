<#
.SYNOPSIS
    Watch one process's window while an input driver plays a schedule: captures of only that
    window before and after each scheduled input, and a report of the process (modules,
    connections, DNS). Windows only.
.DESCRIPTION
    Launch a program (-Exe) or wait for a running one (-ProcessName, -ProcessId), start the input
    driver (-Pad: rea-suite pad with the same schedule; or any -InputCommand), and time every
    capture from the driver's start: the moment `rea-suite pad` reports "plugged", else when the
    driver process started. For each scheduled input at time T it saves before<i>.png at
    T - Before and after<i>.png at T + After, then final.png, all with PrintWindow, so other
    windows and the desktop never appear in them. It focuses the window (once, a few seconds
    before the first input) unless -NoFocus. events.jsonl records what happened and when;
    report.json the process, its modules, its TCP connections and UDP endpoints, and the DNS
    client cache (system-wide: names the process may have looked up).
.EXAMPLE
    .\platforms\windows\window-oracle.ps1 -Exe D:\work\run\Game.exe -Schedule 30:DOWN,33:DOWN,36:A -Pad -Out work\pad-a
.EXAMPLE
    .\platforms\windows\window-oracle.ps1 -ProcessName Game -Schedule 10:A -Pad -PadArguments --idle-pad -Seconds 30
.EXAMPLE
    .\platforms\windows\window-oracle.ps1 -ProcessName Game -Schedule 5:x,9:x -InputCommand python,keys.py -NoFocus
.NOTES
    Captures need the window on an unlocked desktop; PrintWindow with PW_RENDERFULLCONTENT also
    draws DirectX windows, but a full-screen exclusive game may come out black.
#>
#Requires -Version 7
[CmdletBinding(DefaultParameterSetName = 'Launch')]
param(
    [Parameter(ParameterSetName = 'Launch', Mandatory)][string]$Exe,
    [Parameter(ParameterSetName = 'Launch')][string[]]$ArgumentList = @(),
    [Parameter(ParameterSetName = 'Launch')][string]$WorkingDirectory,
    [Parameter(ParameterSetName = 'Name', Mandatory)][string]$ProcessName,
    [Parameter(ParameterSetName = 'Id', Mandatory)][int]$ProcessId,
    [double]$WaitSeconds = 240,          # how long to wait for -ProcessName to appear
    [Parameter(Mandatory)][string]$Schedule,   # TIME:INPUT,... as rea-suite pad takes it; times count here
    [switch]$Pad,                        # input driver: rea-suite pad --presses $Schedule
    [string[]]$PadArguments = @(),       # more arguments for the pad (--idle-pad, --hold 0.2, --dll ...)
    [string[]]$InputCommand = @(),       # another input driver: program, then its arguments
    [string]$Out,                        # default work\window-oracle\<time>
    [double]$Seconds = 60,               # from the driver's start
    [double]$Before = 0.6,
    [double]$After = 1.2,
    [switch]$NoFocus,
    [switch]$NoReport,
    [switch]$Close                       # close a process this script launched, at the end
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
if (-not $Out) { $Out = Join-Path $Root ("work\window-oracle\" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$Out = [System.IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force -Path $Out | Out-Null
if ($Pad -and $InputCommand.Count) { throw 'give -Pad or -InputCommand, not both' }

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class OracleWin32 {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  public struct RECT { public int Left, Top, Right, Bottom; }
}
'@

$times = @($Schedule.Split(',') | Where-Object { $_.Trim() } | ForEach-Object {
        [double]::Parse($_.Trim().Split(':')[0], [Globalization.CultureInfo]::InvariantCulture) } | Sort-Object)
if (-not $times.Count) { throw "no times in -Schedule '$Schedule'" }
$events = Join-Path $Out 'events.jsonl'
$clock = [Diagnostics.Stopwatch]::StartNew()
$zero = $null   # driver start, on $clock
function Since { if ($null -eq $zero) { $null } else { [math]::Round($clock.Elapsed.TotalSeconds - $zero, 3) } }
function Log([hashtable]$fields) {
    $fields['t'] = Since
    $fields['clock'] = [math]::Round($clock.Elapsed.TotalSeconds, 3)
    ($fields | ConvertTo-Json -Compress -Depth 4) | Add-Content -Path $events -Encoding utf8
}

function Window($proc) {
    $proc.Refresh()
    return $proc.MainWindowHandle
}

function Shot($proc, [string]$name) {
    $handle = Window $proc
    if ($handle -eq [IntPtr]::Zero) { Log @{ event = 'shot-skipped'; name = $name; reason = 'no window' }; return }
    if ([OracleWin32]::IsIconic($handle)) { Log @{ event = 'shot-skipped'; name = $name; reason = 'minimized' }; return }
    $rect = New-Object OracleWin32+RECT
    $null = [OracleWin32]::GetClientRect($handle, [ref]$rect)
    if ($rect.Right -le 0 -or $rect.Bottom -le 0) { Log @{ event = 'shot-skipped'; name = $name; reason = 'empty client area' }; return }
    $bitmap = New-Object System.Drawing.Bitmap $rect.Right, $rect.Bottom
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $dc = $graphics.GetHdc()
    $ok = [OracleWin32]::PrintWindow($handle, $dc, 3)   # PW_CLIENTONLY | PW_RENDERFULLCONTENT
    $graphics.ReleaseHdc($dc)
    $path = Join-Path $Out "$name.png"
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose(); $bitmap.Dispose()
    Log @{ event = 'shot'; name = $name; ok = $ok; width = $rect.Right; height = $rect.Bottom }
}

function Focus($proc) {
    $handle = Window $proc
    if ($handle -eq [IntPtr]::Zero) { return $false }
    # Windows lets a process take the foreground after a key event; Alt is the harmless one.
    [OracleWin32]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
    $null = [OracleWin32]::SetForegroundWindow($handle)
    [OracleWin32]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 300
    return ([OracleWin32]::GetForegroundWindow() -eq $handle)
}

function Report($proc) {
    $proc.Refresh()
    $report = [ordered]@{
        time    = (Get-Date).ToString('o')
        process = [ordered]@{ id = $proc.Id; name = $proc.ProcessName; path = $proc.Path; exited = $proc.HasExited
            start = if ($proc.StartTime) { $proc.StartTime.ToString('o') } else { $null }; title = $proc.MainWindowTitle }
        modules = @(); tcp = @(); udp = @(); dns = @()
    }
    if (-not $proc.HasExited) {
        try {
            $report.modules = @($proc.Modules | ForEach-Object { [ordered]@{ name = $_.ModuleName; path = $_.FileName
                    base = ('0x{0:x}' -f $_.BaseAddress.ToInt64()); size = $_.ModuleMemorySize; version = $_.FileVersionInfo.FileVersion } })
        } catch { $report.modules_error = $_.Exception.Message }
        try {
            $report.tcp = @(Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue | ForEach-Object {
                    [ordered]@{ local = "$($_.LocalAddress):$($_.LocalPort)"; remote = "$($_.RemoteAddress):$($_.RemotePort)"; state = "$($_.State)" } })
            $report.udp = @(Get-NetUDPEndpoint -OwningProcess $proc.Id -ErrorAction SilentlyContinue | ForEach-Object {
                    [ordered]@{ local = "$($_.LocalAddress):$($_.LocalPort)" } })
        } catch { $report.network_error = $_.Exception.Message }
    }
    try {
        $report.dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object {
                [ordered]@{ name = $_.Entry; type = "$($_.Type)"; data = $_.Data } })
    } catch { $report.dns_error = $_.Exception.Message }
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $Out 'report.json') -Encoding utf8
}

# --- the process ----------------------------------------------------------------------
$launched = $false
switch ($PSCmdlet.ParameterSetName) {
    'Launch' {
        $start = @{ FilePath = $Exe; PassThru = $true }
        if ($ArgumentList.Count) { $start.ArgumentList = $ArgumentList }
        $start.WorkingDirectory = if ($WorkingDirectory) { $WorkingDirectory } else { Split-Path -Parent (Resolve-Path $Exe) }
        $target = Start-Process @start
        $launched = $true
    }
    'Name' {
        $wait = [Diagnostics.Stopwatch]::StartNew(); $target = $null
        while (-not $target -and $wait.Elapsed.TotalSeconds -lt $WaitSeconds) {
            $target = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $target) { Start-Sleep -Milliseconds 500 }
        }
        if (-not $target) { throw "no process '$ProcessName' within $WaitSeconds s" }
    }
    'Id' { $target = Get-Process -Id $ProcessId }
}
Log @{ event = 'process'; id = $target.Id; launched = $launched }

# --- the input driver -----------------------------------------------------------------
$driver = $null
$driverOut = Join-Path $Out 'input.jsonl'
if ($Pad) {
    $suite = Join-Path $Root 'platforms\windows\rea-suite.ps1'
    $pwsh = (Get-Process -Id $PID).Path
    $driver = Start-Process -FilePath $pwsh -PassThru -NoNewWindow -RedirectStandardOutput $driverOut `
        -RedirectStandardError (Join-Path $Out 'input.err') `
        -ArgumentList (@('-NoProfile', '-File', $suite, 'pad', '--presses', $Schedule, '--tail', '1') + $PadArguments)
} elseif ($InputCommand.Count) {
    $driver = Start-Process -FilePath $InputCommand[0] -ArgumentList ($InputCommand | Select-Object -Skip 1) -PassThru -NoNewWindow `
        -RedirectStandardOutput $driverOut -RedirectStandardError (Join-Path $Out 'input.err')
}
$driverStart = $clock.Elapsed.TotalSeconds
if ($driver) {
    # The pad's times count from its "plugged" line; wait for it (5 s at most), else take the start.
    while ($Pad -and $clock.Elapsed.TotalSeconds - $driverStart -lt 5 -and -not $driver.HasExited) {
        if ((Test-Path $driverOut) -and (Select-String -Path $driverOut -Pattern '"event": "plugged"' -SimpleMatch -Quiet)) { break }
        Start-Sleep -Milliseconds 20
    }
    $plugged = (Test-Path $driverOut) -and (Select-String -Path $driverOut -Pattern '"event": "plugged"' -SimpleMatch -Quiet)
    $zero = if ($plugged) { $clock.Elapsed.TotalSeconds } else { $driverStart }
    Log @{ event = 'input-start'; driver = $driver.Id; from = $(if ($plugged) { 'plugged' } else { 'process start' }) }
} else {
    $zero = $driverStart
    Log @{ event = 'input-start'; driver = $null; from = 'no driver: the schedule counts from now' }
}

# --- the watch ------------------------------------------------------------------------
$focused = $NoFocus.IsPresent
$index = 0; $took = $false
while (-not $target.HasExited -and (Since) -lt $Seconds) {
    Start-Sleep -Milliseconds 50
    $t = Since
    if (-not $focused -and $t -ge ($times[0] - 4)) {
        $focused = Focus $target
        Log @{ event = 'focus'; ok = $focused }
        $focused = $true   # one attempt; the log says whether it took
    }
    if ($index -lt $times.Count -and -not $took -and $t -ge $times[$index] - $Before) { Shot $target ("before{0}" -f $index); $took = $true }
    if ($index -lt $times.Count -and $t -ge $times[$index] + $After) { Shot $target ("after{0}" -f $index); $index++; $took = $false }
    if ($index -ge $times.Count -and $t -ge $times[-1] + $After + 0.5) { break }
}
if (-not $target.HasExited) { Shot $target 'final' }
if (-not $NoReport) { Report $target }
Log @{ event = 'end'; exited = $target.HasExited; exit_code = $(if ($target.HasExited) { $target.ExitCode } else { $null }) }
if ($driver -and -not $driver.HasExited) { & taskkill.exe /T /F /PID $driver.Id | Out-Null }   # with its children (uv, python)
if ($Close -and $launched -and -not $target.HasExited) {
    $null = $target.CloseMainWindow()
    if (-not $target.WaitForExit(30000)) { $target | Stop-Process -Force }
}
Write-Output $Out
