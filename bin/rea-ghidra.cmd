@echo off
rem rea-ghidra on Windows (counterpart of bin/rea-ghidra): platforms\windows\rea-ghidra.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\platforms\windows\rea-ghidra.ps1" %*
exit /b %errorlevel%
