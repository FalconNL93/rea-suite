@echo off
rem rea-suite on Windows (counterpart of bin/rea-suite): platforms\windows\rea-suite.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\platforms\windows\rea-suite.ps1" %*
exit /b %errorlevel%
