@echo off
rem REA with the suite environment on Windows (counterpart of bin/rea): platforms\windows\rea.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\platforms\windows\rea.ps1" %*
exit /b %errorlevel%
