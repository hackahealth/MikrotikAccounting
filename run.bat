@echo off
setlocal
title MikroTik Accounting
rem Runs the program in this window (for a quick test). For permanent use run install.bat instead.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\run.ps1"
echo.
pause
