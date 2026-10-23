@echo off
setlocal
title MikroTik Accounting - update
rem Updates an installed MikroTik Accounting (keeps database, settings and Python). Needs administrator rights.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator permission...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\update.ps1" %*
echo.
pause
