@echo off
setlocal
title MikroTik Accounting - manage
cd /d "%~dp0"
if "%~1"=="" (
    net session >nul 2>&1
    if errorlevel 1 (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
        exit /b
    )
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\manage.ps1" %*
echo.
pause
