@echo off
setlocal
title MikroTik Accounting - uninstall
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
set "MTA_TMP=%TEMP%\mta-uninstall"
if exist "%MTA_TMP%" rmdir /s /q "%MTA_TMP%"
mkdir "%MTA_TMP%"
copy /y "%~dp0windows\common.ps1" "%MTA_TMP%\" >nul
copy /y "%~dp0windows\uninstall.ps1" "%MTA_TMP%\" >nul
set "MTA_DIR=%~dp0"
if "%MTA_DIR:~-1%"=="\" set "MTA_DIR=%MTA_DIR:~0,-1%"
cd /d "%TEMP%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%MTA_TMP%\uninstall.ps1" -InstallDir "%MTA_DIR%"
echo.
pause
