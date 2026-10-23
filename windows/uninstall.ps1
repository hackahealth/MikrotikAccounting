# MikroTik Accounting - remove service, firewall rules and (optionally) the program and its data
param([string]$InstallDir = "", [switch]$KeepData, [switch]$Yes)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $InstallDir) { $InstallDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
if (-not (Test-Admin)) { throw "Run uninstall.bat as administrator." }
Step "Stopping service"
Stop-AppProcesses $InstallDir
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Ok "service removed"
Step "Firewall rules"
Get-NetFirewallRule -DisplayName "MikroTik Accounting*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Ok "removed"
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "MikroTik Accounting.url") -ErrorAction SilentlyContinue
$deleteData = $false
if (-not $KeepData) {
    $a = if ($Yes) { "n" } else { Read-Host "  Also delete the database and backups in $InstallDir\data ? (y/N)" }
    $deleteData = ($a -eq "y" -or $a -eq "Y")
}
Step "Removing program files"
Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue | Where-Object { $deleteData -or ($_.Name -ne "data" -and $_.Name -ne ".env") } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
if ($deleteData) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue; Ok "everything removed" }
else { Ok "program removed; data and .env kept in $InstallDir (install again to continue with the same data)" }
