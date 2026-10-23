# Run MikroTik Accounting in this console window (no service, no admin rights needed). Ctrl+C stops it.
. (Join-Path $PSScriptRoot "common.ps1")
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root
try {
    Step "Python"
    $py = Initialize-Python $Root
    Step "Python packages"
    Initialize-Packages $Root $py
    Step "Settings (.env)"
    $port = Initialize-EnvFile $Root 0
    Show-PortUsers
    Step "Starting  (panel: http://localhost:$port  -  press Ctrl+C to stop)"
    if (-not (Test-Admin)) { Warn "not running as administrator: Windows Firewall may block RADIUS/NetFlow from the routers (install.bat opens the ports)." }
    Start-Job -ScriptBlock { param($p) Start-Sleep 4; Start-Process "http://localhost:$p/" } -ArgumentList $port | Out-Null
    $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $py -m app.main
    $ErrorActionPreference = $old
} catch {
    Say "ERROR: $($_.Exception.Message)" "Red"
    exit 1
}
