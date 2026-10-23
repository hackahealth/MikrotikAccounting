# MikroTik Accounting - Windows installer
#   - copies the program to C:\MikroTikAccounting (keeps data and .env when updating)
#   - uses the bundled Python (or downloads a private copy), installs missing packages
#   - creates .env, opens the firewall, registers a background service (scheduled task as SYSTEM)
#   - starts it and opens the panel in the browser
param(
    [string]$InstallDir = "C:\MikroTikAccounting",
    [int]$WebPort = 0,
    [switch]$NoService,
    [switch]$NoBrowser
)
. (Join-Path $PSScriptRoot "common.ps1")

$Src = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$log = Join-Path $env:TEMP "mikrotik-accounting-install.log"
try { Start-Transcript -Path $log -Append | Out-Null } catch { }

try {
    Say ""
    Say "  MikroTik Accounting - Windows installer" "White"
    if (-not (Test-Admin)) { throw "Administrator rights are required. Right-click install.bat > Run as administrator." }

    Step "Copying program to $InstallDir"
    $same = ($Src.TrimEnd("\").ToLower() -eq $InstallDir.TrimEnd("\").ToLower())
    $firstInstall = -not (Test-Path (Join-Path $InstallDir "data\accounting.db"))
    Stop-AppProcesses $InstallDir
    if (-not $same) {
        New-Item -ItemType Directory -Force $InstallDir | Out-Null
        foreach ($d in @("app", "windows", "mikrotik", "scripts")) {
            if (Test-Path (Join-Path $Src $d)) {
                robocopy (Join-Path $Src $d) (Join-Path $InstallDir $d) /MIR /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
                if ($LASTEXITCODE -ge 8) { throw "copy of $d failed (robocopy $LASTEXITCODE)" }
            }
        }
        if (Test-Path (Join-Path $Src "runtime")) {
            Say "    copying bundled Python runtime..."
            robocopy (Join-Path $Src "runtime") (Join-Path $InstallDir "runtime") /MIR /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
            if ($LASTEXITCODE -ge 8) { throw "copy of runtime failed (robocopy $LASTEXITCODE)" }
        }
        Get-ChildItem $Src -File | Where-Object { $_.Name -ne ".env" } | Copy-Item -Destination $InstallDir -Force
        Ok "files copied"
    } else { Ok "running from the install folder" }
    Get-ChildItem $InstallDir -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

    Step "Python"
    $py = Initialize-Python $InstallDir

    Step "Python packages"
    Initialize-Packages $InstallDir $py

    Step "Settings (.env)"
    $port = Initialize-EnvFile $InstallDir $WebPort
    New-Item -ItemType Directory -Force (Join-Path $InstallDir "data\logs") | Out-Null

    $envVals = Read-EnvFile (Join-Path $InstallDir ".env")
    $rAuth = if ($envVals["RADIUS_AUTH_PORT"]) { [int]$envVals["RADIUS_AUTH_PORT"] } else { 1812 }
    $rAcct = if ($envVals["RADIUS_ACCT_PORT"]) { [int]$envVals["RADIUS_ACCT_PORT"] } else { 1813 }
    $flow = if ($envVals["NETFLOW_PORT"]) { [int]$envVals["NETFLOW_PORT"] } else { 2055 }

    Step "Checking ports"
    Show-PortUsers
    Ok "web panel port $port, RADIUS $rAuth/$rAcct UDP, NetFlow $flow UDP"

    Step "Windows Firewall"
    try {
        Get-NetFirewallRule -DisplayName "MikroTik Accounting*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "MikroTik Accounting - Web panel" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "MikroTik Accounting - RADIUS" -Direction Inbound -Protocol UDP -LocalPort $rAuth, $rAcct -Action Allow -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "MikroTik Accounting - NetFlow" -Direction Inbound -Protocol UDP -LocalPort $flow -Action Allow -Profile Any | Out-Null
    } catch {
        netsh advfirewall firewall delete rule name="MikroTik Accounting - Web panel" | Out-Null
        netsh advfirewall firewall delete rule name="MikroTik Accounting - RADIUS" | Out-Null
        netsh advfirewall firewall delete rule name="MikroTik Accounting - NetFlow" | Out-Null
        netsh advfirewall firewall add rule name="MikroTik Accounting - Web panel" dir=in action=allow protocol=TCP localport=$port | Out-Null
        netsh advfirewall firewall add rule name="MikroTik Accounting - RADIUS" dir=in action=allow protocol=UDP "localport=$rAuth,$rAcct" | Out-Null
        netsh advfirewall firewall add rule name="MikroTik Accounting - NetFlow" dir=in action=allow protocol=UDP localport=$flow | Out-Null
    }
    Ok "inbound TCP $port, UDP $rAuth,$rAcct, UDP $flow allowed"

    if (-not $NoService) {
        Step "Background service (starts with Windows, restarts automatically)"
        $pyw = Get-PythonwExe $InstallDir
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute $pyw -Argument "-m app.supervisor" -WorkingDirectory $InstallDir
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description "MikroTik Accounting (RADIUS + NetFlow + web panel)" | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        Say "    waiting for the panel to start..."
        if (-not (Wait-Healthy $port 90)) {
            Show-LogTail $InstallDir
            throw "The service did not start. See the log lines above (folder $InstallDir\data\logs)."
        }
        Ok "service '$TaskName' is running"

        $url = "http://localhost:$port/"
        try {
            $lnk = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "MikroTik Accounting.url"
            [IO.File]::WriteAllLines($lnk, [string[]]@("[InternetShortcut]", "URL=$url"))
        } catch { }
    }

    Step "Done"
    Say "  Panel address:" "White"
    foreach ($u in (Get-LanUrls $port)) { Say "     $u" "Green" }
    if ($firstInstall) {
        Say "  First login:  admin / admin   (you must choose a new password)" "White"
        Say "  Accounts 'it' and 'hr' are created disabled: set a password and enable them under Panel users." "Gray"
    }
    Say "  Program folder: $InstallDir   (data and backups: $InstallDir\data)" "Gray"
    Say "  Manage service: $InstallDir\manage.bat   Remove: $InstallDir\uninstall.bat" "Gray"
    Say "  Router side: import mikrotik\setup.rsc on each MikroTik (see README)." "Gray"
    if (-not $NoService -and -not $NoBrowser) { Start-Process "http://localhost:$port/" }
    exit 0
} catch {
    Say ""
    Say "  INSTALL FAILED: $($_.Exception.Message)" "Red"
    Say "  Full log: $log" "Yellow"
    exit 1
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
