# MikroTik Accounting - service management:  manage.bat [status|start|stop|restart|logs|open|reset-password <user> <password>]
param([string]$Command = "", [string]$User = "", [string]$Password = "")
. (Join-Path $PSScriptRoot "common.ps1")
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$port = (Read-EnvFile (Join-Path $Root ".env"))["WEB_PORT"]; if (-not $port) { $port = 8080 }

function Show-Status {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { Warn "service is not installed (run install.bat)"; return }
    $up = Wait-Healthy $port 2
    Say ("  service: " + $t.State + "   panel: " + ($(if ($up) { "UP" } else { "DOWN" })) + "   http://localhost:$port") ($(if ($up) { "Green" } else { "Yellow" }))
}

if (-not $Command) {
    Say "  1) status  2) start  3) stop  4) restart  5) logs  6) open panel  7) reset a panel password"
    $choice = Read-Host "  choose"
    $Command = @{ "1" = "status"; "2" = "start"; "3" = "stop"; "4" = "restart"; "5" = "logs"; "6" = "open"; "7" = "reset-password" }[$choice]
}
if (@("start", "stop", "restart", "reset-password") -contains $Command -and -not (Test-Admin)) {
    throw "Run manage.bat as administrator for '$Command'."
}
switch ($Command) {
    "status" { Show-Status }
    "start" { Start-ScheduledTask -TaskName $TaskName; [void](Wait-Healthy $port 60); Show-Status }
    "stop" { Stop-AppProcesses $Root; Ok "stopped" }
    "restart" { Stop-AppProcesses $Root; Start-Sleep 2; Start-ScheduledTask -TaskName $TaskName; [void](Wait-Healthy $port 60); Show-Status }
    "logs" { Show-LogTail $Root }
    "open" { Start-Process "http://localhost:$port/" }
    "reset-password" {
        if (-not $User) { $User = Read-Host "  panel username" }
        if (-not $Password) { $Password = Read-Host "  new password" }
        $py = Get-PythonExe $Root
        Set-Location $Root
        $r = Invoke-Native $py @("-m", "app.auth", "reset", $User, $Password)
        Say $r.Output
    }
    default { Say "usage: manage.bat [status|start|stop|restart|logs|open|reset-password <user> <password>]" }
}
