# MikroTik Accounting - update an existing installation (keeps data, settings and the Python runtime)
#   - finds the installed folder (scheduled task or C:\MikroTikAccounting)
#   - stops the service, backs up the database and the old program files to data\backups\update-<time>
#   - copies the new program files, installs missing packages, starts the service again
#   - if the new version does not start, the old program files are put back automatically
param(
    [string]$InstallDir = "",
    [switch]$NoBrowser
)
. (Join-Path $PSScriptRoot "common.ps1")

$Src = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$log = Join-Path $env:TEMP "mikrotik-accounting-update.log"
try { Start-Transcript -Path $log -Append | Out-Null } catch { }
$Dirs = @("app", "windows", "mikrotik", "scripts")

function Get-NewVersion {
    $f = Join-Path $Src "app\version.py"
    if (Test-Path $f) {
        $m = Select-String -Path $f -Pattern 'VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($m) { return $m.Matches[0].Groups[1].Value }
    }
    return "?"
}

function Get-RunningVersion([int]$port) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/healthz" -UseBasicParsing -TimeoutSec 3
        $j = $r.Content | ConvertFrom-Json
        if ($j.version) { return [string]$j.version }
        return "old"
    } catch { return "" }
}

function Copy-Program([string]$from, [string]$to) {
    foreach ($d in $Dirs) {
        if (Test-Path (Join-Path $from $d)) {
            robocopy (Join-Path $from $d) (Join-Path $to $d) /MIR /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
            if ($LASTEXITCODE -ge 8) { throw "copy of $d failed (robocopy $LASTEXITCODE)" }
        }
    }
    Get-ChildItem $from -File | Where-Object { $_.Name -ne ".env" -and $_.Name -notlike "*.zip" } |
        Copy-Item -Destination $to -Force
}

function Start-Service-Task([string]$root) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Start-ScheduledTask -TaskName $TaskName
        return $true
    }
    return $false
}

try {
    Say ""
    Say "  MikroTik Accounting - update to version $(Get-NewVersion)" "White"
    if (-not (Test-Admin)) { throw "Administrator rights are required. Right-click update.bat > Run as administrator." }

    Step "Finding the installed program"
    if (-not $InstallDir) {
        try {
            $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($t -and $t.Actions -and $t.Actions[0].WorkingDirectory) { $InstallDir = $t.Actions[0].WorkingDirectory }
        } catch { }
    }
    if (-not $InstallDir) { $InstallDir = "C:\MikroTikAccounting" }
    $InstallDir = $InstallDir.TrimEnd("\")
    if (-not (Test-Path (Join-Path $InstallDir "app\web.py"))) {
        throw "No installation found in $InstallDir. Install with the full package (install.bat), or run: update.bat -InstallDir D:\path\to\program"
    }
    if ($Src.TrimEnd("\").ToLower() -eq $InstallDir.ToLower()) { throw "Run update.bat from the extracted update folder, not from $InstallDir." }
    $py = Get-PythonExe $InstallDir
    if (-not $py) { throw "Python runtime not found in $InstallDir\runtime. Use the full package (install.bat) once." }
    $port = Initialize-EnvFile $InstallDir 0
    $old = Get-RunningVersion $port
    Ok "program folder: $InstallDir (running version: $(if ($old) { $old } else { 'not running' }))"

    Step "Stopping the service"
    Stop-AppProcesses $InstallDir
    Start-Sleep -Seconds 2
    Ok "stopped"

    Step "Backup"
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $bak = Join-Path $InstallDir "data\backups\update-$stamp"
    New-Item -ItemType Directory -Force $bak | Out-Null
    $data = Join-Path $InstallDir "data"
    Get-ChildItem $data -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "accounting.db*" -or $_.Name -eq "secret.key" } |
        Copy-Item -Destination $bak -Force
    if (Test-Path (Join-Path $InstallDir ".env")) { Copy-Item (Join-Path $InstallDir ".env") $bak -Force }
    $bakProg = Join-Path $bak "program"
    New-Item -ItemType Directory -Force $bakProg | Out-Null
    Copy-Program $InstallDir $bakProg
    Ok "database and old program saved in $bak"

    Step "Copying the new version"
    Copy-Program $Src $InstallDir
    Get-ChildItem $InstallDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike "*\runtime\*" -and $_.FullName -notlike "*\data\*" } |
        Unblock-File -ErrorAction SilentlyContinue
    Ok "files updated (data, .env and runtime kept)"

    Step "Python packages"
    Initialize-Packages $InstallDir $py

    Step "Starting the service"
    if (-not (Start-Service-Task $InstallDir)) {
        Warn "service task not found; registering it with the installer..."
        & (Join-Path $InstallDir "windows\install.ps1") -InstallDir $InstallDir -NoBrowser
        if ($LASTEXITCODE -ne 0) { throw "installer failed" }
    }
    Say "    waiting for the panel to start (database is upgraded automatically)..."
    $ok = Wait-Healthy $port 120
    if (-not $ok) {
        Show-LogTail $InstallDir
        Warn "the new version did not start - restoring the previous program files..."
        Stop-AppProcesses $InstallDir
        Start-Sleep -Seconds 2
        Copy-Program $bakProg $InstallDir
        Start-Service-Task $InstallDir | Out-Null
        if (Wait-Healthy $port 90) { Warn "previous version restored and running" }
        throw "Update failed; nothing was lost. Send the log lines above ($InstallDir\data\logs) and $log."
    }
    $new = Get-RunningVersion $port
    if ($new -ne (Get-NewVersion)) { Warn "the panel answers with version '$new' (expected $(Get-NewVersion)); check that no old copy is running" }
    else { Ok "running version $new" }

    Step "Done"
    foreach ($u in (Get-LanUrls $port)) { Say "     $u" "Green" }
    Say "  Backup of this update: $bak" "Gray"
    Say "  To go back: stop the service (manage.bat), copy $bakProg\* over $InstallDir, start it again." "Gray"
    if (-not $NoBrowser) { Start-Process "http://localhost:$port/" }
    exit 0
} catch {
    Say ""
    Say "  UPDATE FAILED: $($_.Exception.Message)" "Red"
    Say "  Full log: $log" "Yellow"
    exit 1
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
