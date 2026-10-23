# Shared helpers for install.ps1 / run.ps1 / manage.ps1 (MikroTik Accounting)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

$Global:TaskName = "MikroTik Accounting"
$Global:PyVersion = "3.12.10"
$Global:Modules = "fastapi,uvicorn,sqlalchemy,jinja2,multipart,itsdangerous,pyrad,ldap3,librouteros,Crypto,cryptography,openpyxl,tzdata,paramiko"

function Say([string]$m, [string]$c = "Gray") { Write-Host $m -ForegroundColor $c }
function Step([string]$m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "    !!  $m" -ForegroundColor Yellow }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Run a native program without PowerShell turning its stderr into terminating errors.
function Invoke-Native([string]$exe, [string[]]$arguments) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $exe @arguments 2>&1 | ForEach-Object { "$_" }
        return @{ Code = $LASTEXITCODE; Output = ($out -join "`n") }
    } finally { $ErrorActionPreference = $old }
}

function Get-PythonExe([string]$root) {
    foreach ($p in @("runtime\python\python.exe", "runtime\venv\Scripts\python.exe")) {
        $f = Join-Path $root $p
        if (Test-Path $f) { return $f }
    }
    return $null
}

function Get-PythonwExe([string]$root) {
    $py = Get-PythonExe $root
    if (-not $py) { return $null }
    $w = Join-Path (Split-Path $py) "pythonw.exe"
    if (Test-Path $w) { return $w }
    return $py
}

function Install-PortablePython([string]$root) {
    $dest = Join-Path $root "runtime\python"
    $tmp = Join-Path $env:TEMP "mta-python-$PyVersion.zip"
    $ex = Join-Path $env:TEMP "mta-python-$PyVersion"
    $urls = @("https://api.nuget.org/v3-flatcontainer/python/$PyVersion/python.$PyVersion.nupkg",
              "https://www.nuget.org/api/v2/package/python/$PyVersion")
    foreach ($u in $urls) {
        try {
            Say "    downloading Python $PyVersion from $u ..."
            Invoke-WebRequest -Uri $u -OutFile $tmp -UseBasicParsing
            if (Test-Path $ex) { Remove-Item $ex -Recurse -Force }
            Expand-Archive -Path $tmp -DestinationPath $ex -Force
            New-Item -ItemType Directory -Force $dest | Out-Null
            Copy-Item (Join-Path $ex "tools\*") $dest -Recurse -Force
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            Remove-Item $ex -Recurse -Force -ErrorAction SilentlyContinue
            return (Join-Path $dest "python.exe")
        } catch { Warn "download failed: $($_.Exception.Message)" }
    }
    return $null
}

function New-VenvFromSystemPython([string]$root) {
    foreach ($spec in @("py|-3", "python|", "python3|")) {
        $name, $pre = $spec.Split("|")
        $pre = @($pre | Where-Object { $_ })
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd -or $cmd.Source -like "*WindowsApps*") { continue }   # skip the Microsoft Store stub
        $r = Invoke-Native $cmd.Source ($pre + @("-c", "import sys; print(sys.version_info >= (3, 10))"))
        if ($r.Code -eq 0 -and $r.Output -match "True") {
            $venv = Join-Path $root "runtime\venv"
            $r = Invoke-Native $cmd.Source ($pre + @("-m", "venv", $venv))
            if ($r.Code -eq 0) { return (Join-Path $venv "Scripts\python.exe") }
        }
    }
    return $null
}

# Returns python.exe of the bundled/portable runtime, installing it when missing.
function Initialize-Python([string]$root) {
    $py = Get-PythonExe $root
    if ($py) {
        $r = Invoke-Native $py @("-c", "import sys; print(sys.version.split()[0])")
        if ($r.Code -eq 0) { Ok "Python $($r.Output.Trim()) ($py)"; return $py }
        Warn "bundled Python does not start: $($r.Output)"
    }
    Say "    Python not found next to the program; installing a private copy (no system changes)..."
    $py = Install-PortablePython $root
    if (-not $py) { $py = New-VenvFromSystemPython $root }
    if (-not $py) { throw "Could not get Python. Download the Windows package (mikrotik-accounting-windows.zip) that already contains it, or install Python 3.12 from python.org and run again." }
    Ok "Python ready ($py)"
    return $py
}

function Initialize-Packages([string]$root, [string]$py) {
    $check = "import importlib.util,sys; missing=[m for m in '$Modules'.split(',') if importlib.util.find_spec(m) is None]; print(','.join(missing)); sys.exit(1 if missing else 0)"
    $r = Invoke-Native $py @("-c", $check)
    if ($r.Code -eq 0) { Ok "all Python packages present"; return }
    Say "    missing packages: $($r.Output.Trim()) - installing..."
    $req = Join-Path $root "windows\requirements-windows.txt"
    if (-not (Test-Path $req)) { $req = Join-Path $root "requirements.txt" }
    $wheels = Join-Path $root "runtime\wheels"
    $pipArgs = @("-m", "pip", "install", "--disable-pip-version-check", "--no-warn-script-location", "-r", $req)
    if (Test-Path $wheels) { $pipArgs += @("--no-index", "--find-links", $wheels) }
    $r = Invoke-Native $py @("-m", "pip", "--version")
    if ($r.Code -ne 0) { Invoke-Native $py @("-m", "ensurepip", "--upgrade") | Out-Null }
    $r = Invoke-Native $py $pipArgs
    if ($r.Code -ne 0) { Say $r.Output; throw "pip install failed (internet / proxy?). Use the Windows package that includes all packages." }
    $r = Invoke-Native $py @("-c", $check)
    if ($r.Code -ne 0) { throw "still missing: $($r.Output)" }
    Ok "packages installed"
}

function Test-TcpPortFree([int]$port) {
    try {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $port)
        $l.Start(); $l.Stop(); return $true
    } catch { return $false }
}

function Read-EnvFile([string]$path) {
    $h = @{}
    if (Test-Path $path) {
        foreach ($line in Get-Content $path -Encoding UTF8) {
            $t = $line.Trim()
            if ($t -and -not $t.StartsWith("#") -and $t.Contains("=")) {
                $k, $v = $t.Split("=", 2); $h[$k.Trim()] = $v.Trim()
            }
        }
    }
    return $h
}

function New-RandomSecret([int]$len = 48) {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".ToCharArray()
    $bytes = New-Object byte[] $len
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

# Creates .env on first run; returns the web port.
function Initialize-EnvFile([string]$root, [int]$wantPort = 0) {
    $envFile = Join-Path $root ".env"
    if (Test-Path $envFile) {
        $e = Read-EnvFile $envFile
        $port = if ($e["WEB_PORT"]) { [int]$e["WEB_PORT"] } else { 8080 }
        Ok ".env exists (web port $port)"
        return $port
    }
    $port = $wantPort
    if (-not $port) {
        foreach ($p in @(8080, 8090, 8888, 8081, 9080)) { if (Test-TcpPortFree $p) { $port = $p; break } }
        if (-not $port) { $port = 8080 }
    }
    $lines = @(
        "# MikroTik Accounting settings (created by the installer)",
        "ADMIN_USER=admin",
        "ADMIN_PASSWORD=admin",
        "TZ_NAME=Asia/Tehran",
        "WEB_PORT=$port",
        "RADIUS_AUTH_PORT=1812",
        "RADIUS_ACCT_PORT=1813",
        "NETFLOW_PORT=2055",
        "ACCT_INTERIM=60"
    )
    # keep the encryption key of an existing database (it lives in data\secret.key)
    if (-not (Test-Path (Join-Path $root "data\accounting.db"))) { $lines += "SECRET_KEY=$(New-RandomSecret)" }
    [IO.File]::WriteAllLines($envFile, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
    Ok ".env created (web port $port)"
    return $port
}

function Show-PortUsers {
    foreach ($p in @(1812, 1813, 2055)) {
        try {
            $eps = Get-NetUDPEndpoint -LocalPort $p -ErrorAction SilentlyContinue
            foreach ($ep in $eps) {
                $proc = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
                if ($proc -and $proc.ProcessName -notmatch "^pythonw?$") {
                    Warn "UDP port $p is already used by '$($proc.ProcessName)' (PID $($proc.Id))."
                    if ($p -ne 2055) { Warn "  If this is Windows NPS (RADIUS server role), stop it ('Stop-Service IAS') or change RADIUS_AUTH_PORT / RADIUS_ACCT_PORT in .env and on the router." }
                }
            }
        } catch { }
    }
}

function Get-LanUrls([int]$port) {
    $ips = @()
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -ExpandProperty IPAddress
    } catch { }
    return @("http://localhost:$port") + ($ips | ForEach-Object { "http://$($_):$port" })
}

function Stop-AppProcesses([string]$root) {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
    $rootLower = $root.ToLower().TrimEnd("\")
    try {
        Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith($rootLower) } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch { }
}

function Wait-Healthy([int]$port, [int]$seconds = 90) {
    for ($i = 0; $i -lt $seconds; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/healthz" -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Show-LogTail([string]$root) {
    foreach ($f in @("data\logs\console.log", "data\logs\app.log", "data\logs\service.log")) {
        $p = Join-Path $root $f
        if (Test-Path $p) { Say "---- $f (last lines) ----" "Yellow"; Get-Content $p -Tail 25 | ForEach-Object { Say $_ } }
    }
}
