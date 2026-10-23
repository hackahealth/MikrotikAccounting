"""چه کسی روی کدام رایانه وارد شده: ورود ویندوز کاربران دامنه از Security Log کنترلرهای دامنه (Kerberos 4768/4770،
IP رایانه -> MAC از سابقه دستگاه‌ها) یا از اسکریپت ورود (GPO) که خود رایانه به برنامه خبر می‌دهد."""
import base64
import logging
import os
import subprocess
import threading
from datetime import datetime, timedelta

from sqlalchemy import func

from . import devices
from .db import Device, DeviceHistory, User, SessionLocal, decrypt, get_setting, now, set_setting

log = logging.getLogger("logons")
_LOCK = threading.Lock()
OVERLAP = timedelta(minutes=3)
FIRST_READ = timedelta(hours=12)

# Get-WinEvent on the DC with the AD service account (password via environment, never on the command line).
# 4768 = Kerberos TGT (each Windows logon / unlock), 4770 = ticket renewed (still logged on, every ~10 h).
PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$sec = ConvertTo-SecureString $env:MTA_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:MTA_USER, $sec)
$since = [datetime]::ParseExact($env:MTA_SINCE, 'yyyy-MM-ddTHH:mm:ss', $null)
try {
  $ev = Get-WinEvent -ComputerName $env:MTA_DC -Credential $cred -MaxEvents 50000 `
        -FilterHashtable @{LogName='Security'; Id=4768,4770; StartTime=$since}
} catch {
  if ($_.Exception.Message -match 'No events were found|^No events') { exit 0 }
  [Console]::Error.WriteLine($_.Exception.Message); exit 2
}
foreach ($e in $ev) {
  $d = @{}
  foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
  "{0}`t{1}`t{2}`t{3}`t{4}" -f $e.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss'), $e.Id, $d['TargetUserName'], $d['IpAddress'], $d['Status']
}
"""


def _clean_ip(ip):
    ip = (ip or "").strip()
    if ip.lower().startswith("::ffff:"):
        ip = ip[7:]
    return "" if ip in ("", "-", "::1", "127.0.0.1") else ip


def _clean_user(user):
    u = (user or "").strip()
    if "\\" in u:
        u = u.split("\\", 1)[1]
    if "@" in u:
        u = u.split("@", 1)[0]
    if not u or u.endswith("$") or u.upper() in ("ANONYMOUS LOGON", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return ""
    return u


def parse(text):
    """PowerShell output lines -> [(ts, user, ip)] of successful logons (failed TGT requests have Status != 0x0)."""
    out = []
    for line in (text or "").splitlines():
        p = line.rstrip("\r").split("\t")
        if len(p) < 4:
            continue
        status = p[4].strip().lower() if len(p) > 4 else ""
        if status not in ("", "0x0", "0"):
            continue
        try:
            ts = datetime.strptime(p[0].strip(), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
        user, ip = _clean_user(p[2]), _clean_ip(p[3])
        if user and ip:
            out.append((ts, user, ip))
    return out


def mac_for_ip(db, ip, ts):
    """Device that had this IP at that moment (device history from the routers' ARP / DHCP)."""
    h = db.query(DeviceHistory).filter(DeviceHistory.kind == "ip", DeviceHistory.value == ip,
                                       DeviceHistory.first_seen <= ts + devices.HISTORY_GAP,
                                       DeviceHistory.last_seen >= ts - devices.HISTORY_GAP) \
        .order_by(DeviceHistory.last_seen.desc()).first()
    if h:
        return h.mac
    d = db.query(Device).filter(Device.last_ip == ip).order_by(Device.last_seen.desc()).first()
    return d.mac if d else ""


def record(db, user, ts, source, ip="", computer=""):
    """A user logged on to a computer at ts. Returns the device or None when the computer is not known yet."""
    user = _clean_user(user)
    ip = _clean_ip(ip)
    if not user:
        return None
    mac = mac_for_ip(db, ip, ts) if ip else ""
    d = db.query(Device).filter(Device.mac == mac).first() if mac else None
    if d is None and computer:
        d = db.query(Device).filter(Device.hostname.ilike(computer.strip())).order_by(Device.last_seen.desc()).first()
    if d is None:
        return None
    # Device.last_user stays the hotspot / VPN user: a Windows logon is kept apart (logon_user)
    devices._interval(db, d.mac, "user", user, None, source, ts)
    if computer and not d.hostname:
        d.hostname = computer.strip()[:150]
    if d.logon_at is None or ts >= d.logon_at:
        d.logon_user, d.logon_at, d.logon_source = user[:150], ts, source
    return d


# ------------------------------------------------------------------ message shown at Windows logon
QUOTA_MODES = {"warn": "فقط وقتی مصرف از حد هشدار گذشت", "always": "همیشه", "never": "هرگز"}


def message_settings(db):
    return {"enabled": get_setting(db, "logon_msg_enabled", "0") == "1",
            "title": get_setting(db, "logon_msg_title") or "پیام واحد فناوری اطلاعات",
            "text": get_setting(db, "logon_message"),
            "quota": get_setting(db, "logon_msg_quota", "warn") or "warn"}


def message(db, username):
    """(title, body) for the logon popup of this Windows user, or None when there is nothing to show."""
    from . import policy
    c = message_settings(db)
    if not c["enabled"]:
        return None
    lines = [c["text"].strip()] if (c["text"] or "").strip() else []
    name = _clean_user(username)
    u = db.query(User).filter(func.lower(User.username) == name.lower()).first() if name else None
    if u is not None and c["quota"] != "never":
        w = policy.quota_warning(db, u)
        if w:
            lines.append(w["text"])
        elif c["quota"] == "always":
            quota, used, remaining = policy.quota_state(db, u)
            if quota:
                lines.append(f"باقی‌ماندهٔ حجم اینترنت شما: {policy.size_fa(remaining)}")
    if not lines:
        return None
    return c["title"], "\n\n".join(lines)


# ------------------------------------------------------------------ domain controllers
def settings(db):
    dcs = [x.strip() for x in (get_setting(db, "logon_dcs") or "").replace(",", "\n").splitlines() if x.strip()]
    return {"enabled": get_setting(db, "logon_dc_enabled", "0") == "1",
            "dcs": dcs or ([get_setting(db, "ldap_server")] if get_setting(db, "ldap_server") else []),
            "dcs_text": get_setting(db, "logon_dcs"),
            "user": get_setting(db, "ldap_bind_user"), "domain": get_setting(db, "ldap_domain"),
            "password": decrypt(get_setting(db, "ldap_bind_password")),
            "script_key": get_setting(db, "logon_script_key"),
            "status": get_setting(db, "logon_status"), "error": get_setting(db, "logon_error")}


def _account(c):
    u = c["user"] or ""
    if "\\" in u or "@" in u or not c["domain"]:
        return u
    return f"{c['domain']}\\{u}"


def read_dc(dc, account, password, since):
    """Run Get-WinEvent against one DC. Returns PowerShell stdout; raises RuntimeError with the reason."""
    if os.name != "nt":
        raise RuntimeError("خواندن رویدادهای کنترلر دامنه فقط وقتی برنامه روی ویندوز نصب است ممکن است")
    env = dict(os.environ, MTA_DC=dc, MTA_USER=account, MTA_PW=password or "",
               MTA_SINCE=since.strftime("%Y-%m-%dT%H:%M:%S"))
    script = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode()      # multi-line try/catch: not via stdin
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-EncodedCommand", script], capture_output=True, text=True, env=env, timeout=300,
                       stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or f"exit {r.returncode}").strip()[:500])
    return r.stdout


def hint(err):
    e = (err or "").lower()
    if "access is denied" in e or "unauthorized" in e or "دسترسی" in e:
        return ("کاربر سرویس AD را در کنترلر دامنه عضو گروه «Event Log Readers» کنید (Active Directory Users and "
                "Computers > Builtin > Event Log Readers > Add) و چند دقیقه بعد دوباره امتحان کنید.")
    if "rpc server is unavailable" in e or "rpc" in e:
        return ("روی کنترلر دامنه در Windows Defender Firewall قانون «Remote Event Log Management (RPC)» را فعال کنید "
                "یا: Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management'")
    return ""


def sync_dcs():
    if not _LOCK.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        c = settings(db)
        if not c["enabled"] or not c["dcs"]:
            return
        cur = get_setting(db, "logon_cursor")
        try:
            since = datetime.fromisoformat(cur) - OVERLAP if cur else now() - FIRST_READ
        except ValueError:
            since = now() - FIRST_READ
        latest, found, matched, errors = None, 0, 0, []
        for dc in c["dcs"]:
            try:
                rows = parse(read_dc(dc, _account(c), c["password"], since))
            except Exception as e:  # noqa: BLE001 - one DC down must not stop the others
                errors.append(f"{dc}: {e}")
                continue
            for ts, user, ip in rows:
                found += 1
                if record(db, user, ts, "dc", ip=ip) is not None:
                    matched += 1
                latest = ts if latest is None or ts > latest else latest
        if latest:
            set_setting(db, "logon_cursor", latest.isoformat(timespec="seconds"))
        elif not errors:
            set_setting(db, "logon_cursor", (now() - OVERLAP).isoformat(timespec="seconds"))
        set_setting(db, "logon_status", f"{now():%Y-%m-%d %H:%M}|{found}|{matched}")
        set_setting(db, "logon_error", " | ".join(errors)[:1000])
        db.commit()
    except Exception as e:  # noqa: BLE001
        log.exception("logon sync failed")
        db.rollback()
        set_setting(db, "logon_error", str(e)[:1000])
        db.commit()
    finally:
        db.close()
        SessionLocal.remove()
        _LOCK.release()


def test_dc(c, dc):
    rows = parse(read_dc(dc, _account(c), c["password"], now() - timedelta(hours=1)))
    return len(rows), len({u for _, u, _ in rows})
