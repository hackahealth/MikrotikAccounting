"""نگهبان ورود به سرورها و تجهیزات حساس + گزارش ورود کاربران روی رایانه‌ای غیر از رایانهٔ همیشگی‌شان.

برای هر سرور / تجهیز حفاظت‌شده (ProtectedTarget) فقط اعضای گروه‌های AD مجاز (و حساب‌هایی که جدا اجازه دارند) و
فقط از رایانه‌های مجاز می‌توانند وارد شوند یا درخواست ورود بدهند. هر ورود یا تلاش ورود دیگر یک تخلف است:
با عمل «مسدود» حساب کاربر در AD غیرفعال، کاربر و رایانهٔ مبدأ قفل (روتر هم رایانه را مسدود می‌کند) و تخلف با
جزئیات ثبت و اعلان می‌شود.

منابع رویداد (هر GUARD_SYNC_EVERY ثانیه):
- کنترلرهای دامنه: 4769 (درخواست تیکت سرویس برای حساب رایانهٔ سرور، از IP رایانهٔ مبدأ) و 4768/4771 از IP خود
  سرور (ورود تعاملی RDP / کنسول روی سرور، موفق یا رمز اشتباه)؛
- Security Log خود سرور (اختیاری، دقیق‌تر): 4624 / 4625 با نوع ورود و IP و نام رایانهٔ مبدأ.
"""
import base64
import logging
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy import func

from . import alerts, devices, logons, netscope, security
from .db import (Device, DeviceHistory, LogonViolation, ProtectedTarget, SessionLocal, get_setting, now,
                 set_setting)

log = logging.getLogger("logonguard")
_LOCK = threading.Lock()
OVERLAP = timedelta(minutes=2)
FIRST_READ = timedelta(hours=1)
REPEAT = timedelta(hours=1)          # the same user / target / source / outcome within an hour is one violation
LOGON_TYPES = {"2": "کنسول", "3": "شبکه (SMB / اشتراک فایل ...)", "7": "باز کردن قفل", "8": "شبکه (رمز ساده)",
               "10": "ریموت دسکتاپ (RDP)", "11": "کنسول (رمز کش‌شده)"}
LOCAL_TYPES = ("2", "7", "11")      # sitting at the server itself
ACTIONS = {"block": "مسدود (غیرفعال‌سازی و قفل)", "alarm": "فقط ثبت و هشدار"}

# Get-WinEvent against one host with the AD service account; ids / data filter from the environment.
PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$sec = ConvertTo-SecureString $env:MTA_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:MTA_USER, $sec)
$since = [datetime]::ParseExact($env:MTA_SINCE, 'yyyy-MM-ddTHH:mm:ss', $null)
$f = @{LogName='Security'; Id=[int[]]($env:MTA_IDS -split ','); StartTime=$since}
if ($env:MTA_DATA) { $f['Data'] = [string[]]($env:MTA_DATA -split ',') }
try {
  $ev = Get-WinEvent -ComputerName $env:MTA_HOST -Credential $cred -MaxEvents 20000 -FilterHashtable $f
} catch {
  if ($_.Exception.Message -match 'No events were found|^No events') { exit 0 }
  [Console]::Error.WriteLine($_.Exception.Message); exit 2
}
foreach ($e in $ev) {
  $d = @{}
  foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
  "{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}" -f $e.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss'), $e.Id, $d['TargetUserName'], $d['IpAddress'], $d['Status'], $d['ServiceName'], $d['WorkstationName'], $d['LogonType']
}
"""


def tokens(text):
    from .access import tokens as _t
    return _t(text)


def _short(name):
    n = (name or "").strip().lower().rstrip("$")
    if "\\" in n:
        n = n.split("\\", 1)[1]
    return n.split(".", 1)[0]


def read_events(host, account, password, since, ids, data=()):
    """Security-log events of one host. Returns PowerShell stdout; raises RuntimeError with the reason."""
    if os.name != "nt":
        raise RuntimeError("خواندن رویدادهای ویندوز فقط وقتی برنامه روی ویندوز نصب است ممکن است")
    env = dict(os.environ, MTA_HOST=host, MTA_USER=account, MTA_PW=password or "", MTA_IDS=",".join(map(str, ids)),
               MTA_DATA=",".join(data), MTA_SINCE=since.strftime("%Y-%m-%dT%H:%M:%S"))
    script = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode()
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-EncodedCommand", script], capture_output=True, text=True, env=env, timeout=300,
                       stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or f"exit {r.returncode}").strip()[:500])
    return r.stdout


def parse(text):
    out = []
    for line in (text or "").splitlines():
        p = line.rstrip("\r").split("\t")
        if len(p) < 4:
            continue
        p += [""] * (8 - len(p))
        try:
            ts = datetime.strptime(p[0].strip(), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
        out.append({"ts": ts, "id": p[1].strip(), "user": logons._clean_user(p[2]), "ip": logons._clean_ip(p[3]),
                    "status": p[4].strip().lower(), "service": p[5].strip(), "ws": p[6].strip(),
                    "ltype": p[7].strip()})
    return out


# ------------------------------------------------------------------ targets
_dns = {}


def resolve(name):
    hit = _dns.get(name)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    try:
        ips = set(socket.gethostbyname_ex(name)[2])
    except OSError:
        ips = set()
    _dns[name] = (time.time(), ips)
    return ips


def target_ips(t):
    ips = {a for a in tokens(t.addresses) if "/" not in a and "-" not in a}
    if not ips:
        for h in tokens(t.hosts):
            ips |= resolve(h)
    return ips


def target_names(t):
    return {_short(h) for h in tokens(t.hosts)} | {_short(t.name)}


# ------------------------------------------------------------------ AD groups
_groups = {}
GROUP_TTL = 300


def user_groups(db, username):
    """Lower-case DNs and names of every group the user is in (nested groups too). None when not in AD."""
    key = username.lower()
    hit = _groups.get(key)
    if hit and time.time() - hit[0] < GROUP_TTL:
        return hit[1]
    from ldap3 import BASE, SUBTREE
    from . import ldap_ad
    c = ldap_ad._cfg(db)
    if not c["server"]:
        raise RuntimeError("Active Directory تنظیم نشده")
    conn = ldap_ad._connect(c)
    try:
        conn.search(ldap_ad.base_dn(c, conn), f"(&(objectClass=user)(sAMAccountName={ldap_ad._escape(username)}))",
                    SUBTREE, attributes=["memberOf"])
        rows = [r for r in conn.response if r.get("type") == "searchResEntry"]
        if not rows:
            _groups[key] = (time.time(), None)
            return None

        def parents(entry):
            v = entry.get("attributes", {}).get("memberOf") or []
            return [v] if isinstance(v, str) else list(v)
        seen, todo = set(), parents(rows[0])
        while todo and len(seen) < 500:
            dn = str(todo.pop())
            if dn.lower() in seen:
                continue
            seen.add(dn.lower())
            if conn.search(dn, "(objectClass=*)", BASE, attributes=["memberOf"]):
                for r in conn.response:
                    if r.get("type") == "searchResEntry":
                        todo.extend(parents(r))
    finally:
        try:
            conn.unbind()
        except Exception:
            pass
    names = seen | {ldap_ad._cn(dn).lower() for dn in seen}
    _groups[key] = (time.time(), names)
    return names


def user_allowed(db, t, username):
    """(True | False, error). The allowed groups match by name (CN) or DN; single accounts by name."""
    u = username.lower()
    if u in {x.lower() for x in tokens(t.allowed_users)}:
        return True, ""
    wanted = {g.strip().lower() for g in (t.allowed_groups or "").splitlines() if g.strip()}
    if not wanted:
        return False, ""
    try:
        have = user_groups(db, username)
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]
    if have is None:
        return False, ""
    return bool(wanted & have), ""


# ------------------------------------------------------------------ source computer
def source(db, ip, ws, ts):
    """(mac, name) of the computer the logon came from."""
    mac = logons.mac_for_ip(db, ip, ts) if ip else ""
    d = db.query(Device).filter(Device.mac == mac).first() if mac else None
    name = ws if ws and ws != "-" else ""
    if d is not None:
        name = name or d.hostname or d.label
    return mac, name


def source_allowed(db, t, ip, name, mac):
    allowed = tokens(t.allowed_computers)
    if not allowed:
        return True
    nets = netscope.parse_ranges("\n".join(a for a in allowed if _addr(a)))[0]
    if ip and nets:
        try:
            import ipaddress
            if netscope._in(ipaddress.ip_address(ip), nets):
                return True
        except ValueError:
            pass
    names = {_short(a) for a in allowed if not _addr(a)}
    cand = {_short(name)} if name else set()
    if mac:
        cand.add(mac.lower())
        names |= {a.lower() for a in allowed if devices.normalize_mac(a)}
        names |= {devices.normalize_mac(a).lower() for a in allowed if devices.normalize_mac(a)}
        d = db.query(Device).filter(Device.mac == mac).first()
        if d is not None:
            cand |= {_short(x) for x in (d.hostname, d.label) if x}
    return bool(cand & names)


def _addr(t):
    from .access import _is_addr
    return _is_addr(t)


# ------------------------------------------------------------------ checking one logon
def ignored_users(db):
    c = logons.settings(db)
    out = {logons._clean_user(c["user"] or "").lower()}
    out |= {x.lower() for x in tokens(get_setting(db, "guard_ignore_users"))}
    return {x for x in out if x}


def check(db, t, ev):
    """ev: {ts, user, ip, ws, outcome, how, event, local}. Returns the LogonViolation (new or repeated) or None."""
    user = ev["user"]
    if not user or user.lower() in ignored_users(db):
        return None
    reasons, unsure = [], ""
    ok, err = user_allowed(db, t, user)
    if ok is None:
        unsure = f"عضویت گروه بررسی نشد: {err}"
    elif not ok:
        reasons.append("کاربر عضو گروه / فهرست مجاز نیست")
    mac, name = source(db, ev["ip"], ev.get("ws", ""), ev["ts"])
    if ev.get("local"):
        name = name or f"{t.name} (پشت خود سرور)"
    elif ev["ip"] or name:
        if not source_allowed(db, t, ev["ip"], name, mac):
            reasons.append(f"از رایانهٔ غیرمجاز {name or ev['ip']}")
    if ev["outcome"] == "fail" and reasons:
        reasons.append("تلاش ناموفق ورود")
    if not reasons:
        if unsure:
            log.warning("%s on %s: %s", user, t.name, unsure)
        return None
    prev = db.query(LogonViolation).filter(func.lower(LogonViolation.username) == user.lower(),
                                           LogonViolation.target_id == t.id, LogonViolation.src_ip == ev["ip"],
                                           LogonViolation.outcome == ev["outcome"],
                                           LogonViolation.resolved_at.is_(None),
                                           LogonViolation.last_ts >= ev["ts"] - REPEAT).first()
    if prev is not None:
        if ev["ts"] > prev.last_ts:
            prev.last_ts = ev["ts"]
            prev.count = (prev.count or 1) + 1
        return prev
    v = LogonViolation(ts=ev["ts"], last_ts=ev["ts"], username=user[:150], target_id=t.id, target=t.name[:150],
                       outcome=ev["outcome"], how=ev["how"][:60], src_ip=ev["ip"][:45], src_mac=mac or "",
                       src_name=(name or "")[:150], reasons=" · ".join(reasons + ([unsure] if unsure else []))[:500],
                       event=ev["event"][:300])
    db.add(v)
    db.flush()
    v.actions = " · ".join(enforce(db, t, v) if t.action == "block" else ["فقط هشدار (عمل این سرور: هشدار)"])[:1000]
    what = "تلاش ورود" if v.outcome == "fail" else "ورود"
    alerts.add(db, "guard", f"{what} غیرمجاز {user} به {t.name}",
               f"{v.reasons} · مبدأ: {v.src_name or '-'} {v.src_ip} · {v.how} · اقدام: {v.actions}", "err",
               "/guard")
    return v


def enforce(db, t, v):
    acts = []
    detail = f"تخلف ورود به {t.name}: {v.reasons} (مبدأ {v.src_name or v.src_ip or '-'}، {v.ts:%Y-%m-%d %H:%M})"
    if t.lock_user:
        lk, new = security.lock(db, "user", v.username, detail, "نگهبان ورود", True)
        acts.append("کاربر قفل شد" if new else "کاربر از قبل قفل بود")
    if t.lock_source and (v.src_mac or v.src_ip) and "رایانهٔ غیرمجاز" in (v.reasons or ""):
        kind, value = ("mac", v.src_mac) if v.src_mac else ("ip", v.src_ip)
        lk, new = security.lock(db, kind, value, detail, "نگهبان ورود", True)
        acts.append(f"رایانهٔ مبدأ ({value}) قفل شد" if new else f"رایانهٔ مبدأ ({value}) از قبل قفل بود")
    if t.disable_ad:
        acts.append(disable_ad(db, v.username, detail))
    return acts


def disable_ad(db, username, detail=""):
    from . import ad_admin
    try:
        with ad_admin.AD(db) as ad:
            dn = ad.find_user(username)
            if not dn:
                return "حساب در AD پیدا نشد (حساب محلی؟)"
            ad.set_enabled(dn, False)
        _groups.pop(username.lower(), None)
        return "حساب AD غیرفعال شد"
    except Exception as e:  # noqa: BLE001
        log.warning("disable %s in AD: %s", username, e)
        return f"غیرفعال‌سازی در AD ناموفق: {e}"[:300]


# ------------------------------------------------------------------ events -> logons of targets
def from_dc(rows, targets):
    """DC events -> [(target, ev)]."""
    out = []
    by_name, by_ip = {}, {}
    for t in targets:
        for n in target_names(t):
            by_name[n] = t
        for ip in target_ips(t):
            by_ip[ip] = t
    for r in rows:
        ok = r["status"] in ("", "0x0", "0")
        if r["id"] == "4769":
            t = by_name.get(_short(r["service"]))
            if t is None or r["ip"] in target_ips(t):
                continue
            out.append((t, {"ts": r["ts"], "user": r["user"], "ip": r["ip"], "ws": "", "local": False,
                            "outcome": "ok" if ok else "fail", "how": "درخواست دسترسی (تیکت Kerberos)",
                            "event": f"DC 4769 {r['service']} {r['status']}"}))
        elif r["id"] in ("4768", "4771") and r["ip"] in by_ip:
            t = by_ip[r["ip"]]
            if t.read_direct:          # the server's own log tells the source computer
                continue
            out.append((t, {"ts": r["ts"], "user": r["user"], "ip": "", "ws": "", "local": True,
                            "outcome": "ok" if r["id"] == "4768" and ok else "fail",
                            "how": "ورود تعاملی روی سرور (RDP / کنسول)", "event": f"DC {r['id']} {r['status']}"}))
    return out


def from_server(t, rows):
    out = []
    own = target_ips(t)
    for r in rows:
        if r["id"] not in ("4624", "4625") or r["ltype"] not in LOGON_TYPES:
            continue
        local = r["ltype"] in LOCAL_TYPES or (not r["ip"] and not r["ws"]) or r["ip"] in own
        out.append((t, {"ts": r["ts"], "user": r["user"], "ip": "" if local else r["ip"],
                        "ws": "" if local else r["ws"], "local": local,
                        "outcome": "ok" if r["id"] == "4624" else "fail", "how": LOGON_TYPES[r["ltype"]],
                        "event": f"{t.name} {r['id']} type {r['ltype']} {r['status']}".strip()}))
    return out


def sync():
    if not _LOCK.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        targets = db.query(ProtectedTarget).filter(ProtectedTarget.enabled.is_(True)).all()
        if not targets:
            return
        c = logons.settings(db)
        if not c["dcs"] or not c["user"]:
            set_setting(db, "guard_error", "تنظیمات AD (حساب سرویس و کنترلر دامنه) کامل نیست")
            db.commit()
            return
        account = logons._account(c)
        cur = get_setting(db, "guard_cursor")
        try:
            since = datetime.fromisoformat(cur) - OVERLAP if cur else now() - FIRST_READ
        except ValueError:
            since = now() - FIRST_READ
        started = now()
        data = set()
        for t in targets:
            for n in target_names(t):
                data |= {n.upper() + "$", n + "$"}
            for ip in target_ips(t):
                data |= {ip, "::ffff:" + ip}
        found, errors = [], []
        for dc in c["dcs"]:
            try:
                found += from_dc(parse(read_events(dc, account, c["password"], since, (4768, 4769, 4771),
                                                   sorted(data))), targets)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{dc}: {e}")
        for t in targets:
            if not t.read_direct:
                t.status = f"{now():%Y-%m-%d %H:%M} از کنترلر دامنه"
                continue
            host = (tokens(t.hosts) or [t.name])[0]
            try:
                found += from_server(t, parse(read_events(host, account, c["password"], since, (4624, 4625))))
                t.status = f"{now():%Y-%m-%d %H:%M} خوانده شد"
            except Exception as e:  # noqa: BLE001
                t.status = f"{now():%Y-%m-%d %H:%M} خطا: {e} {logons.hint(str(e))}"[:500]
                errors.append(f"{t.name}: {e}")
        n = 0
        for t, ev in sorted(found, key=lambda x: x[1]["ts"]):
            if check(db, t, ev) is not None:
                n += 1
        set_setting(db, "guard_cursor", started.isoformat(timespec="seconds"))
        set_setting(db, "guard_status", f"{now():%Y-%m-%d %H:%M}|{len(found)}|{n}")
        set_setting(db, "guard_error", " | ".join(errors)[:1000])
        db.commit()
    except Exception as e:  # noqa: BLE001
        log.exception("logon guard failed")
        db.rollback()
        set_setting(db, "guard_error", str(e)[:1000])
        db.commit()
    finally:
        db.close()
        SessionLocal.remove()
        _LOCK.release()


# ------------------------------------------------------------------ router layer
def router_rules(db):
    """Targets with net_block: [(target, [its addresses], [IPs of the allowed computers now])]."""
    out = []
    for t in db.query(ProtectedTarget).filter(ProtectedTarget.enabled.is_(True), ProtectedTarget.net_block.is_(True)):
        addrs = sorted(target_ips(t) | {a for a in tokens(t.addresses) if _addr(a)})
        if not addrs:
            continue
        ok = set()
        for a in tokens(t.allowed_computers):
            if _addr(a):
                ok.add(a)
                continue
            mac = devices.normalize_mac(a)
            q = db.query(Device).filter(Device.mac == mac) if mac else \
                db.query(Device).filter(func.lower(Device.hostname) == _short(a))
            for d in q:
                ok |= devices.current_ips(db, d.mac)
            if not mac:
                ok |= resolve(a)
        out.append((t, addrs, sorted(ok)))
    return out


# ------------------------------------------------------------------ report: logon on another computer
def unusual(db, start, end, days=30, q=""):
    """Windows logons in [start, end) on a computer that is not the user's usual one. The usual computers of a user
    are those used on at least half as many days as the most used one in the `days` before `end` (3 days at least)."""
    from .nightlist import LOGON_SOURCES
    hist = db.query(DeviceHistory.value, DeviceHistory.mac, DeviceHistory.first_seen).filter(
        DeviceHistory.kind == "user", DeviceHistory.source.in_(LOGON_SOURCES),
        DeviceHistory.first_seen >= end - timedelta(days=days), DeviceHistory.first_seen < end)
    usage = {}
    for user, mac, ts in hist:
        usage.setdefault(user.lower(), {}).setdefault(mac, set()).add(ts.date())
    usual = {}
    for user, macs in usage.items():
        top = max(len(x) for x in macs.values())
        if top >= 3:
            usual[user] = {m for m, x in macs.items() if len(x) >= max(3, top / 2)}
    rows = db.query(DeviceHistory).filter(DeviceHistory.kind == "user", DeviceHistory.source.in_(LOGON_SOURCES),
                                          DeviceHistory.last_seen >= start, DeviceHistory.first_seen < end)
    if q:
        rows = rows.filter(DeviceHistory.value.ilike(f"%{q}%"))
    out = []
    for r in rows.order_by(DeviceHistory.first_seen.desc()).limit(5000):
        u = usual.get(r.value.lower())
        if u and r.mac not in u:
            out.append((r, sorted(u)))
    return out
