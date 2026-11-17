"""چند کاربر روی یک دستگاه: وقتی روی یک رایانه یا موبایل (بر اساس MAC) هم‌زمان بیش از یک کاربر وارد شده باشد —
ورود ویندوز (AD، از رویدادهای کنترلر دامنه یا اسکریپت ورود) و / یا ورود هات‌اسپات — ثبت می‌شود، پیام اخطار (متن
قابل ویرایش) روی رایانه (msg.exe)، در صفحهٔ وضعیت هات‌اسپات و با پیامک فرستاده می‌شود و در صورت تکرار، دستگاه و / یا
کاربران خودکار قفل می‌شوند (همان قفل صفحهٔ «ورود ناموفق و قفل» که روتر هم آن را اعمال می‌کند)."""
import ipaddress
import logging
import threading
from datetime import timedelta

from sqlalchemy import func

from . import alerts, devices, netscope, security, winmsg
from .db import AcctSession, Device, DeviceHistory, Nas, SessionLocal, SharedUse, User, get_setting, now

log = logging.getLogger("shareduse")
EVERY = 60
_LOCK = threading.Lock()

BLOCK_WHAT = {"none": "هیچ (فقط ثبت و پیام)", "device": "فقط دستگاه", "users": "فقط کاربران", "both": "دستگاه و کاربران"}
SOURCES = {"dc": "ویندوز", "script": "ویندوز", "hotspot": "هات‌اسپات"}
DEFAULT_TEXT = ("کاربر گرامی، روی دستگاه «{device}» هم‌زمان چند کاربر وارد شده‌اند: {users}.\n"
                "ورود با حساب کاربری دیگران یا استفادهٔ چند نفر از یک حساب مجاز نیست. "
                "این مورد ثبت شد ({count} بار در {days} روز اخیر) و در صورت تکرار، دستگاه و حساب‌ها مسدود می‌شوند.")
DEFAULT_SMS = "اخطار واحد IT: ورود هم‌زمان چند کاربر ({users}) روی دستگاه {device} ثبت شد. در صورت تکرار، حساب شما مسدود می‌شود."


def _int(db, key, default):
    try:
        return max(0, int(get_setting(db, key, str(default)) or default))
    except ValueError:
        return default


def settings(db):
    return {"enabled": get_setting(db, "share_enabled", "1") == "1",
            "window": _int(db, "share_window", 30) or 30,                 # minutes: AD logons counted as "on it"
            "ignore_users": get_setting(db, "share_ignore_users", ""),
            "exempt": get_setting(db, "share_exempt", ""),                 # MAC / IP / CIDR / computer name
            "exempt_types": get_setting(db, "share_exempt_types", "server"),
            "msg_enabled": get_setting(db, "share_msg_enabled", "0") == "1",
            "msg_title": get_setting(db, "share_msg_title", "") or "اخطار واحد فناوری اطلاعات",
            "msg_text": get_setting(db, "share_msg_text", "") or DEFAULT_TEXT,
            "msg_seconds": _int(db, "share_msg_seconds", 300) or 300,
            "sms_enabled": get_setting(db, "share_sms_enabled", "0") == "1",
            "sms_text": get_setting(db, "share_sms_text", "") or DEFAULT_SMS,
            "repeat_days": _int(db, "share_repeat_days", 30) or 30,
            "block_after": _int(db, "share_block_after", 3),               # episodes in repeat_days, 0 = never
            "block_what": get_setting(db, "share_block_what", "none") or "none",
            "block_minutes": _int(db, "share_block_minutes", 0),           # 0 = until released by hand
            "block_ad": get_setting(db, "share_block_ad", "0") == "1",
            "kick": get_setting(db, "share_kick", "1") == "1"}


def tokens(text):
    return [w.strip() for w in netscope.split_names(text) if w.strip()]


def clean(name):
    name = (name or "").strip().split("\\")[-1]
    return name.split("@")[0].strip()


# ------------------------------------------------------------------ SMS (module app/sms.py, optional)
def _sms():
    try:
        from . import sms  # noqa: PLC0415 - the SMS module may not be installed
    except ImportError:
        return None
    return sms if hasattr(sms, "send") else None


def sms_available(db):
    mod = _sms()
    if mod is None:
        return False
    try:
        return bool(mod.enabled(db)) if hasattr(mod, "enabled") else True
    except Exception:  # noqa: BLE001
        return False


def sms_send(db, mobile, text):
    mod = _sms()
    if mod is None:
        return False, "ماژول پیامک نصب نیست"
    try:
        r = mod.send(db, mobile, text)
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:150]
    if isinstance(r, tuple):
        return bool(r[0]), str(r[1] if len(r) > 1 else "")
    return bool(r), ""


# ------------------------------------------------------------------ who is on which device
def _exempt(dev, mac, ip, st):
    if dev is not None and dev.device_type in tokens(st["exempt_types"]):
        return True
    names = {x.lower() for x in tokens(st["exempt"])}
    if mac.lower() in names or (ip and ip in names):
        return True
    if dev is not None and ((dev.hostname or "").lower() in names or (dev.label or "").lower() in names):
        return True
    if ip:
        nets, _ = netscope.parse_ranges("\n".join(x for x in names if not devices.normalize_mac(x)))
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in nets)
        except ValueError:
            return False
    return False


def collect(db, ts=None):
    """-> {mac: {"ip": ip, "users": {lower: (name, {sources})}}} of the devices with more than one user now."""
    ts = ts or now()
    st = settings(db)
    ignore = {clean(x).lower() for x in tokens(st["ignore_users"])}
    from . import config, logons
    svc = clean(logons.settings(db)["user"] or "").lower()
    if svc:
        ignore.add(svc)
    out = {}

    def add(mac, ip, user, source):
        u = clean(user)
        if not mac or not u or u.lower() in ignore or u.endswith("$"):
            return
        e = out.setdefault(mac, {"ip": "", "users": {}})
        if ip and (source == "hotspot" or not e["ip"]):
            e["ip"] = ip
        name, srcs = e["users"].get(u.lower(), (u, set()))
        srcs.add(SOURCES.get(source, source))
        e["users"][u.lower()] = (name, srcs)

    since = ts - timedelta(minutes=st["window"])
    for h in db.query(DeviceHistory).filter(DeviceHistory.kind == "user", DeviceHistory.source.in_(("dc", "script")),
                                            DeviceHistory.last_seen >= since, DeviceHistory.first_seen <= ts):
        add(h.mac, "", h.value, h.source)
    stale = ts - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.service == "hotspot",
                                          AcctSession.last_update >= stale):
        mac = devices.normalize_mac(s.mac)
        if not mac and s.framed_ip:
            mac = logons.mac_for_ip(db, s.framed_ip, ts)
        add(mac, s.framed_ip or "", s.username, "hotspot")
    res = {}
    for mac, e in out.items():
        if len(e["users"]) < 2:
            continue
        dev = db.query(Device).filter(Device.mac == mac).first()
        ip = e["ip"] or (dev.last_ip if dev else "")
        if _exempt(dev, mac, ip, st):
            continue
        e["ip"], e["dev"] = ip, dev
        res[mac] = e
    return res


def users_of(inc):
    return [u for u in (inc.users or "").split(",") if u]


def _label(dev, mac):
    return (dev.label or dev.hostname or mac) if dev else mac


def render(template, inc, st, names=None):
    names = names or users_of(inc)
    vals = {"users": "، ".join(names), "device": inc.device or inc.mac, "ip": inc.ip or "-", "mac": inc.mac,
            "count": inc.repeat or 1, "days": st["repeat_days"], "time": f"{inc.ts:%H:%M}"}
    out = template
    for k, v in vals.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def repeats(db, mac, since):
    return db.query(SharedUse).filter(SharedUse.mac == mac, SharedUse.ts >= since).count()


def user_repeats(db, username, since):
    return db.query(SharedUse).filter(SharedUse.users.like(f"%,{username.lower()},%"), SharedUse.ts >= since).count()


# ------------------------------------------------------------------ message, SMS, block
def warn(db, inc, st, send=None):
    """Pop-up on the computer (msg.exe to its IP). Hotspot users see the warning on the status page (/hs/warn.js)."""
    names = [n for n, _ in _names(db, inc)]
    text = render(st["msg_text"], inc, st, names)
    parts = []
    hs = any("هات‌اسپات" in x for x in (inc.detail or "").split("·"))
    if inc.ip and (send is not None or winmsg.available()):
        send = send or (lambda ip, t: winmsg.send_one(ip, t, st["msg_seconds"]))
        ok, err = send(inc.ip, f"{st['msg_title']}\n\n{text}")
        parts.append("پیام ویندوز رسید" if ok else f"پیام ویندوز ناموفق: {err}"[:200])
    if hs:
        parts.append("اخطار در صفحهٔ هات‌اسپات")
    inc.msg = " · ".join(parts)[:500] or "راهی برای پیام نبود"
    return inc.msg


def _names(db, inc):
    """[(username as in the panel, User or None)]."""
    out = []
    for u in users_of(inc):
        row = db.query(User).filter(func.lower(User.username) == u).first()
        out.append((row.username if row else u, row))
    return out


def send_sms(db, inc, st, send=None):
    send = send or (lambda mobile, text: sms_send(db, mobile, text))
    names = [n for n, _ in _names(db, inc)]
    text = render(st["sms_text"], inc, st, names)
    parts = []
    for name, row in _names(db, inc):
        mobile = (row.mobile or row.phone or "").strip() if row else ""
        if not mobile:
            parts.append(f"{name}: موبایل ثبت نشده")
            continue
        ok, err = send(mobile, text)
        parts.append(f"{name}: {'ارسال شد' if ok else 'ناموفق ' + err}")
    inc.sms = " · ".join(parts)[:500]
    return inc.sms


def kick(db, usernames, mac):
    """Cut the live hotspot sessions of these users and of this device (best effort)."""
    from . import routeros
    n = 0
    q = db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.service == "hotspot")
    for s in q.all():
        if (s.username or "").lower() not in usernames and devices.normalize_mac(s.mac) != mac:
            continue
        nas = (db.query(Nas).filter(Nas.ip == s.nas_ip).first() or db.query(Nas).filter(Nas.api_host == s.nas_ip)
               .first()) if s.nas_ip else None
        try:
            if nas and routeros.disconnect(nas, s.username, s.service, s.acct_session_id, s.framed_ip):
                s.terminate_cause = "Admin-Reset"
                n += 1
        except Exception as e:  # noqa: BLE001
            log.warning("disconnect %s: %s", s.username, e)
    return n


def block(db, inc, what, by, minutes=0, block_ad=False, do_kick=True, users=None):
    """Lock the device (MAC) and / or the users. -> [done]."""
    acts = []
    reason = f"چند کاربر روی یک دستگاه ({inc.device or inc.mac}: {'، '.join(users_of(inc))})"
    users = users if users is not None else users_of(inc)
    if what in ("device", "both"):
        lk, new = security.lock(db, "mac", inc.mac, reason, by, by == "سیستم", minutes)
        acts.append(f"دستگاه {inc.mac} قفل شد" if new else f"دستگاه {inc.mac} از قبل قفل بود")
    if what in ("users", "both"):
        for name, row in _names(db, inc):
            if name.lower() not in users:
                continue
            lk, new = security.lock(db, "user", name, reason, by, by == "سیستم", minutes)
            acts.append(f"کاربر {name} قفل شد" if new else f"کاربر {name} از قبل قفل بود")
            if block_ad and (row is None or row.source == "ldap"):
                from . import logonguard
                acts.append(f"{name}: {logonguard.disable_ad(db, name, reason)}")
    if acts and do_kick:
        try:
            n = kick(db, set(users) if what in ("users", "both") else set(), inc.mac if what in ("device", "both")
                     else "")
            if n:
                acts.append(f"{n} اتصال هات‌اسپات قطع شد")
        except Exception as e:  # noqa: BLE001
            log.warning("kick after block: %s", e)
    if acts:
        inc.actions = " · ".join(x for x in (inc.actions, " · ".join(acts)) if x)[:1000]
    return acts


# ------------------------------------------------------------------ one round
def check(db, ts=None, send=None, sms=None, do_kick=True):
    """Find devices with several users, record / extend episodes, warn and block on repeat.
    -> [SharedUse] new episodes of this round."""
    ts = ts or now()
    st = settings(db)
    if not st["enabled"]:
        return []
    new = []
    for mac, e in collect(db, ts).items():
        users = sorted(e["users"])
        dev = e["dev"]
        cur = db.query(SharedUse).filter(SharedUse.mac == mac, SharedUse.last_ts >= ts - timedelta(
            minutes=st["window"])).order_by(SharedUse.last_ts.desc()).first()
        detail = " · ".join(f"{n}: {'، '.join(sorted(s))}" for n, s in (e["users"][u] for u in users))
        if cur is not None:
            old = set(users_of(cur))
            cur.last_ts = ts
            if not set(users) <= old:
                cur.users = "," + ",".join(sorted(old | set(users))) + ","
                cur.detail = detail[:1000]
            continue
        inc = SharedUse(ts=ts, last_ts=ts, mac=mac, ip=e["ip"][:45], device=_label(dev, mac)[:150],
                        device_type=(dev.device_type if dev else "")[:20], users="," + ",".join(users) + ",",
                        detail=detail[:1000])
        db.add(inc)
        db.flush()
        inc.repeat = repeats(db, mac, ts - timedelta(days=st["repeat_days"]))
        alerts.add(db, "shared", f"چند کاربر روی یک دستگاه: {inc.device}", f"{detail} (بار {inc.repeat})", "warn",
                   "/shared")
        if st["msg_enabled"]:
            try:
                warn(db, inc, st, send)
            except Exception as ex:  # noqa: BLE001
                inc.msg = f"خطا: {ex}"[:500]
        if st["sms_enabled"] and (sms is not None or sms_available(db)):
            send_sms(db, inc, st, sms)
        if st["block_after"] and st["block_what"] != "none":
            since = ts - timedelta(days=st["repeat_days"])
            what = st["block_what"]
            dev_hit = inc.repeat >= st["block_after"]
            hit_users = [u for u in users if user_repeats(db, u, since) >= st["block_after"]]
            if what in ("device", "both") and not dev_hit:
                what = "users" if what == "both" else "none"
            if what in ("users", "both") and not hit_users:
                what = "device" if what == "both" else "none"
            if what != "none":
                acts = block(db, inc, what, "سیستم", st["block_minutes"], st["block_ad"], do_kick, hit_users)
                if acts:
                    alerts.add(db, "lock", f"مسدودی خودکار (چند کاربر روی یک دستگاه): {inc.device}",
                               " · ".join(acts), "err", "/shared")
        new.append(inc)
    db.commit()
    return new


def hotspot_warning(db, user, ip=""):
    """Text for the hotspot status page when this user is on a device that has an open episode now."""
    st = settings(db)
    if not st["enabled"]:
        return ""
    ts = now()
    q = db.query(SharedUse).filter(SharedUse.resolved_at.is_(None), SharedUse.users.like(f"%,{user.username.lower()},%"),
                                   SharedUse.last_ts >= ts - timedelta(minutes=st["window"] + 5))
    inc = q.order_by(SharedUse.last_ts.desc()).first()
    if inc is None:
        return ""
    return render(st["msg_text"], inc, st, [n for n, _ in _names(db, inc)])


def summary(db, days=30, limit=50):
    """Most repeated devices and users of the last days."""
    since = now() - timedelta(days=days)
    rows = db.query(SharedUse).filter(SharedUse.ts >= since).all()
    by_dev, by_user = {}, {}
    for r in rows:
        d = by_dev.setdefault(r.mac, {"mac": r.mac, "device": r.device, "n": 0, "last": r.ts, "users": set()})
        d["n"] += 1
        d["last"] = max(d["last"], r.ts)
        d["users"] |= set(users_of(r))
        for u in users_of(r):
            x = by_user.setdefault(u, {"user": u, "n": 0, "last": r.ts, "devices": set()})
            x["n"] += 1
            x["last"] = max(x["last"], r.ts)
            x["devices"].add(r.device or r.mac)
    key = lambda x: (x["n"], x["last"])  # noqa: E731
    return (sorted(by_dev.values(), key=key, reverse=True)[:limit],
            sorted(by_user.values(), key=key, reverse=True)[:limit])


def job():
    if not _LOCK.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        check(db)
    except Exception:  # noqa: BLE001
        log.exception("shared device check failed")
        db.rollback()
    finally:
        db.close()
        SessionLocal.remove()
        _LOCK.release()
