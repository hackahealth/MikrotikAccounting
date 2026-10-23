"""ورودهای ناموفق و قفل: کاربر، MAC یا IP قفل‌شده نمی‌تواند به هات‌اسپات یا VPN وارد شود. پیش‌فرض اگر ۱۰ بار در
۲۴ ساعت رمز اشتباه وارد شود، خودکار قفل و به مدیر سیستم و کارشناس IT اعلان داده می‌شود."""
import ipaddress
from datetime import timedelta

from sqlalchemy import func, or_

from . import alerts, devices
from .db import AuthLog, Lock, get_setting, now

KINDS = {"user": "کاربر", "mac": "MAC", "ip": "IP"}
# rejections that mean "wrong credentials" (not policy: hours, quota, ...)
BAD_PASSWORD = ("رمز عبور اشتباه", "invalidCredentials", "کاربر یافت نشد", "AD: ")


def source_kind(value):
    """Calling-Station-Id: MAC for hotspot, the client's IP for VPN."""
    v = (value or "").strip()
    if devices.normalize_mac(v):
        return "mac", devices.normalize_mac(v)
    try:
        return "ip", str(ipaddress.ip_address(v.split(":")[0] if v.count(":") == 1 else v))
    except ValueError:
        return "", v


def rules(db):
    def num(key, default):
        try:
            return max(0, int(get_setting(db, key, str(default)) or default))
        except ValueError:
            return default
    return {"count": num("lock_fail_count", 10), "hours": num("lock_fail_hours", 24) or 24,
            "minutes": num("lock_minutes", 0), "lock_source": get_setting(db, "lock_source", "1") == "1"}


def active_locks(db):
    t = now()
    return db.query(Lock).filter(Lock.released_at.is_(None), or_(Lock.until.is_(None), Lock.until > t))


def locked(db, username="", source=""):
    """The active lock that stops this login, or None."""
    keys = []
    if username:
        keys.append(("user", username.lower()))
    k, v = source_kind(source)
    if k:
        keys.append((k, v.lower()))
    for kind, value in keys:
        hit = active_locks(db).filter(Lock.kind == kind, func.lower(Lock.value) == value).first()
        if hit:
            return hit
    return None


def lock(db, kind, value, reason, by="", auto=False, minutes=0):
    value = value.strip()
    if kind == "mac":
        value = devices.normalize_mac(value) or value
    hit = active_locks(db).filter(Lock.kind == kind, func.lower(Lock.value) == value.lower()).first()
    if hit:
        return hit, False
    lk = Lock(kind=kind, value=value[:150], reason=reason[:255], auto=auto, created_by=by,
              until=now() + timedelta(minutes=minutes) if minutes else None)
    db.add(lk)
    return lk, True


def unlock(db, lock_id, by):
    lk = db.get(Lock, lock_id)
    if lk and lk.released_at is None:
        lk.released_at, lk.released_by = now(), by
    return lk


def is_bad_password(reason):
    return any(x in (reason or "") for x in BAD_PASSWORD)


def on_failure(db, username, source, reason):
    """After a rejected login: lock the user / the source when the failed-login rule is reached."""
    if not is_bad_password(reason):
        return []
    r = rules(db)
    if not r["count"]:
        return []
    since = now() - timedelta(hours=r["hours"])
    bad = or_(*[AuthLog.reason.like(f"%{x}%") for x in BAD_PASSWORD])
    done = []
    known = "کاربر یافت نشد" not in reason
    if username and known:
        n = db.query(AuthLog).filter(AuthLog.result == "reject", func.lower(AuthLog.username) == username.lower(),
                                     AuthLog.ts >= since, bad).count()
        if n >= r["count"]:
            lk, new = lock(db, "user", username, f"{n} بار رمز اشتباه در {r['hours']} ساعت", "سیستم", True,
                           r["minutes"])
            if new:
                done.append(lk)
    kind, value = source_kind(source)
    if kind and r["lock_source"]:
        n = db.query(AuthLog).filter(AuthLog.result == "reject", AuthLog.mac == source[:64], AuthLog.ts >= since,
                                     bad).count()
        if n >= r["count"]:
            lk, new = lock(db, kind, value, f"{n} ورود ناموفق در {r['hours']} ساعت از این {KINDS[kind]}", "سیستم",
                           True, r["minutes"])
            if new:
                done.append(lk)
    for lk in done:
        alerts.add(db, "lock", f"قفل خودکار {KINDS[lk.kind]} {lk.value}", lk.reason, "err", "/security")
    return done


def failures(db, hours=24, limit=50):
    """Failed logins of the last hours grouped by user and by source."""
    since = now() - timedelta(hours=hours)
    base = db.query(AuthLog).filter(AuthLog.result == "reject", AuthLog.ts >= since)
    by_user = db.query(AuthLog.username, func.count(AuthLog.id), func.max(AuthLog.ts),
                       func.count(func.distinct(AuthLog.mac))).filter(
        AuthLog.result == "reject", AuthLog.ts >= since).group_by(AuthLog.username) \
        .order_by(func.count(AuthLog.id).desc()).limit(limit).all()
    by_src = db.query(AuthLog.mac, func.count(AuthLog.id), func.max(AuthLog.ts),
                      func.count(func.distinct(AuthLog.username))).filter(
        AuthLog.result == "reject", AuthLog.ts >= since, AuthLog.mac != "").group_by(AuthLog.mac) \
        .order_by(func.count(AuthLog.id).desc()).limit(limit).all()
    return {"total": base.count(), "by_user": by_user, "by_src": by_src,
            "recent": base.order_by(AuthLog.ts.desc()).limit(200).all()}
