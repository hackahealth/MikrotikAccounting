"""How long history is kept: automatic deletion after N months (setting history_keep_months, default 6, 0 = never)
and deletion by hand of everything before a date (page /data)."""
import logging
import os
from datetime import date, datetime, timedelta

from sqlalchemy import func, text

from . import config
from .db import (AcctSession, Alert, AuditLog, AuthLog, Call, DeviceHistory, DeviceTraffic, IfaceDaily, NetEvent,
                 SpeedSample, TrafficCategory, TrafficDomain, User, engine, get_setting, now)

log = logging.getLogger("retention")

# group -> (title, [(model, time column)]); usage is what the automatic deletion touches
GROUPS = {
    "usage": ("سابقهٔ مصرف کاربران (حجم، جلسه‌ها، نوع استفاده، سایت‌ها)",
              [(SpeedSample, SpeedSample.ts), (AcctSession, AcctSession.stop_time),
               (TrafficCategory, TrafficCategory.day), (TrafficDomain, TrafficDomain.day)]),
    "routers": ("ترافیک روترها و دستگاه‌ها (روزانه)", [(IfaceDaily, IfaceDaily.day), (DeviceTraffic, DeviceTraffic.day)]),
    "logs": ("لاگ ورود، رویدادهای شبکه و هشدارها", [(AuthLog, AuthLog.ts), (NetEvent, NetEvent.ts), (Alert, Alert.ts)]),
    "devices": ("سابقهٔ IP / کاربر دستگاه‌ها", [(DeviceHistory, DeviceHistory.last_seen)]),
    "calls": ("تماس‌های ایزابل", [(Call, Call.ts)]),
    "audit": ("لاگ فعالیت کاربران پنل", [(AuditLog, AuditLog.ts)]),
}
AUTO_GROUPS = ("usage", "routers")
TABLE_FA = {"speed_samples": "نمونه‌های مصرف", "sessions": "جلسه‌ها", "traffic_category": "نوع استفاده",
            "traffic_domain": "سایت‌ها", "iface_daily": "ترافیک روزانهٔ اینترفیس", "device_traffic": "ترافیک دستگاه‌ها",
            "auth_log": "لاگ ورود", "net_events": "رویدادهای شبکه", "alerts": "هشدارها",
            "device_history": "سابقهٔ دستگاه", "calls": "تماس‌ها", "audit_log": "لاگ پنل"}


def keep_months(db) -> int:
    try:
        return max(0, int(get_setting(db, "history_keep_months", "6") or 0))
    except ValueError:
        return 6


def cutoff(months: int, ref: datetime = None) -> datetime:
    """Start of the day `months` months (31 days each, so never less than asked) before ref."""
    d = (ref or now()).date() - timedelta(days=31 * months)
    return datetime(d.year, d.month, d.day)


def _protected_users(db):
    """Users whose quota counts all their usage (no period): their samples / sessions are the quota itself."""
    from .policy import Effective
    ids = set()
    for u in db.query(User).all():
        eff = Effective(u)
        if eff.quota_mb and eff.quota_period not in ("daily", "weekly", "monthly"):
            ids.add(u.id)
    return ids


def _delete(db, model, col, before: datetime, keep_users):
    limit = before.date() if col.type.python_type is date else before
    q = db.query(model).filter(col < limit)
    if model is AcctSession:
        q = q.filter(AcctSession.active.is_(False))
    if keep_users and model in (SpeedSample, AcctSession):
        q = q.filter(~model.user_id.in_(keep_users) | model.user_id.is_(None))
    return q.delete(synchronize_session=False)


def purge(db, before: datetime, groups) -> dict:
    """Deletes the rows of the given groups older than `before`. Returns {table: rows deleted}."""
    keep = _protected_users(db)
    out = {}
    for g in groups:
        for model, col in GROUPS.get(g, ("", []))[1]:
            out[model.__tablename__] = out.get(model.__tablename__, 0) + _delete(db, model, col, before, keep)
    db.commit()
    return out


def auto(db):
    months = keep_months(db)
    if not months:
        return {}
    n = purge(db, cutoff(months), AUTO_GROUPS)
    if any(n.values()):
        log.info("history older than %s months deleted: %s", months, n)
    return n


def vacuum():
    """Gives the space of deleted rows back to the disk (SQLite only)."""
    if not config.DATABASE_URL.startswith("sqlite"):
        return
    with engine.connect() as c:
        c = c.execution_options(isolation_level="AUTOCOMMIT")
        c.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        c.execute(text("VACUUM"))


def db_size() -> int:
    if not config.DATABASE_URL.startswith("sqlite:///"):
        return 0
    p = config.DATABASE_URL[len("sqlite:///"):]
    return sum(os.path.getsize(p + s) for s in ("", "-wal") if os.path.exists(p + s))


def stats(db):
    rows = []
    for g, (title, items) in GROUPS.items():
        for model, col in items:
            n, oldest = db.query(func.count(), func.min(col)).select_from(model).one()
            rows.append({"group": g, "group_fa": title, "table": model.__tablename__,
                         "name": TABLE_FA.get(model.__tablename__, model.__tablename__), "count": n or 0,
                         "oldest": oldest.date() if isinstance(oldest, datetime) else oldest})
    return rows
