"""فهرست شبانه: هر شب سر ساعت تعیین‌شده (پیش‌فرض ۲۱:۰۰) دستگاه‌هایی که روشن و روی شبکه‌اند با آخرین کاربر واردشده ثبت می‌شوند."""
import logging
from datetime import datetime, timedelta

from . import config
from . import devices
from .db import Device, DeviceHistory, NightList, SessionLocal, get_setting, now, set_setting

LOGON_SOURCES = ("dc", "script")

log = logging.getLogger("nightlist")
LATE = timedelta(hours=1)          # app started after the check time: still take tonight's list within this window


def online_after(ts):
    return ts - timedelta(seconds=config.ROUTER_POLL_EVERY * 3 + 60)


def check_time(db):
    v = (get_setting(db, "night_list_time", "21:00") or "21:00").strip()
    try:
        hh, mm = (int(x) for x in v.split(":")[:2])
        return hh % 24, mm % 60
    except ValueError:
        return 21, 0


def take(db, ts=None):
    """Store the devices that are on the network now as the list of ts's day (replaces that day's list)."""
    ts = ts or now()
    day = ts.date()
    db.query(NightList).filter(NightList.day == day).delete()
    n = 0
    from .pingcheck import online_filter
    for d in online_filter(db.query(Device), ts).all():
        hs = db.query(DeviceHistory).filter(DeviceHistory.mac == d.mac, DeviceHistory.kind == "user",
                                            DeviceHistory.source.notin_(LOGON_SOURCES)) \
            .order_by(DeviceHistory.last_seen.desc()).first()
        db.add(NightList(day=day, taken_at=ts, mac=d.mac, ip=d.last_ip, nas_id=d.last_nas_id,
                         device_type=d.device_type or "unknown", label=d.label or "", hostname=d.hostname or "",
                         vendor=d.vendor or "", user=d.logon_user or "", user_at=d.logon_at,
                         user_source=d.logon_source if d.logon_user else "",
                         hotspot_user=hs.value if hs else "", hotspot_at=hs.last_seen if hs else None,
                         hotspot_active=bool(hs and ts - hs.last_seen <= devices.HISTORY_GAP)))
        n += 1
    set_setting(db, "night_list_day", day.isoformat())
    db.commit()
    return n


def job():
    db = SessionLocal()
    try:
        ts = now()
        hh, mm = check_time(db)
        due = datetime.combine(ts.date(), datetime.min.time()) + timedelta(hours=hh, minutes=mm)
        if due <= ts < due + LATE and get_setting(db, "night_list_day") != ts.date().isoformat():
            log.info("nightly device list: %s devices", take(db, ts))
    finally:
        db.close()
        SessionLocal.remove()
