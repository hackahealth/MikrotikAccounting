"""اعلان‌ها برای مدیر سیستم و کارشناس IT: قفل شدن حساب، قطع روتر یا تانل، دسترسی غیرمجاز و ..."""
import logging

from .db import Alert, now

log = logging.getLogger("alerts")


def add(db, kind, title, body="", level="warn", link=""):
    """Store an alert (the caller commits). Same unread title within 10 minutes is not repeated."""
    from datetime import timedelta
    dup = db.query(Alert).filter(Alert.title == title[:255], Alert.read_at.is_(None),
                                 Alert.ts >= now() - timedelta(minutes=10)).first()
    if dup:
        return dup
    a = Alert(kind=kind, level=level, title=title[:255], body=body, link=link[:255])
    db.add(a)
    log.warning("alert [%s] %s %s", kind, title, body)
    return a


def unread(db):
    return db.query(Alert).filter(Alert.read_at.is_(None)).count()
