"""مجوز موقت: کار خارج از ساعات مجاز، یا اینترنت آزاد (بدون سقف حجم و بدون مسدودی سایت‌ها) برای یک بازه."""
from .db import TempGrant, now

KINDS = {"hours": "کار خارج از ساعات مجاز", "internet": "اینترنت آزاد (بدون سقف حجم و مسدودی سایت)"}


def active(db, user_id, kind, when=None):
    when = when or now()
    return db.query(TempGrant).filter(TempGrant.user_id == user_id, TempGrant.kind == kind,
                                      TempGrant.revoked_at.is_(None), TempGrant.start <= when,
                                      TempGrant.end > when).order_by(TempGrant.end.desc()).first()
