"""Automatic Windows message (msg.exe) when a user's internet quota passes the warning percent and again when it runs
out: once per level per quota period, to the computers of the user's live sessions (on a shared RDP server only that
user's own session gets it)."""
import logging
from collections import defaultdict
from datetime import timedelta

from . import auth, policy, winmsg
from .db import AcctSession, SessionLocal, User, get_setting, now

log = logging.getLogger("quotamsg")
EVERY = 120


def settings(db):
    return {"enabled": get_setting(db, "quota_msg_enabled", "1") == "1",
            "extra": get_setting(db, "quota_msg_extra", "برای افزایش حجم با واحد IT تماس بگیرید.")}


def targets(db, user, sessions):
    """-> {ip: (who, label)}."""
    out = {}
    for s in sessions:
        if s.service == "proxy" and s.called_station:
            out[s.called_station] = (user.username, f"پروکسی @ {s.called_station}")
        elif s.service == "hotspot" and s.framed_ip:
            out.setdefault(s.framed_ip, ("*", f"هات‌اسپات @ {s.framed_ip}"))
    for label, ip in winmsg.targets(db, "user", user.username):
        out.setdefault(ip, (user.username, label))
    return out


def text_for(user, w, extra):
    name = user.full_name or user.username
    t = f"{name}، {w['text']}"
    return f"{t}\n{extra}" if extra and w["level"] == "err" else t


def check(db, send=None):
    """One round; returns [(username, level, ok count)]. send(ip, text, who) is winmsg.send_one by default."""
    st = settings(db)
    if not st["enabled"]:
        return []
    send = send or (lambda ip, text, who: winmsg.send_one(ip, text, 120, who))
    by_user = defaultdict(list)
    ended = now() - timedelta(minutes=10)      # cut for an exhausted quota just now: still tell them why
    for s in db.query(AcctSession).filter(AcctSession.user_id.isnot(None), AcctSession.last_update >= ended,
                                          AcctSession.active.is_(True) | (AcctSession.stop_time >= ended)):
        by_user[s.user_id].append(s)
    done = []
    for uid, sessions in by_user.items():
        user = db.get(User, uid)
        if user is None:
            continue
        w = policy.quota_warning(db, user)
        if not w:
            continue
        start = policy.period_start(policy.Effective(user).quota_period)
        if user.usage_reset_at and user.usage_reset_at > start:
            start = user.usage_reset_at
        sent = user.quota_msg_level if user.quota_msg_at and user.quota_msg_at >= start else ""
        if sent == "err" or sent == w["level"]:
            continue
        text = text_for(user, w, st["extra"])
        ok = 0
        for ip, (who, label) in targets(db, user, sessions).items():
            good, err = send(ip, text, who)
            ok += bool(good)
            if not good:
                log.info("quota message to %s (%s) failed: %s", user.username, label, err)
        if ok:
            user.quota_msg_level, user.quota_msg_at = w["level"], now()
            auth.audit(db, "سیستم", "پیام خودکار حجم", f"{user.username}: {w['text']} ({ok} رایانه)", "")
        done.append((user.username, w["level"], ok))
    db.commit()
    return done


def job():
    db = SessionLocal()
    try:
        if winmsg.available():
            check(db)
    finally:
        db.close()
        SessionLocal.remove()
