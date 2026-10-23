"""اتصال‌هایی که RADIUS Accounting برایشان نمی‌رسد (کاربران محلی هات‌اسپات / PPP روتر، یا Accounting خاموش)
از روی لیست active روتر (API) ثبت می‌شوند تا آنلاین‌ها، مصرف و سرعت آن‌ها هم در گزارش‌ها بیاید."""
import logging
import re
import threading
from datetime import timedelta

from sqlalchemy import func

from . import config, devices
from .db import AcctSession, Device, SpeedSample, User, get_setting

log = logging.getLogger("apisessions")
PREFIX = "api:"
# RADIUS accounting and the API poll both update the byte counters of a RADIUS session: one at a time
LOCK = threading.RLock()
_UPTIME = re.compile(r"(\d+)([wdhms])")
_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def uptime_seconds(v) -> int:
    """RouterOS durations: '1w2d03:04:05', '3h15m22s', '00:05:10', '45s'."""
    v = str(v or "").strip()
    total = sum(int(n) * _UNITS[u] for n, u in _UPTIME.findall(v))
    m = re.search(r"(\d+):(\d+):(\d+)$", v)
    if m:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    return total


def _int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def nas_key(nas):
    """The nas_ip stored on sessions of this router."""
    return nas.ip if nas.ip and nas.ip != "0.0.0.0" else (nas.api_host or nas.ip)


def _user(db, username, auto_create):
    u = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if u is None and auto_create:
        u = User(username=username, source="router", notes="اکانت محلی روتر (از API)")
        db.add(u)
        db.flush()
    return u


def entries(snap):
    """Normalized active entries of a router snapshot: (sid suffix, service, user, ip, mac, uptime, up, down)."""
    out = []
    for a in snap.get("hotspot_active", []):
        if a.get("user"):
            out.append((f"hs:{a.get('.id', '')}", "hotspot", a["user"], str(a.get("address", "")),
                        devices.normalize_mac(a.get("mac-address", "")), uptime_seconds(a.get("uptime")),
                        _int(a.get("bytes-in")), _int(a.get("bytes-out"))))
    ifaces = {i.get("name"): i for i in snap.get("interfaces", [])}
    for p in snap.get("ppp_active", []):
        if not p.get("name"):
            continue
        iface = ifaces.get(f"<{p.get('service', '')}-{p['name']}>") or {}
        out.append((f"ppp:{p.get('.id', '')}", "vpn", p["name"], str(p.get("address", "")),
                    devices.normalize_mac(p.get("caller-id", "")), uptime_seconds(p.get("uptime")),
                    _int(iface.get("rx-byte")), _int(iface.get("tx-byte"))))
    return out


def _count(db, s, b_in, b_out, up_secs, ts):
    """New router counters of a session -> speed sample (delta), peaks, totals."""
    d_in, d_out = max(0, b_in - (s.bytes_in or 0)), max(0, b_out - (s.bytes_out or 0))
    secs = max(1, int((ts - s.last_update).total_seconds())) if s.last_update else 1
    if d_in or d_out:
        db.add(SpeedSample(session_id=s.id, user_id=s.user_id, ts=ts, seconds=secs, d_in=d_in, d_out=d_out))
        if secs <= config.ROUTER_POLL_EVERY * 3:
            s.peak_up_bps = max(s.peak_up_bps or 0, d_in * 8 // secs)
            s.peak_down_bps = max(s.peak_down_bps or 0, d_out * 8 // secs)
    s.bytes_in, s.bytes_out = max(b_in, s.bytes_in or 0), max(b_out, s.bytes_out or 0)
    s.session_time, s.last_update = max(up_secs, s.session_time or 0), ts


def sync(db, nas, snap, ts):
    """Create / update / close API-tracked sessions of one router from its active lists.
    Logins that RADIUS accounting already covers are only kept up to date between Interim-Updates."""
    key = nas_key(nas)
    prefix = f"{PREFIX}{nas.id}:"
    # RADIUS sessions of this router (stored under its IP; older ones under any of its addresses)
    own = {a for a in (nas.ip, nas.api_host, key) if a and a != "0.0.0.0"}
    own |= {str(a.get("address", "")).split("/")[0] for a in snap.get("addresses", []) if a.get("address")}
    radius = {}
    for r in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.nas_ip.in_(own),
                                          ~AcctSession.acct_session_id.like(PREFIX + "%")) \
            .order_by(AcctSession.start_time.desc()):
        radius.setdefault((r.username.lower(), r.framed_ip or ""), (r.id, r.start_time))
    mine = {s.acct_session_id: s for s in db.query(AcctSession).filter(
        AcctSession.active.is_(True), AcctSession.acct_session_id.like(prefix + "%"))}
    auto = get_setting(db, "acct_auto_create", "1") == "1"
    seen, covered = set(), []
    for suffix, service, username, ip, mac, up_secs, b_in, b_out in entries(snap):
        hit = radius.get((username.lower(), ip)) or radius.get((username.lower(), ""))
        if hit:
            rid, started = hit
            if started and abs((ts - timedelta(seconds=up_secs) - started).total_seconds()) <= 300:
                covered.append((rid, up_secs, b_in, b_out))       # the same login
            continue
        sid = prefix + suffix
        s = mine.get(sid)
        if s is not None and (s.username != username or b_in < (s.bytes_in or 0) or b_out < (s.bytes_out or 0)):
            s.active, s.stop_time, s.terminate_cause = False, s.last_update, "Replaced"
            s = None
        if s is None:
            _free_sid(db, key, sid, username)
            u = _user(db, username, auto)
            dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
            s = AcctSession(acct_session_id=sid, nas_ip=key, username=username, user_id=u.id if u else None,
                            service=service, framed_ip=ip, mac=mac, start_time=ts - timedelta(seconds=up_secs),
                            last_update=ts - timedelta(seconds=up_secs), active=True, bytes_in=0, bytes_out=0,
                            device_type=dev.device_type if dev else ("unknown" if service == "vpn" else ""),
                            device_os=dev.os if dev else "")
            db.add(s)
            db.flush()
            mine[sid] = s
        seen.add(sid)
        _count(db, s, b_in, b_out, up_secs, ts)
        if ip and not s.framed_ip:
            s.framed_ip = ip
    for sid, s in mine.items():
        if sid not in seen:
            s.active, s.stop_time, s.terminate_cause = False, s.last_update, "Logout"
    if covered:
        # same counters RADIUS reports: usage shows up every minute, and the session does not go stale
        # when the router sends no (or rare) Interim-Updates; the next RADIUS packet only adds the rest
        db.commit()
        with LOCK:
            for rid, up_secs, b_in, b_out in covered:
                r = db.get(AcctSession, rid)
                db.refresh(r)
                if r.active:
                    _count(db, r, b_in, b_out, up_secs, ts)
            db.commit()
    return len(seen)


def _free_sid(db, key, sid, username):
    """RouterOS reuses .id values (a hotspot login's .id comes from its IP), so the same user logging in again
    from the same address gets the id of an earlier, finished login: that one keeps its row under a new id."""
    for old in db.query(AcctSession).filter(AcctSession.nas_ip == key, AcctSession.acct_session_id == sid,
                                            AcctSession.username == username):
        old.acct_session_id = f"{sid}~{old.id}"
    db.flush()


def close_replaced(db, username, ip):
    """RADIUS accounting started for a login that was tracked from the API until now."""
    for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.acct_session_id.like(PREFIX + "%"),
                                          AcctSession.username == username, AcctSession.framed_ip == ip):
        s.active, s.stop_time, s.terminate_cause = False, s.last_update, "RADIUS"
