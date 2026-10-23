"""گزارش‌گیری: مصرف، زمان، سرعت، نوع استفاده، دستگاه."""
from datetime import datetime, timedelta

from sqlalchemy import case, extract, func, or_

from .classifier import CATEGORIES
from .db import AcctSession, Department, Group, Office, SpeedSample, TrafficCategory, TrafficDomain, User, now
from .devices import TYPE_FA


class Filter:
    """ids: user ids the report is limited to (None = all users), already combined with the viewer's scope."""
    def __init__(self, start: datetime, end: datetime, ids=None, service=""):
        self.start, self.end, self.ids, self.service = start, end, ids, service

    def user_ids(self, db):
        return self.ids


def _samples(db, f: Filter):
    q = db.query(SpeedSample).filter(SpeedSample.ts >= f.start, SpeedSample.ts < f.end)
    ids = f.user_ids(db)
    if ids is not None:
        q = q.filter(SpeedSample.user_id.in_(ids or [-1]))
    if f.service:
        q = q.join(AcctSession, AcctSession.id == SpeedSample.session_id).filter(AcctSession.service == f.service)
    return q


def _sessions(db, f: Filter):
    q = db.query(AcctSession).filter(AcctSession.start_time < f.end,
                                     or_(AcctSession.stop_time.is_(None), AcctSession.stop_time >= f.start))
    ids = f.user_ids(db)
    if ids is not None:
        q = q.filter(AcctSession.user_id.in_(ids or [-1]))
    if f.service:
        q = q.filter(AcctSession.service == f.service)
    return q


def _overlap_seconds(s: AcctSession, f: Filter) -> int:
    end = s.stop_time or s.last_update or now()
    a, b = max(s.start_time, f.start), min(end, f.end)
    return max(0, int((b - a).total_seconds()))


def _traffic_filter(q, model, db, f: Filter):
    q = q.filter(model.day >= f.start.date(), model.day <= (f.end - timedelta(seconds=1)).date())
    ids = f.user_ids(db)
    if ids is not None:
        q = q.filter(model.user_id.in_(ids or [-1]))
    return q


def parts(total, lan, tunnel):
    """(internal, tunnel, internet) of a total, flow numbers capped so the three always add up to the total."""
    lan = min(lan or 0, total)
    tunnel = min(tunnel or 0, total - lan)
    return lan, tunnel, total - lan - tunnel


def split_usage(db, start: datetime, end: datetime, ids=None):
    """مصرف هر کاربر در هر روز به تفکیک «اینترنت»، «تانل» (شبکه دفاتر دیگر از راه تانل) و «داخل شبکه».
    مبنای حجم کل، Accounting روتر است؛ سهم داخل شبکه و تانل از Traffic-Flow (دسته‌های lan و tunnel) خوانده می‌شود.
    روزهایی که Accounting ندارند فقط از Traffic-Flow حساب می‌شوند."""
    q = db.query(SpeedSample.user_id, func.date(SpeedSample.ts), func.sum(SpeedSample.d_out),
                 func.sum(SpeedSample.d_in)).filter(SpeedSample.ts >= start, SpeedSample.ts < end)
    if ids is not None:
        q = q.filter(SpeedSample.user_id.in_(ids or [-1]))
    acct = {(uid, str(d)[:10]): (int(o or 0), int(i or 0))
            for uid, d, o, i in q.group_by(SpeedSample.user_id, func.date(SpeedSample.ts)).all()}
    lan = TrafficCategory.category == "lan"
    tun = TrafficCategory.category == "tunnel"
    q = db.query(TrafficCategory.user_id, TrafficCategory.day,
                 func.sum(case((lan, TrafficCategory.bytes_down), else_=0)),
                 func.sum(case((lan, TrafficCategory.bytes_up), else_=0)),
                 func.sum(case((tun, TrafficCategory.bytes_down), else_=0)),
                 func.sum(case((tun, TrafficCategory.bytes_up), else_=0)),
                 func.sum(TrafficCategory.bytes_down), func.sum(TrafficCategory.bytes_up)) \
        .filter(TrafficCategory.day >= start.date(), TrafficCategory.day <= (end - timedelta(seconds=1)).date())
    if ids is not None:
        q = q.filter(TrafficCategory.user_id.in_(ids or [-1]))
    flow = {(uid, str(d)[:10]): tuple(int(x or 0) for x in rest)
            for uid, d, *rest in q.group_by(TrafficCategory.user_id, TrafficCategory.day).all()}
    rows, days, users = [], {}, {}
    tot = {k: 0 for k in ("internet_down", "internet_up", "internal_down", "internal_up", "tunnel_down", "tunnel_up")}
    for key in sorted(set(acct) | set(flow), key=lambda k: (k[1], k[0] or 0)):
        uid, day = key
        ld, lu, td, tu, fd, fu = flow.get(key, (0, 0, 0, 0, 0, 0))
        down, up = acct.get(key, (0, 0))
        if not down and not up:
            down, up = fd, fu
        r = {"user_id": uid, "day": day}
        r["internal_down"], r["tunnel_down"], r["internet_down"] = parts(down, ld, td)
        r["internal_up"], r["tunnel_up"], r["internet_up"] = parts(up, lu, tu)
        for k in ("internal", "tunnel", "internet"):
            r[k] = r[k + "_down"] + r[k + "_up"]
        r["total"] = down + up
        rows.append(r)
        for k in tot:
            tot[k] += r[k]
        dd = days.setdefault(day, {"day": day, "internet": 0, "internal": 0, "tunnel": 0})
        uu = users.setdefault(uid, {"internet": 0, "internal": 0, "tunnel": 0})
        for k in ("internet", "internal", "tunnel"):
            dd[k] += r[k]
            uu[k] += r[k]
    for k in ("internet", "internal", "tunnel"):
        tot[k] = tot[k + "_down"] + tot[k + "_up"]
    return {**tot, "daily": [days[d] for d in sorted(days)], "users": users, "user_daily": rows,
            "has_flow": bool(flow)}


def build(db, f: Filter, session_limit=300):
    s_in = func.coalesce(func.sum(SpeedSample.d_in), 0)
    s_out = func.coalesce(func.sum(SpeedSample.d_out), 0)
    up, down = _samples(db, f).with_entities(s_in, s_out).one()
    sessions = _sessions(db, f).order_by(AcctSession.start_time.desc()).all()
    online = sum(_overlap_seconds(s, f) for s in sessions)

    daily = _samples(db, f).with_entities(func.date(SpeedSample.ts), s_in, s_out) \
        .group_by(func.date(SpeedSample.ts)).order_by(func.date(SpeedSample.ts)).all()
    hourly_rows = _samples(db, f).with_entities(extract("hour", SpeedSample.ts), s_in, s_out) \
        .group_by(extract("hour", SpeedSample.ts)).all()
    hourly = [[0, 0] for _ in range(24)]
    for h, i, o in hourly_rows:
        hourly[int(h)] = [int(i), int(o)]

    # per user
    per_user_bytes = {uid: (int(i), int(o)) for uid, i, o in _samples(db, f).with_entities(
        SpeedSample.user_id, s_in, s_out).group_by(SpeedSample.user_id).all()}
    per_user = {}
    for s in sessions:
        r = per_user.setdefault(s.user_id or 0, {"username": s.username, "sessions": 0, "online": 0,
                                                 "peak_down": 0, "peak_up": 0, "devices": set(), "ips": set()})
        r["sessions"] += 1
        r["online"] += _overlap_seconds(s, f)
        r["peak_down"] = max(r["peak_down"], s.peak_down_bps or 0)
        r["peak_up"] = max(r["peak_up"], s.peak_up_bps or 0)
        if s.device_type:
            r["devices"].add(TYPE_FA.get(s.device_type, s.device_type))
    users = {u.id: u for u in db.query(User).filter(User.id.in_(list(per_user) + list(per_user_bytes))).all()}
    groups = {g.id: g.name for g in db.query(Group).all()}
    offices = {o.id: o.name for o in db.query(Office).all()}
    depts = {d.id: d.name for d in db.query(Department).all()}
    user_rows = []
    for uid in set(per_user) | set(per_user_bytes):
        r = per_user.get(uid, {"username": users[uid].username if uid in users else "?", "sessions": 0,
                               "online": 0, "peak_down": 0, "peak_up": 0, "devices": set()})
        i, o = per_user_bytes.get(uid, (0, 0))
        u = users.get(uid)
        user_rows.append({"user_id": uid, "username": r["username"], "full_name": u.full_name if u else "",
                          "group": groups.get(u.group_id, "") if u else "",
                          "office": offices.get(u.office_id, "") if u else "",
                          "department": depts.get(u.department_id, "") if u else "", "up": i, "down": o, "total": i + o,
                          "sessions": r["sessions"], "online": r["online"], "peak_down": r["peak_down"],
                          "peak_up": r["peak_up"], "avg_down": (o * 8 // r["online"]) if r["online"] else 0,
                          "devices": "، ".join(sorted(r["devices"]))})
    split = split_usage(db, f.start, f.end, f.user_ids(db))
    for r in user_rows:
        sp = split["users"].get(r["user_id"], {})
        r["internal"], r["tunnel"], r["internet"] = parts(r["total"], sp.get("internal"), sp.get("tunnel"))
    user_rows.sort(key=lambda x: -x["total"])

    # traffic categories (NetFlow)
    cat_rows = _traffic_filter(db.query(TrafficCategory.category, func.sum(TrafficCategory.bytes_down),
                                        func.sum(TrafficCategory.bytes_up), func.sum(TrafficCategory.flows)),
                               TrafficCategory, db, f).group_by(TrafficCategory.category).all()
    categories = sorted([{"key": c, "name": CATEGORIES.get(c, c), "down": int(d or 0), "up": int(u or 0),
                          "flows": int(n or 0)} for c, d, u, n in cat_rows], key=lambda x: -(x["down"] + x["up"]))
    cat_total = sum(c["down"] + c["up"] for c in categories) or 1
    for c in categories:
        c["pct"] = round(100 * (c["down"] + c["up"]) / cat_total, 1)
    cat_hour_rows = _traffic_filter(db.query(TrafficCategory.hour, TrafficCategory.category,
                                             func.sum(TrafficCategory.bytes_down + TrafficCategory.bytes_up)),
                                    TrafficCategory, db, f).group_by(TrafficCategory.hour,
                                                                     TrafficCategory.category).all()
    cat_by_hour = {}
    for h, c, b in cat_hour_rows:
        cat_by_hour.setdefault(c, [0] * 24)[int(h)] = int(b or 0)

    dom_rows = _traffic_filter(db.query(TrafficDomain.domain, TrafficDomain.category,
                                        func.sum(TrafficDomain.bytes_down), func.sum(TrafficDomain.bytes_up)),
                               TrafficDomain, db, f).group_by(TrafficDomain.domain, TrafficDomain.category) \
        .order_by(func.sum(TrafficDomain.bytes_down + TrafficDomain.bytes_up).desc()).limit(50).all()
    domains = [{"domain": d, "category": CATEGORIES.get(c, c), "down": int(a or 0), "up": int(b or 0)}
               for d, c, a, b in dom_rows]

    # devices
    dev = {}
    for s in sessions:
        k = s.device_type or "unknown"
        r = dev.setdefault(k, {"name": TYPE_FA.get(k, k), "sessions": 0, "bytes": 0, "os": {}})
        r["sessions"] += 1
        r["bytes"] += (s.bytes_in or 0) + (s.bytes_out or 0)
        if s.device_os:
            r["os"][s.device_os] = r["os"].get(s.device_os, 0) + 1
    devices = sorted(dev.values(), key=lambda x: -x["sessions"])
    for d in devices:
        d["os"] = "، ".join(f"{k} ({v})" for k, v in sorted(d["os"].items(), key=lambda x: -x[1]))

    services = {}
    for s in sessions:
        r = services.setdefault(s.service, {"sessions": 0, "bytes": 0})
        r["sessions"] += 1
        r["bytes"] += (s.bytes_in or 0) + (s.bytes_out or 0)

    return {
        "up": int(up), "down": int(down), "total": int(up) + int(down), "online": online,
        "session_count": len(sessions), "user_count": len({s.user_id for s in sessions if s.user_id}),
        "peak_down": max([s.peak_down_bps or 0 for s in sessions] or [0]),
        "daily": [{"day": str(d), "up": int(i), "down": int(o)} for d, i, o in daily],
        "hourly": hourly, "users": user_rows, "categories": categories, "cat_by_hour": cat_by_hour,
        "domains": domains, "devices": devices, "services": services, "split": split,
        "sessions": sessions[:session_limit], "sessions_total": len(sessions),
    }
