"""گزارش مدیریتی و گزارش ساعات اتصال کارکنان (منابع انسانی)."""
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import extract, func, or_

from . import policy
from .reports import parts, split_usage
from .classifier import CATEGORIES
from .db import (AcctSession, AuthLog, Department, Group, Office, SpeedSample, TrafficCategory, TrafficDomain, User,
                 get_setting, now)
from .devices import TYPE_FA

DEFAULT_WORK_HOURS = "sat-wed 08:00-16:00; thu 08:00-12:00"
LEISURE = {"video", "music", "social", "gaming"}


def work_rules(db):
    try:
        return policy.parse_hours(get_setting(db, "work_hours", DEFAULT_WORK_HOURS) or DEFAULT_WORK_HOURS)
    except (ValueError, KeyError):
        return policy.parse_hours(DEFAULT_WORK_HOURS)


def is_work(rules, day, hour) -> bool:
    """Work-hours test for an hourly bucket (checked at its midpoint)."""
    return policy.hours_allowed(rules, datetime(day.year, day.month, day.day, int(hour), 30))


def work_windows(rules, day):
    """Work intervals (datetime pairs) inside a calendar day."""
    base = datetime(day.year, day.month, day.day)
    wd, prev = day.weekday(), (day.weekday() - 1) % 7
    out = []
    for days, s, e in rules or []:
        if s < e and wd in days:
            out.append((base + timedelta(minutes=s), base + timedelta(minutes=e)))
        elif s > e:
            if wd in days:
                out.append((base + timedelta(minutes=s), base + timedelta(days=1)))
            if prev in days:
                out.append((base, base + timedelta(minutes=e)))
        elif s == e and wd in days:
            out.append((base, base + timedelta(days=1)))
    return out


def _overlap(a1, a2, b1, b2):
    return max(0.0, (min(a2, b2) - max(a1, b1)).total_seconds())


def _names(db):
    return ({g.id: g.name for g in db.query(Group).all()}, {o.id: o.name for o in db.query(Office).all()},
            {d.id: d.name for d in db.query(Department).all()})


def _breakdown(per_user, online_by_user, users, key, names, total):
    """Usage grouped by a User attribute (group_id / office_id / department_id)."""
    none = "نامشخص" if key != "group_id" else "بدون گروه"
    grp = defaultdict(lambda: {"bytes": 0, "users": set(), "online": 0.0})
    for uid, (i, o) in per_user.items():
        u = users.get(uid)
        g = names.get(getattr(u, key), none) if u and getattr(u, key) else none
        grp[g]["bytes"] += i + o
        grp[g]["users"].add(uid)
    for uid, sec in online_by_user.items():
        u = users.get(uid)
        g = names.get(getattr(u, key), none) if u and getattr(u, key) else none
        grp[g]["online"] += sec
        grp[g]["users"].add(uid)
    return sorted([{"name": k, "bytes": v["bytes"], "users": len(v["users"]),
                    "per_user": v["bytes"] // max(1, len(v["users"])), "online_h": round(v["online"] / 3600, 1),
                    "share": round(100 * v["bytes"] / total, 1) if total else 0} for k, v in grp.items()],
                  key=lambda x: -x["bytes"])


def _pct_change(cur, prev):
    if not prev:
        return None
    return round(100.0 * (cur - prev) / prev, 1)


def _samples_total(db, start, end, ids):
    q = db.query(func.coalesce(func.sum(SpeedSample.d_in + SpeedSample.d_out), 0)).filter(
        SpeedSample.ts >= start, SpeedSample.ts < end)
    if ids is not None:
        q = q.filter(SpeedSample.user_id.in_(ids))
    return int(q.scalar() or 0)


def _sessions(db, start, end, ids):
    q = db.query(AcctSession).filter(AcctSession.start_time < end,
                                     or_(AcctSession.stop_time.is_(None), AcctSession.stop_time >= start))
    if ids is not None:
        q = q.filter(AcctSession.user_id.in_(ids))
    return q.all()


def _online(s, start, end):
    stop = s.stop_time or s.last_update or now()
    return _overlap(s.start_time, stop, start, end)


def management(db, start: datetime, end: datetime, ids=None):
    """ids: list of user ids the report covers (None = everybody)."""
    rules = work_rules(db)
    span = end - start
    prev_start = start - span

    total = _samples_total(db, start, end, ids)
    prev_total = _samples_total(db, prev_start, start, ids)
    sessions = _sessions(db, start, end, ids)
    prev_sessions = _sessions(db, prev_start, start, ids)
    online = sum(_online(s, start, end) for s in sessions)
    prev_online = sum(_online(s, prev_start, start) for s in prev_sessions)
    active_users = {s.user_id for s in sessions if s.user_id}
    prev_active = {s.user_id for s in prev_sessions if s.user_id}

    # hourly buckets -> daily trend, peak hour, work / non-work split
    q = db.query(func.date(SpeedSample.ts), extract("hour", SpeedSample.ts),
                 func.sum(SpeedSample.d_in), func.sum(SpeedSample.d_out)) \
        .filter(SpeedSample.ts >= start, SpeedSample.ts < end)
    if ids is not None:
        q = q.filter(SpeedSample.user_id.in_(ids))
    daily, by_hour = defaultdict(lambda: [0, 0]), [0] * 24
    work_bytes = off_bytes = 0
    for d, h, i, o in q.group_by(func.date(SpeedSample.ts), extract("hour", SpeedSample.ts)).all():
        day = datetime.strptime(str(d)[:10], "%Y-%m-%d").date()
        b = int(i or 0) + int(o or 0)
        daily[day][0] += int(o or 0)
        daily[day][1] += int(i or 0)
        by_hour[int(h)] += b
        if is_work(rules, day, h):
            work_bytes += b
        else:
            off_bytes += b
    split = split_usage(db, start, end, ids)
    split_day = {d["day"]: d for d in split["daily"]}
    daily_rows = []
    for d, v in sorted(daily.items()):
        sd = split_day.get(d.isoformat(), {})
        internal, tunnel, internet = parts(v[0] + v[1], sd.get("internal"), sd.get("tunnel"))
        daily_rows.append({"day": d, "down": v[0], "up": v[1], "total": v[0] + v[1], "internal": internal,
                           "tunnel": tunnel, "internet": internet})
    peak_hour = max(range(24), key=lambda h: by_hour[h]) if any(by_hour) else None
    peak_day = max(daily_rows, key=lambda r: r["total"]) if daily_rows else None

    # per user bytes
    q = db.query(SpeedSample.user_id, func.sum(SpeedSample.d_in), func.sum(SpeedSample.d_out)).filter(
        SpeedSample.ts >= start, SpeedSample.ts < end)
    if ids is not None:
        q = q.filter(SpeedSample.user_id.in_(ids))
    per_user = {uid: (int(i or 0), int(o or 0)) for uid, i, o in q.group_by(SpeedSample.user_id).all() if uid}
    users = {u.id: u for u in db.query(User).filter(User.id.in_(list(per_user) + list(active_users) or [-1]))}
    groups, offices, depts = _names(db)
    online_by_user = defaultdict(float)
    for s in sessions:
        if s.user_id:
            online_by_user[s.user_id] += _online(s, start, end)

    # categories (NetFlow) incl. per-user and work-hours split
    q = db.query(TrafficCategory.user_id, TrafficCategory.day, TrafficCategory.hour, TrafficCategory.category,
                 TrafficCategory.bytes_down + TrafficCategory.bytes_up) \
        .filter(TrafficCategory.day >= start.date(), TrafficCategory.day <= (end - timedelta(seconds=1)).date())
    if ids is not None:
        q = q.filter(TrafficCategory.user_id.in_(ids))
    cat_total, cat_work = defaultdict(int), defaultdict(int)
    user_cat = defaultdict(lambda: defaultdict(int))
    user_leisure_work = defaultdict(int)
    flow_total = flow_work = 0
    for uid, day, hour, cat, b in q.all():
        b = int(b or 0)
        cat_total[cat] += b
        flow_total += b
        user_cat[uid][cat] += b
        if is_work(rules, day, hour):
            cat_work[cat] += b
            flow_work += b
            if cat in LEISURE:
                user_leisure_work[uid] += b
    cat_sum = sum(cat_total.values()) or 1
    categories = sorted([{"key": c, "name": CATEGORIES.get(c, c), "bytes": v, "pct": round(100 * v / cat_sum, 1),
                          "work": cat_work[c]} for c, v in cat_total.items()], key=lambda x: -x["bytes"])
    leisure_work = sum(v for c, v in cat_work.items() if c in LEISURE)

    top_users = []
    for uid, (i, o) in sorted(per_user.items(), key=lambda x: -(x[1][0] + x[1][1])):
        u = users.get(uid)
        cats = user_cat.get(uid, {})
        top_cat = max(cats, key=cats.get) if cats else ""
        utotal = sum(cats.values())
        su = split["users"].get(uid, {})
        internal, tunnel, internet = parts(i + o, su.get("internal"), su.get("tunnel"))
        top_users.append({
            "internal": internal, "tunnel": tunnel, "internet": internet,
            "user_id": uid, "username": u.username if u else "?", "full_name": u.full_name if u else "",
            "group": groups.get(u.group_id, "") if u else "",
            "office": offices.get(u.office_id, "") if u else "", "department": depts.get(u.department_id, "") if u else "",
            "down": o, "up": i, "total": i + o,
            "share": round(100 * (i + o) / total, 1) if total else 0, "online_h": round(online_by_user[uid] / 3600, 1),
            "top_category": CATEGORIES.get(top_cat, top_cat),
            "leisure_work_pct": round(100 * user_leisure_work[uid] / utotal, 1) if utotal else None,
        })

    missing = {r["user_id"] for r in split["user_daily"]} - set(users)
    if missing:
        users.update({u.id: u for u in db.query(User).filter(User.id.in_(list(missing)))})
    for r in split["user_daily"]:
        u = users.get(r["user_id"])
        r.update({"username": u.username if u else "?", "full_name": u.full_name if u else "",
                  "office": offices.get(u.office_id, "") if u else "",
                  "department": depts.get(u.department_id, "") if u else ""})

    by_group = _breakdown(per_user, online_by_user, users, "group_id", groups, total)
    by_office = _breakdown(per_user, online_by_user, users, "office_id", offices, total)
    by_department = _breakdown(per_user, online_by_user, users, "department_id", depts, total)

    # devices & services
    dev, svc = defaultdict(lambda: [0, 0, set()]), defaultdict(lambda: [0, 0])
    for s in sessions:
        k = TYPE_FA.get(s.device_type or "", s.device_type)
        dev[k][0] += 1
        dev[k][1] += (s.bytes_in or 0) + (s.bytes_out or 0)
        if s.user_id:
            dev[k][2].add(s.user_id)
        svc["هات‌اسپات" if s.service == "hotspot" else "VPN"][0] += 1
        svc["هات‌اسپات" if s.service == "hotspot" else "VPN"][1] += (s.bytes_in or 0) + (s.bytes_out or 0)
    devices = sorted([{"name": k, "sessions": v[0], "bytes": v[1], "users": len(v[2])} for k, v in dev.items()],
                     key=lambda x: -x["sessions"])
    services = [{"name": k, "sessions": v[0], "bytes": v[1]} for k, v in svc.items()]

    # policy events (rejected logins)
    q = db.query(AuthLog.reason, func.count(AuthLog.id), func.count(func.distinct(AuthLog.username))).filter(
        AuthLog.ts >= start, AuthLog.ts < end, AuthLog.result == "reject")
    qq = db.query(AuthLog.username, func.count(AuthLog.id)).filter(
        AuthLog.ts >= start, AuthLog.ts < end, AuthLog.reason.like("%حجم%"))
    if ids is not None:
        names = [u for (u,) in db.query(User.username).filter(User.id.in_(ids))] or ["-"]
        q = q.filter(AuthLog.username.in_(names))
        qq = qq.filter(AuthLog.username.in_(names))
    rejects = [{"reason": r or "-", "count": c, "users": n} for r, c, n in
               q.group_by(AuthLog.reason).order_by(func.count(AuthLog.id).desc()).all()]
    quota_users = list(qq.group_by(AuthLog.username).all())

    q = db.query(TrafficDomain.domain, TrafficDomain.category,
                 func.sum(TrafficDomain.bytes_down + TrafficDomain.bytes_up),
                 func.count(func.distinct(TrafficDomain.user_id))) \
        .filter(TrafficDomain.day >= start.date(), TrafficDomain.day <= (end - timedelta(seconds=1)).date())
    if ids is not None:
        q = q.filter(TrafficDomain.user_id.in_(ids))
    domains = [{"domain": d, "category": CATEGORIES.get(c, c), "bytes": int(b or 0), "users": n} for d, c, b, n in
               q.group_by(TrafficDomain.domain, TrafficDomain.category)
               .order_by(func.sum(TrafficDomain.bytes_down + TrafficDomain.bytes_up).desc()).limit(20).all()]

    return {
        "start": start, "end": end, "prev_start": prev_start,
        "work_hours": get_setting(db, "work_hours", DEFAULT_WORK_HOURS) or DEFAULT_WORK_HOURS,
        "kpi": {
            "total": total, "prev_total": prev_total, "total_change": _pct_change(total, prev_total),
            **dict(zip(("internal", "tunnel", "internet"), parts(total, split["internal"], split["tunnel"]))),
            "internet_pct": round(100 * parts(total, split["internal"], split["tunnel"])[2] / total, 1) if total else 0,
            "users": len(active_users), "prev_users": len(prev_active),
            "users_change": _pct_change(len(active_users), len(prev_active)),
            "online_h": round(online / 3600, 1), "online_change": _pct_change(online, prev_online),
            "per_user": total // max(1, len(active_users)),
            "online_per_user_h": round(online / 3600 / max(1, len(active_users)), 1),
            "sessions": len(sessions),
            "work_bytes": work_bytes, "off_bytes": off_bytes,
            "work_pct": round(100 * work_bytes / total, 1) if total else 0,
            "leisure_work": leisure_work,
            "leisure_work_pct": round(100 * leisure_work / flow_work, 1) if flow_work else None,
            "peak_hour": peak_hour, "peak_day": peak_day,
            "rejects": sum(r["count"] for r in rejects), "quota_users": len(quota_users),
        },
        "daily": daily_rows, "by_hour": by_hour, "categories": categories, "top_users": top_users,
        "by_group": by_group, "by_office": by_office if offices else [],
        "by_department": by_department if depts else [], "devices": devices, "services": services, "rejects": rejects,
        "quota_users": quota_users, "domains": domains, "has_flow": bool(flow_total),
        "user_daily": split["user_daily"],
    }


def attendance(db, start: datetime, end: datetime, ids=None):
    """Per user per day: first connection, last disconnection, online time (merged), inside/outside work hours."""
    rules = work_rules(db)
    sessions = _sessions(db, start, end, ids)
    intervals = defaultdict(list)          # (uid, day) -> [(a, b)]
    for s in sessions:
        if not s.user_id:
            continue
        a, b = max(s.start_time, start), min(s.stop_time or s.last_update or now(), end)
        while a < b:
            day_end = datetime(a.year, a.month, a.day) + timedelta(days=1)
            seg_end = min(b, day_end)
            intervals[(s.user_id, a.date())].append((a, seg_end, s))
            a = seg_end
    q = db.query(SpeedSample.user_id, func.date(SpeedSample.ts), func.sum(SpeedSample.d_in + SpeedSample.d_out)) \
        .filter(SpeedSample.ts >= start, SpeedSample.ts < end)
    if ids is not None:
        q = q.filter(SpeedSample.user_id.in_(ids))
    usage = {(uid, str(d)[:10]): int(b or 0) for uid, d, b in
             q.group_by(SpeedSample.user_id, func.date(SpeedSample.ts)).all()}
    users = {u.id: u for u in db.query(User).filter(User.id.in_([k[0] for k in intervals] or [-1]))}
    groups, offices, depts = _names(db)
    split = {(r["user_id"], r["day"]): r for r in split_usage(db, start, end, ids)["user_daily"]}
    rows = []
    for (uid, day), segs in intervals.items():
        segs.sort(key=lambda x: x[0])
        merged = []
        for a, b, _ in segs:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        total = sum((b - a).total_seconds() for a, b in merged)
        windows = work_windows(rules, day)
        inside = sum(_overlap(a, b, w1, w2) for a, b in merged for w1, w2 in windows)
        u = users.get(uid)
        services = {("هات‌اسپات" if s.service == "hotspot" else "VPN") for _, _, s in segs}
        device_types = {TYPE_FA.get(s.device_type or "", "") for _, _, s in segs if s.device_type}
        rows.append({
            "user_id": uid, "username": u.username if u else "?", "full_name": u.full_name if u else "",
            "group": groups.get(u.group_id, "") if u else "", "day": day,
            "office": offices.get(u.office_id, "") if u else "", "department": depts.get(u.department_id, "") if u else "",
            "personnel_code": u.personnel_code if u else "",
            "first": merged[0][0], "last": merged[-1][1],
            "still_online": any(s.active and s.stop_time is None for _, _, s in segs) and day == now().date(),
            "online": int(total), "inside": int(inside), "outside": int(total - inside), "sessions": len(segs),
            "bytes": usage.get((uid, day.isoformat()), 0), "services": "، ".join(sorted(services)),
            **dict(zip(("internal", "tunnel", "internet"),
                       parts(usage.get((uid, day.isoformat()), 0), split.get((uid, day.isoformat()), {}).get("internal"),
                             split.get((uid, day.isoformat()), {}).get("tunnel")))),
            "devices": "، ".join(sorted(d for d in device_types if d)),
            "work_day": bool(windows),
        })
    rows.sort(key=lambda r: (r["day"], r["first"]), reverse=True)     # newest first
    return rows


def router_internet(db, start: datetime, end: datetime, nas_list):
    """Exact router volumes from interface counters (independent of users and hotspot):
    internet = bytes on the WAN interfaces; tunnel = bytes on the tunnel interfaces (their carrier also crosses
    the WAN); internet without tunnel = the difference."""
    from . import ifstats, netscope
    from .db import IfaceDaily
    d1, d2 = start.date(), (end - timedelta(seconds=1)).date()
    rows, tot = [], {"wan_rx": 0, "wan_tx": 0, "tun_rx": 0, "tun_tx": 0, "wan": 0, "tunnel": 0, "pure": 0}
    for nas in nas_list:
        wan, _ = ifstats.roles(nas)
        tun = netscope.split_names(nas.tunnel_interfaces) or netscope.split_names(nas.auto_tunnels or "")
        vals = {"wan_rx": 0, "wan_tx": 0, "tun_rx": 0, "tun_tx": 0}
        names = set(wan) | set(tun)
        if names:
            for r in db.query(IfaceDaily).filter(IfaceDaily.nas_id == nas.id, IfaceDaily.iface.in_(names),
                                                 IfaceDaily.day >= d1, IfaceDaily.day <= d2):
                if r.iface in wan:
                    vals["wan_rx"] += r.rx or 0
                    vals["wan_tx"] += r.tx or 0
                elif r.iface in tun:
                    vals["tun_rx"] += r.rx or 0
                    vals["tun_tx"] += r.tx or 0
        vals["wan"] = vals["wan_rx"] + vals["wan_tx"]
        vals["tunnel"] = vals["tun_rx"] + vals["tun_tx"]
        vals["pure"] = max(0, vals["wan"] - vals["tunnel"])
        rows.append({"nas": nas, "name": nas.name, "wan_ifs": wan, "tun_ifs": tun, **vals})
        for k in tot:
            tot[k] += vals[k]
    return {"rows": rows, "total": tot, "configured": any(r["wan_ifs"] for r in rows)}
