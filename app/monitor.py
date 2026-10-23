"""پایش روترها و تانل‌ها (فقط مدیر سیستم و کارشناس IT): در هر بار خواندن API، در دسترس بودن روتر، وضعیت اینترفیس‌های
تانل و ping از روتر به مقصدهای تعیین‌شده (مثلاً سرور دفتر مرکزی از راه تانل) بررسی و تغییر وضعیت‌ها ثبت و اعلان می‌شود."""
import re
import threading
from datetime import timedelta

from . import alerts, netscope, routeros
from .db import NetEvent, get_setting, now

STATE_FA = {"up": "وصل", "down": "قطع", "slow": "کند"}
CONFIRM = 2                 # a bad state is believed after this many polls in a row
_pending = {}               # (nas_id, target) -> (state, count)
_lock = threading.Lock()


def _ms(v):
    """RouterOS durations: '12ms', '1ms345us', '1s5ms', '850us' -> milliseconds."""
    total = 0.0
    for num, unit in re.findall(r"([\d.]+)(ms|us|s|m)", str(v or "")):
        total += float(num) * {"ms": 1, "us": 0.001, "s": 1000, "m": 60000}[unit]
    return total


def ping_summary(replies):
    """(packet loss %, average rtt ms or None, error text)."""
    if not replies:
        return 100, None, "پاسخی نیامد"
    if replies[-1].get("error"):
        return 100, None, replies[-1]["error"]
    last = next((r for r in reversed(replies) if "packet-loss" in r), None)
    if last is not None:
        loss = int(str(last.get("packet-loss", "100")).rstrip("%") or 100)
        avg = _ms(last.get("avg-rtt")) if last.get("avg-rtt") not in (None, "") else None
        return loss, (avg if loss < 100 else None), ""
    times = [_ms(r["time"]) for r in replies if r.get("time")]
    loss = round(100 * (len(replies) - len(times)) / len(replies))
    return loss, (sum(times) / len(times) if times else None), ""


def slow_ms(db):
    try:
        return max(1, int(get_setting(db, "monitor_slow_ms", "150") or 150))
    except ValueError:
        return 150


def auto_tunnels(interfaces):
    return [str(i.get("name")) for i in interfaces if str(i.get("type", "")).lower() in netscope.TUNNEL_TYPES
            and not routeros._yes(i.get("dynamic")) and i.get("name")]


def tunnel_names(nas, interfaces):
    return netscope.split_names(nas.tunnel_interfaces) or auto_tunnels(interfaces)


def observe(db, nas, ok, snap=None, error=""):
    """One poll of a router -> states of its targets ('router', 'tunnel:<iface>', 'ping:<address>')."""
    states = {"router": ("up" if ok else "down", "" if ok else str(error)[:200])}
    if ok and snap is not None:
        ifaces = {str(i.get("name")): i for i in snap.get("interfaces", [])}
        auto = ",".join(auto_tunnels(snap.get("interfaces", [])))[:300]
        if (nas.auto_tunnels or "") != auto:
            nas.auto_tunnels = auto
        for name in tunnel_names(nas, snap.get("interfaces", [])):
            i = ifaces.get(name)
            if i is None:
                states[f"tunnel:{name}"] = ("down", "اینترفیس روی روتر نیست")
            elif routeros._yes(i.get("disabled")):
                continue
            else:
                states[f"tunnel:{name}"] = ("up" if routeros._yes(i.get("running")) else "down",
                                           "" if routeros._yes(i.get("running")) else "اینترفیس running نیست")
        limit = slow_ms(db)
        for target, replies in (snap.get("pings") or {}).items():
            loss, avg, err = ping_summary(replies)
            detail = err or (f"میانگین {avg:.0f} ms، از دست رفته {loss}%" if avg is not None else f"از دست رفته {loss}%")
            state = "down" if loss >= 100 else ("slow" if (avg or 0) > limit or loss >= 30 else "up")
            states[f"ping:{target}"] = (state, detail)
    elif not ok:
        # router unreachable: its tunnels / pings are unknown, not down
        pass
    for target, (state, detail) in states.items():
        _set(db, nas, target, state, detail)
    return states


def _label(nas, target):
    if target == "router":
        return f"روتر {nas.name}"
    kind, name = target.split(":", 1)
    return f"{'تانل' if kind == 'tunnel' else 'ping به'} {name} در روتر {nas.name}"


def _set(db, nas, target, state, detail):
    key = (nas.id, target)
    cur = db.query(NetEvent).filter(NetEvent.nas_id == nas.id, NetEvent.target == target,
                                    NetEvent.ended_at.is_(None)).order_by(NetEvent.ts.desc()).first()
    with _lock:
        if cur is not None and cur.state == state:
            _pending.pop(key, None)
            cur.detail = detail or cur.detail
            return
        if state != "up" and cur is not None:
            st, n = _pending.get(key, (state, 0))
            n = n + 1 if st == state else 1
            _pending[key] = (state, n)
            if n < CONFIRM:
                return
        _pending.pop(key, None)
    t = now()
    if cur is not None:
        cur.ended_at = t
    db.add(NetEvent(nas_id=nas.id, target=target, state=state, detail=detail, ts=t))
    if state in ("down", "slow"):
        alerts.add(db, "monitor", f"{STATE_FA[state]}: {_label(nas, target)}", detail, "err" if state == "down" else "warn",
                   "/monitor")
    elif cur is not None and cur.state in ("down", "slow"):
        mins = int((t - cur.ts).total_seconds() // 60)
        alerts.add(db, "monitor", f"دوباره وصل: {_label(nas, target)}", f"بعد از {mins} دقیقه {STATE_FA[cur.state]}",
                   "info", "/monitor")


def overview(db, nas_list, days=7):
    """Current state and availability of the last days for every target of every router."""
    since = now() - timedelta(days=days)
    t = now()
    out = []
    for nas in nas_list:
        evs = db.query(NetEvent).filter(NetEvent.nas_id == nas.id,
                                        (NetEvent.ended_at.is_(None)) | (NetEvent.ended_at >= since)) \
            .order_by(NetEvent.ts).all()
        targets = {}
        for e in evs:
            r = targets.setdefault(e.target, {"target": e.target, "label": _label(nas, e.target), "state": None,
                                              "since": None, "detail": "", "bad": 0.0, "span": 0.0, "events": 0})
            a, b = max(e.ts, since), (e.ended_at or t)
            secs = max(0.0, (b - a).total_seconds())
            r["span"] += secs
            if e.state != "up":
                r["bad"] += secs
                r["events"] += 1
            if e.ended_at is None:
                r["state"], r["since"], r["detail"] = e.state, e.ts, e.detail
        for r in targets.values():
            r["availability"] = round(100 * (1 - r["bad"] / r["span"]), 2) if r["span"] else None
        order = sorted(targets.values(), key=lambda r: (r["target"] != "router", r["target"]))
        out.append({"nas": nas, "targets": order})
    return out
