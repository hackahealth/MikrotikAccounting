"""ترافیک اینترفیس‌های روتر: شمارنده‌های /interface در هر بار خواندن API (حدود هر دقیقه) به اختلاف تبدیل و
برای گراف سرعت لحظه‌ای و حجم مصرف (امروز روی دیروز) ذخیره می‌شود."""
import threading
from datetime import datetime, timedelta

from . import netscope
from .db import IfaceDaily, IfaceSample, now

# dynamic per-user interfaces (VPN server side) are not graphed
SKIP_TYPES = ("pptp-in", "l2tp-in", "sstp-in", "ovpn-in", "pppoe-in")
MAX_IFACES = 64
_last = {}          # (nas_id, iface) -> (rx_byte, tx_byte, ts)
_lock = threading.Lock()


def _yes(v):
    return str(v).lower() in ("true", "yes")


def _counter(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def graphable(interfaces):
    out = []
    for i in interfaces:
        name = str(i.get("name") or "")
        if not name or _yes(i.get("dynamic")) or str(i.get("type", "")).startswith(SKIP_TYPES):
            continue
        rx, tx = _counter(i.get("rx-byte")), _counter(i.get("tx-byte"))
        if rx is None or tx is None:
            continue
        out.append((name[:64], rx, tx))
    return out[:MAX_IFACES]


def record(db, nas_id, interfaces, ts):
    """Counter deltas since the previous poll -> IfaceSample + IfaceDaily. Returns rows written."""
    n = 0
    with _lock:
        for name, rx, tx in graphable(interfaces):
            key = (nas_id, name)
            prev = _last.get(key)
            _last[key] = (rx, tx, ts)
            if prev is None:
                continue
            seconds = int((ts - prev[2]).total_seconds())
            d_rx, d_tx = rx - prev[0], tx - prev[1]
            if seconds <= 0 or d_rx < 0 or d_tx < 0:       # router reboot / counters reset
                continue
            db.add(IfaceSample(nas_id=nas_id, iface=name, ts=ts, seconds=seconds, rx=d_rx, tx=d_tx))
            day = db.query(IfaceDaily).filter(IfaceDaily.nas_id == nas_id, IfaceDaily.iface == name,
                                              IfaceDaily.day == ts.date()).first()
            if day is None:
                db.add(IfaceDaily(nas_id=nas_id, iface=name, day=ts.date(), rx=d_rx, tx=d_tx))
            else:
                day.rx += d_rx
                day.tx += d_tx
            n += 1
    return n


def interfaces_of(db, nas_id, since_days=14):
    """Interface names with recorded traffic (newest data first is not needed: sorted by name)."""
    since = now().date() - timedelta(days=since_days)
    return sorted({i for (i,) in db.query(IfaceDaily.iface).filter(IfaceDaily.nas_id == nas_id,
                                                                     IfaceDaily.day >= since).distinct()})


def roles(nas):
    """(wan interface names, lan interface names) chosen on the router form."""
    wan = [w for w in netscope.split_names(nas.wan_interfaces) if not w.isdigit()]
    lan = netscope.split_names(nas.lan_interfaces)
    return wan, lan


def day_series(db, nas_id, ifaces, day):
    """Per minute of `day`: rx/tx speed (bit/s, summed over the interfaces; None where no data) and bytes."""
    start = datetime.combine(day, datetime.min.time())
    rx_b, tx_b = [0] * 1440, [0] * 1440
    rx_s, tx_s = [None] * 1440, [None] * 1440
    per = {}            # (iface, minute) -> [rx, tx, seconds]
    if ifaces:
        for s in db.query(IfaceSample).filter(IfaceSample.nas_id == nas_id, IfaceSample.iface.in_(ifaces),
                                              IfaceSample.ts >= start, IfaceSample.ts < start + timedelta(days=1)):
            m = min(1439, int((s.ts - start).total_seconds() // 60))
            e = per.setdefault((s.iface, m), [0, 0, 0])
            e[0] += s.rx
            e[1] += s.tx
            e[2] += s.seconds
    for (_, m), (rx, tx, sec) in per.items():
        rx_b[m] += rx
        tx_b[m] += tx
        if sec:
            rx_s[m] = (rx_s[m] or 0) + rx * 8 / sec
            tx_s[m] = (tx_s[m] or 0) + tx * 8 / sec
    return {"rx_bps": [round(v) if v is not None else None for v in rx_s],
            "tx_bps": [round(v) if v is not None else None for v in tx_s],
            "rx_bytes": rx_b, "tx_bytes": tx_b}


def day_totals(db, nas_id, ifaces, day):
    rx = tx = 0
    if ifaces:
        for r in db.query(IfaceDaily).filter(IfaceDaily.nas_id == nas_id, IfaceDaily.iface.in_(ifaces),
                                             IfaceDaily.day == day):
            rx += r.rx or 0
            tx += r.tx or 0
    return rx, tx


def wire_size(snap) -> int:
    """Approximate bytes one API poll moves over the link (RouterOS API words '=key=value' + framing + TCP/IP)."""
    total = 0
    for v in snap.values():
        if isinstance(v, list):
            for row in v:
                total += 8 + sum(len(str(k)) + len(str(x)) + 4 for k, x in row.items())
        else:
            total += len(str(v)) + 8
    return int(total * 1.06) + 2000          # TCP/IP headers, login and the requests themselves


def cleanup(db, days):
    db.query(IfaceSample).filter(IfaceSample.ts < now() - timedelta(days=days)).delete()
