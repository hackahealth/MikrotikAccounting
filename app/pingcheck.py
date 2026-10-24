"""Second check of the devices shown online: the router itself pings each one (ARP ping on the LAN interface, which
answers even when the Windows firewall drops ICMP, and a normal ping). A device that answers neither is no longer
taken as online from weak signs (a static ARP entry, an old hotspot host) until it is seen again for sure."""
import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from . import config, routeros
from .db import Device, Nas, SessionLocal, get_setting, now

log = logging.getLogger("pingcheck")
DEAD = {}               # mac -> time the device failed the ping check (cleared by a strong sign or a reply)
_lock = threading.Lock()
WORKERS = 6
state = {"last": None, "checked": 0, "dead": 0, "by_router": {}}


def minutes(db) -> int:
    try:
        return max(0, int(get_setting(db, "ping_verify_minutes", "5") or 0))
    except ValueError:
        return 5


def is_dead(mac) -> bool:
    return mac in DEAD


def alive(mac):
    with _lock:
        DEAD.pop(mac, None)


def _iface_for(ip, addresses):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    best = None
    for r in addresses:
        if routeros._yes(r.get("disabled")) or not r.get("interface"):
            continue
        try:
            net = ipaddress.ip_interface(str(r.get("address", ""))).network
        except ValueError:
            continue
        if a.version == net.version and a in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, str(r["interface"]))
    return best[1] if best else ""


def _answered(rows) -> bool:
    for r in rows:
        try:
            if int(r.get("received", 0) or 0) > 0:
                return True
        except (TypeError, ValueError):
            pass
        if r.get("time") and not r.get("status"):
            return True
    return False


def ping_one(conn, ip, iface):
    """True when the device answers an ARP ping (same LAN) or an ICMP ping."""
    if iface:
        try:
            if _answered([dict(r) for r in conn("/ping", **{"address": ip, "count": "2", "interval": "0.3",
                                                             "arp-ping": "yes", "interface": iface})]):
                return True
        except Exception as e:    # noqa: BLE001 - old RouterOS without arp-ping
            log.debug("arp-ping %s: %s", ip, e)
    try:
        return _answered([dict(r) for r in conn("/ping", **{"address": ip, "count": "2", "interval": "0.3"})])
    except Exception as e:        # noqa: BLE001
        log.debug("ping %s: %s", ip, e)
        return False


def check_router(nas, targets):
    """targets: [(mac, ip)] -> {mac: answered}"""
    if not targets:
        return {}
    conn = routeros.api(nas)
    try:
        addresses = routeros._list(conn, "ip", "address")
    finally:
        conn.close()
    chunks = [targets[i::WORKERS] for i in range(WORKERS)]

    def run(chunk):
        out = {}
        if not chunk:
            return out
        c = routeros.api(nas)
        try:
            for mac, ip in chunk:
                out[mac] = ping_one(c, ip, _iface_for(ip, addresses))
        finally:
            c.close()
        return out
    res = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for part in ex.map(run, chunks):
            res.update(part)
    return res


def kick(db, nas, macs):
    """Disconnects the hotspot logins of devices that answer no ping (left on after the computer was turned off)."""
    from . import devices
    from .db import AcctSession
    if not macs:
        return 0
    n = 0
    for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.service == "hotspot",
                                          AcctSession.mac != "").all():
        if devices.normalize_mac(s.mac) in macs and s.nas_ip in (nas.ip, nas.api_host, "0.0.0.0"):
            try:
                if routeros.disconnect(nas, s.username, s.service, s.acct_session_id, s.framed_ip):
                    n += 1
            except Exception as e:      # noqa: BLE001
                log.warning("kick %s: %s", s.username, e)
    if n:
        log.info("%s: %s hotspot logins of silent devices disconnected", nas.name, n)
    return n


def run_once():
    db = SessionLocal()
    try:
        ts = now()
        since = ts - timedelta(seconds=config.ROUTER_POLL_EVERY * 3 + 60)
        routers = {n.id: n for n in db.query(Nas).filter(Nas.api_user != "").all()}
        by_nas = {}
        for d in db.query(Device).filter(Device.last_seen >= since, Device.last_ip != "").all():
            if d.last_nas_id in routers:
                by_nas.setdefault(d.last_nas_id, []).append((d.mac, d.last_ip))
        checked = dead = 0
        per = {}
        for nid, targets in by_nas.items():
            try:
                res = check_router(routers[nid], targets)
            except Exception as e:      # noqa: BLE001
                per[routers[nid].name] = f"خطا: {e}"[:150]
                continue
            ok = sum(1 for v in res.values() if v)
            per[routers[nid].name] = f"{ok} از {len(res)} پاسخ دادند"
            with _lock:
                for mac, answered in res.items():
                    if answered:
                        DEAD.pop(mac, None)
                    else:
                        DEAD.setdefault(mac, ts)
            for d in db.query(Device).filter(Device.mac.in_(list(res))):
                d.ping_ok, d.ping_at = res[d.mac], ts
            db.commit()
            if get_setting(db, "ping_kick", "0") == "1":
                kick(db, routers[nid], {m for m, v in res.items() if not v})
            checked += len(res)
            dead += len(res) - ok
        state.update(last=ts, checked=checked, dead=dead, by_router=per)
    finally:
        db.close()
        SessionLocal.remove()


def job():
    """Own thread: the pings of all devices take a while and must not hold up the router polls."""
    while True:
        db = SessionLocal()
        try:
            m = minutes(db)
        finally:
            db.close()
            SessionLocal.remove()
        time.sleep(max(1, m or 5) * 60)
        if m:
            try:
                run_once()
            except Exception:           # noqa: BLE001
                log.exception("ping check failed")


def online_filter(q, ts):
    """Devices online now: seen in the last polls and not failing the ping check since."""
    q = q.filter(Device.last_seen >= ts - timedelta(seconds=config.ROUTER_POLL_EVERY * 3 + 60))
    return q.filter((Device.ping_ok.isnot(False)) | (Device.ping_at.is_(None)) | (Device.last_seen > Device.ping_at))
