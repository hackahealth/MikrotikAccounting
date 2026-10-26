"""کارهای پس‌زمینه: اعمال سیاست (قطع خودکار)، دریافت اطلاعات از روتر، همگام‌سازی AD، پاکسازی."""
import json
import logging
import threading
import time
from datetime import timedelta

from . import (access, quotamsg, apisessions, classifier, config, devices, grants, ifstats, ldap_ad, logons, monitor,
               netscope, nightlist, pbx, pingcheck, policy, retention, routeros, security, wancheck)
from .db import AcctSession, Nas, SessionLocal, User, get_setting, now

log = logging.getLogger("jobs")

live = {"rates": {}, "routers": {}, "updated": None, "api_bytes": {}}   # rates: ip -> (up_bps, down_bps); api_bytes: nas id -> bytes per poll


def _parse_rate(v):
    try:
        up, down = str(v).split("/")
        return int(up), int(down)
    except Exception:
        return 0, 0


def enforce():
    """Disconnect users who passed their quota / allowed hours / expiry, close stale sessions."""
    db = SessionLocal()
    try:
        ts = now()
        stale = ts - timedelta(seconds=config.ACCT_INTERIM * 3 + 300)
        for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.last_update < stale):
            s.active, s.stop_time, s.terminate_cause = False, s.last_update, "Stale"
        db.commit()
        nas_by_ip = {}
        for n in db.query(Nas).all():
            nas_by_ip.setdefault(n.ip, n)
            if n.api_host:
                nas_by_ip.setdefault(n.api_host, n)
        for s in db.query(AcctSession).filter(AcctSession.active.is_(True)).all():
            user = db.get(User, s.user_id) if s.user_id else None
            if user is None or s.service == "proxy":          # the proxy cuts its own users
                continue
            eff = policy.Effective(user)
            reason = ""
            if not user.enabled:
                reason = "disabled"
            elif security.locked(db, user.username, s.mac or ""):
                reason = "locked"
            elif user.expire_at and ts.date() > user.expire_at:
                reason = "expired"
            else:
                try:
                    rules = policy.parse_hours(eff.allowed_hours)
                except ValueError:
                    rules = None
                if not policy.hours_allowed(rules, ts) and not grants.active(db, user.id, "hours", ts):
                    reason = "hours"
                else:
                    q, used, rem = policy.quota_state(db, user, eff)
                    if q is not None and rem <= 0 and not grants.active(db, user.id, "internet", ts):
                        reason = "quota"
            nas = nas_by_ip.get(s.nas_ip) or nas_by_ip.get("0.0.0.0")
            if reason and nas is not None:
                ok = routeros.disconnect(nas, s.username, s.service, s.acct_session_id, s.framed_ip)
                log.info("enforce: disconnect %s (%s) -> %s", s.username, reason, ok)
                if ok:
                    s.terminate_cause = f"Policy:{reason}"
        db.commit()
    finally:
        db.close()
        SessionLocal.remove()


def _arp_live(a) -> bool:
    """ARP entry that proves the device is on the network now (ROS7 'status', ROS6 'complete' flag of a dynamic
    entry). A static / DHCP-made ('permanent') entry stays when the device is off: only a weak sign."""
    if routeros._yes(a.get("disabled")) or routeros._yes(a.get("invalid")) or not a.get("mac-address"):
        return False
    status = str(a.get("status", "")).lower()
    if status:
        return status in ("reachable", "delay", "probe")
    return routeros._yes(a.get("complete", True)) and not routeros._yes(a.get("published")) \
        and routeros._yes(a.get("dynamic", True)) and not routeros._yes(a.get("DHCP"))


def _host_live(h) -> bool:
    """Hotspot host with traffic in the last polls (host-dead-time); old RouterOS without the field: weak sign."""
    v = h.get("host-dead-time")
    if v in (None, ""):
        return False
    return apisessions.uptime_seconds(v) <= config.ROUTER_POLL_EVERY * 3


def _record_devices(db, nas, snap, ts):
    """Device presence on this router: MAC -> IP / logged-in user, kept as history intervals.
    Strong signs (an active login, ARP reachable, recent traffic / DHCP) always count and clear a failed ping check;
    weak signs (hotspot host or static ARP entry only) count only while the device is not failing the ping check."""
    seen = {}

    def put(mac, ip="", user="", source="", host=None, strong=True):
        m = devices.normalize_mac(mac or "")
        if not m:
            return
        e = seen.setdefault(m, {"ips": {}, "users": {}, "host": None, "strong": False})
        e["strong"] = e["strong"] or strong
        if ip:
            e["ips"].setdefault(str(ip), source)
        if user:
            e["users"].setdefault(user, source)
        if host:
            e["host"] = host
    for a in snap.get("hotspot_active", []):    # a login whose device has been silent long (keepalive off): weak
        idle = a.get("idle-time")
        put(a.get("mac-address"), a.get("address"), a.get("user"), "hotspot",
            strong=idle in (None, "") or apisessions.uptime_seconds(idle) <= config.ROUTER_POLL_EVERY * 5)
    for h in snap.get("hotspot_hosts", []):
        put(h.get("mac-address"), h.get("address"), "", "host", h.get("host-name"), strong=_host_live(h))
    for p in snap.get("ppp_active", []):
        put(p.get("caller-id"), p.get("address"), p.get("name"), "ppp")
    for a in snap.get("arp", []):
        if _arp_live(a):
            put(a.get("mac-address"), a.get("address"), "", "arp")
    for lease in snap.get("leases", []):
        m = devices.normalize_mac(lease.get("mac-address", ""))
        bound = str(lease.get("status", "")).lower() == "bound"
        recent = apisessions.uptime_seconds(lease.get("last-seen")) <= config.ROUTER_POLL_EVERY * 3 \
            if lease.get("last-seen") not in (None, "", "never") else False
        if m and bound and (m in seen or recent):
            put(m, lease.get("active-address") or lease.get("address"), "", "dhcp", lease.get("host-name"), strong=recent)
    n = 0
    for m, e in seen.items():
        if e["strong"]:
            pingcheck.alive(m)
        elif pingcheck.is_dead(m):
            continue
        n += 1
        for ip, src in e["ips"].items():
            devices.record(db, m, ip=ip, nas_id=nas.id, source=src, ts=ts, hostname=e["host"])
        for user, src in e["users"].items():
            devices.record(db, m, user=user, nas_id=nas.id, source=src, ts=ts)
        if not e["ips"] and not e["users"]:
            devices.record(db, m, nas_id=nas.id, ts=ts, hostname=e["host"])
    return n


def poll_routers():
    db = SessionLocal()
    try:
        rates = {}
        ts = now()
        for nas in db.query(Nas).filter(Nas.api_user != "").all():
            try:
                snap = routeros.snapshot(nas)
            except Exception as e:
                live["routers"][nas.name] = f"خطا: {e}"
                log.warning("router %s poll failed: %s", nas.name, e)
                try:
                    monitor.observe(db, nas, False, error=e)
                    db.commit()
                except Exception:  # noqa: BLE001
                    db.rollback()
                    log.exception("monitor %s", nas.name)
                continue
            n_api, n_dev = 0, 0
            live["api_bytes"][nas.id] = ifstats.wire_size(snap)
            if snap.get("identity") and not nas.identifier:
                # RADIUS packets carry the identity as NAS-Identifier: tells routers behind one NAT address apart
                nas.identifier = str(snap["identity"])[:100]
                db.commit()
                from .radius_server import nas_cache
                nas_cache.invalidate()
            try:
                classifier.dns_map.update(snap["dns"])
                netscope.scope.learn(nas.id, snap.get("interfaces", []), snap.get("addresses", []))
                facts = json.dumps(wancheck.learn(nas, snap), ensure_ascii=False, sort_keys=True)
                if (nas.iface_facts or "") != facts:
                    nas.iface_facts = facts
                for lease in snap["leases"]:
                    if lease.get("mac-address"):
                        devices.upsert(db, lease["mac-address"], hostname=lease.get("host-name"),
                                       dhcp_class=lease.get("class-id"))
                for h in snap["hotspot_hosts"]:
                    if h.get("mac-address") and h.get("host-name"):
                        devices.upsert(db, h["mac-address"], hostname=h.get("host-name"))
                for q in snap["queues"]:
                    target = str(q.get("target", "")).split(",")[0].split("/")[0]
                    if target and "rate" in q:
                        rates[target] = _parse_rate(q["rate"])
                n_api = apisessions.sync(db, nas, snap, ts)
                n_dev = _record_devices(db, nas, snap, ts)
                ifstats.record(db, nas.id, snap.get("interfaces", []), ts)
                db.commit()
                try:
                    monitor.observe(db, nas, True, snap)
                    db.commit()
                except Exception:  # noqa: BLE001 - monitoring must not lose the poll
                    db.rollback()
                    log.exception("monitor %s", nas.name)
            except Exception as e:
                db.rollback()
                log.exception("router %s: session/device update failed", nas.name)
                live["routers"][nas.name] = f"خطا در پردازش اطلاعات روتر: {e}"
                continue
            live["routers"][nas.name] = (f"OK ({snap.get('identity', '')}) · {len(snap['hotspot_active'])} هات‌اسپات"
                                         f" · {len(snap['ppp_active'])} VPN · {n_dev} دستگاه"
                                         + (f" · {n_api} بدون Accounting" if n_api else ""))
        live["rates"], live["updated"] = rates, now()
        # devices of RADIUS sessions (also covers routers without API access)
        nas_ids = {}
        for n in db.query(Nas).all():
            nas_ids.setdefault(n.ip, n.id)
            if n.api_host:
                nas_ids.setdefault(n.api_host, n.id)
        stale = ts - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
        for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.last_update >= stale,
                                              AcctSession.mac != "").all():
            if devices.normalize_mac(s.mac):
                devices.record(db, s.mac, ip=s.framed_ip, user=s.username,
                               nas_id=nas_ids.get(s.nas_ip, nas_ids.get("0.0.0.0")),
                               source="api" if s.acct_session_id.startswith(apisessions.PREFIX) else "radius", ts=ts)
        db.commit()
        # refresh device type on active sessions
        from .db import Device
        for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.mac != "").all():
            d = db.query(Device).filter(Device.mac == s.mac).first()
            if d and (d.device_type != s.device_type or d.os != s.device_os):
                s.device_type, s.device_os = d.device_type, d.os
        db.commit()
    finally:
        db.close()
        SessionLocal.remove()


def ldap_job():
    db = SessionLocal()
    try:
        if ldap_ad.enabled(db) and get_setting(db, "ldap_auto_sync") == "1":
            ldap_ad.sync_users(db)
    except Exception as e:
        log.warning("AD sync failed: %s", e)
    finally:
        db.close()
        SessionLocal.remove()


def cleanup():
    db = SessionLocal()
    try:
        ifstats.cleanup(db, config.IFACE_SAMPLE_DAYS)
        db.commit()
        retention.auto(db)
    finally:
        db.close()
        SessionLocal.remove()


def _every(seconds, fn):
    def run():
        while True:
            try:
                fn()
            except Exception:
                log.exception("job %s failed", fn.__name__)
            time.sleep(seconds)
    threading.Thread(target=run, daemon=True, name=f"job-{fn.__name__}").start()


def start():
    _every(config.ENFORCE_EVERY, enforce)
    _every(config.ROUTER_POLL_EVERY, poll_routers)
    _every(config.LDAP_SYNC_EVERY, ldap_job)
    _every(config.PBX_SYNC_EVERY, pbx.sync_all)
    _every(config.LOGON_SYNC_EVERY, logons.sync_dcs)
    _every(60, nightlist.job)
    _every(60, access.job)
    _every(quotamsg.EVERY, quotamsg.job)
    threading.Thread(target=pingcheck.job, daemon=True, name="job-pingcheck").start()
    _every(86400, cleanup)
