"""Access control kept on the routers (RouterOS firewall, items commented 'macc', nothing else is touched):

- before login: the hotspot already lets nothing through; exempt devices (MAC / IP list, and devices of the chosen
  types such as IP phones) get a hotspot 'bypassed' binding and no limits;
- blocked sites (or, in allow-list mode, only the allowed sites) for everybody except exempt devices and users with an
  'internet' temporary grant (list macc-free); plain-HTTP requests to a blocked site get the block page of the panel;
- after login, hotspot users may reach only the internal destinations allowed for users (when that limit is on);
- sensitive internal objects (NVR, finance server ...): access from outside their allowed sources is caught by the
  router (address list macc-v<id>) and alarmed; with action 'block' it is also dropped.
"""
import ipaddress
import logging
import re
from datetime import timedelta
from urllib.parse import urlparse

from . import alerts, devices, grants, netscope, routeros
from .db import AccessExempt, AcctSession, Device, Nas, NetObject, SiteRule, get_setting, now

log = logging.getLogger("access")
TAG = "macc"
FREE = "macc-free"
DYNAMIC_LISTS = (FREE,)
VIOL_PREFIX = "macc-v"
DEFAULT_INTERNAL = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"


def tokens(text):
    out = []
    for line in (text or "").splitlines():
        out.extend(t for t in re.split(r"[\s,;]+", line.split("#", 1)[0]) if t)
    return out


def _is_addr(t):
    try:
        if "-" in t:
            a, b = t.split("-", 1)
            ipaddress.ip_address(a)
            ipaddress.ip_address(b)
        else:
            ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def clean_pattern(p):
    """'https://www.Example.com/x' -> 'example.com'; IP / CIDR kept. '' when not usable."""
    p = str(p or "").strip().lower()
    if not p:
        return ""
    if _is_addr(p):
        return p
    if "://" in p:
        p = urlparse(p).hostname or ""
    p = p.split("/")[0].split(":")[0].strip(".")
    if p.startswith("*."):
        p = p[2:]
    if p.startswith("www."):
        p = p[4:]
    return p if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", p) else ""


def settings(db):
    return {
        "sites_mode": get_setting(db, "acl_sites_mode", "block"),            # block | allow
        "internal_restrict": get_setting(db, "acl_internal_restrict", "0") == "1",
        "allowed_internal": get_setting(db, "acl_allowed_internal", ""),
        "exempt_types": [t for t in get_setting(db, "acl_exempt_types", "phone").split(",") if t],
        "block_page": get_setting(db, "acl_block_page", "1") == "1",
    }


def _panel_target(db):
    u = urlparse(get_setting(db, "public_url", "") or "")
    try:
        ipaddress.ip_address(u.hostname or "")
    except ValueError:
        return None
    return u.hostname, str(u.port or 80)


def blocked_domains(db):
    return [r.pattern for r in db.query(SiteRule).filter(SiteRule.enabled.is_(True), SiteRule.action == "block")
            if not _is_addr(r.pattern)]


_blocked_cache = {"ts": 0.0, "domains": []}


def is_blocked_host(db, host):
    import time
    host = (host or "").split(":")[0].lower().strip(".")
    if not host or _is_addr(host):
        return False
    if time.time() - _blocked_cache["ts"] > 30:
        _blocked_cache.update(ts=time.time(), domains=blocked_domains(db))
    return any(host == d or host.endswith("." + d) for d in _blocked_cache["domains"])


def invalidate():
    _blocked_cache["ts"] = 0
    _plan_hash.clear()


def exempt_for(db, nas):
    """-> (macs, ips) of the devices that need no login on this router."""
    macs, ips = set(), set()
    for e in db.query(AccessExempt).filter((AccessExempt.nas_id.is_(None)) | (AccessExempt.nas_id == nas.id)):
        if e.kind == "mac":
            m = devices.normalize_mac(e.value)
            if m:
                macs.add(m)
        elif _is_addr(e.value):
            ips.add(e.value)
    types = settings(db)["exempt_types"]
    if types:
        for d in db.query(Device).filter(Device.device_type.in_(types), Device.last_nas_id == nas.id):
            macs.add(d.mac)
    for d in db.query(Device).filter(Device.mac.in_(macs or {"-"}), Device.last_ip != ""):
        ips.add(d.last_ip)                  # MAC exempt -> its current IP is free of the firewall limits too
    return sorted(macs), sorted(ips)


def desired(db, nas):
    """Everything this router should hold: {"lists": {name: [addr]}, "filter": [rule], "nat": [rule],
    "bindings": [binding]}."""
    st = settings(db)
    lists = {}
    filt, nat = [], []
    macs, ips = exempt_for(db, nas)
    lists[FREE] = ips                       # static part (exempt devices); grants add dynamic entries
    # sensitive objects of this router (or of every router)
    for o in db.query(NetObject).filter(NetObject.sensitive.is_(True),
                                        (NetObject.nas_id.is_(None)) | (NetObject.nas_id == nas.id)):
        addrs = tokens(o.addresses)
        if not addrs:
            continue
        lst, ok = f"macc-s{o.id}", f"macc-s{o.id}-ok"
        lists[lst] = addrs
        allowed = [a for a in tokens(o.allowed_from) if _is_addr(a)]
        base = {"chain": "forward", "connection-state": "new", "dst-address-list": lst}
        if allowed:
            lists[ok] = allowed
            base["src-address-list"] = "!" + ok
        filt.append(dict(base, action="add-src-to-address-list", **{"address-list": f"{VIOL_PREFIX}{o.id}",
                                                                     "address-list-timeout": "1h"},
                         comment=f"{TAG} sensitive {o.id}: {o.name}"[:200]))
        if o.sensitive_action == "block":
            filt.append(dict(base, action="drop", comment=f"{TAG} sensitive block {o.id}"))
    # internal destinations after login
    if st["internal_restrict"]:
        ok = tokens(st["allowed_internal"])
        for o in db.query(NetObject).filter(NetObject.users_allowed.is_(True), NetObject.sensitive.isnot(True),
                                            (NetObject.nas_id.is_(None)) | (NetObject.nas_id == nas.id)):
            ok.extend(tokens(o.addresses))
        lists["macc-int-ok"] = sorted(set(ok))
        lists["macc-internal"] = tokens(get_setting(db, "internal_ranges", DEFAULT_INTERNAL)) or tokens(DEFAULT_INTERNAL)
        filt.append({"chain": "forward", "connection-state": "new", "hotspot": "auth",
                     "dst-address-list": "macc-int-ok", "action": "accept", "comment": f"{TAG} internal allowed"})
        filt.append({"chain": "forward", "connection-state": "new", "hotspot": "auth", "src-address-list": "!" + FREE,
                     "dst-address-list": "macc-internal", "action": "add-src-to-address-list",
                     "address-list": f"{VIOL_PREFIX}int", "address-list-timeout": "1h",
                     "comment": f"{TAG} internal not allowed"})
        filt.append({"chain": "forward", "connection-state": "new", "hotspot": "auth", "src-address-list": "!" + FREE,
                     "dst-address-list": "macc-internal", "action": "drop", "comment": f"{TAG} internal drop"})
    # sites
    rules = db.query(SiteRule).filter(SiteRule.enabled.is_(True)).all()
    block = sorted({r.pattern for r in rules if r.action == "block"})
    allow = sorted({r.pattern for r in rules if r.action == "allow"})
    if st["sites_mode"] == "allow":
        lists["macc-allow"] = allow
        lists["macc-internal"] = lists.get("macc-internal") or tokens(get_setting(db, "internal_ranges",
                                                                                  DEFAULT_INTERNAL))
        filt.append({"chain": "forward", "connection-state": "new", "hotspot": "auth",
                     "dst-address-list": "macc-allow", "action": "accept", "comment": f"{TAG} allowed site"})
        filt.append({"chain": "forward", "connection-state": "new", "hotspot": "auth", "src-address-list": "!" + FREE,
                     "dst-address-list": "!macc-internal", "protocol": "tcp", "action": "reject",
                     "reject-with": "tcp-reset", "comment": f"{TAG} not an allowed site"})
        filt.append({"chain": "forward", "connection-state": "new", "hotspot": "auth", "src-address-list": "!" + FREE,
                     "dst-address-list": "!macc-internal", "action": "drop", "comment": f"{TAG} not an allowed site"})
    elif block:
        lists["macc-block"] = block
        tgt = _panel_target(db) if st["block_page"] else None
        if tgt:
            nat.append({"chain": "dstnat", "protocol": "tcp", "dst-port": "80", "src-address-list": "!" + FREE,
                        "dst-address-list": "macc-block", "action": "dst-nat", "to-addresses": tgt[0],
                        "to-ports": tgt[1], "comment": f"{TAG} block page"})
        filt.append({"chain": "forward", "connection-state": "new", "src-address-list": "!" + FREE,
                     "dst-address-list": "macc-block", "protocol": "tcp", "action": "reject",
                     "reject-with": "tcp-reset", "comment": f"{TAG} blocked site"})
        filt.append({"chain": "forward", "connection-state": "new", "src-address-list": "!" + FREE,
                     "dst-address-list": "macc-block", "action": "drop", "comment": f"{TAG} blocked site"})
    of_macs = {d.last_ip for d in db.query(Device).filter(Device.mac.in_(macs or {"-"}))}
    bindings = [{"mac-address": m, "type": "bypassed", "comment": f"{TAG} exempt"} for m in macs]
    bindings += [{"address": i, "type": "bypassed", "comment": f"{TAG} exempt"} for i in ips
                 if "/" not in i and "-" not in i and i not in of_macs]
    return {"lists": lists, "filter": filt, "nat": nat, "bindings": bindings}


def script(plan):
    """The plan as a RouterOS script (shown to the admin before applying)."""
    def kv(d):
        return " ".join(f'{k}="{v}"' if " " in str(v) else f"{k}={v}" for k, v in d.items())
    out = ["# items of the accounting panel (comment macc)"]
    for name, addrs in plan["lists"].items():
        for a in addrs:
            out.append(f"/ip firewall address-list add list={name} address={a} comment={TAG}")
    for r in plan["nat"]:
        out.append("/ip firewall nat add " + kv(r) + " place-before=0")
    for r in plan["filter"]:
        out.append("/ip firewall filter add " + kv(r))
    for b in plan["bindings"]:
        out.append("/ip hotspot ip-binding add " + kv(b))
    return "\n".join(out)


def _mine(item):
    return str(item.get("comment", "")).startswith(TAG)


def apply(db, nas, remove_only=False):
    """Brings the router's macc items to the plan. Returns a short summary."""
    plan = {"lists": {}, "filter": [], "nat": [], "bindings": []} if remove_only else desired(db, nas)
    conn = routeros.api(nas)
    n_add = n_del = 0
    try:
        al = conn.path("ip", "firewall", "address-list")
        have = {}
        for i in routeros.rows(al):
            lst = str(i.get("list", ""))
            if not lst.startswith("macc-") or routeros._yes(i.get("dynamic")):
                continue
            have[(lst, str(i.get("address", "")))] = i[".id"]
        want = {(lst, a) for lst, addrs in plan["lists"].items() for a in addrs}
        stale = [i for k, i in have.items() if k not in want]
        if stale:
            al.remove(*stale)
            n_del += len(stale)
        for lst, a in sorted(want - set(have)):
            try:
                al.add(list=lst, address=a, comment=TAG)
                n_add += 1
            except Exception as e:     # noqa: BLE001 - a domain the router cannot resolve yet is still added later
                log.warning("%s: address-list %s %s: %s", nas.name, lst, a, e)
        for path, rules in ((("ip", "firewall", "filter"), plan["filter"]), (("ip", "firewall", "nat"), plan["nat"])):
            p = conn.path(*path)
            items = routeros.rows(p)
            old = [i[".id"] for i in items if _mine(i)]
            if old:
                p.remove(*old)
                n_del += len(old)
            first = next((i[".id"] for i in items if not _mine(i)), None)
            for r in rules:
                kw = dict(r)
                if first:
                    kw["place-before"] = first
                p.add(**kw)
                n_add += 1
        hb = conn.path("ip", "hotspot", "ip-binding")
        try:
            old = [i[".id"] for i in routeros.rows(hb) if _mine(i)]
            if old:
                hb.remove(*old)
                n_del += len(old)
            for b in plan["bindings"]:
                hb.add(**b)
                n_add += 1
        except Exception as e:         # noqa: BLE001 - router without hotspot
            log.info("%s: hotspot ip-binding: %s", nas.name, e)
    finally:
        conn.close()
    return f"{n_add} مورد اضافه، {n_del} مورد حذف"


def sync_free(db, nas, conn=None):
    """Users with an 'internet' grant: the IPs of their sessions on this router go to macc-free for 10 minutes."""
    ts = now()
    stale = ts - timedelta(minutes=15)
    ips = set()
    for s in db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.last_update >= stale,
                                          AcctSession.user_id.isnot(None), AcctSession.framed_ip != "",
                                          AcctSession.nas_ip.in_([nas.ip, nas.api_host or nas.ip])):
        if grants.active(db, s.user_id, "internet", ts):
            ips.add(s.framed_ip)
    if not ips:
        return 0
    own = conn is None
    conn = conn or routeros.api(nas)
    try:
        al = conn.path("ip", "firewall", "address-list")
        have = {str(i.get("address")): i for i in routeros.rows(al) if str(i.get("list")) == FREE}
        n = 0
        for ip in ips:
            i = have.get(ip)
            if i is None:
                al.add(list=FREE, address=ip, timeout="10m", comment=f"{TAG} grant")
                n += 1
            elif routeros._yes(i.get("dynamic")):
                al.update(**{".id": i[".id"], "timeout": "10m"})
        return n
    finally:
        if own:
            conn.close()


def violations(db, nas, address_list):
    """macc-v* entries made by the router's rules -> alarms (once per source and object per hour)."""
    objs = {o.id: o for o in db.query(NetObject).filter(NetObject.sensitive.is_(True))}
    n = 0
    for i in address_list:
        lst = str(i.get("list", ""))
        if not lst.startswith(VIOL_PREFIX):
            continue
        ip = str(i.get("address", ""))
        key = lst[len(VIOL_PREFIX):]
        d = db.query(Device).filter(Device.last_ip == ip).order_by(Device.last_seen.desc()).first()
        who = " / ".join(x for x in (d.label or d.hostname, d.logon_user, d.last_user, d.mac) if x) if d else ""
        if key == "int":
            title = f"دسترسی غیرمجاز به شبکهٔ داخلی از {ip}"
        else:
            o = objs.get(int(key)) if key.isdigit() else None
            title = f"دسترسی غیرمجاز به {o.name if o else 'آدرس حساس'} از {ip}"
        before = db.query(alerts.Alert).filter(alerts.Alert.title == title,
                                               alerts.Alert.ts >= now() - timedelta(hours=1)).first()
        if before is None:
            alerts.add(db, "access", title, f"روتر {nas.name}" + (f" · دستگاه: {who}" if who else ""), "err",
                       f"/devices?q={ip}")
            n += 1
    return n


def flow_alarm(db_factory, rid, local_ip, obj, ts):
    """NetFlow saw a device reach a sensitive object (works without the router rules too)."""
    allowed = netscope.parse_ranges(obj.get("allowed_from", ""))[0]
    try:
        a = ipaddress.ip_address(local_ip)
    except ValueError:
        return
    if allowed and netscope._in(a, allowed):
        return
    key = (obj["id"], local_ip)
    last = _flow_seen.get(key)
    if last and ts - last < timedelta(hours=1):
        return
    _flow_seen[key] = ts
    db = db_factory()
    try:
        title = f"دسترسی غیرمجاز به {obj['name']} از {local_ip}"
        if db.query(alerts.Alert).filter(alerts.Alert.title == title,
                                         alerts.Alert.ts >= now() - timedelta(hours=1)).first() is None:
            d = db.query(Device).filter(Device.last_ip == local_ip).order_by(Device.last_seen.desc()).first()
            who = " / ".join(x for x in (d.label or d.hostname, d.logon_user, d.last_user, d.mac) if x) if d else ""
            nas = db.get(Nas, rid)
            alerts.add(db, "access", title, f"دیده‌شده در ترافیک روتر {nas.name if nas else rid}"
                       + (f" · دستگاه: {who}" if who else ""), "err", f"/devices?q={local_ip}")
            db.commit()
    finally:
        db.close()


_flow_seen = {}


_plan_hash = {}


def job():
    """Every minute for routers with access control on: alarms from the router's lists, grant IPs, and the plan
    re-applied when it changed (new exempt device IP, new rule ...)."""
    import hashlib
    import json
    from .db import SessionLocal
    db = SessionLocal()
    try:
        for nas in db.query(Nas).filter(Nas.acl_enabled.is_(True), Nas.api_user != "").all():
            try:
                plan = desired(db, nas)
                h = hashlib.sha1(json.dumps(plan, sort_keys=True).encode()).hexdigest()
                if _plan_hash.get(nas.id) != h:
                    nas.acl_status = apply(db, nas)
                    nas.acl_applied_at = now()
                    _plan_hash[nas.id] = h
                conn = routeros.api(nas)
                try:
                    violations(db, nas, routeros._list(conn, "ip", "firewall", "address-list"))
                    sync_free(db, nas, conn)
                finally:
                    conn.close()
                db.commit()
            except Exception as e:     # noqa: BLE001
                db.rollback()
                log.warning("access %s: %s", nas.name, e)
                nas.acl_status = f"خطا: {e}"[:300]
                db.commit()
    finally:
        db.close()
        SessionLocal.remove()


def forget(nas_id):
    _plan_hash.pop(nas_id, None)
