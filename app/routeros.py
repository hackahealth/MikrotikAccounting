"""ارتباط با روتر میکروتیک: RouterOS API و RADIUS Disconnect (CoA)."""
import logging
import socket
import ssl

from librouteros import connect
from pyrad import packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

from . import config
from .db import Nas, decrypt

log = logging.getLogger("routeros")
_dict = None


def _dictionary():
    global _dict
    if _dict is None:
        _dict = Dictionary(config.RADIUS_DICTIONARY)
    return _dict


def api(nas: Nas):
    if not nas.api_user:
        raise RuntimeError(f"API روتر {nas.name} تنظیم نشده")
    kwargs = {"username": nas.api_user, "password": decrypt(nas.api_password_enc),
              "host": nas.api_host or nas.ip, "port": nas.api_port or (8729 if nas.api_ssl else 8728), "timeout": 10}
    if nas.api_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:    # api-ssl without a certificate on the router only offers anonymous DH
            ctx.set_ciphers("DEFAULT:ADH:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        kwargs["ssl_wrapper"] = lambda s: ctx.wrap_socket(s, server_hostname=kwargs["host"])
    return connect(encoding="utf-8", **kwargs)


# librouteros turns "1001" into 1001 and "no" into False; these fields are always text
TEXT_KEYS = {"name", "user", "host-name", "comment", "password", "profile", "caller-id", "email", "server",
             "html-directory", "class-id", "service", "address-list", "routes", "remote-address", "local-address"}


def norm(item):
    item = dict(item)
    for k in TEXT_KEYS.intersection(item):
        v = item[k]
        if isinstance(v, bool):
            item[k] = "yes" if v else "no"
        elif not isinstance(v, str) and v is not None:
            item[k] = str(v)
    return item


def rows(path):
    return [norm(i) for i in path]


def _list(conn, *path):
    try:
        return rows(conn.path(*path))
    except Exception as e:
        log.debug("path %s failed: %s", path, e)
        return []


def snapshot(nas: Nas):
    """Pull everything needed in one connection."""
    from . import wancheck
    conn = api(nas)
    try:
        return {
            "hotspot_active": _list(conn, "ip", "hotspot", "active"),
            "ppp_active": _list(conn, "ppp", "active"),
            "queues": _list(conn, "queue", "simple"),
            "leases": _list(conn, "ip", "dhcp-server", "lease"),
            "hotspot_hosts": _list(conn, "ip", "hotspot", "host"),
            "dns": _list(conn, "ip", "dns", "cache", "all"),
            "identity": next(iter(_list(conn, "system", "identity")), {}).get("name", ""),
            "interfaces": _list(conn, "interface"),
            "addresses": _list(conn, "ip", "address"),
            "arp": _list(conn, "ip", "arp"),
            "pings": {t: ping(conn, t) for t in split_targets(getattr(nas, "monitor_targets", ""))},
            "wan": wancheck.read(conn),
        }
    finally:
        conn.close()


def split_targets(text):
    return [t for t in str(text or "").replace(",", " ").split() if t][:5]


def ping(conn, address, count=3):
    """/ping from the router (e.g. HQ server through the tunnel): the replies, the last one has avg-rtt / packet-loss."""
    try:
        return [dict(r) for r in conn("/ping", **{"address": address, "count": str(count), "interval": "0.3"})]
    except Exception as e:  # noqa: BLE001
        log.debug("ping %s failed: %s", address, e)
        return [{"error": str(e)}]


def _yes(v):
    return str(v).lower() in ("true", "yes")


def network_info(nas: Nas):
    """Interfaces with their Traffic-Flow index, a guess of the internet (WAN) interfaces from the default route /
    DHCP / PPPoE clients, and the internal networks on the other interfaces."""
    import ipaddress
    from .netscope import ifindex
    conn = api(nas)
    try:
        ifaces = _list(conn, "interface")
        addrs = _list(conn, "ip", "address")
        routes = _list(conn, "ip", "route")
        dhcp = _list(conn, "ip", "dhcp-client")
        pools = _list(conn, "ip", "pool")
        from . import wancheck
        children = wancheck.read(conn)["children"]
    finally:
        conn.close()
    names = {i.get("name") for i in ifaces if i.get("name")}
    nets = []
    for a in addrs:
        try:
            nets.append((ipaddress.ip_interface(a.get("address", "")).network, a.get("interface", ""),
                         _yes(a.get("dynamic")) or _yes(a.get("disabled"))))
        except ValueError:
            pass
    wan = []

    def add(name):
        if name and name in names and name not in wan:
            wan.append(name)
    for r in routes:
        if r.get("dst-address") not in ("0.0.0.0/0", "::/0") or _yes(r.get("disabled")):
            continue
        if "active" in r and not _yes(r.get("active")):
            continue
        cands = [str(r.get("immediate-gw", "")), str(r.get("gateway", ""))] + \
            str(r.get("gateway-status", "")).split()[-1:]
        for c in cands:
            for t in c.split(","):
                t = t.split("%")[-1].strip()
                if t in names:
                    add(t)
                    continue
                try:
                    gw = ipaddress.ip_address(t)
                except ValueError:
                    continue
                for net, iface, _ in nets:
                    if gw.version == net.version and gw in net:
                        add(iface)
    for d in dhcp:
        if _yes(d.get("add-default-route", "yes")) and not _yes(d.get("disabled")):
            add(d.get("interface"))
    for i in ifaces:
        if str(i.get("type", "")).startswith(("pppoe-out", "lte")) and _yes(i.get("running", True)):
            add(i.get("name"))
    # the port under a PPPoE / VLAN that is itself WAN is not counted twice
    under = {c["parent"] for c in children if c["name"] in wan}
    wan = [w for w in wan if w not in under]
    lan = []
    for net, iface, dyn in nets:
        if iface in wan or iface in under or dyn or net.prefixlen == net.max_prefixlen:
            continue
        if str(net) not in lan:
            lan.append(str(net))
    for p in pools:
        for rng in str(p.get("ranges", "")).split(","):
            if rng.strip() and rng.strip() not in lan:
                lan.append(rng.strip())
    out_ifaces = [{"name": i.get("name"), "type": i.get("type", ""), "index": ifindex(i),
                   "running": _yes(i.get("running")), "comment": i.get("comment", "")}
                  for i in ifaces if i.get("name")]
    lan_ifaces = []
    for net, iface, dyn in nets:
        if iface and iface not in wan and not dyn and iface not in lan_ifaces:
            lan_ifaces.append(iface)
    return {"interfaces": out_ifaces, "wan": wan, "lan": lan, "lan_ifaces": lan_ifaces}


def disconnect_api(nas: Nas, username: str, service: str = "") -> int:
    conn = api(nas)
    removed = 0
    try:
        paths = [("ip", "hotspot", "active"), ("ppp", "active")]
        if service == "vpn":
            paths = paths[::-1]
        for p in paths:
            path = conn.path(*p)
            for item in rows(path):
                if item.get("user", item.get("name")) == username:
                    path.remove(item[".id"])
                    removed += 1
    finally:
        conn.close()
    return removed


def disconnect_coa(nas: Nas, username: str, acct_session_id: str = "", framed_ip: str = "") -> bool:
    target = nas.ip if nas.ip and nas.ip != "0.0.0.0" else nas.api_host
    if not target:
        return False
    cl = Client(server=target, secret=nas.secret.encode(), dict=_dictionary(), coaport=nas.coa_port or 3799)
    cl.timeout, cl.retries = 3, 1
    req = cl.CreateCoAPacket(code=packet.DisconnectRequest, User_Name=username)
    if acct_session_id:
        req["Acct-Session-Id"] = acct_session_id
    if framed_ip:
        req["Framed-IP-Address"] = framed_ip
    try:
        reply = cl.SendPacket(req)
        return reply.code == packet.DisconnectACK
    except (socket.error, Exception) as e:
        log.warning("CoA to %s failed: %s", target, e)
        return False


def disconnect(nas: Nas, username: str, service="", acct_session_id="", framed_ip="") -> bool:
    """Try RADIUS Disconnect-Request first (only for RADIUS sessions), then RouterOS API."""
    if not acct_session_id.startswith("api:") and disconnect_coa(nas, username, acct_session_id, framed_ip):
        return True
    if nas.api_user:
        try:
            return disconnect_api(nas, username, service) > 0
        except Exception as e:
            log.warning("API disconnect failed: %s", e)
    return False


# ------------------------------------------------------------------ local accounts on the router
# kind -> (API path, editable fields)
LOCAL_KINDS = {
    "hs_user": (("ip", "hotspot", "user"),
                ["name", "password", "profile", "server", "limit-uptime", "limit-bytes-total", "limit-bytes-in",
                 "limit-bytes-out", "mac-address", "address", "email", "comment", "disabled"]),
    "hs_profile": (("ip", "hotspot", "user", "profile"),
                   ["name", "rate-limit", "shared-users", "session-timeout", "idle-timeout", "keepalive-timeout",
                    "address-pool", "address-list", "mac-cookie-timeout", "transparent-proxy"]),
    "ppp_secret": (("ppp", "secret"),
                   ["name", "password", "service", "profile", "local-address", "remote-address", "caller-id",
                    "routes", "limit-bytes-in", "limit-bytes-out", "comment", "disabled"]),
    "ppp_profile": (("ppp", "profile"),
                    ["name", "local-address", "remote-address", "rate-limit", "dns-server", "only-one",
                     "address-list", "use-encryption", "session-timeout", "idle-timeout", "change-tcp-mss"]),
}
# value used when a field is cleared and "unset" is not supported
CLEAR_VALUES = {"limit-uptime": "0s", "limit-bytes-total": "0", "limit-bytes-in": "0", "limit-bytes-out": "0",
                "mac-address": "00:00:00:00:00:00", "server": "all", "address": "0.0.0.0", "session-timeout": "0s",
                "idle-timeout": "none", "caller-id": "", "routes": "", "comment": "", "email": "",
                "rate-limit": "", "address-list": ""}


def local_overview(nas: Nas):
    """Everything the local-accounts page needs, in one API connection."""
    conn = api(nas)
    try:
        return {
            "hs_user": _list(conn, "ip", "hotspot", "user"),
            "hs_profile": _list(conn, "ip", "hotspot", "user", "profile"),
            "hs_server": _list(conn, "ip", "hotspot"),
            "hs_active": _list(conn, "ip", "hotspot", "active"),
            "ppp_secret": _list(conn, "ppp", "secret"),
            "ppp_profile": _list(conn, "ppp", "profile"),
            "ppp_active": _list(conn, "ppp", "active"),
            "pools": _list(conn, "ip", "pool"),
            "identity": next(iter(_list(conn, "system", "identity")), {}).get("name", ""),
        }
    finally:
        conn.close()


def _clean(kind, fields):
    allowed = LOCAL_KINDS[kind][1]
    out = {}
    for k, v in fields.items():
        if k not in allowed:
            continue
        if isinstance(v, bool):
            out[k] = v
        else:
            out[k] = str(v if v is not None else "").strip()
    return out


def local_save(nas: Nas, kind: str, fields: dict, item_id: str = "") -> str:
    """Add (no item_id) or update an item. Returns the item id."""
    path_parts, _ = LOCAL_KINDS[kind]
    data = _clean(kind, fields)
    conn = api(nas)
    try:
        path = conn.path(*path_parts)
        if not item_id:
            return path.add(**{k: v for k, v in data.items() if v != ""})
        current = next((i for i in rows(path) if i.get(".id") == item_id), None)
        if current is None:
            raise RuntimeError("این مورد روی روتر پیدا نشد (شاید حذف شده)")
        changes, unset = {}, []
        for k, v in data.items():
            old = current.get(k)
            if v == "":
                if old not in (None, "", 0, False):
                    unset.append(k)
            elif v != old and str(v) != str(old):
                changes[k] = v
        unset = [u for u in unset if u not in ("password", "name")]   # empty password field = keep current
        if changes:
            path.update(**{".id": item_id}, **changes)
        for k in unset:
            try:
                tuple(conn("/" + "/".join(path_parts) + "/unset", **{"numbers": item_id, "value-name": k}))
            except Exception:
                if k in CLEAR_VALUES:
                    path.update(**{".id": item_id, k: CLEAR_VALUES[k]})
        return item_id
    finally:
        conn.close()


def local_remove(nas: Nas, kind: str, ids) -> int:
    conn = api(nas)
    try:
        ids = [i for i in ids if i]
        if ids:
            conn.path(*LOCAL_KINDS[kind][0]).remove(*ids)
        return len(ids)
    finally:
        conn.close()


def local_set_disabled(nas: Nas, kind: str, ids, disabled: bool) -> int:
    conn = api(nas)
    try:
        path = conn.path(*LOCAL_KINDS[kind][0])
        for i in ids:
            path.update(**{".id": i, "disabled": disabled})
        return len(ids)
    finally:
        conn.close()


def local_reset_counters(nas: Nas, ids) -> int:
    conn = api(nas)
    try:
        for i in ids:
            tuple(conn("/ip/hotspot/user/reset-counters", **{"numbers": i}))
        return len(ids)
    finally:
        conn.close()


def kick_active(nas: Nas, service: str, ids) -> int:
    conn = api(nas)
    try:
        path = conn.path(*(("ip", "hotspot", "active") if service == "hotspot" else ("ppp", "active")))
        path.remove(*ids)
        return len(ids)
    finally:
        conn.close()


def local_bulk_add(nas: Nas, kind: str, items) -> tuple:
    """items: list of field dicts. Returns (added, errors[])."""
    conn = api(nas)
    added, errors = 0, []
    try:
        path = conn.path(*LOCAL_KINDS[kind][0])
        existing = {i.get("name") for i in rows(path)}
        for fields in items:
            data = {k: v for k, v in _clean(kind, fields).items() if v != ""}
            if data.get("name") in existing:
                errors.append(f"{data.get('name')}: تکراری")
                continue
            try:
                path.add(**data)
                existing.add(data.get("name"))
                added += 1
            except Exception as e:
                errors.append(f"{data.get('name')}: {e}")
    finally:
        conn.close()
    return added, errors
