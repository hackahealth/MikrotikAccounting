"""Which of the interfaces chosen as WAN on a router really carry internet: the default route's interface, PPPoE / VLAN /
LTE ... over a physical port (the port must not be counted twice) and ports that belong to the internal network (a
bridge port, or an interface with an address of the office's LAN) are told apart. Learned on every API poll."""
import ipaddress
import json
import re

from . import netscope, routeros

CHILD_PATHS = (("interface", "pppoe-client"), ("interface", "vlan"), ("interface", "lte"), ("interface", "macvlan"),
               ("interface", "vrrp"))


def read(conn):
    """Extra API reads for the WAN check (one connection, already open)."""
    out = {"children": [], "bridge_ports": routeros._list(conn, "interface", "bridge", "port"), "routes": []}
    for p in CHILD_PATHS:
        for i in routeros._list(conn, *p):
            if i.get("name") and i.get("interface"):
                out["children"].append({"name": str(i["name"]), "parent": str(i["interface"])})
    for r in routeros._list(conn, "ip", "route"):
        if str(r.get("dst-address", "")) == "0.0.0.0/0" and routeros._yes(r.get("active", True)) \
                and not routeros._yes(r.get("disabled")):
            out["routes"].append({k: str(r.get(k, "")) for k in ("gateway", "immediate-gw", "gateway-status")})
    return out


def _route_ifaces(routes, names):
    found = []
    for r in routes:
        cands = []
        ig = r.get("immediate-gw", "")
        if "%" in ig:
            cands.append(ig.split("%", 1)[1])
        elif ig:
            cands.append(ig)
        gs = r.get("gateway-status", "")
        m = re.search(r"via\s+(\S+)", gs)
        if m:
            cands.append(m.group(1))
        elif gs:
            cands.append(gs.split()[0])
        cands.append(r.get("gateway", "").split("%")[-1])
        for c in cands:
            if c in names and c not in found:
                found.append(c)
    return found


def learn(nas, snap) -> dict:
    """Facts about the router's interfaces kept on Nas.iface_facts (JSON)."""
    extra = snap.get("wan") or {}
    names = {str(i.get("name")) for i in snap.get("interfaces", []) if i.get("name")}
    types = {str(i.get("name")): str(i.get("type", "")) for i in snap.get("interfaces", []) if i.get("name")}
    lan = netscope.parse_ranges(nas.lan_ranges or "")[0]
    addr = {}
    for a in snap.get("addresses", []):
        if routeros._yes(a.get("disabled")) or not a.get("interface"):
            continue
        addr.setdefault(str(a["interface"]), []).append(str(a.get("address", "")))
    lan_ifaces = set()
    for iface, addrs in addr.items():
        for a in addrs:
            try:
                ip = ipaddress.ip_interface(a).ip
            except ValueError:
                continue
            if lan and netscope._in(ip, lan):
                lan_ifaces.add(iface)
    bridges = {}
    for p in extra.get("bridge_ports", []):
        if p.get("interface") and not routeros._yes(p.get("disabled")):
            bridges[str(p["interface"])] = str(p.get("bridge", ""))
    return {
        "types": types,
        "parents": {c["name"]: c["parent"] for c in extra.get("children", [])},
        "bridge_of": bridges,
        "lan_ifaces": sorted(lan_ifaces),
        "default_route": _route_ifaces(extra.get("routes", []), names),
    }


def facts(nas) -> dict:
    try:
        return json.loads(nas.iface_facts or "{}")
    except ValueError:
        return {}


def check(nas, wan):
    """-> {iface: (counted, note)} for the WAN interfaces chosen on the router form."""
    f = facts(nas)
    parents = f.get("parents", {})
    bridge_of = f.get("bridge_of", {})
    lan_ifaces = set(f.get("lan_ifaces", []))
    dr = f.get("default_route", [])
    out = {}
    for w in wan:
        kids = [c for c, p in parents.items() if p == w and c in wan]
        br = bridge_of.get(w)
        if kids:
            out[w] = (False, f"زیربنای {'، '.join(kids)} است؛ ترافیکش یک بار در آن حساب شده")
        elif w in lan_ifaces or (br and br in lan_ifaces):
            out[w] = (False, "آدرس شبکهٔ داخلی دارد یا عضو بریج شبکهٔ داخلی است؛ اینترنت حساب نشد")
        elif dr and w not in dr and not any(parents.get(d) == w for d in dr):
            out[w] = (True, "مسیر پیش‌فرض (default route) از این اینترفیس نیست")
        else:
            out[w] = (True, "")
    return out


def suggested(nas):
    """WAN interfaces worth choosing: those of the default route (the PPPoE / VLAN on top, not the port under it)."""
    return facts(nas).get("default_route", [])
