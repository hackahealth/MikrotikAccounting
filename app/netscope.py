"""تفکیک ترافیک به «اینترنت»، «تانل» (شبکه دفاتر دیگر از راه تانل روی اینترنت) و «داخل شبکه»: با اینترفیس‌های WAN و
تانل هر روتر و رنج‌های IP."""
import ipaddress
import re
import threading
import time

from .db import Nas, SessionLocal, get_setting

DEFAULT_INTERNAL = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16"
# RouterOS interface types that are tunnels (client and server side; l2tp-in etc. are the dynamic server ends)
TUNNEL_TYPES = ("eoip", "eoipv6", "gre", "gre6", "gre-tunnel", "ipip", "ipipv6", "6to4", "vxlan", "wg", "wireguard",
                "l2tp-out", "l2tp-in", "sstp-out", "sstp-in", "pptp-out", "pptp-in", "ovpn-out", "ovpn-in")


def parse_ranges(text):
    """CIDR / single IP / a.b.c.d-e.f.g.h, separated by newline, space, comma; '#' starts a comment.
    Returns (networks, invalid tokens)."""
    nets, bad = [], []
    for line in (text or "").splitlines():
        for tok in re.split(r"[\s,;]+", line.split("#", 1)[0]):
            if not tok:
                continue
            try:
                if "-" in tok:
                    a, b = tok.split("-", 1)
                    nets.extend(ipaddress.summarize_address_range(ipaddress.ip_address(a.strip()),
                                                                  ipaddress.ip_address(b.strip())))
                else:
                    nets.append(ipaddress.ip_network(tok, strict=False))
            except (ValueError, TypeError):
                bad.append(tok)
    return nets, bad


def split_names(text):
    return [w for w in re.split(r"[\s,;]+", text or "") if w]


def ifindex(item):
    """RouterOS interface .id ('*1A') -> numeric index used by Traffic-Flow / SNMP."""
    try:
        return int(str(item.get(".id", "")).lstrip("*"), 16)
    except ValueError:
        return None


def _in(addr, nets):
    return any(addr.version == n.version and addr in n for n in nets)


class Scope:
    def __init__(self):
        self.lock = threading.Lock()
        self.ts = 0
        self.internal, self.internet = [], []
        self.routers = {}       # nas_id -> {"lan": [nets], "wan": [names], "wan_idx": set(), "tun"..., "tun_idx"}
        self.auto_tun = {}      # nas_id -> {index of a tunnel-type interface}  (learned via API)
        self.by_ip = {}         # exporter ip -> nas_id (Nas.ip / api_host)
        self.ifnames = {}       # nas_id -> {interface name: index}  (learned via API)
        self.aliases = {}       # router's own addresses -> {nas_id}
        self.cache = {}

    def invalidate(self):
        self.ts = 0

    def refresh(self, force=False):
        if not force and time.time() - self.ts < 60:
            return
        db = SessionLocal()
        try:
            internal = parse_ranges(get_setting(db, "internal_ranges", DEFAULT_INTERNAL))[0]
            internet = parse_ranges(get_setting(db, "internet_ranges", ""))[0]
            routers, by_ip = {}, {}
            for n in db.query(Nas).all():
                routers[n.id] = {"lan": parse_ranges(n.lan_ranges)[0], "wan": split_names(n.wan_interfaces),
                                 "tun": split_names(n.tunnel_interfaces),
                                 "tun_nets": parse_ranges(n.tunnel_ranges)[0]}
                for ip in (n.ip, n.api_host):
                    if ip:
                        by_ip[ip] = n.id
        finally:
            db.close()
            SessionLocal.remove()
        with self.lock:
            self.internal, self.internet, self.routers, self.by_ip = internal, internet, routers, by_ip
            for rid in routers:
                self._resolve(rid)
            self.cache = {}
        self.ts = time.time()

    def _resolve(self, rid):
        r = self.routers.get(rid)
        if r is None:
            return
        names = self.ifnames.get(rid, {})

        def indexes(words):
            return {int(w) if w.isdigit() else names[w] for w in words if w.isdigit() or w in names}
        r["wan_idx"] = indexes(r["wan"])
        # no tunnel interface chosen: every tunnel-type interface of the router (EoIP, GRE, L2TP, SSTP, WireGuard...)
        r["tun_idx"] = indexes(r.get("tun", [])) if r.get("tun") else set(self.auto_tun.get(rid, ()))

    def learn(self, nas_id, interfaces, addresses=()):
        """Called on every router poll: interface name -> index, and the router's own IPs (flow exporter)."""
        names = {i["name"]: ifindex(i) for i in interfaces if i.get("name") and ifindex(i) is not None}
        tun = {ifindex(i) for i in interfaces if str(i.get("type", "")).lower() in TUNNEL_TYPES
               and ifindex(i) is not None}
        with self.lock:
            if names:
                self.ifnames[nas_id] = names
                self.auto_tun[nas_id] = tun
            for a in addresses:
                ip = str(a.get("address", "")).split("/")[0]
                if ip:
                    self.aliases.setdefault(ip, set()).add(nas_id)
            self._resolve(nas_id)

    def router_id(self, exporter):
        rid = self.by_ip.get(exporter)
        if rid is None:
            ids = self.aliases.get(exporter, set())
            if len(ids) == 1:
                rid = next(iter(ids))
            elif len(self.routers) == 1:
                rid = next(iter(self.routers))
        return rid

    def is_internal(self, exporter, remote, in_if=0, out_if=0):
        self.refresh()
        return self.is_internal_for(self.router_id(exporter), remote, in_if, out_if)

    def is_internal_for(self, rid, remote, in_if=0, out_if=0):
        """Is this remote address inside the network (local or through a tunnel), as seen from router rid?"""
        return self.classify_for(rid, remote, in_if, out_if) != "internet"

    def classify_for(self, rid, remote, in_if=0, out_if=0):
        """'internet', 'tunnel' (another office's network through a tunnel over the internet) or 'lan'."""
        self.refresh()
        key = (rid, remote)
        hit = self.cache.get(key)
        if hit is None:
            try:
                a = ipaddress.ip_address(remote)
            except ValueError:
                return False
            r = self.routers.get(rid)
            hit = (_in(a, self.internet), bool(r) and _in(a, r["lan"]), _in(a, self.internal),
                   bool(r) and _in(a, r.get("tun_nets", [])))
            if len(self.cache) > 200000:
                self.cache = {}
            self.cache[key] = hit
        exception, router_lan, global_lan, tun_net = hit
        if exception:
            return "internet"
        if tun_net:                       # e.g. IPsec without a tunnel interface: the other offices' subnets
            return "tunnel"
        r = self.routers.get(rid, {})
        tun = r.get("tun_idx")
        if tun and (in_if in tun or out_if in tun):
            # a public address through the tunnel is internet that the office gets from HQ
            return "tunnel" if (router_lan or global_lan) else "internet"
        if router_lan:
            return "lan"
        wan = r.get("wan_idx")
        if wan and (in_if or out_if):
            return "lan" if in_if not in wan and out_if not in wan else "internet"
        return "lan" if global_lan else "internet"

    def describe(self, nas):
        """Short text for the routers table."""
        parts = []
        if nas.wan_interfaces:
            parts.append("WAN: " + "، ".join(split_names(nas.wan_interfaces)))
        nets = parse_ranges(nas.lan_ranges)[0]
        if nets:
            parts.append(f"{len(nets)} رنج داخلی")
        if nas.tunnel_interfaces:
            parts.append("تانل: " + "، ".join(split_names(nas.tunnel_interfaces)))
        if parse_ranges(nas.tunnel_ranges)[0]:
            parts.append(f"{len(parse_ranges(nas.tunnel_ranges)[0])} رنج دفاتر دیگر")
        return " · ".join(parts) or "پیش‌فرض (رنج‌های عمومی)"


scope = Scope()
