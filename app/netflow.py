"""جمع‌آوری Traffic-Flow میکروتیک (NetFlow v5 / v9 / IPFIX) و انتساب ترافیک به کاربران."""
import ipaddress
import logging
import socket
import struct
import threading
import time
from collections import defaultdict
from datetime import timedelta

from . import classifier, config, netobjects, netscope, udp
from .db import AcctSession, Nas, SessionLocal, TrafficCategory, TrafficDomain, now

log = logging.getLogger("netflow")

# Field ids we use (NetFlow v9 and IPFIX share these numbers)
F_BYTES, F_PKTS, F_PROTO, F_SPORT, F_SRC4, F_DPORT, F_DST4 = 1, 2, 4, 7, 8, 11, 12
F_SRC6, F_DST6 = 27, 28
F_IN_IF, F_OUT_IF = 10, 14
F_POSTNAT_SRC4, F_POSTNAT_DST4 = 225, 226


def _ip4(b):
    return socket.inet_ntoa(b)


def _ip6(b):
    return str(ipaddress.IPv6Address(b))


def parse_v5(data):
    count = struct.unpack("!H", data[2:4])[0]
    out = []
    for i in range(count):
        r = data[24 + i * 48: 72 + i * 48]
        if len(r) < 48:
            break
        src, dst = _ip4(r[0:4]), _ip4(r[4:8])
        in_if, out_if = struct.unpack("!HH", r[12:16])
        pkts, octets = struct.unpack("!II", r[16:24])
        sport, dport = struct.unpack("!HH", r[32:36])
        proto = r[38]
        out.append({"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "bytes": octets,
                    "in_if": in_if, "out_if": out_if})
    return out


class TemplateParser:
    """NetFlow v9 / IPFIX template-based parser."""

    def __init__(self):
        self.templates = {}

    def parse(self, data, exporter):
        version = struct.unpack("!H", data[0:2])[0]
        if version == 9:
            source_id = struct.unpack("!I", data[16:20])[0]
            offset, tpl_set, opt_set = 20, 0, 1
        else:  # IPFIX (10)
            source_id = struct.unpack("!I", data[12:16])[0]
            offset, tpl_set, opt_set = 16, 2, 3
        flows = []
        while offset + 4 <= len(data):
            set_id, set_len = struct.unpack("!HH", data[offset:offset + 4])
            if set_len < 4:
                break
            body = data[offset + 4: offset + set_len]
            if set_id == tpl_set:
                self._templates(body, exporter, source_id, version)
            elif set_id >= 256:
                tpl = self.templates.get((exporter, source_id, set_id))
                if tpl:
                    flows.extend(self._records(body, tpl))
            offset += set_len
        return flows

    def _templates(self, body, exporter, source_id, version):
        p = 0
        while p + 4 <= len(body):
            tid, count = struct.unpack("!HH", body[p:p + 4])
            p += 4
            fields = []
            for _ in range(count):
                ftype, flen = struct.unpack("!HH", body[p:p + 4])
                p += 4
                if version == 10 and ftype & 0x8000:  # enterprise field
                    ftype &= 0x7FFF
                    p += 4
                    ftype = -ftype  # mark as unknown
                fields.append((ftype, flen))
            self.templates[(exporter, source_id, tid)] = fields

    @staticmethod
    def _records(body, tpl):
        size = sum(l for _, l in tpl)
        out = []
        if size == 0 or any(l == 0xFFFF for _, l in tpl):  # variable-length not supported
            return out
        for p in range(0, len(body) - size + 1, size):
            rec, q = {}, p
            for ftype, flen in tpl:
                v = body[q:q + flen]
                q += flen
                if ftype in (F_SRC4, F_DST4, F_POSTNAT_SRC4, F_POSTNAT_DST4) and flen == 4:
                    rec[ftype] = _ip4(v)
                elif ftype in (F_SRC6, F_DST6) and flen == 16:
                    rec[ftype] = _ip6(v)
                elif ftype in (F_BYTES, F_PKTS, F_PROTO, F_SPORT, F_DPORT, F_IN_IF, F_OUT_IF):
                    rec[ftype] = int.from_bytes(v, "big")
            src = rec.get(F_SRC4) or rec.get(F_SRC6)
            dst = rec.get(F_DST4) or rec.get(F_DST6)
            if not src or not dst:
                continue
            out.append({"src": src, "dst": dst, "sport": rec.get(F_SPORT, 0), "dport": rec.get(F_DPORT, 0),
                        "proto": rec.get(F_PROTO, 0), "bytes": rec.get(F_BYTES, 0),
                        "post_src": rec.get(F_POSTNAT_SRC4), "post_dst": rec.get(F_POSTNAT_DST4),
                        "in_if": rec.get(F_IN_IF, 0), "out_if": rec.get(F_OUT_IF, 0)})
        return out


class Collector:
    def __init__(self):
        self.parser = TemplateParser()
        self.ip_user = {}       # user IP -> [(user id, router id)] of active sessions
        self.ip_user_ts = 0
        self.lock = threading.Lock()
        self.cat_buf = defaultdict(lambda: [0, 0, 0])      # (uid, day, hour, cat) -> [down, up, flows]
        self.dom_buf = defaultdict(lambda: ["", 0, 0])     # (uid, day, domain) -> [cat, down, up]
        self.stats = {"packets": 0, "flows": 0, "matched": 0}
        self.exporters = {}     # sender -> {"packets", "flows", "matched", "last", "version", "rid", "routers"}
        self.per_router = {}    # router id -> {"matched", "last"}
        self.ports = {}         # dedicated listening port -> router id
        self.started = False

    def refresh_ip_map(self):
        if time.time() - self.ip_user_ts < 15:
            return
        db = SessionLocal()
        try:
            rid_of = {}
            for n in db.query(Nas).all():
                for ip in (n.api_host, n.ip):
                    if ip and ip != "0.0.0.0":
                        rid_of[ip] = n.id
            stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
            rows = db.query(AcctSession.framed_ip, AcctSession.user_id, AcctSession.nas_ip).filter(
                AcctSession.active.is_(True), AcctSession.last_update >= stale, AcctSession.framed_ip != "").all()
            m = {}
            for ip, uid, nas_ip in rows:
                if uid:
                    m.setdefault(ip, []).append((uid, rid_of.get(nas_ip)))
            self.ip_user = m
        finally:
            db.close()
            SessionLocal.remove()
        self.ip_user_ts = time.time()

    def _exp(self, exporter):
        e = self.exporters.get(exporter)
        if e is None:
            if len(self.exporters) > 500:
                self.exporters.clear()
            e = self.exporters[exporter] = {"packets": 0, "flows": 0, "matched": 0, "last": None, "version": 0,
                                            "rid": None, "routers": {}, "bytes": 0, "first": now()}
        return e

    def handle(self, data, exporter, src_port=0, rid=None, label=None):
        """exporter: sender IP. src_port tells apart routers behind one NAT address (their templates differ);
        rid: router fixed by a dedicated listening port."""
        self.stats["packets"] += 1
        label = label or exporter
        e = self._exp(label)
        e["packets"] += 1
        e["bytes"] += len(data) + 28        # + UDP/IP headers: what the link carries
        e["last"] = now()
        e["rid"] = rid
        if len(data) < 4:
            return
        version = struct.unpack("!H", data[0:2])[0]
        e["version"] = version
        if version == 5:
            flows = parse_v5(data)
        elif version in (9, 10):
            flows = self.parser.parse(data, f"{exporter}:{src_port}" if src_port else exporter)
        else:
            return
        self.refresh_ip_map()
        ts = now()
        for f in flows:
            self.add_flow(f, ts, exporter, rid, label)

    def _user(self, ip, hint):
        """(user id, router id) of the active session with this IP; the hinted router wins when routers of
        several offices give out the same addresses."""
        c = self.ip_user.get(ip) if ip else None
        if not c:
            return None
        if hint is not None and len(c) > 1:
            for hit in c:
                if hit[1] == hint:
                    return hit
        return c[0]

    def add_flow(self, f, ts, exporter="", rid=None, sender=None):
        self.stats["flows"] += 1
        e = self._exp(sender or exporter) if exporter else None
        if e:
            e["flows"] += 1
        # routers behind NAT all reach us from one address: the router of the user's session tells them apart
        hint = rid if rid is not None else netscope.scope.router_id(exporter) if exporter else None
        try:
            netobjects.index.account(hint, f, ts)        # every device behind the router, user or not
        except Exception:
            log.exception("device traffic")
        hit = self._user(f["src"], hint) or self._user(f.get("post_src"), hint)
        if hit:
            remote, rport, down, up = f["dst"], f["dport"], 0, f["bytes"]
        else:
            hit = self._user(f["dst"], hint) or self._user(f.get("post_dst"), hint)
            if not hit:
                return
            remote, rport, down, up = f["src"], f["sport"], f["bytes"], 0
        uid, router = hit[0], (rid if rid is not None else hit[1] if hit[1] is not None else hint)
        self.stats["matched"] += 1
        if e:
            e["matched"] += 1
            e["routers"][router] = e["routers"].get(router, 0) + 1
        if router is not None:
            r = self.per_router.setdefault(router, {"matched": 0, "last": None})
            r["matched"] += 1
            r["last"] = ts
        where = netscope.scope.classify_for(router, remote, f.get("in_if", 0), f.get("out_if", 0))
        if where != "internet":
            cat, label = where, classifier.dns_map.lookup(remote) or remote
        else:
            cat, label = classifier.classify_flow(remote, rport, f["proto"], down)
        day, hour = ts.date(), ts.hour
        with self.lock:
            c = self.cat_buf[(uid, day, hour, cat)]
            c[0] += down
            c[1] += up
            c[2] += 1
            d = self.dom_buf[(uid, day, label[:255])]
            if not d[0] or d[0] in ("web", "other"):
                d[0] = cat
            d[1] += down
            d[2] += up

    def flush(self):
        netobjects.index.flush()
        with self.lock:
            cats, doms = self.cat_buf, self.dom_buf
            self.cat_buf, self.dom_buf = defaultdict(lambda: [0, 0, 0]), defaultdict(lambda: ["", 0, 0])
        if not cats and not doms:
            return
        db = SessionLocal()
        try:
            for (uid, day, hour, cat), (down, up, n) in cats.items():
                row = db.query(TrafficCategory).filter_by(user_id=uid, day=day, hour=hour, category=cat).first()
                if row is None:
                    db.add(TrafficCategory(user_id=uid, day=day, hour=hour, category=cat, bytes_down=down,
                                           bytes_up=up, flows=n))
                else:
                    row.bytes_down += down
                    row.bytes_up += up
                    row.flows += n
            for (uid, day, dom), (cat, down, up) in doms.items():
                row = db.query(TrafficDomain).filter_by(user_id=uid, day=day, domain=dom).first()
                if row is None:
                    db.add(TrafficDomain(user_id=uid, day=day, domain=dom, category=cat, bytes_down=down,
                                         bytes_up=up))
                else:
                    row.bytes_down += down
                    row.bytes_up += up
                    if row.category in ("web", "other") and cat not in ("web", "other"):
                        row.category = cat
            db.commit()
        except Exception:
            db.rollback()
            log.exception("flush failed")
        finally:
            db.close()
            SessionLocal.remove()

    def serve(self, sock, port, rid=None):
        while True:
            got = udp.recv(sock, 65535)
            if got is None:
                return
            data, addr = got
            if rid is None:
                fixed, label = None, addr[0]
            else:
                fixed, label = self.ports.get(port), f"{addr[0]} → {port}"
                if fixed is None:               # port taken off the router: ignore what still arrives
                    continue
            try:
                self.handle(data, addr[0], addr[1], fixed, label)
            except Exception:
                log.exception("bad flow packet from %s", addr[0])

    def sync_ports(self):
        """Listen on the dedicated Traffic-Flow ports of routers (a router behind NAT whose users' IPs overlap
        another office's can send to its own port)."""
        if not self.started:
            return
        db = SessionLocal()
        try:
            wanted = {n.flow_port: n.id for n in db.query(Nas).filter(Nas.flow_port > 0)
                      if n.flow_port != config.NETFLOW_PORT}
        finally:
            db.close()
            SessionLocal.remove()
        for port, rid in wanted.items():
            if port in self.ports:
                self.ports[port] = rid
                continue
            try:
                sock = udp.listen(config.NETFLOW_BIND, port, rcvbuf=4 * 1024 * 1024)
            except OSError as e:
                log.warning("Traffic-Flow port %s could not be opened: %s", port, e)
                continue
            udp.allow_firewall(port, f"MikroTik Accounting - NetFlow {port}")
            self.ports[port] = rid
            threading.Thread(target=self.serve, args=(sock, port, rid), daemon=True, name=f"netflow-{port}").start()
            log.info("Traffic-Flow port %s for router %s", port, rid)
        for port in list(self.ports):
            if port not in wanted:
                self.ports[port] = None

    def start(self):
        s = udp.listen(config.NETFLOW_BIND, config.NETFLOW_PORT, rcvbuf=4 * 1024 * 1024)
        log.info("NetFlow collector on %s:%s", config.NETFLOW_BIND, config.NETFLOW_PORT)
        threading.Thread(target=self.serve, args=(s, config.NETFLOW_PORT), daemon=True, name="netflow").start()
        self.started = True
        try:
            self.sync_ports()
        except Exception:
            log.exception("dedicated Traffic-Flow ports")

        def flusher():
            while True:
                time.sleep(30)
                self.flush()
        threading.Thread(target=flusher, daemon=True, name="netflow-flush").start()


collector = Collector()
