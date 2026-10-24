"""سرورها، دوربین‌ها، تلفن‌ها و ... هر دفتر و ترافیک هر دستگاه پشت هر روتر (از NetFlow، مستقل از کاربر هات‌اسپات):
هر جریان به دستگاه محلی (IP -> MAC) و مقصد آن (اینترنت / تانل / شبکه داخلی / یکی از سرورها و دستگاه‌های تعریف‌شده)
نسبت داده می‌شود."""
import ipaddress
import logging
import threading
import time
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import func

from . import devices, netscope
from .db import Device, DeviceTraffic, Nas, NetObject, SessionLocal, now

log = logging.getLogger("netobjects")

KINDS = [("server", "سرور"), ("camera", "دوربین"), ("nvr", "ضبط تصویر (NVR/DVR)"), ("phone", "تلفن"),
         ("pbx", "سرور تلفن (ایزابل)"), ("printer", "پرینتر"), ("other", "سایر")]
KIND_FA = dict(KINDS)
TARGET_FA = {"internet": "اینترنت", "tunnel": "تانل (دفاتر دیگر)", "lan": "شبکه داخلی"}
# device types (devices page) that count as cameras / phones even without an object
TYPE_KIND = {"camera": "camera", "nvr": "nvr", "phone": "phone"}


class Index:
    def __init__(self):
        self.lock = threading.Lock()
        self.ts = 0
        self.objects = []           # [(network, NetObject-like dict)]
        self.by_id = {}
        self.ip_mac = {}            # (nas_id, ip) -> mac
        self.ip_mac_any = {}        # ip -> mac (newest)
        self.buf = defaultdict(lambda: [0, 0, 0])

    def refresh(self, force=False):
        if not force and time.time() - self.ts < 60:
            return
        db = SessionLocal()
        try:
            objs, by_id = [], {}
            for o in db.query(NetObject).all():
                d = {"id": o.id, "nas_id": o.nas_id, "kind": o.kind, "name": o.name, "sensitive": bool(o.sensitive),
                     "allowed_from": o.allowed_from or ""}
                by_id[o.id] = d
                for n in netscope.parse_ranges(o.addresses)[0]:
                    objs.append((n, d))
            objs.sort(key=lambda x: -x[0].prefixlen)         # the most specific address first
            ip_mac, any_ = {}, {}
            since = now() - timedelta(days=2)
            for mac, ip, nid in db.query(Device.mac, Device.last_ip, Device.last_nas_id) \
                    .filter(Device.last_ip != "", Device.last_seen >= since).order_by(Device.last_seen):
                ip_mac[(nid, ip)] = mac
                any_[ip] = mac
        finally:
            db.close()
            SessionLocal.remove()
        with self.lock:
            self.objects, self.by_id, self.ip_mac, self.ip_mac_any = objs, by_id, ip_mac, any_
        self.ts = time.time()

    def match(self, rid, ip, where=None):
        """The object at this address as seen from router rid (an object of another office with the same address as
        a device of this office's LAN does not match)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for n, o in self.objects:
            if a.version != n.version or a not in n:
                continue
            if o["nas_id"] in (None, rid):
                return o
            if where != "lan" and best is None:
                best = o
        return best

    def is_local(self, rid, ip):
        r = netscope.scope.routers.get(rid)
        if r is None:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if r["lan"]:
            return netscope._in(a, r["lan"])
        return netscope._in(a, netscope.scope.internal) and not netscope._in(a, r.get("tun_nets", [])) \
            and (rid, ip) in self.ip_mac

    def mac(self, rid, ip):
        return self.ip_mac.get((rid, ip)) or self.ip_mac_any.get(ip, "")

    def account(self, rid, f, ts):
        """One flow seen by router rid -> the local device's traffic to its destination."""
        if rid is None:
            return
        self.refresh()
        src, dst, b = f["src"], f["dst"], f["bytes"]
        s_loc, d_loc = self.is_local(rid, src), self.is_local(rid, dst)
        if s_loc and d_loc:
            # inside the office: the device talking to a known object is the local side
            if self.match(rid, src, "lan") and not self.match(rid, dst, "lan"):
                local, remote, down, up = dst, src, b, 0
            else:
                local, remote, down, up = src, dst, 0, b
        elif s_loc:
            local, remote, down, up = src, dst, 0, b
        elif d_loc:
            local, remote, down, up = dst, src, b, 0
        else:
            return
        where = netscope.scope.classify_for(rid, remote, f.get("in_if", 0), f.get("out_if", 0))
        robj = self.match(rid, remote, where)
        lobj = self.match(rid, local, "lan")
        if robj and robj.get("sensitive") and (not lobj or lobj["id"] != robj["id"]):
            try:
                from . import access
                access.flow_alarm(SessionLocal, rid, local, robj, ts)
            except Exception:              # noqa: BLE001 - an alarm must not lose the flow
                log.exception("sensitive access alarm")
        key = (rid, ts.date(), self.mac(rid, local), local, "obj" if robj else where,
               robj["id"] if robj else 0, lobj["id"] if lobj else 0)
        with self.lock:
            e = self.buf[key]
            e[0] += down
            e[1] += up
            e[2] += 1

    def flush(self):
        with self.lock:
            buf, self.buf = self.buf, defaultdict(lambda: [0, 0, 0])
        if not buf:
            return
        db = SessionLocal()
        try:
            for (rid, day, mac, ip, target, oid, lid), (down, up, n) in buf.items():
                row = db.query(DeviceTraffic).filter_by(nas_id=rid, day=day, mac=mac, ip=ip, target=target,
                                                        obj_id=oid, local_obj=lid).first()
                if row is None:
                    db.add(DeviceTraffic(nas_id=rid, day=day, mac=mac, ip=ip, target=target, obj_id=oid,
                                         local_obj=lid, bytes_down=down, bytes_up=up, flows=n))
                else:
                    row.bytes_down += down
                    row.bytes_up += up
                    row.flows += n
            db.commit()
        except Exception:
            db.rollback()
            log.exception("device traffic flush failed")
        finally:
            db.close()
            SessionLocal.remove()


index = Index()


def cleanup(db, days):
    db.query(DeviceTraffic).filter(DeviceTraffic.day < (now() - timedelta(days=days)).date()).delete()


# ------------------------------------------------------------------ reports
def report(db, start, end, nas_ids):
    """Office / router report from device traffic: totals per destination group, per object, per device."""
    d1, d2 = start.date(), (end - timedelta(seconds=1)).date()
    q = db.query(DeviceTraffic.nas_id, DeviceTraffic.mac, DeviceTraffic.ip, DeviceTraffic.target, DeviceTraffic.obj_id,
                 DeviceTraffic.local_obj, func.sum(DeviceTraffic.bytes_down), func.sum(DeviceTraffic.bytes_up)) \
        .filter(DeviceTraffic.day >= d1, DeviceTraffic.day <= d2, DeviceTraffic.nas_id.in_(list(nas_ids) or [-1])) \
        .group_by(DeviceTraffic.nas_id, DeviceTraffic.mac, DeviceTraffic.ip, DeviceTraffic.target,
                  DeviceTraffic.obj_id, DeviceTraffic.local_obj)
    rows = q.all()
    objs = {o.id: o for o in db.query(NetObject)}
    macs = {r[1] for r in rows if r[1]}
    devs = {d.mac: d for d in db.query(Device).filter(Device.mac.in_(macs or {"-"}))} if macs else {}
    nas_names = {n.id: n.name for n in db.query(Nas)}

    groups = {k: {"key": k, "name": v, "down": 0, "up": 0} for k, v in TARGET_FA.items()}
    by_obj, by_dev = {}, {}
    kinds = defaultdict(lambda: {"down": 0, "up": 0, "items": set()})
    for nid, mac, ip, target, oid, lid, down, up in rows:
        down, up = int(down or 0), int(up or 0)
        dev = devs.get(mac)
        dkey = mac or ip
        e = by_dev.setdefault((nid, dkey), {"nas_id": nid, "router": nas_names.get(nid, "?"), "mac": mac, "ips": set(),
                                            "device": dev, "internet": 0, "tunnel": 0, "lan": 0, "objects": 0,
                                            "total": 0, "local_obj": objs.get(lid)})
        e["ips"].add(ip)
        e["total"] += down + up
        if target == "obj":
            o = objs.get(oid)
            e["objects"] += down + up
            if o is not None:
                x = by_obj.setdefault(oid, {"obj": o, "router": nas_names.get(o.nas_id, "همه دفاتر"), "down": 0,
                                            "up": 0, "devices": set(), "internet": 0, "tunnel": 0, "lan": 0})
                x["down"] += up            # the object's own view: what the devices sent is its download
                x["up"] += down
                x["devices"].add(dkey)
                k = kinds[o.kind]
                k["down"] += down
                k["up"] += up
                k["items"].add(o.id)
        else:
            g = groups[target]
            g["down"] += down
            g["up"] += up
            e[target] += down + up
        # the local device is a camera / phone ... (object or device type): its own traffic, wherever it goes
        lo = objs.get(lid)
        if lo is not None:
            x = by_obj.setdefault(lid, {"obj": lo, "router": nas_names.get(lo.nas_id, "همه دفاتر"), "down": 0, "up": 0,
                                        "devices": set(), "internet": 0, "tunnel": 0, "lan": 0})
            x["down"] += down
            x["up"] += up
            if target in ("internet", "tunnel", "lan"):
                x[target] += down + up
            k = kinds[lo.kind]
            k["down"] += down
            k["up"] += up
            k["items"].add(lo.id)
        elif dev is not None and dev.device_type in TYPE_KIND:
            k = kinds[TYPE_KIND[dev.device_type]]
            k["down"] += down
            k["up"] += up
            k["items"].add("d" + mac)
    total = sum(e["total"] for e in by_dev.values())
    devices_rows = sorted(by_dev.values(), key=lambda e: -e["total"])
    for e in devices_rows:
        e["ips"] = "، ".join(sorted(e["ips"]))
        d = e["device"]
        e["type"] = devices.TYPE_FA.get(d.device_type, "") if d else ""
        e["name"] = (d.label or d.hostname) if d else ""
        e["windows_user"] = d.logon_user if d else ""
        e["hotspot_user"] = d.last_user if d else ""
    obj_rows = sorted(by_obj.values(), key=lambda x: -(x["down"] + x["up"]))
    for x in obj_rows:
        x["devices"] = len(x["devices"])
        x["total"] = x["down"] + x["up"]
    return {
        "total": total,
        "groups": [dict(g, total=g["down"] + g["up"]) for g in groups.values()],
        "objects_total": sum(e["objects"] for e in devices_rows),
        "kinds": [{"kind": k, "name": KIND_FA.get(k, k), "total": v["down"] + v["up"], "down": v["down"], "up": v["up"],
                   "count": len(v["items"])} for k, v in sorted(kinds.items(), key=lambda kv: -(kv[1]["down"] + kv[1]["up"]))],
        "objects": obj_rows,
        "devices": devices_rows,
        "has_data": bool(rows),
    }
