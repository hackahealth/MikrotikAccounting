"""تشخیص نوع دستگاه (رایانه / موبایل / تبلت) از روی MAC، نام میزبان، DHCP و User-Agent."""
import os
import re

from datetime import timedelta

from . import config
from .db import Device, DeviceHistory, now

_OUI = None

MOBILE_VENDORS = ["samsung", "xiaomi", "huawei", "honor", "oppo", "vivo", "oneplus", "realme", "motorola",
                  "nokia", "sony mobile", "lg electronics", "htc", "zte", "tecno", "infinix", "itel", "meizu",
                  "lenovo mobile", "google", "nothing technology", "transsion", "guangdong oppo", "fiberhome"]
PC_VENDORS = ["intel", "realtek", "dell", "hewlett", "hp inc", "lenovo", "asustek", "micro-star", "gigabyte",
              "liteon", "lite-on", "azurewave", "qualcomm atheros", "atheros", "acer", "toshiba", "msi",
              "foxconn", "hon hai", "pegatron", "elitegroup", "microsoft", "vmware", "broadcom", "killer",
              "chicony", "wistron", "quanta", "compal", "tp-link", "d-link"]
TV_VENDORS = ["roku", "lg innotek", "tcl", "hisense", "skyworth", "amlogic"]
# network equipment, checked before the PC / mobile vendor lists (e.g. "Aruba, a Hewlett Packard Enterprise")
EQUIPMENT_VENDORS = [
    ("printer", ["brother", "kyocera", "epson", "ricoh", "xerox", "lexmark", "konica", "pantum", "zebra",
                 "sharp corporation", "canon"]),
    ("phone", ["grandstream", "yealink", "fanvil", "snom", "polycom", "avaya", "htek", "akuvox", "escene"]),
    ("camera", ["hikvision", "dahua", "uniview", "axis communications", "vivotek", "milesight"]),
    ("thin", ["wyse", "ncomputing", "igel", "10zig", "atrust", "centerm"]),
    ("router", ["routerboard", "mikrotik"]),
    ("ap", ["ubiquiti", "ruckus", "aruba", "cambium", "engenius"]),
    ("switch", ["cisco systems", "juniper", "h3c", "hewlett packard enterprise"]),
    ("storage", ["synology", "qnap"]),
    ("ups", ["eaton", "american power conversion", "schneider electric"]),
]

HOSTNAME_RULES = [
    (r"^npi[0-9a-f]{6}|^brw[0-9a-f]{6}|^epson|^kmb[0-9a-f]|^km[0-9a-f]{6}|^canon|^ricoh|^xrx|^et[0-9a-f]{12}|printer|^prn",
     "printer", ""),
    (r"scanner|^scan", "scanner", ""),
    (r"^sep[0-9a-f]{12}|^yealink|^grandstream|^gxp|^grp\d|^fanvil|^snom|voip|ipphone", "phone", ""),
    (r"^wyse|^igel|^tc-|thin|^hpt\d|^t6\d\d", "thin", ""),
    (r"^ipc|^dvr|^nvr|^hik|^dh-|camera|^cam\d", "camera", ""),
    (r"^mikrotik|^routeros", "router", ""),
    (r"^srv|server", "server", "Windows Server"),
    (r"^(iphone|.*s-iphone)", "mobile", "iOS"),
    (r"ipad", "tablet", "iPadOS"),
    (r"^android|galaxy|redmi|poco|^mi-|^m2\d|huawei|honor|oppo|vivo|oneplus|realme|nokia|^sm-|motorola|moto",
     "mobile", "Android"),
    (r"^desktop-|^laptop-|^win-|-pc$|^pc-|windows", "pc", "Windows"),
    (r"macbook|imac|mac-?mini|mac-?pro", "pc", "macOS"),
    (r"ubuntu|debian|fedora|linux|arch", "pc", "Linux"),
    (r"chromebook|^cros", "pc", "ChromeOS"),
    (r"tv|bravia|roku|firetv|chromecast|smarttv", "tv", "SmartTV"),
]


def _load_oui():
    global _OUI
    if _OUI is None:
        _OUI = {}
        path = os.path.join(config.BASE_DIR, "data", "oui.txt")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t", 1)
                    if len(p) == 2:
                        _OUI[p[0]] = p[1]
    return _OUI


def normalize_mac(mac: str) -> str:
    h = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(h) != 12:
        return ""
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def vendor_of(mac: str) -> str:
    m = normalize_mac(mac)
    return _load_oui().get(m.replace(":", "")[:6], "") if m else ""


def is_random_mac(mac: str) -> bool:
    m = normalize_mac(mac)
    return bool(m) and (int(m[:2], 16) & 0x02) != 0


def from_user_agent(ua: str):
    u = (ua or "").lower()
    if not u:
        return None
    if "ipad" in u or ("macintosh" in u and "mobile" in u):
        return "tablet", "iPadOS"
    if "iphone" in u:
        return "mobile", "iOS"
    if "android" in u:
        return ("mobile" if "mobile" in u else "tablet"), "Android"
    if "windows phone" in u:
        return "mobile", "Windows Phone"
    if "smart-tv" in u or "smarttv" in u or "tizen" in u or "webos" in u:
        return "tv", "SmartTV"
    if "windows nt" in u:
        return "pc", "Windows"
    if "cros" in u:
        return "pc", "ChromeOS"
    if "macintosh" in u or "mac os x" in u:
        return "pc", "macOS"
    if "linux" in u or "x11" in u:
        return "pc", "Linux"
    return None


def from_dhcp_class(cls: str):
    c = (cls or "").lower()
    if c.startswith("android-dhcp") or c.startswith("dhcpcd") and "android" in c:
        return "mobile", "Android"
    if c.startswith("msft"):
        return "pc", "Windows"
    if c.startswith("dhcpcd"):
        return "pc", "Linux"
    return None


def from_hostname(h: str):
    h = (h or "").lower()
    if not h:
        return None
    for pattern, typ, os_ in HOSTNAME_RULES:
        if re.search(pattern, h):
            return typ, os_
    return None


def from_vendor(v: str):
    v = (v or "").lower()
    if not v:
        return None
    for typ, names in EQUIPMENT_VENDORS:
        if any(x in v for x in names):
            return typ, ""
    if "apple" in v:
        return "mobile", "Apple"  # majority of Apple devices on Wi-Fi are iPhones; refined by hostname/UA
    if any(x in v for x in MOBILE_VENDORS):
        return "mobile", "Android"
    if any(x in v for x in TV_VENDORS):
        return "tv", ""
    if any(x in v for x in PC_VENDORS):
        return "pc", ""
    return None


GENERIC = ("pc", "mobile", "tablet", "tv")


def classify(mac="", hostname="", dhcp_class="", user_agent=""):
    """Returns dict(device_type, os, vendor, random_mac, detected_by)."""
    rnd = is_random_mac(mac)
    vendor = "" if rnd else vendor_of(mac)
    by_host, by_vendor = from_hostname(hostname), from_vendor(vendor)
    # printers / phones / thin clients... also send "MSFT 5.0" or "dhcpcd" as DHCP class: their name or maker wins
    for name, res in (("hostname", by_host), ("mac-vendor", by_vendor)):
        if res and res[0] not in GENERIC:
            return {"device_type": res[0], "os": res[1], "vendor": vendor, "random_mac": rnd, "detected_by": name}
    for name, res in (("user-agent", from_user_agent(user_agent)), ("dhcp", from_dhcp_class(dhcp_class)),
                      ("hostname", by_host), ("mac-vendor", by_vendor)):
        if res:
            return {"device_type": res[0], "os": res[1], "vendor": vendor, "random_mac": rnd, "detected_by": name}
    if rnd:
        # iOS 14+ / Android 10+ use private (random) MACs on Wi-Fi by default
        return {"device_type": "mobile", "os": "", "vendor": "MAC تصادفی", "random_mac": True,
                "detected_by": "random-mac"}
    return {"device_type": "unknown", "os": "", "vendor": vendor, "random_mac": False, "detected_by": ""}


def upsert(db, mac, hostname=None, dhcp_class=None, user_agent=None, seen=False) -> Device:
    """Create/update a device and (re)classify it. seen=True marks it as present now."""
    m = normalize_mac(mac)
    if not m:
        return None
    d = db.query(Device).filter(Device.mac == m).first()
    if d is None:
        d = Device(mac=m)
        db.add(d)
    if hostname:
        d.hostname = str(hostname)[:150]
    if dhcp_class:
        d.dhcp_vendor_class = str(dhcp_class)[:150]
    if user_agent:
        d.user_agent = str(user_agent)[:500]
    r = classify(m, d.hostname, d.dhcp_vendor_class, d.user_agent)
    d.vendor, d.random_mac = r["vendor"], r["random_mac"]
    if d.detected_by != "manual":          # a type corrected by hand is kept
        d.device_type, d.os, d.detected_by = r["device_type"], r["os"], r["detected_by"]
    if seen or d.last_seen is None:
        d.last_seen = now()
    return d


# ------------------------------------------------------------------ device history (IP / user intervals)
HISTORY_GAP = timedelta(minutes=int(os.environ.get("DEVICE_HISTORY_GAP_MIN", "15")))
_open = {}      # (mac, kind, value, nas_id) -> (row id, last_seen) of the interval still open


def _interval(db, mac, kind, value, nas_id, source, ts):
    key = (mac, kind, value, nas_id)
    hit = _open.get(key)
    if hit is None:
        row = db.query(DeviceHistory).filter_by(mac=mac, kind=kind, value=value, nas_id=nas_id) \
            .order_by(DeviceHistory.last_seen.desc()).first()
        hit = (row.id, row.last_seen) if row else None
    if hit and ts - hit[1] <= HISTORY_GAP:
        if ts > hit[1]:
            db.query(DeviceHistory).filter(DeviceHistory.id == hit[0]).update({"last_seen": ts})
            hit = (hit[0], ts)
    else:
        row = DeviceHistory(mac=mac, kind=kind, value=value[:150], nas_id=nas_id, source=source, first_seen=ts,
                            last_seen=ts)
        db.add(row)
        db.flush()
        hit = (row.id, ts)
    if len(_open) > 200000:
        _open.clear()
    _open[key] = hit


def record(db, mac, ip="", user="", nas_id=None, source="", ts=None, hostname=None):
    """A device was seen now with this IP and/or logged-in user on this router."""
    m = normalize_mac(mac)
    if not m:
        return None
    ts = ts or now()
    ip, user = str(ip or "").strip(), str(user or "").strip()
    d = upsert(db, m, hostname=hostname)
    if d.id is None:                       # new device
        d.first_seen = d.last_seen = ts
    else:
        d.last_seen = max(d.last_seen or ts, ts)
        if d.first_seen is None or ts < d.first_seen:
            d.first_seen = ts
    if nas_id:
        d.last_nas_id = nas_id
    if ip:
        d.last_ip = ip[:45]
        _interval(db, m, "ip", ip, nas_id, source, ts)
    if user:
        d.last_user = user[:150]
        _interval(db, m, "user", user, nas_id, source, ts)
    return d


def stale_days(db):
    from .db import get_setting
    try:
        return max(1, int(get_setting(db, "device_stale_days", "30") or 30))
    except ValueError:
        return 30


TYPES = [("pc", "رایانه"), ("laptop", "لپ‌تاپ"), ("thin", "تین کلاینت"), ("server", "سرور"),
         ("mobile", "موبایل"), ("tablet", "تبلت"), ("printer", "پرینتر"), ("scanner", "اسکنر"),
         ("phone", "تلفن (VoIP)"), ("router", "روتر"), ("switch", "سوییچ"), ("ap", "اکسس پوینت / وای‌فای"),
         ("camera", "دوربین"), ("nvr", "دستگاه ضبط (NVR/DVR)"), ("storage", "ذخیره‌ساز (NAS)"),
         ("attendance", "حضور و غیاب"), ("ups", "UPS"), ("tv", "تلویزیون هوشمند"), ("other", "سایر"),
         ("unknown", "نامشخص")]
TYPE_FA = dict(TYPES, **{"": "نامشخص"})
COMPUTERS = ("pc", "laptop", "thin", "server")       # what the nightly list shows by default
