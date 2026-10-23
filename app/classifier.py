"""دسته‌بندی ترافیک: استریم ویدیو، دانلود، وب‌گردی، شبکه اجتماعی، پیام‌رسان، بازی و ..."""
import ipaddress
import threading

from . import config

CATEGORIES = {
    "video": "استریم ویدیو",
    "music": "موسیقی و پادکست",
    "social": "شبکه‌های اجتماعی",
    "messaging": "پیام‌رسان",
    "voip": "تماس و ویدیوکنفرانس",
    "download": "دانلود فایل",
    "update": "به‌روزرسانی سیستم/اپ",
    "cloud": "فضای ابری",
    "gaming": "بازی آنلاین",
    "ai": "هوش مصنوعی",
    "email": "ایمیل",
    "vpn": "VPN / پروکسی",
    "p2p": "تورنت / P2P",
    "dns": "DNS",
    "web": "وب‌گردی",
    "other": "سایر",
    "lan": "شبکه داخلی",
    "tunnel": "تانل (شبکه دفاتر دیگر)",
}

# (category, domain suffixes / keywords). Checked in order: first match wins.
DOMAIN_RULES = [
    ("update", ["windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "dl.delivery.mp",
                "swcdn.apple.com", "mesu.apple.com", "updates.cdn-apple.com", "gvt1.com", "gvt2.com",
                "play.googleapis.com", "android.clients.google.com", "update.googleapis.com",
                "archive.ubuntu.com", "security.ubuntu.com", "update.miui.com", "ota.", "officecdn.microsoft.com",
                "download.windowsupdate", "tlu.dl.delivery", "msedge.net", "appldnld.apple.com"]),
    ("video", ["googlevideo.com", "youtube.com", "youtu.be", "ytimg.com", "youtube-nocookie.com", "yt3.ggpht.com",
               "aparat.com", "aparat.cam", "filimo.com", "namava.ir", "telewebion.com", "telewebion.ir",
               "filmnet.ir", "tamasha.com", "uptvs.com", "lenz.ir", "anten.ir", "sepehrtv.ir", "tva.tv",
               "netflix.com", "nflxvideo.net", "nflxso.net", "nflxext.com", "twitch.tv", "ttvnw.net", "jtvnw.net",
               "vimeo.com", "vimeocdn.com", "dailymotion.com", "dmcdn.net", "tiktokcdn.com", "tiktokv.com",
               "tiktok.com", "byteoversea.com", "ibytedtos.com", "musical.ly", "primevideo.com", "aiv-cdn.net",
               "hulu.com", "disneyplus.com", "dssott.com", "bamgrid.com", "hbomax.com", "max.com", "kick.com"]),
    ("music", ["spotify.com", "scdn.co", "spotifycdn.com", "soundcloud.com", "sndcdn.com", "deezer.com",
               "radiojavan.com", "rjassets.com", "navaak.com", "music.apple.com", "castbox.fm", "beeptunes.com"]),
    ("social", ["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com",
                "twitter.com", "twimg.com", "x.com", "linkedin.com", "licdn.com", "snapchat.com", "sc-cdn.net",
                "pinterest.com", "pinimg.com", "reddit.com", "redd.it", "redditmedia.com", "threads.net",
                "rubika.ir", "iranlms.ir", "virasty.com"]),
    ("messaging", ["telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org", "whatsapp.net",
                   "whatsapp.com", "wa.me", "signal.org", "viber.com", "eitaa.com", "bale.ai", "splus.ir",
                   "igap.net", "gap.im", "discord.com", "discordapp.com", "discord.gg", "discordapp.net"]),
    ("voip", ["zoom.us", "zoom.com", "zoomgov.com", "teams.microsoft.com", "teams.live.com", "skype.com",
              "webex.com", "meet.google.com", "skyroom.online", "bigbluebutton", "adobeconnect", "gotomeeting",
              "anydesk.com", "teamviewer.com"]),
    ("ai", ["openai.com", "chatgpt.com", "oaiusercontent.com", "claude.ai", "anthropic.com", "gemini.google.com",
            "perplexity.ai", "deepseek.com", "copilot.microsoft.com", "midjourney.com", "huggingface.co"]),
    ("gaming", ["steampowered.com", "steamcontent.com", "steamserver.net", "steamstatic.com", "epicgames.com",
                "epicgames.dev", "xboxlive.com", "playstation.net", "playstation.com", "riotgames.com", "ea.com",
                "battle.net", "blizzard.com", "pubgmobile.com", "igamecj.com", "supercell.com", "roblox.com",
                "rbxcdn.com", "callofduty.com", "activision.com", "garena.com", "mihoyo.com", "hoyoverse.com"]),
    ("cloud", ["drive.google.com", "docs.google.com", "dropbox.com", "dropboxusercontent.com", "onedrive.live.com",
               "1drv.ms", "sharepoint.com", "icloud.com", "icloud-content.com", "box.com", "mega.nz", "mega.co.nz",
               "pcloud.com", "wetransfer.com"]),
    ("download", ["download", "dl.", "dl1.", "dl2.", "dl3.", "cdn.downloads", "sourceforge.net",
                  "objects.githubusercontent.com", "github-releases", "releases.", "mediafire.com", "uploadboy",
                  "uptobox", "p30download", "soft98", "sarzamindownload", "downloadha", "yasdl", "dlfile",
                  "filehippo", "apkpure", "apkmirror", "cafebazaar.ir", "myket.ir", "fosshub", "videolan.org",
                  "nvidia.com/download", "dl.google.com", "redirector.gvt1.com", "1fichier", "rapidgator",
                  "nitroflare", "uploaded.net", "picofile.com", "s3.amazonaws.com", "akamaihd.net"]),
    ("email", ["mail.", "imap.", "smtp.", "pop.", "outlook.office365.com", "outlook.com", "mail.google.com",
               "mail.yahoo.com", "zoho.com"]),
]

# Well-known IP ranges (used when DNS name is unknown, e.g. DoH clients).
IP_RULES = [
    ("messaging", "Telegram", ["91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
                   "91.108.56.0/22", "149.154.160.0/20", "95.161.64.0/20", "91.105.192.0/23", "185.76.151.0/24"]),
    ("social", "Meta (Instagram/WhatsApp/Facebook)", ["157.240.0.0/16", "31.13.24.0/21", "31.13.64.0/18", "179.60.192.0/22", "69.171.224.0/19",
                "66.220.144.0/20", "173.252.64.0/18", "129.134.0.0/16", "163.70.128.0/17"]),
    ("video", "Netflix", ["23.246.0.0/18", "37.77.184.0/21", "45.57.0.0/17", "64.120.128.0/17", "66.197.128.0/17",
               "108.175.32.0/20", "185.2.220.0/22", "185.9.188.0/22", "192.173.64.0/18", "198.38.96.0/19",
               "198.45.48.0/20"]),  # Netflix Open Connect
    ("google", "Google", ["142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16", "216.58.192.0/19", "74.125.0.0/16",
                "173.194.0.0/16", "209.85.128.0/17", "64.233.160.0/19", "108.177.0.0/17", "216.239.32.0/19"]),
    ("voip", "Zoom/Teams", ["3.7.35.0/25", "170.114.0.0/16", "52.112.0.0/14", "52.122.0.0/15"]),  # Zoom / Teams media
]

PORT_RULES = [  # (proto or None, port set, category)
    (None, {53, 853}, "dns"),
    (None, {25, 465, 587, 110, 995, 143, 993}, "email"),
    (None, {1194, 1701, 1723, 51820, 500, 4500, 8443, 1080, 9050, 9150, 2408}, "vpn"),
    (17, {3478, 3479, 3480, 3481, 5060, 5061, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309,
          8801, 8802, 8803, 8804, 8805, 8806, 8807, 8808, 8809, 8810}, "voip"),
    (None, set(range(6881, 7000)) | {51413, 6969, 1337, 2710}, "p2p"),
    (None, {27015, 27016, 27017, 27018, 27019, 27020, 3074, 3075, 3659, 9330, 9331, 10012, 17500}, "gaming"),
    (None, {80, 443, 8080, 8000, 8008, 8888}, "web"),
]
IP_PROTO_CATEGORY = {47: "vpn", 50: "vpn", 51: "vpn"}  # GRE / ESP / AH

_ip_nets = [(cat, name, ipaddress.ip_network(n)) for cat, name, nets in IP_RULES for n in nets]

SECOND_LEVEL = {"co", "com", "ac", "org", "net", "gov", "sch", "edu", "id"}


def base_domain(name: str) -> str:
    parts = name.lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def category_of_domain(name: str):
    n = (name or "").lower().rstrip(".")
    if not n:
        return None
    for cat, rules in DOMAIN_RULES:
        for r in rules:
            if r.endswith("."):  # host label prefix, e.g. "dl." matches dl.example.com
                if n.startswith(r) or ("." + r) in n:
                    return cat
            elif "/" in r or "." not in r:  # keyword
                if r.split("/")[0] in n:
                    return cat
            elif n == r or n.endswith("." + r):
                return cat
    return None


def category_of_ip(ip: str):
    """Returns (category, network name) or (None, None)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    for cat, name, net in _ip_nets:
        if a.version == net.version and a in net:
            return cat, name
    return None, None


class DnsMap:
    """IP -> best domain name, built from the router's DNS cache (A/AAAA + CNAME chains)."""

    def __init__(self):
        self.ip2name = {}
        self.lock = threading.Lock()

    def update(self, entries):
        cname_rev = {}
        for e in entries:
            if e.get("type") == "CNAME" and e.get("data"):
                cname_rev[e["data"].lower().rstrip(".")] = e.get("name", "").lower().rstrip(".")
        new = {}
        for e in entries:
            if e.get("type") not in ("A", "AAAA") or not e.get("data"):
                continue
            name = e.get("name", "").lower().rstrip(".")
            chain, seen = [name], {name}
            while chain[-1] in cname_rev and cname_rev[chain[-1]] not in seen and len(chain) < 10:
                chain.append(cname_rev[chain[-1]])
                seen.add(chain[-1])
            # prefer the name that classifies; otherwise the original (top of the chain)
            best = next((c for c in chain if category_of_domain(c)), chain[-1])
            new[str(e["data"])] = best
        with self.lock:
            self.ip2name.update(new)
            if len(self.ip2name) > 500000:
                self.ip2name = new

    def lookup(self, ip):
        return self.ip2name.get(ip)


dns_map = DnsMap()


def classify_flow(remote_ip: str, remote_port: int, proto: int, bytes_down: int, domain: str = None):
    """Returns (category, label for 'domain' column)."""
    domain = domain or dns_map.lookup(remote_ip)
    cat = category_of_domain(domain) if domain else None
    label = base_domain(domain) if domain else remote_ip
    if cat is None:
        ipcat, netname = category_of_ip(remote_ip)
        if netname and not domain:
            label = netname
        if ipcat == "google":
            # QUIC/HTTPS heavy flows from Google networks are almost always YouTube video
            cat = "video" if bytes_down > 5 * 1024 * 1024 else "web"
        elif ipcat:
            cat = ipcat
    if cat is None and proto in IP_PROTO_CATEGORY:
        cat = IP_PROTO_CATEGORY[proto]
    if cat is None:
        for p, ports, c in PORT_RULES:
            if (p is None or p == proto) and remote_port in ports:
                cat = c
                break
    if cat is None:
        cat = "p2p" if proto == 17 and remote_port > 10000 and bytes_down > 1024 * 1024 else "other"
    # A single large flow on generic web traffic is a file download
    if cat in ("web", "other") and bytes_down >= config.BIG_FLOW_BYTES:
        cat = "download"
    return cat, label
