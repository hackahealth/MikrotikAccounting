"""Issabel PBX administration through its REST API (/pbxapi, JWT): extensions, ring groups, queues, trunks, routes,
IVR, time conditions ... Every resource of the API has the same shape (GET list / GET id?fields=* / POST / PUT id /
DELETE id); Issabel applies the configuration itself after each change.

TLS: Issabel ships a self-signed certificate. The admin pins it once on the PBX servers page (the certificate is
fetched, its SHA-256 fingerprint shown to compare with the server's own, then stored); calls then trust only that
certificate. Without a pinned certificate the normal system trust store is used."""
import hashlib
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .db import PbxServer, decrypt

log = logging.getLogger("pbxapi")

# known resources: (Persian label, id key in the list rows, extra list columns)
RESOURCES = {
    "extensions": ("داخلی‌ها", "extension", ["tech", "dial"]),
    "ringgroups": ("گروه‌های زنگ", "extension", ["strategy", "extension_list"]),
    "queues": ("صف‌ها", "extension", ["strategy", "timeout"]),
    "trunks": ("ترانک‌ها", "id", ["tech", "channelid"]),
    "inboundroutes": ("مسیرهای ورودی", "id", ["extension", "cidnum", "destination"]),
    "outboundroutes": ("مسیرهای خروجی", "id", ["outcid", "dest"]),
    "ivr": ("منوی صوتی (IVR)", "id", []),
    "timeconditions": ("شرط‌های زمانی", "id", []),
    "timegroups": ("گروه‌های زمانی", "id", []),
    "conferences": ("اتاق کنفرانس", "extension", []),
    "announcements": ("اعلان‌ها", "id", []),
    "recordings": ("صداهای ضبط‌شده", "id", ["filename"]),
    "callflow": ("کنترل جریان تماس (روز/شب)", "id", []),
    "miscdestinations": ("مقصدهای متفرقه", "id", ["destdial"]),
    "customdestinations": ("مقصدهای سفارشی", "id", []),
    "featurecodes": ("کدهای ویژه", "id", ["customcode", "enabled"]),
    "paging": ("پیجینگ و اینترکام", "extension", []),
    "parkinglots": ("پارک تماس", "id", ["parkext", "numslots"]),
    "blacklist": ("لیست سیاه", "id", []),
    "cidlookup": ("جستجوی نام تماس‌گیرنده", "id", ["sourcetype"]),
    "musiconhold": ("موزیک انتظار", "id", []),
    "languages": ("زبان‌ها", "id", ["lang_code"]),
    "disa": ("DISA", "id", ["cid"]),
    "callback": ("Callback", "id", ["callbacknum"]),
}
# resources that can be the destination of a call, and how Issabel writes that destination
DESTINATIONS = (("extensions", "from-did-direct,{e},1", "extension"), ("queues", "ext-queues,{e},1", "extension"),
                ("ringgroups", "ext-group,{e},1", "extension"), ("ivr", "ivr-{i},s,1", "id"),
                ("timeconditions", "timeconditions,{i},1", "id"), ("conferences", "ext-meetme,{e},1", "extension"),
                ("announcements", "app-announcement-{i},s,1", "id"), ("callflow", "app-daynight,{i},1", "id"),
                ("miscdestinations", "ext-miscdests,{i},1", "id"))
FIXED_DESTINATIONS = [("app-blackhole,hangup,1", "قطع تماس (Hangup)"), ("app-blackhole,busy,1", "اشغال (Busy)"),
                      ("app-blackhole,congestion,1", "Congestion")]

FIELD_FA = {
    "extension": "شماره", "name": "نام", "secret": "رمز SIP", "tech": "نوع (sip / pjsip / iax2)", "dial": "رشتهٔ شماره‌گیری",
    "voicemail.enabled": "صندوق صوتی", "voicemail.pin": "رمز صندوق صوتی", "voicemail.email": "ایمیل صندوق صوتی",
    "extension_options.ring_time": "مدت زنگ (ثانیه)", "extension_options.call_waiting": "انتظار تماس",
    "recording.inbound_external": "ضبط ورودی بیرونی", "recording.inbound_internal": "ضبط ورودی داخلی",
    "recording.outbound_external": "ضبط خروجی بیرونی", "recording.outbound_internal": "ضبط خروجی داخلی",
    "callerid_override.outbound": "شمارهٔ نمایشی خروجی", "strategy": "روش زنگ‌زدن", "timeout": "مهلت (ثانیه)",
    "extension_list": "اعضا (داخلی‌ها)", "ring_time": "مدت زنگ (ثانیه)", "destination": "مقصد",
    "destination_if_no_answer": "مقصد در صورت پاسخ ندادن", "cidnum": "شمارهٔ تماس‌گیرنده", "description": "توضیح",
    "outcid": "شمارهٔ نمایشی", "channelid": "نام کانال", "dest": "مقصد", "pin": "رمز", "password": "رمز",
    "time_group_id": "گروه زمانی", "destination_if_time_matches": "مقصد در زمان مجاز",
    "destination_if_time_does_not_match": "مقصد در زمان غیرمجاز",
}

_tokens = {}            # server id -> (token, time)
_lock = threading.Lock()
TOKEN_TTL = 50 * 60     # Issabel tokens last an hour


class PbxApiError(RuntimeError):
    pass


def enabled(server) -> bool:
    return bool(server and server.api_user and server.api_password_enc)


def base_url(server) -> str:
    u = (server.api_url or "").strip().rstrip("/")
    return u or f"https://{server.host}/pbxapi"


def fetch_certificate(server):
    """-> (pem, sha256 fingerprint) of the certificate the Issabel web server presents, to be pinned after the
    admin compares the fingerprint (Issabel: openssl x509 -in /etc/pki/tls/certs/localhost.crt -noout -fingerprint -sha256)."""
    u = urllib.parse.urlparse(base_url(server))
    if u.scheme != "https":
        raise PbxApiError("آدرس API با https نیست")
    try:
        pem = ssl.get_server_certificate((u.hostname, u.port or 443), timeout=15)
    except OSError as e:
        raise PbxApiError(f"دریافت گواهی ایزابل ممکن نشد: {e}") from e
    return pem, fingerprint(pem)


def fingerprint(pem):
    der = ssl.PEM_cert_to_DER_cert(pem)
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _ctx(server):
    pem = (server.api_cert or "").strip()
    if not pem:
        return ssl.create_default_context()
    ctx = ssl.create_default_context(cadata=pem)    # only the pinned certificate is trusted
    ctx.check_hostname = False                      # its name is the PBX's own (localhost.localdomain), not the IP
    return ctx


def _http(server, method, url, body=None, headers=None, timeout=30):
    data = None
    headers = dict(headers or {})
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        else:
            data = str(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        ctx = _ctx(server) if url.startswith("https") else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})
    except ssl.SSLError as e:
        raise PbxApiError("گواهی HTTPS ایزابل تأیید نشد؛ در صفحهٔ سرورهای ایزابل «دریافت و ثبت گواهی» را بزنید"
                          f" ({e.reason or e})") from e
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLError):
            raise PbxApiError("گواهی HTTPS ایزابل تأیید نشد؛ در صفحهٔ سرورهای ایزابل «دریافت و ثبت گواهی» را بزنید") from e
        raise PbxApiError(f"اتصال به API ایزابل ممکن نشد: {reason}") from e


def _json(text):
    try:
        return json.loads(text) if text.strip() else {}
    except ValueError:
        return {"raw": text[:300]}


def _errors(status, data):
    errs = data.get("errors") if isinstance(data, dict) else None
    if errs:
        return "؛ ".join(f"{e.get('source', '')} {e.get('detail', '')}".strip() for e in errs)[:500]
    if status == 403:
        return "دسترسی رد شد (کاربر و رمز API ایزابل را بررسی کنید)"
    if status == 404:
        return "پیدا نشد"
    return f"خطای {status}" + (f": {data.get('raw')}" if isinstance(data, dict) and data.get("raw") else "")


class Client:
    def __init__(self, server: PbxServer):
        if not enabled(server):
            raise PbxApiError(f"API ایزابل برای سرور {server.name if server else ''} تنظیم نشده (صفحهٔ سرورهای ایزابل)")
        self.server = server
        self.base = base_url(server)

    def login(self):
        body = urllib.parse.urlencode({"user": self.server.api_user,
                                       "password": decrypt(self.server.api_password_enc)})
        status, text, _ = _http(self.server, "POST", self.base + "/authenticate", body)
        data = _json(text)
        tok = data.get("access_token") if isinstance(data, dict) else None
        if status != 200 or not tok:
            raise PbxApiError("ورود به API ایزابل ناموفق بود: " + _errors(status, data))
        with _lock:
            _tokens[self.server.id] = (tok, time.time())
        return tok

    def _token(self):
        with _lock:
            t = _tokens.get(self.server.id)
        if t and time.time() - t[1] < TOKEN_TTL:
            return t[0]
        return self.login()

    def call(self, method, path, body=None, params=None):
        url = self.base + "/" + path.strip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params)
        for attempt in (0, 1):
            status, text, headers = _http(self.server, method, url, body,
                                          {"Authorization": "Bearer " + self._token()})
            data = _json(text)
            expired = isinstance(data, dict) and data.get("status") == "expired"
            if (status == 403 or expired) and attempt == 0:
                with _lock:
                    _tokens.pop(self.server.id, None)
                continue
            if status >= 400:
                raise PbxApiError(_errors(status, data))
            return status, data, headers
        raise PbxApiError("دسترسی رد شد")

    # ------------------------------------------------------------- generic resource calls
    def controllers(self):
        _, data, _ = self.call("GET", "")
        return list(data.get("controllers", [])) if isinstance(data, dict) else []

    def list(self, resource):
        _, data, _ = self.call("GET", resource)
        res = data.get("results", []) if isinstance(data, dict) else []
        return res if isinstance(res, list) else [res]

    def get(self, resource, rid):
        _, data, _ = self.call("GET", f"{resource}/{_q(rid)}", params={"fields": "*"})
        res = data.get("results", []) if isinstance(data, dict) else []
        if isinstance(res, list):
            if not res:
                raise PbxApiError("پیدا نشد")
            return res[0]
        return res

    def create(self, resource, fields, rid=""):
        """POST (next free number / id) or PUT with the number given. -> the new id."""
        if rid:
            self.call("PUT", f"{resource}/{_q(rid)}", fields)
            return str(rid)
        _, _, headers = self.call("POST", resource, fields)
        loc = headers.get("Location") or headers.get("location") or ""
        return loc.rstrip("/").rsplit("/", 1)[-1] if loc else ""

    def update(self, resource, rid, fields):
        self.call("PUT", f"{resource}/{_q(rid)}", fields)

    def delete(self, resource, rid):
        self.call("DELETE", f"{resource}/{_q(rid)}")


def _q(rid):
    return urllib.parse.quote(str(rid), safe=",^")


def row_id(resource, row):
    key = RESOURCES.get(resource, ("", "id", []))[1]
    return str(row.get(key) or row.get("id") or row.get("extension") or "")


def flatten(d, prefix=""):
    """{'a': {'b': 1}, 'l': [1, 2]} -> {'a.b': 1, 'l': [1, 2]} (lists stay lists)."""
    out = {}
    for k, v in (d or {}).items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(flatten(v, key))
        else:
            out[key] = v
    return out


def unflatten(flat):
    out = {}
    for k, v in flat.items():
        cur = out
        parts = k.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


def destinations(client, available=None):
    """[(destination, label)] of everything a call can be sent to."""
    out = list(FIXED_DESTINATIONS)
    for res, fmt, key in DESTINATIONS:
        if available is not None and res not in available:
            continue
        try:
            rows = client.list(res)
        except PbxApiError:
            continue
        for r in rows:
            e = str(r.get("extension", "") or "")
            i = str(r.get("id", "") or e)
            if not (e if key == "extension" else i):
                continue
            out.append((fmt.format(e=e, i=i), f"{RESOURCES[res][0]}: {('<' + e + '> ') if e else ''}{r.get('name', '')}"))
    return out


def used_numbers(client):
    used = set()
    for res in ("extensions", "queues", "ringgroups", "conferences", "paging"):
        try:
            used |= {str(r.get("extension", "")) for r in client.list(res)}
        except PbxApiError:
            pass
    return used


def free_numbers(used, ranges, count=15):
    """Extension numbers inside the server's ranges that no extension / queue / group / conference uses."""
    out = []
    if ranges:
        for lo, hi in ranges:
            n = lo
            while n <= hi and len(out) < count:
                if str(n) not in used:
                    out.append(str(n))
                n += 1
    else:
        nums = sorted(int(e) for e in used if e.isdigit())
        n = nums[0] if nums else 100
        while len(out) < count:
            if str(n) not in used:
                out.append(str(n))
            n += 1
    return out
