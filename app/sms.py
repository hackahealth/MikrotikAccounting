"""ارسال پیامک از طریق سامانه‌های پیامکی ایرانی (کاوه‌نگار، SMS.ir، ملی‌پیامک، فراز اس‌ام‌اس / IPPanel یا هر
وب‌سرویس HTTP دلخواه).

    sms.enabled(db) -> bool
    sms.send(db, mobile, text, purpose="", username="") -> (ok, error)

Every message starts with the title (setting sms_title, default «سامانه مدیریت شبکه تاپیک») and is logged in SmsLog.
Only the standard library is used (no new pip packages: they cannot be downloaded on the server)."""
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .db import SmsLog, decrypt, encrypt, get_setting, now, set_setting

log = logging.getLogger("sms")

DEFAULT_TITLE = "سامانه مدیریت شبکه تاپیک"
PROVIDERS = {
    "kavenegar": "کاوه‌نگار (Kavenegar)",
    "smsir": "SMS.ir",
    "melipayamak": "ملی‌پیامک (Melipayamak)",
    "ippanel": "فراز اس‌ام‌اس / IPPanel",
    "http": "وب‌سرویس HTTP دلخواه",
}
# setting key -> default ; *_enc keys are stored encrypted
KEYS = {"sms_enabled": "0", "sms_provider": "kavenegar", "sms_title": DEFAULT_TITLE, "sms_sender": "",
        "sms_api_key_enc": "", "sms_username": "", "sms_password_enc": "",
        "sms_http_url": "", "sms_http_method": "GET", "sms_http_body": "", "sms_http_ok": "",
        "sms_reset_self": "1", "sms_reset_admin": "1", "sms_quota_enabled": "0", "sms_quota_exhausted": "1"}
TIMEOUT = 15


def settings(db) -> dict:
    st = {k: get_setting(db, k, d) for k, d in KEYS.items()}
    st["api_key"] = decrypt(st.pop("sms_api_key_enc")) if get_setting(db, "sms_api_key_enc", "") else ""
    st["password"] = decrypt(st.pop("sms_password_enc")) if get_setting(db, "sms_password_enc", "") else ""
    return st


def save_settings(db, form):
    for k, d in KEYS.items():
        if k.endswith("_enc"):
            v = str(form.get(k[:-4], "") or "")
            if v:                       # empty field = keep the stored secret
                set_setting(db, k, encrypt(v))
            continue
        if k in ("sms_enabled", "sms_reset_self", "sms_reset_admin", "sms_quota_enabled", "sms_quota_exhausted"):
            set_setting(db, k, "1" if form.get(k) else "0")
        elif k in form:
            set_setting(db, k, str(form.get(k) or "").strip() if k != "sms_http_body" else str(form.get(k) or ""))
    if form.get("sms_provider") not in PROVIDERS:
        set_setting(db, "sms_provider", "kavenegar")


def enabled(db) -> bool:
    st = settings(db)
    if st["sms_enabled"] != "1":
        return False
    p = st["sms_provider"]
    if p == "http":
        return bool(st["sms_http_url"])
    if p == "melipayamak":
        return bool(st["sms_username"] and st["password"])
    return bool(st["api_key"])


def normalize_mobile(v) -> str:
    """Iranian mobile -> 09xxxxxxxxx, '' if it is not one. Accepts Persian / Arabic digits, +98, 0098, 98, 9xx."""
    s = str(v or "").translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789"))
    s = re.sub(r"[^\d+]", "", s)
    if s.startswith("+"):
        s = s[1:]
    if s.startswith("0098"):
        s = s[4:]
    elif s.startswith("98") and len(s) == 12:
        s = s[2:]
    if s.startswith("9") and len(s) == 10:
        s = "0" + s
    return s if re.fullmatch(r"09\d{9}", s) else ""


def mask(mobile) -> str:
    m = normalize_mobile(mobile) or str(mobile or "")
    return m[:4] + "***" + m[-4:] if len(m) >= 8 else m


def full_text(db, text) -> str:
    title = get_setting(db, "sms_title", DEFAULT_TITLE).strip()
    return f"{title}\n{text}" if title else text


# ------------------------------------------------------------------ providers
def _http(url, data=None, headers=None, method=None):
    """-> (status, body text). data: dict (json) | bytes | None."""
    headers = dict(headers or {})
    body = None
    if isinstance(data, (dict, list)):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        body = data.encode("utf-8")
    elif data is not None:
        body = data
    headers.setdefault("Accept", "application/json")
    headers.setdefault("User-Agent", "TAPIK-Net")
    req = urllib.request.Request(url, data=body, headers=headers, method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _json(body):
    try:
        return json.loads(body)
    except ValueError:
        return {}


def _kavenegar(st, mobile, text):
    url = f"https://api.kavenegar.com/v1/{urllib.parse.quote(st['api_key'])}/sms/send.json"
    data = {"receptor": mobile, "message": text}
    if st["sms_sender"]:
        data["sender"] = st["sms_sender"]
    code, body = _http(url, urllib.parse.urlencode(data).encode(),
                       {"Content-Type": "application/x-www-form-urlencoded"})
    r = _json(body).get("return", {})
    if code == 200 and r.get("status") == 200:
        return True, ""
    return False, f"کاوه‌نگار {r.get('status', code)}: {r.get('message') or body[:200]}"


def _smsir(st, mobile, text):
    data = {"lineNumber": int(st["sms_sender"]) if st["sms_sender"].isdigit() else st["sms_sender"],
            "messageText": text, "mobiles": [mobile]}
    code, body = _http("https://api.sms.ir/v1/send/bulk", data, {"X-API-KEY": st["api_key"]})
    r = _json(body)
    if code == 200 and r.get("status") == 1:
        return True, ""
    return False, f"SMS.ir {r.get('status', code)}: {r.get('message') or body[:200]}"


def _melipayamak(st, mobile, text):
    data = {"username": st["sms_username"], "password": st["password"], "to": mobile, "from": st["sms_sender"],
            "text": text, "isflash": "false"}
    code, body = _http("https://rest.payamak-panel.com/api/SendSMS/SendSMS", urllib.parse.urlencode(data).encode(),
                       {"Content-Type": "application/x-www-form-urlencoded"})
    r = _json(body)
    if code == 200 and r.get("RetStatus") == 1:
        return True, ""
    return False, f"ملی‌پیامک {r.get('RetStatus', code)}: {r.get('StrRetStatus') or body[:200]}"


def _ippanel(st, mobile, text):
    data = {"recipient": [mobile], "sender": st["sms_sender"], "message": text}
    code, body = _http("https://api2.ippanel.com/api/v1/sms/send/webservice/single", data,
                       {"apikey": st["api_key"]})
    r = _json(body)
    if code in (200, 201) and str(r.get("status", "")).upper() in ("OK", "SUCCESS"):
        return True, ""
    return False, f"IPPanel {code}: {r.get('message') or r.get('error_message') or body[:200]}"


def _custom(st, mobile, text):
    """URL / body with {to} {text} {sender} {key} {username} {password}; success when the answer contains
    sms_http_ok (or any 2xx answer when it is empty)."""
    def fill(t, quote):
        vals = {"to": mobile, "text": text, "sender": st["sms_sender"], "key": st["api_key"],
                "username": st["sms_username"], "password": st["password"]}
        for k, v in vals.items():
            t = t.replace("{" + k + "}", quote(v))
        return t
    url = fill(st["sms_http_url"], lambda v: urllib.parse.quote(str(v), safe=""))
    method = (st["sms_http_method"] or "GET").upper()
    body = None
    headers = {}
    if method == "POST":
        raw = st["sms_http_body"] or ""
        if raw.strip().startswith("{"):
            body = fill(raw, lambda v: json.dumps(str(v), ensure_ascii=False)[1:-1])
            headers["Content-Type"] = "application/json"
        else:
            body = fill(raw, lambda v: urllib.parse.quote(str(v), safe=""))
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    code, ans = _http(url, body if body is not None else (b"" if method == "POST" else None), headers, method)
    ok_mark = st["sms_http_ok"].strip()
    if 200 <= code < 300 and (not ok_mark or ok_mark in ans):
        return True, ""
    return False, f"HTTP {code}: {ans[:200]}"


SENDERS = {"kavenegar": _kavenegar, "smsir": _smsir, "melipayamak": _melipayamak, "ippanel": _ippanel,
           "http": _custom}
_transport = None       # tests: fn(provider, settings, mobile, text) -> (ok, error)


def send(db, mobile, text, purpose="", username="", title=True):
    """Send one SMS. Returns (ok, error). Never raises; every attempt is written to SmsLog."""
    to = normalize_mobile(mobile)
    if not to:
        ok, err = False, f"شماره موبایل نادرست است: {mobile}"
    elif not enabled(db):
        ok, err = False, "ارسال پیامک فعال یا تنظیم نشده (صفحهٔ «پیامک»)"
    else:
        st = settings(db)
        body = full_text(db, text) if title else text
        try:
            if _transport is not None:
                ok, err = _transport(st["sms_provider"], st, to, body)
            else:
                ok, err = SENDERS.get(st["sms_provider"], _kavenegar)(st, to, body)
        except Exception as e:      # noqa: BLE001  network, DNS, TLS ...
            ok, err = False, f"خطای ارتباط با سامانهٔ پیامکی: {e}"
    if not ok:
        log.warning("sms to %s failed: %s", mask(mobile), err)
    try:
        db.add(SmsLog(mobile=to or str(mobile or "")[:20], purpose=purpose[:20], username=(username or "")[:150],
                      text=_redact(text)[:500], ok=bool(ok), error=(err or "")[:300]))
        db.commit()
    except Exception:       # noqa: BLE001
        db.rollback()
    return bool(ok), err or ""


def _redact(text):
    """Codes and passwords are not kept in the log."""
    return re.sub(r"(رمز(?: جدید)?|کد(?: تایید)?|code|password)(\s*[:：]\s*)(\S+)", r"\1\2****", text, flags=re.I)


def recent(db, limit=100):
    return db.query(SmsLog).order_by(SmsLog.id.desc()).limit(limit).all()
