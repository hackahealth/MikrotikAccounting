"""تماس‌های زنده از Asterisk Manager Interface (AMI، پورت 5038) ایزابل با یک کاربر فقط‌خواندنی:
CoreShowChannels، کانال‌های یک تماس با Linkedid کنار هم گذاشته می‌شوند."""
import socket
import time

from . import pbx
from .db import decrypt


def _blocks(sock, until, timeout):
    """Read AMI messages (blank-line separated 'Key: value' blocks) until one has Event == until."""
    buf, out, end = b"", [], time.monotonic() + timeout
    while True:
        while b"\r\n\r\n" in buf:
            raw, buf = buf.split(b"\r\n\r\n", 1)
            msg = {}
            for line in raw.decode("utf-8", "replace").split("\r\n"):
                if ": " in line:
                    k, v = line.split(": ", 1)
                    msg[k] = v
            if msg.get("Response") == "Error":
                raise RuntimeError(msg.get("Message") or "AMI error")
            out.append(msg)
            if msg.get("Event") == until or (until == "Response" and "Response" in msg):
                return out
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("AMI پاسخ نداد")
        sock.settimeout(left)
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("AMI اتصال را بست")
        buf += chunk


def channels(server, timeout=6):
    """Raw CoreShowChannel events of one server. Replaced in tests."""
    with socket.create_connection((server.host, server.ami_port or 5038), timeout=timeout) as s:
        s.settimeout(timeout)
        banner = s.recv(200)
        if b"Asterisk" not in banner:
            raise ConnectionError("پاسخ AMI نیست")
        s.sendall(f"Action: Login\r\nUsername: {server.ami_user}\r\nSecret: {decrypt(server.ami_password_enc)}\r\n"
                  f"Events: off\r\n\r\n".encode())
        _blocks(s, "Response", timeout)
        s.sendall(b"Action: CoreShowChannels\r\nActionID: mta1\r\n\r\n")
        msgs = _blocks(s, "CoreShowChannelsComplete", timeout)
        try:
            s.sendall(b"Action: Logoff\r\n\r\n")
        except OSError:
            pass
    return [m for m in msgs if m.get("Event") == "CoreShowChannel"]


def _secs(v):
    try:
        h, m, sec = (int(x) for x in str(v).split(":"))
        return h * 3600 + m * 60 + sec
    except ValueError:
        return 0


def live_calls(server, all_ranges, owners_of):
    """Calls in progress: [{'direction','extension','user','other','state','seconds','queue'}]."""
    cl = pbx.Classifier(server, all_ranges)
    calls = {}
    for ch in channels(server):
        key = ch.get("Linkedid") or ch.get("BridgeId") or ch.get("Uniqueid") or ch.get("Channel")
        p = pbx.peer(ch.get("Channel"))
        if str(ch.get("Channel", "")).startswith("Local/"):
            continue
        e = calls.setdefault(key, {"exts": [], "outside": [], "seconds": 0, "queue": "",
                                   "trunk_first": None, "talk": False})
        num = ch.get("CallerIDNum") or ""
        other = ch.get("ConnectedLineNum") or ""
        if cl.is_ext(p):
            if p not in e["exts"]:
                e["exts"].append(p)
            if other and not cl.is_ext(other) and other not in e["outside"] and other != "<unknown>":
                e["outside"].append(other)
            if e["trunk_first"] is None:
                e["trunk_first"] = False
        else:
            if e["trunk_first"] is None:
                e["trunk_first"] = True
            if num and not cl.is_ext(num) and num not in e["outside"]:
                e["outside"].append(num)
        if ch.get("Uniqueid") and ch.get("Uniqueid") == ch.get("Linkedid"):      # the channel that started the call
            e["trunk_first"] = not cl.is_ext(p)
        if (ch.get("Application") or "").lower() == "queue":
            e["queue"] = ch.get("Exten") or (ch.get("ApplicationData") or "").split(",")[0]
        state = (ch.get("ChannelStateDesc") or "").lower()
        if state == "up" and (ch.get("BridgeId") or ch.get("BridgedChannel")):
            e["talk"] = True
        e["seconds"] = max(e["seconds"], _secs(ch.get("Duration")))
    out = []
    for e in calls.values():
        if not e["exts"] and not e["outside"]:
            continue
        direction = "internal" if not e["outside"] else ("in" if e["trunk_first"] else "out")
        ext = e["exts"][0] if e["exts"] else ""
        out.append({"direction": direction, "extension": "، ".join(e["exts"]), "user_id": owners_of(ext),
                    "other": e["outside"][0] if e["outside"] else (e["exts"][1] if len(e["exts"]) > 1 else ""),
                    "state": "talk" if e["talk"] else ("wait" if e["queue"] else "ring"), "seconds": e["seconds"],
                    "queue": e["queue"], "pbx_id": server.id})
    return sorted(out, key=lambda r: -r["seconds"])


def test(server):
    try:
        n = len(channels(server))
        return True, f"اتصال AMI برقرار است؛ {n} کانال فعال"
    except Exception as e:  # noqa: BLE001
        hint = (" — کاربر AMI اجازهٔ write = reporting ندارد (در manager_custom.conf اضافه و "
                "asterisk -rx \"manager reload\" را اجرا کنید، یا تنظیم خودکار SSH را دوباره بزنید)"
                if "Permission denied" in str(e) else "")
        return False, f"اتصال AMI ناموفق: {e}{hint}"
