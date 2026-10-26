"""Authenticating web proxy for shared computers (RDP / terminal servers): everybody on such a server reaches the
internet from the server's one address, so the router cannot tell the users apart. The browsers there use this proxy
(GPO), which asks each Windows user once for their AD (or panel) username and password, then counts the traffic and
applies quota / allowed hours / lock / blocked sites per user, like a hotspot or VPN session. The sessions show with
service 'proxy' (NAS 'proxy', the client computer's IP in called_station); traffic to internal addresses is 'lan'."""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import logging
import threading
import time
from collections import defaultdict
from datetime import timedelta
from html import escape
from urllib.parse import urlsplit

from sqlalchemy import func

from . import access, classifier, grants, ldap_ad, netscope, policy, security
from .db import (AcctSession, AuthLog, SessionLocal, SiteRule, SpeedSample, TrafficCategory, TrafficDomain, User,
                 decrypt, get_setting, now)

log = logging.getLogger("proxy")
NAS = "proxy"
REALM = "Internet"
AUTH_TTL = 900            # a verified username + password is trusted this long
FAIL_TTL = 30             # the same wrong password is not re-checked (nor re-logged) within this
POLICY_TTL = 30
IDLE_CLOSE = 300          # a proxy session without connections or traffic for this long is closed
HEAD_LIMIT = 65536


def settings(db):
    try:
        port = int(get_setting(db, "proxy_port", "3128") or 3128)
    except ValueError:
        port = 3128
    clients = get_setting(db, "proxy_clients", "")
    return {"enabled": get_setting(db, "proxy_enabled", "0") == "1", "port": port, "clients": clients,
            "nets": netscope.parse_ranges(clients or get_setting(db, "internal_ranges", access.DEFAULT_INTERNAL))[0]}


def clean_username(name):
    """'CORP\\m.karimi' / 'm.karimi@corp.local' -> 'm.karimi'."""
    name = (name or "").strip().split("\\")[-1]
    return name.split("@")[0].strip()[:150]


def authenticate(db, username, password):
    """-> (User, '') or (None, reason). Same rules as hotspot/VPN PAP: AD users against AD (imported on first use when
    inside the configured Base DN), panel-local users against their stored password."""
    name = clean_username(username)
    if not name or not password:
        return None, "نام کاربری یا رمز خالی است"
    user = db.query(User).filter(func.lower(User.username) == name.lower()).first()
    if (user is None or user.source == "router") and ldap_ad.enabled(db):
        ok, why = ldap_ad.authenticate(db, name, password)
        if not ok:
            return None, why or "کاربر یافت نشد"
        try:
            ldap_ad.sync_users(db, only_usernames={name})
        except Exception as e:  # noqa: BLE001
            return None, f"خواندن کاربر از AD ناموفق: {e}"
        db.expire_all()
        user = db.query(User).filter(func.lower(User.username) == name.lower()).first()
        if user is None or user.source != "ldap":
            return None, "حساب AD در Base DN / فیلتر تعریف‌شده برای اینترنت نیست"
        return user, ""
    if user is None:
        return None, "کاربر یافت نشد"
    if user.source == "ldap":
        ok, why = ldap_ad.authenticate(db, user.username, password)
        return (user, "") if ok else (None, why or "رمز عبور اشتباه است")
    if user.source == "local" and user.password_enc:
        if hmac.compare_digest(decrypt(user.password_enc).encode(), password.encode()):
            return user, ""
        return None, "رمز عبور اشتباه است"
    return None, "اکانت محلی روتر است (باید در خود روتر احراز شود)"


def site_allowed(db, host, uid):
    """Blocked sites (or, in allow-list mode, only the allowed ones), except for users with an 'internet' grant."""
    st = access.settings(db)
    if st["sites_mode"] != "allow" and not access.is_blocked_host(db, host):
        return True
    if grants.active(db, uid, "internet"):
        return True
    if st["sites_mode"] != "allow":
        return False
    h = host.lower().strip(".")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    for r in db.query(SiteRule).filter(SiteRule.enabled.is_(True), SiteRule.action == "allow"):
        p = r.pattern
        if ip is not None:
            try:
                if ip in ipaddress.ip_network(p, strict=False):
                    return True
            except ValueError:
                pass
        elif h == p or h.endswith("." + p):
            return True
    return ip is not None and any(ip in n for n in netscope.parse_ranges(
        get_setting(db, "internal_ranges", access.DEFAULT_INTERNAL))[0])


def _page(code, title, text, extra=""):
    body = (f'<!doctype html><html dir="rtl"><meta charset="utf-8"><title>{escape(title)}</title>'
            f'<body style="font:15px Tahoma,sans-serif;padding:40px;text-align:center"><h2>{escape(title)}</h2>'
            f'<p>{escape(text)}</p></body></html>').encode()
    reason = {403: "Forbidden", 407: "Proxy Authentication Required", 400: "Bad Request",
              502: "Bad Gateway", 504: "Gateway Timeout"}.get(code, "Error")
    head = (f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\n"
            f"{extra}Connection: close\r\nProxy-Connection: close\r\n\r\n").encode()
    return head + body


class Proxy:
    def __init__(self):
        self.lock = threading.Lock()
        self.auth_ok = {}           # (name, sha) -> (expires, uid, username)
        self.auth_bad = {}          # (name, sha) -> (expires, reason shown)
        self.pol = {}               # uid -> (expires, ok, reason)
        self.bytes = defaultdict(lambda: [0, 0])                # (uid, client ip) -> [up, down]
        self.dom = defaultdict(lambda: ["", 0, 0])              # (uid, host) -> [category, down, up]
        self.conns = defaultdict(set)                           # (uid, client ip) -> {writers}
        self.seen = {}              # (uid, client ip) -> last activity (monotonic)
        self.sessions = {}          # (uid, client ip) -> AcctSession id
        self.names = {}             # uid -> username
        self.loop = None
        self.server = None
        self.port = None
        self.error = ""
        self.nets = []
        self.internal = []
        self.started = False

    # ------------------------------------------------------------------ checks (worker threads)
    def _check_auth(self, header, client):
        """-> (uid, username, '') or (None, None, reason); reason '' means 'ask for credentials' again, a reason is
        shown as is (locked account)."""
        if not header or not header.lower().startswith("basic "):
            return None, None, ""
        try:
            raw = base64.b64decode(header.split(None, 1)[1].strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            try:
                raw = base64.b64decode(header.split(None, 1)[1].strip()).decode("cp1256")
            except Exception:  # noqa: BLE001
                return None, None, ""
        username, _, password = raw.partition(":")
        key = (clean_username(username).lower(), hashlib.sha256(password.encode()).hexdigest())
        t = time.monotonic()
        with self.lock:
            hit = self.auth_ok.get(key)
            if hit and hit[0] > t:
                return hit[1], hit[2], ""
            bad = self.auth_bad.get(key)
            if bad and bad[0] > t:
                return None, None, bad[1]
        db = SessionLocal()
        try:
            name = clean_username(username)
            lk = security.locked(db, name)
            if lk:
                user, reason, method = None, f"قفل شده: {lk.reason}", "locked"
            else:
                user, reason = authenticate(db, username, password)
                method = "basic"
            db.add(AuthLog(username=(user.username if user else name)[:150], nas_ip=NAS, mac=client[:64],
                           service="proxy", method=method, result="accept" if user else "reject", reason=reason[:255]))
            db.flush()
            if user is None and method != "locked":
                try:
                    security.on_failure(db, name, "", reason)   # never lock the shared server's address
                except Exception:  # noqa: BLE001
                    log.exception("failed-login rule")
            if user is not None:
                user.last_login = now()
            db.commit()
            log.info("proxy auth %s user=%s client=%s %s", "ACCEPT" if user else "REJECT", name, client, reason)
            with self.lock:
                if user is None:
                    shown = reason if method == "locked" else ""
                    self.auth_bad[key] = (t + FAIL_TTL, shown)
                    return None, None, shown
                self.auth_ok[key] = (t + AUTH_TTL, user.id, user.username)
                self.names[user.id] = user.username
                self.pol.pop(user.id, None)
            return user.id, user.username, ""
        finally:
            db.close()
            SessionLocal.remove()

    def _policy(self, uid, force=False):
        t = time.monotonic()
        with self.lock:
            hit = self.pol.get(uid)
            if hit and hit[0] > t and not force:
                return hit[1], hit[2]
        db = SessionLocal()
        try:
            user = db.get(User, uid)
            if user is None:
                ok, reason = False, "کاربر یافت نشد"
            elif security.locked(db, user.username):
                ok, reason = False, "حساب قفل شده است"
            else:
                ok, reason, _ = policy.check_access(db, user, "proxy")
        finally:
            db.close()
            SessionLocal.remove()
        with self.lock:
            self.pol[uid] = (t + POLICY_TTL, ok, reason)
        return ok, reason

    def _site(self, host, uid):
        db = SessionLocal()
        try:
            return site_allowed(db, host, uid)
        finally:
            db.close()
            SessionLocal.remove()

    # ------------------------------------------------------------------ connections (event loop)
    def _client_ok(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        return a.is_loopback or any(a in n for n in self.nets)

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        client = peer[0] if peer else ""
        if client.startswith("::ffff:"):
            client = client[7:]
        if not self._client_ok(client):
            writer.close()
            return
        key = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 120)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
                return
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3:
                writer.write(_page(400, "درخواست نادرست", "Bad request"))
                return
            method, target, version = parts
            headers = []
            auth = ""
            for ln in lines[1:]:
                if not ln:
                    continue
                k, _, v = ln.partition(":")
                if k.strip().lower() == "proxy-authorization":
                    auth = v.strip()
                elif k.strip().lower() not in ("proxy-connection", "connection", "keep-alive"):
                    headers.append(ln)
            loop = asyncio.get_running_loop()
            uid, username, why = await loop.run_in_executor(None, self._check_auth, auth, client)
            if uid is None and why:
                writer.write(_page(403, "دسترسی به اینترنت بسته است", why))
                return
            if uid is None:
                writer.write(_page(407, "ورود به اینترنت", "نام کاربری و رمز ویندوز (دامنه) خود را وارد کنید.",
                                   f'Proxy-Authenticate: Basic realm="{REALM}", charset="UTF-8"\r\n'))
                return
            ok, reason = await loop.run_in_executor(None, self._policy, uid)
            if not ok:
                writer.write(_page(403, "دسترسی به اینترنت بسته است", f"{username}: {reason}"))
                return
            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                host = host.strip("[]")
            else:
                u = urlsplit(target)
                if u.scheme.lower() != "http" or not u.hostname:
                    writer.write(_page(400, "درخواست نادرست", "فقط آدرس کامل http و CONNECT پشتیبانی می‌شود"))
                    return
                host, port = u.hostname, str(u.port or 80)
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            try:
                port = int(port)
            except ValueError:
                writer.write(_page(400, "درخواست نادرست", "Bad port"))
                return
            if not await loop.run_in_executor(None, self._site, host, uid):
                writer.write(_page(403, "این سایت مسدود است", host))
                return
            try:
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 20)
            except asyncio.TimeoutError:
                writer.write(_page(504, "پاسخی نیامد", f"{host}:{port}"))
                return
            except OSError as e:
                writer.write(_page(502, "اتصال برقرار نشد", f"{host}:{port} — {e.strerror or e}"))
                return
            key = (uid, client)
            remote = (up_w.get_extra_info("peername") or ("",))[0]
            cat = self._category(host, remote)
            with self.lock:
                self.conns[key].add(writer)
                self.seen[key] = time.monotonic()
                self.names[uid] = username
            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self._count(key, host, cat, 0, 0)
            else:
                out = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
                data = out.encode("latin-1")
                up_w.write(data)
                self._count(key, host, cat, len(data), 0)
            await writer.drain()
            await asyncio.gather(self._pipe(reader, up_w, key, host, cat, True),
                                 self._pipe(up_r, writer, key, host, cat, False))
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("proxy connection")
        finally:
            if key is not None:
                with self.lock:
                    self.conns[key].discard(writer)
                    self.seen[key] = time.monotonic()
            try:
                if not writer.is_closing():
                    await writer.drain()
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _pipe(self, src, dst, key, host, cat, upward):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                self._count(key, host, cat, len(data) if upward else 0, 0 if upward else len(data))
                await dst.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
                else:
                    dst.close()
            except (OSError, RuntimeError):
                try:
                    dst.close()
                except Exception:  # noqa: BLE001
                    pass

    def _category(self, host, remote):
        for a in (host, remote):
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                continue
            if any(ip in n for n in self.internal):
                return "lan"
        return classifier.category_of_domain(host) or "web"

    def _count(self, key, host, cat, up, down):
        with self.lock:
            b = self.bytes[key]
            b[0] += up
            b[1] += down
            d = self.dom[(key[0], host.lower()[:255])]
            d[0] = cat
            d[1] += down
            d[2] += up
            if up or down:
                self.seen[key] = time.monotonic()

    # ------------------------------------------------------------------ accounting (flusher thread)
    def flush(self):
        """Write the counted traffic into proxy sessions, speed samples and the category / domain tables; close idle
        sessions; re-check the users with open connections and cut those no longer allowed."""
        t = time.monotonic()
        with self.lock:
            counts, doms = self.bytes, self.dom
            self.bytes, self.dom = defaultdict(lambda: [0, 0]), defaultdict(lambda: ["", 0, 0])
            live = {k for k, w in self.conns.items() if w} | {k for k, s in self.seen.items() if t - s < IDLE_CLOSE}
            names = dict(self.names)
            for k in [k for k in self.conns if not self.conns[k]]:
                del self.conns[k]
        ts = now()
        db = SessionLocal()
        try:
            for key in live | set(counts):
                uid, client = key
                up, down = counts.get(key, (0, 0))
                s = db.get(AcctSession, self.sessions[key]) if key in self.sessions else None
                if s is None or not s.active:
                    s = AcctSession(acct_session_id=f"proxy-{uid}-{client}-{int(ts.timestamp())}", nas_ip=NAS,
                                    username=names.get(uid, ""), user_id=uid, service="proxy", framed_ip="",
                                    mac="", called_station=client, start_time=ts, last_update=ts, bytes_in=0,
                                    bytes_out=0, device_type="server", active=True)
                    db.add(s)
                    db.flush()
                    self.sessions[key] = s.id
                secs = max(1, int((ts - (s.last_update or ts)).total_seconds())) if s.last_update else 60
                s.bytes_in = (s.bytes_in or 0) + up
                s.bytes_out = (s.bytes_out or 0) + down
                s.last_update = ts
                s.session_time = int((ts - s.start_time).total_seconds())
                if up or down:
                    s.peak_down_bps = max(s.peak_down_bps or 0, down * 8 // secs)
                    s.peak_up_bps = max(s.peak_up_bps or 0, up * 8 // secs)
                    db.add(SpeedSample(session_id=s.id, user_id=uid, ts=ts, seconds=secs, d_in=up, d_out=down))
            for key in [k for k in self.sessions if k not in live and k not in counts]:
                s = db.get(AcctSession, self.sessions.pop(key))
                if s is not None and s.active:
                    s.active, s.stop_time, s.terminate_cause = False, s.last_update or ts, "Idle-Timeout"
            day, hour = ts.date(), ts.hour
            cats = defaultdict(lambda: [0, 0, 0])
            for (uid, host), (cat, down, up) in doms.items():
                c = cats[(uid, cat)]
                c[0] += down
                c[1] += up
                c[2] += 1
                label = host if cat == "lan" else classifier.base_domain(host)
                row = db.query(TrafficDomain).filter_by(user_id=uid, day=day, domain=label[:255]).first()
                if row is None:
                    db.add(TrafficDomain(user_id=uid, day=day, domain=label[:255], category=cat, bytes_down=down,
                                         bytes_up=up))
                    db.flush()
                else:
                    row.bytes_down += down
                    row.bytes_up += up
            for (uid, cat), (down, up, n) in cats.items():
                row = db.query(TrafficCategory).filter_by(user_id=uid, day=day, hour=hour, category=cat).first()
                if row is None:
                    db.add(TrafficCategory(user_id=uid, day=day, hour=hour, category=cat, bytes_down=down,
                                           bytes_up=up, flows=n))
                    db.flush()
                else:
                    row.bytes_down += down
                    row.bytes_up += up
                    row.flows += n
            db.commit()
        except Exception:
            db.rollback()
            log.exception("proxy flush failed")
        finally:
            db.close()
            SessionLocal.remove()
        for uid in {k[0] for k in live}:
            ok, reason = self._policy(uid, force=True)
            if not ok:
                self.kick(uid, reason)

    def kick(self, uid, reason=""):
        """Close every open connection of this user (blocked after quota / hours / lock)."""
        with self.lock:
            writers = [w for k, ws in self.conns.items() if k[0] == uid for w in ws]
            for k in [k for k, v in self.auth_ok.items() if v[1] == uid]:
                del self.auth_ok[k]
        if writers and self.loop is not None:
            log.info("proxy: cut %s connections of user %s (%s)", len(writers), uid, reason)
            for w in writers:
                self.loop.call_soon_threadsafe(w.close)

    # ------------------------------------------------------------------ lifecycle
    def apply_settings(self):
        db = SessionLocal()
        try:
            st = settings(db)
            self.internal = netscope.parse_ranges(get_setting(db, "internal_ranges", access.DEFAULT_INTERNAL))[0]
        finally:
            db.close()
            SessionLocal.remove()
        self.nets = st["nets"]
        want = st["port"] if st["enabled"] else None
        if want == self.port and (self.server is not None or want is None):
            return
        if self.server is not None:
            srv, self.server, self.port = self.server, None, None
            asyncio.run_coroutine_threadsafe(self._close(srv), self.loop).result(10)
            log.info("proxy stopped")
        if want is None:
            self.error = ""
            return
        try:
            self.server = asyncio.run_coroutine_threadsafe(
                asyncio.start_server(self.handle, host="0.0.0.0", port=want, limit=HEAD_LIMIT), self.loop).result(10)
            self.port, self.error = want, ""
            log.info("proxy listening on port %s", want)
        except Exception as e:  # noqa: BLE001
            self.error = str(e)[:200]
            self.port = want
            log.warning("proxy on port %s failed: %s", want, e)

    @staticmethod
    async def _close(srv):
        srv.close()
        await srv.wait_closed()

    def start(self):
        if self.started:
            return
        self.started = True
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True, name="proxy-loop").start()

        def keeper():
            n = 0
            while True:
                try:
                    if n % 2 == 0:
                        self.apply_settings()
                    self.flush()
                except Exception:  # noqa: BLE001
                    log.exception("proxy keeper")
                n += 1
                time.sleep(30)
        threading.Thread(target=keeper, daemon=True, name="proxy-keeper").start()

    def status(self):
        with self.lock:
            users = {k[0] for k, w in self.conns.items() if w}
            conns = sum(len(w) for w in self.conns.values())
        return {"running": self.server is not None, "port": self.port, "error": self.error, "users": len(users),
                "conns": conns}


server = Proxy()


def start():
    server.start()
