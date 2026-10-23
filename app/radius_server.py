"""سرور RADIUS (احراز هویت 1812 و حسابداری 1813) برای هات‌اسپات و VPN میکروتیک."""
import logging
import threading
import time
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

from pyrad import packet
from pyrad.dictionary import Dictionary
from sqlalchemy import func

from . import apisessions, chap, config, devices, ldap_ad, netscope, policy, security, udp
from .db import (AcctSession, AuthLog, Device, Nas, SessionLocal, SpeedSample, User, decrypt,
                 get_setting, now)

log = logging.getLogger("radius")

TERMINATE_CAUSES = {1: "User-Request", 2: "Lost-Carrier", 3: "Lost-Service", 4: "Idle-Timeout",
                    5: "Session-Timeout", 6: "Admin-Reset", 7: "Admin-Reboot", 8: "Port-Error", 9: "NAS-Error",
                    10: "NAS-Request", 11: "NAS-Reboot", 12: "Port-Unneeded", 13: "Port-Preempted",
                    14: "Port-Suspended", 15: "Service-Unavailable", 16: "Callback", 17: "User-Error",
                    18: "Host-Request"}


class NasRef:
    """What the RADIUS server needs of a router."""
    __slots__ = ("id", "name", "secret", "ip", "identifier")

    def __init__(self, n):
        self.id, self.name, self.secret, self.ip = n.id, n.name, n.secret, n.ip
        self.identifier = (n.identifier or "").strip().lower()

    def key(self, src):
        """nas_ip stored on sessions / logs: the router's own IP (several routers can share a NAT address)."""
        return self.ip if self.ip and self.ip != "0.0.0.0" else src


class NasCache:
    """Routers by source IP, NAS-IP-Address and NAS-Identifier, refreshed from DB every 30 seconds.

    Routers of other offices often reach this server through NAT, so their packets all come from one address
    (the main office router / firewall). They are told apart by the NAS-Identifier (router identity) and
    NAS-IP-Address attributes they send, and finally by which router's secret verifies the packet."""

    def __init__(self):
        self._ts, self._lock = 0, threading.Lock()
        self.by_src, self.by_addr, self.by_ident, self.by_id = {}, {}, {}, {}

    def _refresh(self):
        if time.time() - self._ts <= 30:
            return
        db = SessionLocal()
        try:
            rows = db.query(Nas).all()
        finally:
            db.close()
            SessionLocal.remove()
        by_src, by_addr, by_ident, by_id = {}, {}, {}, {}
        for n in rows:
            r = by_id[n.id] = NasRef(n)
            by_src.setdefault(n.ip, []).append(r)
            for ip in {n.ip, n.api_host}:
                if ip and ip != "0.0.0.0":
                    by_addr.setdefault(ip, []).append(r)
            if r.identifier:
                by_ident.setdefault(r.identifier, []).append(r)
        self.by_src, self.by_addr, self.by_ident, self.by_id = by_src, by_addr, by_ident, by_id
        self._ts = time.time()

    def candidates(self, src, identifier="", nas_ip=""):
        """Routers this packet may come from, most likely first: a matching NAS-Identifier (unique one
        counts most), NAS-IP-Address (router IP, API address or an address read from the router), source IP."""
        with self._lock:
            self._refresh()
            score = {}

            def add(refs, points):
                for r in refs or ():
                    if r is not None:
                        score[r] = score.get(r, 0) + points
            if identifier:
                same = self.by_ident.get(identifier.strip().lower(), [])
                add(same, 4 if len(same) == 1 else 2)
            if nas_ip:
                with netscope.scope.lock:
                    learned = list(netscope.scope.aliases.get(nas_ip, ()))
                add(set(self.by_addr.get(nas_ip, [])) | {self.by_id.get(i) for i in learned}, 3)
            add(self.by_src.get(src), 1)
            out = sorted(score, key=lambda r: (-score[r], r.id))
            out += [r for r in self.by_src.get("0.0.0.0", []) if r not in score]
            return out

    def all(self):
        with self._lock:
            self._refresh()
            return sorted(self.by_id.values(), key=lambda r: r.id)

    def get(self, ip):
        c = self.candidates(ip)
        return (c[0].name, c[0].secret) if c else None

    def invalidate(self):
        self._ts = 0


nas_cache = NasCache()

# what arrives, per (source IP, NAS-Identifier, NAS-IP-Address) (shown on the routers page for troubleshooting)
diag = {}


def _diag(key, nas, what):
    d = diag.get(key)
    if d is None:
        if len(diag) > 500:
            diag.clear()
        d = diag[key] = {"name": "", "nas_id": None, "auth": 0, "acct": 0, "dropped": 0, "bad_secret": 0,
                         "last": None, "last_acct": None}
    d["name"], d["nas_id"] = (nas.name, nas.id) if nas else ("", None)
    d[what] += 1
    d["last"] = now()
    if what == "acct":
        d["last_acct"] = d["last"]


def _attr(pkt, name, default=None):
    try:
        v = pkt.get(name)
        return v[0] if v else default
    except (KeyError, IndexError):
        return default


def _octets(pkt, code):
    """Raw value of a standard attribute by number (works even if dictionary type differs)."""
    v = pkt.get(code)
    return v[0] if v else None


def _service(pkt) -> str:
    st = _attr(pkt, "Service-Type")
    return "vpn" if st in (2, "Framed-User") else "hotspot"


def _strip_user(name: str) -> str:
    name = (name or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    return name


def _total(pkt, low, high) -> int:
    return int(_attr(pkt, low, 0) or 0) + (int(_attr(pkt, high, 0) or 0) << 32)


class RadiusServer:
    def __init__(self):
        self.dict = Dictionary(config.RADIUS_DICTIONARY)
        self.pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="radius-auth")
        self.acct_lock = apisessions.LOCK
        self.socks = []

    # ------------------------------------------------------------------ sockets
    def start(self):
        for port, handler in ((config.RADIUS_AUTH_PORT, self._on_auth), (config.RADIUS_ACCT_PORT, self._on_acct)):
            s = udp.listen(config.RADIUS_BIND, port)
            self.socks.append(s)
            threading.Thread(target=self._loop, args=(s, handler), daemon=True, name=f"radius-{port}").start()
        log.info("RADIUS listening on %s:%s/%s", config.RADIUS_BIND, config.RADIUS_AUTH_PORT, config.RADIUS_ACCT_PORT)

    def _loop(self, sock, handler):
        while True:
            got = udp.recv(sock, 4096)
            if got is None:
                return
            data, addr = got
            if handler is self._on_auth:
                self.pool.submit(self._safe, handler, sock, data, addr)
            else:
                self._safe(handler, sock, data, addr)

    def _safe(self, handler, sock, data, addr):
        try:
            reply = handler(data, addr)
            if reply is not None:
                try:
                    sock.sendto(reply, addr)
                except OSError as e:
                    log.warning("RADIUS reply to %s failed: %s", addr[0], e)
        except Exception:
            log.exception("Error handling RADIUS packet from %s", addr[0])
        finally:
            SessionLocal.remove()

    def identify(self, data, src, acct):
        """Decode a request and find the router that sent it. Returns (packet, NasRef or None)."""
        cls = packet.AcctPacket if acct else packet.AuthPacket
        req = cls(packet=data, secret=b"", dict=self.dict)
        ident = str(_attr(req, "NAS-Identifier", "") or "").strip()
        nas_ip = str(_attr(req, "NAS-IP-Address", "") or "").strip()
        key = (src, ident, nas_ip)
        likely = nas_cache.candidates(src, ident, nas_ip)
        # Accounting is always signed; an Access-Request only when it carries a Message-Authenticator.
        # A signed packet can be tried against every router's secret (e.g. a branch that sends no identity).
        checkable = acct or bool(req.message_authenticator)
        cands = likely + [r for r in nas_cache.all() if r not in likely] if checkable else likely
        for c in cands:
            req.secret = c.secret.encode()
            if not checkable or (req.VerifyAcctRequest() if acct else req.verify_message_authenticator()):
                _diag(key, c, "acct" if acct else "auth")
                return req, c
        if not likely:
            log.warning("Packet from unknown router dropped: source %s, NAS-Identifier %r, NAS-IP-Address %s "
                        "(add it under روترها)", src, ident, nas_ip or "-")
            _diag(key, None, "dropped")
        else:
            log.warning("Bad %s from %s (NAS-Identifier %r): no router's secret matches",
                        "accounting authenticator" if acct else "Message-Authenticator", src, ident)
            _diag(key, likely[0], "bad_secret")
        return req, None

    # ------------------------------------------------------------------ auth
    def _on_auth(self, data, addr):
        req, nas = self.identify(data, addr[0], acct=False)
        if nas is None or req.code != packet.AccessRequest:
            return None
        ok, reason, attrs, method, extra = self.authenticate(req, nas.key(addr[0]))
        reply = req.CreateReply()
        reply.code = packet.AccessAccept if ok else packet.AccessReject
        if ok:
            for k, v in attrs.items():
                reply[k] = v
            if extra:
                success, send_key, recv_key = extra
                reply["MS-CHAP2-Success"] = success
                reply["MS-MPPE-Encryption-Policy"] = b"\x00\x00\x00\x01"
                reply["MS-MPPE-Encryption-Types"] = b"\x00\x00\x00\x06"
                reply["MS-MPPE-Send-Key"] = reply.SaltCrypt(send_key)
                reply["MS-MPPE-Recv-Key"] = reply.SaltCrypt(recv_key)
        else:
            reply["Reply-Message"] = reason
            if method == "mschapv2":
                ident = (_attr(req, "MS-CHAP2-Response") or b"\x00")[0:1]
                reply["MS-CHAP-Error"] = ident + b"E=691 R=0 V=3"
        if req.message_authenticator:
            reply.add_message_authenticator()
        return reply.ReplyPacket()

    def authenticate(self, req, nas_ip):
        """Returns (ok, reason, reply_attrs, method, mschap_extra)."""
        raw_user = _attr(req, "User-Name", "") or ""
        username = _strip_user(raw_user)
        mac = devices.normalize_mac(_attr(req, "Calling-Station-Id", "") or "") or (
            _attr(req, "Calling-Station-Id", "") or "")
        service = _service(req)
        db = SessionLocal()
        method, extra = "", None
        try:
            user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
            lk = security.locked(db, username, _attr(req, "Calling-Station-Id", "") or "")
            if lk:
                return self._done(db, False, f"قفل شده ({security.KINDS[lk.kind]} {lk.value}): {lk.reason}"[:200], {},
                                  username, nas_ip, mac, service, "locked")

            pap = req.get(2)
            chap_pw = _attr(req, "CHAP-Password")
            ms2 = _attr(req, "MS-CHAP2-Response")
            if pap:
                method = "pap"
            elif chap_pw:
                method = "chap"
            elif ms2:
                method = "mschapv2"
            else:
                return self._done(db, False, "روش احراز هویت پشتیبانی نمی‌شود", {}, username, nas_ip, mac, service,
                                  "unknown", None)

            # Unknown user (or one only seen in a router's accounting): try Active Directory (PAP only).
            # Only accounts inside the configured Base DN / filter are accepted and imported.
            if (user is None or user.source == "router") and method == "pap" and ldap_ad.enabled(db):
                password = req.PwDecrypt(pap[0])
                ok, why = ldap_ad.authenticate(db, username, password)
                if ok:
                    try:
                        ldap_ad.sync_users(db, only_usernames={username})
                    except Exception as e:
                        log.warning("AD import of %s failed: %s", username, e)
                        return self._done(db, False, f"خواندن کاربر از AD ناموفق: {e}", {}, username, nas_ip, mac,
                                          service, method)
                    db.expire_all()
                    user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
                    if user is None or user.source != "ldap":
                        return self._done(db, False, "حساب AD در Base DN / فیلتر تعریف‌شده برای اینترنت نیست", {},
                                          username, nas_ip, mac, service, method)
                    return self._finish(db, user, method, None, nas_ip, mac, service)
                if user is None:
                    return self._done(db, False, why or "کاربر یافت نشد", {}, username, nas_ip, mac, service, method)

            if user is None:
                return self._done(db, False, "کاربر یافت نشد", {}, username, nas_ip, mac, service, method)

            if user.source == "router":
                return self._done(db, False, "اکانت محلی روتر است (باید در خود روتر احراز شود)", {}, username,
                                  nas_ip, mac, service, method)
            if user.source == "ldap":
                if method != "pap":
                    return self._done(db, False, "کاربران AD فقط با PAP قابل احراز هویت هستند", {}, username,
                                      nas_ip, mac, service, method)
                ok, why = ldap_ad.authenticate(db, username, req.PwDecrypt(pap[0]))
                if not ok:
                    return self._done(db, False, why, {}, username, nas_ip, mac, service, method)
            else:
                password = decrypt(user.password_enc)
                if method == "pap":
                    ok = req.PwDecrypt(pap[0]) == password
                elif method == "chap":
                    challenge = _attr(req, "CHAP-Challenge") or req.authenticator
                    ok = chap.verify_chap(password, chap_pw, challenge)
                else:
                    auth_challenge = _attr(req, "MS-CHAP-Challenge") or b""
                    ok, success, sk, rk = chap.verify_mschapv2(raw_user, password, auth_challenge, ms2)
                    extra = (success, sk, rk) if ok else None
                if not ok:
                    return self._done(db, False, "رمز عبور اشتباه است", {}, username, nas_ip, mac, service, method)
            return self._finish(db, user, method, extra, nas_ip, mac, service)
        finally:
            db.close()

    def _finish(self, db, user, method, extra, nas_ip, mac, service):
        ok, reason, attrs = policy.check_access(db, user, service, mac if service == "hotspot" else "")
        if ok:
            user.last_login = now()
        return self._done(db, ok, reason, attrs, user.username, nas_ip, mac, service, method, extra)

    def _done(self, db, ok, reason, attrs, username, nas_ip, mac, service, method, extra=None):
        db.add(AuthLog(username=username, nas_ip=nas_ip, mac=mac[:64], service=service, method=method,
                       result="accept" if ok else "reject", reason=reason[:255]))
        db.flush()
        if not ok and method != "locked":
            try:
                security.on_failure(db, username, mac, reason)
            except Exception:  # noqa: BLE001 - never break authentication over the lock rule
                log.exception("failed-login rule")
        db.commit()
        log.info("auth %s user=%s nas=%s mac=%s %s %s", "ACCEPT" if ok else "REJECT", username, nas_ip, mac,
                 method, reason)
        return ok, reason, attrs, method, extra

    # ------------------------------------------------------------------ accounting
    def _on_acct(self, data, addr):
        req, nas = self.identify(data, addr[0], acct=True)
        if nas is None or req.code != packet.AccountingRequest:
            return None
        with self.acct_lock:
            self.account(req, nas.key(addr[0]), nas.id)
        reply = req.CreateReply()
        return reply.ReplyPacket()

    def account(self, req, nas_ip, nas_id=None):
        status = _attr(req, "Acct-Status-Type")
        status = {"Start": 1, "Stop": 2, "Interim-Update": 3, "Accounting-On": 7, "Accounting-Off": 8}.get(
            status, status)
        db = SessionLocal()
        try:
            n = db.get(Nas, nas_id) if nas_id else (db.query(Nas).filter(Nas.ip == nas_ip).first() or
                                                    db.query(Nas).filter(Nas.ip == "0.0.0.0").first())
            if n:
                n.last_seen = now()
            if status in (7, 8):  # NAS reboot: close all its sessions
                for s in db.query(AcctSession).filter(AcctSession.nas_ip == nas_ip, AcctSession.active.is_(True)):
                    s.active, s.stop_time, s.terminate_cause = False, now(), "NAS-Reboot"
                db.commit()
                return
            username = _strip_user(_attr(req, "User-Name", ""))
            sid = _attr(req, "Acct-Session-Id", "") or ""
            s = db.query(AcctSession).filter(AcctSession.nas_ip == nas_ip, AcctSession.acct_session_id == sid,
                                             AcctSession.username == username).first()
            ts = now()
            if s is None:
                if status == 2 and not sid:
                    return
                user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
                if user is None and username and get_setting(db, "acct_auto_create", "1") == "1":
                    # account authenticated by the router's own local database (hotspot user / ppp secret)
                    user = User(username=username, source="router", notes="اکانت محلی روتر (از Accounting)")
                    db.add(user)
                    db.flush()
                raw_mac = _attr(req, "Calling-Station-Id", "") or ""
                mac = devices.normalize_mac(raw_mac) or raw_mac
                s = AcctSession(acct_session_id=sid, nas_ip=nas_ip, username=username,
                                user_id=user.id if user else None, service=_service(req),
                                framed_ip=str(_attr(req, "Framed-IP-Address", "") or ""), mac=mac[:64],
                                called_station=(_attr(req, "Called-Station-Id", "") or "")[:100],
                                nas_port_id=(_attr(req, "NAS-Port-Id", "") or "")[:100],
                                start_time=ts - timedelta(seconds=int(_attr(req, "Acct-Session-Time", 0) or 0)),
                                last_update=ts, active=True)
                dev = db.query(Device).filter(Device.mac == mac).first() if devices.normalize_mac(mac) else None
                if dev is None and devices.normalize_mac(mac):
                    dev = devices.upsert(db, mac)
                if dev:
                    s.device_type, s.device_os = dev.device_type, dev.os
                elif s.service == "vpn":
                    s.device_type = "unknown"
                db.add(s)
                db.flush()
                if s.framed_ip:
                    apisessions.close_replaced(db, username, s.framed_ip)
            new_in = _total(req, "Acct-Input-Octets", "Acct-Input-Gigawords")
            new_out = _total(req, "Acct-Output-Octets", "Acct-Output-Gigawords")
            d_in, d_out = max(0, new_in - (s.bytes_in or 0)), max(0, new_out - (s.bytes_out or 0))
            secs = max(1, int((ts - (s.last_update or ts)).total_seconds())) if status != 1 else 0
            if status != 1 and (d_in or d_out):
                db.add(SpeedSample(session_id=s.id, user_id=s.user_id, ts=ts, seconds=secs, d_in=d_in, d_out=d_out))
                if secs >= 10:
                    s.peak_up_bps = max(s.peak_up_bps or 0, d_in * 8 // secs)
                    s.peak_down_bps = max(s.peak_down_bps or 0, d_out * 8 // secs)
            s.bytes_in, s.bytes_out = max(new_in, s.bytes_in or 0), max(new_out, s.bytes_out or 0)
            s.session_time = int(_attr(req, "Acct-Session-Time", s.session_time) or 0)
            s.last_update = ts
            if not s.framed_ip:
                s.framed_ip = str(_attr(req, "Framed-IP-Address", "") or "")
            if status == 2:
                s.active, s.stop_time = False, ts
                cause = _attr(req, "Acct-Terminate-Cause", 0)
                s.terminate_cause = TERMINATE_CAUSES.get(cause, str(cause or ""))
            else:
                s.active = True
            db.commit()
        finally:
            db.close()


server = None


def start():
    global server
    server = RadiusServer()
    server.start()
    return server
