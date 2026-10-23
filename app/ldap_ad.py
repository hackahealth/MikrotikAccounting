"""اتصال به Active Directory ویندوز: احراز هویت (bind) و همگام‌سازی کاربران."""
import logging
import ssl
import warnings

from ldap3 import BASE, DSA, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SIMPLE, SUBTREE, Connection, Server, Tls
from sqlalchemy import func

from .db import Department, Group, Office, User, decrypt, get_setting, now

log = logging.getLogger("ldap")


def _cfg(db):
    return {
        "server": get_setting(db, "ldap_server"),
        "port": int(get_setting(db, "ldap_port", "389") or 389),
        "ssl": get_setting(db, "ldap_use_ssl", "0") == "1",
        "domain": get_setting(db, "ldap_domain"),
        "bind_user": get_setting(db, "ldap_bind_user"),
        "bind_password": decrypt(get_setting(db, "ldap_bind_password")),
        "base_dn": get_setting(db, "ldap_base_dn"),
        "user_filter": get_setting(db, "ldap_user_filter"),
        "default_group": get_setting(db, "ldap_default_group"),
    }


class _DCTls(Tls):
    """TLS towards a domain controller: self-signed certificates accepted (no validation) and TLS 1.0/1.1 still
    allowed: older Windows Servers (2008 R2 / 2012 without updates) have only those, and Python's default
    (TLS 1.2+, security level 2) makes Schannel drop the handshake with WinError 10054."""

    def wrap_socket(self, connection, do_handshake=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            pass
        connection.socket = ctx.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=do_handshake)


def _server(c):
    port = 636 if c["ssl"] and c["port"] == 389 else c["port"]      # LDAPS ticked but port left at 389
    return Server(c["server"], port=port, use_ssl=c["ssl"], get_info=DSA, connect_timeout=5, tls=_DCTls())


def ssl_hint(c, e) -> str:
    """Why a DC drops the TLS handshake (WinError 10054 / 'socket ssl wrapping error')."""
    text = str(e)
    if not c["ssl"] or not any(k in text for k in ("10054", "ssl wrapping", "reset by peer", "EOF")):
        return ""
    return ("کنترلر دامنه اتصال LDAPS را بست؛ یعنی روی پورت 636 گواهی قابل استفاده‌ای برای LDAPS ندارد. روی خود DC: "
            "گواهی باید نام کامل DC را داشته باشد و در Cert:\\LocalMachine\\My باشد؛ گواهی self-signed باید در "
            "Trusted Root (Cert:\\LocalMachine\\Root) هم کپی شود؛ کلید آن باید با «Microsoft RSA SChannel Cryptographic "
            "Provider» ساخته شده باشد؛ و بعد NTDS یا DC ری‌استارت شود. خطای Schannel با شماره 36886 در System Event Log "
            "یعنی DC گواهی مناسب پیدا نکرده است.")


def _connect(c, timeout=30):
    """Bind with the service account (referrals off: AD returns ForestDnsZones/Configuration references)."""
    return Connection(_server(c), user=_principal(c, c["bind_user"]), password=c["bind_password"],
                      authentication=SIMPLE, receive_timeout=timeout, auto_bind=True, auto_referrals=False)


def base_dn(c, conn):
    """Configured Base DN, otherwise the domain root read from the DC (defaultNamingContext), otherwise built
    from the DNS domain name (corp.local -> DC=corp,DC=local)."""
    if c["base_dn"]:
        return c["base_dn"]
    info = conn.server.info
    v = (info.other.get("defaultNamingContext") if info and info.other else None) or []
    v = v[0] if isinstance(v, (list, tuple)) and v else v
    if not v and c["domain"] and "." in c["domain"]:
        v = ",".join("DC=" + p for p in c["domain"].split(".") if p)
    if not v and info and info.naming_contexts:
        v = next((n for n in info.naming_contexts if n.upper().startswith("DC=")), "")
    if not v:
        raise RuntimeError("Base DN پیدا نشد؛ آن را دستی وارد کنید، مثلاً DC=corp,DC=local")
    return str(v)


def _user_filter(c):
    f = (c["user_filter"] or "").strip()
    if f and not f.startswith("("):
        f = f"({f})"
    return "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*)%s)" % f


def _principal(c, username):
    if "@" in username or "\\" in username:
        return username
    return f"{username}@{c['domain']}" if c["domain"] else username


def enabled(db) -> bool:
    return bool(get_setting(db, "ldap_server"))


def authenticate(db, username: str, password: str):
    """Bind as the user. Returns (ok, reason)."""
    c = _cfg(db)
    if not c["server"]:
        return False, "Active Directory تنظیم نشده"
    if not password:
        return False, "رمز خالی"
    conn = None
    try:
        conn = Connection(_server(c), user=_principal(c, username), password=password, authentication=SIMPLE,
                          receive_timeout=10)
        if conn.bind():
            return True, ""
        return False, f"AD: {conn.result.get('description', 'invalidCredentials')}"
    except Exception as e:  # network errors
        log.warning("LDAP auth error: %s", e)
        return False, f"خطای اتصال AD: {e}"
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def test_connection(db):
    """Bind, find the Base DN and count the users it would import. Returns (ok, message)."""
    c = _cfg(db)
    try:
        conn = _connect(c, 15)
    except Exception as e:
        hint = ssl_hint(c, e)
        return False, f"ورود کاربر سرویس ناموفق: {e}" + (f" — {hint}" if hint else "")
    try:
        base = base_dn(c, conn)
        n = sum(1 for e in conn.extend.standard.paged_search(base, _user_filter(c), search_scope=SUBTREE,
                                                             paged_size=500, generator=True,
                                                             attributes=["sAMAccountName"])
                if e.get("type") == "searchResEntry")
    except Exception as e:
        return False, f"اتصال موفق بود ولی جستجوی کاربران خطا داد: {e}"
    finally:
        conn.unbind()
    src = "" if c["base_dn"] else " (تشخیص خودکار)"
    if not n:
        return False, f"اتصال موفق، ولی در Base DN «{base}»{src} هیچ کاربری پیدا نشد. Base DN و فیلتر اضافه را بررسی کنید."
    return True, f"اتصال موفق · Base DN: {base}{src} · {n} کاربر پیدا شد"


def fetch_users(db, username=None):
    """All users matching the Base DN and filter, or only the one with this sAMAccountName."""
    c = _cfg(db)
    conn = _connect(c)
    flt = _user_filter(c)
    if username:
        flt = f"(&{flt}(sAMAccountName={_escape(username)}))"
    entries = conn.extend.standard.paged_search(
        base_dn(c, conn), flt, search_scope=SUBTREE, paged_size=500, generator=True,
        attributes=["sAMAccountName", "displayName", "mail", "telephoneNumber", "memberOf",
                    "userAccountControl", "distinguishedName", "department", "physicalDeliveryOfficeName",
                    "l", "employeeID", "title", "mobile", "company", "ipPhone"])
    out = []
    for e in entries:
        if e.get("type") != "searchResEntry":
            continue
        a = e["attributes"]
        uac = _s(a.get("userAccountControl")) or 0
        member_of = a.get("memberOf") or []
        if isinstance(member_of, str):
            member_of = [member_of]
        out.append({
            "username": _s(a.get("sAMAccountName")),
            "full_name": _s(a.get("displayName")),
            "email": _s(a.get("mail")),
            "phone": _s(a.get("telephoneNumber")),
            "mobile": _s(a.get("mobile")),
            "ip_phone": _s(a.get("ipPhone")),
            "title": _s(a.get("title")),
            "company": _s(a.get("company")),
            "city": _s(a.get("l")),
            "member_of": [str(m).lower() for m in member_of],
            "disabled": bool(int(uac) & 2),
            "dn": e.get("dn", ""),
            "department": _s(a.get("department")),
            "office": _s(a.get("physicalDeliveryOfficeName")) or _s(a.get("l")),
            "employee_id": _s(a.get("employeeID")),
        })
    conn.unbind()
    return out


def _s(v):
    if isinstance(v, (list, tuple)):
        v = v[0] if v else ""
    return str(v or "").strip()


class _OrgMap:
    """Find (or create) Office / Department rows from AD attribute values."""
    def __init__(self, db, create):
        self.db, self.create = db, create
        self.offices = {}
        for o in db.query(Office).all():
            for k in (o.ldap_value, o.name, o.city):
                if k:
                    self.offices.setdefault(k.strip().lower(), o)
        self.depts = {}
        for d in db.query(Department).all():
            for k in (d.ldap_value, d.name):
                if k:
                    self.depts.setdefault((k.strip().lower(), d.office_id), d)
                    self.depts.setdefault((k.strip().lower(), None), d)

    def office(self, value):
        if not value:
            return None
        o = self.offices.get(value.lower())
        if o is None and self.create:
            o = Office(name=value[:100], ldap_value=value[:200])
            self.db.add(o)
            self.db.flush()
            self.offices[value.lower()] = o
        return o

    def department(self, value, office):
        if not value:
            return None
        oid = office.id if office else None
        d = self.depts.get((value.lower(), oid)) or self.depts.get((value.lower(), None))
        if d is None and self.create:
            d = Department(name=value[:100], ldap_value=value[:200])   # shared by all offices
            self.db.add(d)
            self.db.flush()
            self.depts[(value.lower(), None)] = d
        return d


def list_groups(db):
    """[(name, DN, member count)] of all AD groups under the Base DN."""
    c = _cfg(db)
    conn = _connect(c)
    try:
        res = []
        for e in conn.extend.standard.paged_search(base_dn(c, conn), "(objectClass=group)", search_scope=SUBTREE,
                                                   paged_size=500, generator=True, attributes=["cn", "member"]):
            if e.get("type") != "searchResEntry":
                continue
            a = e["attributes"]
            members = a.get("member") or []
            res.append((_s(a.get("cn")) or e["dn"].split(",")[0][3:], e["dn"],
                        len(members) if isinstance(members, (list, tuple)) else 1))
    finally:
        conn.unbind()
    return sorted(res, key=lambda x: x[0].lower())


def change_password(db, user, old_password: str, new_password: str):
    """Change an AD user's own password (needs LDAPS or StartTLS: AD refuses password changes in clear text)."""
    c = _cfg(db)
    conn = Connection(_server(c), user=_principal(c, user.username), password=old_password, authentication=SIMPLE,
                      receive_timeout=15, auto_referrals=False)
    if not c["ssl"]:
        conn.open()
        try:
            conn.start_tls()
        except Exception as e:
            raise RuntimeError("تغییر رمز کاربر دامنه فقط روی اتصال رمزشده (LDAPS) ممکن است. "
                               "از مدیر شبکه بخواهید LDAPS را فعال کند یا رمز را در ویندوز (Ctrl+Alt+Del) عوض کنید.") from e
    if not conn.bind():
        raise RuntimeError("رمز فعلی درست نیست")
    try:
        dn = user.ldap_dn
        if not dn:
            conn.search(base_dn(c, conn), f"(sAMAccountName={_escape(user.username)})", SUBTREE, attributes=["cn"])
            dn = conn.entries[0].entry_dn if conn.entries else ""
        if not dn:
            raise RuntimeError("حساب کاربر در AD پیدا نشد")
        if not conn.extend.microsoft.modify_password(dn, new_password, old_password):
            desc = conn.result.get("message") or conn.result.get("description", "")
            raise RuntimeError(f"AD رمز جدید را نپذیرفت (طول، پیچیدگی یا تکراری بودن رمز را بررسی کنید). {desc}")
    finally:
        conn.unbind()


# ------------------------------------------------------------------ writing changes back to AD
# local User field -> AD attribute (office / department come from the Office / Department rows)
AD_FIELDS = (("full_name", "displayName"), ("email", "mail"), ("phone", "telephoneNumber"), ("mobile", "mobile"),
             ("title", "title"), ("company", "company"), ("city", "l"), ("personnel_code", "employeeID"))
_IGNORE_ADD = (20, 68)        # attributeOrValueExists, entryAlreadyExists: already a member
_IGNORE_DEL = (16, 53)        # noSuchAttribute, unwillingToPerform: not a member
_WHY = {50: "کاربر سرویس AD اجازه تغییر این حساب را ندارد؛ در AD برای آن Delegate Control بدهید (راهنما در README)",
        32: "حساب یا گروه در AD پیدا نشد", 19: "AD مقدار را نپذیرفت (محدودیت)", 21: "قالب مقدار برای AD نادرست است",
        53: "AD این تغییر را انجام نمی‌دهد"}


def ad_values(user, offices, departments):
    """AD attribute values that represent this user's local fields. offices / departments: {id: row}."""
    v = {attr: (getattr(user, f) or "").strip() for f, attr in AD_FIELDS}
    o = offices.get(user.office_id)
    d = departments.get(user.department_id)
    v["physicalDeliveryOfficeName"] = (o.ldap_value or o.name) if o else ""
    v["department"] = (d.ldap_value or d.name) if d else ""
    return v


def _why(conn, what=""):
    r = conn.result or {}
    msg = _WHY.get(r.get("result"), "")
    detail = r.get("message") or r.get("description") or ""
    return " ".join(x for x in (what, msg or detail, f"({detail})" if msg and detail else "") if x)


class Writer:
    """One service-account connection used to write a batch of user changes to AD.
    The service account needs write rights on the users (and on the mapped groups for membership)."""
    def __init__(self, db):
        self.c = _cfg(db)
        if not self.c["server"]:
            raise RuntimeError("Active Directory تنظیم نشده")
        self.conn = _connect(self.c)
        self._base = None

    def close(self):
        try:
            self.conn.unbind()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _dn_and_groups(self, user):
        dn = user.ldap_dn
        if dn and self.conn.search(dn, "(objectClass=user)", BASE, attributes=["memberOf"]) and self.conn.entries:
            e = self.conn.entries[0]
        else:
            if self._base is None:
                self._base = base_dn(self.c, self.conn)
            self.conn.search(self._base, f"(&(objectClass=user)(sAMAccountName={_escape(user.username)}))", SUBTREE,
                             attributes=["memberOf"])
            if not self.conn.entries:
                raise RuntimeError("حساب کاربر در AD پیدا نشد")
            e = self.conn.entries[0]
        groups = e.memberOf.values if "memberOf" in e.entry_attributes else []
        return e.entry_dn, {str(g).lower() for g in groups}

    def update(self, user, attrs, add_group="", remove_groups=()):
        """attrs: {AD attribute: value} ('' clears it). add_group: group DN to add the user to;
        remove_groups: group DNs to take the user out of (only those it is a member of are touched)."""
        dn, member_of = self._dn_and_groups(user)
        if attrs:
            changes = {k: [(MODIFY_REPLACE, [v] if v else [])] for k, v in attrs.items()}
            if not self.conn.modify(dn, changes):
                raise RuntimeError(_why(self.conn, "ثبت خصیصه‌ها در AD ناموفق:"))
        for g in remove_groups:
            if g and g.lower() != (add_group or "").lower() and g.lower() in member_of:
                if not self.conn.modify(g, {"member": [(MODIFY_DELETE, [dn])]}) \
                        and self.conn.result.get("result") not in _IGNORE_DEL:
                    raise RuntimeError(_why(self.conn, f"خارج کردن از گروه {_cn(g)} ناموفق:"))
        if add_group and add_group.lower() not in member_of:
            if not self.conn.modify(add_group, {"member": [(MODIFY_ADD, [dn])]}) \
                    and self.conn.result.get("result") not in _IGNORE_ADD:
                raise RuntimeError(_why(self.conn, f"افزودن به گروه {_cn(add_group)} ناموفق:"))
        if user.ldap_dn != dn:
            user.ldap_dn = dn


def _cn(dn):
    first = str(dn).split(",")[0]
    return first.split("=", 1)[1] if "=" in first else first


def _escape(v):
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(v)


def sync_users(db, only_usernames=None):
    """Create/update users from AD. Returns dict of counters."""
    only = {n.lower() for n in only_usernames} if only_usernames else None
    users = fetch_users(db, next(iter(only))) if only and len(only) == 1 else fetch_users(db)
    if not users and not only:
        raise RuntimeError("هیچ کاربری از AD دریافت نشد؛ «تست اتصال» را بزنید و Base DN و فیلتر را بررسی کنید. "
                           "(کاربران فعلی غیرفعال نشدند)")
    groups = db.query(Group).all()
    by_dn = {g.ldap_group_dn.lower(): g for g in groups if g.ldap_group_dn}
    default_name = get_setting(db, "ldap_default_group")
    default_group = next((g for g in groups if g.name == default_name), None)
    stats = {"created": 0, "updated": 0, "disabled": 0, "total": len(users)}
    org = _OrgMap(db, get_setting(db, "ldap_auto_org", "1") == "1")
    seen = set()
    for u in users:
        if not u["username"] or (only and u["username"].lower() not in only):
            continue
        seen.add(u["username"].lower())
        group = next((by_dn[m] for m in u["member_of"] if m in by_dn), default_group)
        obj = db.query(User).filter(func.lower(User.username) == u["username"].lower()).first()
        if obj is None:
            obj = User(username=u["username"], source="ldap", group=group)
            db.add(obj)
            stats["created"] += 1
        elif obj.source == "local":
            continue  # never overwrite a local user with the same name
        else:
            if obj.source == "router":        # was auto-created from a router's accounting; it is an AD account
                obj.source = "ldap"
            stats["updated"] += 1
            if group is not None and any(m in by_dn for m in u["member_of"]):
                obj.group = group
        obj.full_name, obj.email, obj.phone, obj.ldap_dn = u["full_name"], u["email"], u["phone"], u["dn"]
        obj.mobile, obj.title, obj.company, obj.city = u["mobile"], u["title"], u["company"], u["city"]
        obj.ip_phone = (u.get("ip_phone") or "")[:50]
        obj.enabled = not u["disabled"]
        office = org.office(u.get("office"))
        if office is not None:
            obj.office = office
        dept = org.department(u.get("department"), office)
        if dept is not None:
            obj.department = dept
        if u.get("employee_id"):
            obj.personnel_code = u["employee_id"]
    # AD accounts removed from AD -> disable
    if not only:
        for obj in db.query(User).filter(User.source == "ldap", User.enabled.is_(True)).all():
            if obj.username.lower() not in seen:
                obj.enabled = False
                stats["disabled"] += 1
    from .auth import link_ad_users     # AD panel accounts: scope follows the office / unit read now
    db.flush()
    link_ad_users(db, only)
    db.commit()
    log.info("AD sync %s at %s", stats, now())
    return stats
