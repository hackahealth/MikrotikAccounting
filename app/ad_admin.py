"""Active Directory administration from the panel: organizational units, users, groups (and their members) and
computers. Everything is done with the service account of the AD settings, which needs the matching rights in AD
(Delegate Control on the OUs, or membership of Account Operators / Domain Admins). Passwords are only sent over an
encrypted connection (LDAPS, or StartTLS on 389)."""
import logging
from datetime import datetime, timedelta

from ldap3 import BASE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SIMPLE, SUBTREE, Connection
from ldap3.utils.dn import escape_rdn

from . import ldap_ad

log = logging.getLogger("ad_admin")

UAC_DISABLED, UAC_NORMAL, UAC_NO_EXPIRE = 2, 512, 65536
GROUP_SCOPES = {"global": ("سراسری (Global)", 2), "domain_local": ("محلی دامین (Domain Local)", 4),
                "universal": ("یونیورسال (Universal)", 8)}
SECURITY = -2147483648           # 0x80000000
USER_ATTRS = ["sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "cn", "mail", "title",
              "department", "physicalDeliveryOfficeName", "l", "company", "telephoneNumber", "mobile", "ipPhone",
              "employeeID", "description", "userAccountControl", "lockoutTime", "memberOf", "whenCreated",
              "lastLogonTimestamp", "pwdLastSet", "accountExpires"]
EDITABLE = (("givenName", "نام"), ("sn", "نام خانوادگی"), ("displayName", "نام نمایشی"), ("mail", "ایمیل"),
            ("title", "سمت"), ("department", "واحد (department)"), ("physicalDeliveryOfficeName", "دفتر (office)"),
            ("l", "شهر"), ("company", "شرکت"), ("telephoneNumber", "تلفن"), ("mobile", "موبایل"),
            ("ipPhone", "داخلی (ipPhone)"), ("employeeID", "کد پرسنلی"), ("description", "توضیح"))


class ADError(RuntimeError):
    pass


def _v(entry, key, default=""):
    a = entry.get("attributes", {}) if isinstance(entry, dict) else {}
    v = a.get(key, default)
    if isinstance(v, (list, tuple)):
        return v[0] if len(v) == 1 and key not in ("memberOf", "member", "objectClass") else (list(v) if v else default)
    return v if v not in (None, []) else default


def _ft(v):
    """AD FILETIME / generalized time -> datetime (UTC naive) or None."""
    if isinstance(v, datetime):
        return v.replace(tzinfo=None) if v.year > 1601 else None
    try:
        n = int(v or 0)
    except (TypeError, ValueError):
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime(1601, 1, 1) + timedelta(microseconds=n / 10)


class AD:
    """One service-account connection for a page / an action."""

    def __init__(self, db, secure=False):
        self.c = ldap_ad._cfg(db)
        if not self.c["server"]:
            raise ADError("Active Directory تنظیم نشده (صفحهٔ Active Directory)")
        self.secure = secure
        if secure and not self.c["ssl"]:
            conn = Connection(ldap_ad._server(self.c), user=ldap_ad._principal(self.c, self.c["bind_user"]),
                              password=self.c["bind_password"], authentication=SIMPLE, receive_timeout=30,
                              auto_referrals=False)
            conn.open()
            try:
                conn.start_tls()
            except Exception as e:
                raise ADError("برای تعیین رمز، اتصال به AD باید رمزشده باشد (LDAPS یا StartTLS) و کنترلر دامنه "
                              "گواهی LDAPS ندارد. در تنظیمات AD گزینهٔ LDAPS را فعال کنید.") from e
            if not conn.bind():
                raise ADError("ورود حساب سرویس AD ناموفق بود")
            self.conn = conn
        else:
            self.conn = ldap_ad._connect(self.c)
        self.base = ldap_ad.base_dn(self.c, self.conn)
        self.domain = self.c["domain"] or ".".join(p[3:] for p in self.base.split(",") if p.upper().startswith("DC="))

    def close(self):
        try:
            self.conn.unbind()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _ok(self, ok, what):
        if not ok:
            raise ADError(ldap_ad._why(self.conn, what))

    def _search(self, base, flt, attrs, scope=SUBTREE, limit=0):
        out = []
        for e in self.conn.extend.standard.paged_search(base, flt, search_scope=scope, attributes=attrs,
                                                        paged_size=500, generator=True):
            if e.get("type") == "searchResEntry":
                out.append(e)
                if limit and len(out) >= limit:
                    break
        return out

    # ---------------------------------------------------------- OUs
    def ous(self):
        """[(dn, name, depth)] of the OUs and built-in containers (Users, Computers), sorted as a tree."""
        rows = self._search(self.base, "(|(objectClass=organizationalUnit)(&(objectClass=container)(|(cn=Users)(cn=Computers))))",
                            ["ou", "cn", "description"])
        base_depth = len(self.base.split(","))
        out = []
        for e in rows:
            dn = e["dn"]
            parts = dn.split(",")
            name = str(_v(e, "ou") or _v(e, "cn") or parts[0].split("=", 1)[-1])
            out.append((dn, name, len(parts) - base_depth - 1))
        out.sort(key=lambda x: list(reversed([p.lower() for p in x[0].split(",")])))
        return out

    def create_ou(self, parent, name, description=""):
        dn = f"OU={escape_rdn(name.strip())},{parent or self.base}"
        attrs = {"description": description} if description else {}
        self._ok(self.conn.add(dn, ["top", "organizationalUnit"], attrs), f"ساخت OU {name} ناموفق:")
        return dn

    def delete_ou(self, dn):
        if self._search(dn, "(objectClass=*)", ["cn"], scope=LEVEL, limit=1):
            raise ADError("OU خالی نیست؛ اول محتوای آن را منتقل یا حذف کنید")
        self._ok(self.conn.delete(dn), "حذف OU ناموفق:")

    # ---------------------------------------------------------- users
    def users(self, q="", ou="", limit=500):
        flt = "(&(objectCategory=person)(objectClass=user)"
        if q:
            x = ldap_ad._escape(q)
            flt += f"(|(sAMAccountName=*{x}*)(displayName=*{x}*)(cn=*{x}*)(mail=*{x}*)(department=*{x}*))"
        flt += ")"
        return [self._user_row(e) for e in self._search(ou or self.base, flt, USER_ATTRS, limit=limit)]

    def _user_row(self, e):
        uac = int(_v(e, "userAccountControl", 0) or 0)
        member = _v(e, "memberOf", [])
        member = [member] if isinstance(member, str) else member
        lock = _ft(_v(e, "lockoutTime", 0))
        return {"dn": e["dn"], "sam": str(_v(e, "sAMAccountName")), "upn": str(_v(e, "userPrincipalName")),
                "name": str(_v(e, "displayName") or _v(e, "cn")), "disabled": bool(uac & UAC_DISABLED),
                "locked": lock is not None, "uac": uac, "member_of": [str(m) for m in member],
                "ou": e["dn"].split(",", 1)[1] if "," in e["dn"] else "",
                "created": _ft(_v(e, "whenCreated", 0)), "last_logon": _ft(_v(e, "lastLogonTimestamp", 0)),
                "pwd_set": _ft(_v(e, "pwdLastSet", 0)),
                "attrs": {k: str(_v(e, k)) for k, _ in EDITABLE}}

    def user(self, dn):
        rows = self._search(dn, "(objectClass=user)", USER_ATTRS, scope=BASE)
        if not rows:
            raise ADError("کاربر در AD پیدا نشد")
        return self._user_row(rows[0])

    def find_user(self, sam):
        rows = self._search(self.base, f"(&(objectClass=user)(sAMAccountName={ldap_ad._escape(sam)}))", ["cn"])
        return rows[0]["dn"] if rows else ""

    def create_user(self, ou, sam, given="", sn="", display="", password="", must_change=True, enabled=True,
                    attrs=None, groups=()):
        sam = sam.strip()
        if not sam or len(sam) > 20 or any(ch in sam for ch in '"/\\[]:;|=,+*?<>@ '):
            raise ADError("نام کاربری (sAMAccountName) نادرست است: حداکثر ۲۰ نویسه، بدون فاصله و نویسه‌های خاص")
        if self.find_user(sam):
            raise ADError(f"کاربر {sam} در AD وجود دارد")
        display = display.strip() or " ".join(x for x in (given, sn) if x).strip() or sam
        dn = f"CN={escape_rdn(display)},{ou or 'CN=Users,' + self.base}"
        a = {"sAMAccountName": sam, "userPrincipalName": f"{sam}@{self.domain}", "displayName": display,
             "userAccountControl": UAC_NORMAL | UAC_DISABLED}
        if given:
            a["givenName"] = given
        if sn:
            a["sn"] = sn
        for k, v in (attrs or {}).items():
            if v:
                a[k] = v
        self._ok(self.conn.add(dn, ["top", "person", "organizationalPerson", "user"], a), "ساخت کاربر ناموفق:")
        try:
            if password:
                self.set_password(dn, password, must_change)
                if enabled:
                    self.set_enabled(dn, True)
            for g in groups:
                self.add_member(g, dn)
        except ADError as e:
            raise ADError(f"کاربر ساخته شد ولی: {e}") from e
        return dn

    def update_user(self, dn, attrs):
        changes = {k: [(MODIFY_REPLACE, [v] if v else [])] for k, v in attrs.items() if k in dict(EDITABLE)}
        if changes:
            self._ok(self.conn.modify(dn, changes), "ثبت مشخصات ناموفق:")

    def set_password(self, dn, password, must_change=True):
        if not self.secure and not self.c["ssl"]:
            raise ADError("تعیین رمز فقط روی اتصال رمزشده ممکن است")
        if not self.conn.extend.microsoft.modify_password(dn, password):
            raise ADError(ldap_ad._why(self.conn, "AD رمز را نپذیرفت (طول و پیچیدگی رمز را بررسی کنید):"))
        self._ok(self.conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, ["0" if must_change else "-1"])]}),
                 "تنظیم «تغییر رمز در ورود بعدی» ناموفق:")

    def set_enabled(self, dn, enabled):
        rows = self._search(dn, "(objectClass=*)", ["userAccountControl"], scope=BASE)
        uac = int(_v(rows[0], "userAccountControl", UAC_NORMAL) or UAC_NORMAL) if rows else UAC_NORMAL
        new = (uac & ~UAC_DISABLED) if enabled else (uac | UAC_DISABLED)
        self._ok(self.conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [str(new)])]}), "تغییر وضعیت ناموفق:")

    def unlock(self, dn):
        self._ok(self.conn.modify(dn, {"lockoutTime": [(MODIFY_REPLACE, ["0"])]}), "باز کردن قفل ناموفق:")

    def move(self, dn, new_ou):
        rdn = dn.split(",", 1)[0]
        self._ok(self.conn.modify_dn(dn, rdn, new_superior=new_ou), "انتقال ناموفق:")
        return f"{rdn},{new_ou}"

    def delete(self, dn):
        self._ok(self.conn.delete(dn), "حذف ناموفق:")

    # ---------------------------------------------------------- groups
    def groups(self, q="", ou=""):
        flt = "(objectClass=group)" if not q else f"(&(objectClass=group)(cn=*{ldap_ad._escape(q)}*))"
        out = []
        for e in self._search(ou or self.base, flt, ["cn", "description", "groupType", "member", "mail"]):
            members = _v(e, "member", [])
            members = [members] if isinstance(members, str) else members
            gt = int(_v(e, "groupType", 0) or 0)
            scope = next((k for k, (_, bit) in GROUP_SCOPES.items() if gt & bit), "")
            out.append({"dn": e["dn"], "name": str(_v(e, "cn")), "description": str(_v(e, "description")),
                        "security": bool(gt & SECURITY) or gt < 0, "scope": scope, "members": [str(m) for m in members],
                        "ou": e["dn"].split(",", 1)[1] if "," in e["dn"] else ""})
        return sorted(out, key=lambda g: g["name"].lower())

    def group(self, dn):
        rows = [g for g in self.groups(ou=dn) if g["dn"].lower() == dn.lower()]
        if not rows:
            raise ADError("گروه پیدا نشد")
        return rows[0]

    def create_group(self, ou, name, scope="global", security=True, description=""):
        name = name.strip()
        if not name or len(name) > 64:
            raise ADError("نام گروه نادرست است")
        if self._search(self.base, f"(&(objectClass=group)(sAMAccountName={ldap_ad._escape(name)}))", ["cn"], limit=1):
            raise ADError(f"گروه {name} وجود دارد")
        bit = GROUP_SCOPES.get(scope, GROUP_SCOPES["global"])[1]
        gt = (bit | SECURITY) if security else bit
        if gt >= 2 ** 31:
            gt -= 2 ** 32
        dn = f"CN={escape_rdn(name)},{ou or 'CN=Users,' + self.base}"
        a = {"sAMAccountName": name, "groupType": gt}
        if description:
            a["description"] = description
        self._ok(self.conn.add(dn, ["top", "group"], a), "ساخت گروه ناموفق:")
        return dn

    def add_member(self, group_dn, member_dn):
        if not self.conn.modify(group_dn, {"member": [(MODIFY_ADD, [member_dn])]}) \
                and self.conn.result.get("result") not in ldap_ad._IGNORE_ADD:
            raise ADError(ldap_ad._why(self.conn, f"افزودن به گروه {ldap_ad._cn(group_dn)} ناموفق:"))

    def remove_member(self, group_dn, member_dn):
        if not self.conn.modify(group_dn, {"member": [(MODIFY_DELETE, [member_dn])]}) \
                and self.conn.result.get("result") not in ldap_ad._IGNORE_DEL:
            raise ADError(ldap_ad._why(self.conn, f"خارج کردن از گروه {ldap_ad._cn(group_dn)} ناموفق:"))

    def set_groups(self, member_dn, wanted, current):
        """Membership of a user (or group) = wanted (DNs); current: its memberOf now."""
        cur = {c.lower(): c for c in current}
        want = {w.lower(): w for w in wanted if w}
        for k, g in want.items():
            if k not in cur:
                self.add_member(g, member_dn)
        for k, g in cur.items():
            if k not in want:
                self.remove_member(g, member_dn)

    # ---------------------------------------------------------- computers
    def computers(self, q="", ou=""):
        flt = "(objectClass=computer)" if not q else f"(&(objectClass=computer)(cn=*{ldap_ad._escape(q)}*))"
        out = []
        for e in self._search(ou or self.base, flt, ["cn", "operatingSystem", "operatingSystemVersion",
                                                     "lastLogonTimestamp", "userAccountControl", "dNSHostName",
                                                     "description"], limit=2000):
            uac = int(_v(e, "userAccountControl", 0) or 0)
            out.append({"dn": e["dn"], "name": str(_v(e, "cn")), "os": str(_v(e, "operatingSystem")),
                        "os_version": str(_v(e, "operatingSystemVersion")), "dns": str(_v(e, "dNSHostName")),
                        "last_logon": _ft(_v(e, "lastLogonTimestamp", 0)), "disabled": bool(uac & UAC_DISABLED),
                        "uac": uac, "description": str(_v(e, "description")),
                        "ou": e["dn"].split(",", 1)[1] if "," in e["dn"] else ""})
        return sorted(out, key=lambda x: x["name"].lower())

    set_computer_enabled = set_enabled
