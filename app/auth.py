"""کاربران پنل، نقش‌ها و سطوح دسترسی.

بازیابی رمز در صورت فراموشی:  python -m app.auth reset <username> <new-password>
"""
import base64
import hashlib
import hmac
import logging
import os
import re
import sys
from datetime import timedelta

from sqlalchemy import func

from . import config
from .db import AuditLog, PanelUser, User, now

log = logging.getLogger("auth")

PERMISSIONS = {
    "dashboard": "داشبورد",
    "users_view": "مشاهده کاربران و گروه‌ها",
    "users_edit": "ایجاد / ویرایش / حذف کاربران",
    "groups_edit": "مدیریت گروه‌ها و سیاست‌ها (سرعت، حجم، ساعت)",
    "live_view": "مشاهده کاربران آنلاین",
    "live_disconnect": "قطع اتصال کاربر",
    "reports_view": "گزارش‌های مصرف",
    "reports_export": "خروجی Excel از گزارش‌ها",
    "mgmt_reports": "گزارش مدیریتی",
    "attendance": "گزارش ساعات اتصال کارکنان",
    "devices_view": "مشاهده دستگاه‌ها",
    "devices_edit": "اصلاح نوع دستگاه",
    "logs_view": "لاگ ورود کاربران اینترنت",
    "nas_manage": "مدیریت روترها",
    "router_traffic": "گراف ترافیک روترها",
    "calls_view": "گزارش تماس‌ها (ایزابل)",
    "pbx_manage": "تنظیم سرورهای ایزابل و داخلی‌ها",
    "mt_local": "اکانت‌های محلی میکروتیک (هات‌اسپات / VPN)",
    "hotspot_deploy": "بروزرسانی فولدر hotspot روترها",
    "org_manage": "مدیریت دفترها و واحدها",
    "ad_sync": "همگام‌سازی Active Directory",
    "ad_manage": "تنظیمات Active Directory",
    "settings": "تنظیمات سیستم (ساعات کاری)",
    "panel_users": "مدیریت کاربران پنل و دسترسی‌ها",
    "audit_view": "لاگ فعالیت کاربران پنل",
    "net_monitor": "پایش روترها، تانل‌ها و سرورها",
    "alerts_view": "هشدارهای سیستم (قفل، قطعی)",
    "security_manage": "ورودهای ناموفق و قفل کاربر / MAC / IP",
    "grants_manage": "مجوز موقت (خارج از ساعت / اینترنت آزاد)",
    "data_manage": "مدت نگهداری و حذف سابقه",
    "router_admin": "نسخه، بروزرسانی و ریبوت روترها",
    "access_manage": "کنترل دسترسی (سایت‌ها، مقاصد داخلی، استثناها)",
    "ad_message": "ارسال پیام به رایانه‌های کاربران",
    "ad_admin": "مدیریت Active Directory (کاربر، گروه، OU، رایانه) — فقط از آدرس داخلی",
}
# shown and allowed only when the panel is opened through an internal address (never through the public IP)
INTERNAL_ONLY = {"ad_admin"}
INTERNAL_PREFIXES = ("/adm/", "/adm")

ROLES = {
    "admin": ("مدیر سیستم", list(PERMISSIONS)),
    "it": ("کارشناس IT", ["dashboard", "users_view", "users_edit", "groups_edit", "live_view", "live_disconnect",
                          "reports_view", "reports_export", "devices_view", "devices_edit", "logs_view", "ad_sync",
                          "mt_local", "hotspot_deploy", "org_manage", "router_traffic", "pbx_manage", "net_monitor",
                          "alerts_view", "security_manage", "grants_manage", "router_admin", "access_manage",
                          "ad_message"]),
    "hr": ("کارشناس منابع انسانی", ["dashboard", "users_view", "reports_view", "reports_export", "mgmt_reports",
                                    "attendance", "calls_view"]),
    "unit_manager": ("مدیر دفتر / واحد", ["dashboard", "users_view", "live_view", "reports_view", "reports_export",
                                          "mgmt_reports", "attendance", "router_traffic", "calls_view"]),
}
# Permissions a scoped (office / unit) panel user can never have: they only view their own staff.
SCOPED_FORBIDDEN = {"users_edit", "groups_edit", "live_disconnect", "devices_edit", "nas_manage", "ad_sync",
                    "ad_manage", "settings", "panel_users", "audit_view", "mt_local", "hotspot_deploy", "org_manage",
                    "devices_view", "logs_view", "pbx_manage", "net_monitor", "alerts_view", "security_manage",
                    "grants_manage", "data_manage", "router_admin", "access_manage", "ad_message", "ad_admin"}

# (method, path regex, permission | "a|b" any-of | "" = any logged-in user)
ROUTES = [
    ("GET", r"/", "dashboard"),
    ("GET", r"/account", ""), ("POST", r"/account", ""), ("GET", r"/logout", ""), ("POST", r"/tour/done", ""),
    ("GET", r"/live", "live_view"), ("GET", r"/api/live", "live_view"),
    ("POST", r"/live/\d+/disconnect", "live_disconnect"),
    ("GET", r"/users", "users_view"), ("GET", r"/users/new", "users_edit"), ("GET", r"/users/\d+/edit", "users_edit"),
    ("POST", r"/users/.*", "users_edit"),
    ("GET", r"/groups", "users_view"), ("GET", r"/groups/new", "groups_edit"),
    ("GET", r"/groups/\d+/edit", "groups_edit"), ("POST", r"/groups/.*", "groups_edit"),
    ("GET", r"/reports", "reports_view"), ("GET", r"/reports/export", "reports_export"),
    ("GET", r"/mgmt", "mgmt_reports"), ("GET", r"/mgmt/export\.xlsx", "mgmt_reports"),
    ("GET", r"/mgmt/print", "mgmt_reports"), ("POST", r"/settings", "settings"),
    ("GET", r"/attendance", "attendance"), ("GET", r"/attendance/export\.xlsx", "attendance"),
    ("GET", r"/devices", "devices_view"), ("POST", r"/devices/\d+/type", "devices_edit"),
    ("GET", r"/devices/[0-9A-Fa-f:.\-]{12,17}", "devices_view"), ("POST", r"/devices/settings", "devices_edit"),
    ("GET", r"/devices/night(\.xlsx)?", "devices_view"), ("POST", r"/devices/night/take", "devices_edit"),
    ("POST", r"/devices/bulk-type", "devices_edit"), ("POST", r"/devices/logon-settings", "devices_edit"),
    ("GET", r"/logs", "logs_view"),
    ("GET", r"/traffic", "router_traffic"), ("GET", r"/api/traffic", "router_traffic"),
    ("GET", r"/calls", "calls_view"), ("GET", r"/calls/export\.xlsx", "calls_view"),
    ("GET", r"/calls/live", "calls_view"), ("GET", r"/api/calls/live", "calls_view"),
    ("GET", r"/pbx", "pbx_manage"), ("GET", r"/pbx/new", "pbx_manage"), ("GET", r"/pbx/\d+/edit", "pbx_manage"),
    ("POST", r"/pbx/.*", "pbx_manage"),
    ("GET", r"/nas", "nas_manage"), ("GET", r"/nas/\d+/edit", "nas_manage"), ("POST", r"/nas/.*", "nas_manage"),
    ("GET", r"/ad", "ad_sync|ad_manage"), ("POST", r"/ad/sync", "ad_sync"), ("POST", r"/ad/.*", "ad_manage"),
    ("GET", r"/admins", "panel_users"), ("GET", r"/admins/new", "panel_users"),
    ("GET", r"/admins/\d+/edit", "panel_users"), ("POST", r"/admins/.*", "panel_users"),
    ("GET", r"/audit", "audit_view"),
    ("GET", r"/org", "org_manage"), ("POST", r"/org/.*", "org_manage"),
    ("GET", r"/mt-local", "mt_local"), ("POST", r"/mt-local/.*", "mt_local"),
    ("GET", r"/hotspot(/\d+/(download|files|edit))?", "hotspot_deploy"), ("POST", r"/hotspot/.*", "hotspot_deploy"),
    ("GET", r"/netobjects", "nas_manage"), ("POST", r"/netobjects/.*", "nas_manage"),
    ("GET", r"/offices", "mgmt_reports|router_traffic"), ("GET", r"/offices/export\.xlsx", "mgmt_reports|router_traffic"),
    ("GET", r"/monitor", "net_monitor"), ("POST", r"/monitor/settings", "net_monitor"),
    ("GET", r"/alerts", "alerts_view"), ("POST", r"/alerts/read", "alerts_view"),
    ("GET", r"/security", "security_manage"), ("POST", r"/security/.*", "security_manage"),
    ("GET", r"/grants", "grants_manage"), ("POST", r"/grants/.*", "grants_manage"),
    ("GET", r"/data", "data_manage"), ("POST", r"/data/.*", "data_manage"),
    ("GET", r"/routeros", "router_admin"), ("POST", r"/routeros/.*", "router_admin"),
    ("GET", r"/access(/preview/\d+)?", "access_manage"), ("POST", r"/access/.*", "access_manage"),
    ("GET", r"/winlogons", "devices_view"),
    ("GET", r"/messages", "ad_message"), ("POST", r"/messages/.*", "ad_message"),
    ("GET", r"/adm(/(users|user|groups|group|ous|computers))?", "ad_admin"), ("POST", r"/adm/.*", "ad_admin"),
]
_ROUTES = [(m, re.compile(p + r"/?$"), perm) for m, p, perm in ROUTES]

# Landing page per permission (first one the user has)
LANDING = [("dashboard", "/"), ("mgmt_reports", "/mgmt"), ("reports_view", "/reports"), ("attendance", "/attendance"),
           ("calls_view", "/calls"),
           ("live_view", "/live"), ("users_view", "/users")]


def required_permission(method: str, path: str):
    """Returns permission string, '' for any logged-in user, or None when the route is unknown (deny)."""
    method = "GET" if method == "HEAD" else method
    for m, rx, perm in _ROUTES:
        if m == method and rx.match(path):
            return perm
    return None


def user_permissions(u: PanelUser) -> set:
    if u.role == "admin":
        return set(PERMISSIONS)
    if u.permissions:
        perms = {p for p in u.permissions.split(",") if p in PERMISSIONS}
    else:
        perms = set(ROLES.get(u.role, ("", []))[1])
    if u.role == "unit_manager" or u.scope_offices or u.scope_departments:
        perms -= SCOPED_FORBIDDEN
    return perms


def allowed(perms: set, needed: str) -> bool:
    if needed == "":
        return True
    return any(p in perms for p in needed.split("|"))


def landing(perms: set) -> str:
    return next((url for p, url in LANDING if p in perms), "/account")


# ------------------------------------------------------------------ passwords (scrypt)
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


def password_problem(password: str) -> str:
    if len(password) < 8:
        return "رمز باید حداقل ۸ کاراکتر باشد"
    if password.isdigit() or password.isalpha():
        return "رمز باید ترکیبی از حرف و عدد باشد"
    return ""


MAX_FAILS, LOCK_MINUTES = 5, 10


def ad_name(username: str) -> str:
    """sAMAccountName out of 'DOMAIN\\name' or 'name@domain'."""
    u = (username or "").strip()
    if "\\" in u:
        u = u.split("\\", 1)[1]
    return u.split("@", 1)[0] if "@" in u else u


def find_panel_user(db, username: str):
    username = (username or "").strip()
    if not username:
        return None
    u = db.query(PanelUser).filter(PanelUser.username == username).first()
    if u is None:   # AD accounts: any case, also typed as DOMAIN\name or name@domain
        u = db.query(PanelUser).filter(PanelUser.source == "ldap",
                                       func.lower(PanelUser.username) == ad_name(username).lower()).first()
    return u


def is_local(u) -> bool:
    return (u.source or "local") != "ldap"


def check_login(db, username: str, password: str):
    """Returns (PanelUser or None, error message). AD panel accounts sign in with their domain password."""
    u = find_panel_user(db, username)
    if u is None:
        verify_password(password, hash_password("x"))  # constant-ish time
        return None, "نام کاربری یا رمز عبور اشتباه است"
    if u.locked_until and u.locked_until > now():
        return None, "به دلیل تلاش‌های ناموفق، این حساب چند دقیقه قفل است"
    if is_local(u):
        ok = verify_password(password, u.password_hash)
    else:
        from . import ldap_ad
        ok, why = ldap_ad.authenticate(db, u.username, password)
        if not ok and not why.startswith("AD:") and why != "رمز خالی":     # AD not reachable / not set up
            return None, f"ورود با حساب Active Directory ممکن نشد: {why}"
    if not ok:
        u.failed_count = (u.failed_count or 0) + 1
        if u.failed_count >= MAX_FAILS:
            u.locked_until, u.failed_count = now() + timedelta(minutes=LOCK_MINUTES), 0
        db.commit()
        return None, "نام کاربری یا رمز عبور اشتباه است"
    if not u.enabled:
        return None, "این حساب غیرفعال است"
    u.failed_count, u.locked_until, u.last_login = 0, None, now()
    if not is_local(u):
        link_ad_user(db, u, ad_internet_user(db, u.username, refresh=True))
    db.commit()
    return u, ""


def ad_internet_user(db, username: str, refresh=False):
    """The internet user of this AD account (imported from AD first when refresh, so office / unit are current).
    None when the account is outside the Base DN / filter used for internet users."""
    if refresh:
        from . import ldap_ad
        try:
            ldap_ad.sync_users(db, only_usernames={username})
        except Exception as e:
            log.warning("AD lookup of panel account %s failed: %s", username, e)
    return db.query(User).filter(User.source == "ldap", func.lower(User.username) == username.lower()).first()


def link_ad_user(db, a, user):
    """An AD panel account and the internet user of the same account are one person: the panel account takes
    its name, and its office / unit as scope when chosen (they follow AD on every sync and login)."""
    if is_local(a):
        a.user_id = None
        return
    a.user_id = user.id if user else None
    if user is not None and user.full_name and not a.full_name:
        a.full_name = user.full_name
    if a.scope_own_office:
        a.scope_offices = str(user.office_id) if user is not None and user.office_id else "0"
    if a.scope_own_department:
        a.scope_departments = str(user.department_id) if user is not None and user.department_id else "0"


def link_ad_users(db, usernames=None):
    """After an AD sync: refresh the scope of AD panel accounts from their (updated) internet users."""
    q = db.query(PanelUser).filter(PanelUser.source == "ldap")
    for a in q:
        if usernames is None or a.username.lower() in usernames:
            link_ad_user(db, a, ad_internet_user(db, a.username))


def local_admins_left(db, exclude_id) -> int:
    """Enabled local (non-AD) administrators other than this one: the panel must stay reachable without AD."""
    return db.query(PanelUser).filter(PanelUser.role == "admin", PanelUser.enabled.is_(True),
                                      func.coalesce(PanelUser.source, "local") != "ldap",
                                      PanelUser.id != (exclude_id or 0)).count()


def audit(db, username: str, action: str, detail: str = "", ip: str = ""):
    db.add(AuditLog(username=username or "-", action=action[:100], detail=(detail or "")[:500], ip=ip or ""))
    db.commit()


DEFAULT_PASSWORDS = {"it": "it12345678", "hr": "hr12345678"}


def bootstrap_panel_users(db):
    """First run: create the admin from ADMIN_USER/ADMIN_PASSWORD plus IT and HR accounts. IT / HR stay disabled
    until an admin enables them (or IT_PASSWORD / HR_PASSWORD give them a real password): with a well-known
    password anyone who reaches the panel first could take them over."""
    if db.query(PanelUser).count():
        secure_default_accounts(db)
        return
    defaults = [
        (config.ADMIN_USER, config.ADMIN_PASSWORD, "admin", "مدیر سیستم", True),
        (os.environ.get("IT_USER", "it"), os.environ.get("IT_PASSWORD", ""), "it", "کارشناس IT", False),
        (os.environ.get("HR_USER", "hr"), os.environ.get("HR_PASSWORD", ""), "hr", "کارشناس منابع انسانی", False),
    ]
    for username, password, role, name, is_admin in defaults:
        enabled = is_admin or bool(password and not password_problem(password))
        password = password or DEFAULT_PASSWORDS.get(role, "")
        weak = password in ("admin", *DEFAULT_PASSWORDS.values()) or bool(password_problem(password))
        db.add(PanelUser(username=username, full_name=name, role=role, password_hash=hash_password(password),
                         must_change_password=weak, enabled=enabled))
    from .db import set_setting
    set_setting(db, "default_accounts_secured", "1")
    db.commit()


def secure_default_accounts(db):
    """Older versions created it / hr enabled with a known password: disable them (once, on the first start of
    this version) while that password is unchanged."""
    from .db import get_setting, set_setting
    if get_setting(db, "default_accounts_secured") == "1":
        return
    set_setting(db, "default_accounts_secured", "1")
    for u in db.query(PanelUser).filter(PanelUser.role.in_(list(DEFAULT_PASSWORDS)), PanelUser.enabled.is_(True),
                                        PanelUser.must_change_password.is_(True)):
        if verify_password(DEFAULT_PASSWORDS[u.role], u.password_hash):
            u.enabled = False
            log.warning("panel account %s still had its default password and was disabled", u.username)
    db.commit()


def _cli():
    from .db import SessionLocal, init_db
    if len(sys.argv) != 4 or sys.argv[1] != "reset":
        print("usage: python -m app.auth reset <username> <new-password>")
        sys.exit(1)
    init_db()
    db = SessionLocal()
    u = db.query(PanelUser).filter(PanelUser.username == sys.argv[2]).first()
    if u is None:
        u = PanelUser(username=sys.argv[2], role="admin", full_name="مدیر سیستم")
        db.add(u)
    u.password_hash, u.enabled, u.locked_until, u.must_change_password = hash_password(sys.argv[3]), True, None, True
    u.source = "local"
    db.commit()
    print(f"password of {u.username} reset (role={u.role}); it must be changed at next login")


if __name__ == "__main__":
    _cli()
