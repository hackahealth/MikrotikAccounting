"""ریست رمز با پیامک.

* مدیر از پنل: رمز تصادفی جدید روی AD (یا کاربر محلی) گذاشته و با نام کاربری به موبایل کاربر پیامک می‌شود.
* خود کاربر از صفحهٔ ورود (/forgot): شماره موبایل -> کد تایید پیامکی -> رمز جدید دلخواه برای کاربر AD.

Mobile numbers come from the AD attribute "mobile" (User.mobile after AD sync; read live from AD as well)."""
import hashlib
import hmac
import logging
import re
import secrets
from datetime import timedelta

from . import config, sms
from .db import ResetCode, User, encrypt, now

log = logging.getLogger("pwreset")

CODE_MINUTES = 5
CODE_TRIES = 5
RESEND_SECONDS = 60
PER_MOBILE_DAY = 6
PER_IP_HOUR = 15


class ResetError(Exception):
    pass


def gen_password(length=10) -> str:
    """Random password that passes the default AD complexity rule (upper, lower, digit), easy to type from an SMS."""
    upper, lower, digits = "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnpqrstuvwxyz", "23456789"
    while True:
        p = [secrets.choice(upper), secrets.choice(lower)] + [secrets.choice(lower + digits) for _ in range(length - 4)] \
            + [secrets.choice(digits), secrets.choice(digits)]
        s = "".join(p)
        if any(c.isdigit() for c in s) and any(c.islower() for c in s):
            return s


def check_strength(pw: str, username: str = "") -> str:
    """'' when acceptable, else the reason (AD may still refuse it by its own policy)."""
    if len(pw) < 8:
        return "رمز باید دست‌کم ۸ نویسه باشد"
    kinds = sum(bool(re.search(rx, pw)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if kinds < 3:
        return "رمز باید دست‌کم سه نوع از این‌ها را داشته باشد: حرف کوچک، حرف بزرگ، عدد، نشانه"
    if username and len(username) >= 3 and username.lower() in pw.lower():
        return "رمز نباید نام کاربری را در خود داشته باشد"
    return ""


def _digits(v) -> str:
    return str(v or "").translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")).strip()


def _hash(mobile, code) -> str:
    return hmac.new(config.SECRET_KEY.encode(), f"{mobile}:{code}".encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ who has this mobile
def _ad_mobile(db, user) -> str:
    """The user's mobile read live from AD ('' if not an AD user / AD not reachable)."""
    if user.source != "ldap":
        return ""
    try:
        from . import ad_admin
        with ad_admin.AD(db) as ad:
            dn = user.ldap_dn or ad.find_user(user.username)
            rows = ad._search(dn, "(objectClass=user)", ["mobile"], scope="BASE") if dn else []
            return str(ad_admin._v(rows[0], "mobile", "") or "") if rows else ""
    except Exception as e:      # noqa: BLE001
        log.info("AD mobile of %s: %s", user.username, e)
        return ""


def user_mobile(db, user) -> str:
    """Mobile for this user: AD (live) first, then the synced User.mobile. Updates User.mobile when AD differs."""
    live = sms.normalize_mobile(_ad_mobile(db, user))
    if live and live != sms.normalize_mobile(user.mobile):
        user.mobile = live
        db.commit()
    return live or sms.normalize_mobile(user.mobile)


def users_for_mobile(db, mobile):
    """Enabled local / AD users whose mobile is this number (synced data plus a live AD search)."""
    m = sms.normalize_mobile(mobile)
    if not m:
        return []
    found = {u.id: u for u in db.query(User).filter(User.mobile != "", User.enabled.is_(True)).all()
             if sms.normalize_mobile(u.mobile) == m and u.source in ("ldap", "local")}
    try:        # numbers typed into AD after the last sync
        from . import ad_admin, ldap_ad
        if ldap_ad.enabled(db):
            variants = {m, "+98" + m[1:], "98" + m[1:], "0098" + m[1:], m[1:]}
            flt = "(&(objectClass=user)(|" + "".join(f"(mobile={ldap_ad._escape(v)})" for v in variants) + "))"
            with ad_admin.AD(db) as ad:
                for e in ad._search(ad.base, flt, ["sAMAccountName"], limit=20):
                    sam = str(ad_admin._v(e, "sAMAccountName", "") or "")
                    u = next((x for x in db.query(User).filter(User.username.ilike(sam)).all()
                              if x.username.lower() == sam.lower()), None) if sam else None
                    if u is not None and u.enabled and u.id not in found:
                        if not u.ldap_dn:
                            u.ldap_dn = e["dn"]
                        u.mobile = m
                        found[u.id] = u
            db.commit()
    except Exception as e:      # noqa: BLE001
        log.info("AD search by mobile: %s", e)
    return sorted(found.values(), key=lambda u: u.username.lower())


# ------------------------------------------------------------------ setting the password
def set_password(db, user, password, must_change=False):
    """New password on AD (AD users) or locally (local users). Also clears an AD lockout."""
    if user.source == "ldap":
        from . import ad_admin
        try:
            with ad_admin.AD(db, secure=True) as ad:
                dn = user.ldap_dn or ad.find_user(user.username)
                if not dn:
                    raise ResetError("حساب کاربر در AD پیدا نشد")
                ad.set_password(dn, password, must_change)
                try:
                    ad.unlock(dn)
                except Exception:       # noqa: BLE001
                    pass
                if user.ldap_dn != dn:
                    user.ldap_dn = dn
        except ad_admin.ADError as e:
            raise ResetError(str(e)) from e
    elif user.source == "local":
        user.password_enc = encrypt(password)
    else:
        raise ResetError("رمز اکانت‌های محلی روتر از صفحهٔ «اکانت‌های میکروتیک» عوض می‌شود")
    try:        # a lock from wrong passwords would stop the new password too
        from . import security
        for lk in security.active_locks(db).filter_by(kind="user").all():
            if (lk.value or "").lower() == user.username.lower() and lk.auto:
                security.unlock(db, lk.id, "ریست رمز با پیامک")
    except Exception:       # noqa: BLE001
        pass
    db.commit()


def admin_reset(db, user, must_change=False, by=""):
    """Random new password + SMS with user name and password. Returns (ok, message)."""
    if not sms.enabled(db):
        return False, "ارسال پیامک فعال یا تنظیم نشده (منوی «پیامک»)"
    mobile = user_mobile(db, user)
    if not mobile:
        return False, f"برای {user.username} شماره موبایل معتبر در AD (فیلد Mobile) ثبت نشده"
    pw = gen_password()
    try:
        set_password(db, user, pw, must_change)
    except ResetError as e:
        return False, f"تعیین رمز ناموفق: {e}"
    text = f"{user.full_name or user.username} گرامی، رمز شما ریست شد.\nنام کاربری: {user.username}\nرمز جدید: {pw}"
    if must_change:
        text += "\nدر اولین ورود به ویندوز رمز را عوض کنید."
    ok, err = sms.send(db, mobile, text, "reset_admin", user.username)
    from . import auth
    auth.audit(db, by or "-", "ریست رمز با پیامک", f"{user.username} → {sms.mask(mobile)}" + ("" if ok else f" (پیامک ناموفق: {err})"))
    if not ok:
        return False, f"رمز {user.username} عوض شد ولی پیامک نرفت ({err}). رمز جدید: {pw}"
    return True, f"رمز جدید {user.username} به {sms.mask(mobile)} پیامک شد"


# ------------------------------------------------------------------ self service
def request_code(db, mobile, ip=""):
    """Sends a one-time code. Returns (ok, message, normalized mobile)."""
    m = sms.normalize_mobile(mobile)
    if not m:
        return False, "شماره موبایل را درست وارد کنید (مثل 09121234567)", ""
    from .db import get_setting
    if get_setting(db, "sms_reset_self", "1") != "1" or not sms.enabled(db):
        return False, "بازیابی رمز با پیامک فعال نیست؛ با واحد IT تماس بگیرید", m
    ts = now()
    last = db.query(ResetCode).filter(ResetCode.mobile == m).order_by(ResetCode.id.desc()).first()
    if last and (ts - last.ts).total_seconds() < RESEND_SECONDS:
        wait = RESEND_SECONDS - int((ts - last.ts).total_seconds())
        return False, f"کد قبلی تازه فرستاده شده؛ {wait} ثانیه دیگر دوباره امتحان کنید", m
    if db.query(ResetCode).filter(ResetCode.mobile == m, ResetCode.ts >= ts - timedelta(days=1)).count() >= PER_MOBILE_DAY:
        return False, "تعداد درخواست‌های امروز این شماره زیاد بوده؛ فردا امتحان کنید یا با واحد IT تماس بگیرید", m
    if ip and db.query(ResetCode).filter(ResetCode.ip == ip, ResetCode.ts >= ts - timedelta(hours=1)).count() >= PER_IP_HOUR:
        return False, "درخواست‌های زیاد از این رایانه؛ کمی بعد امتحان کنید", m
    users = [u for u in users_for_mobile(db, m) if u.source in ("ldap", "local")]
    db.add(ResetCode(mobile=m, code_hash="", expires_at=ts, used=True, ip=ip or ""))   # counts toward the limits
    db.commit()
    if not users:
        return False, "این شماره برای هیچ کاربری ثبت نشده؛ با واحد IT تماس بگیرید", m
    code = f"{secrets.randbelow(1000000):06d}"
    db.add(ResetCode(mobile=m, code_hash=_hash(m, code), expires_at=ts + timedelta(minutes=CODE_MINUTES), ip=ip or ""))
    db.commit()
    names = "، ".join(u.username for u in users)
    text = f"کد تایید: {code}\nنام کاربری: {names}\nاین کد برای تغییر رمز است و {CODE_MINUTES} دقیقه اعتبار دارد. آن را به کسی ندهید."
    ok, err = sms.send(db, m, text, "reset_otp", names)
    if not ok:
        return False, f"ارسال پیامک ناموفق بود: {err}", m
    return True, f"کد تایید به {sms.mask(m)} پیامک شد", m


def reset_with_code(db, mobile, code, username, new_password, ip=""):
    """Returns (ok, message)."""
    m = sms.normalize_mobile(mobile)
    code = re.sub(r"\D", "", _digits(code))
    if not m or not code:
        return False, "شماره و کد تایید را وارد کنید"
    ts = now()
    rc = db.query(ResetCode).filter(ResetCode.mobile == m, ResetCode.used.is_(False),
                                    ResetCode.expires_at >= ts).order_by(ResetCode.id.desc()).first()
    if rc is None:
        return False, "کد تایید منقضی شده یا وجود ندارد؛ دوباره کد بگیرید"
    if rc.tries >= CODE_TRIES:
        rc.used = True
        db.commit()
        return False, "چند بار کد اشتباه وارد شد؛ دوباره کد بگیرید"
    if not hmac.compare_digest(rc.code_hash, _hash(m, code)):
        rc.tries += 1
        db.commit()
        return False, "کد تایید درست نیست"
    users = users_for_mobile(db, m)
    username = _digits(username).strip()
    if len(users) == 1 and not username:
        user = users[0]
    else:
        user = next((u for u in users if u.username.lower() == username.lower()), None)
    if user is None:
        return False, "نام کاربری را همان‌طور که در پیامک آمده وارد کنید"
    why = check_strength(new_password, user.username)
    if why:
        return False, why
    try:
        set_password(db, user, new_password, must_change=False)
    except ResetError as e:
        return False, f"تعیین رمز ناموفق: {e}"
    rc.used = True
    db.commit()
    from . import auth
    auth.audit(db, user.username, "ریست رمز با پیامک (خود کاربر)", f"{sms.mask(m)}", ip or "")
    sms.send(db, m, f"رمز کاربر {user.username} تغییر کرد. اگر شما این کار را نکرده‌اید فوراً با واحد IT تماس بگیرید.",
             "reset_done", user.username)
    return True, f"رمز {user.username} تغییر کرد. اکنون با رمز جدید وارد شوید."
