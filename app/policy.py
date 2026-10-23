"""سیاست‌ها: ساعات مجاز، سهمیه حجم، سرعت، تعداد اتصال همزمان."""
import re
from datetime import datetime, timedelta

from sqlalchemy import func

from . import config
from .db import AcctSession, SpeedSample, TrafficCategory, User, get_setting, now
from .jalali import jalali_month_start

DAY_ORDER = ["sat", "sun", "mon", "tue", "wed", "thu", "fri"]
PY_WEEKDAY = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
FA_DAYS = {"شنبه": "sat", "یکشنبه": "sun", "دوشنبه": "mon", "سه‌شنبه": "tue", "سهشنبه": "tue", "سه شنبه": "tue",
           "چهارشنبه": "wed", "پنجشنبه": "thu", "پنج‌شنبه": "thu", "جمعه": "fri"}


def parse_hours(spec: str):
    """'sat-wed 08:00-17:00; thu 08:00-13:00; fri 22:00-02:00' -> [(weekdays set, start_min, end_min)].
    Empty spec -> None (no restriction). Raises ValueError on bad syntax."""
    spec = (spec or "").strip()
    if not spec:
        return None
    for fa, en in sorted(FA_DAYS.items(), key=lambda x: -len(x[0])):
        spec = spec.replace(fa, en)
    spec = spec.translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789"))
    rules = []
    for part in re.split(r"[;\n]+", spec):
        part = part.strip().lower()
        if not part:
            continue
        m = re.fullmatch(r"([a-z,\- ]+?)\s+(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})", part)
        if not m:
            raise ValueError(f"قاعده نامعتبر: {part}")
        days = set()
        for token in m.group(1).replace(" ", "").split(","):
            if token in ("all", "*"):
                days.update(PY_WEEKDAY.values())
            elif "-" in token:
                a, b = token.split("-")
                ia, ib = DAY_ORDER.index(a), DAY_ORDER.index(b)
                i = ia
                while True:
                    days.add(PY_WEEKDAY[DAY_ORDER[i]])
                    if i == ib:
                        break
                    i = (i + 1) % 7
            else:
                days.add(PY_WEEKDAY[token])
        start = int(m.group(2)) * 60 + int(m.group(3))
        end = int(m.group(4)) * 60 + int(m.group(5))
        if not (0 <= start <= 1440 and 0 <= end <= 1440):
            raise ValueError(f"ساعت نامعتبر: {part}")
        rules.append((days, start, end))
    return rules


def hours_allowed(rules, dt: datetime) -> bool:
    if rules is None:
        return True
    t = dt.hour * 60 + dt.minute
    wd = dt.weekday()
    prev = (wd - 1) % 7
    for days, start, end in rules:
        if start < end:
            if wd in days and start <= t < end:
                return True
        elif start > end:  # crosses midnight
            if (wd in days and t >= start) or (prev in days and t < end):
                return True
        else:  # start == end -> whole day
            if wd in days:
                return True
    return False


def seconds_until_denied(rules, dt: datetime):
    """Seconds the user may stay connected from dt (None = unlimited)."""
    if rules is None:
        return None
    probe = dt.replace(second=0, microsecond=0)
    for i in range(1, 7 * 1440 + 1):
        probe += timedelta(minutes=1)
        if not hours_allowed(rules, probe):
            return max(60, int((probe - dt).total_seconds()))
    return None


class Effective:
    """Resolved settings for a user (user overrides > group)."""

    def __init__(self, user: User):
        g = user.group
        self.rate_limit = user.rate_limit or (g.rate_limit if g else "")
        self.quota_mb = user.quota_mb if user.quota_mb is not None else (g.quota_mb if g else 0)
        self.quota_period = user.quota_period or (g.quota_period if g else "monthly")
        self.allowed_hours = user.allowed_hours or (g.allowed_hours if g else "")
        self.simultaneous_use = user.simultaneous_use if user.simultaneous_use is not None else (
            g.simultaneous_use if g else 1)
        self.session_timeout = (g.session_timeout_min * 60) if g and g.session_timeout_min else 0
        self.idle_timeout = (g.idle_timeout_min * 60) if g and g.idle_timeout_min else 0
        self.allow_hotspot = g.allow_hotspot if g else True
        self.allow_vpn = g.allow_vpn if g else True
        self.address_list = g.address_list if g else ""


def period_start(period: str, ref: datetime = None) -> datetime:
    ref = ref or now()
    today = ref.date()
    if period == "daily":
        d = today
    elif period == "weekly":  # Iranian week starts Saturday
        d = today - timedelta(days=(today.weekday() - 5) % 7)
    elif period == "monthly":
        d = jalali_month_start(today)
    else:
        return datetime(2000, 1, 1)
    return datetime(d.year, d.month, d.day)


def internet_only(db) -> bool:
    """Quota counts internet traffic only: internal-network and tunnel traffic (Traffic-Flow) is not deducted."""
    return get_setting(db, "quota_internet_only", "1") == "1"


def usage_bytes(db, user: User, since: datetime) -> int:
    if user.usage_reset_at and user.usage_reset_at > since:
        since = user.usage_reset_at
    total = db.query(func.coalesce(func.sum(SpeedSample.d_in + SpeedSample.d_out), 0)) \
        .filter(SpeedSample.user_id == user.id, SpeedSample.ts >= since).scalar()
    total = int(total or 0)
    if total and internet_only(db):
        free = db.query(func.coalesce(func.sum(TrafficCategory.bytes_down + TrafficCategory.bytes_up), 0)).filter(
            TrafficCategory.user_id == user.id, TrafficCategory.category.in_(("lan", "tunnel")),
            (TrafficCategory.day > since.date())
            | ((TrafficCategory.day == since.date()) & (TrafficCategory.hour >= since.hour))).scalar()
        total -= min(int(free or 0), total)
    return total


def quota_state(db, user: User, eff: Effective = None):
    """Returns (quota_bytes or None, used_bytes, remaining_bytes or None)."""
    eff = eff or Effective(user)
    used = usage_bytes(db, user, period_start(eff.quota_period))
    if not eff.quota_mb:
        return None, used, None
    q = int(eff.quota_mb) * 1024 * 1024
    return q, used, max(0, q - used)


def warn_pct(db) -> int:
    try:
        return max(1, min(100, int(get_setting(db, "quota_warn_pct", "80") or 80)))
    except ValueError:
        return 80


def size_fa(n) -> str:
    n = float(n or 0)
    if n >= 1024 ** 3:
        s = f"{n / 1024 ** 3:.1f} گیگابایت"
    else:
        s = f"{n / 1024 ** 2:.0f} مگابایت"
    return s.translate(str.maketrans("0123456789.", "۰۱۲۳۴۵۶۷۸۹/"))


def quota_warning(db, user: User):
    """{'pct','used','quota','remaining','text','level'} once usage passed quota_warn_pct, else None."""
    eff = Effective(user)
    quota, used, remaining = quota_state(db, user, eff)
    if not quota:
        return None
    from . import grants
    if grants.active(db, user.id, "internet"):
        return None
    pct = min(100, round(100 * used / quota))
    if pct < warn_pct(db):
        return None
    fa = str(pct).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹"))
    if remaining <= 0:
        text, level = "حجم اینترنت شما تمام شده است.", "err"
    else:
        text, level = f"{fa}٪ حجم اینترنت شما مصرف شده؛ باقی‌مانده: {size_fa(remaining)}", "warn"
    return {"pct": pct, "used": used, "quota": quota, "remaining": remaining, "text": text, "level": level}


def active_session_count(db, user: User, exclude_mac: str = "") -> int:
    stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    q = db.query(AcctSession).filter(AcctSession.user_id == user.id, AcctSession.active.is_(True),
                                     AcctSession.last_update >= stale)
    if exclude_mac:
        q = q.filter(AcctSession.mac != exclude_mac)
    return q.count()


def check_access(db, user: User, service: str, mac: str = "", when: datetime = None):
    """Policy checks after password verification. Returns (ok, reason, reply_attrs dict)."""
    when = when or now()
    eff = Effective(user)
    if not user.enabled:
        return False, "کاربر غیرفعال است", {}
    if user.expire_at and when.date() > user.expire_at:
        return False, "اعتبار کاربر منقضی شده", {}
    if service == "hotspot" and not eff.allow_hotspot:
        return False, "هات‌اسپات برای گروه مجاز نیست", {}
    if service == "vpn" and not eff.allow_vpn:
        return False, "VPN برای گروه مجاز نیست", {}
    if user.allowed_macs and mac:
        allowed = {m.strip().upper().replace("-", ":") for m in user.allowed_macs.split(",") if m.strip()}
        if mac.upper().replace("-", ":") not in allowed:
            return False, "دستگاه (MAC) مجاز نیست", {}
    try:
        rules = parse_hours(eff.allowed_hours)
    except ValueError:
        rules = None
    from . import grants
    hours_grant = grants.active(db, user.id, "hours", when)
    if not hours_allowed(rules, when) and not hours_grant:
        return False, "خارج از ساعات مجاز", {}
    quota, used, remaining = quota_state(db, user, eff)
    if grants.active(db, user.id, "internet", when):
        quota = remaining = None                  # temporary free internet: no quota
    if quota is not None and remaining <= 0:
        return False, "حجم مجاز تمام شده", {}
    if eff.simultaneous_use and active_session_count(db, user, exclude_mac=mac) >= eff.simultaneous_use:
        return False, "تعداد اتصال همزمان بیش از حد مجاز", {}

    attrs = {"Acct-Interim-Interval": config.ACCT_INTERIM}
    if eff.rate_limit:
        attrs["Mikrotik-Rate-Limit"] = eff.rate_limit
    # with a temporary out-of-hours permission the app disconnects the user when it ends (enforce job)
    timeouts = [t for t in (None if hours_grant else seconds_until_denied(rules, when), eff.session_timeout) if t]
    if user.expire_at:
        exp = datetime(user.expire_at.year, user.expire_at.month, user.expire_at.day) + timedelta(days=1)
        timeouts.append(max(60, int((exp - when).total_seconds())))
    if timeouts:
        attrs["Session-Timeout"] = min(timeouts)
    if eff.idle_timeout:
        attrs["Idle-Timeout"] = eff.idle_timeout
    if remaining is not None and not internet_only(db):        # the router would count internal traffic too
        attrs["Mikrotik-Total-Limit"] = remaining & 0xFFFFFFFF
        attrs["Mikrotik-Total-Limit-Gigawords"] = remaining >> 32
    if user.static_ip:
        attrs["Framed-IP-Address"] = user.static_ip
    if eff.address_list:
        attrs["Mikrotik-Address-List"] = eff.address_list
    return True, "", attrs
