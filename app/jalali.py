"""تبدیل تاریخ میلادی و شمسی."""
from datetime import date, datetime


def g2j(gy, gm, gd):
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = 355666 + (365 * gy) + ((gy2 + 3) // 4) - ((gy2 + 99) // 100) + ((gy2 + 399) // 400) + gd + g_d_m[gm - 1]
    jy = -1595 + (33 * (days // 12053))
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm, jd = 1 + days // 31, 1 + days % 31
    else:
        jm, jd = 7 + (days - 186) // 30, 1 + (days - 186) % 30
    return jy, jm, jd


def j2g(jy, jm, jd):
    jy += 1595
    days = -355668 + (365 * jy) + ((jy // 33) * 8) + (((jy % 33) + 3) // 4) + jd
    days += (jm - 1) * 31 if jm < 7 else ((jm - 7) * 30) + 186
    gy = 400 * (days // 146097)
    days %= 146097
    if days > 36524:
        days -= 1
        gy += 100 * (days // 36524)
        days %= 36524
        if days >= 365:
            days += 1
    gy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        gy += (days - 1) // 365
        days = (days - 1) % 365
    gd = days + 1
    leap = (gy % 4 == 0 and gy % 100 != 0) or (gy % 400 == 0)
    sal_a = [0, 31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    gm = 0
    while gm < 13 and gd > sal_a[gm]:
        gd -= sal_a[gm]
        gm += 1
    return gy, gm, gd


def to_jalali_str(d, with_time=False):
    if d is None:
        return "-"
    if isinstance(d, str):
        d = date.fromisoformat(d[:10])
    jy, jm, jd = g2j(d.year, d.month, d.day)
    s = f"{jy:04d}/{jm:02d}/{jd:02d}"
    if with_time and isinstance(d, datetime):
        s += f" {d.hour:02d}:{d.minute:02d}"
    return s


def parse_date(s: str):
    """Accepts 1404/07/23 (Jalali) or 2025-10-15 (Gregorian)."""
    s = (s or "").strip().translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789"))
    if not s:
        return None
    sep = "/" if "/" in s else "-"
    y, m, d = (int(x) for x in s.split(sep))
    if y < 1700:
        y, m, d = j2g(y, m, d)
    return date(y, m, d)


def jalali_month_start(d: date) -> date:
    jy, jm, _ = g2j(d.year, d.month, d.day)
    return date(*j2g(jy, jm, 1))
