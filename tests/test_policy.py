from datetime import datetime

from app import jalali, policy


def test_hours():
    r = policy.parse_hours("sat-wed 08:00-17:00; thu 08:00-13:00")
    assert policy.hours_allowed(r, datetime(2026, 10, 17, 9, 0))      # Saturday
    assert not policy.hours_allowed(r, datetime(2026, 10, 17, 18, 0))
    assert not policy.hours_allowed(r, datetime(2026, 10, 16, 9, 0))  # Friday
    assert policy.hours_allowed(r, datetime(2026, 10, 15, 12, 59))    # Thursday
    assert policy.seconds_until_denied(r, datetime(2026, 10, 17, 16, 0)) == 3600


def test_hours_persian_and_midnight():
    r = policy.parse_hours("جمعه 22:00-02:00")
    assert policy.hours_allowed(r, datetime(2026, 10, 16, 23, 0))
    assert policy.hours_allowed(r, datetime(2026, 10, 17, 1, 0))
    assert not policy.hours_allowed(r, datetime(2026, 10, 17, 3, 0))


def test_jalali():
    assert jalali.g2j(2026, 10, 15) == (1405, 7, 23)
    assert jalali.parse_date("1405/07/23").isoformat() == "2026-10-15"
