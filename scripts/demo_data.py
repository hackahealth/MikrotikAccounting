"""ساخت داده نمونه برای دیدن پنل بدون روتر:  python -m scripts.demo_data"""
import random
from datetime import timedelta

from app.auth import hash_password
from app.db import (AcctSession, Department, Device, Group, Nas, Office, PanelUser, SessionLocal, SpeedSample,
                    TrafficCategory, TrafficDomain, User, encrypt, init_db, now)

random.seed(7)
init_db()
db = SessionLocal()
staff = Group(name="کارمندان", rate_limit="2M/8M", quota_mb=50 * 1024, quota_period="monthly",
              allowed_hours="sat-wed 07:00-19:00; thu 07:00-14:00", simultaneous_use=2)
guests = Group(name="مهمان", rate_limit="512k/2M", quota_mb=2048, quota_period="daily", allow_vpn=False)
mgmt = Group(name="مدیران", rate_limit="10M/20M", quota_mb=0, simultaneous_use=3)
db.add_all([staff, guests, mgmt, Nas(name="دفتر مرکزی", ip="192.168.88.1", secret="demo",
                                         wan_interfaces="ether1", lan_ranges="192.168.100.0/24")])
yazd, tehran = Office(name="دفتر یزد", city="یزد"), Office(name="دفتر تهران", city="تهران")
db.add_all([yazd, tehran])
db.flush()
fin, tech = Department(name="مالی"), Department(name="فنی")
db.add_all([fin, tech])
db.flush()
db.add(PanelUser(username="yazd", full_name="مدیر دفتر یزد", role="unit_manager", scope_offices=str(yazd.id),
                 password_hash=hash_password("Yazd12345")))
org = {"ali": (yazd, fin), "sara": (yazd, tech), "reza": (tehran, fin), "guest01": (None, None), "maryam": (tehran, tech),
       "hamed": (yazd, tech)}
people = [("ali", "علی رضایی", staff, "local"), ("sara", "سارا محمدی", staff, "ldap"), ("reza", "رضا کریمی", mgmt, "ldap"),
          ("guest01", "مهمان ۱", guests, "local"), ("maryam", "مریم احمدی", staff, "ldap"), ("hamed", "حامد نوری", staff, "local")]
devs = [("3C:22:FB:10:00:01", "mobile", "iOS", "Apple, Inc."), ("8C:EC:4B:10:00:02", "pc", "Windows", "Dell Inc."),
        ("DA:A1:19:10:00:03", "mobile", "Android", "MAC تصادفی"), ("F4:8C:50:10:00:04", "pc", "Windows", "Intel Corporate")]
cats = ["video", "web", "social", "messaging", "download", "update", "voip", "music", "cloud", "ai", "lan"]
doms = {"video": ["googlevideo.com", "aparat.com", "filimo.com"], "web": ["digikala.com", "google.com", "varzesh3.com"],
        "social": ["cdninstagram.com", "twimg.com"], "messaging": ["Telegram", "whatsapp.net"],
        "download": ["soft98.ir", "objects.githubusercontent.com"], "update": ["windowsupdate.com"],
        "voip": ["skyroom.online"], "music": ["radiojavan.com"], "cloud": ["dropbox.com"], "ai": ["chatgpt.com"],
        "lan": ["fileserver.corp.local", "erp.corp.local", "192.168.100.20"]}
t0 = now()
for i, (un, fn, g, src) in enumerate(people):
    u = User(username=un, full_name=fn, group=g, source=src, password_enc=encrypt("1234") if src == "local" else "",
             last_login=t0 - timedelta(hours=i), office=org[un][0], department=org[un][1],
             personnel_code=str(1000 + i) if org[un][0] else "")
    db.add(u)
    db.flush()
    for day in range(10):
        start = (t0 - timedelta(days=day)).replace(hour=random.randint(7, 11), minute=random.randint(0, 59))
        if start > t0:
            continue
        mac, dt, os_, vendor = random.choice(devs)
        dur = random.randint(3600, 8 * 3600)
        active = day == 0 and i < 4
        stop = None if active else start + timedelta(seconds=dur)
        s = AcctSession(acct_session_id=f"{un}-{day}", nas_ip="192.168.88.1", username=un, user_id=u.id,
                        service="vpn" if (i == 2 and day % 2) else "hotspot", framed_ip=f"10.5.50.{10 + i}",
                        mac=mac, start_time=start, last_update=t0 if active else stop, stop_time=stop,
                        session_time=dur, device_type=dt, device_os=os_, active=active,
                        terminate_cause="" if active else random.choice(["User-Request", "Idle-Timeout", "Lost-Carrier"]))
        db.add(s)
        db.flush()
        total_in = total_out = 0
        for h in range(0, dur, 900):
            ts = start + timedelta(seconds=h)
            if ts > t0:
                break
            d_out = random.randint(1, 60) * 1024 * 1024
            d_in = d_out // random.randint(5, 15)
            total_in += d_in
            total_out += d_out
            db.add(SpeedSample(session_id=s.id, user_id=u.id, ts=ts, seconds=900, d_in=d_in, d_out=d_out))
            c = random.choices(cats, weights=[30, 20, 12, 8, 10, 4, 4, 3, 2, 2, 18])[0]
            row = db.query(TrafficCategory).filter_by(user_id=u.id, day=ts.date(), hour=ts.hour, category=c).first()
            if row is None:
                db.add(TrafficCategory(user_id=u.id, day=ts.date(), hour=ts.hour, category=c, bytes_down=d_out,
                                       bytes_up=d_in, flows=random.randint(5, 200)))
                db.flush()
            else:
                row.bytes_down += d_out
                row.bytes_up += d_in
            d = random.choice(doms[c])
            row = db.query(TrafficDomain).filter_by(user_id=u.id, day=ts.date(), domain=d).first()
            if row is None:
                db.add(TrafficDomain(user_id=u.id, day=ts.date(), domain=d, category=c, bytes_down=d_out, bytes_up=d_in))
                db.flush()
            else:
                row.bytes_down += d_out
                row.bytes_up += d_in
        s.bytes_in, s.bytes_out = total_in, total_out
        s.peak_down_bps = random.randint(2, 8) * 1_000_000
for mac, dt, os_, vendor in devs:
    db.add(Device(mac=mac, device_type=dt, os=os_, vendor=vendor, detected_by="mac-vendor"))
db.commit()
print("demo data created")
