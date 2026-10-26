"""اتصال به سرورهای ایزابل (Asterisk): خواندن سوابق تماس (جدول cdr در asteriskcdrdb) با کاربر فقط‌خواندنی MySQL،
تشخیص جهت تماس، نسبت دادن داخلی به افراد بر اساس بازه زمانی تخصیص، و گزارش تماس‌ها."""
import logging
import re
import threading
from collections import defaultdict
from datetime import timedelta

from .db import (Call, ExtensionAssignment, Group, Office, Department, PbxServer, SessionLocal, User, decrypt, get_setting,
                 now, set_setting)

log = logging.getLogger("pbx")
OVERLAP = timedelta(hours=4)        # CDR rows are written at hang-up with the call's start time: read back this far
BATCH = 5000
_lock = threading.Lock()
status = {}                         # pbx id -> last sync message (for the settings page)


# ------------------------------------------------------------------ parsing
def parse_ranges(text):
    out = []
    for part in re.split(r"[\s,;]+", text or ""):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
        if m:
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            out.append((min(lo, hi), max(lo, hi)))
    return out


def in_ranges(num, ranges):
    num = str(num or "")
    if not num.isdigit() or len(num) > 7 or num.startswith("0"):     # 0... is always an outside number
        return False
    if not ranges:                  # not configured: 2-5 digit numbers are extensions
        return 2 <= len(num) <= 5
    n = int(num)
    return any(lo <= n <= hi for lo, hi in ranges)


def peer(channel):
    """'SIP/101-0000a1b2' -> '101', 'PJSIP/trunk-tci-00000012' -> 'trunk-tci', 'Local/101@from-queue-0001;2' -> '101'."""
    ch = str(channel or "")
    if "/" not in ch:
        return ""
    tech, rest = ch.split("/", 1)
    if tech.lower() == "local":
        return rest.split("@", 1)[0]
    if tech.upper() == "DAHDI":
        return "DAHDI"
    return re.sub(r"-[0-9a-fA-F]{1,8}(;\d)?$", "", rest)


def digits(num):
    s = re.sub(r"[^\d+]", "", str(num or ""))
    if s.startswith("+98"):
        s = "0" + s[3:]
    elif s.startswith("+"):
        s = "00" + s[1:]
    return s


def same_number(a, b):
    a, b = digits(a), digits(b)
    return bool(a) and bool(b) and a[-10:] == b[-10:]


def category(num):
    n = digits(num)
    if n.startswith("00"):
        return "بین‌الملل"
    if n.startswith("09") or (len(n) == 10 and n.startswith("9")):
        return "موبایل"
    if n.startswith("0") and len(n) >= 10:
        return "بین‌شهری"
    if len(n) >= 5:
        return "شهری"
    return "سایر"


class Classifier:
    def __init__(self, server, all_ranges):
        self.ranges = parse_ranges(server.ext_ranges)
        self.trunks = {t.lower() for t in re.split(r"[\s,;]+", server.trunks or "") if t}
        self.all_ranges = all_ranges        # every server's extensions: calls between our own servers are internal

    def is_ext(self, x):
        return in_ranges(x, self.ranges)

    def is_trunk(self, p):
        if not p:
            return False
        if self.trunks:
            return p.lower() in self.trunks or p == "DAHDI"
        return not self.is_ext(p)

    def ours(self, num):
        return any(in_ranges(num, r) for r in self.all_ranges)

    def __call__(self, r):
        """-> (direction, our extension, the other party)"""
        sp, dp = peer(r.get("channel")), peer(r.get("dstchannel"))
        src, dst = str(r.get("src") or ""), str(r.get("dst") or "")
        src_ext = self.is_ext(sp) or (not sp and self.is_ext(src))
        if src_ext:
            ext = sp if self.is_ext(sp) else src
            if self.is_ext(dp) or (not dp and self.is_ext(dst)):
                return "internal", ext, dp if self.is_ext(dp) else dst
            if self.is_trunk(dp) or (dst and not self.is_ext(dst)):
                return ("internal" if self.ours(dst) and len(digits(dst)) <= 7 else "out"), ext, dst
            return "internal", ext, dst
        if self.is_trunk(sp) or (src and not self.is_ext(src)):
            ext = dp if self.is_ext(dp) else (dst if self.is_ext(dst) else "")
            return ("internal" if self.ours(src) and len(digits(src)) <= 7 else "in"), ext, src
        return "unknown", "", dst

    def trunk(self, r, direction):
        """The trunk (SIP peer / DAHDI) of an inbound or outbound leg."""
        p = peer(r.get("channel") if direction == "in" else r.get("dstchannel") if direction == "out" else "")
        return p if p and self.is_trunk(p) else ""


# ------------------------------------------------------------------ extension owners
class Owners:
    def __init__(self, db):
        self.by_ext = defaultdict(list)
        for a in db.query(ExtensionAssignment).all():
            self.by_ext[a.extension].append(a)

    def user(self, pbx_id, ext, day):
        best = None
        for a in self.by_ext.get(str(ext), ()):
            if a.pbx_id not in (None, pbx_id):
                continue
            if (a.start and day < a.start) or (a.end and day > a.end):
                continue
            if best is None or (a.pbx_id is not None and best.pbx_id is None):
                best = a
        return best.user_id if best else None


def relink(db, extension=None):
    """Recompute call owners after assignments change."""
    owners = Owners(db)
    q = db.query(Call).filter(Call.extension != "")
    if extension:
        q = q.filter(Call.extension == str(extension))
    n = 0
    for c in q.yield_per(2000):
        uid = owners.user(c.pbx_id, c.extension, c.ts.date())
        if uid != c.user_id:
            c.user_id = uid
            n += 1
    db.commit()
    return n


def overlapping(db, user_id, pbx_id, ext, start, end, skip_id=None):
    """Another person holding the same extension in an overlapping period (same server or 'all servers')."""
    q = db.query(ExtensionAssignment).filter(ExtensionAssignment.extension == ext,
                                             ExtensionAssignment.user_id != user_id)
    if skip_id:
        q = q.filter(ExtensionAssignment.id != skip_id)
    for a in q:
        if pbx_id is not None and a.pbx_id is not None and a.pbx_id != pbx_id:
            continue
        if (a.end is None or start is None or a.end >= start) and (end is None or a.start is None or a.start <= end):
            return a
    return None


# ------------------------------------------------------------------ reading the CDR
def _pymysql():
    try:
        import pymysql
    except ImportError:                      # bundled copy in app/vendor (no pip / download needed)
        import os, sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "vendor"))
        import pymysql
    return pymysql


def _connect(server, timeout=10):
    pymysql = _pymysql()
    return pymysql.connect(host=server.host, port=server.port or 3306, user=server.db_user,
                           password=decrypt(server.db_password_enc), database=server.db_name or "asteriskcdrdb",
                           charset="utf8", connect_timeout=timeout, read_timeout=120,
                           cursorclass=pymysql.cursors.DictCursor)


WANTED = ("calldate", "src", "dst", "channel", "dstchannel", "disposition", "duration", "billsec", "uniqueid",
          "linkedid", "sequence", "did", "dcontext", "lastapp")


def fetch(server, since, limit=BATCH):
    """CDR rows with calldate >= since, oldest first. Replaced in tests."""
    conn = _connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM cdr")
            have = {r["Field"] for r in cur.fetchall()}
            cols = ", ".join(c for c in WANTED if c in have)
            cur.execute(f"SELECT {cols} FROM cdr WHERE calldate >= %s ORDER BY calldate LIMIT %s", (since, limit))
            return cur.fetchall()
    finally:
        conn.close()


def test(server):
    """(ok, message) for the settings page."""
    try:
        conn = _connect(server, 8)
    except Exception as e:
        return False, f"اتصال به MySQL ناموفق: {e}"
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n, MIN(calldate) AS a, MAX(calldate) AS b FROM cdr")
            r = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS n FROM cdr WHERE calldate >= %s", (now() - timedelta(days=7),))
            week = cur.fetchone()["n"]
        return True, f"اتصال برقرار است: {r['n']} رکورد تماس (از {r['a']} تا {r['b']})، {week} رکورد در ۷ روز اخیر."
    except Exception as e:
        return False, f"اتصال برقرار شد ولی جدول cdr خوانده نشد: {e}"
    finally:
        conn.close()


def queue_of(r):
    """The queue number of a CDR row that went through Queue() (FreePBX / Issabel context ext-queues)."""
    if str(r.get("lastapp") or "").lower() == "queue" or str(r.get("dcontext") or "") == "ext-queues":
        return str(r.get("dst") or "")[:32]
    return ""


def answered_leg(c):
    """Talked to a person: Queue() itself answers the caller, so a queue leg counts only when an agent took it."""
    if c.disposition != "ANSWERED" or not c.billsec:
        return False
    return not (c.queue and c.extension in ("", c.queue))


def _key(r):
    uid = str(r.get("uniqueid") or "")
    if r.get("sequence") not in (None, ""):
        return f"{uid}:{r['sequence']}"[:120]
    return f"{uid}:{r.get('dst', '')}:{r.get('dstchannel', '')}:{r.get('calldate')}"[:120]


def store(db, server, rows, classify, owners):
    if not rows:
        return 0
    t0 = min(r["calldate"] for r in rows)
    seen = {k: (i, t) for k, i, t in db.query(Call.key, Call.id, Call.trunk).filter(
        Call.pbx_id == server.id, Call.ts >= t0 - timedelta(minutes=1))}
    n = 0
    for r in rows:
        k = _key(r)
        if not r.get("calldate"):
            continue
        if k in seen:
            cid, trunk = seen[k]
            if cid and not trunk:                   # read again (older history): fill the trunk of older versions
                t = classify.trunk(r, classify(r)[0])
                if t:
                    db.query(Call).filter(Call.id == cid).update({"trunk": t[:64]})
                    seen[k] = (cid, t)
            continue
        seen[k] = (None, "")
        direction, ext, other = classify(r)
        ts = r["calldate"]
        db.add(Call(pbx_id=server.id, key=k, linkedid=str(r.get("linkedid") or r.get("uniqueid") or k)[:64], ts=ts,
                    direction=direction, extension=str(ext or "")[:32], other=str(other or "")[:64],
                    user_id=owners.user(server.id, ext, ts.date()) if ext else None,
                    disposition=str(r.get("disposition") or "")[:20], duration=int(r.get("duration") or 0),
                    billsec=int(r.get("billsec") or 0), src=str(r.get("src") or "")[:64],
                    dst=str(r.get("dst") or "")[:64], did=str(r.get("did") or "")[:64],
                    queue=queue_of(r), trunk=classify.trunk(r, direction)[:64]))
        n += 1
    return n


def sync_server(db, server, all_ranges, owners, max_batches=40):
    since = (server.cursor - OVERLAP) if server.cursor else now() - timedelta(days=7)
    classify = Classifier(server, all_ranges)
    total = 0
    for _ in range(max_batches):
        rows = fetch(server, since)
        total += store(db, server, rows, classify, owners)
        if rows:
            newest = max(r["calldate"] for r in rows)
            server.cursor = max(server.cursor or newest, newest)
        db.commit()
        if len(rows) < BATCH:
            break
        since = max(r["calldate"] for r in rows)
        if since == min(r["calldate"] for r in rows):     # a whole batch in one second: step past it
            since += timedelta(seconds=1)
    return total


def sync_all():
    if not _lock.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        servers = db.query(PbxServer).filter(PbxServer.enabled.is_(True)).all()
        if not servers:
            return
        all_ranges = [parse_ranges(s.ext_ranges) for s in db.query(PbxServer).all()]
        owners = Owners(db)
        for s in servers:
            if not s.db_user:            # administration through the API only: no CDR database to read
                continue
            try:
                n = sync_server(db, s, all_ranges, owners)
                s.last_error = ""
                s.imported = (s.imported or 0) + n
            except Exception as e:
                db.rollback()
                s = db.get(PbxServer, s.id)
                s.last_error = str(e)[:500]
                log.warning("pbx %s: %s", s.name, e)
            s.last_sync = now()
            db.commit()
        try:
            missed_alert(db)
            db.commit()
        except Exception as e:  # noqa: BLE001
            db.rollback()
            log.warning("missed-call alert: %s", e)
    finally:
        db.close()
        SessionLocal.remove()
        _lock.release()


# ------------------------------------------------------------------ reports
DIR_FA = {"in": "ورودی", "out": "خروجی", "internal": "داخلی", "unknown": "نامشخص"}
WEEKDAYS = ["شنبه", "یکشنبه", "دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه"]


def _query(db, start, end, ids=None, pbx_id=None):
    q = db.query(Call).filter(Call.ts >= start, Call.ts < end)
    if ids is not None:
        q = q.filter(Call.user_id.in_(ids or [-1]))
    if pbx_id:
        q = q.filter(Call.pbx_id == pbx_id)
    return q


def build(db, start, end, ids=None, pbx_id=None, top=15):
    legs = _query(db, start, end, ids, pbx_id).order_by(Call.ts).all()
    calls = {}                                     # (pbx, linkedid) -> one logical call
    for c in legs:
        k = (c.pbx_id, c.linkedid)
        e = calls.get(k)
        if e is None:
            e = calls[k] = {"ts": c.ts, "direction": c.direction, "other": c.other, "answered": False, "talk": 0,
                            "ring": None, "exts": [], "users": set(), "pbx_id": c.pbx_id, "trunk": "", "did": "",
                            "src": c.src}
        if c.direction != "unknown" and e["direction"] == "unknown":
            e["direction"], e["other"] = c.direction, c.other
        if c.extension and c.extension not in e["exts"] and c.extension != c.queue \
                and c.extension not in e.get("queues", ()):
            e["exts"].append(c.extension)
        e["trunk"] = e["trunk"] or (c.trunk or "")
        e["did"] = e["did"] or (c.did or "")
        if c.user_id:
            e["users"].add(c.user_id)
        if c.queue and c.queue not in e.setdefault("queues", []):
            e["queues"].append(c.queue)
        if answered_leg(c):
            e["answered"] = True
            e["talk"] = max(e["talk"], c.billsec)
            ring = max(0, c.duration - c.billsec)
            e["ring"] = ring if e["ring"] is None else min(e["ring"], ring)
    cl = list(calls.values())
    stats = {d: {"count": 0, "answered": 0, "talk": 0} for d in ("in", "out", "internal")}
    hours = [[0] * 24 for _ in range(7)]
    by_hour = [0] * 24
    daily = defaultdict(lambda: {"in": 0, "out": 0, "internal": 0, "missed": 0})
    dest, callers = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0, 0])
    rings = []
    for e in cl:
        d = e["direction"]
        if d not in stats:
            continue
        s = stats[d]
        s["count"] += 1
        s["answered"] += e["answered"]
        s["talk"] += e["talk"]
        wd = (e["ts"].weekday() + 2) % 7
        if d != "internal":
            hours[wd][e["ts"].hour] += 1
            by_hour[e["ts"].hour] += 1
        day = daily[e["ts"].date()]
        day[d] += 1
        if d == "in" and not e["answered"]:
            day["missed"] += 1
        if d == "in" and e["answered"] and e["ring"] is not None:
            rings.append(e["ring"])
        if d == "out" and e["other"]:
            dest[digits(e["other"]) or e["other"]][0] += 1
            dest[digits(e["other"]) or e["other"]][1] += e["talk"]
        if d == "in" and e["other"]:
            c = callers[digits(e["other"]) or e["other"]]
            c[0] += 1
            c[1] += e["talk"]
            c[2] += not e["answered"]
    talk_total = sum(s["talk"] for s in stats.values())
    answered_total = sum(s["answered"] for s in stats.values())
    # missed inbound calls nobody called back (or that did not call again and get answered)
    later_out = defaultdict(list)
    for c in db.query(Call.ts, Call.other, Call.direction, Call.disposition, Call.billsec, Call.queue,
                      Call.extension).filter(Call.ts >= start, Call.direction.in_(("in", "out"))):
        if c.direction == "out" or answered_leg(c):
            later_out[digits(c.other)[-10:]].append(c.ts)
    missed = {}
    for e in cl:
        if e["direction"] != "in" or e["answered"] or not e["other"]:
            continue
        num = digits(e["other"])
        back = any(t > e["ts"] for t in later_out.get(num[-10:], ()))
        if back:
            continue
        m = missed.setdefault(num, {"number": e["other"], "count": 0, "first": e["ts"], "last": e["ts"], "exts": set()})
        m["count"] += 1
        m["last"] = max(m["last"], e["ts"])
        m["exts"].update(e["exts"])
    missed_list = sorted(missed.values(), key=lambda m: m["last"], reverse=True)
    for m in missed_list:
        m["exts"] = "، ".join(sorted(m["exts"]))
    return {
        "stats": stats, "calls": len(cl), "talk": talk_total,
        "avg_talk": int(talk_total / answered_total) if answered_total else 0,
        "avg_ring": int(sum(rings) / len(rings)) if rings else 0,
        "heat": hours, "heat_max": max(max(r) for r in hours) if cl else 0, "by_hour": by_hour,
        "daily": [dict(v, day=k) for k, v in sorted(daily.items())],
        "destinations": [{"number": k, "count": v[0], "talk": v[1], "category": category(k)}
                         for k, v in sorted(dest.items(), key=lambda x: (-x[1][0], -x[1][1]))[:top]],
        "categories": _cats(dest),
        "callers": [{"number": k, "count": v[0], "talk": v[1], "missed": v[2]}
                    for k, v in sorted(callers.items(), key=lambda x: (-x[1][0], -x[1][1]))[:top]],
        "people": people(db, legs, {k for k, e in calls.items() if e["answered"]}),
        "missed": missed_list[:100], "missed_count": len(missed_list),
        "unassigned": _unassigned(legs),
        "queues": queues(db, calls, legs),
        "long_calls": long_calls(cl),
        "frequent": frequent(cl),
        "trunks": trunks(cl),
        "ext_service": ext_service(legs),
    }


def ends(e):
    """(from, to) of a logical call: the outside number or our extension(s)."""
    exts = "، ".join(e["exts"]) or "-"
    if e["direction"] == "in":
        return e["other"] or "-", exts
    if e["direction"] == "out":
        return exts, e["other"] or "-"
    return (e["exts"][0] if e["exts"] else e["src"] or "-"), (e["other"] or "-")


def long_calls(cl, top=25):
    rows = sorted((e for e in cl if e["answered"] and e["direction"] in ("in", "out", "internal")),
                  key=lambda e: -e["talk"])[:top]
    return [dict(ts=e["ts"], direction=e["direction"], talk=e["talk"], trunk=e["trunk"], users=sorted(e["users"]),
                 frm=ends(e)[0], to=ends(e)[1], pbx_id=e["pbx_id"]) for e in rows]


def frequent(cl, top=25):
    """The same two parties again and again: (our extension, the other number / extension) with 2+ calls."""
    pairs = {}
    for e in cl:
        if e["direction"] not in ("in", "out", "internal") or not e["other"]:
            continue
        ours = e["exts"][0] if e["exts"] else (e["src"] if e["direction"] != "in" else "")
        if not ours:
            continue
        other = digits(e["other"]) or e["other"]
        a, b = (ours, other) if e["direction"] != "internal" else tuple(sorted((ours, other)))
        p = pairs.setdefault((e["direction"] if e["direction"] == "internal" else "x", a, b),
                             {"ext": a, "other": b, "internal": e["direction"] == "internal", "in": 0, "out": 0,
                              "count": 0, "answered": 0, "talk": 0, "users": set(), "last": e["ts"]})
        p["count"] += 1
        p["in" if e["direction"] == "in" else "out"] += 1
        p["answered"] += e["answered"]
        p["talk"] += e["talk"]
        p["users"].update(e["users"])
        p["last"] = max(p["last"], e["ts"])
    rows = sorted((p for p in pairs.values() if p["count"] >= 2), key=lambda p: (-p["count"], -p["talk"]))[:top]
    return [dict(p, users=sorted(p["users"])) for p in rows]


def trunks(cl):
    """Per trunk (SIP line): inbound and outbound calls, unanswered inbound, talk time, the DIDs dialled."""
    out = {}
    for e in cl:
        if e["direction"] not in ("in", "out"):
            continue
        t = out.setdefault(e["trunk"] or "نامشخص", {"trunk": e["trunk"] or "نامشخص", "in": 0, "in_answered": 0,
                                                     "out": 0, "out_answered": 0, "talk": 0, "dids": set()})
        t[e["direction"]] += 1
        t[e["direction"] + "_answered"] += e["answered"]
        t["talk"] += e["talk"]
        if e["direction"] == "in" and e["did"]:
            t["dids"].add(e["did"])
    return [dict(t, missed=t["in"] - t["in_answered"], dids="، ".join(sorted(t["dids"])[:8]))
            for t in sorted(out.values(), key=lambda t: -(t["in"] + t["out"]))]


def ext_service(legs):
    """Per extension that was rung: how often it rang, answered, did not answer, and how long it rang before
    answering, separately for calls from outside the organization (inbound) and from colleagues (internal)."""
    out = {}
    for c in legs:
        if c.direction == "in":
            ext, origin = c.extension, "out"
        elif c.direction == "internal":
            ext, origin = digits(c.other), "int"
        else:
            continue
        if not ext or len(ext) > 7 or (c.queue and ext == c.queue):
            continue
        r = out.setdefault((c.pbx_id, ext), {"ext": ext, "pbx_id": c.pbx_id,
                                             "out": {"rang": 0, "answered": 0, "rings": []},
                                             "int": {"rang": 0, "answered": 0, "rings": []}})
        x = r[origin]
        x["rang"] += 1
        if answered_leg(c):
            x["answered"] += 1
            x["rings"].append(max(0, c.duration - c.billsec))
    rows = []
    for r in out.values():
        row = {"ext": r["ext"], "pbx_id": r["pbx_id"]}
        for o in ("out", "int"):
            x = r[o]
            missed = x["rang"] - x["answered"]
            row[o] = {"rang": x["rang"], "answered": x["answered"], "missed": missed,
                      "missed_pct": round(100 * missed / x["rang"]) if x["rang"] else 0,
                      "avg_ring": round(sum(x["rings"]) / len(x["rings"])) if x["rings"] else 0,
                      "max_ring": max(x["rings"], default=0)}
        row["missed"] = row["out"]["missed"] + row["int"]["missed"]
        rows.append(row)
    rows.sort(key=lambda r: (-r["missed"], -max(r["out"]["avg_ring"], r["int"]["avg_ring"])))
    return rows


def ext_owners(db):
    """Extension -> the name of whoever holds it today."""
    today = now().date()
    users = {u.id: (u.full_name or u.username) for u in db.query(User.id, User.full_name, User.username)}
    out = {}
    for a in db.query(ExtensionAssignment):
        if (not a.start or a.start <= today) and (not a.end or a.end >= today) and a.user_id in users:
            out[a.extension] = users[a.user_id]
    return out


def sl_seconds(db):
    try:
        return max(1, int(get_setting(db, "pbx_sl_seconds", "20") or 20))
    except ValueError:
        return 20


def queues(db, calls, legs):
    """Per queue: offered, answered by an agent, abandoned, wait times and the service level (answered within N s)."""
    by_call = defaultdict(list)
    for c in legs:
        by_call[(c.pbx_id, c.linkedid)].append(c)
    sl = sl_seconds(db)
    out = {}
    for k, e in calls.items():
        if not e.get("queues"):
            continue
        parts = by_call[k]
        start = min(c.ts for c in parts)
        answers = [c.ts + timedelta(seconds=max(0, c.duration - c.billsec)) for c in parts if answered_leg(c)]
        q = out.setdefault((e["pbx_id"], e["queues"][0]), {"queue": e["queues"][0], "pbx_id": e["pbx_id"], "offered": 0,
                                                           "answered": 0, "abandoned": 0, "waits": [], "lost_waits": [],
                                                           "in_sl": 0, "talk": 0})
        q["offered"] += 1
        if answers:
            wait = max(0, int((min(answers) - start).total_seconds()))
            q["answered"] += 1
            q["waits"].append(wait)
            q["in_sl"] += wait <= sl
            q["talk"] += e["talk"]
        else:
            q["abandoned"] += 1
            q["lost_waits"].append(max((c.duration for c in parts if c.queue), default=0))
    rows = []
    for q in out.values():
        w, lw = q.pop("waits"), q.pop("lost_waits")
        rows.append(dict(q, avg_wait=int(sum(w) / len(w)) if w else 0, max_wait=max(w, default=0),
                         avg_abandon=int(sum(lw) / len(lw)) if lw else 0,
                         sl_pct=round(100 * q["in_sl"] / q["offered"], 1) if q["offered"] else 0,
                         answered_pct=round(100 * q["answered"] / q["offered"], 1) if q["offered"] else 0))
    return sorted(rows, key=lambda r: -r["offered"])


# ------------------------------------------------------------------ alert: many unanswered inbound calls
def missed_alert(db):
    """At most once an hour: alert when the unanswered inbound calls of the last hour reach pbx_missed_alert."""
    from . import alerts
    try:
        limit = int(get_setting(db, "pbx_missed_alert", "0") or 0)
    except ValueError:
        limit = 0
    if limit <= 0:
        return None
    t = now()
    last = get_setting(db, "pbx_missed_alert_at")
    if last and last > (t - timedelta(hours=1)).isoformat(timespec="seconds"):
        return None
    rep = build(db, t - timedelta(hours=1), t + timedelta(minutes=1))
    s = rep["stats"]["in"]
    lost = s["count"] - s["answered"]
    if lost < limit:
        return None
    set_setting(db, "pbx_missed_alert_at", t.isoformat(timespec="seconds"))
    body = f"{lost} تماس ورودی از {s['count']} تماس در یک ساعت گذشته پاسخ داده نشد"
    if rep["queues"]:
        body += " · " + "، ".join(f"صف {q['queue']}: {q['abandoned']} رهاشده" for q in rep["queues"] if q["abandoned"])
    return alerts.add(db, "calls", "تماس‌های ورودی بی‌پاسخ زیاد", body, "warn", "/calls?preset=today")


# ------------------------------------------------------------------ extensions suggested by Active Directory (ipPhone)
def ad_suggestions(db):
    """Users whose AD ipPhone is an extension that nobody holds today."""
    today = now().date()
    held = {a.extension for a in db.query(ExtensionAssignment)
            if (not a.start or a.start <= today) and (not a.end or a.end >= today)}
    ranges = [parse_ranges(s.ext_ranges) for s in db.query(PbxServer)]
    out = []
    for u in db.query(User).filter(User.ip_phone != "", User.ip_phone.isnot(None)).order_by(User.username):
        ext = digits(u.ip_phone)
        if not ext or ext in held or len(ext) > 7:
            continue
        if ranges and not any(in_ranges(ext, r) for r in ranges):
            continue
        out.append({"user_id": u.id, "username": u.username, "full_name": u.full_name, "extension": ext})
    return out


def _cats(dest):
    out = defaultdict(lambda: [0, 0])
    for k, (n, talk) in dest.items():
        c = out[category(k)]
        c[0] += n
        c[1] += talk
    return [{"name": k, "count": v[0], "talk": v[1]} for k, v in sorted(out.items(), key=lambda x: -x[1][0])]


def people(db, legs, answered_calls=None):
    """Per person: inbound calls that rang them / they answered / nobody answered, outbound, talk time."""
    answered_calls = answered_calls or set()
    rows = {}
    for c in legs:
        if not c.user_id or c.direction not in ("in", "out", "internal"):
            continue
        r = rows.setdefault(c.user_id, {"user_id": c.user_id, "in": 0, "in_answered": 0, "out": 0, "out_answered": 0,
                                        "internal": 0, "talk": 0, "missed": 0, "exts": set(), "calls": set()})
        key = (c.pbx_id, c.linkedid, c.direction)
        r["exts"].add(c.extension)
        ans = answered_leg(c)
        if key not in r["calls"]:
            r["calls"].add(key)
            r[c.direction] += 1
            if c.direction == "in" and (c.pbx_id, c.linkedid) not in answered_calls:
                r["missed"] += 1
        if ans and (key, "a") not in r["calls"]:
            r["calls"].add((key, "a"))
            if c.direction in ("in", "out"):
                r[c.direction + "_answered"] += 1
            r["talk"] += c.billsec
    users = {u.id: u for u in db.query(User).filter(User.id.in_(list(rows) or [-1]))}
    offices = {o.id: o.name for o in db.query(Office)}
    depts = {d.id: d.name for d in db.query(Department)}
    grps = {g.id: g.name for g in db.query(Group)}
    out = []
    for uid, r in rows.items():
        u = users.get(uid)
        answered = r["in_answered"] + r["out_answered"]
        out.append(dict(r, exts="، ".join(sorted(r["exts"])), calls=None,
                        username=u.username if u else "?", full_name=u.full_name if u else "",
                        office=offices.get(u.office_id, "") if u else "", department=depts.get(u.department_id, "") if u else "",
                        group=grps.get(u.group_id, "") if u else "",
                        office_id=u.office_id if u else None, department_id=u.department_id if u else None,
                        total=r["in"] + r["out"],
                        avg_talk=int(r["talk"] / answered) if answered else 0))
    out.sort(key=lambda r: (-r["total"], -r["talk"]))
    return out


def by_unit(people_rows, key):
    out = {}
    for r in people_rows:
        name = r[key] or "نامشخص"
        e = out.setdefault(name, {"name": name, "in": 0, "in_answered": 0, "out": 0, "out_answered": 0,
                                  "internal": 0, "missed": 0, "talk": 0, "people": 0})
        for k in ("in", "in_answered", "out", "out_answered", "internal", "missed", "talk"):
            e[k] += r[k]
        e["people"] += 1
    return sorted(out.values(), key=lambda e: -(e["in"] + e["out"]))


def _unassigned(legs):
    out = defaultdict(lambda: {"count": 0, "last": None, "pbx_id": None})
    for c in legs:
        if c.extension and not c.user_id:
            e = out[(c.pbx_id, c.extension)]
            e["count"] += 1
            e["pbx_id"] = c.pbx_id
            e["last"] = c.ts if e["last"] is None else max(e["last"], c.ts)
    return [dict(v, extension=k[1]) for k, v in sorted(out.items(), key=lambda x: -x[1]["count"])]


def recent(db, start, end, ids=None, pbx_id=None, limit=200):
    return _query(db, start, end, ids, pbx_id).order_by(Call.ts.desc()).limit(limit).all()


def assignments_of(db, user_id):
    return db.query(ExtensionAssignment).filter(ExtensionAssignment.user_id == user_id) \
        .order_by(ExtensionAssignment.end.is_(None).desc(), ExtensionAssignment.start.desc()).all()


def current_extensions(db, user_ids):
    today = now().date()
    out = defaultdict(list)
    for a in db.query(ExtensionAssignment).filter(ExtensionAssignment.user_id.in_(list(user_ids) or [-1])):
        if (not a.start or a.start <= today) and (not a.end or a.end >= today):
            out[a.user_id].append(a.extension)
    return out



def free_extensions(db):
    """Extensions seen on the PBX servers that nobody holds today and that no user has as AD ipPhone:
    [(extension, number of calls)], in numeric order."""
    from sqlalchemy import func
    today = now().date()
    held = {a.extension for a in db.query(ExtensionAssignment)
            if (not a.start or a.start <= today) and (not a.end or a.end >= today)}
    held |= {digits(u.ip_phone) for u in db.query(User).filter(User.ip_phone != "", User.ip_phone.isnot(None),
                                                                    User.enabled.is_(True))}
    ranges = [r for r in (parse_ranges(s.ext_ranges) for s in db.query(PbxServer)) if r]
    out = {}
    for ext, n in db.query(Call.extension, func.count(Call.id)).filter(Call.extension != "").group_by(Call.extension):
        e = digits(ext)
        if not e or e != str(ext) or len(e) > 7 or e in held:
            continue
        if ranges and not any(in_ranges(e, r) for r in ranges):
            continue
        out[e] = out.get(e, 0) + n
    return sorted(out.items(), key=lambda x: (len(x[0]), x[0]))
