"""پنل وب مدیریت (FastAPI)."""
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from . import (alerts, ami, auth, classifier, config, devices, grants, hotspot, ifstats, jalali, logons, monitor, nightlist, pbx,
               jobs, ldap_ad, mgmt, netscope, policy, reports, routeros, scope, security, tour, xlsx)
from .db import (LDAP_KEYS, AcctSession, Alert, AuditLog, AuthLog, Call, Lock, NetEvent, TempGrant, DeployLog, Department, Device, DeviceHistory,
                 ExtensionAssignment, Group, NightList, PbxServer,
                 HotspotPackage, Nas, Office, PanelUser, SessionLocal, SpeedSample, TrafficCategory, TrafficDomain, User,
                 decrypt, encrypt, get_setting, init_db, now, request_scope, set_setting)
from .version import VERSION

log = logging.getLogger("web")


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(title="MikroTik Accounting", docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(config.BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(config.BASE_DIR, "templates"))

FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
FA_TO_EN = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024


def fmt_rate(bps):
    bps = float(bps or 0)
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000 or unit == "Gbps":
            return f"{bps:.0f} {unit}" if unit == "bps" else f"{bps:.1f} {unit}"
        bps /= 1000


def fmt_duration(sec):
    sec = int(sec or 0)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    return (f"{d} روز " if d else "") + f"{h:02d}:{m:02d}"


templates.env.filters.update({
    "bytes": fmt_bytes, "rate": fmt_rate, "duration": fmt_duration,
    "mmss": lambda sec: f"{int(sec or 0) // 60}:{int(sec or 0) % 60:02d}",
    "jdate": lambda d: jalali.to_jalali_str(d), "jdt": lambda d: jalali.to_jalali_str(d, True),
    "devtype": lambda t: devices.TYPE_FA.get(t or "", t), "fa": lambda s: str(s).translate(FA_DIGITS),
})
templates.env.globals.update({"CATEGORIES": classifier.CATEGORIES, "ROLES": auth.ROLES, "VERSION": VERSION,
                              "DEVICE_TYPES": devices.TYPES})


# ------------------------------------------------------------------ helpers / auth
PUBLIC = ("/login", "/static", "/ua", "/healthz", "/my", "/logon", "/hs/")


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    token = request_scope.set(object())          # every request gets its own DB session, closed at the end
    try:
        return await _auth(request, call_next)
    finally:
        SessionLocal.remove()
        request_scope.reset(token)


async def _auth(request, call_next):
    path = request.url.path
    if path.startswith(PUBLIC):
        return await call_next(request)
    db = SessionLocal()
    me = db.get(PanelUser, request.session.get("uid") or 0)
    if me is None or not me.enabled or request.session.get("pw") != me.password_hash[-12:]:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)
    perms = auth.user_permissions(me)
    request.state.me, request.state.perms = me, perms
    db.commit()             # give the connection back to the pool before the route (maybe in a worker thread) runs
    if me.must_change_password and path not in ("/account", "/logout"):
        return RedirectResponse("/account", status_code=303)
    needed = auth.required_permission(request.method, path)
    if needed is None or not auth.allowed(perms, needed):
        if path == "/" and request.method == "GET":
            return RedirectResponse(auth.landing(perms), status_code=303)
        return templates.TemplateResponse(request, "denied.html", {"me": me, "perms": perms, "flash": None},
                                          status_code=403)
    return await call_next(request)


# added after auth_mw so it wraps it (outermost middleware runs first)
app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY, max_age=12 * 3600)


def render(request, name, **ctx):
    ctx.setdefault("flash", request.session.pop("flash", None))
    me = getattr(request.state, "me", None)
    ctx.setdefault("me", me)
    ctx.setdefault("perms", getattr(request.state, "perms", set()))
    if me is not None and scope.is_scoped(me) and "scope_label" not in ctx:
        ctx["scope_label"] = scope.scope_label(SessionLocal(), me)
    if me is not None and "alerts_view" in ctx["perms"] and "alert_count" not in ctx:
        ctx["alert_count"] = alerts.unread(SessionLocal())
    if me is not None and "tour" not in ctx:
        ctx["tour"] = tour.panel_steps(me, ctx["perms"], ctx.get("scope_label", ""))
        ctx["tour_auto"] = (me.tour_seen or "") != tour.VERSION and not me.must_change_password
    return templates.TemplateResponse(request, name, ctx)


def _org_lists(db, me):
    return {"offices": scope.visible_offices(db, me), "departments": scope.visible_departments(db, me)}


def flash(request, msg, kind="ok"):
    request.session["flash"] = {"msg": msg, "kind": kind}


def redirect(url):
    return RedirectResponse(url, status_code=303)


def log_action(request, action, detail=""):
    me = getattr(request.state, "me", None)
    db = SessionLocal()
    auth.audit(db, me.username if me else "-", action, detail, request.client.host if request.client else "")


def _int(v, default=None):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _bool(form, key):
    return form.get(key) in ("1", "on", "true", "yes")


def _date(text):
    """Jalali / Gregorian date from a form or query string; None when empty or invalid."""
    try:
        return jalali.parse_date(text) if text else None
    except (ValueError, TypeError):
        return None


def _local(url, default="/"):
    """Only redirect to a path of this panel (a form's 'back' field could point anywhere)."""
    url = str(url or "")
    return url if url.startswith("/") and not url.startswith("//") and "\\" not in url else default


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": VERSION}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    db = SessionLocal()
    try:
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        ip = request.client.host if request.client else ""
        if username and auth.find_panel_user(db, username) is None and \
                db.query(User.id).filter(func.lower(User.username) == auth.ad_name(username).lower()).first():
            # one login page for everyone: an internet user (no panel access) lands on their own usage page
            err = _my_signin(request, db, auth.ad_name(username), password, ip)
            if err:
                flash(request, err, "err")
                return redirect("/login")
            return redirect("/my")
        u, err = auth.check_login(db, username, password)
        if u is None:
            auth.audit(db, username, "ورود ناموفق به پنل", err, ip)
            flash(request, err, "err")
            return redirect("/login")
        request.session.clear()
        request.session["uid"], request.session["pw"] = u.id, u.password_hash[-12:]
        linked = db.get(User, u.user_id) if u.user_id else None
        if linked is not None:      # the same person's internet usage page opens without a second login
            request.session["my_uid"], request.session["my_fp"] = linked.id, _my_fp(linked)
        auth.audit(db, u.username, "ورود به پنل", "حساب AD" if not auth.is_local(u) else "", ip)
        return redirect("/account" if u.must_change_password else auth.landing(auth.user_permissions(u)))
    finally:
        db.close()
        SessionLocal.remove()


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    me = request.state.me
    linked = SessionLocal().get(User, me.user_id) if me.user_id else None
    return render(request, "account.html", roles=auth.ROLES, permissions=auth.PERMISSIONS, linked=linked,
                  is_local=auth.is_local(me))


@app.post("/account")
async def account_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    me = db.get(PanelUser, request.state.me.id)
    if not auth.is_local(me):
        flash(request, "رمز شما همان رمز Active Directory است؛ آن را در ویندوز یا صفحه «مصرف اینترنت من» عوض کنید.",
              "err")
        return redirect("/account")
    if not auth.verify_password(str(form.get("current", "")), me.password_hash):
        flash(request, "رمز فعلی اشتباه است", "err")
        return redirect("/account")
    new, again = str(form.get("new", "")), str(form.get("again", ""))
    problem = auth.password_problem(new) or ("تکرار رمز یکسان نیست" if new != again else "")
    if not problem and auth.verify_password(new, me.password_hash):
        problem = "رمز جدید باید با رمز فعلی فرق داشته باشد"
    if problem:
        flash(request, problem, "err")
        return redirect("/account")
    me.password_hash, me.must_change_password = auth.hash_password(new), False
    db.commit()
    request.session["pw"] = me.password_hash[-12:]
    log_action(request, "تغییر رمز خود")
    flash(request, "رمز عبور تغییر کرد")
    return redirect(auth.landing(auth.user_permissions(me)))


@app.post("/tour/done")
def tour_done(request: Request):
    """The first-login tour was finished or skipped: do not start it automatically again."""
    db = SessionLocal()
    me = db.get(PanelUser, request.state.me.id)
    me.tour_seen = tour.VERSION
    db.commit()
    return Response(status_code=204)


@app.post("/admins/reset-tour")
def admins_reset_tour(request: Request):
    db = SessionLocal()
    db.query(PanelUser).update({PanelUser.tour_seen: ""})
    db.query(User).update({User.tour_seen: ""})
    db.commit()
    log_action(request, "نمایش دوباره آموزش برای همه کاربران")
    flash(request, "آموزش ورود اول در ورود بعدی دوباره برای همه کاربران پنل و صفحه «مصرف من» نشان داده می‌شود")
    return redirect("/admins")


# ------------------------------------------------------------------ panel users (admins)
@app.get("/admins", response_class=HTMLResponse)
def admins_list(request: Request):
    db = SessionLocal()
    items = db.query(PanelUser).order_by(PanelUser.username).all()
    ids = [a.user_id for a in items if a.user_id]
    linked = {u.id: u for u in db.query(User).filter(User.id.in_(ids))} if ids else {}
    return render(request, "admins.html", items=items, now=now(), roles=auth.ROLES, permissions=auth.PERMISSIONS,
                  user_permissions=auth.user_permissions, scope_labels={a.id: scope.scope_label(db, a) for a in items},
                  linked=linked, is_local=auth.is_local)


def _admin_form(request, a):
    db = SessionLocal()
    ad = ldap_ad.enabled(db)
    ad_users = db.query(User.username, User.full_name).filter(User.source == "ldap", User.enabled.is_(True)) \
        .order_by(User.username).limit(5000).all() if ad else []
    linked = db.get(User, a.user_id) if a and a.user_id else None
    return render(request, "admin_form.html", a=a, roles=auth.ROLES, permissions=auth.PERMISSIONS,
                  current=auth.user_permissions(a) if a else set(), forbidden=sorted(auth.SCOPED_FORBIDDEN),
                  all_offices=db.query(Office).order_by(Office.name).all(),
                  all_departments=db.query(Department).order_by(Department.name).all(),
                  sel_offices=scope._ids(a.scope_offices) if a else set(),
                  sel_departments=scope._ids(a.scope_departments) if a else set(),
                  ad_enabled=ad, ad_users=ad_users, linked=linked, is_ad=bool(a) and not auth.is_local(a))


@app.get("/admins/new", response_class=HTMLResponse)
def admin_new(request: Request, user: int = 0):
    u = SessionLocal().get(User, user) if user else None
    if u is not None and u.source == "ldap":
        # "panel access" from an AD user's page: an office manager by default, scoped to their own office
        a = PanelUser(username=u.username, full_name=u.full_name or "", role="unit_manager", source="ldap",
                      enabled=True, scope_own_office=bool(u.office_id), scope_own_department=False,
                      scope_offices=str(u.office_id or ""), scope_departments="", user_id=u.id, permissions="")
        return _admin_form(request, a)
    return _admin_form(request, None)


@app.get("/admins/{aid}/edit", response_class=HTMLResponse)
def admin_edit(request: Request, aid: int):
    return _admin_form(request, SessionLocal().get(PanelUser, aid))


@app.post("/admins/save")
async def admin_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    aid = _int(form.get("id"))
    a = db.get(PanelUser, aid) if aid else PanelUser()
    back = f"/admins/{aid}/edit" if aid else "/admins/new"
    source = "ldap" if form.get("source") == "ldap" else "local"
    username = str(form.get("username", "")).strip()
    if source == "ldap":
        username = auth.ad_name(username)
    role = form.get("role", "it")
    if not username or role not in auth.ROLES:
        flash(request, "نام کاربری و نقش الزامی است", "err")
        return redirect(back)
    if source == "ldap" and not ldap_ad.enabled(db):
        flash(request, "برای کاربر پنل از AD ابتدا Active Directory را در صفحه «Active Directory» تنظیم کنید", "err")
        return redirect(back)
    clash = db.query(PanelUser).filter(PanelUser.id != (aid or 0))
    clash = clash.filter(func.lower(PanelUser.username) == username.lower()) if source == "ldap" else \
        clash.filter(PanelUser.username == username)
    if clash.first():
        flash(request, "این نام کاربری وجود دارد", "err")
        return redirect(back)
    was_local = not aid or auth.is_local(a)
    password = str(form.get("password", "")) if source == "local" else ""
    if source == "local" and not password and (not aid or not was_local):
        flash(request, "برای کاربر پنل محلی رمز لازم است", "err")
        return redirect(back)
    if password and auth.password_problem(password):
        flash(request, auth.password_problem(password), "err")
        return redirect(back)
    me = request.state.me
    enabled = _bool(form, "enabled")
    if aid == me.id and (role != "admin" or not enabled):
        flash(request, "نمی‌توانید نقش مدیر یا فعال بودن حساب خودتان را بردارید", "err")
        return redirect(back)
    if aid and a.role == "admin" and a.enabled and auth.is_local(a) and \
            (role != "admin" or not enabled or source == "ldap") and not auth.local_admins_left(db, a.id):
        flash(request, "حداقل یک مدیر سیستم با حساب محلی (غیر AD) باید فعال بماند تا اگر AD در دسترس نبود هم "
                       "بتوان وارد پنل شد", "err")
        return redirect(back)
    own_office = source == "ldap" and role != "admin" and _bool(form, "scope_own_office")
    own_dept = source == "ldap" and role != "admin" and _bool(form, "scope_own_department")
    linked = auth.ad_internet_user(db, username, refresh=True) if source == "ldap" else None
    if (own_office or own_dept) and linked is None:
        flash(request, f"«{username}» در کاربران اینترنت AD (Base DN / فیلتر) پیدا نشد؛ دفتر یا واحد را دستی "
                       "انتخاب کنید", "err")
        return redirect(back)
    a.username, a.full_name, a.role, a.enabled = username, form.get("full_name", ""), role, enabled
    custom = _bool(form, "custom_perms") and role != "admin"
    a.permissions = ",".join(p for p in auth.PERMISSIONS if form.get(f"perm_{p}")) if custom else ""
    if role == "admin":
        a.scope_offices = a.scope_departments = ""
    else:
        a.scope_offices = ",".join(str(int(x)) for x in form.getlist("scope_offices") if str(x).isdigit())
        a.scope_departments = ",".join(str(int(x)) for x in form.getlist("scope_departments") if str(x).isdigit())
    a.source, a.scope_own_office, a.scope_own_department = source, own_office, own_dept
    auth.link_ad_user(db, a, linked)
    if role == "unit_manager" and not a.scope_offices and not a.scope_departments:
        db.rollback()
        flash(request, "برای مدیر دفتر / واحد حداقل یک دفتر یا واحد انتخاب کنید", "err")
        return redirect(back)
    if password:
        a.password_hash = auth.hash_password(password)
        a.must_change_password = _bool(form, "must_change")
        a.locked_until, a.failed_count = None, 0
    elif source == "ldap" and (not aid or was_local):
        # the domain password is checked against AD; the stored hash only ends older sessions of this account
        a.password_hash = auth.hash_password(os.urandom(24).hex())
        a.must_change_password, a.locked_until, a.failed_count = False, None, 0
    if not aid:
        db.add(a)
    db.commit()
    log_action(request, "ذخیره کاربر پنل", f"{a.username} ({auth.ROLES[a.role][0]})" +
               (" · حساب AD" if source == "ldap" else "") + (" + رمز جدید" if password else ""))
    flash(request, "کاربر پنل ذخیره شد" + ("" if source == "local" or linked else
                                          " (این حساب AD در کاربران اینترنت نیست؛ ورود به پنل با رمز AD کار می‌کند)"))
    return redirect("/admins")


@app.post("/admins/{aid}/delete")
def admin_delete(request: Request, aid: int):
    db = SessionLocal()
    a = db.get(PanelUser, aid)
    if a and a.id != request.state.me.id:
        if a.role == "admin" and a.enabled and auth.is_local(a) and not auth.local_admins_left(db, a.id):
            flash(request, "آخرین مدیر سیستم با حساب محلی را نمی‌توان حذف کرد", "err")
            return redirect("/admins")
        db.delete(a)
        db.commit()
        log_action(request, "حذف کاربر پنل", a.username)
        flash(request, "کاربر پنل حذف شد")
    return redirect("/admins")


@app.post("/admins/{aid}/unlock")
def admin_unlock(request: Request, aid: int):
    db = SessionLocal()
    a = db.get(PanelUser, aid)
    if a:
        a.locked_until, a.failed_count = None, 0
        db.commit()
        log_action(request, "باز کردن قفل کاربر پنل", a.username)
    return redirect("/admins")


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, q: str = ""):
    db = SessionLocal()
    qry = db.query(AuditLog)
    if q:
        qry = qry.filter(AuditLog.username.ilike(f"%{q}%") | AuditLog.action.ilike(f"%{q}%") |
                         AuditLog.detail.ilike(f"%{q}%"))
    return render(request, "audit.html", items=qry.order_by(AuditLog.ts.desc()).limit(1000).all(), q=q)


# ------------------------------------------------------------------ dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    db = SessionLocal()
    me = request.state.me
    ids = scope.resolve_ids(db, me)
    today = datetime.combine(now().date(), datetime.min.time())
    rep = reports.build(db, reports.Filter(today, today + timedelta(days=1), ids=ids), session_limit=0)
    stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    aq = db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.last_update >= stale)
    if ids is not None:
        aq = aq.filter(AcctSession.user_id.in_(ids))
    active = aq.all()
    by_dev = {}
    for s in active:
        k = devices.TYPE_FA.get(s.device_type or "", s.device_type)
        by_dev[k] = by_dev.get(k, 0) + 1
    uq = scope.scope_query(db.query(User), me)
    stats = {
        "users": uq.count(), "enabled": uq.filter(User.enabled.is_(True)).count(),
        "active": len(active), "hotspot": sum(1 for s in active if s.service == "hotspot"),
        "vpn": sum(1 for s in active if s.service == "vpn"),
        "rejects": _auth_q(db, ids).filter(AuthLog.ts >= today, AuthLog.result == "reject").count(),
    }
    return render(request, "dashboard.html", rep=rep, stats=stats, by_dev=by_dev, routers=jobs.live["routers"],
                  nas=db.query(Nas).all())


# ------------------------------------------------------------------ router traffic graphs
def _traffic_routers(db, me):
    q = db.query(Nas).order_by(Nas.name)
    if scope.is_scoped(me):
        q = q.filter(Nas.office_id.in_([o.id for o in scope.visible_offices(db, me)] or [-1]))
    return q.all()


def _traffic_day(request):
    d = _date(request.query_params.get("day", ""))
    today = now().date()
    return d if d and d <= today else today


@app.get("/traffic", response_class=HTMLResponse)
def traffic_page(request: Request):
    db = SessionLocal()
    routers = _traffic_routers(db, request.state.me)
    day = _traffic_day(request)
    today = now().date()
    overview = []
    for n in routers:
        wan, lan = ifstats.roles(n)
        w = ifstats.day_totals(db, n.id, wan, today)
        wy = ifstats.day_totals(db, n.id, wan, today - timedelta(days=1))
        lt = ifstats.day_totals(db, n.id, lan, today)
        overview.append({"nas": n, "wan": wan, "lan": lan, "down": w[0], "up": w[1], "y_total": sum(wy),
                         "lan_total": sum(lt)})
    nid = _int(request.query_params.get("nas"))
    nas = next((n for n in routers if n.id == nid), None) or \
        next((n for n in routers if n.wan_interfaces or n.lan_interfaces), routers[0] if routers else None)
    ctx = {"routers": routers, "overview": overview, "nas": nas, "day": day, "today": today,
           "day_j": jalali.to_jalali_str(day), "status": jobs.live["routers"], "config_days": config.IFACE_SAMPLE_DAYS}
    if nas is not None:
        wan, lan = ifstats.roles(nas)
        ctx.update(ifaces=sorted(set(ifstats.interfaces_of(db, nas.id)) | set(wan) | set(lan)), wan=wan, lan=lan)
    return render(request, "traffic.html", **ctx)


@app.get("/api/traffic")
def traffic_api(request: Request):
    """Speed (bit/s) and volume per minute of a day and of the day before, for one router and a set of interfaces.
    role=wan|lan: download is rx on internet interfaces and tx on internal ones (towards the users)."""
    db = SessionLocal()
    p = request.query_params
    nas = next((n for n in _traffic_routers(db, request.state.me) if n.id == _int(p.get("nas"))), None)
    if nas is None:
        return Response('{"error": "router"}', media_type="application/json", status_code=404)
    role = "lan" if p.get("role") == "lan" else "wan"
    wan, lan = ifstats.roles(nas)
    ifaces = [p["iface"]] if p.get("iface") else (lan if role == "lan" else wan)
    day = _traffic_day(request)
    out = {"ifaces": ifaces, "role": role, "day": jalali.to_jalali_str(day),
           "prev_day": jalali.to_jalali_str(day - timedelta(days=1)), "is_today": day == now().date()}
    for key, d in (("cur", day), ("prev", day - timedelta(days=1))):
        sr = ifstats.day_series(db, nas.id, ifaces, d)
        dn, up = ("tx", "rx") if role == "lan" else ("rx", "tx")
        out[key] = {"down": sr[dn + "_bps"], "up": sr[up + "_bps"], "down_b": sr[dn + "_bytes"],
                    "up_b": sr[up + "_bytes"]}
        rx, tx = ifstats.day_totals(db, nas.id, ifaces, d)
        out[key]["total_down"], out[key]["total_up"] = (tx, rx) if role == "lan" else (rx, tx)
    if out["is_today"]:
        t = now()
        out["minute"] = t.hour * 60 + t.minute
    import json
    return Response(json.dumps(out), media_type="application/json")


def _auth_q(db, ids):
    q = db.query(AuthLog)
    if ids is not None:
        q = q.filter(AuthLog.username.in_([u for (u,) in db.query(User.username).filter(User.id.in_(ids))] or ["-"]))
    return q


# ------------------------------------------------------------------ users
@app.get("/users", response_class=HTMLResponse)
def users_list(request: Request, q: str = "", group: str = "", source: str = "", status: str = "",
               office: str = "", department: str = ""):
    db = SessionLocal()
    qry = scope.scope_query(db.query(User), request.state.me)
    if _int(office):
        qry = qry.filter(User.office_id == _int(office))
    if _int(department):
        qry = qry.filter(User.department_id == _int(department))
    if q:
        like = f"%{q}%"
        qry = qry.filter(User.username.ilike(like) | User.full_name.ilike(like) | User.email.ilike(like)
                         | User.mobile.ilike(like) | User.phone.ilike(like) | User.personnel_code.ilike(like))
    if _int(group):
        qry = qry.filter(User.group_id == _int(group))
    if source:
        qry = qry.filter(User.source == source)
    if status == "on":
        qry = qry.filter(User.enabled.is_(True))
    elif status == "off":
        qry = qry.filter(User.enabled.is_(False))
    users = qry.order_by(User.username).limit(2000).all()
    stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    online = {uid for (uid,) in db.query(AcctSession.user_id).filter(AcctSession.active.is_(True),
                                                                     AcctSession.last_update >= stale)}
    rows = []
    for u in users:
        eff = policy.Effective(u)
        quota, used, remaining = policy.quota_state(db, u, eff)
        rows.append({"u": u, "eff": eff, "quota": quota, "used": used, "online": u.id in online,
                     "pct": min(100, int(100 * used / quota)) if quota else 0})
    return render(request, "users.html", rows=rows, groups=db.query(Group).order_by(Group.name).all(),
                  q=q, group=group, source=source, status=status, office=office, department=department,
                  qs=str(request.query_params), ad_enabled=ldap_ad.enabled(db), bulk_text=BULK_TEXT,
                  **_org_lists(db, request.state.me))


def _user_form_ctx(db, user):
    devs = db.query(DeviceHistory).filter(
        DeviceHistory.kind == "user", func.lower(DeviceHistory.value) == user.username.lower()
    ).order_by(DeviceHistory.last_seen.desc()).limit(200).all() if user else []
    return {"user": user, "groups": db.query(Group).order_by(Group.name).all(),
            "offices": db.query(Office).order_by(Office.name).all(),
            "departments": db.query(Department).order_by(Department.name).all(),
            "password": decrypt(user.password_enc) if user and user.password_enc else "",
            "devs": devs, "nas_names": _nas_names(db) if devs else {},
            "dev_types": {d.mac: d.device_type for d in db.query(Device).filter(
                Device.mac.in_({h.mac for h in devs}))} if devs else {},
            "exts": pbx.assignments_of(db, user.id) if user else [],
            "pbx_names": _pbx_names(db),
            "panel": db.query(PanelUser).filter(PanelUser.source == "ldap", func.lower(PanelUser.username) ==
                                                user.username.lower()).first() if user and user.source == "ldap"
            else None}


@app.get("/users/new", response_class=HTMLResponse)
def user_new(request: Request):
    db = SessionLocal()
    return render(request, "user_form.html", **_user_form_ctx(db, None))


@app.get("/users/{uid}/edit", response_class=HTMLResponse)
def user_edit(request: Request, uid: int):
    db = SessionLocal()
    return render(request, "user_form.html", **_user_form_ctx(db, db.get(User, uid)))


def _org_maps(db):
    return ({o.id: o for o in db.query(Office).all()}, {d.id: d for d in db.query(Department).all()},
            {g.id: g for g in db.query(Group).all()})


def _write_ad(writer, user, before, before_group, maps, exclusive=True):
    """Push the changed AD-backed fields (and group membership) of an AD user. Returns a short description."""
    offices, depts, groups = maps
    after = ldap_ad.ad_values(user, offices, depts)
    attrs = {k: v for k, v in after.items() if v != before.get(k)}
    add_dn, remove = "", []
    if user.group_id != before_group:
        g = groups.get(user.group_id)
        add_dn = g.ldap_group_dn if g and g.ldap_group_dn else ""
        if exclusive:
            remove = [x.ldap_group_dn for x in groups.values() if x.ldap_group_dn]
    if not attrs and not add_dn and not remove:
        return ""
    writer.update(user, attrs, add_dn, remove)
    return "، ".join(list(attrs) + ([f"گروه {ldap_ad._cn(add_dn)}"] if add_dn else []))


@app.post("/users/save")
async def user_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    uid = _int(form.get("id"))
    user = db.get(User, uid) if uid else User(source="local")
    username = str(form.get("username", "")).strip()
    if not username:
        flash(request, "نام کاربری الزامی است", "err")
        return redirect(f"/users/{uid}/edit" if uid else "/users/new")
    dup = db.query(User).filter(func.lower(User.username) == username.lower(), User.id != (uid or 0)).first()
    if dup:
        flash(request, "این نام کاربری قبلاً ثبت شده", "err")
        return redirect(f"/users/{uid}/edit" if uid else "/users/new")
    hours = str(form.get("allowed_hours", "")).strip()
    try:
        policy.parse_hours(hours)
    except (ValueError, KeyError) as e:
        flash(request, f"فرمت ساعات مجاز نادرست است: {e}", "err")
        return redirect(f"/users/{uid}/edit" if uid else "/users/new")
    try:
        expire = jalali.parse_date(form.get("expire_at", ""))
        quota = _quota_mb(form)
    except (ValueError, TypeError):
        flash(request, "تاریخ انقضا (مثل 1405/12/29) یا عدد سهمیه نادرست است", "err")
        return redirect(f"/users/{uid}/edit" if uid else "/users/new")
    maps = _org_maps(db)
    is_ad = bool(uid) and user.source == "ldap"
    before, before_group = (ldap_ad.ad_values(user, maps[0], maps[1]), user.group_id) if is_ad else ({}, None)
    if user.source != "ldap":
        user.username = username
    user.full_name = str(form.get("full_name", "")).strip()
    user.email = str(form.get("email", "")).strip()
    user.phone = str(form.get("phone", "")).strip()
    user.mobile = str(form.get("mobile", "")).strip().translate(FA_TO_EN)
    user.title = str(form.get("title", "")).strip()
    user.company = str(form.get("company", "")).strip()
    user.city = str(form.get("city", "")).strip()
    if user.source == "local" and form.get("password"):
        user.password_enc = encrypt(str(form.get("password")))
    user.enabled = _bool(form, "enabled")
    user.group_id = _int(form.get("group_id"))
    user.office_id = _int(form.get("office_id"))
    user.department_id = _int(form.get("department_id"))
    user.personnel_code = str(form.get("personnel_code", "")).strip()
    user.rate_limit = str(form.get("rate_limit", "")).strip()
    user.quota_mb = quota
    user.quota_period = form.get("quota_period", "")
    user.allowed_hours = hours
    user.simultaneous_use = _int(form.get("simultaneous_use"))
    user.expire_at = expire
    user.static_ip = str(form.get("static_ip", "")).strip()
    user.allowed_macs = str(form.get("allowed_macs", "")).strip()
    user.notes = form.get("notes", "")
    written = ""
    if is_ad and _bool(form, "ad_write") and ldap_ad.enabled(db):
        try:
            with ldap_ad.Writer(db) as w:
                written = _write_ad(w, user, before, before_group, maps)
        except Exception as e:
            db.rollback()
            log.warning("AD write for %s failed: %s", user.username, e)
            flash(request, f"تغییرات ذخیره نشد؛ نوشتن در Active Directory ناموفق بود: {e}", "err")
            return redirect(f"/users/{uid}/edit")
    if not uid:
        db.add(user)
    db.commit()
    log_action(request, "ذخیره کاربر اینترنت", user.username + (f" (AD: {written})" if written else ""))
    flash(request, "کاربر ذخیره شد" + (" و تغییرات در Active Directory هم ثبت شد" if written else ""))
    return redirect("/users")


# fields of the bulk edit form: name -> (label, AD attribute or "")
BULK_TEXT = {"city": "محل / شهر", "title": "سمت", "company": "شرکت", "phone": "تلفن", "mobile": "موبایل"}


@app.post("/users/bulk-edit", response_class=HTMLResponse)
async def users_bulk_edit(request: Request):
    form = await request.form()
    db = SessionLocal()
    me = request.state.me
    ids = {int(x) for x in form.getlist("ids") if str(x).isdigit()}
    fields = set(form.getlist("set"))
    back = _local(form.get("back"), "/users")
    if not ids or not fields:
        flash(request, "هیچ کاربری انتخاب نشده یا هیچ فیلدی برای تغییر تیک نخورده", "err")
        return redirect(back)
    v = {k: str(form.get("v_" + k, "")).strip() for k in fields}
    try:
        if "allowed_hours" in v:
            policy.parse_hours(v["allowed_hours"])
        expire = jalali.parse_date(v["expire_at"]) if "expire_at" in v else None
        quota = int(float(v["quota_gb"]) * 1024) if v.get("quota_gb") else None
        simul = int(v["simultaneous_use"]) if v.get("simultaneous_use") else None
    except (ValueError, KeyError) as e:
        flash(request, f"مقدار نادرست: {e}", "err")
        return redirect(back)
    if "mobile" in v:
        v["mobile"] = v["mobile"].translate(FA_TO_EN)
    maps = _org_maps(db)
    users = scope.scope_query(db.query(User), me).filter(User.id.in_(ids)).order_by(User.username).all()
    ad_write = _bool(form, "ad_write") and ldap_ad.enabled(db)
    exclusive = _bool(form, "ad_exclusive")
    writer, writer_error = None, ""
    results = []
    track = ("group_id", "office_id", "department_id", "rate_limit", "quota_mb", "allowed_hours", "simultaneous_use",
             "expire_at", *BULK_TEXT)
    for u in users:
        old = {f: getattr(u, f) for f in track}
        before, before_group = ldap_ad.ad_values(u, maps[0], maps[1]), u.group_id
        if "group_id" in v:
            u.group_id = _int(v["group_id"])
        if "office_id" in v:
            u.office_id = _int(v["office_id"])
        if "department_id" in v:
            u.department_id = _int(v["department_id"])
        for k in BULK_TEXT:
            if k in v:
                setattr(u, k, v[k])
        if "rate_limit" in v:
            u.rate_limit = v["rate_limit"]
        if "quota_gb" in v:
            u.quota_mb = quota
        if "allowed_hours" in v:
            u.allowed_hours = v["allowed_hours"]
        if "simultaneous_use" in v:
            u.simultaneous_use = simul
        if "expire_at" in v:
            u.expire_at = expire
        note = "فقط در این برنامه"
        if u.source == "ldap" and ad_write:
            try:
                if writer is None:
                    if writer_error:
                        raise RuntimeError(writer_error)
                    try:
                        writer = ldap_ad.Writer(db)
                    except Exception as e:
                        writer_error = f"اتصال به AD ناموفق: {e}"
                        raise RuntimeError(writer_error)
                written = _write_ad(writer, u, before, before_group, maps, exclusive)
                note = f"در AD ثبت شد: {written}" if written else "تغییری برای AD نداشت"
            except Exception as e:
                for f, val in old.items():
                    setattr(u, f, val)
                results.append({"u": u, "ok": False, "msg": str(e)})
                continue
        elif u.source == "ldap":
            note = "فقط در این برنامه (با همگام‌سازی بعدی AD ممکن است برگردد)"
        results.append({"u": u, "ok": True, "msg": note})
    if writer is not None:
        writer.close()
    db.commit()
    ok = sum(1 for r in results if r["ok"])
    log_action(request, "ویرایش گروهی کاربران", f"{ok} از {len(results)} کاربر؛ فیلدها: {', '.join(sorted(fields))}")
    return render(request, "users_bulk_result.html", results=results, ok=ok, back=back,
                  fields=sorted(fields), ad_write=ad_write)


def _quota_mb(form):
    v = str(form.get("quota_value", "")).strip()
    if v == "":
        return None
    unit = form.get("quota_unit", "GB")
    return int(float(v) * (1024 if unit == "GB" else 1))


@app.post("/users/{uid}/delete")
def user_delete(request: Request, uid: int):
    db = SessionLocal()
    u = db.get(User, uid)
    if u:
        # SQLite may give the next new user the same id: detach the history so it is not inherited
        for model in (AcctSession, SpeedSample, TrafficCategory, TrafficDomain):
            db.query(model).filter(model.user_id == uid).update({"user_id": None}, synchronize_session=False)
        db.delete(u)
        db.commit()
        log_action(request, "حذف کاربر اینترنت", u.username)
        flash(request, "کاربر حذف شد")
    return redirect("/users")


@app.post("/users/{uid}/reset")
def user_reset(request: Request, uid: int):
    db = SessionLocal()
    u = db.get(User, uid)
    if u:
        u.usage_reset_at = now()
        db.commit()
        log_action(request, "صفر کردن مصرف", u.username)
        flash(request, f"مصرف {u.username} صفر شد")
    return redirect("/users")


@app.post("/users/{uid}/toggle")
def user_toggle(request: Request, uid: int):
    db = SessionLocal()
    u = db.get(User, uid)
    if u:
        u.enabled = not u.enabled
        db.commit()
        log_action(request, "فعال کردن کاربر" if u.enabled else "غیرفعال کردن کاربر", u.username)
    return redirect("/users")


@app.post("/users/bulk")
async def users_bulk(request: Request):
    """Bulk create local users: one per line 'username,password[,full name]'."""
    form = await request.form()
    db = SessionLocal()
    gid, oid, did = _int(form.get("group_id")), _int(form.get("office_id")), _int(form.get("department_id"))
    n = 0
    for line in str(form.get("lines", "")).splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2 or not parts[0]:
            continue
        if db.query(User).filter(func.lower(User.username) == parts[0].lower()).first():
            continue
        db.add(User(username=parts[0], password_enc=encrypt(parts[1]), full_name=parts[2] if len(parts) > 2 else "",
                    group_id=gid, office_id=oid, department_id=did, source="local"))
        n += 1
    db.commit()
    log_action(request, "ایجاد گروهی کاربران", f"{n} کاربر")
    flash(request, f"{n} کاربر ایجاد شد")
    return redirect("/users")


# ------------------------------------------------------------------ groups
@app.get("/groups", response_class=HTMLResponse)
def groups_list(request: Request):
    db = SessionLocal()
    counts = dict(db.query(User.group_id, func.count(User.id)).group_by(User.group_id).all())
    return render(request, "groups.html", groups=db.query(Group).order_by(Group.name).all(), counts=counts)


@app.get("/groups/new", response_class=HTMLResponse)
def group_new(request: Request):
    return render(request, "group_form.html", g=None)


@app.get("/groups/{gid}/edit", response_class=HTMLResponse)
def group_edit(request: Request, gid: int):
    db = SessionLocal()
    return render(request, "group_form.html", g=db.get(Group, gid))


@app.post("/groups/save")
async def group_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    gid = _int(form.get("id"))
    g = db.get(Group, gid) if gid else Group()
    hours = str(form.get("allowed_hours", "")).strip()
    try:
        policy.parse_hours(hours)
    except (ValueError, KeyError) as e:
        flash(request, f"فرمت ساعات مجاز نادرست است: {e}", "err")
        return redirect(f"/groups/{gid}/edit" if gid else "/groups/new")
    g.name = str(form.get("name", "")).strip() or "گروه"
    g.description = form.get("description", "")
    g.rate_limit = str(form.get("rate_limit", "")).strip()
    g.quota_mb = _quota_mb(form) or 0
    g.quota_period = form.get("quota_period", "monthly")
    g.allowed_hours = hours
    g.simultaneous_use = _int(form.get("simultaneous_use"), 1)
    g.session_timeout_min = _int(form.get("session_timeout_min"), 0)
    g.idle_timeout_min = _int(form.get("idle_timeout_min"), 0)
    g.allow_hotspot = _bool(form, "allow_hotspot")
    g.allow_vpn = _bool(form, "allow_vpn")
    g.address_list = str(form.get("address_list", "")).strip()
    g.ldap_group_dn = str(form.get("ldap_group_dn", "")).strip()
    if not gid:
        db.add(g)
    db.commit()
    log_action(request, "ذخیره گروه", g.name)
    flash(request, "گروه ذخیره شد")
    return redirect("/groups")


@app.post("/groups/{gid}/delete")
def group_delete(request: Request, gid: int):
    db = SessionLocal()
    g = db.get(Group, gid)
    if g:
        db.query(User).filter(User.group_id == gid).update({User.group_id: None})
        db.delete(g)
        db.commit()
        log_action(request, "حذف گروه", g.name)
        flash(request, "گروه حذف شد")
    return redirect("/groups")


# ------------------------------------------------------------------ offices & departments
@app.get("/org", response_class=HTMLResponse)
def org_page(request: Request, edit_office: int = 0, edit_dept: int = 0):
    db = SessionLocal()
    oc = dict(db.query(User.office_id, func.count(User.id)).group_by(User.office_id).all())
    dc = dict(db.query(User.department_id, func.count(User.id)).group_by(User.department_id).all())
    managers = {}
    for a in db.query(PanelUser).all():
        for oid in scope._ids(a.scope_offices):
            managers.setdefault(("o", oid), []).append(a.full_name or a.username)
        for did in scope._ids(a.scope_departments):
            managers.setdefault(("d", did), []).append(a.full_name or a.username)
    return render(request, "org.html", offices=db.query(Office).order_by(Office.name).all(),
                  departments=db.query(Department).order_by(Department.name).all(), oc=oc, dc=dc,
                  managers=managers, eo=db.get(Office, edit_office) if edit_office else None,
                  ed=db.get(Department, edit_dept) if edit_dept else None,
                  unassigned=db.query(User).filter(User.office_id.is_(None)).count())


@app.post("/org/office/save")
async def office_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    oid = _int(form.get("id"))
    o = db.get(Office, oid) if oid else Office()
    name = str(form.get("name", "")).strip()
    if not name or db.query(Office).filter(Office.name == name, Office.id != (oid or 0)).first():
        flash(request, "نام دفتر خالی یا تکراری است", "err")
        return redirect("/org")
    o.name, o.code, o.city = name, str(form.get("code", "")).strip(), str(form.get("city", "")).strip()
    o.ldap_value, o.description = str(form.get("ldap_value", "")).strip(), form.get("description", "")
    if not oid:
        db.add(o)
    db.commit()
    log_action(request, "ذخیره دفتر", o.name)
    flash(request, "دفتر ذخیره شد")
    return redirect("/org")


@app.post("/org/office/{oid}/delete")
def office_delete(request: Request, oid: int):
    db = SessionLocal()
    o = db.get(Office, oid)
    if o:
        db.query(User).filter(User.office_id == oid).update({User.office_id: None})
        db.query(Department).filter(Department.office_id == oid).update({Department.office_id: None})
        db.query(Nas).filter(Nas.office_id == oid).update({Nas.office_id: None})
        db.delete(o)
        db.commit()
        log_action(request, "حذف دفتر", o.name)
        flash(request, "دفتر حذف شد (کاربران آن بدون دفتر شدند)")
    return redirect("/org")


@app.post("/org/dept/save")
async def dept_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    did = _int(form.get("id"))
    d = db.get(Department, did) if did else Department()
    name = str(form.get("name", "")).strip()
    office_id = _int(form.get("office_id"))
    if not name or db.query(Department).filter(Department.name == name, Department.office_id == office_id,
                                               Department.id != (did or 0)).first():
        flash(request, "نام واحد خالی یا تکراری است", "err")
        return redirect("/org")
    d.name, d.office_id = name, office_id
    d.ldap_value, d.description = str(form.get("ldap_value", "")).strip(), form.get("description", "")
    if not did:
        db.add(d)
    db.commit()
    log_action(request, "ذخیره واحد", d.name)
    flash(request, "واحد ذخیره شد")
    return redirect("/org")


@app.post("/org/dept/{did}/delete")
def dept_delete(request: Request, did: int):
    db = SessionLocal()
    d = db.get(Department, did)
    if d:
        db.query(User).filter(User.department_id == did).update({User.department_id: None})
        db.delete(d)
        db.commit()
        log_action(request, "حذف واحد", d.name)
        flash(request, "واحد حذف شد")
    return redirect("/org")


@app.post("/org/assign")
async def org_assign(request: Request):
    """Assign many users to an office / department at once."""
    form = await request.form()
    db = SessionLocal()
    names = [x.strip() for x in str(form.get("usernames", "")).replace(",", "\n").splitlines() if x.strip()]
    values = {}
    if form.get("office_id") not in (None, "keep"):
        values[User.office_id] = _int(form.get("office_id"))
    if form.get("department_id") not in (None, "keep"):
        values[User.department_id] = _int(form.get("department_id"))
    n = 0
    if names and values:
        q = db.query(User)
        if _int(form.get("from_group")):
            q = q.filter(User.group_id == _int(form.get("from_group")))
        if names != ["*"]:
            q = q.filter(User.username.in_(names))
        n = q.update(values, synchronize_session=False)
        db.commit()
    log_action(request, "تخصیص دفتر/واحد به کاربران", f"{n} کاربر")
    flash(request, f"{n} کاربر به‌روزرسانی شد")
    return redirect("/org")


# ------------------------------------------------------------------ routers (NAS)
NET_DETECTED = {}   # nas id -> last auto-detect result (kept server-side: too big for the session cookie)


def _nas_page(request, edit=None):
    db = SessionLocal()
    detected = NET_DETECTED.get(edit.id, {}) if edit else {}
    interfaces = detected.get("interfaces") or []
    if edit and not interfaces:
        names = netscope.scope.ifnames.get(edit.id, {})
        interfaces = [{"name": k, "index": v, "type": "", "running": True} for k, v in sorted(names.items())]
    wan = netscope.split_names(edit.wan_interfaces) if edit else []
    known = {i["name"] for i in interfaces}
    from .netflow import collector
    from .radius_server import diag
    items = db.query(Nas).all()
    stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    by_ip = {}
    for n in items:
        for ip in (n.ip, n.api_host):
            if ip and ip != "0.0.0.0":
                by_ip.setdefault(ip, n.name)
    active = {}
    for nas_ip, sid in db.query(AcctSession.nas_ip, AcctSession.acct_session_id).filter(
            AcctSession.active.is_(True), AcctSession.last_update >= stale):
        e = active.setdefault(by_ip.get(nas_ip, nas_ip), [0, 0])
        e[1 if sid.startswith("api:") else 0] += 1
    names = {n.id: n.name for n in items}
    netscope.scope.refresh()
    radius_diag = [dict(d, src=k[0], ident=k[1], nas_ip=k[2]) for k, d in sorted(diag.items())]
    flow_diag, flow_day = [], {}
    for sender, e in sorted(collector.exporters.items()):
        rid = e.get("rid") if e.get("rid") is not None else netscope.scope.router_id(sender.split(" ")[0])
        split = sorted(((names.get(r, "؟"), c) for r, c in e.get("routers", {}).items() if r != rid),
                       key=lambda x: -x[1])
        flow_diag.append(dict(e, sender=sender, router=names.get(rid, ""), split=split))
        if rid is not None and e.get("first"):
            secs = max(60.0, (now() - e["first"]).total_seconds())
            flow_day[rid] = flow_day.get(rid, 0) + e.get("bytes", 0) * 86400 / secs
    # "add router" from a diagnostics row: identity / address the packets carried
    new = {k: request.query_params.get(k, "") for k in ("ident", "nas_ip")} if not edit else {}
    return render(request, "nas.html", items=items, status=jobs.live["routers"], edit=edit,
                  radius_diag=radius_diag, flow_diag=flow_diag, flow_seen=collector.per_router, new=new,
                  flow_port=config.NETFLOW_PORT, active=active, flow_day=flow_day,
                  api_day={k: v * 86400 / max(1, config.ROUTER_POLL_EVERY) for k, v in jobs.live["api_bytes"].items()},
                  lan_ifs=netscope.split_names(edit.lan_interfaces) if edit else [],
                  tun_ifs=netscope.split_names(edit.tunnel_interfaces) if edit else [],
                  tunnel_types=netscope.TUNNEL_TYPES,
                  offices=db.query(Office).order_by(Office.name).all(), detected=detected, interfaces=interfaces,
                  wan=wan, wan_extra=" ".join(w for w in wan if w not in known), describe=netscope.scope.describe,
                  internal_ranges=get_setting(db, "internal_ranges", netscope.DEFAULT_INTERNAL),
                  internet_ranges=get_setting(db, "internet_ranges", ""),
                  quota_internet_only=policy.internet_only(db))


@app.get("/nas", response_class=HTMLResponse)
def nas_list(request: Request):
    return _nas_page(request)


@app.get("/nas/{nid}/edit", response_class=HTMLResponse)
def nas_edit(request: Request, nid: int):
    db = SessionLocal()
    n = db.get(Nas, nid)
    if n is None:
        return redirect("/nas")
    return _nas_page(request, n)


def _ranges_field(request, form, key):
    text = str(form.get(key, "")).strip()
    nets, bad = netscope.parse_ranges(text)
    if bad:
        flash(request, "رنج نامعتبر نادیده گرفته شد: " + "، ".join(bad[:10]), "err")
        text = "\n".join(str(n) for n in nets)
    return text


@app.post("/nas/save")
async def nas_save(request: Request):
    from .radius_server import nas_cache
    form = await request.form()
    db = SessionLocal()
    nid = _int(form.get("id"))
    ip = str(form.get("ip", "")).strip()
    dup = db.query(Nas).filter(Nas.ip == ip, Nas.id != (nid or 0)).first() if ip else None
    if dup:
        flash(request, f"روتر «{dup.name}» با همین IP ({ip}) ثبت شده است؛ هر روتر را با IP واقعی خودش ثبت کنید "
                       "(0.0.0.0 فقط برای یک روتر قابل استفاده است)", "err")
        return redirect(f"/nas/{nid}/edit" if nid else "/nas")
    flow_port = _int(form.get("flow_port"), 0) or 0
    taken = {config.RADIUS_AUTH_PORT, config.RADIUS_ACCT_PORT, _int(os.environ.get("WEB_PORT", "8080"), 8080)}
    other = db.query(Nas).filter(Nas.flow_port == flow_port, Nas.id != (nid or 0)).first() if flow_port else None
    if flow_port and (flow_port in taken or not 1024 <= flow_port <= 65535 or other):
        flash(request, f"پورت Traffic-Flow {flow_port} قابل استفاده نیست" +
              (f" (روتر «{other.name}» آن را دارد)" if other else " (۱۰۲۴ تا ۶۵۵۳۵ و غیر از پورت‌های RADIUS و پنل)"),
              "err")
        return redirect(f"/nas/{nid}/edit" if nid else "/nas")
    n = db.get(Nas, nid) if nid else Nas()
    n.name = form.get("name", "router")
    n.ip = ip
    n.identifier = str(form.get("identifier", "")).strip()[:100]
    n.flow_port = 0 if flow_port == config.NETFLOW_PORT else flow_port
    if form.get("secret"):
        n.secret = str(form.get("secret"))
    n.api_host = str(form.get("api_host", "")).strip()
    n.api_port = _int(form.get("api_port"), 8728)
    n.api_user = str(form.get("api_user", "")).strip()
    if form.get("api_password"):
        n.api_password_enc = encrypt(str(form.get("api_password")))
    n.api_ssl = _bool(form, "api_ssl")
    n.coa_port = _int(form.get("coa_port"), 3799)
    n.office_id = _int(form.get("office_id"))
    n.file_proto = "sftp" if form.get("file_proto") == "sftp" else "ftp"
    n.file_port = _int(form.get("file_port"), 0)
    n.hotspot_dir = str(form.get("hotspot_dir", "")).strip().strip("/")
    wan = [str(w) for w in form.getlist("wan")] + netscope.split_names(str(form.get("wan_extra", "")))
    n.wan_interfaces = ",".join(dict.fromkeys(w for w in wan if w))[:300]
    n.lan_ranges = _ranges_field(request, form, "lan_ranges")
    lan_ifs = [str(w) for w in form.getlist("lan_if")] + netscope.split_names(str(form.get("lan_if_extra", "")))
    n.lan_interfaces = ",".join(dict.fromkeys(w for w in lan_ifs if w))[:300]
    tun_ifs = [str(w) for w in form.getlist("tun_if")] + netscope.split_names(str(form.get("tun_if_extra", "")))
    n.tunnel_interfaces = ",".join(dict.fromkeys(w for w in tun_ifs if w))[:300]
    n.tunnel_ranges = _ranges_field(request, form, "tunnel_ranges")
    n.monitor_targets = " ".join(routeros.split_targets(str(form.get("monitor_targets", ""))))[:300]
    if not n.secret or not n.ip:
        flash(request, "IP و Secret الزامی است", "err")
        return redirect("/nas")
    if not nid:
        db.add(n)
    db.commit()
    NET_DETECTED.pop(n.id, None)
    nas_cache.invalidate()
    netscope.scope.invalidate()
    from .netflow import collector
    try:
        collector.sync_ports()
    except Exception as e:
        flash(request, f"باز کردن پورت Traffic-Flow ناموفق: {e}", "err")
    log_action(request, "ذخیره روتر", f"{n.name} {n.ip} NAS-Identifier={n.identifier} WAN={n.wan_interfaces}")
    if request.session.get("flash", {}).get("kind") != "err":
        flash(request, "روتر ذخیره شد")
    return redirect("/nas")


@app.post("/nas/scope")
async def nas_scope_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    set_setting(db, "internal_ranges", _ranges_field(request, form, "internal_ranges"))
    set_setting(db, "internet_ranges", _ranges_field(request, form, "internet_ranges"))
    set_setting(db, "quota_internet_only", "1" if form.get("quota_internet_only") else "0")
    db.commit()
    netscope.scope.invalidate()
    log_action(request, "تنظیم رنج‌های داخل شبکه / اینترنت")
    if request.session.get("flash", {}).get("kind") != "err":
        flash(request, "رنج‌های داخل شبکه ذخیره شد")
    return redirect("/nas")


@app.post("/nas/{nid}/detect-net")
def nas_detect_net(request: Request, nid: int):
    db = SessionLocal()
    n = db.get(Nas, nid)
    if n is None:
        return redirect("/nas")
    try:
        info = routeros.network_info(n)
    except Exception as e:
        flash(request, f"خواندن اینترفیس‌ها از روتر ناموفق بود: {e}", "err")
        return redirect(f"/nas/{nid}/edit")
    netscope.scope.learn(n.id, [{"name": i["name"], ".id": f"*{i['index']:X}", "type": i.get("type", "")}
                                for i in info["interfaces"] if i["index"] is not None])
    NET_DETECTED[n.id] = info
    flash(request, f"اینترفیس WAN پیشنهادی: {'، '.join(info['wan']) or 'پیدا نشد'} · "
                   f"{len(info['lan'])} رنج داخلی پیدا شد. بررسی کنید و «ذخیره» را بزنید.")
    return redirect(f"/nas/{nid}/edit")


@app.post("/nas/{nid}/delete")
def nas_delete(request: Request, nid: int):
    from .radius_server import nas_cache
    db = SessionLocal()
    n = db.get(Nas, nid)
    if n:
        db.delete(n)
        db.commit()
        nas_cache.invalidate()
        from .netflow import collector
        collector.sync_ports()
        log_action(request, "حذف روتر", f"{n.name} {n.ip}")
    return redirect("/nas")


@app.post("/nas/{nid}/test")
def nas_test(request: Request, nid: int):
    db = SessionLocal()
    n = db.get(Nas, nid)
    try:
        snap = routeros.snapshot(n)
        flash(request, f"اتصال API موفق: {snap.get('identity')} | هات‌اسپات فعال: {len(snap['hotspot_active'])}"
                       f" | VPN فعال: {len(snap['ppp_active'])}")
    except Exception as e:
        flash(request, f"خطا در اتصال API: {e}", "err")
    return redirect("/nas")


# ------------------------------------------------------------------ Active Directory
def _ad_page(request, ad_groups=None):
    db = SessionLocal()
    cfg = {k: get_setting(db, k) for k in LDAP_KEYS}
    cfg["ldap_bind_password"] = "********" if cfg["ldap_bind_password"] else ""
    mapped = {g.ldap_group_dn.lower(): g.name for g in db.query(Group).all() if g.ldap_group_dn}
    return render(request, "ad.html", cfg=cfg, groups=db.query(Group).order_by(Group.name).all(),
                  ad_groups=ad_groups, mapped=mapped,
                  ldap_users=db.query(User).filter(User.source == "ldap").count())


@app.get("/ad", response_class=HTMLResponse)
def ad_page(request: Request):
    return _ad_page(request)


@app.post("/ad/save")
async def ad_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    for k in LDAP_KEYS:
        v = str(form.get(k, "")).strip()
        if k == "ldap_bind_password":
            if v and v != "********":
                set_setting(db, k, encrypt(v))
            continue
        if k in ("ldap_use_ssl", "ldap_auto_sync", "ldap_auto_org"):
            v = "1" if _bool(form, k) else "0"
        set_setting(db, k, v)
    if _bool(form, "ldap_use_ssl") and str(form.get("ldap_port", "")).strip() in ("", "389"):
        set_setting(db, "ldap_port", "636")
    db.commit()
    log_action(request, "تغییر تنظیمات Active Directory")
    flash(request, "تنظیمات Active Directory ذخیره شد")
    return redirect("/ad")


@app.post("/ad/test")
def ad_test(request: Request):
    db = SessionLocal()
    try:
        ok, msg = ldap_ad.test_connection(db)
        flash(request, msg if ok else f"خطا: {msg}", "ok" if ok else "err")
    except Exception as e:
        flash(request, f"خطا: {e}", "err")
    return redirect("/ad")


@app.post("/ad/groups", response_class=HTMLResponse)
def ad_groups(request: Request):
    # rendered directly: the list is far too big for the session cookie
    db = SessionLocal()
    try:
        groups = ldap_ad.list_groups(db)
    except Exception as e:
        flash(request, f"خطا در خواندن گروه‌های AD: {e}", "err")
        return redirect("/ad")
    if not groups:
        flash(request, "هیچ گروهی در Base DN پیدا نشد", "err")
    return _ad_page(request, ad_groups=groups)


@app.post("/ad/sync")
def ad_sync(request: Request):
    db = SessionLocal()
    try:
        st = ldap_ad.sync_users(db)
        log_action(request, "همگام‌سازی AD", str(st))
        flash(request, f"همگام‌سازی انجام شد: {st['total']} کاربر در AD، {st['created']} جدید، "
                       f"{st['updated']} به‌روزرسانی، {st['disabled']} غیرفعال")
    except Exception as e:
        flash(request, f"خطا در همگام‌سازی: {e}", "err")
    return redirect("/ad")


# ------------------------------------------------------------------ live sessions
def _live_rows(db, me):
    stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    rows = []
    q = db.query(AcctSession).filter(AcctSession.active.is_(True), AcctSession.last_update >= stale)
    ids = scope.resolve_ids(db, me)
    if ids is not None:
        q = q.filter(AcctSession.user_id.in_(ids))
    for s in q.order_by(AcctSession.start_time.desc()).all():
        up, down = jobs.live["rates"].get(s.framed_ip, (None, None))
        rows.append({"s": s, "up": up, "down": down, "duration": int((now() - s.start_time).total_seconds())})
    return rows


@app.get("/live", response_class=HTMLResponse)
def live_page(request: Request):
    db = SessionLocal()
    names = {}
    for n in db.query(Nas).all():
        names.setdefault(n.ip, n.name)
        if n.api_host:
            names.setdefault(n.api_host, n.name)
    return render(request, "live.html", rows=_live_rows(db, request.state.me), updated=jobs.live["updated"],
                  nas_names=names)


@app.get("/api/live")
def live_api(request: Request):
    db = SessionLocal()
    return [{"id": r["s"].id, "username": r["s"].username, "ip": r["s"].framed_ip,
             "up": fmt_rate(r["up"]) if r["up"] is not None else "-",
             "down": fmt_rate(r["down"]) if r["down"] is not None else "-",
             "bytes": fmt_bytes((r["s"].bytes_in or 0) + (r["s"].bytes_out or 0)),
             "duration": fmt_duration(r["duration"])} for r in _live_rows(db, request.state.me)]


def _nas_for_ip(db, ip):
    """Router of a session: by RADIUS source IP, API address, or the 'any IP' (0.0.0.0) entry."""
    return (db.query(Nas).filter(Nas.ip == ip).first() or db.query(Nas).filter(Nas.api_host == ip).first()
            or db.query(Nas).filter(Nas.ip == "0.0.0.0").first()) if ip else None


@app.post("/live/{sid}/disconnect")
def live_disconnect(request: Request, sid: int):
    db = SessionLocal()
    s = db.get(AcctSession, sid)
    nas = _nas_for_ip(db, s.nas_ip) if s else None
    if s and nas and routeros.disconnect(nas, s.username, s.service, s.acct_session_id, s.framed_ip):
        s.terminate_cause = "Admin-Reset"
        db.commit()
        log_action(request, "قطع اتصال کاربر", s.username)
        flash(request, f"اتصال {s.username} قطع شد")
    else:
        flash(request, "قطع اتصال ناموفق بود (CoA یا API روتر را بررسی کنید)", "err")
    return redirect("/live")


# ------------------------------------------------------------------ reports
def _report_filter(request: Request, default_preset="today"):
    p = request.query_params
    today = now().date()
    preset = p.get("preset", "")
    if not preset and not p.get("from"):
        preset = default_preset
    start = _date(p.get("from", ""))
    end = _date(p.get("to", ""))
    if preset == "today" or (not start and not preset):
        start = end = today
    elif preset == "yesterday":
        start = end = today - timedelta(days=1)
    elif preset == "week":
        start, end = policy.period_start("weekly").date(), today
    elif preset == "month":
        start, end = jalali.jalali_month_start(today), today
    elif preset == "30d":
        start, end = today - timedelta(days=29), today
    elif preset == "lastmonth":
        end = jalali.jalali_month_start(today) - timedelta(days=1)
        start = jalali.jalali_month_start(end)
    elif preset == "90d":
        start, end = today - timedelta(days=89), today
    start = start or today
    end = end or today
    db = SessionLocal()
    me = getattr(request.state, "me", None)
    user_id, group_id = _int(p.get("user_id")), _int(p.get("group_id"))
    office_id, department_id = _int(p.get("office_id")), _int(p.get("department_id"))
    ids = scope.resolve_ids(db, me, group_id, office_id, department_id, user_id)
    f = reports.Filter(datetime.combine(start, datetime.min.time()),
                       datetime.combine(end + timedelta(days=1), datetime.min.time()),
                       ids=ids, service=p.get("service", ""))
    if user_id and ids == [-1]:     # user outside the viewer's scope
        user_id = None
    f.user_id, f.group_id, f.office_id, f.department_id = user_id, group_id, office_id, department_id
    return f, start, end


def _filter_caption(db, f):
    parts = []
    for model, key, label in ((Office, "office_id", "دفتر"), (Department, "department_id", "واحد"),
                              (Group, "group_id", "گروه"), (User, "user_id", "کاربر")):
        oid = getattr(f, key, None)
        obj = db.get(model, oid) if oid else None
        if obj is not None:
            parts.append(f"{label} {getattr(obj, 'name', None) or obj.full_name or obj.username}")
    return " · ".join(parts)


def _filter_lists(db, me):
    users = scope.scope_query(db.query(User.id, User.username, User.full_name), me).order_by(User.username).all()
    return {"users": users, "groups": db.query(Group).order_by(Group.name).all(), **_org_lists(db, me)}


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    db = SessionLocal()
    f, start, end = _report_filter(request)
    rep = reports.build(db, f)
    sel_user = db.get(User, f.user_id) if f.user_id else None
    quota = policy.quota_state(db, sel_user) if sel_user else None
    return render(request, "reports.html", rep=rep, f=f, start=jalali.to_jalali_str(start),
                  end=jalali.to_jalali_str(end), sel_user=sel_user, quota=quota, qs=str(request.query_params),
                  **_filter_lists(db, request.state.me))


@app.get("/reports/export")
def reports_export(request: Request, kind: str = "users"):
    db = SessionLocal()
    f, start, end = _report_filter(request)
    rep = reports.build(db, f, session_limit=100000)
    buf = io.StringIO()
    buf.write("﻿")  # Excel UTF-8 BOM
    w = csv.writer(buf)
    if kind == "sessions":
        w.writerow(["کاربر", "سرویس", "شروع", "پایان", "مدت (ثانیه)", "IP", "MAC", "دستگاه", "سیستم‌عامل",
                    "دانلود (بایت)", "آپلود (بایت)", "حداکثر سرعت دانلود (bps)", "علت قطع"])
        for s in rep["sessions"]:
            w.writerow([s.username, s.service, jalali.to_jalali_str(s.start_time, True),
                        jalali.to_jalali_str(s.stop_time, True) if s.stop_time else "فعال", s.session_time,
                        s.framed_ip, s.mac, devices.TYPE_FA.get(s.device_type or "", ""), s.device_os,
                        s.bytes_out, s.bytes_in, s.peak_down_bps, s.terminate_cause])
    elif kind == "categories":
        w.writerow(["نوع استفاده", "دانلود (بایت)", "آپلود (بایت)", "درصد", "تعداد Flow"])
        for c in rep["categories"]:
            w.writerow([c["name"], c["down"], c["up"], c["pct"], c["flows"]])
    elif kind == "domains":
        w.writerow(["دامنه/مقصد", "نوع", "دانلود (بایت)", "آپلود (بایت)"])
        for d in rep["domains"]:
            w.writerow([d["domain"], d["category"], d["down"], d["up"]])
    elif kind == "daily":
        rows = rep["split"]["user_daily"]
        users = {u.id: u for u in db.query(User).filter(User.id.in_({r["user_id"] for r in rows} or {-1}))}
        offices = {o.id: o.name for o in db.query(Office).all()}
        depts = {d.id: d.name for d in db.query(Department).all()}
        w.writerow(["تاریخ", "کاربر", "نام", "دفتر", "واحد", "اینترنت (بایت)", "داخل شبکه (بایت)", "مجموع (بایت)",
                    "دانلود اینترنت", "آپلود اینترنت", "دانلود داخلی", "آپلود داخلی", "تانل (بایت)", "دانلود تانل",
                    "آپلود تانل"])
        for r in rows:
            u = users.get(r["user_id"])
            w.writerow([jalali.to_jalali_str(r["day"]), u.username if u else "?", u.full_name if u else "", offices.get(u.office_id, "") if u else "",
                        depts.get(u.department_id, "") if u else "", r["internet"], r["internal"], r["total"],
                        r["internet_down"], r["internet_up"], r["internal_down"], r["internal_up"], r["tunnel"],
                        r["tunnel_down"], r["tunnel_up"]])
    else:
        w.writerow(["کاربر", "نام", "دفتر", "واحد", "گروه", "دانلود (بایت)", "آپلود (بایت)", "مجموع (بایت)",
                    "اینترنت (بایت)", "داخل شبکه (بایت)",
                    "تعداد اتصال", "مدت آنلاین (ثانیه)", "میانگین سرعت دانلود (bps)", "حداکثر سرعت دانلود (bps)",
                    "دستگاه‌ها", "تانل (بایت)"])
        for u in rep["users"]:
            w.writerow([u["username"], u["full_name"], u["office"], u["department"], u["group"], u["down"], u["up"],
                        u["total"], u["internet"], u["internal"], u["sessions"],
                        u["online"], u["avg_down"], u["peak_down"], u["devices"], u["tunnel"]])
    name = f"report-{kind}-{start.isoformat()}-{end.isoformat()}.csv"
    log_action(request, "خروجی گزارش", f"{kind} {jalali.to_jalali_str(start)}..{jalali.to_jalali_str(end)}")
    return Response(buf.getvalue().encode("utf-8"), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ------------------------------------------------------------------ management & HR reports
def _mgmt_routers(db, me, f):
    """Routers of the report: the chosen office, else every router the viewer's scope covers."""
    q = db.query(Nas).order_by(Nas.name)
    if getattr(f, "office_id", None):
        return q.filter(Nas.office_id == f.office_id).all()
    if scope.is_scoped(me):
        oids = [o.id for o in scope.visible_offices(db, me)]
        return q.filter(Nas.office_id.in_(oids or [-1])).all()
    if getattr(f, "user_id", None) or getattr(f, "group_id", None) or getattr(f, "department_id", None):
        return []           # a person / group report: router totals do not belong to it
    return q.all()


def _mgmt_ctx(request):
    db = SessionLocal()
    f, start, end = _report_filter(request, default_preset="month")
    rep = mgmt.management(db, f.start, f.end, ids=f.ids)
    rep["routers"] = mgmt.router_internet(db, f.start, f.end, _mgmt_routers(db, request.state.me, f))
    caption = " · ".join(x for x in (scope.scope_label(db, request.state.me), _filter_caption(db, f)) if x)
    calls = None
    if "calls_view" in getattr(request.state, "perms", set()) and db.query(PbxServer.id).first():
        calls = pbx.build(db, f.start, f.end, ids=f.ids)
        calls["offices"] = pbx.by_unit(calls["people"], "office")
        calls["departments"] = pbx.by_unit(calls["people"], "department")
    return db, f, rep, {"rep": rep, "f": f, "calls": calls, "start": jalali.to_jalali_str(start), "end": jalali.to_jalali_str(end),
                        "caption": caption, "qs": str(request.query_params), "generated": now(),
                        **_filter_lists(db, request.state.me)}


@app.get("/mgmt", response_class=HTMLResponse)
def mgmt_page(request: Request):
    db, f, rep, ctx = _mgmt_ctx(request)
    return render(request, "mgmt.html", **ctx)


@app.get("/mgmt/print", response_class=HTMLResponse)
def mgmt_print(request: Request):
    db, f, rep, ctx = _mgmt_ctx(request)
    log_action(request, "چاپ / PDF گزارش مدیریتی", f"{ctx['start']}..{ctx['end']}")
    return render(request, "mgmt_print.html", **ctx)


@app.get("/mgmt/export.xlsx")
def mgmt_export(request: Request):
    db, f, rep, ctx = _mgmt_ctx(request)
    data = xlsx.management_xlsx(rep, ctx["caption"], ctx["calls"])
    log_action(request, "خروجی Excel گزارش مدیریتی", f"{ctx['start']}..{ctx['end']}")
    name = f"management-report-{f.start.date().isoformat()}.xlsx"
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/settings")
async def settings_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    hours = str(form.get("work_hours", "")).strip()
    try:
        if not policy.parse_hours(hours):
            raise ValueError("خالی است")
    except (ValueError, KeyError) as e:
        flash(request, f"فرمت ساعات کاری نادرست است: {e}", "err")
        return redirect(_local(form.get("back"), "/mgmt"))
    set_setting(db, "work_hours", hours)
    db.commit()
    log_action(request, "تغییر ساعات کاری", hours)
    flash(request, "ساعات کاری ذخیره شد")
    return redirect(_local(form.get("back"), "/mgmt"))


def _attendance_ctx(request):
    db = SessionLocal()
    f, start, end = _report_filter(request, default_preset="today")
    rows = mgmt.attendance(db, f.start, f.end, ids=f.ids)
    caption = " · ".join(x for x in (scope.scope_label(db, request.state.me), _filter_caption(db, f)) if x)
    return db, f, rows, {"rows": rows, "f": f, "start": jalali.to_jalali_str(start), "end": jalali.to_jalali_str(end),
                         "caption": caption, **_filter_lists(db, request.state.me),
                         "qs": str(request.query_params),
                         "work_hours": get_setting(db, "work_hours", mgmt.DEFAULT_WORK_HOURS) or mgmt.DEFAULT_WORK_HOURS}


@app.get("/attendance", response_class=HTMLResponse)
def attendance_page(request: Request):
    db, f, rows, ctx = _attendance_ctx(request)
    return render(request, "attendance.html", **ctx)


@app.get("/attendance/export.xlsx")
def attendance_export(request: Request):
    db, f, rows, ctx = _attendance_ctx(request)
    data = xlsx.attendance_xlsx(rows, f"گزارش ساعات اتصال کارکنان {ctx['start']} تا {ctx['end']}"
                                      + (f" — {ctx['caption']}" if ctx["caption"] else "")
                                      + f" — ساعات کاری: {ctx['work_hours']}")
    log_action(request, "خروجی Excel ساعات اتصال", f"{ctx['start']}..{ctx['end']}")
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="attendance-{f.start.date().isoformat()}.xlsx"'})


# ------------------------------------------------------------------ calls (Issabel)
def _pbx_names(db):
    return {s.id: s.name for s in db.query(PbxServer)}


def _calls_ctx(request):
    db = SessionLocal()
    f, start, end = _report_filter(request, default_preset="today")
    p = request.query_params
    pbx_id = _int(p.get("pbx"))
    rep = pbx.build(db, f.start, f.end, ids=f.ids, pbx_id=pbx_id)
    rep["offices"] = pbx.by_unit(rep["people"], "office")
    rep["departments"] = pbx.by_unit(rep["people"], "department")
    direction = p.get("dir", "")
    recent = pbx.recent(db, f.start, f.end, ids=f.ids, pbx_id=pbx_id, limit=100)
    if direction in ("in", "out", "internal"):
        recent = [r for r in recent if r.direction == direction]
    names = _pbx_names(db)
    users = {u.id: u for u in db.query(User).filter(User.id.in_({r.user_id for r in recent if r.user_id} or {-1}))}
    caption = " · ".join(x for x in (scope.scope_label(db, request.state.me), _filter_caption(db, f),
                                      names.get(pbx_id, "")) if x)
    return db, f, rep, {"c": rep, "f": f, "start": jalali.to_jalali_str(start), "end": jalali.to_jalali_str(end),
                        "caption": caption, "qs": str(request.query_params), "recent": recent, "dir": direction,
                        "qs_nodir": urlencode([(k, v) for k, v in p.multi_items() if k != "dir"]),
                        "pbx_names": names, "pbx_id": pbx_id, "call_users": users,
                        "servers": db.query(PbxServer).order_by(PbxServer.name).all(),
                        "weekdays": pbx.WEEKDAYS, "sl_seconds": pbx.sl_seconds(db), **_filter_lists(db, request.state.me)}


@app.get("/calls", response_class=HTMLResponse)
def calls_page(request: Request):
    db, f, rep, ctx = _calls_ctx(request)
    return render(request, "calls.html", **ctx)


@app.get("/calls/export.xlsx")
def calls_export(request: Request):
    db, f, rep, ctx = _calls_ctx(request)
    rows = pbx.recent(db, f.start, f.end, ids=f.ids, pbx_id=ctx["pbx_id"], limit=100000)
    data = xlsx.calls_xlsx(rep, f"گزارش تماس‌ها {ctx['start']} تا {ctx['end']}"
                           + (f" — {ctx['caption']}" if ctx["caption"] else ""), rows, ctx["pbx_names"])
    log_action(request, "خروجی Excel تماس‌ها", f"{ctx['start']}..{ctx['end']}")
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="calls-{f.start.date().isoformat()}.xlsx"'})


def _pbx_page(request, edit=None):
    db = SessionLocal()
    since = now() - timedelta(days=30)
    legs = db.query(Call).filter(Call.ts >= since, Call.extension != "", Call.user_id.is_(None)).all()
    users = db.query(User.id, User.username, User.full_name).order_by(User.username).all()
    names = {u.id: (u.full_name or u.username) for u in users}
    assigns = db.query(ExtensionAssignment).order_by(ExtensionAssignment.extension,
                                                     ExtensionAssignment.start.desc()).all()
    return render(request, "pbx.html", servers=db.query(PbxServer).order_by(PbxServer.name).all(), edit=edit,
                  unassigned=pbx._unassigned(legs), users=users, user_names=names, assigns=assigns,
                  pbx_names=_pbx_names(db), offices=db.query(Office).order_by(Office.name).all(),
                  calls_count={i: n for i, n in db.query(Call.pbx_id, func.count(Call.id)).group_by(Call.pbx_id)},
                  today=jalali.to_jalali_str(now().date()), ad_suggest=pbx.ad_suggestions(db),
                  sl_seconds=pbx.sl_seconds(db), missed_alert=get_setting(db, "pbx_missed_alert", "0"))


@app.post("/pbx/settings")
async def pbx_settings(request: Request):
    form = await request.form()
    db = SessionLocal()
    sl = _int(str(form.get("pbx_sl_seconds", "")).translate(FA_TO_EN))
    if sl and sl > 0:
        set_setting(db, "pbx_sl_seconds", str(sl))
    ma = _int(str(form.get("pbx_missed_alert", "")).translate(FA_TO_EN))
    if ma is not None and ma >= 0:
        set_setting(db, "pbx_missed_alert", str(ma))
    db.commit()
    log_action(request, "تنظیم گزارش تماس", f"سطح سرویس {sl} ثانیه، هشدار {ma}")
    flash(request, "ذخیره شد")
    return redirect("/pbx#settings")


@app.post("/pbx/ad-assign")
async def pbx_ad_assign(request: Request):
    """Assign every (or the chosen) extension suggested by the users' AD ipPhone, from today."""
    form = await request.form()
    db = SessionLocal()
    chosen = {str(x) for x in form.getlist("pick")}
    n, errors = 0, []
    for sug in pbx.ad_suggestions(db):
        if chosen and f"{sug['user_id']}:{sug['extension']}" not in chosen:
            continue
        err = _add_assignment(request, db, sug["user_id"], sug["extension"], None, None, None)
        if err:
            errors.append(f"{sug['extension']}: {err}")
        else:
            n += 1
    flash(request, f"{n} داخلی از روی AD تخصیص داده شد" + (" — " + "؛ ".join(errors) if errors else ""),
          "err" if errors and not n else "ok")
    return redirect("/pbx#ad")


# ------------------------------------------------------------------ live calls (AMI)
def _live_calls(db, me):
    servers = db.query(PbxServer).filter(PbxServer.enabled.is_(True), PbxServer.ami_user != "").all()
    all_ranges = [pbx.parse_ranges(x.ext_ranges) for x in db.query(PbxServer).all()]
    owners = pbx.Owners(db)
    today = now().date()
    rows, errors = [], []
    for s in servers:
        try:
            rows += ami.live_calls(s, all_ranges, lambda ext, sid=s.id: owners.user(sid, ext, today) if ext else None)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{s.name}: {e}")
    ids = scope.resolve_ids(db, me)
    if ids is not None:
        rows = [r for r in rows if r["user_id"] in set(ids)]
    users = {u.id: u for u in db.query(User).filter(User.id.in_({r["user_id"] for r in rows if r["user_id"]} or {-1}))}
    names = _pbx_names(db)
    for r in rows:
        u = users.get(r["user_id"])
        r["user"] = (u.full_name or u.username) if u else ""
        r["server"] = names.get(r["pbx_id"], "")
    return rows, errors, bool(servers)


@app.get("/calls/live", response_class=HTMLResponse)
async def calls_live(request: Request):
    db = SessionLocal()
    rows, errors, configured = await run_in_threadpool(_live_calls, db, request.state.me)
    return render(request, "calls_live.html", rows=rows, errors=errors, configured=configured,
                  dir_fa=pbx.DIR_FA)


@app.get("/api/calls/live")
async def calls_live_api(request: Request):
    db = SessionLocal()
    rows, errors, configured = await run_in_threadpool(_live_calls, db, request.state.me)
    return {"rows": rows, "errors": errors, "configured": configured}


@app.get("/pbx", response_class=HTMLResponse)
def pbx_list(request: Request):
    return _pbx_page(request)


@app.get("/pbx/new", response_class=HTMLResponse)
def pbx_new(request: Request):
    return _pbx_page(request, PbxServer(port=3306, db_name="asteriskcdrdb", enabled=True))


@app.get("/pbx/{sid}/edit", response_class=HTMLResponse)
def pbx_edit(request: Request, sid: int):
    db = SessionLocal()
    s = db.get(PbxServer, sid)
    return _pbx_page(request, s) if s else redirect("/pbx")


@app.post("/pbx/save")
async def pbx_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    sid = _int(form.get("id"))
    s = db.get(PbxServer, sid) if sid else PbxServer()
    if s is None:
        return redirect("/pbx")
    s.name = str(form.get("name", "")).strip()[:100]
    s.host = str(form.get("host", "")).strip()[:100]
    s.port = _int(form.get("port"), 3306) or 3306
    s.db_name = str(form.get("db_name", "")).strip()[:64] or "asteriskcdrdb"
    s.db_user = str(form.get("db_user", "")).strip()[:100]
    if form.get("db_password"):
        s.db_password_enc = encrypt(str(form.get("db_password")))
    s.ext_ranges = str(form.get("ext_ranges", "")).strip()[:300]
    s.trunks = str(form.get("trunks", "")).strip()[:300]
    s.office_id = _int(form.get("office_id"))
    s.enabled = _bool(form, "enabled")
    s.ami_port = _int(form.get("ami_port"), 5038) or 5038
    s.ami_user = str(form.get("ami_user", "")).strip()[:100]
    if form.get("ami_password"):
        s.ami_password_enc = encrypt(str(form.get("ami_password")))
    if not s.name or not s.host:
        flash(request, "نام و آدرس سرور الزامی است", "err")
        return redirect(f"/pbx/{sid}/edit" if sid else "/pbx/new")
    if s.ext_ranges and not pbx.parse_ranges(s.ext_ranges):
        flash(request, "بازه داخلی‌ها نادرست است؛ مثال: 100-399, 5000-5099", "err")
        return redirect(f"/pbx/{sid}/edit" if sid else "/pbx/new")
    db.add(s)
    db.commit()
    log_action(request, "ذخیره سرور ایزابل", f"{s.name} {s.host}:{s.port}")
    ok, msg = pbx.test(s)
    if s.ami_user:
        ok2, msg2 = ami.test(s)
        ok, msg = ok and ok2, msg + " " + msg2
    flash(request, ("ذخیره شد. " + msg) if ok else ("ذخیره شد ولی " + msg), "ok" if ok else "err")
    return redirect("/pbx")


@app.post("/pbx/{sid}/test")
def pbx_test(request: Request, sid: int):
    db = SessionLocal()
    s = db.get(PbxServer, sid)
    if s:
        ok, msg = pbx.test(s)
        if s.ami_user:
            ok2, msg2 = ami.test(s)
            ok, msg = ok and ok2, msg + " " + msg2
        flash(request, msg, "ok" if ok else "err")
    return redirect("/pbx")


@app.post("/pbx/{sid}/sync")
async def pbx_sync(request: Request, sid: int):
    form = await request.form()
    db = SessionLocal()
    s = db.get(PbxServer, sid)
    if s is None:
        return redirect("/pbx")
    days = _int(form.get("days"))
    if days:
        s.cursor = now() - timedelta(days=min(days, 730)) + pbx.OVERLAP
        db.commit()
        log_action(request, "خواندن سوابق قبلی ایزابل", f"{s.name} {days} روز")
    before = s.imported or 0
    pbx.sync_all()
    db.expire_all()
    s = db.get(PbxServer, sid)
    if s.last_error:
        flash(request, f"خواندن ناموفق: {s.last_error}", "err")
    else:
        flash(request, f"{(s.imported or 0) - before} تماس جدید ثبت شد")
    return redirect("/pbx")


@app.post("/pbx/{sid}/delete")
def pbx_delete(request: Request, sid: int):
    db = SessionLocal()
    s = db.get(PbxServer, sid)
    if s:
        db.query(Call).filter(Call.pbx_id == sid).delete()
        db.query(ExtensionAssignment).filter(ExtensionAssignment.pbx_id == sid).delete()
        db.delete(s)
        db.commit()
        log_action(request, "حذف سرور ایزابل", s.name)
        flash(request, "سرور و سوابق تماس آن حذف شد")
    return redirect("/pbx")


def _add_assignment(request, db, user_id, ext, pbx_id, start, end, close_current=False):
    """Returns an error message or None."""
    ext = str(ext or "").strip()
    if not ext.isdigit() or len(ext) > 7:
        return "شماره داخلی نادرست است"
    if db.get(User, user_id) is None:
        return "کاربر پیدا نشد"
    if start and end and end < start:
        return "تاریخ پایان قبل از شروع است"
    touched = {ext}
    if close_current:
        for a in db.query(ExtensionAssignment).filter(ExtensionAssignment.user_id == user_id,
                                                      ExtensionAssignment.end.is_(None)):
            if a.extension != ext and (a.start is None or start is None or a.start < start):
                a.end = (start or now().date()) - timedelta(days=1)
                touched.add(a.extension)
    other = pbx.overlapping(db, user_id, pbx_id, ext, start, end)
    if other is not None:
        holder = db.get(User, other.user_id)
        name = (holder.full_name or holder.username) if holder else "?"
        if other.end is None and start and (other.start is None or other.start < start):
            other.end = start - timedelta(days=1)
            flash(request, f"داخلی {ext} از {name} گرفته شد (تخصیص قبلی تا {jalali.to_jalali_str(other.end)} بسته شد)")
        else:
            db.rollback()
            return f"داخلی {ext} در این بازه به {name} تخصیص داده شده است"
    db.add(ExtensionAssignment(user_id=user_id, pbx_id=pbx_id, extension=ext, start=start, end=end))
    db.commit()
    for e in touched:
        pbx.relink(db, e)
    log_action(request, "تخصیص داخلی", f"{ext} -> {user_id}")
    return None


@app.post("/pbx/assign")
async def pbx_assign(request: Request):
    form = await request.form()
    db = SessionLocal()
    err = _add_assignment(request, db, _int(form.get("user_id")), form.get("extension"), _int(form.get("pbx_id")),
                          _date(form.get("start", "")), _date(form.get("end", "")))
    if err:
        flash(request, err, "err")
    elif not request.session.get("flash"):
        flash(request, "داخلی تخصیص داده شد و تماس‌های آن به نام این شخص ثبت شد")
    return redirect(_local(form.get("back"), "/pbx"))


@app.post("/pbx/assign/{aid}/delete")
async def pbx_assign_delete(request: Request, aid: int):
    form = await request.form()
    db = SessionLocal()
    a = db.get(ExtensionAssignment, aid)
    if a:
        ext = a.extension
        db.delete(a)
        db.commit()
        pbx.relink(db, ext)
        log_action(request, "حذف تخصیص داخلی", ext)
        flash(request, "تخصیص حذف شد")
    return redirect(_local(form.get("back"), "/pbx"))


@app.post("/users/{uid}/ext")
async def user_ext_add(request: Request, uid: int):
    form = await request.form()
    db = SessionLocal()
    err = _add_assignment(request, db, uid, form.get("extension"), _int(form.get("pbx_id")),
                          _date(form.get("start", "")), _date(form.get("end", "")), _bool(form, "close_current"))
    if err:
        flash(request, err, "err")
    elif not request.session.get("flash"):
        flash(request, "داخلی ثبت شد")
    return redirect(f"/users/{uid}/edit#ext")


@app.post("/users/{uid}/ext/{aid}/end")
async def user_ext_end(request: Request, uid: int, aid: int):
    form = await request.form()
    db = SessionLocal()
    a = db.get(ExtensionAssignment, aid)
    if a and a.user_id == uid:
        end = _date(form.get("end", "")) or now().date()
        if a.start and end < a.start:
            flash(request, "تاریخ پایان قبل از شروع است", "err")
        else:
            a.end = end
            db.commit()
            pbx.relink(db, a.extension)
            log_action(request, "پایان تخصیص داخلی", f"{a.extension} {uid}")
    return redirect(f"/users/{uid}/edit#ext")


@app.post("/users/{uid}/ext/{aid}/delete")
def user_ext_delete(request: Request, uid: int, aid: int):
    db = SessionLocal()
    a = db.get(ExtensionAssignment, aid)
    if a and a.user_id == uid:
        ext = a.extension
        db.delete(a)
        db.commit()
        pbx.relink(db, ext)
        log_action(request, "حذف تخصیص داخلی", f"{ext} {uid}")
    return redirect(f"/users/{uid}/edit#ext")


# ------------------------------------------------------------------ devices & logs
def _parse_dt(text):
    """'1404/07/23 14:30' (Jalali) or '2025-10-15 14:30' -> datetime, None when empty / invalid."""
    text = (text or "").strip().translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789"))
    if not text:
        return None
    parts = text.split()
    try:
        d = jalali.parse_date(parts[0])
        hh, mm = (int(x) for x in (parts[1].split(":") + ["0"])[:2]) if len(parts) > 1 else (0, 0)
        return datetime(d.year, d.month, d.day, hh, mm)
    except (ValueError, IndexError):
        return None


def _nas_names(db):
    return {n.id: n.name for n in db.query(Nas).all()}


def _device_state(d, ts, stale):
    if d.last_seen is None:
        return "stale"
    if ts - d.last_seen <= timedelta(seconds=config.ROUTER_POLL_EVERY * 3 + 60):
        return "online"
    return "active" if ts - d.last_seen <= stale else "stale"


@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request, q: str = "", status: str = "", nas: str = "", at: str = "", page: int = 1,
                 type: str = ""):
    db = SessionLocal()
    ts = now()
    stale = timedelta(days=devices.stale_days(db))
    online_after = ts - timedelta(seconds=config.ROUTER_POLL_EVERY * 3 + 60)
    at_dt = _parse_dt(at)
    qry = db.query(Device)
    hist = []
    q = q.strip()
    if q or at_dt:
        hq = db.query(DeviceHistory)
        if q:
            hq = hq.filter(DeviceHistory.value.ilike(f"%{q}%") | DeviceHistory.mac.ilike(f"%{q}%"))
        if at_dt:
            hq = hq.filter(DeviceHistory.first_seen <= at_dt + timedelta(minutes=1),
                           DeviceHistory.last_seen >= at_dt - devices.HISTORY_GAP)
        hist = hq.order_by(DeviceHistory.last_seen.desc()).limit(500).all()
    if q:
        macs = {h.mac for h in hist}
        cond = (Device.mac.ilike(f"%{q}%") | Device.hostname.ilike(f"%{q}%") | Device.vendor.ilike(f"%{q}%")
                | Device.last_ip.ilike(f"%{q}%") | Device.last_user.ilike(f"%{q}%") | Device.label.ilike(f"%{q}%")
                | Device.logon_user.ilike(f"%{q}%"))
        qry = qry.filter(cond | Device.mac.in_(macs)) if macs else qry.filter(cond)
    elif at_dt:
        qry = qry.filter(Device.mac.in_({h.mac for h in hist}))
    if status == "online":
        qry = qry.filter(Device.last_seen >= online_after)
    elif status == "active":
        qry = qry.filter(Device.last_seen >= ts - stale)
    elif status == "stale":
        qry = qry.filter((Device.last_seen < ts - stale) | Device.last_seen.is_(None))
    if nas.isdigit():
        qry = qry.filter(Device.last_nas_id == int(nas))
    if type == "computers":
        qry = qry.filter(Device.device_type.in_(devices.COMPUTERS))
    elif type:
        qry = qry.filter(Device.device_type == type)
    total = qry.count()
    per = 500
    page = max(1, page)
    items = qry.order_by(Device.last_seen.desc()).offset((page - 1) * per).limit(per).all()
    counts = {"all": db.query(Device).count(),
              "online": db.query(Device).filter(Device.last_seen >= online_after).count(),
              "stale": db.query(Device).filter((Device.last_seen < ts - stale) | Device.last_seen.is_(None)).count()}
    return render(request, "devices.html", items=items, hist=hist, q=q, status=status, nas=nas, at=at,
                  at_dt=at_dt, page=page, pages=max(1, (total + per - 1) // per), total=total, counts=counts,
                  nas_names=_nas_names(db), routers=db.query(Nas).order_by(Nas.name).all(),
                  state={d.id: _device_state(d, ts, stale) for d in items}, now=ts, gap=devices.HISTORY_GAP,
                  stale_days=devices.stale_days(db), qs=str(request.query_params), type=type,
                  lg=logons.settings(db), lg_hint=logons.hint(get_setting(db, "logon_error")),
                  lm=logons.message_settings(db), logon_quota_modes=logons.QUOTA_MODES, warn_pct=policy.warn_pct(db),
                  night_time="%02d:%02d" % nightlist.check_time(db))


# ------------------------------------------------------------------ nightly list of devices that are on
def _night_ctx(request):
    db = SessionLocal()
    qp = request.query_params
    days = [d for (d,) in db.query(NightList.day).distinct().order_by(NightList.day.desc()).limit(60)]
    day = None
    if qp.get("day"):
        try:
            day = jalali.parse_date(qp.get("day").strip().translate(FA_TO_EN))
        except ValueError:
            day = None
    day = day or (days[0] if days else now().date())
    kind = qp.get("type", "computers")
    rows = db.query(NightList).filter(NightList.day == day).all()
    counts = {}
    for r in rows:
        counts[r.device_type or "unknown"] = counts.get(r.device_type or "unknown", 0) + 1
    if kind == "computers":
        rows = [r for r in rows if r.device_type in devices.COMPUTERS]
    elif kind:
        rows = [r for r in rows if r.device_type == kind]
    rows.sort(key=lambda r: (devices.TYPE_FA.get(r.device_type, r.device_type),
                             (r.user or r.hotspot_user or "~").lower(), r.ip))
    names = {u.username.lower(): (u.id, u.full_name or "") for u in db.query(User.id, User.username, User.full_name)
             .filter(func.lower(User.username).in_({(x or "").lower() for r in rows for x in (r.user, r.hotspot_user)
                                                    if x}))} if rows else {}
    return db, {"rows": rows, "day": day, "day_j": jalali.to_jalali_str(day), "days": days, "type": kind,
                "counts": counts, "names": names, "nas_names": _nas_names(db),
                "taken_at": rows[0].taken_at if rows else None, "night_time": "%02d:%02d" % nightlist.check_time(db)}


@app.get("/devices/night", response_class=HTMLResponse)
def night_page(request: Request):
    db, ctx = _night_ctx(request)
    return render(request, "night.html", **ctx)


@app.get("/devices/night.xlsx")
def night_export(request: Request):
    db, c = _night_ctx(request)
    src = {"dc": "کنترلر دامنه", "script": "اسکریپت ورود"}
    name = lambda u: c["names"].get((u or "").lower(), (0, ""))[1]     # noqa: E731
    jt = lambda t: jalali.to_jalali_str(t, True) if t else ""            # noqa: E731
    rows = []
    for r in c["rows"]:
        win = r.user if r.user_source in src else ""                    # lists before 1.10.1 mixed both kinds
        hs = r.hotspot_user or ("" if win else r.user)
        rows.append((devices.TYPE_FA.get(r.device_type, r.device_type), r.label or r.hostname, r.hostname, r.mac,
                     r.ip, c["nas_names"].get(r.nas_id, ""), win, name(win), jt(r.user_at) if win else "",
                     src.get(r.user_source, ""), hs, name(hs), "بله" if r.hotspot_active else ("خیر" if hs else ""),
                     jt(r.hotspot_at), r.vendor))
    data = xlsx.simple_xlsx("سیستم‌های روشن", ["نوع", "نام", "نام میزبان", "MAC", "IP", "روتر", "کاربر ویندوز (AD)",
                                              "نام", "زمان ورود ویندوز", "منبع", "کاربر هات‌اسپات / VPN", "نام",
                                              "ساعت ۲۱ وصل بود", "آخرین مشاهده هات‌اسپات", "سازنده"], rows,
                            f"سیستم‌های روشن در {c['day_j']} ساعت {c['night_time']}",
                            {2: 22, 4: 19, 7: 18, 8: 20, 9: 18, 11: 18, 12: 20, 14: 18, 15: 26})
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="devices-on-{c["day"].isoformat()}.xlsx"'})


@app.post("/devices/night/take")
async def night_take(request: Request):
    db = SessionLocal()
    n = nightlist.take(db)
    log_action(request, "ثبت فهرست سیستم‌های روشن", str(n))
    flash(request, f"فهرست امروز با {n} دستگاه روشن ثبت شد (جایگزین فهرست قبلی امروز)")
    return redirect("/devices/night")


@app.post("/devices/logon-settings")
async def logon_settings(request: Request):
    form = await request.form()
    db = SessionLocal()
    t = str(form.get("night_list_time", "21:00")).strip().translate(FA_TO_EN)
    try:
        hh, mm = (int(x) for x in t.split(":")[:2])
        assert 0 <= hh < 24 and 0 <= mm < 60
    except (ValueError, AssertionError):
        flash(request, "ساعت فهرست شبانه نادرست است (مثلاً 21:00)", "err")
        return redirect("/devices#logon")
    set_setting(db, "night_list_time", f"{hh:02d}:{mm:02d}")
    set_setting(db, "logon_dc_enabled", "1" if form.get("logon_dc_enabled") else "0")
    set_setting(db, "logon_dcs", str(form.get("logon_dcs", "")).strip())
    if "logon_msg_form" in form:
        set_setting(db, "logon_msg_enabled", "1" if form.get("logon_msg_enabled") else "0")
        set_setting(db, "logon_msg_title", str(form.get("logon_msg_title", "")).strip()[:120])
        set_setting(db, "logon_message", str(form.get("logon_message", "")).strip()[:2000])
        mode = str(form.get("logon_msg_quota", "warn"))
        set_setting(db, "logon_msg_quota", mode if mode in logons.QUOTA_MODES else "warn")
        try:
            set_setting(db, "quota_warn_pct", str(max(1, min(100, int(str(form.get("quota_warn_pct", "80"))
                                                                     .translate(FA_TO_EN))))))
        except ValueError:
            pass
    if form.get("new_key"):
        set_setting(db, "logon_script_key", secrets.token_hex(12))
    elif form.get("no_key"):
        set_setting(db, "logon_script_key", "")
    db.commit()
    log_action(request, "تنظیم ورود کاربران و فهرست شبانه", f"{hh:02d}:{mm:02d}")
    msg = "ذخیره شد"
    if form.get("test") and form.get("logon_dc_enabled"):
        c = logons.settings(db)
        for dc in c["dcs"]:
            try:
                n, users = await run_in_threadpool(logons.test_dc, c, dc)
                msg += f" — {dc}: {n} ورود از {users} کاربر در یک ساعت گذشته"
            except Exception as e:  # noqa: BLE001
                flash(request, f"{dc}: {e} {logons.hint(str(e))}", "err")
                return redirect("/devices#logon")
    flash(request, msg)
    return redirect("/devices#logon")


@app.api_route("/logon", methods=["GET", "POST"])
async def logon_report(request: Request):
    """Called by the Windows logon script on each computer: ?u=%USERNAME%&c=%COMPUTERNAME%&k=key"""
    q = dict(request.query_params)
    if request.method == "POST":
        q.update({k: str(v) for k, v in (await request.form()).items()})
    db = SessionLocal()
    key = get_setting(db, "logon_script_key")
    if not key or not secrets.compare_digest(str(q.get("k", "")), key):
        return Response("forbidden", status_code=403, media_type="text/plain")
    d = logons.record(db, q.get("u", ""), now(), "script", ip=request.client.host if request.client else "",
                      computer=q.get("c", ""))
    db.commit()
    if q.get("m") == "1":           # logon popup: first line = title, rest = text; empty = nothing to show
        m = logons.message(db, q.get("u", ""))
        return Response(f"{m[0]}\n{m[1]}" if m else "", media_type="text/plain; charset=utf-8")
    return Response("ok" if d else "unknown device", media_type="text/plain")


@app.get("/devices/{mac}", response_class=HTMLResponse)
def device_detail(request: Request, mac: str):
    db = SessionLocal()
    m = devices.normalize_mac(mac)
    d = db.query(Device).filter(Device.mac == m).first() if m else None
    if d is None:
        flash(request, "دستگاه پیدا نشد", "err")
        return redirect("/devices")
    ts = now()
    stale = timedelta(days=devices.stale_days(db))
    rows = db.query(DeviceHistory).filter(DeviceHistory.mac == m).order_by(DeviceHistory.last_seen.desc()).all()
    users = {u.username.lower(): u.id for u in db.query(User.username, User.id).filter(
        User.username.in_({r.value for r in rows if r.kind == "user"}))} if rows else {}
    sessions = db.query(AcctSession).filter(AcctSession.mac == m).order_by(AcctSession.start_time.desc()).limit(200).all()
    summary = {}
    for r in rows:
        e = summary.setdefault((r.kind, r.value), {"kind": r.kind, "value": r.value, "first": r.first_seen,
                                                   "last": r.last_seen, "secs": 0, "count": 0, "nas": set()})
        e["first"] = min(e["first"], r.first_seen)
        e["last"] = max(e["last"], r.last_seen)
        e["secs"] += int((r.last_seen - r.first_seen).total_seconds())
        e["count"] += 1
        if r.nas_id:
            e["nas"].add(r.nas_id)
    summary = sorted(summary.values(), key=lambda e: e["last"], reverse=True)
    return render(request, "device_detail.html", d=d, ips=[r for r in rows if r.kind == "ip"],
                  users_hist=[r for r in rows if r.kind == "user"], sessions=sessions, summary=summary,
                  user_ids=users, nas_names=_nas_names(db), state=_device_state(d, ts, stale), now=ts,
                  gap=devices.HISTORY_GAP, stale_days=devices.stale_days(db))


@app.post("/devices/settings")
async def device_settings(request: Request):
    form = await request.form()
    db = SessionLocal()
    v = str(form.get("device_stale_days", "")).strip().translate(FA_TO_EN)
    if not v.isdigit() or int(v) < 1:
        flash(request, "تعداد روز نادرست است", "err")
        return redirect("/devices")
    set_setting(db, "device_stale_days", v)
    db.commit()
    log_action(request, "تغییر مدت راکد شدن دستگاه", f"{v} روز")
    flash(request, f"دستگاهی که {v} روز دیده نشود «راکد» نمایش داده می‌شود (سابقه آن پاک نمی‌شود)")
    return redirect("/devices")


@app.post("/devices/{did}/type")
async def device_set_type(request: Request, did: int):
    form = await request.form()
    db = SessionLocal()
    d = db.get(Device, did)
    if d:
        if form.get("device_type") in devices.TYPE_FA:
            d.device_type = form.get("device_type")
            d.detected_by = "manual"
        if "label" in form:
            d.label = str(form.get("label", "")).strip()[:150]
        db.commit()
        log_action(request, "اصلاح نوع دستگاه", f"{d.mac} -> {d.device_type} {d.label or ''}")
    return redirect(_local(form.get("back"), "/devices"))


@app.post("/devices/bulk-type")
async def device_bulk_type(request: Request):
    form = await request.form()
    db = SessionLocal()
    t = form.get("device_type")
    ids = [int(x) for x in form.getlist("ids") if str(x).isdigit()]
    if t not in devices.TYPE_FA or not ids:
        flash(request, "دستگاه و نوع را انتخاب کنید", "err")
    else:
        n = db.query(Device).filter(Device.id.in_(ids)).update({"device_type": t, "detected_by": "manual"},
                                                                synchronize_session=False)
        db.commit()
        log_action(request, "تعیین نوع گروهی دستگاه‌ها", f"{n} -> {t}")
        flash(request, f"نوع {n} دستگاه «{devices.TYPE_FA[t]}» شد")
    return redirect(_local(form.get("back"), "/devices"))


@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, q: str = "", result: str = ""):
    db = SessionLocal()
    qry = db.query(AuthLog)
    if q:
        qry = qry.filter(AuthLog.username.ilike(f"%{q}%"))
    if result:
        qry = qry.filter(AuthLog.result == result)
    return render(request, "logs.html", items=qry.order_by(AuthLog.ts.desc()).limit(500).all(), q=q, result=result)


# ------------------------------------------------------------------ MikroTik local accounts (hotspot users / ppp secrets)
MT_LABELS = {
    "name": "نام", "password": "رمز", "profile": "پروفایل", "server": "سرور هات‌اسپات",
    "limit-uptime": "سقف زمان اتصال (مثل 10h یا 30d)", "limit-bytes-total": "سقف حجم کل (مثل 5G یا 500M)",
    "limit-bytes-in": "سقف آپلود (مثل 1G)", "limit-bytes-out": "سقف دانلود (مثل 4G)", "mac-address": "MAC مجاز",
    "address": "IP ثابت", "email": "ایمیل", "comment": "توضیح / نام کامل", "disabled": "غیرفعال",
    "rate-limit": "سرعت (آپلود/دانلود مثل 2M/4M)", "shared-users": "تعداد اتصال همزمان",
    "session-timeout": "حداکثر مدت هر اتصال (مثل 4h)", "idle-timeout": "قطع پس از بیکاری (مثل 10m یا none)",
    "keepalive-timeout": "Keepalive timeout", "address-pool": "Pool آدرس", "address-list": "Address-List",
    "mac-cookie-timeout": "اعتبار MAC Cookie (مثل 3d)", "transparent-proxy": "Transparent proxy",
    "service": "سرویس", "local-address": "آدرس سمت روتر", "remote-address": "آدرس کاربر یا نام Pool",
    "caller-id": "Caller-ID مجاز", "routes": "Routes", "dns-server": "DNS", "only-one": "فقط یک اتصال همزمان",
    "use-encryption": "رمزنگاری", "change-tcp-mss": "تغییر TCP MSS",
}
MT_TITLES = {"hs_user": "کاربران هات‌اسپات", "hs_profile": "پروفایل‌های هات‌اسپات", "ppp_secret": "اکانت‌های VPN (PPP Secret)",
             "ppp_profile": "پروفایل‌های VPN"}
SIZE_FIELDS = {"limit-bytes-total", "limit-bytes-in", "limit-bytes-out"}
BOOL_FIELDS = {"disabled", "transparent-proxy"}
ENUM_FIELDS = {"service": ["any", "pptp", "l2tp", "sstp", "ovpn", "pppoe", "async"],
               "only-one": ["default", "yes", "no"], "use-encryption": ["default", "yes", "no", "required"],
               "change-tcp-mss": ["default", "yes", "no"]}


def parse_size(v):
    """'5G' / '500M' / '1.5GB' / '1048576' -> bytes as string ('' stays '')."""
    v = str(v or "").strip().upper().replace("B", "").replace(" ", "")
    if not v:
        return ""
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}.get(v[-1], 1)
    num = v[:-1] if v[-1] in "KMGT" else v
    return str(int(float(num) * mult))


def rosval(v):
    return "yes" if v is True else "no" if v is False else ("" if v is None else str(v))


def sizestr(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return v or ""
    if n <= 0:
        return ""
    for unit, m in (("T", 1024 ** 4), ("G", 1024 ** 3), ("M", 1024 ** 2), ("K", 1024)):
        if n % m == 0:
            return f"{n // m}{unit}"
    return str(n)


templates.env.filters.update({"rosval": rosval, "sizestr": sizestr})


def _mt_nas(db, nas_id):
    items = db.query(Nas).filter(Nas.api_user != "").order_by(Nas.name).all()
    nas = next((n for n in items if n.id == nas_id), items[0] if items else None)
    return items, nas


def _mt_fields(kind, form):
    fields = {}
    for f in routeros.LOCAL_KINDS[kind][1]:
        if f in BOOL_FIELDS:
            fields[f] = _bool(form, "f_" + f)
        elif f in SIZE_FIELDS:
            fields[f] = parse_size(form.get("f_" + f, ""))
        elif ("f_" + f) in form:
            fields[f] = str(form.get("f_" + f, ""))
    return fields


def _link_app_user(db, name, comment="", office_id=None, department_id=None):
    """Keep a matching app user (source=router) so reports, offices and units cover router-local accounts."""
    u = db.query(User).filter(func.lower(User.username) == str(name).lower()).first()
    if u is None:
        u = User(username=name, source="router", full_name=comment or "", notes="اکانت محلی روتر")
        db.add(u)
    if u.source == "router":
        if comment and not u.full_name:
            u.full_name = comment
        if office_id:
            u.office_id = office_id
        if department_id:
            u.department_id = department_id
    return u


@app.get("/mt-local", response_class=HTMLResponse)
def mt_local_page(request: Request, nas_id: int = 0, tab: str = "hs_user", q: str = "", edit: str = ""):
    db = SessionLocal()
    routers, nas = _mt_nas(db, nas_id)
    tab = tab if tab in routeros.LOCAL_KINDS else "hs_user"
    data, error = {}, ""
    if nas:
        try:
            data = routeros.local_overview(nas)
        except Exception as e:
            error = f"اتصال API به {nas.name} ناموفق بود: {e}"
    items = data.get(tab, [])
    if q:
        ql = q.lower()
        items = [i for i in items if ql in str(i.get("name", "")).lower() or ql in str(i.get("comment", "")).lower()]
    online = {a.get("user") for a in data.get("hs_active", [])} | {a.get("name") for a in data.get("ppp_active", [])}
    current = next((i for i in data.get(tab, []) if i.get(".id") == edit), None) if edit else None
    return render(request, "mt_local.html", routers=routers, nas=nas, tab=tab, data=data, items=items, q=q,
                  error=error, online=online, current=current, edit=edit, kinds=routeros.LOCAL_KINDS,
                  titles=MT_TITLES, labels=MT_LABELS, size_fields=SIZE_FIELDS, bool_fields=BOOL_FIELDS,
                  enum_fields=ENUM_FIELDS, offices=db.query(Office).order_by(Office.name).all(),
                  departments=db.query(Department).order_by(Department.name).all())


def _mt_back(nas_id, kind, q=""):
    return redirect(f"/mt-local?nas_id={nas_id}&tab={kind}" + (f"&q={q}" if q else ""))


@app.post("/mt-local/save")
async def mt_local_save(request: Request):
    form = await request.form()
    db = SessionLocal()
    nas = db.get(Nas, _int(form.get("nas_id")) or 0)
    kind = form.get("kind", "")
    if nas is None or kind not in routeros.LOCAL_KINDS:
        return redirect("/mt-local")
    fields = _mt_fields(kind, form)
    item_id = str(form.get("item_id", ""))
    if not fields.get("name"):
        flash(request, "نام الزامی است", "err")
        return _mt_back(nas.id, kind)
    try:
        routeros.local_save(nas, kind, fields, item_id)
        if kind in ("hs_user", "ppp_secret"):
            _link_app_user(db, fields["name"], fields.get("comment", ""), _int(form.get("office_id")),
                           _int(form.get("department_id")))
            db.commit()
        log_action(request, ("ویرایش" if item_id else "ایجاد") + " " + MT_TITLES[kind] + " روی روتر",
                   f"{nas.name}: {fields['name']}")
        flash(request, f"«{fields['name']}» روی روتر {nas.name} ذخیره شد")
    except Exception as e:
        flash(request, f"خطای روتر: {e}", "err")
        return redirect(f"/mt-local?nas_id={nas.id}&tab={kind}" + (f"&edit={item_id}" if item_id else ""))
    return _mt_back(nas.id, kind)


@app.post("/mt-local/action")
async def mt_local_action(request: Request):
    form = await request.form()
    db = SessionLocal()
    nas = db.get(Nas, _int(form.get("nas_id")) or 0)
    kind, action = form.get("kind", ""), form.get("action", "")
    ids = [str(i) for i in form.getlist("ids") if i]
    names = [str(n) for n in form.getlist("names")]
    if nas is None or kind not in routeros.LOCAL_KINDS:
        return redirect("/mt-local")
    if not ids:
        flash(request, "موردی انتخاب نشده", "err")
        return _mt_back(nas.id, kind)
    try:
        if action == "delete":
            n = routeros.local_remove(nas, kind, ids)
            label = "حذف"
        elif action in ("disable", "enable"):
            n = routeros.local_set_disabled(nas, kind, ids, action == "disable")
            label = "غیرفعال" if action == "disable" else "فعال"
        elif action == "reset" and kind == "hs_user":
            n = routeros.local_reset_counters(nas, ids)
            label = "صفر کردن شمارنده"
        elif action == "link" and kind in ("hs_user", "ppp_secret"):
            data = routeros.local_overview(nas)[kind]
            for it in data:
                if it.get(".id") in ids:
                    _link_app_user(db, str(it.get("name")), str(it.get("comment", "") or ""),
                                   _int(form.get("office_id")), _int(form.get("department_id")))
            db.commit()
            n, label = len(ids), "ثبت در برنامه (برای گزارش و دفتر/واحد)"
        else:
            return _mt_back(nas.id, kind)
        log_action(request, f"{label} {MT_TITLES[kind]} روی روتر", f"{nas.name}: {n} مورد " + "، ".join(names)[:300])
        flash(request, f"{label}: {n} مورد روی {nas.name}")
    except Exception as e:
        flash(request, f"خطای روتر: {e}", "err")
    return _mt_back(nas.id, kind)


@app.post("/mt-local/kick")
async def mt_local_kick(request: Request):
    form = await request.form()
    db = SessionLocal()
    nas = db.get(Nas, _int(form.get("nas_id")) or 0)
    service, name = form.get("service", "hotspot"), str(form.get("name", ""))
    try:
        data = routeros.local_overview(nas)
        act = data["hs_active"] if service == "hotspot" else data["ppp_active"]
        ids = [a[".id"] for a in act if a.get("user", a.get("name")) == name]
        routeros.kick_active(nas, service, ids)
        log_action(request, "قطع اتصال اکانت محلی روتر", f"{nas.name}: {name}")
        flash(request, f"اتصال {name} قطع شد")
    except Exception as e:
        flash(request, f"خطای روتر: {e}", "err")
    return _mt_back(nas.id if nas else 0, "hs_user" if service == "hotspot" else "ppp_secret")


def _gen_password(length, digits_only):
    import secrets
    alphabet = "0123456789" if digits_only else "abcdefghjkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(max(4, length)))


@app.post("/mt-local/bulk", response_class=HTMLResponse)
async def mt_local_bulk(request: Request):
    """Bulk create hotspot users / VPN secrets: from lines or generated (voucher style)."""
    form = await request.form()
    db = SessionLocal()
    nas = db.get(Nas, _int(form.get("nas_id")) or 0)
    kind = form.get("kind", "hs_user")
    if nas is None or kind not in ("hs_user", "ppp_secret"):
        return redirect("/mt-local")
    common = {k: v for k, v in _mt_fields(kind, form).items() if k not in ("name", "password", "comment")}
    items = []
    if form.get("mode") == "generate":
        prefix = str(form.get("prefix", "u")).strip()
        start = _int(form.get("start"), 1)
        count = min(_int(form.get("count"), 10), 2000)
        width = len(str(start + count - 1))
        for i in range(start, start + count):
            items.append({"name": f"{prefix}{str(i).zfill(width)}",
                          "password": _gen_password(_int(form.get("pass_len"), 6), _bool(form, "digits")),
                          "comment": str(form.get("bulk_comment", ""))})
    else:
        for line in str(form.get("lines", "")).splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0]:
                items.append({"name": parts[0], "password": parts[1], "comment": parts[2] if len(parts) > 2 else ""})
    for it in items:
        it.update(common)
    try:
        added, errors = routeros.local_bulk_add(nas, kind, items)
    except Exception as e:
        flash(request, f"خطای روتر: {e}", "err")
        return _mt_back(nas.id, kind)
    ok_items = [it for it in items if not any(err.startswith(f"{it['name']}:") for err in errors)]
    for it in ok_items:
        _link_app_user(db, it["name"], it.get("comment", ""), _int(form.get("office_id")),
                       _int(form.get("department_id")))
    db.commit()
    log_action(request, f"ایجاد گروهی {MT_TITLES[kind]} روی روتر", f"{nas.name}: {added} مورد")
    return render(request, "mt_bulk_result.html", nas=nas, kind=kind, items=ok_items, errors=errors, added=added,
                  titles=MT_TITLES, profile=common.get("profile", ""), limit_uptime=common.get("limit-uptime", ""),
                  limit_total=common.get("limit-bytes-total", ""))


# ------------------------------------------------------------------ hotspot folder (remote update)
def _public_url(request, db):
    return get_setting(db, "public_url") or str(request.base_url).rstrip("/")


@app.get("/hotspot", response_class=HTMLResponse)
def hotspot_page(request: Request):
    db = SessionLocal()
    routers = db.query(Nas).order_by(Nas.name).all()
    pkgs = db.query(HotspotPackage).order_by(HotspotPackage.created_at.desc()).all()
    logs = db.query(DeployLog).order_by(DeployLog.ts.desc()).limit(50).all()
    return render(request, "hotspot.html", routers=routers, pkgs=pkgs, logs=logs,
                  pkg_names={p.id: p.name for p in pkgs}, nas_names={n.id: n.name for n in routers},
                  public_url=_public_url(request, db), detected=request.session.pop("hs_detected", {}),
                  beacon=hotspot.beacon_tag(_public_url(request, db)))


@app.post("/hotspot/upload")
async def hotspot_upload(request: Request):
    form = await request.form()
    db = SessionLocal()
    up = form.get("file")
    if up is None or not getattr(up, "filename", ""):
        flash(request, "فایل ZIP فولدر hotspot را انتخاب کنید", "err")
        return redirect("/hotspot")
    data = await up.read()
    url = str(form.get("public_url", "")).strip() or _public_url(request, db)
    try:
        files, warnings = hotspot.read_upload(data, _bool(form, "inject"), url)
    except ValueError as e:
        flash(request, str(e), "err")
        return redirect("/hotspot")
    if form.get("public_url"):
        set_setting(db, "public_url", url)
    name = str(form.get("name", "")).strip() or os.path.splitext(up.filename)[0]
    pkg = hotspot.save_package(db, name, files, note=str(form.get("note", "")), user=request.state.me.username)
    log_action(request, "بارگذاری بسته hotspot", f"{pkg.name} ({pkg.files} فایل)")
    flash(request, f"بسته «{pkg.name}» با {pkg.files} فایل ذخیره شد" + ("؛ " + "؛ ".join(warnings) if warnings else ""),
          "err" if warnings else "ok")
    return redirect("/hotspot")


@app.post("/hotspot/deploy")
async def hotspot_deploy(request: Request):
    form = await request.form()
    db = SessionLocal()
    pkg = db.get(HotspotPackage, _int(form.get("package_id")) or 0)
    nas_ids = [_int(x) for x in form.getlist("nas_ids") if _int(x)]
    if pkg is None or not nas_ids:
        flash(request, "بسته و حداقل یک روتر را انتخاب کنید", "err")
        return redirect("/hotspot")
    results = []
    for nid in nas_ids:
        nas = db.get(Nas, nid)
        if nas is None:
            continue
        rec = hotspot.deploy(db, pkg, nas, request.state.me.username, make_backup=_bool(form, "backup"),
                             mirror=_bool(form, "mirror"), directory=str(form.get("directory", "")).strip() or None)
        results.append(f"{nas.name}: {'✔' if rec.ok else '✘'} {rec.message}")
        log_action(request, "نصب بسته hotspot روی روتر", f"{pkg.name} -> {nas.name}: {'موفق' if rec.ok else rec.message}")
    ok = all("✔" in r for r in results)
    flash(request, " | ".join(results), "ok" if ok else "err")
    return redirect("/hotspot")


@app.post("/hotspot/backup")
async def hotspot_backup(request: Request):
    form = await request.form()
    db = SessionLocal()
    nas = db.get(Nas, _int(form.get("nas_id")) or 0)
    if nas is None:
        return redirect("/hotspot")
    try:
        pkg = hotspot.backup(db, nas, request.state.me.username, note="پشتیبان دستی")
        log_action(request, "پشتیبان‌گیری فولدر hotspot", f"{nas.name}: {pkg.files} فایل")
        flash(request, f"پشتیبان {nas.name} با {pkg.files} فایل گرفته شد (در فهرست بسته‌ها، قابل دانلود و بازگردانی)")
    except Exception as e:
        flash(request, f"پشتیبان‌گیری از {nas.name} ناموفق بود: {e}", "err")
    return redirect("/hotspot")


@app.post("/hotspot/detect")
async def hotspot_detect(request: Request):
    form = await request.form()
    db = SessionLocal()
    nas = db.get(Nas, _int(form.get("nas_id")) or 0)
    try:
        dirs = hotspot.detect_dirs(nas)
        request.session["hs_detected"] = {str(nas.id): "، ".join(dirs) or "پروفایل هات‌اسپاتی پیدا نشد"}
    except Exception as e:
        flash(request, f"خطای API: {e}", "err")
    return redirect("/hotspot")


@app.post("/hotspot/settings")
async def hotspot_settings(request: Request):
    form = await request.form()
    db = SessionLocal()
    for n in db.query(Nas).all():
        if f"proto_{n.id}" in form:
            n.file_proto = "sftp" if form.get(f"proto_{n.id}") == "sftp" else "ftp"
            n.file_port = _int(form.get(f"port_{n.id}"), 0)
            n.hotspot_dir = str(form.get(f"dir_{n.id}", "")).strip().strip("/")
    db.commit()
    log_action(request, "تنظیم انتقال فایل روترها")
    flash(request, "تنظیمات ذخیره شد")
    return redirect("/hotspot")


@app.get("/hotspot/{pid}/download")
def hotspot_download(request: Request, pid: int):
    db = SessionLocal()
    pkg = db.get(HotspotPackage, pid)
    if pkg is None:
        return redirect("/hotspot")
    with open(hotspot.package_path(pkg), "rb") as fh:
        data = fh.read()
    log_action(request, "دانلود بسته hotspot", pkg.name)
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="hotspot-{pkg.id}.zip"'})


@app.post("/hotspot/{pid}/delete")
def hotspot_delete(request: Request, pid: int):
    db = SessionLocal()
    pkg = db.get(HotspotPackage, pid)
    if pkg:
        hotspot.delete_package(db, pkg)
        log_action(request, "حذف بسته hotspot", pkg.name)
        flash(request, "بسته حذف شد")
    return redirect("/hotspot")


@app.get("/hotspot/{pid}/files", response_class=HTMLResponse)
def hotspot_files(request: Request, pid: int):
    db = SessionLocal()
    pkg = db.get(HotspotPackage, pid)
    files = sorted((p, len(d)) for p, d in hotspot.load_package(pkg).items()) if pkg else []
    return render(request, "hotspot_files.html", pkg=pkg, files=files, text_ext=hotspot.TEXT_EXT,
                  ext=lambda p: os.path.splitext(p)[1].lower())


@app.get("/hotspot/{pid}/edit", response_class=HTMLResponse)
def hotspot_edit(request: Request, pid: int, path: str = ""):
    db = SessionLocal()
    pkg = db.get(HotspotPackage, pid)
    files = hotspot.load_package(pkg) if pkg else {}
    if path and path not in files and not hotspot._safe(path):
        return redirect(f"/hotspot/{pid}/files")
    content = files.get(path, b"").decode("utf-8", errors="replace")
    return render(request, "hotspot_edit.html", pkg=pkg, path=path, content=content, new=path not in files)


@app.post("/hotspot/{pid}/edit")
async def hotspot_edit_save(request: Request, pid: int):
    form = await request.form()
    db = SessionLocal()
    pkg = db.get(HotspotPackage, pid)
    path = hotspot._safe(str(form.get("path", "")))
    if pkg is None or not path:
        flash(request, "مسیر فایل نامعتبر است", "err")
        return redirect(f"/hotspot/{pid}/files")
    hotspot.update_package_file(db, pkg, path, str(form.get("content", "")).replace("\r\n", "\n").encode("utf-8"))
    log_action(request, "ویرایش فایل بسته hotspot", f"{pkg.name}: {path}")
    flash(request, f"{path} ذخیره شد")
    return redirect(f"/hotspot/{pid}/files")


# ------------------------------------------------------------------ self-service page for internet users (/my)
MY_FAILS = {}            # username or IP -> [failures, first failure time]
MY_MAX_FAILS, MY_LOCK_SECONDS = 5, 600


def _my_locked(*keys):
    t = time.time()
    for k in keys:
        f = MY_FAILS.get(k)
        if f and t - f[1] > MY_LOCK_SECONDS:
            MY_FAILS.pop(k, None)
        elif f and f[0] >= MY_MAX_FAILS:
            return True
    return False


def _my_fail(*keys):
    for k in keys:
        f = MY_FAILS.setdefault(k, [0, time.time()])
        f[0] += 1


def _my_fp(u):
    """Session fingerprint: a local user's session ends when the password changes."""
    return "ldap" if u.source == "ldap" else hashlib.sha256((u.password_enc or "").encode()).hexdigest()[:16]


def _my_user(request, db):
    u = db.get(User, request.session.get("my_uid") or 0)
    if u is None or request.session.get("my_fp") != _my_fp(u):
        request.session.pop("my_uid", None)
        return None
    return u


def _my_check_password(db, u, password):
    if u is None or not password:
        return False
    if u.source == "ldap":
        return ldap_ad.authenticate(db, u.username, password)[0]
    if u.source == "local" and u.password_enc:
        return hmac.compare_digest(decrypt(u.password_enc).encode(), password.encode())
    return False


def _my_context(db, u):
    eff = policy.Effective(u)
    quota, used, remaining = policy.quota_state(db, u, eff)
    t = now()
    today = datetime.combine(t.date(), datetime.min.time())
    end = today + timedelta(days=1)
    rep = reports.build(db, reports.Filter(today - timedelta(days=29), end, ids=[u.id]), session_limit=20)
    month = reports.split_usage(db, policy.period_start("monthly"), end, [u.id])
    day = reports.split_usage(db, today, end, [u.id])
    stale = t - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
    online = db.query(AcctSession).filter(AcctSession.user_id == u.id, AcctSession.active.is_(True),
                                          AcctSession.last_update >= stale).all()
    try:
        in_hours = policy.hours_allowed(policy.parse_hours(eff.allowed_hours), t)
    except ValueError:
        in_hours = True
    status, kind = "فعال", "ok"
    if not u.enabled:
        status, kind = "غیرفعال", "err"
    elif u.expire_at and t.date() > u.expire_at:
        status, kind = "منقضی شده", "err"
    elif quota is not None and remaining <= 0:
        status, kind = "حجم تمام شده", "err"
    elif not in_hours:
        status, kind = "خارج از ساعات مجاز", "warn"
    period = {"daily": "روزانه", "weekly": "هفتگی", "monthly": "ماهانه"}.get(eff.quota_period, "کل")
    return {"u": u, "eff": eff, "quota": quota, "used": used, "remaining": remaining, "period": period,
            "pct": min(100, round(100 * used / quota)) if quota else 0, "rep": rep, "month": month, "day": day,
            "online": online, "status": status, "status_kind": kind, "warn": policy.quota_warning(db, u)}


WARN_JS = """(function(){var d=document.createElement('div');d.dir='rtl';
d.style.cssText='position:fixed;top:0;left:0;right:0;z-index:99999;padding:10px 14px;font:14px Tahoma,sans-serif;'+
'text-align:center;color:#fff;background:%s';d.textContent=%s;
var x=document.createElement('a');x.textContent=' \u00d7';x.href='#';x.style.cssText='color:#fff;margin-right:12px;text-decoration:none';
x.onclick=function(){d.remove();return false};d.appendChild(x);
(document.body||document.documentElement).appendChild(d);})();"""


@app.get("/hs/warn.js")
def hotspot_warn(request: Request, u: str = ""):
    """Quota banner for the hotspot status / alogin page: <script src=".../hs/warn.js?u=$(username)">.
    Only answered for a user with an active session from the asking IP (or via the router's NAT)."""
    js = Response("", media_type="application/javascript", headers={"Cache-Control": "no-store"})
    ip = request.client.host if request.client else ""
    db = SessionLocal()
    try:
        name = (u or "").strip()[:150]
        user = db.query(User).filter(User.username.ilike(name)).first() if name else None
        if user is None:
            return js
        stale = now() - timedelta(seconds=config.ACCT_INTERIM * 3 + 60)
        live = db.query(AcctSession).filter(AcctSession.user_id == user.id, AcctSession.active.is_(True),
                                            AcctSession.last_update >= stale).all()
        if not any(ip and ip in (x.framed_ip, x.nas_ip) for x in live):
            return js
        w = policy.quota_warning(db, user)
        if not w:
            return js
        color = "#c62828" if w["level"] == "err" else "#ef6c00"
        return Response(WARN_JS % (color, json.dumps(w["text"])), media_type="application/javascript",
                        headers={"Cache-Control": "no-store"})
    finally:
        db.close()
        SessionLocal.remove()


@app.get("/my", response_class=HTMLResponse)
def my_page(request: Request):
    db = SessionLocal()
    try:
        u = _my_user(request, db)
        if u is None:
            return render(request, "my_login.html")
        return render(request, "my.html", my_tour=tour.my_steps(u), my_tour_auto=(u.tour_seen or "") != tour.VERSION,
                      **_my_context(db, u))
    finally:
        db.close()
        SessionLocal.remove()


@app.post("/my/login")
async def my_login(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    ip = request.client.host if request.client else ""
    db = SessionLocal()
    try:
        err = _my_signin(request, db, username, password, ip)
        if err:
            flash(request, err, "err")
        return redirect("/my")
    finally:
        db.close()
        SessionLocal.remove()


def _my_signin(request, db, username, password, ip):
    """Internet user login to their own usage page. Returns an error text, '' on success."""
    key = "u:" + username.lower()
    if _my_locked(key, "ip:" + ip):
        return "تلاش ناموفق زیاد بود؛ ۱۰ دقیقه دیگر دوباره امتحان کنید."
    u = db.query(User).filter(func.lower(User.username) == username.lower()).first() if username else None
    if not _my_check_password(db, u, password):
        _my_fail(key, "ip:" + ip)
        auth.audit(db, username, "ورود ناموفق کاربر به صفحه مصرف من", "", ip)
        return "نام کاربری یا رمز عبور اشتباه است"
    MY_FAILS.pop(key, None)
    request.session["my_uid"], request.session["my_fp"] = u.id, _my_fp(u)
    return ""


@app.post("/my/tour/done")
def my_tour_done(request: Request):
    db = SessionLocal()
    try:
        u = _my_user(request, db)
        if u is not None:
            u.tour_seen = tour.VERSION
            db.commit()
        return Response(status_code=204)
    finally:
        db.close()
        SessionLocal.remove()


@app.get("/my/logout")
def my_logout(request: Request):
    request.session.pop("my_uid", None)
    request.session.pop("my_fp", None)
    return redirect("/my")


@app.post("/my/password")
async def my_password(request: Request):
    form = await request.form()
    db = SessionLocal()
    try:
        u = _my_user(request, db)
        if u is None:
            return redirect("/my")
        cur, new, again = (str(form.get(k, "")) for k in ("current", "new", "again"))
        ip = request.client.host if request.client else ""
        key = "u:" + u.username.lower()
        err = ""
        if _my_locked(key):
            err = "تلاش ناموفق زیاد بود؛ ۱۰ دقیقه دیگر دوباره امتحان کنید."
        elif new != again:
            err = "رمز جدید و تکرار آن یکی نیستند"
        elif len(new) < 6:
            err = "رمز جدید باید حداقل ۶ کاراکتر باشد"
        elif new.lower() == u.username.lower():
            err = "رمز نباید با نام کاربری یکی باشد"
        elif new == cur:
            err = "رمز جدید با رمز فعلی یکی است"
        elif u.source == "ldap":
            try:
                ldap_ad.change_password(db, u, cur, new)
            except Exception as e:
                err = str(e)
                if "رمز فعلی" in err:
                    _my_fail(key)
        elif not _my_check_password(db, u, cur):
            _my_fail(key)
            err = "رمز فعلی درست نیست"
        else:
            u.password_enc = encrypt(new)
            db.commit()
            request.session["my_fp"] = _my_fp(u)
        if err:
            flash(request, err, "err")
        else:
            auth.audit(db, u.username, "تغییر رمز توسط خود کاربر", "صفحه مصرف من", ip)
            flash(request, "رمز عبور عوض شد. از این به بعد برای اتصال به اینترنت رمز جدید را وارد کنید.")
        return redirect("/my#password")
    finally:
        db.close()
        SessionLocal.remove()


# ------------------------------------------------------------------ User-Agent beacon (hotspot login page)
GIF = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")


@app.get("/ua")
def ua_beacon(request: Request, mac: str = "", ua: str = ""):
    db = SessionLocal()
    try:
        if devices.normalize_mac(mac):
            devices.upsert(db, mac, user_agent=ua or request.headers.get("user-agent", ""))
            db.commit()
    finally:
        db.close()
    return Response(GIF, media_type="image/gif", headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ network monitor (admin / IT)
@app.get("/monitor", response_class=HTMLResponse)
def monitor_page(request: Request, days: int = 7):
    db = SessionLocal()
    days = max(1, min(90, days))
    routers = db.query(Nas).filter(Nas.api_user != "").order_by(Nas.name).all()
    names = {n.id: n.name for n in db.query(Nas).all()}
    events = db.query(NetEvent).filter(NetEvent.state != "up").order_by(NetEvent.ts.desc()).limit(100).all()
    return render(request, "monitor.html", rows=monitor.overview(db, routers, days), days=days, events=events,
                  names=names, slow=monitor.slow_ms(db), state_fa=monitor.STATE_FA, label=monitor._label, now=now())


@app.post("/monitor/settings")
async def monitor_settings(request: Request):
    form = await request.form()
    db = SessionLocal()
    v = _int(str(form.get("monitor_slow_ms", "")).translate(FA_TO_EN))
    if v and v > 0:
        set_setting(db, "monitor_slow_ms", str(v))
    db.commit()
    log_action(request, "تنظیم پایش شبکه", f"کند > {v} ms")
    flash(request, "ذخیره شد")
    return redirect("/monitor")


# ------------------------------------------------------------------ alerts
@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, kind: str = "", unread: int = 0):
    db = SessionLocal()
    q = db.query(Alert)
    if kind:
        q = q.filter(Alert.kind == kind)
    if unread:
        q = q.filter(Alert.read_at.is_(None))
    return render(request, "alerts.html", items=q.order_by(Alert.ts.desc()).limit(500).all(), kind=kind,
                  unread=unread)


@app.post("/alerts/read")
async def alerts_read(request: Request):
    form = await request.form()
    db = SessionLocal()
    q = db.query(Alert).filter(Alert.read_at.is_(None))
    ids = [_int(x) for x in form.getlist("id") if _int(x)]
    if ids:
        q = q.filter(Alert.id.in_(ids))
    n = 0
    for a in q.all():
        a.read_at, a.read_by = now(), request.state.me.username
        n += 1
    db.commit()
    flash(request, f"{n} هشدار خوانده شد")
    return redirect(_local(form.get("back"), "/alerts"))


# ------------------------------------------------------------------ failed logins and locks
@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request, hours: int = 24):
    db = SessionLocal()
    hours = max(1, min(24 * 30, hours))
    f = security.failures(db, hours)
    locks = security.active_locks(db).order_by(Lock.created_at.desc()).all()
    old = db.query(Lock).filter(Lock.released_at.isnot(None)).order_by(Lock.released_at.desc()).limit(50).all()
    locked_vals = {(lk.kind, lk.value.lower()) for lk in locks}
    return render(request, "security.html", f=f, hours=hours, locks=locks, old=old, rules=security.rules(db),
                  kinds=security.KINDS, locked_vals=locked_vals, source_kind=security.source_kind)


@app.post("/security/lock")
async def security_lock(request: Request):
    form = await request.form()
    db = SessionLocal()
    kind = str(form.get("kind", ""))
    value = str(form.get("value", "")).strip()
    if kind not in security.KINDS or not value:
        flash(request, "نوع و مقدار قفل را وارد کنید", "err")
        return redirect("/security")
    if kind == "mac" and not devices.normalize_mac(value):
        flash(request, "MAC نادرست است", "err")
        return redirect("/security")
    if kind == "ip":
        k, v = security.source_kind(value)
        if k != "ip":
            flash(request, "IP نادرست است", "err")
            return redirect("/security")
        value = v
    minutes = (_int(str(form.get("hours", "")).translate(FA_TO_EN), 0) or 0) * 60
    lk, new = security.lock(db, kind, value, str(form.get("reason", "")).strip() or "قفل دستی",
                            request.state.me.username, False, minutes)
    db.commit()
    log_action(request, "قفل", f"{security.KINDS[kind]} {lk.value}")
    flash(request, f"{security.KINDS[kind]} {lk.value} قفل شد" if new else "از قبل قفل بود")
    return redirect(_local(form.get("back"), "/security"))


@app.post("/security/{lock_id}/unlock")
async def security_unlock(request: Request, lock_id: int):
    form = await request.form()
    db = SessionLocal()
    lk = security.unlock(db, lock_id, request.state.me.username)
    db.commit()
    if lk:
        log_action(request, "باز کردن قفل", f"{security.KINDS.get(lk.kind, lk.kind)} {lk.value}")
        flash(request, f"قفل {lk.value} باز شد")
    return redirect(_local(form.get("back"), "/security"))


@app.post("/security/rules")
async def security_rules(request: Request):
    form = await request.form()
    db = SessionLocal()
    for key in ("lock_fail_count", "lock_fail_hours", "lock_minutes"):
        v = _int(str(form.get(key, "")).translate(FA_TO_EN))
        if v is not None and v >= 0:
            set_setting(db, key, str(v))
    set_setting(db, "lock_source", "1" if form.get("lock_source") else "0")
    db.commit()
    log_action(request, "تنظیم قفل خودکار", str(security.rules(db)))
    flash(request, "ذخیره شد")
    return redirect("/security#rules")


# ------------------------------------------------------------------ temporary grants
def _grant_rows(db, q):
    rows = q.order_by(TempGrant.start.desc()).limit(300).all()
    users = {u.id: u for u in db.query(User).filter(User.id.in_({g.user_id for g in rows}))} if rows else {}
    return [(g, users.get(g.user_id)) for g in rows]


def _dt(day_text, time_text, default_time="00:00"):
    d = _date(day_text)
    if d is None:
        return None
    t = (str(time_text or "").strip() or default_time).translate(FA_TO_EN)
    try:
        hh, mm = (int(x) for x in t.split(":")[:2])
        return datetime(d.year, d.month, d.day, hh, mm)
    except (ValueError, TypeError):
        return None


@app.get("/grants", response_class=HTMLResponse)
def grants_page(request: Request, user: int = 0):
    db = SessionLocal()
    t = now()
    active = _grant_rows(db, db.query(TempGrant).filter(TempGrant.revoked_at.is_(None), TempGrant.end > t))
    past = _grant_rows(db, db.query(TempGrant).filter((TempGrant.revoked_at.isnot(None)) | (TempGrant.end <= t)))
    sel = db.get(User, user) if user else None
    return render(request, "grants.html", active=active, past=past, kinds=grants.KINDS, sel=sel,
                  today=jalali.to_jalali_str(t.date()), now=t)


@app.post("/grants/add")
async def grants_add(request: Request):
    form = await request.form()
    db = SessionLocal()
    back = _local(form.get("back"), "/grants")
    name = str(form.get("username", "")).strip()
    u = db.query(User).filter(User.username.ilike(name)).first() if name else None
    kind = str(form.get("kind", ""))
    start = _dt(form.get("start_day"), form.get("start_time"), "00:00")
    end = _dt(form.get("end_day"), form.get("end_time"), "23:59")
    ordered = str(form.get("ordered_by", "")).strip()
    err = ("کاربر پیدا نشد" if u is None else "نوع مجوز را انتخاب کنید" if kind not in grants.KINDS else
           "تاریخ و ساعت شروع / پایان نادرست است" if not start or not end or end <= start else
           "نام دستوردهنده الزامی است" if not ordered else "")
    if err:
        flash(request, err, "err")
        return redirect(back)
    g = TempGrant(user_id=u.id, kind=kind, start=start, end=end, ordered_by=ordered[:150],
                  reason=str(form.get("reason", "")).strip()[:500], created_by=request.state.me.username)
    db.add(g)
    db.commit()
    log_action(request, "مجوز موقت", f"{u.username}: {grants.KINDS[kind]} {jalali.to_jalali_str(start, True)} تا "
                                     f"{jalali.to_jalali_str(end, True)} به دستور {ordered}")
    flash(request, f"مجوز «{grants.KINDS[kind]}» برای {u.username} ثبت شد")
    return redirect(back)


@app.post("/grants/{gid}/revoke")
async def grants_revoke(request: Request, gid: int):
    form = await request.form()
    db = SessionLocal()
    g = db.get(TempGrant, gid)
    if g and g.revoked_at is None:
        g.revoked_at = now()
        db.commit()
        log_action(request, "لغو مجوز موقت", str(gid))
        flash(request, "مجوز لغو شد")
    return redirect(_local(form.get("back"), "/grants"))
