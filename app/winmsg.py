"""Pop-up message on users' Windows computers (msg.exe from the panel's server to each computer's IP).
The computers must accept it: GPO registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server
AllowRemoteRPC = 1 and the firewall allowing File and Printer Sharing (SMB 445) from the panel server."""
import logging
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from .db import Device, now
from .pingcheck import online_filter

log = logging.getLogger("winmsg")
COMPUTERS = ("pc", "laptop", "thin", "server", "unknown")


def available():
    return os.name == "nt" and bool(shutil.which("msg"))


def send_one(ip, text, seconds=300):
    if not available():
        return False, "msg.exe فقط روی سرور ویندوزی برنامه در دسترس است"
    try:
        r = subprocess.run(["msg", "*", f"/server:{ip}", f"/time:{int(seconds)}", text], capture_output=True,
                           timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)[:150]
    if r.returncode == 0:
        return True, ""
    err = (r.stderr or r.stdout or b"").decode("cp1252", "replace").strip()
    return False, err[:150] or f"exit {r.returncode}"


def targets(db, mode, value=""):
    """-> [(label, ip)] of the computers to send to."""
    ts = now()
    out = {}
    if mode == "user":
        name = (value or "").strip().lower().split("\\")[-1]
        q = db.query(Device).filter(Device.last_ip != "", Device.logon_at >= ts - timedelta(days=1))
        for d in online_filter(q, ts).all():
            if (d.logon_user or "").lower().split("\\")[-1] == name:
                out[d.last_ip] = f"{d.logon_user} @ {d.label or d.hostname or d.last_ip}"
    elif mode == "device":
        d = db.query(Device).filter(Device.mac == value).first()
        if d and d.last_ip:
            out[d.last_ip] = d.label or d.hostname or d.last_ip
    elif mode in ("router", "all"):
        q = db.query(Device).filter(Device.last_ip != "", Device.device_type.in_(COMPUTERS))
        if mode == "router":
            q = q.filter(Device.last_nas_id == int(value or 0))
        for d in online_filter(q, ts).all():
            if d.logon_user or d.device_type != "unknown":
                out[d.last_ip] = f"{d.logon_user or '-'} @ {d.label or d.hostname or d.last_ip}"
    return sorted((v, k) for k, v in out.items())


def send(db, mode, value, text, seconds=300):
    tg = targets(db, mode, value)
    with ThreadPoolExecutor(max_workers=16) as ex:
        res = list(ex.map(lambda t: (t[0], t[1]) + send_one(t[1], text, seconds), tg))
    return res
