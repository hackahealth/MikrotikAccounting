"""RouterOS version, update and reboot of the routers from the panel; update packages (.npk) uploaded to the panel
are sent to a router by FTP / SFTP and installed by its next reboot (routers without access to MikroTik's servers)."""
import logging
import os
import re

from . import config, hotspot, routeros
from .db import Nas

log = logging.getLogger("rosadmin")

NPK_DIR = os.path.join(config.DATA_DIR, "routeros_packages")
MAX_NPK = 200 * 1024 * 1024
ARCHES = ("arm64", "arm", "mipsbe", "mmips", "smips", "tile", "ppc", "x86", "x86_64")


def info(nas: Nas) -> dict:
    """Version, model, uptime and update state of one router."""
    conn = routeros.api(nas)
    try:
        res = next(iter(routeros._list(conn, "system", "resource")), {})
        rb = next(iter(routeros._list(conn, "system", "routerboard")), {})
        upd = next(iter(routeros._list(conn, "system", "package", "update")), {})
        pkgs = routeros._list(conn, "system", "package")
    finally:
        conn.close()
    return {
        "version": str(res.get("version", "")), "arch": str(res.get("architecture-name", "")),
        "board": str(res.get("board-name", "")), "uptime": str(res.get("uptime", "")),
        "cpu": res.get("cpu-load"), "free_mem": res.get("free-memory"), "total_mem": res.get("total-memory"),
        "free_hdd": res.get("free-hdd-space"), "total_hdd": res.get("total-hdd-space"),
        "routerboard": bool(rb.get("routerboard")), "model": str(rb.get("model", "")),
        "fw_current": str(rb.get("current-firmware", "")), "fw_upgrade": str(rb.get("upgrade-firmware", "")),
        "channel": str(upd.get("channel", "")), "installed": str(upd.get("installed-version", "")),
        "latest": str(upd.get("latest-version", "")), "status": str(upd.get("status", "")),
        "packages": [{"name": str(p.get("name", "")), "version": str(p.get("version", "")),
                      "disabled": bool(p.get("disabled")), "scheduled": str(p.get("scheduled", ""))} for p in pkgs],
    }


def _run(nas: Nas, cmd: str, drop_ok=False, **kw):
    conn = routeros.api(nas)
    try:
        return [dict(r) for r in conn(cmd, **kw)]
    except Exception:
        if drop_ok:            # the router closes the connection while rebooting
            return []
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def check_updates(nas: Nas, channel: str = "") -> dict:
    if channel:
        _run(nas, "/system/package/update/set", channel=channel)
    _run(nas, "/system/package/update/check-for-updates")
    return info(nas)


def install_update(nas: Nas):
    """Downloads the latest version from MikroTik and reboots (the router needs internet)."""
    _run(nas, "/system/package/update/install", drop_ok=True)


def upgrade_firmware(nas: Nas):
    """RouterBOARD firmware: copied now, active after the next reboot."""
    _run(nas, "/system/routerboard/upgrade")


def reboot(nas: Nas):
    _run(nas, "/system/reboot", drop_ok=True)


# ------------------------------------------------------------------ uploaded .npk packages
def safe_name(name: str) -> str:
    name = os.path.basename(str(name or "").replace("\\", "/"))
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,120}\.npk", name):
        raise ValueError("فقط فایل .npk بسته‌های میکروتیک با نام لاتین پذیرفته می‌شود")
    return name


def npk_arch(name: str) -> str:
    """routeros-7.16-arm64.npk / routeros-mipsbe-6.49.10.npk -> the architecture ('' when not in the name)."""
    parts = re.split(r"[-_]", name[:-4].lower())
    for a in sorted(ARCHES, key=len, reverse=True):
        if a in parts:
            return a
    return "x86" if parts and parts[0] == "routeros" and len(parts) == 2 else ""


def npk_version(name: str) -> str:
    m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:(?:beta|rc)\d+)?)", name)
    return m.group(1) if m else ""


def save_npk(name: str, data: bytes) -> str:
    name = safe_name(name)
    if not data or len(data) > MAX_NPK:
        raise ValueError("فایل خالی یا بیش از حد بزرگ است")
    if data[:4] != b"\x1e\xf1\xd0\xba":
        raise ValueError("این فایل بستهٔ معتبر میکروتیک (npk) نیست")
    os.makedirs(NPK_DIR, exist_ok=True)
    with open(os.path.join(NPK_DIR, name), "wb") as fh:
        fh.write(data)
    return name


def list_npk():
    if not os.path.isdir(NPK_DIR):
        return []
    out = []
    for n in sorted(os.listdir(NPK_DIR)):
        p = os.path.join(NPK_DIR, n)
        if n.endswith(".npk") and os.path.isfile(p):
            out.append({"name": n, "size": os.path.getsize(p), "arch": npk_arch(n), "version": npk_version(n),
                        "mtime": os.path.getmtime(p)})
    return out


def delete_npk(name: str):
    p = os.path.join(NPK_DIR, safe_name(name))
    if os.path.isfile(p):
        os.remove(p)


def arch_ok(name: str, arch: str) -> bool:
    a = npk_arch(name)
    return not a or not arch or a == arch.lower() or (a == "x86" and arch.lower() in ("x86", "x86_64"))


def send_npk(nas: Nas, name: str, arch: str = ""):
    """Puts the package in the root of the router's files: RouterOS installs it on the next reboot."""
    name = safe_name(name)
    if not arch_ok(name, arch):
        raise ValueError(f"معماری بسته ({npk_arch(name)}) با معماری روتر ({arch}) یکی نیست")
    with open(os.path.join(NPK_DIR, name), "rb") as fh:
        data = fh.read()
    tr = hotspot.transfer(nas)
    try:
        tr.put(name, data)
    finally:
        tr.close()
