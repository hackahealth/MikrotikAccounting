"""بروزرسانی از راه دور فولدر hotspot روترهای میکروتیک (FTP / SFTP) با پشتیبان‌گیری و بازگشت."""
import ftplib
import io
import logging
import os
import posixpath
import re
import socket
import zipfile

from . import config, routeros
from .db import DeployLog, HotspotPackage, Nas, decrypt, now

log = logging.getLogger("hotspot")

PKG_DIR = os.path.join(config.DATA_DIR, "hotspot_packages")
os.makedirs(PKG_DIR, exist_ok=True)
MAX_ZIP = 50 * 1024 * 1024
SKIP = re.compile(r"(^|/)(__MACOSX|\.DS_Store|Thumbs\.db|desktop\.ini|\.git)(/|$)", re.I)
TEXT_EXT = {".html", ".htm", ".css", ".js", ".txt", ".xml", ".json", ".svg"}
BEACON_MARK = "/ua?mac="


# ------------------------------------------------------------------ packages
def _normalize(names):
    """Common top folder to strip (e.g. 'hotspot/') when every file is inside it."""
    files = [n for n in names if not n.endswith("/")]
    tops = {n.split("/", 1)[0] for n in files}
    if len(tops) == 1 and all("/" in n for n in files):
        return tops.pop() + "/"
    return ""


def _safe(path):
    path = path.replace("\\", "/").lstrip("/")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or not parts:
        return None
    return "/".join(parts)


def beacon_tag(server_url):
    return (f'<img src="{server_url.rstrip("/")}/ua?mac=$(mac-esc)" width="1" height="1" alt="" '
            f'style="position:absolute;left:-9999px">')


WARN_MARK = "/hs/warn.js"


def warn_tag(server_url):
    return f'<script src="{server_url.rstrip("/")}/hs/warn.js?u=$(username)" async></script>'


def inject_beacon(html: bytes, server_url: str, mark=BEACON_MARK, tag=None) -> bytes:
    text = html.decode("utf-8", errors="surrogateescape")
    if mark in text or not server_url:
        return html
    tag = tag or beacon_tag(server_url)
    m = re.search(r"</body\s*>", text, re.I)
    text = text[:m.start()] + tag + "\n" + text[m.start():] if m else text + "\n" + tag
    return text.encode("utf-8", errors="surrogateescape")


def read_upload(data: bytes, inject=False, server_url=""):
    """Validate an uploaded zip -> dict path->bytes (top folder stripped) and warnings."""
    if len(data) > MAX_ZIP:
        raise ValueError("حجم فایل بیش از ۵۰ مگابایت است")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("فایل ZIP معتبر نیست")
    names = [n for n in zf.namelist() if not SKIP.search(n)]
    strip = _normalize(names)
    files = {}
    for n in names:
        if n.endswith("/"):
            continue
        rel = _safe(n[len(strip):] if strip and n.startswith(strip) else n)
        if rel:
            files[rel] = zf.read(n)
    if not files:
        raise ValueError("فایل ZIP خالی است")
    warnings = []
    if "login.html" not in files:
        warnings.append("فایل login.html در ریشه بسته نیست (فولدر hotspot باید login.html داشته باشد)")
    if inject:
        for page in ("login.html", "alogin.html"):
            if page in files:
                files[page] = inject_beacon(files[page], server_url)
        for page in ("alogin.html", "status.html"):     # quota warning banner once usage passed the warning level
            if page in files:
                files[page] = inject_beacon(files[page], server_url, WARN_MARK, warn_tag(server_url))
    return files, warnings


def write_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(files):
            zf.writestr(path, files[path])
    return buf.getvalue()


def save_package(db, name, files, kind="upload", nas_id=None, note="", user=""):
    pkg = HotspotPackage(name=name[:150], kind=kind, nas_id=nas_id, note=note[:255], created_by=user,
                         files=len(files), size=sum(len(v) for v in files.values()))
    db.add(pkg)
    db.flush()
    pkg.filename = f"{pkg.id}-{kind}.zip"
    with open(os.path.join(PKG_DIR, pkg.filename), "wb") as fh:
        fh.write(write_zip(files))
    db.commit()
    return pkg


def package_path(pkg):
    return os.path.join(PKG_DIR, pkg.filename or "")


def load_package(pkg) -> dict:
    with zipfile.ZipFile(package_path(pkg)) as zf:
        return {n: zf.read(n) for n in zf.namelist() if not n.endswith("/")}


def update_package_file(db, pkg, path, content: bytes):
    files = load_package(pkg)
    files[path] = content
    with open(package_path(pkg), "wb") as fh:
        fh.write(write_zip(files))
    pkg.files, pkg.size = len(files), sum(len(v) for v in files.values())
    db.commit()


def delete_package(db, pkg):
    try:
        os.remove(package_path(pkg))
    except OSError:
        pass
    db.delete(pkg)
    db.commit()


# ------------------------------------------------------------------ transfer (FTP / SFTP)
class FtpTransfer:
    def __init__(self, host, port, user, password, timeout=20):
        self.ftp = ftplib.FTP()
        self.ftp.connect(host, port or 21, timeout=timeout)
        self.ftp.login(user, password)
        self.ftp.set_pasv(True)
        self._dirs = set()

    def mkdirs(self, directory):
        cur = ""
        for part in [p for p in directory.split("/") if p]:
            cur = f"{cur}/{part}" if cur else part
            if cur in self._dirs:
                continue
            try:
                self.ftp.mkd(cur)
            except ftplib.error_perm:
                pass  # exists
            self._dirs.add(cur)

    def put(self, path, data: bytes):
        self.mkdirs(posixpath.dirname(path))
        self.ftp.storbinary(f"STOR {path}", io.BytesIO(data))

    def get(self, path) -> bytes:
        buf = io.BytesIO()
        self.ftp.retrbinary(f"RETR {path}", buf.write)
        return buf.getvalue()

    def delete(self, path):
        self.ftp.delete(path)

    def walk(self, directory):
        """Recursive file listing (fallback when the API is not available)."""
        out = []
        try:
            names = self.ftp.nlst(directory)
        except ftplib.error_perm:
            return out
        for n in names:
            full = n if n.startswith(directory + "/") else f"{directory}/{posixpath.basename(n)}"
            if posixpath.basename(full) in (".", ".."):
                continue
            try:
                self.ftp.cwd("/" + full)
                self.ftp.cwd("/")
                out += self.walk(full)
            except ftplib.error_perm:
                out.append(full)
        return out

    def close(self):
        try:
            self.ftp.quit()
        except Exception:
            self.ftp.close()


class SftpTransfer:
    def __init__(self, host, port, user, password, timeout=20):
        import paramiko
        sock = socket.create_connection((host, port or 22), timeout=timeout)
        self.t = paramiko.Transport(sock)
        self.t.connect(username=user, password=password)
        self.sftp = paramiko.SFTPClient.from_transport(self.t)
        self._dirs = set()

    def mkdirs(self, directory):
        cur = ""
        for part in [p for p in directory.split("/") if p]:
            cur = f"{cur}/{part}" if cur else part
            if cur in self._dirs:
                continue
            try:
                self.sftp.mkdir(cur)
            except IOError:
                pass
            self._dirs.add(cur)

    def put(self, path, data: bytes):
        self.mkdirs(posixpath.dirname(path))
        with self.sftp.open(path, "wb") as fh:
            fh.write(data)

    def get(self, path) -> bytes:
        with self.sftp.open(path, "rb") as fh:
            return fh.read()

    def delete(self, path):
        self.sftp.remove(path)

    def walk(self, directory):
        import stat
        out = []
        try:
            entries = self.sftp.listdir_attr(directory)
        except IOError:
            return out
        for e in entries:
            full = f"{directory}/{e.filename}"
            if stat.S_ISDIR(e.st_mode or 0):
                out += self.walk(full)
            else:
                out.append(full)
        return out

    def close(self):
        self.sftp.close()
        self.t.close()


def transfer(nas: Nas):
    host = nas.api_host or nas.ip
    if not nas.api_user:
        raise RuntimeError("کاربر API/FTP برای این روتر تعریف نشده")
    cls = SftpTransfer if (nas.file_proto or "ftp") == "sftp" else FtpTransfer
    return cls(host, nas.file_port or 0, nas.api_user, decrypt(nas.api_password_enc))


# ------------------------------------------------------------------ router side
def detect_dirs(nas: Nas):
    """html-directory of the router's hotspot profiles (via API)."""
    conn = routeros.api(nas)
    try:
        dirs = []
        for p in routeros.rows(conn.path("ip", "hotspot", "profile")):
            d = str(p.get("html-directory") or "").strip().strip("/")
            if d and d not in dirs:
                dirs.append(d)
        return dirs
    finally:
        conn.close()


def target_dir(nas: Nas):
    if nas.hotspot_dir:
        return nas.hotspot_dir.strip().strip("/")
    try:
        dirs = detect_dirs(nas)
        if dirs:
            return dirs[0]
    except Exception as e:
        log.info("detect html-directory on %s failed: %s", nas.name, e)
    return "hotspot"


def remote_files(nas: Nas, directory, tr=None):
    """Relative paths of the files under directory (API /file, else FTP/SFTP walk)."""
    try:
        conn = routeros.api(nas)
        try:
            items = routeros.rows(conn.path("file"))
        finally:
            conn.close()
        out = []
        for f in items:
            name = str(f.get("name", ""))
            if name.startswith(directory + "/") and f.get("type") != "directory":
                out.append(name[len(directory) + 1:])
        if out or tr is None:
            return out
    except Exception as e:
        log.info("API file list on %s failed: %s", nas.name, e)
        if tr is None:
            raise
    return [p[len(directory) + 1:] for p in tr.walk(directory)]


def backup(db, nas: Nas, user="", note="", tr=None, directory=None):
    """Download the router's current hotspot folder into a stored package."""
    directory = directory or target_dir(nas)
    own = tr is None
    tr = tr or transfer(nas)
    try:
        files = {}
        for rel in remote_files(nas, directory, tr):
            if SKIP.search(rel):
                continue
            files[rel] = tr.get(f"{directory}/{rel}")
    finally:
        if own:
            tr.close()
    if not files:
        raise RuntimeError(f"فولدر {directory} روی {nas.name} خالی است یا پیدا نشد")
    stamp = now().strftime("%Y-%m-%d %H:%M")
    return save_package(db, f"پشتیبان {nas.name} ({directory}) {stamp}", files, kind="backup", nas_id=nas.id,
                        note=note, user=user)


def deploy(db, pkg, nas: Nas, user="", make_backup=True, mirror=False, directory=None):
    """Upload a package into the router's hotspot folder. Returns DeployLog."""
    rec = DeployLog(package_id=pkg.id, nas_id=nas.id, username=user)
    db.add(rec)
    try:
        files = load_package(pkg)
        directory = (directory or target_dir(nas)).strip("/")
        rec.target_dir = directory
        tr = transfer(nas)
        try:
            existing = []
            if make_backup or mirror:
                try:
                    existing = remote_files(nas, directory, tr)
                except Exception as e:
                    log.info("listing %s failed: %s", directory, e)
            if make_backup and existing:
                b = backup(db, nas, user, note=f"قبل از نصب بسته «{pkg.name}»", tr=tr, directory=directory)
                rec.backup_id = b.id
            for rel, data in sorted(files.items()):
                tr.put(f"{directory}/{rel}", data)
            removed = 0
            if mirror:
                for rel in existing:
                    if rel not in files:
                        try:
                            tr.delete(f"{directory}/{rel}")
                            removed += 1
                        except Exception as e:
                            log.info("delete %s failed: %s", rel, e)
        finally:
            tr.close()
        rec.ok, rec.files = True, len(files)
        rec.message = f"{len(files)} فایل در {directory} نوشته شد" + (f"، {removed} فایل اضافه حذف شد" if mirror else "")
    except Exception as e:
        rec.ok, rec.message = False, str(e)[:1000]
        log.warning("hotspot deploy to %s failed: %s", nas.name, e)
    db.commit()
    return rec
