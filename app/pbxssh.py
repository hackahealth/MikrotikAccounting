"""Automatic Issabel setup over SSH: the admin types the SSH (root) password once (it is not stored) and the panel does
the steps of the manual guide itself:
- a read-only MySQL user for the CDR (GRANT SELECT on asteriskcdrdb to the panel's IP), MySQL opened to the network
  when it listens on localhost only;
- an AMI user for live calls (section in manager_custom.conf, allowed only from the panel's IP);
- the web server's certificate for the API, pinned when it matches the one the API presents;
- the firewall of the Issabel opened for the panel's IP (3306, 5038).
The SSH host key is remembered on first use and checked afterwards (PbxServer.ssh_hostkey)."""
import base64
import hashlib
import logging
import re
import secrets
import socket

from . import ami, pbx, pbxapi
from .db import encrypt

log = logging.getLogger("pbxssh")
STEPS = {"cdr": "کاربر فقط‌خواندنی MySQL برای گزارش تماس", "ami": "کاربر AMI برای تماس‌های زنده",
         "cert": "گواهی وب ایزابل برای API", "firewall": "باز کردن فایروال ایزابل برای سرور برنامه"}
DB_USER = "acct_reader"
AMI_USER = "acct_live"


class SshError(Exception):
    pass


def host_fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class Session:
    """One SSH connection; run(script) feeds a bash script on stdin (secrets never appear in a command line)."""

    def __init__(self, host, port, user, password, known_fp="", timeout=15):
        import paramiko
        try:
            sock = socket.create_connection((host, port or 22), timeout=timeout)
        except OSError as e:
            raise SshError(f"اتصال SSH به {host}:{port or 22} ممکن نشد: {e}") from e
        self.local_ip = sock.getsockname()[0]
        self.t = paramiko.Transport(sock)
        try:
            self.t.start_client(timeout=timeout)
            self.fp = host_fingerprint(self.t.get_remote_server_key())
            if known_fp and known_fp != self.fp:
                raise SshError(f"کلید SSH ایزابل عوض شده است ({self.fp}، قبلاً {known_fp}). اگر سرور را دوباره نصب "
                               "کرده‌اید، کلید ثبت‌شده را در همین صفحه پاک کنید.")
            self.t.auth_password(user, password)
        except paramiko.AuthenticationException as e:
            self.t.close()
            raise SshError("نام کاربری یا رمز SSH اشتباه است") from e
        except paramiko.SSHException as e:
            self.t.close()
            raise SshError(f"SSH: {e}") from e

    def run(self, script, timeout=180):
        ch = self.t.open_session(timeout=30)
        ch.settimeout(timeout)
        ch.exec_command("/bin/bash -s")
        ch.sendall(script.encode())
        ch.shutdown_write()
        out = b""
        while True:
            d = ch.recv(65536)
            if not d:
                break
            out += d
        code = ch.recv_exit_status()
        ch.close()
        return code, out.decode("utf-8", "replace")

    def close(self):
        self.t.close()


def _q(v):
    """Single-quoted shell literal."""
    return "'" + str(v).replace("'", "'\"'\"'") + "'"


def script(steps, app_ip, db_password="", ami_password="", sudo=False):
    """The bash run on the Issabel. Prints 'OK <step> <text>' / 'ERR <step> <text>' / 'INFO <key> <value>' lines."""
    s = ["set -u", f"APP={_q(app_ip)}", 'SUDO=""']
    if sudo:
        s.append('[ "$(id -u)" != 0 ] && SUDO="sudo -n"')
    s.append('[ "$(id -u)" != 0 ] && [ -z "$SUDO" ] && { echo "ERR all کاربر SSH باید root باشد"; exit 0; }')
    s.append("""echo "INFO tz $(readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')"
echo "INFO pbxapi $([ -d /var/www/html/pbxapi ] && echo yes || echo no)"
echo "INFO hostname $(hostname)"
""")
    if "cdr" in steps:
        s.append(f"""
DBPW={_q(db_password)}
ROOTPW=$($SUDO sh -c 'grep -hE "^mysqlrootpwd" /etc/issabel.conf /etc/elastix.conf 2>/dev/null' | head -1 | cut -d= -f2-)
if [ -z "$ROOTPW" ]; then echo "ERR cdr رمز root دیتابیس در /etc/issabel.conf پیدا نشد"; else
  my() {{ if [ -z "$SUDO" ]; then MYSQL_PWD="$ROOTPW" mysql -uroot; else $SUDO env MYSQL_PWD="$ROOTPW" mysql -uroot; fi; }}
  if my <<SQL
GRANT SELECT ON asteriskcdrdb.* TO '{DB_USER}'@'$APP' IDENTIFIED BY '$DBPW';
FLUSH PRIVILEGES;
SQL
  then echo "OK cdr کاربر {DB_USER} ساخته شد (فقط خواندن asteriskcdrdb از $APP)"
  else echo "ERR cdr ساخت کاربر MySQL ناموفق بود"; fi
  if $SUDO sh -c 'ss -ltn 2>/dev/null || netstat -ltn' | grep -E ':3306\\b' | grep -qvE '127\\.0\\.0\\.1:3306|\\[::1\\]:3306'; then
    echo "OK cdr MySQL روی شبکه در دسترس است"
  else
    for f in /etc/my.cnf /etc/my.cnf.d/*.cnf; do
      [ -f "$f" ] && $SUDO grep -qE '^[[:space:]]*(bind-address|skip-networking)' "$f" && \\
        {{ [ -f "$f.macc-bak" ] || $SUDO cp "$f" "$f.macc-bak"; }} && $SUDO sed -i -E 's/^([[:space:]]*)(bind-address|skip-networking)/#\\1\\2/' "$f"
    done
    $SUDO systemctl restart mariadb 2>/dev/null || $SUDO systemctl restart mysqld 2>/dev/null || $SUDO service mysqld restart >/dev/null 2>&1
    sleep 2
    if $SUDO sh -c 'ss -ltn 2>/dev/null || netstat -ltn' | grep -E ':3306\\b' | grep -qvE '127\\.0\\.0\\.1:3306|\\[::1\\]:3306'; then
      echo "OK cdr MySQL برای شبکه باز شد (نسخهٔ قبلی تنظیمات با پسوند .macc-bak)"
    else echo "ERR cdr MySQL هنوز فقط روی localhost است"; fi
  fi
fi
""")
    if "ami" in steps:
        s.append(f"""
AMIPW={_q(ami_password)}
F=/etc/asterisk/manager_custom.conf
$SUDO touch "$F"
$SUDO cp "$F" "$F.macc-bak"
$SUDO awk 'BEGIN{{skip=0}} /^\\[/{{skip=($0=="[{AMI_USER}]")}} !skip' "$F.macc-bak" | $SUDO tee "$F" >/dev/null
printf '\\n[{AMI_USER}]\\nsecret = %s\\ndeny = 0.0.0.0/0.0.0.0\\npermit = %s/255.255.255.255\\nread = call,reporting,agent\\nwrite = reporting\\n' "$AMIPW" "$APP" | $SUDO tee -a "$F" >/dev/null
$SUDO chown asterisk:asterisk "$F" 2>/dev/null
if $SUDO asterisk -rx "manager reload" >/dev/null 2>&1; then echo "OK ami کاربر {AMI_USER} ساخته و AMI دوباره خوانده شد"
else echo "ERR ami asterisk -rx 'manager reload' ناموفق بود"; fi
""")
    if "cert" in steps:
        s.append("""
C=$($SUDO sh -c 'grep -hE "^[[:space:]]*SSLCertificateFile" /etc/httpd/conf.d/ssl.conf 2>/dev/null' | awk '{print $2}' | head -1)
[ -z "$C" ] && C=/etc/pki/tls/certs/localhost.crt
if $SUDO test -f "$C"; then echo "CERT-BEGIN"; $SUDO sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$C" | sed -n '1,/END CERTIFICATE/p'; echo "CERT-END"
else echo "ERR cert فایل گواهی $C پیدا نشد"; fi
""")
    if "firewall" in steps:
        s.append("""
if command -v iptables >/dev/null; then
  for P in 3306 5038; do
    $SUDO iptables -C INPUT -s "$APP" -p tcp --dport $P -j ACCEPT 2>/dev/null || $SUDO iptables -I INPUT 1 -s "$APP" -p tcp --dport $P -j ACCEPT
  done
  echo "OK firewall پورت‌های 3306 و 5038 برای $APP باز شد"
else echo "OK firewall iptables نصب نیست؛ کاری لازم نبود"; fi
""")
    return "\n".join(s) + "\n"


def parse(out):
    """-> (results [(ok, step, text)], info {key: value}, certificate pem or '')."""
    res, info, pem, inside = [], {}, [], False
    for line in out.splitlines():
        if line == "CERT-BEGIN":
            inside = True
            continue
        if line == "CERT-END":
            inside = False
            continue
        if inside:
            pem.append(line)
            continue
        m = re.match(r"(OK|ERR|INFO) (\S+) ?(.*)", line)
        if not m:
            continue
        if m.group(1) == "INFO":
            info[m.group(2)] = m.group(3).strip()
        else:
            res.append((m.group(1) == "OK", m.group(2), m.group(3).strip()))
    text = "\n".join(pem).strip()
    return res, info, (text + "\n") if "BEGIN CERTIFICATE" in text else ""


def setup(db, server, user, password, port=22, steps=("cdr", "ami", "cert", "firewall"), connect=None):
    """Runs the chosen steps, stores what they produced on the server row, and checks each connection. Returns
    {"results": [(ok, step, text)], "info": {...}, "fingerprint": ssh host key}. connect(...) replaces Session in
    tests."""
    steps = [x for x in steps if x in STEPS]
    sess = (connect or Session)(server.host, port, user, password, server.ssh_hostkey or "")
    try:
        db_pw, ami_pw = secrets.token_hex(12), secrets.token_hex(12)
        code, out = sess.run(script(steps, sess.local_ip, db_pw, ami_pw, sudo=user != "root"))
        app_ip, fp = sess.local_ip, sess.fp
    finally:
        sess.close()
    results, info, pem = parse(out)
    if not results and code:
        results.append((False, "all", f"اجرای اسکریپت روی ایزابل ناموفق بود (کد {code})"))
    server.ssh_hostkey = fp
    good = {step for ok, step, _ in results if ok}
    bad = {step for ok, step, _ in results if not ok}
    if "cdr" in steps and "cdr" in good and "cdr" not in bad:
        server.db_user, server.db_password_enc = DB_USER, encrypt(db_pw)
        server.db_name = server.db_name or "asteriskcdrdb"
        ok, msg = pbx.test(server)
        results.append((ok, "cdr", msg))
    if "ami" in steps and "ami" in good:
        server.ami_user, server.ami_password_enc = AMI_USER, encrypt(ami_pw)
        server.ami_port = server.ami_port or 5038
        ok, msg = ami.test(server)
        results.append((ok, "ami", msg))
    if "cert" in steps and pem:
        try:
            live_pem, live_fp = pbxapi.fetch_certificate(server)
            if live_fp == pbxapi.fingerprint(pem):
                server.api_cert = live_pem
                results.append((True, "cert", f"گواهی وب ایزابل ثبت شد ({live_fp[:23]}…)"))
            else:
                results.append((False, "cert", "گواهی که وب ایزابل نشان می‌دهد با فایل گواهی روی سرور یکی نیست؛ "
                                               "ثبت نشد"))
        except (pbxapi.PbxApiError, ValueError) as e:
            results.append((False, "cert", str(e)))
    if info.get("tz") and "Tehran" not in info["tz"]:
        results.append((False, "tz", f"منطقهٔ زمانی ایزابل {info['tz']} است؛ برای گزارش درست باید Asia/Tehran باشد "
                                     "(timedatectl set-timezone Asia/Tehran)"))
    if info.get("pbxapi") == "no":
        results.append((False, "api", "API ایزابل (pbxapi) روی این سرور نصب نیست"))
    log.info("issabel %s ssh setup from %s: %s", server.host, app_ip, results)
    return {"results": results, "info": info, "fingerprint": fp, "app_ip": app_ip}
