"""تنظیمات برنامه از متغیرهای محیطی (و فایل .env کنار برنامه، در صورت وجود)."""
import os
import secrets
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
ENV_FILE = os.environ.get("ENV_FILE", os.path.join(ROOT_DIR, ".env"))


def load_env_file(path=ENV_FILE):
    """KEY=VALUE lines; real environment variables win over the file."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)


load_env_file()

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(ROOT_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
LOG_DIR = os.path.join(DATA_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.environ.get("LOG_FILE", os.path.join(LOG_DIR, "app.log"))

DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'accounting.db')}")
_LEGACY_KEY = "change-me-please-32chars-minimum!!"


def _secret_key():
    """SECRET_KEY from env/.env; otherwise a random key kept in DATA_DIR/secret.key (created on first run)."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(DATA_DIR, "secret.key")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            key = fh.read().strip()
        if key:
            return key
    # an existing database from an older version was encrypted with the old default key
    key = _LEGACY_KEY if os.path.isfile(os.path.join(DATA_DIR, "accounting.db")) else secrets.token_urlsafe(48)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(key)
    except OSError:
        pass
    return key


SECRET_KEY = _secret_key()
TZ = ZoneInfo(os.environ.get("TZ_NAME", "Asia/Tehran"))

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

RADIUS_BIND = os.environ.get("RADIUS_BIND", "0.0.0.0")
RADIUS_AUTH_PORT = int(os.environ.get("RADIUS_AUTH_PORT", "1812"))
RADIUS_ACCT_PORT = int(os.environ.get("RADIUS_ACCT_PORT", "1813"))
RADIUS_DICTIONARY = os.path.join(BASE_DIR, "data", "dictionary")
# Interim-Update interval sent to the NAS (seconds)
ACCT_INTERIM = int(os.environ.get("ACCT_INTERIM", "60"))

NETFLOW_BIND = os.environ.get("NETFLOW_BIND", "0.0.0.0")
NETFLOW_PORT = int(os.environ.get("NETFLOW_PORT", "2055"))

ENABLE_RADIUS = os.environ.get("ENABLE_RADIUS", "1") == "1"
ENABLE_NETFLOW = os.environ.get("ENABLE_NETFLOW", "1") == "1"
ENABLE_SCHEDULER = os.environ.get("ENABLE_SCHEDULER", "1") == "1"

# How often background jobs run (seconds)
ENFORCE_EVERY = int(os.environ.get("ENFORCE_EVERY", "30"))
ROUTER_POLL_EVERY = int(os.environ.get("ROUTER_POLL_EVERY", "60"))
LDAP_SYNC_EVERY = int(os.environ.get("LDAP_SYNC_EVERY", "3600"))
# Flow larger than this (bytes) in a generic web category is counted as "download"
BIG_FLOW_BYTES = int(os.environ.get("BIG_FLOW_BYTES", str(20 * 1024 * 1024)))
# Keep raw speed samples this many days
SAMPLE_RETENTION_DAYS = int(os.environ.get("SAMPLE_RETENTION_DAYS", "400"))
LOGON_SYNC_EVERY = int(os.environ.get("LOGON_SYNC_EVERY", "120"))   # Windows logons read from the DCs
PBX_SYNC_EVERY = int(os.environ.get("PBX_SYNC_EVERY", "60"))       # Issabel call records (CDR) read
IFACE_SAMPLE_DAYS = int(os.environ.get("IFACE_SAMPLE_DAYS", "14"))   # per-minute interface counters (graphs)
