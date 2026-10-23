"""مدل‌های پایگاه داده (SQLAlchemy)."""
import base64
import contextvars
import hashlib
import threading
from datetime import datetime

from cryptography.fernet import Fernet
from sqlalchemy import (BigInteger, Boolean, Column, Date, DateTime, ForeignKey,
                        Index, Integer, String, Text, UniqueConstraint, create_engine, event, inspect, text)
from sqlalchemy.orm import declarative_base, relationship, scoped_session, sessionmaker

from . import config

_connect_args = {"check_same_thread": False, "timeout": 30} if config.DATABASE_URL.startswith("sqlite") else {}
# web worker threads (up to 40), RADIUS, Traffic-Flow and the jobs each hold a connection while working
engine = create_engine(config.DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True, pool_size=10,
                       max_overflow=40, pool_timeout=60)

if config.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

# One session per web request (also when a sync route runs in a worker thread), otherwise one per thread.
request_scope = contextvars.ContextVar("db_request_scope", default=None)


def _scope():
    return request_scope.get() or threading.get_ident()


SessionLocal = scoped_session(sessionmaker(bind=engine, expire_on_commit=False), scopefunc=_scope)
Base = declarative_base()

_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(config.SECRET_KEY.encode()).digest()))


def encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode() if value else ""


def decrypt(value: str) -> str:
    return _fernet.decrypt(value.encode()).decode() if value else ""


def now() -> datetime:
    """Local (configured TZ) naive datetime."""
    return datetime.now(config.TZ).replace(tzinfo=None)


class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255), default="")
    rate_limit = Column(String(100), default="")          # MikroTik format: "2M/4M" (upload/download)
    quota_mb = Column(BigInteger, default=0)              # 0 = unlimited
    quota_period = Column(String(10), default="monthly")  # daily|weekly|monthly|total
    allowed_hours = Column(String(255), default="")       # e.g. "sat-wed 08:00-17:00; thu 08:00-13:00"
    simultaneous_use = Column(Integer, default=1)          # 0 = unlimited
    session_timeout_min = Column(Integer, default=0)
    idle_timeout_min = Column(Integer, default=0)
    allow_hotspot = Column(Boolean, default=True)
    allow_vpn = Column(Boolean, default=True)
    address_list = Column(String(100), default="")        # MikroTik address-list name for firewall/mangle
    ldap_group_dn = Column(String(500), default="")       # AD group mapped to this group
    users = relationship("User", back_populates="group")


class Office(Base):
    """دفتر / شعبه (مثلاً دفتر یزد، دفتر تهران)."""
    __tablename__ = "offices"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    code = Column(String(30), default="")
    city = Column(String(100), default="")
    ldap_value = Column(String(200), default="")           # AD physicalDeliveryOfficeName / l value
    description = Column(String(255), default="")


class Department(Base):
    """واحد سازمانی (مالی، فنی، ...)؛ می‌تواند به یک دفتر وابسته باشد یا مشترک بین دفترها."""
    __tablename__ = "departments"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    office_id = Column(Integer, ForeignKey("offices.id"), nullable=True)
    office = relationship("Office")
    ldap_value = Column(String(200), default="")           # AD department value
    description = Column(String(255), default="")
    __table_args__ = (UniqueConstraint("name", "office_id", name="uq_dept"),)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False, index=True)
    full_name = Column(String(200), default="")
    email = Column(String(200), default="")
    phone = Column(String(50), default="")
    mobile = Column(String(50), default="")               # AD attribute "mobile"
    ip_phone = Column(String(50), default="")             # AD attribute "ipPhone" (desk phone extension)
    title = Column(String(150), default="")               # AD "title" (job title)
    company = Column(String(150), default="")             # AD "company"
    city = Column(String(150), default="")                # AD "l" (city / location)
    tour_seen = Column(String(10), default="")            # first-login tour of the usage page (/my) shown
    source = Column(String(10), default="local")          # local|ldap|router
    password_enc = Column(Text, default="")               # local users only (reversible, for CHAP/MS-CHAPv2)
    enabled = Column(Boolean, default=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)
    group = relationship("Group", back_populates="users")
    office_id = Column(Integer, ForeignKey("offices.id"), nullable=True, index=True)
    office = relationship("Office")
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True, index=True)
    department = relationship("Department")
    personnel_code = Column(String(50), default="")
    # Per-user overrides (empty / None = inherit from group)
    rate_limit = Column(String(100), default="")
    quota_mb = Column(BigInteger, nullable=True)
    quota_period = Column(String(10), default="")
    allowed_hours = Column(String(255), default="")
    simultaneous_use = Column(Integer, nullable=True)
    expire_at = Column(Date, nullable=True)
    static_ip = Column(String(45), default="")
    allowed_macs = Column(String(500), default="")        # comma separated; empty = any
    ldap_dn = Column(String(500), default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=now)
    last_login = Column(DateTime, nullable=True)
    usage_reset_at = Column(DateTime, nullable=True)      # manual quota reset point


class Nas(Base):
    __tablename__ = "nas"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(45), unique=True, nullable=False)  # router's own IP (source IP of RADIUS packets without NAT)
    secret = Column(String(200), nullable=False)
    identifier = Column(String(100), default="")          # NAS-Identifier (= /system identity); routers behind NAT
    flow_port = Column(Integer, default=0)                # own Traffic-Flow port (0 = the shared port)
    api_host = Column(String(100), default="")            # RouterOS API host (default = ip)
    api_port = Column(Integer, default=8728)
    api_user = Column(String(100), default="")
    api_password_enc = Column(Text, default="")
    api_ssl = Column(Boolean, default=False)
    coa_port = Column(Integer, default=3799)
    last_seen = Column(DateTime, nullable=True)
    office_id = Column(Integer, ForeignKey("offices.id"), nullable=True)
    file_proto = Column(String(5), default="ftp")         # ftp|sftp  (hotspot folder upload)
    file_port = Column(Integer, default=0)                # 0 = default (21 / 22)
    hotspot_dir = Column(String(200), default="")         # empty = auto-detect from hotspot profile
    wan_interfaces = Column(String(300), default="")      # internet-facing interfaces (names or ifIndex), csv
    lan_ranges = Column(Text, default="")                 # internal networks behind this router (CIDR per line)
    lan_interfaces = Column(String(300), default="")      # internal-network interfaces (traffic graph), csv
    tunnel_interfaces = Column(String(300), default="")   # tunnels to other offices (empty = every tunnel-type iface)
    tunnel_ranges = Column(Text, default="")              # other offices' networks reached through a tunnel / IPsec
    monitor_targets = Column(String(300), default="")    # addresses the router pings (HQ server through the tunnel)
    auto_tunnels = Column(String(300), default="")       # tunnel-type interfaces seen on the router (when none chosen)


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    mac = Column(String(17), unique=True, nullable=False)
    device_type = Column(String(20), default="unknown")   # devices.TYPES keys
    os = Column(String(50), default="")
    vendor = Column(String(100), default="")
    hostname = Column(String(150), default="")
    dhcp_vendor_class = Column(String(150), default="")
    user_agent = Column(String(500), default="")
    random_mac = Column(Boolean, default=False)
    detected_by = Column(String(100), default="")
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    last_ip = Column(String(45), default="")
    last_nas_id = Column(Integer, nullable=True)
    last_user = Column(String(150), default="")
    label = Column(String(150), default="")               # name given by hand ("پرینتر طبقه ۲")
    logon_user = Column(String(150), default="")          # last Windows logon on this computer
    logon_at = Column(DateTime, nullable=True)
    logon_source = Column(String(20), default="")         # dc|script


class NightList(Base):
    """Devices that were on at the nightly check time (default 21:00), one row per device per night."""
    __tablename__ = "night_list"
    id = Column(Integer, primary_key=True)
    day = Column(Date, index=True, nullable=False)
    taken_at = Column(DateTime)
    mac = Column(String(17), nullable=False)
    ip = Column(String(45), default="")
    nas_id = Column(Integer, nullable=True)
    device_type = Column(String(20), default="")
    label = Column(String(150), default="")
    hostname = Column(String(150), default="")
    vendor = Column(String(100), default="")
    user = Column(String(150), default="")
    user_at = Column(DateTime, nullable=True)
    user_source = Column(String(20), default="")
    hotspot_user = Column(String(150), default="")         # hotspot / VPN login on this device
    hotspot_at = Column(DateTime, nullable=True)           # last time that login was seen
    hotspot_active = Column(Boolean, default=False)        # still logged in at the check time


class DeviceHistory(Base):
    """Continuous intervals in which a device (MAC) had an IP address or a logged-in user on a router.
    Never deleted: a device that is not seen any more just becomes stale."""
    __tablename__ = "device_history"
    id = Column(Integer, primary_key=True)
    mac = Column(String(17), index=True, nullable=False)
    kind = Column(String(4), nullable=False)              # ip|user
    value = Column(String(150), index=True, nullable=False)
    nas_id = Column(Integer, nullable=True)
    source = Column(String(20), default="")               # hotspot|host|arp|dhcp|ppp|radius
    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)


class AcctSession(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    acct_session_id = Column(String(100), nullable=False)
    nas_ip = Column(String(45), nullable=False)
    username = Column(String(150), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    service = Column(String(10), default="hotspot")       # hotspot|vpn
    framed_ip = Column(String(45), default="", index=True)
    mac = Column(String(64), default="")                  # Calling-Station-Id
    called_station = Column(String(100), default="")
    nas_port_id = Column(String(100), default="")
    start_time = Column(DateTime, default=now, index=True)
    last_update = Column(DateTime, default=now)
    stop_time = Column(DateTime, nullable=True, index=True)
    session_time = Column(Integer, default=0)
    bytes_in = Column(BigInteger, default=0)              # user upload (NAS Acct-Input)
    bytes_out = Column(BigInteger, default=0)             # user download (NAS Acct-Output)
    peak_down_bps = Column(BigInteger, default=0)
    peak_up_bps = Column(BigInteger, default=0)
    terminate_cause = Column(String(50), default="")
    device_type = Column(String(20), default="")
    device_os = Column(String(50), default="")
    active = Column(Boolean, default=True, index=True)
    __table_args__ = (UniqueConstraint("nas_ip", "acct_session_id", "username", name="uq_session"),)


class SpeedSample(Base):
    """Interim-update deltas: used for hourly usage and speed graphs."""
    __tablename__ = "speed_samples"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), index=True)
    user_id = Column(Integer, index=True)
    ts = Column(DateTime, index=True)
    seconds = Column(Integer)
    d_in = Column(BigInteger)
    d_out = Column(BigInteger)


class IfaceSample(Base):
    """Router interface counters, one row per router poll (about a minute): traffic graphs of /traffic."""
    __tablename__ = "iface_samples"
    id = Column(Integer, primary_key=True)
    nas_id = Column(Integer, index=True)
    iface = Column(String(64))
    ts = Column(DateTime)
    seconds = Column(Integer)
    rx = Column(BigInteger)
    tx = Column(BigInteger)
    __table_args__ = (Index("ix_iface_samples_key", "nas_id", "iface", "ts"),)


class IfaceDaily(Base):
    """Router interface volume per day (kept as long as speed samples)."""
    __tablename__ = "iface_daily"
    id = Column(Integer, primary_key=True)
    nas_id = Column(Integer)
    iface = Column(String(64))
    day = Column(Date)
    rx = Column(BigInteger, default=0)
    tx = Column(BigInteger, default=0)
    __table_args__ = (UniqueConstraint("nas_id", "iface", "day"),)


class PbxServer(Base):
    """An Issabel / Asterisk server; its call records (CDR) are read from MySQL with a read-only user."""
    __tablename__ = "pbx_servers"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    host = Column(String(100), nullable=False)
    port = Column(Integer, default=3306)
    db_name = Column(String(64), default="asteriskcdrdb")
    db_user = Column(String(100), default="")
    db_password_enc = Column(Text, default="")
    ext_ranges = Column(String(300), default="")          # internal extensions, e.g. "100-399, 5000-5099"
    trunks = Column(String(300), default="")              # trunk channel names (csv); empty = anything not an extension
    office_id = Column(Integer, ForeignKey("offices.id"), nullable=True)
    enabled = Column(Boolean, default=True)
    cursor = Column(DateTime, nullable=True)              # calldate of the newest record read
    last_sync = Column(DateTime, nullable=True)
    last_error = Column(Text, default="")
    imported = Column(Integer, default=0)
    ami_port = Column(Integer, default=5038)              # Asterisk Manager Interface (live calls); no user = off
    ami_user = Column(String(100), default="")
    ami_password_enc = Column(Text, default="")


class ExtensionAssignment(Base):
    """Extension -> person for a period (an extension changes hands; a person can have several)."""
    __tablename__ = "extension_assignments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    pbx_id = Column(Integer, nullable=True)               # None = this extension on every server
    extension = Column(String(32), index=True)
    start = Column(Date, nullable=True)                   # None = from the beginning
    end = Column(Date, nullable=True)                     # None = still assigned (inclusive end day otherwise)
    note = Column(String(200), default="")


class Call(Base):
    """One CDR row (a call leg) of a PBX server."""
    __tablename__ = "calls"
    id = Column(Integer, primary_key=True)
    pbx_id = Column(Integer, index=True)
    key = Column(String(120))                             # uniqueid + sequence (or dst) on that server
    linkedid = Column(String(64), index=True)             # legs of one call share it
    ts = Column(DateTime, index=True)
    direction = Column(String(10))                        # in|out|internal|unknown
    extension = Column(String(32), default="")            # our side
    other = Column(String(64), default="")                # the external number / the other extension
    user_id = Column(Integer, index=True, nullable=True)
    disposition = Column(String(20), default="")          # ANSWERED|NO ANSWER|BUSY|FAILED|CONGESTION
    duration = Column(Integer, default=0)                 # seconds incl. ringing
    billsec = Column(Integer, default=0)                  # talk time
    src = Column(String(64), default="")
    dst = Column(String(64), default="")
    did = Column(String(64), default="")
    queue = Column(String(32), default="")                # queue number when this leg went through a queue
    __table_args__ = (UniqueConstraint("pbx_id", "key"), Index("ix_calls_user_ts", "user_id", "ts"))


class TrafficCategory(Base):
    """Aggregated NetFlow traffic per user / hour / category."""
    __tablename__ = "traffic_category"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    day = Column(Date, index=True)
    hour = Column(Integer)
    category = Column(String(30))
    bytes_down = Column(BigInteger, default=0)
    bytes_up = Column(BigInteger, default=0)
    flows = Column(Integer, default=0)
    __table_args__ = (UniqueConstraint("user_id", "day", "hour", "category", name="uq_tc"),)


class TrafficDomain(Base):
    """Aggregated NetFlow traffic per user / day / remote domain (or IP)."""
    __tablename__ = "traffic_domain"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    day = Column(Date, index=True)
    domain = Column(String(255))
    category = Column(String(30))
    bytes_down = Column(BigInteger, default=0)
    bytes_up = Column(BigInteger, default=0)
    __table_args__ = (UniqueConstraint("user_id", "day", "domain", name="uq_td"),)


class AuthLog(Base):
    __tablename__ = "auth_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    username = Column(String(150), index=True)
    nas_ip = Column(String(45))
    mac = Column(String(64), default="")
    service = Column(String(10), default="")
    method = Column(String(15), default="")
    result = Column(String(10))                            # accept|reject
    reason = Column(String(255), default="")


class PanelUser(Base):
    """Login accounts of the web panel (admin, IT, HR ...)."""
    __tablename__ = "panel_users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(200), default="")
    role = Column(String(20), default="it")
    permissions = Column(Text, default="")                # comma separated; empty = role defaults
    password_hash = Column(String(300), nullable=False)
    enabled = Column(Boolean, default=True)
    must_change_password = Column(Boolean, default=False)
    failed_count = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now)
    last_login = Column(DateTime, nullable=True)
    scope_offices = Column(String(500), default="")       # comma separated office ids (unit/office managers)
    scope_departments = Column(String(500), default="")   # comma separated department ids
    source = Column(String(10), default="local")          # local|ldap (password checked against Active Directory)
    user_id = Column(Integer, nullable=True)              # internet user with the same AD account
    scope_own_office = Column(Boolean, default=False)     # scope follows that user's office / unit in AD
    scope_own_department = Column(Boolean, default=False)
    tour_seen = Column(String(10), default="")            # version of the first-login tour already shown


class HotspotPackage(Base):
    """A stored copy of a MikroTik hotspot html folder (uploaded or backed up from a router)."""
    __tablename__ = "hotspot_packages"
    id = Column(Integer, primary_key=True)
    name = Column(String(150), nullable=False)
    kind = Column(String(10), default="upload")           # upload|backup
    nas_id = Column(Integer, nullable=True)               # router of a backup
    filename = Column(String(200))                        # zip under DATA_DIR/hotspot_packages
    files = Column(Integer, default=0)
    size = Column(BigInteger, default=0)
    note = Column(String(255), default="")
    created_by = Column(String(100), default="")
    created_at = Column(DateTime, default=now)


class DeployLog(Base):
    __tablename__ = "deploy_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    package_id = Column(Integer)
    nas_id = Column(Integer)
    username = Column(String(100), default="")
    target_dir = Column(String(200), default="")
    files = Column(Integer, default=0)
    ok = Column(Boolean, default=False)
    message = Column(Text, default="")
    backup_id = Column(Integer, nullable=True)


class AuditLog(Base):
    """Who did what in the panel."""
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    username = Column(String(100), index=True)
    ip = Column(String(45), default="")
    action = Column(String(100))
    detail = Column(String(500), default="")


class Alert(Base):
    """Notification for the system admin / IT expert (lockouts, router or tunnel down, forbidden access...)."""
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    kind = Column(String(20), index=True)                 # lock|monitor|access
    level = Column(String(10), default="warn")            # info|warn|err
    title = Column(String(255))
    body = Column(Text, default="")
    link = Column(String(255), default="")
    read_at = Column(DateTime, nullable=True)
    read_by = Column(String(100), default="")


class Lock(Base):
    """A user, MAC or IP that may not log in to the hotspot / VPN."""
    __tablename__ = "locks"
    id = Column(Integer, primary_key=True)
    kind = Column(String(4), nullable=False)              # user|mac|ip
    value = Column(String(150), nullable=False, index=True)
    reason = Column(String(255), default="")
    auto = Column(Boolean, default=False)                 # locked by the failed-login rule
    created_at = Column(DateTime, default=now)
    created_by = Column(String(100), default="")
    until = Column(DateTime, nullable=True)               # None = until unlocked by hand
    released_at = Column(DateTime, nullable=True)
    released_by = Column(String(100), default="")


class TempGrant(Base):
    """Temporary permission: work outside the allowed hours, or free internet (no quota / no site blocking)."""
    __tablename__ = "temp_grants"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    kind = Column(String(10), nullable=False)             # hours|internet
    start = Column(DateTime, nullable=False)
    end = Column(DateTime, nullable=False)
    ordered_by = Column(String(150), nullable=False)      # who ordered it
    reason = Column(String(500), default="")
    created_by = Column(String(100), default="")
    created_at = Column(DateTime, default=now)
    revoked_at = Column(DateTime, nullable=True)


class NetEvent(Base):
    """Router / tunnel up-down and slow-link history (network monitoring)."""
    __tablename__ = "net_events"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    nas_id = Column(Integer, index=True)
    target = Column(String(100))                          # "router" or the tunnel interface / ping target
    state = Column(String(10))                            # up|down|slow
    detail = Column(String(255), default="")
    ended_at = Column(DateTime, nullable=True)            # when this state ended


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text, default="")


Index("ix_sessions_user_start", AcctSession.user_id, AcctSession.start_time)
Index("ix_devhist_key", DeviceHistory.mac, DeviceHistory.kind, DeviceHistory.value, DeviceHistory.nas_id)

LDAP_KEYS = ["ldap_server", "ldap_port", "ldap_use_ssl", "ldap_domain", "ldap_bind_user", "ldap_bind_password",
             "ldap_base_dn", "ldap_user_filter", "ldap_default_group", "ldap_auto_sync", "ldap_auto_org"]


def get_setting(db, key, default=""):
    s = db.get(Setting, key)
    return s.value if s and s.value is not None else default


def set_setting(db, key, value):
    s = db.get(Setting, key)
    if s is None:
        s = Setting(key=key)
        db.add(s)
    s.value = value


def _migrate():
    """Add columns introduced by newer versions to existing tables (create_all does not alter tables)."""
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in tables:
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                ddl = col.type.compile(dialect=engine.dialect)
                default = ""
                if col.default is not None and getattr(col.default, "is_scalar", False):
                    v = col.default.arg
                    default = " DEFAULT " + (("1" if v else "0") if isinstance(v, bool) else
                                             str(v) if isinstance(v, (int, float)) else "'" + str(v).replace("'", "''") + "'")
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}{default}'))


def init_db():
    Base.metadata.create_all(engine)
    _migrate()
    db = SessionLocal()
    try:
        if not db.query(Group).count():
            db.add(Group(name="پیش‌فرض", description="گروه پیش‌فرض", rate_limit="2M/4M", quota_mb=0,
                         quota_period="monthly", simultaneous_use=1))
            db.commit()
        from .auth import bootstrap_panel_users
        bootstrap_panel_users(db)
    finally:
        db.close()
        SessionLocal.remove()
