# ============================================================================
# MikroTik (RouterOS v7) setup for mikrotik-accounting
# Edit the 7 values below, upload via Winbox > Files, then run:
#   /import file-name=setup.rsc
# (Persian guide: README.md section "تنظیم میکروتیک")
# ============================================================================
# IP of the accounting server
:global acctServer "192.168.88.10"
# RADIUS secret (enter the same secret in panel > Routers)
:global acctSecret "Str0ng-Radius-Secret"
# Router IP that packets to the server come from (enter this IP in panel > Routers)
:global routerIp "192.168.88.1"
# Users' (hotspot) interface / bridge
:global lanIf "bridge"
# Password for the API user
:global apiPass "Api-Pass-ChangeMe"
# Unique name of this router: sent as NAS-Identifier, it tells apart offices whose packets reach the
# server through NAT from the same address (enter the same name in panel > Routers > NAS-Identifier)
:global routerName "Office-Main"
# Traffic-Flow port on the server: 2055, or this router's own port set in panel > Routers
:global flowPort 2055

/system identity set name=$routerName

# ---- RADIUS for Hotspot and PPP (VPN) ----
/radius add service=hotspot,ppp address=$acctServer secret=$acctSecret src-address=$routerIp \
    authentication-port=1812 accounting-port=1813 timeout=3s comment="mikrotik-accounting"
# Allow the server to disconnect users (RADIUS Disconnect / CoA)
/radius incoming set accept=yes port=3799

# ---- Hotspot ----
# http-pap is required for Active Directory users (use an HTTPS login page if possible)
/ip hotspot profile set [find] use-radius=yes radius-accounting=yes radius-interim-update=1m \
    login-by=http-chap,http-pap,mac-cookie
/ip hotspot walled-garden ip add dst-address=$acctServer action=accept comment="accounting UA beacon"

# ---- PPP / VPN (L2TP, SSTP, PPTP, OpenVPN, PPPoE) ----
/ppp aaa set use-radius=yes accounting=yes interim-update=1m
# Local users work with MS-CHAPv2. AD users need PAP inside an encrypted tunnel, e.g.:
# /interface sstp-server server set enabled=yes authentication=pap,mschap2
# /interface l2tp-server server set enabled=yes use-ipsec=required ipsec-secret=YourPSK authentication=pap,mschap2

# ---- Traffic-Flow (usage type: video, download, browsing ...) ----
# v9/IPFIX carries pre/post NAT addresses. interfaces=all counts each packet once (on its ingress interface).
/ip traffic-flow set enabled=yes interfaces=all cache-entries=256k active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=$acctServer port=$flowPort version=ipfix

# ---- DNS: users must resolve through the router so site names can be detected ----
/ip dns set allow-remote-requests=yes cache-size=16384KiB cache-max-ttl=1d
/ip firewall nat add chain=dstnat in-interface=$lanIf protocol=udp dst-port=53 action=redirect to-ports=53 comment="force DNS (accounting)"
/ip firewall nat add chain=dstnat in-interface=$lanIf protocol=tcp dst-port=53 action=redirect to-ports=53 comment="force DNS (accounting)"

# ---- API/FTP user, only from the server IP ----
# read/write/api: live data, disconnect users, manage local hotspot users and PPP secrets
# ftp: remote update of the hotspot folder (login.html ...)
/user group add name=accounting policy=read,write,api,ftp,!local,!telnet,!ssh,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon
/user add name=accounting group=accounting password=$apiPass address=($acctServer . "/32")
/ip service set api disabled=no address=($acctServer . "/32")
# FTP only from the server (if other systems use FTP on this router, add their IPs to address=)
/ip service set ftp disabled=no address=($acctServer . "/32")
# For SFTP instead of FTP: add "ssh" to the group policy above and run:
# /ip service set ssh disabled=no address=($acctServer . "/32")

:log info "mikrotik-accounting setup done"
