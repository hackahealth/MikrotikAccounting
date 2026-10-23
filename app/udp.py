"""UDP listening sockets for RADIUS / Traffic-Flow that keep working on Windows."""
import logging
import socket
import sys
import time

log = logging.getLogger("udp")
SIO_UDP_CONNRESET = 0x9800000C


def _disable_connreset(sock):
    """Windows reports an ICMP port-unreachable for an earlier reply as WSAECONNRESET on the next recvfrom."""
    try:
        import ctypes
        from ctypes import wintypes
        ws2 = ctypes.windll.ws2_32
        ws2.WSAIoctl.argtypes = [ctypes.c_size_t, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p]
        flag, ret = wintypes.BOOL(False), wintypes.DWORD(0)
        ws2.WSAIoctl(sock.fileno(), SIO_UDP_CONNRESET, ctypes.byref(flag), ctypes.sizeof(flag), None, 0,
                     ctypes.byref(ret), None, None)
    except Exception as e:
        log.debug("SIO_UDP_CONNRESET: %s", e)


def listen(host, port, rcvbuf=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if sys.platform == "win32":
        # the port is ours alone: no silent sharing with Windows NPS or a second copy of the program
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except (AttributeError, OSError):
            pass
        _disable_connreset(s)
    if rcvbuf:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except OSError:
            pass
    s.bind((host, port))
    return s


def recv(sock, size):
    """recvfrom that survives transient errors. Returns None once the socket is closed."""
    while True:
        try:
            return sock.recvfrom(size)
        except ConnectionResetError:
            continue
        except OSError as e:
            if sock.fileno() == -1:
                return None
            log.warning("UDP receive error on port %s: %s", sock.getsockname()[1], e)
            time.sleep(0.2)


def allow_firewall(port, name):
    """Open an extra UDP port in Windows Firewall (the program runs as SYSTEM); no-op elsewhere."""
    if sys.platform != "win32":
        return
    import subprocess
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True, timeout=20, creationflags=flags)
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow",
                        "protocol=UDP", f"localport={port}"], capture_output=True, timeout=20, creationflags=flags)
    except Exception as e:
        log.warning("firewall rule for UDP %s: %s", port, e)
