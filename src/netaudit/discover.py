"""Host discovery: figure out the local subnet, find live hosts, read the ARP table."""

from __future__ import annotations

import ctypes
import ipaddress
import platform
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

# Ports that answer on almost every kind of device; a connect (or a refusal) proves the host is up.
_LIVENESS_PORTS = (80, 443, 22, 445, 139, 53, 8080, 62078, 5000, 554)

MAX_HOSTS = 4096


class ScopeError(ValueError):
    """Raised when a requested scan range is unsafe or too large."""


def local_ip() -> str:
    """Return this machine's primary LAN address (no packets are sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def default_network() -> ipaddress.IPv4Network:
    """Guess the local /24 from the primary address."""
    return ipaddress.ip_network(f"{local_ip()}/24", strict=False)


def validate_scope(cidr: str, allow_public: bool = False, force: bool = False) -> ipaddress.IPv4Network:
    """Parse a CIDR and refuse ranges that are public or unreasonably large."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ScopeError(f"Not a valid network: {cidr}") from exc
    if net.version != 4:
        raise ScopeError("Only IPv4 networks are supported.")
    if not net.is_private and not allow_public:
        raise ScopeError(
            f"{net} is not a private network. Only scan networks you own; "
            "pass --allow-public if you really are authorized."
        )
    if net.num_addresses > MAX_HOSTS and not force:
        raise ScopeError(f"{net} has {net.num_addresses} addresses; the limit is {MAX_HOSTS} (use --force).")
    return net


_WINDOWS = platform.system() == "Windows"
# Spawning many ping.exe processes from threads is unreliable on Windows, so there we call
# the ICMP API directly; elsewhere a semaphore keeps the number of ping processes sane.
_PING_SLOTS = threading.BoundedSemaphore(32)


def _ping_windows(ip: str, timeout_ms: int) -> bool:
    iphlpapi = ctypes.windll.iphlpapi
    iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
    iphlpapi.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint16,
                                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    handle = iphlpapi.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return False
    try:
        payload = b"netaudit"
        reply = ctypes.create_string_buffer(256)
        addr = int.from_bytes(socket.inet_aton(ip), "little")
        count = iphlpapi.IcmpSendEcho(handle, addr, payload, len(payload), None, reply, len(reply), timeout_ms)
        # ICMP_ECHO_REPLY starts with the replying address, then the status (0 = IP_SUCCESS).
        reply_addr, status = int.from_bytes(reply.raw[0:4], "little"), int.from_bytes(reply.raw[4:8], "little")
        return count > 0 and status == 0 and reply_addr == addr
    finally:
        iphlpapi.IcmpCloseHandle(handle)


def _ping(ip: str, timeout_ms: int) -> bool:
    if _WINDOWS:
        try:
            return _ping_windows(ip, timeout_ms)
        except (OSError, AttributeError):
            return False
    cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    with _PING_SLOTS:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 2)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return out.returncode == 0


def _tcp_alive(ip: str, timeout: float) -> bool:
    for port in _LIVENESS_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                code = s.connect_ex((ip, port))
            except OSError:
                continue
            # 0 = open; ECONNREFUSED/WSAECONNREFUSED = host answered with a reset.
            if code in (0, 111, 10061):
                return True
    return False


def is_alive(ip: str, timeout: float = 0.6) -> bool:
    return _ping(ip, int(timeout * 1000)) or _tcp_alive(ip, timeout)


def sweep(net: ipaddress.IPv4Network, timeout: float = 0.6, workers: int = 128) -> list[str]:
    """Return live hosts in the network, combining probes with whatever the ARP cache knows."""
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        alive = {ip for ip, up in zip(hosts, pool.map(lambda h: is_alive(h, timeout), hosts)) if up}
    # The probes above also fill the ARP cache, which catches devices that ignore ping and TCP.
    alive |= {ip for ip in arp_table() if ipaddress.ip_address(ip) in net}
    alive.discard(str(net.broadcast_address))
    return sorted(alive, key=lambda ip: ipaddress.ip_address(ip))


_WIN_ARP = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)", re.M)
_UNIX_ARP = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})")
_PROC_ARP = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(0x[0-9a-f]+)\s+([0-9a-f:]{17})", re.M)


def normalize_mac(mac: str) -> str:
    parts = re.split(r"[:-]", mac)
    return ":".join(p.zfill(2) for p in parts).upper()


def parse_arp(text: str) -> dict[str, str]:
    """Parse `arp -a` (Windows or BSD/macOS) or /proc/net/arp output into {ip: MAC}."""
    table: dict[str, str] = {}
    for ip, mac, _kind in _WIN_ARP.findall(text):
        table[ip] = normalize_mac(mac)
    for ip, mac in _UNIX_ARP.findall(text):
        table[ip] = normalize_mac(mac)
    for ip, flags, mac in _PROC_ARP.findall(text):
        if flags != "0x0":
            table[ip] = normalize_mac(mac)
    for ip, mac in list(table.items()):
        first = int(mac.split(":")[0], 16)
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or first & 1:  # broadcast / multicast
            del table[ip]
    return table


def arp_table() -> dict[str, str]:
    """Read the OS ARP cache."""
    try:
        with open("/proc/net/arp", encoding="ascii") as fh:
            return parse_arp(fh.read())
    except OSError:
        pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp(out)


def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    return "" if name == ip else name
