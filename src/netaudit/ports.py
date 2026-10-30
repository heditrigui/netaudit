"""TCP port scanning and light service fingerprinting."""

from __future__ import annotations

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

# Ports that matter on home and small-office networks: admin panels, remote access,
# file sharing, cameras, IoT and casting protocols.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 515: "lpd",
    548: "afp", 554: "rtsp", 631: "ipp", 873: "rsync", 1080: "socks", 1883: "mqtt",
    2049: "nfs", 2323: "telnet-alt", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5000: "upnp/airplay", 5001: "https-alt", 5357: "wsd", 5432: "postgres", 5555: "adb",
    5900: "vnc", 6379: "redis", 6466: "androidtv-remote", 7000: "airplay",
    8000: "http-alt", 8008: "googlecast", 8009: "googlecast-tls", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8883: "mqtt-tls", 8888: "http-alt", 9000: "http-alt",
    9100: "jetdirect", 10000: "webmin", 27017: "mongodb", 32400: "plex", 49152: "upnp",
    62078: "iphone-sync",
}

HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 49152}


def port_list(spec: str) -> list[int]:
    """Turn 'common', 'all', or '22,80,8000-8100' into a sorted port list."""
    spec = spec.strip().lower()
    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad:
        raise ValueError(f"Invalid port(s): {bad[:5]}")
    return sorted(ports)


def _is_open(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((ip, port)) == 0
        except OSError:
            return False


def scan(ip: str, ports: list[int], timeout: float = 0.8, workers: int = 200) -> list[int]:
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        results = pool.map(lambda p: (p, _is_open(ip, p, timeout)), ports)
        return [p for p, up in results if up]


_STATUS = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})")
_LOCATION = re.compile(rb"^location:\s*(.+?)\r?$", re.I | re.M)
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_SERVER = re.compile(rb"^server:\s*(.+?)\r?$", re.I | re.M)


def parse_http(raw: bytes) -> dict[str, str]:
    info: dict[str, str] = {}
    if m := _STATUS.match(raw):
        info["status"] = m.group(1).decode()
    if m := _LOCATION.search(raw):
        info["location"] = m.group(1).decode("latin-1").strip()[:200]
    if m := _SERVER.search(raw):
        info["server"] = m.group(1).decode("latin-1").strip()
    if m := _TITLE.search(raw):
        info["title"] = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:80]
    return info


def http_get(ip: str, port: int, path: str = "/", timeout: float = 3.0, limit: int = 65536) -> bytes:
    """Minimal HTTP/1.0 GET returning raw headers + body (no redirects, no TLS)."""
    req = f"GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netaudit\r\nConnection: close\r\n\r\n"
    data = b""
    deadline = time.monotonic() + timeout * 2  # stops slow-drip and streaming endpoints
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall(req.encode())
        while len(data) < limit and time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    return data


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> dict[str, str]:
    """Best-effort service identification for one open port."""
    try:
        if port in HTTP_PORTS:
            return parse_http(http_get(ip, port, timeout=timeout, limit=16384))
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            text = s.recv(256).decode("utf-8", "replace").strip()
    except OSError:
        return {}
    return {"banner": text.splitlines()[0][:100]} if text else {}
