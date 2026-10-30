"""Security findings: rules for risky services plus a few device-specific probes."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

from netaudit import ports as portmod

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    severity: str
    title: str
    advice: str
    port: int | None = None


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    name: str = ""  # friendly name set with `netaudit name`
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, dict[str, str]] = field(default_factory=dict)
    kind: str = ""
    gateway: bool = False  # the default gateway of the machine running the scan
    upnp: dict = field(default_factory=dict)  # SSDP answer plus the UPnP device description
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in self.findings))

    @property
    def worst(self) -> str:
        for sev in SEVERITY_ORDER:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "ok"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["services"] = {str(k): v for k, v in self.services.items()}
        d["score"] = self.score
        d["worst"] = self.worst
        return d


# port -> (severity, title, advice)
PORT_RULES: dict[int, tuple[str, str, str]] = {
    23: ("critical", "Telnet is open", "Telnet sends passwords in clear text and is a favourite of IoT botnets. Disable it and use SSH."),
    2323: ("critical", "Telnet (alternate port) is open", "Often a hidden debug shell on cameras and routers. Disable it or update the firmware."),
    5555: ("critical", "Android Debug Bridge (ADB) is exposed", "Anyone on the network can get a shell on this device. Turn off network/wireless debugging."),
    21: ("high", "FTP is open", "FTP is unencrypted. Use SFTP, or disable the service."),
    5900: ("high", "VNC remote desktop is open", "Make sure VNC requires a strong password, or put it behind a VPN."),
    6379: ("high", "Redis is reachable", "Redis has no authentication by default. Bind it to localhost or set requirepass."),
    27017: ("high", "MongoDB is reachable", "Enable authentication and bind to localhost if it is not meant to be shared."),
    3389: ("medium", "Remote Desktop (RDP) is open", "Fine on a trusted LAN, but enable Network Level Authentication and never forward it to the internet."),
    445: ("medium", "SMB file sharing is open", "Normal for PCs and NAS boxes. Make sure SMBv1 is disabled and shares need a password."),
    1883: ("medium", "MQTT broker without TLS", "Smart-home messages travel in clear text. Require a password, or use port 8883 with TLS."),
    554: ("medium", "RTSP camera stream is open", "Camera streams often have default or no passwords. Set a strong camera password."),
    10000: ("medium", "Webmin admin panel is open", "Keep Webmin updated and restrict who can reach it."),
    3306: ("medium", "MySQL is reachable", "Restrict database access to the hosts that need it."),
    5432: ("medium", "PostgreSQL is reachable", "Restrict database access in pg_hba.conf."),
    2049: ("medium", "NFS is reachable", "Check /etc/exports so shares are not open to the whole network."),
    9100: ("low", "Raw printing (JetDirect) is open", "Anyone on the network can send print jobs. Usually acceptable at home."),
    139: ("low", "NetBIOS is open", "Legacy Windows networking. Disable NetBIOS over TCP/IP if you do not need it."),
}


def guess_kind(dev: Device) -> str:
    p = set(dev.open_ports)
    text = " ".join(v for s in dev.services.values() for v in s.values()).lower()
    if "hccast" in text:
        return "Cast receiver / projector (HCCast)"
    if dev.gateway or upnp_igd(dev):
        return "Router / gateway"
    if 8008 in p or 8009 in p:
        return "Google Cast / Android TV"
    if 62078 in p:
        return "iPhone / iPad"
    if 9100 in p or 631 in p or 515 in p:
        return "Printer"
    if 554 in p:
        return "IP camera / NVR"
    if 32400 in p:
        return "Plex media server"
    if 5000 in p and 5001 in p:
        return "NAS"
    if 53 in p and (80 in p or 443 in p):
        return "Router / gateway"
    if 3389 in p or (445 in p and 135 in p):
        return "Windows PC"
    if 22 in p:
        return "Linux / server"
    if 1883 in p or 8883 in p:
        return "Smart-home hub"
    return ""


def upnp_igd(dev: Device) -> bool:
    return any(k in t for t in dev.upnp.get("types", [])
               for k in ("InternetGatewayDevice", "WANIPConnection", "WANPPPConnection"))


def upnp_wps(dev: Device) -> bool:
    return any("WFADevice" in t or "WFAWLANConfig" in t for t in dev.upnp.get("types", []))


# Server/banner software that is known to be outdated or vulnerable on consumer devices.
OUTDATED_SOFTWARE: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"RomPager/4\.[0-3]", re.I), "critical", "RomPager 4.x web server (Misfortune Cookie)",
     "This firmware is vulnerable to CVE-2014-9222, which lets attackers take over the device. "
     "Update the firmware or replace the router."),
    (re.compile(r"\bBoa/0\.9", re.I), "high", "Boa web server",
     "Boa has been unmaintained since 2005 and has known remote exploits. "
     "Update the firmware, or replace the device if no update exists."),
    (re.compile(r"\buc-httpd", re.I), "high", "uc-httpd camera web server",
     "Used by Xiongmai-based cameras and DVRs with known backdoors and botnet exploits. "
     "Update the firmware and keep it off the internet."),
    (re.compile(r"GoAhead-Webs", re.I), "medium", "Old GoAhead web server",
     "Old GoAhead builds in IP cameras have authentication bypass bugs (for example CVE-2017-8225). "
     "Update the firmware."),
    (re.compile(r"miniupnpd/1\.\d", re.I), "medium", "Old MiniUPnP daemon (1.x)",
     "MiniUPnPd before 2.0 has known memory-corruption bugs. Update the router firmware, or turn UPnP off."),
]

_VERSION = re.compile(r"\d+\.\d+")


def _banners(dev: Device) -> list[tuple[int | None, str]]:
    out = []
    for port, info in sorted(dev.services.items()):
        for key in ("server", "banner"):
            if info.get(key):
                out.append((port, info[key]))
    if dev.upnp.get("server"):
        out.append((None, dev.upnp["server"]))
    model = " ".join(dev.upnp.get(k, "") for k in ("manufacturer", "model_name", "model_number")).split()
    if model:
        out.append((None, "UPnP: " + " ".join(model)))
    return out


def router_findings(dev: Device) -> list[Finding]:
    out = []
    if upnp_igd(dev):
        out.append(Finding(
            "medium", "UPnP port forwarding (IGD) is enabled",
            "Any program on any device here can open ports on your router to the internet without asking, "
            "which malware uses to expose itself. Turn UPnP off in the router unless a console or app needs it.",
        ))
    if upnp_wps(dev):
        out.append(Finding(
            "medium", "WPS appears to be enabled",
            "The router offers Wi-Fi Protected Setup over UPnP. WPS PINs can be brute-forced to recover the "
            "Wi-Fi password. Disable WPS in the router's wireless settings.",
        ))
    if dev.kind == "Router / gateway" and 80 in dev.open_ports:
        http = dev.services.get(80, {})
        to_https = http.get("status", "").startswith("3") and http.get("location", "").lower().startswith("https:")
        if not to_https:
            out.append(Finding(
                "medium", "Router admin page is reachable over plain HTTP",
                "Your router password crosses the network unencrypted when you log in. Turn on HTTPS-only "
                "administration if the router supports it, and use a long, unique admin password.", 80,
            ))
    return out


def banner_findings(dev: Device) -> list[Finding]:
    """Flag known-outdated server software, and note any exposed version string (info only)."""
    out, seen = [], set()
    for port, text in _banners(dev):
        for pattern, severity, title, advice in OUTDATED_SOFTWARE:
            if pattern.search(text) and title not in seen:
                seen.add(title)
                out.append(Finding(severity, f"{title}: {text[:60]}", advice, port))
        if _VERSION.search(text) and text not in seen:
            seen.add(text)
            out.append(Finding(
                "info", f"Software version visible: {text[:80]}",
                "Version banners tell attackers which exploits to try. Keep the firmware up to date.", port,
            ))
    return out


def _probe_hccast(dev: Device, timeout: float) -> list[Finding]:
    """HCCast projectors and dongles publish their Wi-Fi Direct password on an unauthenticated page."""
    try:
        raw = portmod.http_get(dev.ip, 80, "/setting_get", timeout=timeout)
        body = raw.split(b"\r\n\r\n", 1)[1]
        data = json.loads(body.decode("utf-8", "replace"))
    except (OSError, IndexError, ValueError):
        return []
    out = [Finding(
        "medium",
        "Device settings readable without a password",
        f"http://{dev.ip}/setting_get exposes the device configuration to anyone on the network.",
        80,
    )]
    if str(data.get("device_password", "")) in {"12345678", "88888888", "00000000"}:
        out.append(Finding(
            "high",
            "Default Wi-Fi Direct password",
            "Anyone nearby can connect and cast to it. Change the password in the device's network settings.",
            80,
        ))
    return out


def evaluate(dev: Device, probe_timeout: float = 3.0) -> list[Finding]:
    findings = [Finding(*PORT_RULES[p], port=p) for p in dev.open_ports if p in PORT_RULES]
    findings += router_findings(dev)
    findings += banner_findings(dev)
    router_http = any(f.title.startswith("Router admin page") for f in findings)
    if (80 in dev.open_ports and 443 not in dev.open_ports and not router_http
            and dev.kind not in ("Windows PC", "Linux / server")):
        findings.append(Finding(
            "low", "Admin page only over plain HTTP",
            "Passwords typed into this device's web page are not encrypted.", 80,
        ))
    if "hccast" in " ".join(dev.services.get(80, {}).values()).lower():
        findings.extend(_probe_hccast(dev, probe_timeout))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return findings
