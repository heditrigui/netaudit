"""Security findings: rules for risky services plus a few device-specific probes."""

from __future__ import annotations

import json
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
    if 80 in dev.open_ports and 443 not in dev.open_ports and dev.kind not in ("Windows PC", "Linux / server"):
        findings.append(Finding(
            "low", "Admin page only over plain HTTP",
            "Passwords typed into this device's web page are not encrypted.", 80,
        ))
    if "hccast" in " ".join(dev.services.get(80, {}).values()).lower():
        findings.extend(_probe_hccast(dev, probe_timeout))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return findings
