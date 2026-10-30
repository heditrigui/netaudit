"""Watch mode: compare consecutive scans and describe what changed."""

from __future__ import annotations

import re
from pathlib import Path

from netaudit import store
from netaudit.risks import SEVERITY_ORDER

MIN_INTERVAL = 60  # seconds; rescanning faster than this only adds noise and load
_INTERVAL = re.compile(r"^(\d+(?:\.\d+)?)\s*([smhd]?)$", re.I)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 60}


def parse_interval(text: str) -> float:
    """'90s', '15m', '1h', '1d'; a bare number means minutes."""
    m = _INTERVAL.match(text.strip())
    if not m:
        raise ValueError(f"Not an interval: {text!r} (use e.g. 90s, 15m, 1h)")
    seconds = float(m.group(1)) * _UNITS[m.group(2).lower()]
    if seconds < MIN_INTERVAL:
        raise ValueError(f"The interval must be at least {MIN_INTERVAL} seconds.")
    return seconds


def state_path(network: str) -> Path:
    return store.data_dir() / f"watch-{network.replace('/', '_')}.json"


def _label(d: dict) -> str:
    name = d.get("name") or d.get("hostname") or d.get("vendor")
    return f"{name} ({d['ip']})" if name else d["ip"]


def detect_changes(old: list[dict], new: list[dict], min_severity: str = "low") -> list[dict]:
    """Events between two scans' device lists (as in the JSON report): new devices, MAC/IP changes,
    newly opened ports and new findings at or above min_severity."""
    by_mac = {d["mac"]: d for d in old if d.get("mac")}
    by_ip = {d["ip"]: d for d in old}
    current_macs = {d["mac"] for d in new if d.get("mac")}
    limit = SEVERITY_ORDER.index(min_severity)
    events = []

    def event(kind: str, d: dict, text: str) -> None:
        events.append({"kind": kind, "ip": d["ip"], "mac": d.get("mac", ""), "text": text})

    for d in new:
        prev = by_mac.get(d["mac"]) if d.get("mac") else None
        if prev and prev["ip"] != d["ip"]:
            event("ip_changed", d, f"{_label(d)} moved from {prev['ip']} to {d['ip']}")
        if prev is None:
            prev = by_ip.get(d["ip"])
            if prev and prev.get("mac") and d.get("mac") and prev["mac"] != d["mac"]:
                if prev["mac"] in current_macs:
                    prev = None  # the old device moved elsewhere; this is someone new on its address
                else:
                    event("mac_changed", d, f"{d['ip']} now answers with MAC {d['mac']} (was {prev['mac']})")
        if prev is None:
            worst = [f["title"] for f in d.get("findings", []) if SEVERITY_ORDER.index(f["severity"]) <= limit]
            extra = f"; {', '.join(worst[:3])}" if worst else ""
            ports = ", ".join(map(str, d.get("open_ports", []))) or "no open ports"
            mac = f" {d['mac']}" if d.get("mac") else ""
            event("new_device", d, f"New device {_label(d)}{mac} - {ports}{extra}")
            continue
        opened = sorted(set(d.get("open_ports", [])) - set(prev.get("open_ports", [])))
        if opened:
            event("new_port", d, f"{_label(d)} opened port(s) {', '.join(map(str, opened))}")
        before = {(f["severity"], f["title"]) for f in prev.get("findings", [])}
        for f in d.get("findings", []):
            if SEVERITY_ORDER.index(f["severity"]) <= limit and (f["severity"], f["title"]) not in before:
                event("new_finding", d, f"{_label(d)}: [{f['severity'].upper()}] {f['title']}")
    return events


def format_alert(network: str, events: list[dict]) -> tuple[str, str]:
    subject = f"netaudit: {len(events)} change(s) on {network}"
    return subject, "\n".join(f"- {e['text']}" for e in events)

