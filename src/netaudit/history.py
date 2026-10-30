"""Per-device history across scans: first/last seen, IP changes, and how findings evolved."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from netaudit import store
from netaudit.risks import Device

MAX_SNAPSHOTS = 200  # per device; a snapshot is only added when something changed
MAX_SCANS = 1000


def path() -> Path:
    return store.data_dir() / "history.json"


def load() -> dict:
    return store.read_json(path(), {"devices": {}, "scans": []})


def save(hist: dict) -> None:
    store.write_json(path(), hist)


def device_id(mac: str, ip: str) -> str:
    return mac or f"ip:{ip}"


def _snapshot(d: Device) -> dict:
    return {
        "ip": d.ip,
        "open_ports": list(d.open_ports),
        "findings": [{"severity": f.severity, "title": f.title} for f in d.findings if f.severity != "info"],
        "score": d.score,
    }


def record(hist: dict, devices: list[Device], at: datetime, network: str) -> None:
    stamp = at.isoformat(timespec="seconds")
    hist.setdefault("scans", []).append({"at": stamp, "network": network, "devices": len(devices)})
    del hist["scans"][:-MAX_SCANS]
    for d in devices:
        e = hist.setdefault("devices", {}).setdefault(device_id(d.mac, d.ip), {
            "mac": d.mac, "first_seen": stamp, "seen": 0, "ips": [], "snapshots": [],
        })
        e["last_seen"] = stamp
        e["seen"] += 1
        for k in ("vendor", "hostname", "kind"):
            e[k] = getattr(d, k) or e.get(k, "")
        if e["ips"] and e["ips"][-1]["ip"] == d.ip:
            e["ips"][-1]["last_seen"] = stamp
        else:
            e["ips"].append({"ip": d.ip, "first_seen": stamp, "last_seen": stamp})
        snap = _snapshot(d)
        last = e["snapshots"][-1] if e["snapshots"] else None
        if last is None or {k: last[k] for k in snap} != snap:
            e["snapshots"].append({"at": stamp, **snap})
            del e["snapshots"][:-MAX_SNAPSHOTS]


def find(hist: dict, target: str, names: dict[str, str]) -> list[tuple[str, dict]]:
    """Match a device by friendly name, MAC, or any IP it has used."""
    t = target.strip().lower()
    out = []
    for key, e in hist.get("devices", {}).items():
        name = store.lookup_name(names, e.get("mac", ""), e["ips"][-1]["ip"] if e["ips"] else "")
        if t in (name.lower(), (e.get("mac") or "").lower()) or any(t == x["ip"] for x in e["ips"]):
            out.append((key, e))
    return out


def changes(prev: dict | None, cur: dict) -> list[str]:
    """Describe what changed between two snapshots, in short phrases."""
    if prev is None:
        ports = ", ".join(map(str, cur["open_ports"])) or "none"
        return [f"first seen at {cur['ip']}, ports {ports}, score {cur['score']}"]
    out = []
    if prev["ip"] != cur["ip"]:
        out.append(f"IP {prev['ip']} -> {cur['ip']}")
    opened = sorted(set(cur["open_ports"]) - set(prev["open_ports"]))
    closed = sorted(set(prev["open_ports"]) - set(cur["open_ports"]))
    if opened:
        out.append("opened " + ", ".join(map(str, opened)))
    if closed:
        out.append("closed " + ", ".join(map(str, closed)))
    before = {(f["severity"], f["title"]) for f in prev["findings"]}
    after = {(f["severity"], f["title"]) for f in cur["findings"]}
    out += [f"+ [{s.upper()}] {t}" for s, t in sorted(after - before)]
    out += [f"fixed: {t}" for _s, t in sorted(before - after)]
    if prev["score"] != cur["score"]:
        out.append(f"score {prev['score']} -> {cur['score']}")
    return out


def timeline(e: dict) -> list[tuple[str, list[str]]]:
    snaps = e.get("snapshots", [])
    return [(s["at"], changes(snaps[i - 1] if i else None, s)) for i, s in enumerate(snaps)]


def _day(stamp: str) -> str:
    return stamp.replace("T", " ")[:16]


def overview(hist: dict, names: dict[str, str]) -> str:
    rows = [("NAME", "MAC", "LAST IP", "FIRST SEEN", "LAST SEEN", "IPS", "SCORE")]
    entries = sorted(hist.get("devices", {}).values(), key=lambda e: e.get("last_seen", ""), reverse=True)
    for e in entries:
        ip = e["ips"][-1]["ip"] if e["ips"] else "-"
        label = store.lookup_name(names, e.get("mac", ""), ip) or e.get("hostname") or e.get("vendor") or "-"
        score = str(e["snapshots"][-1]["score"]) if e.get("snapshots") else "-"
        rows.append((label[:28], e.get("mac") or "-", ip, _day(e["first_seen"]), _day(e["last_seen"]),
                     str(len({x["ip"] for x in e["ips"]})), score))
    if len(rows) == 1:
        return "No history yet. Run `netaudit scan` to start recording.\n"
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    return f"{len(entries)} device(s) seen in {len(hist.get('scans', []))} scan(s)\n\n" + "\n".join(lines) + "\n"


def detail(e: dict, names: dict[str, str]) -> str:
    ip = e["ips"][-1]["ip"] if e["ips"] else ""
    name = store.lookup_name(names, e.get("mac", ""), ip)
    head = " - ".join(x for x in (name, e.get("hostname"), e.get("vendor"), e.get("kind")) if x)
    lines = [f"{e.get('mac') or ip}  {head}".rstrip(),
             f"First seen {_day(e['first_seen'])}, last seen {_day(e['last_seen'])}, in {e['seen']} scan(s)",
             "", "IP addresses:"]
    lines += [f"  {x['ip']:15}  {_day(x['first_seen'])} .. {_day(x['last_seen'])}" for x in e["ips"]]
    lines += ["", "Changes:"]
    for at, what in timeline(e):
        lines.append(f"  {_day(at)}  {'; '.join(what)}")
    return "\n".join(lines) + "\n"
