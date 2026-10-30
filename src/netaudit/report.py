"""Console, JSON and HTML reports, plus comparison against a previous scan."""

from __future__ import annotations

import html
import json
from datetime import datetime

from netaudit import __version__
from netaudit.ports import COMMON_PORTS
from netaudit.risks import Device

ICON = {"critical": "!!", "high": "! ", "medium": "~ ", "low": "- ", "info": "  ", "ok": "ok"}


def _port_label(p: int) -> str:
    name = COMMON_PORTS.get(p)
    return f"{p}/{name}" if name else str(p)


def _name_cell(d: Device) -> str:
    e = html.escape
    if d.name:
        sub = " &middot; ".join(e(x) for x in (d.hostname, d.vendor) if x)
        return f"<b>{e(d.name)}</b><br><span class='muted'>{sub}</span>"
    return f"{e(d.hostname or '-')}<br><span class='muted'>{e(d.vendor or '')}</span>"


def device_key(d: dict) -> str:
    """Identify a device across scans: by MAC when it is a real one, else by IP."""
    mac = d.get("mac") or ""
    if mac and not (int(mac.split(":")[0], 16) & 0x02):
        return mac
    return d["ip"]


def diff(previous: dict, devices: list[Device]) -> dict[str, list[dict]]:
    old = {device_key(d): d for d in previous.get("devices", [])}
    new = {device_key(d.to_dict()): d.to_dict() for d in devices}
    changed = []
    for key in old.keys() & new.keys():
        added = sorted(set(new[key]["open_ports"]) - set(old[key]["open_ports"]))
        if added:
            changed.append({**new[key], "new_ports": added})
    return {
        "new": [new[k] for k in new.keys() - old.keys()],
        "gone": [old[k] for k in old.keys() - new.keys()],
        "new_ports": changed,
    }


def to_json(network: str, devices: list[Device], started: datetime) -> dict:
    return {
        "tool": "netaudit",
        "version": __version__,
        "network": network,
        "scanned_at": started.isoformat(timespec="seconds"),
        "devices": [d.to_dict() for d in devices],
    }


def console(network: str, devices: list[Device], changes: dict | None = None) -> str:
    lines = [f"\nnetaudit - {network} - {len(devices)} device(s)\n"]
    rows = [("", "IP", "MAC", "VENDOR / NAME", "TYPE", "OPEN PORTS", "SCORE")]
    for d in devices:
        name = d.name or d.hostname or d.vendor
        rows.append((
            ICON[d.worst], d.ip, d.mac or "-", (name or "-")[:28], (d.kind or "-")[:26],
            ", ".join(_port_label(p) for p in d.open_ports)[:40] or "-", str(d.score),
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())

    risky = [(d, f) for d in devices for f in d.findings if f.severity != "info"]
    if risky:
        lines.append("\nFindings:")
        for d, f in risky:
            lines.append(f"  [{f.severity.upper():8}] {d.ip:15} {f.title}")
            lines.append(f"  {'':10} {'':15} -> {f.advice}")
    else:
        lines.append("\nNo risky services found.")

    if changes:
        if changes["new"]:
            lines.append("\nNew since last scan: " + ", ".join(f"{d['ip']} ({d['mac'] or '?'})" for d in changes["new"]))
        if changes["gone"]:
            lines.append("Gone since last scan: " + ", ".join(d["ip"] for d in changes["gone"]))
        for d in changes["new_ports"]:
            lines.append(f"Newly opened on {d['ip']}: " + ", ".join(_port_label(p) for p in d["new_ports"]))
    return "\n".join(lines) + "\n"


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1c2330;--muted:#667085;--line:#e4e7ec;
--critical:#b42318;--high:#d9480f;--medium:#b54708;--low:#475467;--ok:#027a48}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--text:#e6e9ef;--muted:#98a2b3;--line:#2a303c;
--critical:#f97066;--high:#fd853a;--medium:#fdb022;--low:#98a2b3;--ok:#32d583}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}
.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:24px}.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.ok{color:var(--ok)}
code{font-size:12px}ul{margin:4px 0;padding-left:18px}
"""


def to_html(network: str, devices: list[Device], started: datetime, changes: dict | None = None) -> str:
    e = html.escape
    counts = {s: sum(1 for d in devices for f in d.findings if f.severity == s) for s in ("critical", "high", "medium")}
    avg = round(sum(d.score for d in devices) / len(devices)) if devices else 100
    rows = []
    for d in devices:
        findings = "".join(
            f"<li><span class='{f.severity}'>{e(f.title)}</span><br><span class='muted'>{e(f.advice)}</span></li>"
            for f in d.findings
        ) or "<span class='muted'>None</span>"
        rows.append(
            f"<tr><td><b>{e(d.ip)}</b><br><code class='muted'>{e(d.mac or '-')}</code></td>"
            f"<td>{_name_cell(d)}</td>"
            f"<td>{e(d.kind or '-')}</td>"
            f"<td>{e(', '.join(_port_label(p) for p in d.open_ports) or '-')}</td>"
            f"<td><ul>{findings}</ul></td>"
            f"<td><span class='pill {d.worst}'>{d.score}</span></td></tr>"
        )
    change_html = ""
    if changes and (changes["new"] or changes["gone"] or changes["new_ports"]):
        items = [f"<li>New device: <b>{e(d['ip'])}</b> {e(d['mac'] or '')}</li>" for d in changes["new"]]
        items += [f"<li>Gone: {e(d['ip'])}</li>" for d in changes["gone"]]
        items += [f"<li>Newly opened on {e(d['ip'])}: {e(', '.join(map(_port_label, d['new_ports'])))}</li>" for d in changes["new_ports"]]
        change_html = f"<h2>Changes since last scan</h2><ul>{''.join(items)}</ul>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Audit {e(network)}</title>
<style>{_CSS}</style></head><body><main>
<h1>Network audit</h1><div class="muted">{e(network)} &middot; {started:%Y-%m-%d %H:%M} &middot; netaudit {__version__}</div>
<div class="cards"><div class="card"><b>{len(devices)}</b>devices</div>
<div class="card"><b class="critical">{counts['critical']}</b>critical</div>
<div class="card"><b class="high">{counts['high']}</b>high</div>
<div class="card"><b class="medium">{counts['medium']}</b>medium</div>
<div class="card"><b>{avg}</b>average score</div></div>
{change_html}
<div class="wrap"><table><thead><tr><th>Address</th><th>Name / vendor</th><th>Type</th><th>Open ports</th><th>Findings</th><th>Score</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
</main></body></html>
"""


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
