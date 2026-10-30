"""Command-line entry point."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from netaudit import __version__, discover, history, notify, oui, report, store, watch
from netaudit import ports as portmod
from netaudit.risks import Device, evaluate, guess_kind


def audit_host(ip: str, mac: str, port_spec: list[int], timeout: float, no_dns: bool,
               upnp: dict | None = None, gateway: str = "") -> Device:
    dev = Device(ip=ip, mac=mac, vendor=oui.vendor(mac), gateway=ip == gateway)
    if not no_dns:
        dev.hostname = discover.reverse_dns(ip)
    dev.open_ports = portmod.scan(ip, port_spec, timeout=timeout)
    for p in dev.open_ports:
        info = portmod.grab_banner(ip, p)
        if info:
            dev.services[p] = info
    if upnp:
        desc = discover.describe_upnp(ip, upnp.get("location", ""))
        dev.upnp = {**upnp, **desc, "types": list(dict.fromkeys(upnp["types"] + desc.get("types", [])))}
    dev.kind = guess_kind(dev)
    dev.findings = evaluate(dev)
    return dev


def run_scan(net: ipaddress.IPv4Network, port_spec: list[int], args: argparse.Namespace, log) -> list[Device]:
    """Discover, scan and evaluate every host; shared by `scan` and `watch`."""
    log(f"Discovering hosts on {net} ...")
    hosts = discover.sweep(net, timeout=args.timeout, workers=args.workers)
    self_ip = discover.local_ip()
    ssdp = {} if args.no_upnp else discover.ssdp_search(local=self_ip)
    ssdp = {ip: v for ip, v in ssdp.items() if ipaddress.ip_address(ip) in net}
    hosts = sorted(set(hosts) | set(ssdp), key=ipaddress.ip_address)
    arp = discover.arp_table()
    gateway = discover.default_gateway()
    log(f"Found {len(hosts)} host(s). Scanning {len(port_spec)} port(s) each ...")

    with ThreadPoolExecutor(max_workers=16) as pool:
        devices = list(pool.map(
            lambda ip: audit_host(ip, arp.get(ip, ""), port_spec, args.timeout, args.no_dns, ssdp.get(ip), gateway),
            hosts,
        ))
    names = store.load_names()
    for d in devices:
        if d.ip == self_ip:
            d.hostname = d.hostname or "(this computer)"
        d.name = store.lookup_name(names, d.mac, d.ip)
    return devices


def _scope(args: argparse.Namespace):
    net = discover.validate_scope(args.cidr or str(discover.default_network()), args.allow_public, args.force)
    return net, portmod.port_list(args.ports)


def _logger(args: argparse.Namespace):
    return (lambda *a: None) if args.quiet else (lambda *a: print(*a, file=sys.stderr))


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        net, port_spec = _scope(args)
    except (discover.ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    started = datetime.now()
    t0 = time.monotonic()
    log = _logger(args)
    if not oui.have_registry():
        log("tip: run `netaudit update-oui` once to show device vendors.")
    devices = run_scan(net, port_spec, args, log)
    hist = None
    if not args.no_history:
        hist = history.load()
        history.record(hist, devices, started, str(net))
        history.save(hist)

    changes = report.diff(report.load(args.baseline), devices) if args.baseline else None
    print(report.console(str(net), devices, changes))
    log(f"Done in {time.monotonic() - t0:.0f}s.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report.to_json(str(net), devices, started), fh, indent=2)
        log(f"JSON saved to {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(str(net), devices, started, changes, hist))
        log(f"HTML report saved to {args.html}")

    if args.fail_on:
        levels = ["critical", "high", "medium"]
        blocking = set(levels[: levels.index(args.fail_on) + 1])
        if any(f.severity in blocking for d in devices for f in d.findings):
            return 1
    return 0


def _senders(args: argparse.Namespace):
    return notify.channels(notify.load_config(args.config))


def cmd_watch(args: argparse.Namespace) -> int:
    try:
        net, port_spec = _scope(args)
        interval = watch.parse_interval(args.every)
        senders = _senders(args)
    except (discover.ScopeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log = _logger(args)

    def say(*a):  # status lines that --quiet keeps
        print(*a, file=sys.stderr)

    if senders:
        say(f"Alerts go to: {', '.join(name for name, _ in senders)}")
    else:
        say(f"No alert channels configured ({notify.config_path()} or NETAUDIT_* variables); changes are only printed.")

    state = watch.state_path(str(net))
    previous = store.read_json(state, None)
    runs = 0
    while True:
        started = datetime.now()
        t0 = time.monotonic()
        devices = run_scan(net, port_spec, args, log)
        hist = None
        if not args.no_history:
            hist = history.load()
            history.record(hist, devices, started, str(net))
            history.save(hist)
        current = report.to_json(str(net), devices, started)
        stamp = f"{started:%Y-%m-%d %H:%M}"
        if previous is None:
            say(f"[{stamp}] Baseline recorded: {len(devices)} device(s). Watching for changes every {args.every}.")
        else:
            events = watch.detect_changes(previous["devices"], current["devices"], args.min_severity)
            if events:
                subject, body = watch.format_alert(str(net), events)
                print(f"[{stamp}] {subject}\n{body}", flush=True)
                for err in notify.send_all(senders, subject, body):
                    say(f"alert failed: {err}")
            else:
                say(f"[{stamp}] No changes ({len(devices)} device(s)).")
        store.write_json(state, current)
        previous = current
        if args.json:
            store.write_json(Path(args.json), current)
        if args.html:
            Path(args.html).write_text(report.to_html(str(net), devices, started, None, hist), encoding="utf-8")
        runs += 1
        if args.count and runs >= args.count:
            return 0
        time.sleep(max(0.0, interval - (time.monotonic() - t0)))


def cmd_test_alerts(args: argparse.Namespace) -> int:
    try:
        senders = _senders(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not senders:
        print(f"No alert channels configured. Create {notify.config_path()} or set NETAUDIT_* variables (see README).",
              file=sys.stderr)
        return 1
    errors = notify.send_all(senders, "netaudit test alert", "If you can read this, netaudit watch alerts work.")
    for name, _ in senders:
        failed = [e for e in errors if e.startswith(name + ":")]
        print(f"{name}: {'FAILED - ' + failed[0].split(': ', 1)[1] if failed else 'sent'}")
    return 1 if errors else 0


def cmd_name(args: argparse.Namespace) -> int:
    names = store.load_names()
    if not args.target:
        if not names:
            print('No names yet. Add one with: netaudit name 192.168.1.238 "Projector"')
        for key, name in sorted(names.items(), key=lambda kv: kv[1].lower()):
            print(f"{key:17}  {name}")
        return 0

    # An existing friendly name can be used as the target, to rename or remove it.
    key = next((k for k, v in names.items() if v.lower() == args.target.lower()), None)
    if key is None:
        try:
            key = store.normalize_target(args.target)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not store.is_mac(key):
            # Prefer the MAC behind an IP, so the name follows the device when its IP changes.
            key = discover.arp_table().get(key) or _mac_from_history(key) or key

    if args.remove:
        if names.pop(key, None) is None:
            print(f"error: no name set for {args.target}", file=sys.stderr)
            return 1
        store.save_names(names)
        print(f"Removed the name for {key}")
        return 0
    if not args.name:
        print(names.get(key, f"(no name set for {key})"))
        return 0
    names[key] = args.name.strip()
    store.save_names(names)
    via = f" ({args.target})" if key != args.target else ""
    print(f"Named {key}{via}: {names[key]}")
    return 0


def _mac_from_history(ip: str) -> str:
    for e in history.load().get("devices", {}).values():
        if e.get("mac") and e["ips"] and e["ips"][-1]["ip"] == ip:
            return e["mac"]
    return ""


def cmd_history(args: argparse.Namespace) -> int:
    hist, names = history.load(), store.load_names()
    if not args.device:
        print(history.overview(hist, names), end="")
        return 0
    matches = history.find(hist, args.device, names)
    if not matches:
        print(f"error: no history for {args.device}", file=sys.stderr)
        return 1
    print("\n".join(history.detail(e, names) for _key, e in matches), end="")
    return 0


def cmd_update_oui(_args: argparse.Namespace) -> int:
    print(f"Downloading the IEEE vendor registry from {oui.IEEE_URL} ...")
    try:
        n = oui.update()
    except Exception as exc:  # network errors, HTTP errors, bad data
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {n} vendors to {oui.cache_path()}")
    return 0


def _add_scan_args(s: argparse.ArgumentParser) -> None:
    s.add_argument("cidr", nargs="?", help="network to scan, e.g. 192.168.1.0/24 (default: your local /24)")
    s.add_argument("-p", "--ports", default="common", help="'common' (default), 'all', or a list like 22,80,8000-8100")
    s.add_argument("--html", metavar="FILE", help="write an HTML report")
    s.add_argument("--json", metavar="FILE", help="write machine-readable results (usable as a --baseline later)")
    s.add_argument("--timeout", type=float, default=0.8, help="per-connection timeout in seconds (default 0.8)")
    s.add_argument("--workers", type=int, default=128, help="parallel discovery probes (default 128)")
    s.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    s.add_argument("--no-upnp", action="store_true", help="skip UPnP/SSDP discovery and the router UPnP checks")
    s.add_argument("--allow-public", action="store_true", help="allow scanning non-private ranges you are authorized to test")
    s.add_argument("--force", action="store_true", help=f"allow ranges larger than {discover.MAX_HOSTS} addresses")
    s.add_argument("-q", "--quiet", action="store_true", help="only print the results")
    s.add_argument("--no-history", action="store_true", help="do not record this scan in the device history")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netaudit", description="Inventory and audit the devices on your network.")
    p.add_argument("--version", action="version", version=f"netaudit {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="discover devices and check them for risky services")
    _add_scan_args(s)
    s.add_argument("--baseline", metavar="FILE", help="previous --json output; report new devices and newly opened ports")
    s.add_argument("--fail-on", choices=["critical", "high", "medium"], help="exit 1 if findings at or above this level exist")
    s.set_defaults(func=cmd_scan)

    n = sub.add_parser("name", help="give a device a friendly name (by IP or MAC), or list names")
    n.add_argument("target", nargs="?", help="IP address, MAC address, or an existing name")
    n.add_argument("name", nargs="?", help='the friendly name, e.g. "Living room TV"')
    n.add_argument("--remove", action="store_true", help="forget the name for this device")
    n.set_defaults(func=cmd_name)

    w = sub.add_parser("watch", help="rescan on a schedule and alert on new devices, ports and findings")
    _add_scan_args(w)
    w.add_argument("--every", default="15m", help="time between scans, e.g. 90s, 15m, 1h (default 15m, minimum 60s)")
    w.add_argument("--config", metavar="FILE", help=f"alert settings (default {notify.config_path()})")
    w.add_argument("--min-severity", choices=["critical", "high", "medium", "low"], default="low",
                   help="lowest severity of new findings to alert on (default low)")
    w.add_argument("--count", type=int, default=0, help="stop after this many scans (default: run until Ctrl+C)")
    w.set_defaults(func=cmd_watch)

    t = sub.add_parser("test-alerts", help="send a test message to every configured alert channel")
    t.add_argument("--config", metavar="FILE", help=f"alert settings (default {notify.config_path()})")
    t.set_defaults(func=cmd_test_alerts)

    h = sub.add_parser("history", help="show every device seen so far, or one device's timeline")
    h.add_argument("device", nargs="?", help="IP, MAC or friendly name")
    h.set_defaults(func=cmd_history)

    u = sub.add_parser("update-oui", help="download the IEEE MAC vendor list (about 6 MB, once)")
    u.set_defaults(func=cmd_update_oui)
    p.set_defaults(commands=set(sub.choices))
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    commands = parser.get_default("commands")
    # `netaudit` and `netaudit 192.168.1.0/24 ...` both mean `netaudit scan ...`.
    if not argv or (argv[0] not in commands and argv[0] not in ("-h", "--help", "--version")):
        argv = ["scan", *argv]
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
