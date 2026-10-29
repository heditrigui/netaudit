"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from netaudit import __version__, discover, oui, report
from netaudit import ports as portmod
from netaudit.risks import Device, evaluate, guess_kind


def audit_host(ip: str, mac: str, port_spec: list[int], timeout: float, no_dns: bool) -> Device:
    dev = Device(ip=ip, mac=mac, vendor=oui.vendor(mac))
    if not no_dns:
        dev.hostname = discover.reverse_dns(ip)
    dev.open_ports = portmod.scan(ip, port_spec, timeout=timeout)
    for p in dev.open_ports:
        info = portmod.grab_banner(ip, p)
        if info:
            dev.services[p] = info
    dev.kind = guess_kind(dev)
    dev.findings = evaluate(dev)
    return dev


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        net = discover.validate_scope(args.cidr or str(discover.default_network()), args.allow_public, args.force)
        port_spec = portmod.port_list(args.ports)
    except (discover.ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    started = datetime.now()
    t0 = time.monotonic()
    log = (lambda *a: None) if args.quiet else (lambda *a: print(*a, file=sys.stderr))
    if not oui.have_registry():
        log("tip: run `netaudit update-oui` once to show device vendors.")
    log(f"Discovering hosts on {net} ...")
    hosts = discover.sweep(net, timeout=args.timeout, workers=args.workers)
    arp = discover.arp_table()
    self_ip = discover.local_ip()
    log(f"Found {len(hosts)} host(s). Scanning {len(port_spec)} port(s) each ...")

    with ThreadPoolExecutor(max_workers=16) as pool:
        devices = list(pool.map(
            lambda ip: audit_host(ip, arp.get(ip, ""), port_spec, args.timeout, args.no_dns), hosts
        ))
    for d in devices:
        if d.ip == self_ip:
            d.hostname = d.hostname or "(this computer)"

    changes = report.diff(report.load(args.baseline), devices) if args.baseline else None
    print(report.console(str(net), devices, changes))
    log(f"Done in {time.monotonic() - t0:.0f}s.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report.to_json(str(net), devices, started), fh, indent=2)
        log(f"JSON saved to {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(str(net), devices, started, changes))
        log(f"HTML report saved to {args.html}")

    if args.fail_on:
        levels = ["critical", "high", "medium"]
        blocking = set(levels[: levels.index(args.fail_on) + 1])
        if any(f.severity in blocking for d in devices for f in d.findings):
            return 1
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netaudit", description="Inventory and audit the devices on your network.")
    p.add_argument("--version", action="version", version=f"netaudit {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="discover devices and check them for risky services")
    s.add_argument("cidr", nargs="?", help="network to scan, e.g. 192.168.1.0/24 (default: your local /24)")
    s.add_argument("-p", "--ports", default="common", help="'common' (default), 'all', or a list like 22,80,8000-8100")
    s.add_argument("--html", metavar="FILE", help="write an HTML report")
    s.add_argument("--json", metavar="FILE", help="write machine-readable results (usable as a --baseline later)")
    s.add_argument("--baseline", metavar="FILE", help="previous --json output; report new devices and newly opened ports")
    s.add_argument("--timeout", type=float, default=0.8, help="per-connection timeout in seconds (default 0.8)")
    s.add_argument("--workers", type=int, default=128, help="parallel discovery probes (default 128)")
    s.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    s.add_argument("--fail-on", choices=["critical", "high", "medium"], help="exit 1 if findings at or above this level exist")
    s.add_argument("--allow-public", action="store_true", help="allow scanning non-private ranges you are authorized to test")
    s.add_argument("--force", action="store_true", help=f"allow ranges larger than {discover.MAX_HOSTS} addresses")
    s.add_argument("-q", "--quiet", action="store_true", help="only print the results table")
    s.set_defaults(func=cmd_scan)

    u = sub.add_parser("update-oui", help="download the IEEE MAC vendor list (about 6 MB, once)")
    u.set_defaults(func=cmd_update_oui)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args = parser.parse_args(["scan", *(argv or sys.argv[1:])])
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
