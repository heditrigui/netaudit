import json
import socket
import threading
from datetime import datetime

import pytest

from netaudit import discover, oui, report, risks
from netaudit import ports as portmod
from netaudit.risks import Device, Finding

WIN_ARP = """
Interface: 192.168.1.100 --- 0x12
  Internet Address      Physical Address      Type
  192.168.1.1           00-1a-2b-3c-4d-01     dynamic
  192.168.1.238         00-1a-2b-3c-4d-ee     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

MAC_ARP = "? (10.0.0.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n"

PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.0.11     0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def test_parse_windows_arp_skips_broadcast_and_multicast():
    table = discover.parse_arp(WIN_ARP)
    assert table == {"192.168.1.1": "00:1A:2B:3C:4D:01", "192.168.1.238": "00:1A:2B:3C:4D:EE"}


def test_parse_bsd_and_proc_arp():
    assert discover.parse_arp(MAC_ARP) == {"10.0.0.1": "00:11:22:33:44:55"}
    assert discover.parse_arp(PROC_ARP) == {"192.168.0.10": "AA:BB:CC:DD:EE:FF"}


@pytest.mark.parametrize("cidr", ["8.8.8.0/24", "1.1.1.1/32"])
def test_public_ranges_are_refused(cidr):
    with pytest.raises(discover.ScopeError):
        discover.validate_scope(cidr)
    assert discover.validate_scope(cidr, allow_public=True)


def test_large_ranges_need_force():
    with pytest.raises(discover.ScopeError):
        discover.validate_scope("10.0.0.0/8")
    assert discover.validate_scope("192.168.1.0/24").num_addresses == 256


def test_port_list_specs():
    assert portmod.port_list("22, 80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert 5555 in portmod.port_list("common")
    assert len(portmod.port_list("all")) == 65535
    with pytest.raises(ValueError):
        portmod.port_list("70000")


def test_randomized_mac_detection():
    assert oui.is_randomized("02:1A:2B:3C:4D:EE")
    assert not oui.is_randomized("00:1A:2B:3C:4D:EE")


def test_oui_registry_parsing():
    text = 'Registry,Assignment,Organization Name,Organization Address\nMA-L,F0A882,"Example Corp",Somewhere\n'
    assert oui.parse_registry(text) == {"F0A882": "Example Corp"}


def test_http_parsing():
    raw = b"HTTP/1.0 200 OK\r\nServer: hccastsmartdisplay/1.0.0\r\n\r\n<html><title> Setup \n Page</title>"
    assert portmod.parse_http(raw) == {"server": "hccastsmartdisplay/1.0.0", "title": "Setup Page"}


def test_rules_and_score():
    dev = Device(ip="192.168.1.50", open_ports=[23, 80, 5555])
    dev.findings = risks.evaluate(dev)
    sevs = [f.severity for f in dev.findings]
    assert sevs[:2] == ["critical", "critical"]
    assert "low" in sevs  # HTTP-only admin page
    assert dev.worst == "critical"
    assert dev.score == 100 - 40 - 40 - 3


def test_guess_kind():
    assert risks.guess_kind(Device(ip="x", open_ports=[8008, 8009])) == "Google Cast / Android TV"
    assert risks.guess_kind(Device(ip="x", open_ports=[80], services={80: {"server": "hccastsmartdisplay/1.0"}})).startswith("Cast")


def test_diff_detects_new_devices_and_ports():
    prev = {"devices": [
        {"ip": "192.168.1.2", "mac": "00:11:22:33:44:55", "open_ports": [80]},
        {"ip": "192.168.1.3", "mac": "00:11:22:33:44:66", "open_ports": []},
    ]}
    now = [
        Device(ip="192.168.1.20", mac="00:11:22:33:44:55", open_ports=[80, 23]),  # same MAC, new IP
        Device(ip="192.168.1.9", mac="00:AA:BB:CC:DD:EE"),
    ]
    changes = report.diff(prev, now)
    assert [d["ip"] for d in changes["new"]] == ["192.168.1.9"]
    assert [d["ip"] for d in changes["gone"]] == ["192.168.1.3"]
    assert changes["new_ports"][0]["new_ports"] == [23]


def test_reports_render():
    dev = Device(ip="192.168.1.5", mac="00:11:22:33:44:55", open_ports=[23], kind="Router / gateway",
                 findings=[Finding("critical", "Telnet <open>", "Disable it", 23)])
    text = report.console("192.168.1.0/24", [dev])
    assert "Telnet <open>" in text and "192.168.1.5" in text
    page = report.to_html("192.168.1.0/24", [dev], datetime(2026, 1, 1))
    assert "Telnet &lt;open&gt;" in page and "<!doctype html>" in page
    data = report.to_json("192.168.1.0/24", [dev], datetime(2026, 1, 1))
    assert json.loads(json.dumps(data))["devices"][0]["score"] == 60


class _HCCastStub(threading.Thread):
    """A tiny local HTTP server that imitates an HCCast projector."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                req = conn.recv(1024)
                body = json.dumps({"device_password": "12345678"}) if b"/setting_get" in req else "<title>x</title>"
                conn.sendall(f"HTTP/1.0 200 OK\r\nServer: hccastsmartdisplay/1.0.0\r\n\r\n{body}".encode())


def test_scan_banner_and_hccast_probe(monkeypatch):
    stub = _HCCastStub()
    stub.start()
    assert portmod.scan("127.0.0.1", [stub.port]) == [stub.port]
    assert portmod.parse_http(portmod.http_get("127.0.0.1", stub.port))["server"].startswith("hccast")

    real_get = portmod.http_get
    monkeypatch.setattr(portmod, "http_get", lambda ip, port, *a, **k: real_get(ip, stub.port, *a, **k))
    dev = Device(ip="127.0.0.1", open_ports=[80], services={80: {"server": "hccastsmartdisplay/1.0.0"}})
    titles = [f.title for f in risks.evaluate(dev)]
    assert "Default Wi-Fi Direct password" in titles
    stub.sock.close()
