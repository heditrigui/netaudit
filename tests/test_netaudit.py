import json
import socket
import threading
from datetime import datetime

import pytest

from netaudit import cli, discover, history, oui, report, risks, store
from netaudit import ports as portmod
from netaudit.risks import Device, Finding

@pytest.fixture(autouse=True)
def data_home(tmp_path, monkeypatch):
    """Keep names, history and watch state out of the real data folder."""
    monkeypatch.setenv("NETAUDIT_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


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
    assert portmod.parse_http(raw) == {"status": "200", "server": "hccastsmartdisplay/1.0.0", "title": "Setup Page"}
    redirect = portmod.parse_http(b"HTTP/1.1 302 Found\r\nLocation: https://192.168.1.1/\r\n\r\n")
    assert redirect == {"status": "302", "location": "https://192.168.1.1/"}


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


def test_normalize_target():
    assert store.normalize_target("00-1a-2b-3c-4d-ee") == "00:1A:2B:3C:4D:EE"
    assert store.normalize_target("192.168.1.238") == "192.168.1.238"
    with pytest.raises(ValueError):
        store.normalize_target("projector")


def test_name_command_prefers_mac_and_renames(monkeypatch, capsys):
    monkeypatch.setattr(discover, "arp_table", lambda: {"192.168.1.238": "00:1A:2B:3C:4D:EE"})
    assert cli.main(["name", "192.168.1.238", "Projector"]) == 0
    assert store.load_names() == {"00:1A:2B:3C:4D:EE": "Projector"}
    assert cli.main(["name", "projector", "Living room projector"]) == 0
    assert store.load_names() == {"00:1A:2B:3C:4D:EE": "Living room projector"}
    assert cli.main(["name", "192.168.1.50", "NAS"]) == 0  # no MAC known: keyed by IP
    assert store.lookup_name(store.load_names(), "", "192.168.1.50") == "NAS"
    capsys.readouterr()
    assert cli.main(["name"]) == 0
    assert "Living room projector" in capsys.readouterr().out
    assert cli.main(["name", "NAS", "--remove"]) == 0
    assert "192.168.1.50" not in store.load_names()


def _fake_scan(devices):
    def run_scan(net, port_spec, args, log):
        names = store.load_names()
        out = [Device(**{k: v for k, v in d.items()}) for d in devices]
        for d in out:
            d.kind = d.kind or risks.guess_kind(d)
            d.findings = risks.evaluate(d)
            d.name = store.lookup_name(names, d.mac, d.ip)
        return out
    return run_scan


def test_names_appear_in_scan_output(monkeypatch, capsys, tmp_path):
    store.save_names({"00:1A:2B:3C:4D:EE": "Projector"})
    monkeypatch.setattr(cli, "run_scan", _fake_scan([{"ip": "192.168.1.238", "mac": "00:1A:2B:3C:4D:EE"}]))
    out_json, out_html = tmp_path / "s.json", tmp_path / "s.html"
    # No `scan` subcommand: a bare network means scan.
    assert cli.main(["192.168.1.0/24", "-q", "--json", str(out_json), "--html", str(out_html)]) == 0
    assert "Projector" in capsys.readouterr().out
    assert json.loads(out_json.read_text())["devices"][0]["name"] == "Projector"
    assert "<b>Projector</b>" in out_html.read_text()


def _scanned(ip, mac="", ports=()):
    d = Device(ip=ip, mac=mac, open_ports=list(ports))
    d.findings = risks.evaluate(d)
    return d


def test_history_tracks_ips_and_only_snapshots_changes():
    hist = {"devices": {}, "scans": []}
    history.record(hist, [_scanned("192.168.1.20", "00:11:22:33:44:55", [80])], datetime(2026, 10, 1, 9), "net")
    history.record(hist, [_scanned("192.168.1.20", "00:11:22:33:44:55", [80])], datetime(2026, 10, 2, 9), "net")
    history.record(hist, [_scanned("192.168.1.21", "00:11:22:33:44:55", [80, 23])], datetime(2026, 10, 3, 9), "net")
    e = hist["devices"]["00:11:22:33:44:55"]
    assert (e["first_seen"], e["last_seen"], e["seen"]) == ("2026-10-01T09:00:00", "2026-10-03T09:00:00", 3)
    assert [x["ip"] for x in e["ips"]] == ["192.168.1.20", "192.168.1.21"]
    assert e["ips"][0]["last_seen"] == "2026-10-02T09:00:00"
    assert len(e["snapshots"]) == 2  # the unchanged second scan adds nothing
    last = history.timeline(e)[-1][1]
    assert "IP 192.168.1.20 -> 192.168.1.21" in last and "opened 23" in last
    assert any("Telnet" in x for x in last)
    assert history.find(hist, "192.168.1.20", {}) and history.find(hist, "laptop", {"00:11:22:33:44:55": "Laptop"})


def test_history_command_and_html_section(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "run_scan", _fake_scan([{"ip": "192.168.1.77", "mac": "00:12:34:56:78:9A", "open_ports": [554]}]))
    assert cli.main(["scan", "192.168.1.0/24", "-q"]) == 0
    monkeypatch.setattr(cli, "run_scan", _fake_scan([{"ip": "192.168.1.77", "mac": "00:12:34:56:78:9A", "open_ports": [23, 554]}]))
    page = tmp_path / "r.html"
    assert cli.main(["scan", "192.168.1.0/24", "-q", "--html", str(page)]) == 0
    assert "Device history" in page.read_text(encoding="utf-8") and "90 &rarr; 50" in page.read_text(encoding="utf-8")
    store.save_names({"00:12:34:56:78:9A": "Camera"})
    capsys.readouterr()
    assert cli.main(["history"]) == 0
    assert "Camera" in capsys.readouterr().out
    assert cli.main(["history", "camera"]) == 0
    out = capsys.readouterr().out
    assert "in 2 scan(s)" in out and "opened 23" in out
    assert cli.main(["history", "10.9.9.9"]) == 1
    assert cli.main(["scan", "192.168.1.0/24", "-q", "--no-history"]) == 0
    assert history.load()["devices"]["00:12:34:56:78:9A"]["seen"] == 2


def test_parse_gateway_on_each_platform():
    win = "Network Destination        Netmask          Gateway       Interface  Metric\n" \
          "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25\n"
    bsd = "   route to: default\ndestination: default\n    gateway: 10.0.0.1\n  interface: en0\n"
    proc = "Iface\tDestination\tGateway \tFlags\nwlan0\t0001A8C0\t00000000\t0001\nwlan0\t00000000\t0101A8C0\t0003\n"
    assert discover.parse_gateway(win) == "192.168.1.1"
    assert discover.parse_gateway(bsd) == "10.0.0.1"
    assert discover.parse_gateway(proc) == "192.168.1.1"
    assert discover.parse_gateway("nothing here") == ""


def test_ssdp_responses_are_merged_per_host():
    found = {}
    igd = (b"HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
           b"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nSERVER: Linux/3.4 UPnP/1.0 MiniUPnPd/1.8\r\n"
           b"USN: uuid:abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
    wfa = b"HTTP/1.1 200 OK\r\nST: urn:schemas-wifialliance-org:device:WFADevice:1\r\n\r\n"
    discover._merge_ssdp(found, "192.168.1.1", discover.parse_ssdp(igd))
    discover._merge_ssdp(found, "192.168.1.1", discover.parse_ssdp(wfa))
    entry = found["192.168.1.1"]
    assert entry["location"] == "http://192.168.1.1:5000/rootDesc.xml"
    assert entry["types"] == ["urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                              "urn:schemas-wifialliance-org:device:WFADevice:1"]


class _HTTPStub(threading.Thread):
    """Serve one fixed HTTP response to every connection on 127.0.0.1."""

    def __init__(self, response: bytes):
        super().__init__(daemon=True)
        self.response = response
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
                conn.recv(1024)
                conn.sendall(self.response)


def test_upnp_description_is_read_only_from_the_device_itself():
    xml = (b"<root><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>"
           b"<friendlyName>Home Router</friendlyName><manufacturer>Example &amp; Co</manufacturer>"
           b"<modelName>XR-500</modelName><modelNumber>V1.0.3.88</modelNumber>"
           b"<serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType></device></root>")
    stub = _HTTPStub(b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\n" + xml)
    stub.start()
    desc = discover.describe_upnp("127.0.0.1", f"http://127.0.0.1:{stub.port}/rootDesc.xml")
    stub.sock.close()
    assert desc["manufacturer"] == "Example & Co" and desc["model_number"] == "V1.0.3.88"
    assert "urn:schemas-wifialliance-org:service:WFAWLANConfig:1" in desc["types"]
    # A LOCATION pointing anywhere else is never fetched.
    assert discover.describe_upnp("127.0.0.1", "http://192.0.2.10/rootDesc.xml") == {}


def test_router_checks():
    router = Device(ip="192.168.1.1", gateway=True, open_ports=[53, 80],
                    services={80: {"status": "200", "server": "RomPager/4.07 UPnP/1.0"}},
                    upnp={"server": "Linux/3.4 UPnP/1.0 MiniUPnPd/1.8", "model_number": "V1.0.3.88",
                          "types": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                                    "urn:schemas-wifialliance-org:device:WFADevice:1"]})
    router.kind = risks.guess_kind(router)
    titles = {f.title: f.severity for f in risks.evaluate(router)}
    assert router.kind == "Router / gateway"
    assert titles["UPnP port forwarding (IGD) is enabled"] == "medium"
    assert titles["WPS appears to be enabled"] == "medium"
    assert titles["Router admin page is reachable over plain HTTP"] == "medium"
    assert "Admin page only over plain HTTP" not in titles  # no duplicate of the generic rule
    assert titles["RomPager 4.x web server (Misfortune Cookie): RomPager/4.07 UPnP/1.0"] == "critical"
    assert any(t.startswith("Old MiniUPnP daemon") for t in titles)
    assert titles["Software version visible: UPnP: V1.0.3.88"] == "info"

    safe = Device(ip="192.168.1.1", gateway=True, open_ports=[80, 443],
                  services={80: {"status": "301", "location": "https://192.168.1.1/"}})
    safe.kind = risks.guess_kind(safe)
    assert risks.evaluate(safe) == []
