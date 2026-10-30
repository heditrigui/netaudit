# netaudit

**Find every device on your network and flag the risky ones, in one command.**

`netaudit` sweeps your home or small-office LAN, works out what each device is, checks it for services that attackers love (Telnet, exposed ADB, open databases, default passwords), and gives every device a security score. It runs with zero dependencies beyond Python, on Windows, macOS and Linux.

![netaudit HTML report](docs/screenshot.png)

```
$ netaudit scan

netaudit - 192.168.1.0/24 - 5 device(s)

    IP             MAC                VENDOR / NAME     TYPE                               OPEN PORTS                 SCORE
ok  192.168.1.1    00:1A:2B:3C:4D:01  router.lan        Router / gateway                   53/dns, 80/http, 443/https 100
!   192.168.1.238  00:1A:2B:3C:4D:EE  -                 Cast receiver / projector (HCCast) 80/http, 5000/upnp/airplay 62
!!  192.168.1.77   00:12:34:56:78:9A  -                 IP camera / NVR                    23/telnet, 554/rtsp        47
...

Findings:
  [CRITICAL] 192.168.1.77    Telnet is open
                             -> Telnet sends passwords in clear text and is a favourite of IoT botnets. Disable it and use SSH.
  [HIGH    ] 192.168.1.238   Default Wi-Fi Direct password
                             -> Anyone nearby can connect and cast to it. Change the password in the device's network settings.
```

## Install

```bash
pip install git+https://github.com/heditrigui/netaudit
netaudit update-oui    # optional, once: downloads the IEEE vendor list so MACs show manufacturers
```

## Usage

```bash
netaudit scan                                   # your local /24, common ports
netaudit scan 192.168.0.0/24 --html report.html # pretty, shareable report
netaudit scan --json today.json                 # save results...
netaudit scan --baseline today.json             # ...and later see new devices and newly opened ports
netaudit scan -p all                            # all 65,535 ports (slow)
netaudit scan --fail-on high                    # exit code 1 if anything high/critical is found (cron, CI)
netaudit 192.168.0.0/24                         # `scan` is the default command
```

### Friendly names

```bash
netaudit name 192.168.1.238 "Projector"         # by IP (stored under its MAC when known, so it follows the device)
netaudit name 00:1A:2B:3C:4D:EE "Projector"     # or by MAC
netaudit name projector "Living room projector" # rename
netaudit name projector --remove
netaudit name                                   # list all names
```

Names appear in the console table, the HTML report and the JSON output (`"name"`).

### Device history

Every scan is recorded locally, per device (by MAC): when it was first and last seen, which IPs it used, and how its open ports, findings and score changed over time.

```bash
netaudit history                                # every device seen so far
netaudit history projector                      # one device's timeline, by name, MAC or IP
netaudit scan --no-history                      # scan without recording
```

HTML reports get a **Device history** section with first-seen dates, IPs used, the score trend and the latest change.

### Watch mode and alerts

```bash
netaudit watch --every 15m                      # rescan every 15 minutes until Ctrl+C
netaudit watch 192.168.1.0/24 --every 1h --min-severity high --html live.html
netaudit test-alerts                            # check that your alert channels work
```

After the first scan (the baseline), `watch` alerts when:

- a new device joins the network,
- a known device moves to a new IP, or an IP starts answering with a different MAC,
- a device opens a new port,
- a new finding appears (`--min-severity` sets the lowest level; info notes never alert).

The last scan is kept, so restarting `watch` doesn't re-alert on the same things. Intervals shorter than 60 seconds are refused.

Alerts go to Telegram, Discord and/or email. Configure them in `config.ini` in the netaudit data folder (or pass `--config FILE`):

```ini
[telegram]
token = 123456:ABC-your-bot-token
chat_id = 123456789

[discord]
webhook = https://discord.com/api/webhooks/...

[email]
host = smtp.example.com
port = 587
security = starttls        ; starttls (default), ssl or none
user = you@example.com
password = app-password
from = you@example.com
to = you@example.com, someone@example.com
```

Each setting can also come from an environment variable, which wins over the file: `NETAUDIT_TELEGRAM_TOKEN`, `NETAUDIT_TELEGRAM_CHAT_ID`, `NETAUDIT_DISCORD_WEBHOOK`, `NETAUDIT_SMTP_HOST`, `NETAUDIT_SMTP_PORT`, `NETAUDIT_SMTP_SECURITY`, `NETAUDIT_SMTP_USER`, `NETAUDIT_SMTP_PASSWORD`, `NETAUDIT_SMTP_FROM`, `NETAUDIT_SMTP_TO`. Prefer environment variables for passwords and tokens, or keep the config file readable only by you.

### Where data is kept

Names (`names.json`), history (`history.json`), watch state and `config.ini` live in `%LOCALAPPDATA%\netaudit` on Windows and `~/.local/share/netaudit` (or `$XDG_DATA_HOME/netaudit`) elsewhere. Set `NETAUDIT_HOME` to use another folder.

## What it checks

| Check | Why it matters |
|---|---|
| Telnet (23, 2323) | Clear-text logins; the main way IoT botnets like Mirai spread |
| Android Debug Bridge (5555) | Gives anyone on the network a shell on TVs, boxes and projectors |
| FTP, VNC, Redis, MongoDB | Commonly left without passwords or encryption |
| RDP, SMB, NetBIOS | Normal on PCs, but worth knowing about and hardening |
| RTSP cameras, MQTT | Camera streams and smart-home traffic often have weak or no auth |
| Plain-HTTP admin pages | Router and device passwords sent unencrypted (medium on the router unless it redirects to HTTPS) |
| UPnP port forwarding (IGD) | Lets any program on the network open ports on your router to the internet |
| WPS offered over UPnP | WPS PINs can be brute-forced to recover the Wi-Fi password |
| Outdated server software | RomPager 4.x (Misfortune Cookie), Boa, uc-httpd, old GoAhead and MiniUPnPd 1.x |
| Version banners | Firmware and software versions exposed in headers, banners and UPnP descriptions (info) |
| HCCast projectors and dongles | Settings page is readable without login and often shows a default `12345678` password |
| New devices and ports | Compare with a previous scan, or run `watch`, to spot anything that just appeared |

Each device gets a score from 100 (nothing found) down to 0, and a guessed type (router, printer, camera, Windows PC, Cast device…) based on its ports and banners.

## How it works

1. **Discovery.** ICMP echo (via the native API on Windows, `ping` elsewhere) plus TCP probes to common ports, then the OS ARP cache for MAC addresses, which also catches devices that ignore ping. An SSDP (UPnP) search finds devices that announce themselves, and the routing table identifies your router.
2. **Port scan.** Concurrent TCP connect scan, no raw sockets or admin rights needed.
3. **Fingerprinting.** HTTP status, redirects, `Server` headers and page titles, plain-text banners, UPnP device descriptions (model and firmware numbers), and a few device-specific probes.
4. **Rules.** Each finding has a severity, a plain-English explanation and a fix.

## Responsible use

Only scan networks you own or are authorized to test. By default `netaudit` refuses public IP ranges (`--allow-public` overrides) and ranges larger than 4,096 addresses (`--force`). It only opens TCP connections, reads banners and sends one SSDP multicast search on the local segment; UPnP descriptions are only fetched from the device that announced them. It never tries to log in or exploit anything. `--no-upnp` skips the SSDP step.

## Development

```bash
git clone https://github.com/heditrigui/netaudit && cd netaudit
pip install -e ".[dev]"
pytest
```

Ideas and pull requests are welcome, especially new device probes and risk rules (see `src/netaudit/risks.py`).

## License

MIT
