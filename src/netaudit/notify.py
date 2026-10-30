"""Alert channels for watch mode: Telegram, Discord webhooks and SMTP email (stdlib only)."""

from __future__ import annotations

import configparser
import json
import os
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Callable

from netaudit import __version__, store

USER_AGENT = f"netaudit/{__version__} (+https://github.com/heditrigui/netaudit)"

# Environment variables override the config file, key by key.
ENV = {
    ("telegram", "token"): "NETAUDIT_TELEGRAM_TOKEN",
    ("telegram", "chat_id"): "NETAUDIT_TELEGRAM_CHAT_ID",
    ("discord", "webhook"): "NETAUDIT_DISCORD_WEBHOOK",
    ("email", "host"): "NETAUDIT_SMTP_HOST",
    ("email", "port"): "NETAUDIT_SMTP_PORT",
    ("email", "security"): "NETAUDIT_SMTP_SECURITY",
    ("email", "user"): "NETAUDIT_SMTP_USER",
    ("email", "password"): "NETAUDIT_SMTP_PASSWORD",
    ("email", "from"): "NETAUDIT_SMTP_FROM",
    ("email", "to"): "NETAUDIT_SMTP_TO",
}

Sender = Callable[[str, str], None]  # (subject, body)


def config_path() -> Path:
    return store.data_dir() / "config.ini"


def load_config(path: str | None = None) -> dict[str, dict[str, str]]:
    parser = configparser.ConfigParser(interpolation=None)
    target = Path(path) if path else config_path()
    if path and not target.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    parser.read(target, encoding="utf-8")
    cfg = {s: dict(parser[s]) for s in parser.sections()}
    for (section, key), var in ENV.items():
        if os.environ.get(var):
            cfg.setdefault(section, {})[key] = os.environ[var]
    return cfg


def _post(url: str, data: bytes, content_type: str) -> None:
    req = urllib.request.Request(url, data=data, headers={"Content-Type": content_type, "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as resp:
        resp.read()


def send_telegram(token: str, chat_id: str, text: str) -> None:
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:4096], "disable_web_page_preview": "true"})
    _post(f"https://api.telegram.org/bot{token}/sendMessage", data.encode(), "application/x-www-form-urlencoded")


def send_discord(webhook: str, text: str) -> None:
    _post(webhook, json.dumps({"content": text[:2000], "username": "netaudit"}).encode(), "application/json")


def send_email(cfg: dict[str, str], subject: str, body: str) -> None:
    security = cfg.get("security", "starttls").lower()
    port = int(cfg.get("port") or (465 if security == "ssl" else 587 if security == "starttls" else 25))
    recipients = [a.strip() for a in cfg["to"].split(",") if a.strip()]
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg.get("from") or cfg.get("user") or recipients[0], ", ".join(recipients)
    msg.set_content(body)
    context = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(cfg["host"], port, timeout=30, context=context)
    else:
        server = smtplib.SMTP(cfg["host"], port, timeout=30)
    with server:
        if security == "starttls":
            server.starttls(context=context)
        if cfg.get("user"):
            server.login(cfg["user"], cfg.get("password", ""))
        server.send_message(msg)


def channels(cfg: dict[str, dict[str, str]]) -> list[tuple[str, Sender]]:
    """Build one sender per fully configured channel."""
    out: list[tuple[str, Sender]] = []
    tg = cfg.get("telegram", {})
    if tg.get("token") and tg.get("chat_id"):
        out.append(("telegram", lambda subject, body: send_telegram(tg["token"], tg["chat_id"], f"{subject}\n\n{body}")))
    dc = cfg.get("discord", {})
    if dc.get("webhook"):
        out.append(("discord", lambda subject, body: send_discord(dc["webhook"], f"**{subject}**\n{body}")))
    em = cfg.get("email", {})
    if em.get("host") and em.get("to"):
        out.append(("email", lambda subject, body: send_email(em, subject, body)))
    return out


def send_all(senders: list[tuple[str, Sender]], subject: str, body: str) -> list[str]:
    """Send through every channel; returns error messages instead of raising, so one bad channel never stops the rest."""
    errors = []
    for name, send in senders:
        try:
            send(subject, body)
        except Exception as exc:  # network, HTTP, auth and config errors
            errors.append(f"{name}: {exc}")
    return errors
