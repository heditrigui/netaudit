"""Local data: where netaudit keeps its files, plus friendly device names."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path

_MAC = re.compile(r"^[0-9a-fA-F]{1,2}([:-][0-9a-fA-F]{1,2}){5}$")


def data_dir() -> Path:
    """Folder for names, history and watch state. NETAUDIT_HOME overrides it."""
    if os.environ.get("NETAUDIT_HOME"):
        return Path(os.environ["NETAUDIT_HOME"])
    if os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "netaudit"
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "netaudit"


def read_json(path: Path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path: Path, data) -> None:
    """Write atomically, so a scan and a watch running at once never leave a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def is_mac(text: str) -> bool:
    return bool(_MAC.match(text.strip()))


def normalize_target(target: str) -> str:
    """A MAC (any common notation) becomes AA:BB:CC:DD:EE:FF; an IP is validated as-is."""
    target = target.strip()
    if is_mac(target):
        return ":".join(p.zfill(2) for p in re.split(r"[:-]", target)).upper()
    try:
        return str(ipaddress.IPv4Address(target))
    except ValueError as exc:
        raise ValueError(f"Not an IPv4 address or MAC address: {target}") from exc


# Friendly names: {"AA:BB:..": "Projector", "192.168.1.50": "NAS"}. MAC keys survive IP changes.

def names_path() -> Path:
    return data_dir() / "names.json"


def load_names() -> dict[str, str]:
    return read_json(names_path(), {})


def save_names(names: dict[str, str]) -> None:
    write_json(names_path(), names)


def lookup_name(names: dict[str, str], mac: str, ip: str) -> str:
    return (mac and names.get(mac)) or names.get(ip, "")
