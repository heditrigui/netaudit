"""MAC vendor lookup from the IEEE OUI registry (downloaded on demand, cached locally)."""

from __future__ import annotations

import csv
import io
import os
import urllib.request
from functools import lru_cache
from pathlib import Path

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def cache_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "netaudit" / "oui.csv"


def is_randomized(mac: str) -> bool:
    """True for locally administered MACs, which phones and laptops use for Wi-Fi privacy."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def parse_registry(text: str) -> dict[str, str]:
    reader = csv.reader(io.StringIO(text))
    table = {}
    for row in reader:
        if len(row) >= 3 and len(row[1]) == 6:
            table[row[1].upper()] = row[2].strip()
    return table


@lru_cache(maxsize=1)
def _registry() -> dict[str, str]:
    try:
        return parse_registry(cache_path().read_text(encoding="utf-8"))
    except OSError:
        return {}


def vendor(mac: str) -> str:
    if not mac:
        return ""
    if is_randomized(mac):
        return "(private / randomized MAC)"
    return _registry().get(mac.replace(":", "")[:6].upper(), "")


def have_registry() -> bool:
    return bool(_registry())


def update(url: str = IEEE_URL) -> int:
    """Download the IEEE registry into the cache. Returns the number of vendors."""
    req = urllib.request.Request(url, headers={"User-Agent": "netaudit"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        text = resp.read().decode("utf-8", "replace")
    table = parse_registry(text)
    if len(table) < 1000:
        raise RuntimeError("Downloaded registry looks wrong; not saving it.")
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _registry.cache_clear()
    return len(table)
