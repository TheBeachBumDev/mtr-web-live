"""Wall-clock timestamps for operator-visible logs (clone, DR, etc.)."""
import os
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def wall_clock_iso() -> str:
    """
    Prefer TZ (IANA), then first line of /etc/timezone (Debian), then system local time.

    For Docker on Linux, docker-compose mounts the host's /etc/localtime into **core** so
    naive local time matches the host without setting TZ.
    """
    tz_name = (os.environ.get("TZ") or "").strip()
    if tz_name:
        try:
            return datetime.now(ZoneInfo(tz_name)).isoformat(timespec="seconds")
        except Exception:
            pass
    try:
        p = Path("/etc/timezone")
        if p.is_file():
            line = p.read_text(encoding="utf-8").strip().splitlines()[0].strip()
            if line and not line.startswith("#"):
                return datetime.now(ZoneInfo(line)).isoformat(timespec="seconds")
    except Exception:
        pass
    return datetime.now().astimezone().isoformat(timespec="seconds")
