# Simple reachability monitoring (PostgreSQL + system ping)
import os
import re
import sqlite3
import subprocess
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import db_runtime

DB_PATH = os.getenv("MONITORING_DB_PATH", os.path.join("data", "monitoring.db"))

DEFAULT_WARN_MS = float(os.getenv("MONITORING_WARN_MS_DEFAULT", "100"))

# Background sampler interval (seconds); each tick stores one sample per device.
SAMPLE_INTERVAL_SEC = max(30, int(os.getenv("MONITORING_SAMPLE_INTERVAL_SEC", "120")))

# Require this many consecutive failed samples (each sample = MONITORING_PINGS_PER_SAMPLE pings)
# before reporting DOWN. Reduces flapping under load or brief packet loss.
DOWN_AFTER_CONSECUTIVE_FAILS = max(
    1, min(50, int(os.getenv("MONITORING_DOWN_AFTER_FAILS", "5")))
)

# Each monitoring sample runs ping -c N; device is up if any reply is received (Linux ping rc 0).
PINGS_PER_SAMPLE = max(1, min(10, int(os.getenv("MONITORING_PINGS_PER_SAMPLE", "5"))))

# Seconds between successive echo requests within one sample (Linux: ping -i). Min 0.2 on many systems.
try:
    PING_SPACING_SEC = float(
        (os.getenv("MONITORING_PING_SPACING_SEC", "1") or "1").strip() or "1"
    )
except (TypeError, ValueError):
    PING_SPACING_SEC = 1.0
PING_SPACING_SEC = max(0.2, min(10.0, PING_SPACING_SEC))


def is_monitoring_sampling_enabled() -> bool:
    """
    When false: no ICMP from the automated sampler or from /api/monitoring/status refreshes;
    Backhauls also skips periodic polls and blocks SNMP snmpget/snmpwalk probes to customer gear.
    Use on DR standby clones (MONITORING_SAMPLING_ENABLED=0). Promote sets 1 again.
    Default on so existing installs behave unchanged.
    """
    v = (os.getenv("MONITORING_SAMPLING_ENABLED") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


# How long to retain raw samples (hours).
SAMPLE_RETENTION_HOURS = float(os.getenv("MONITORING_SAMPLE_RETENTION_HOURS", "24"))
# How long to retain persisted recovered outage entries (days).
OUTAGE_RETENTION_DAYS = float(os.getenv("MONITORING_OUTAGE_RETENTION_DAYS", "90"))

TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]%]+$")

# Rough IPv4 check for "10.0.0.1 50" → target + warn (2-token) disambiguation.
IPV4_TOKEN_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

TIME_MS_RE = re.compile(r"time=([\d.]+)\s*ms", re.I)

_TRANSITION_LOCK = threading.Lock()
# Rolling history: → down is not stored here (see currently-down UI). Ring size fixed at 10.
_TRANSITION_LOG_MAX = max(1, min(10, int(os.getenv("MONITORING_TRANSITION_LOG_MAX", "10"))))
_TRANSITION_LOG: deque = deque(maxlen=_TRANSITION_LOG_MAX)
_OUTAGE_LOG_MAX = max(1, min(500, int(os.getenv("MONITORING_OUTAGE_LOG_MAX", "200"))))
_PREV_LEVELS: Dict[int, str] = {}
# ISO timestamp when reported level first became down (cleared when not down).
_DOWN_SINCE: Dict[int, str] = {}

# Hysteresis for DOWN: per-device streak + last ok/warn while target was reachable.
_DOWN_STREAK: Dict[int, int] = {}
_STABLE_OK_WARN: Dict[int, str] = {}
_LAST_GOOD_LATENCY_MS: Dict[int, float] = {}
# High site (site group) aggregate alarm: True while any member in the group is "down".
_HS_GROUP_ALARM: Dict[int, bool] = {}

TAB_DISPLAY_FLAT = "flat"
TAB_DISPLAY_HIGH_SITES = "high_sites"


def _parse_iso_utc(ts: Optional[str]) -> Optional[datetime]:
    s = str(ts or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _format_outage_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return ""
    total = int(max(0, round(float(seconds))))
    h = total // 3600
    m = (total % 3600) // 60
    s = total % 60
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _ensure_db_dir() -> None:
    d = os.path.dirname(DB_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def get_conn() -> sqlite3.Connection:
    return db_runtime.get_conn("monitoring")


def _ensure_monitoring_schema(conn: Any) -> None:
    """Migrations for High Sites + tab display mode (PostgreSQL)."""
    try:
        conn.execute(
            "ALTER TABLE monitoring_tabs ADD COLUMN IF NOT EXISTS display_mode TEXT NOT NULL DEFAULT 'flat'"
        )
    except Exception:
        pass
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_site_groups (
                id BIGSERIAL PRIMARY KEY,
                tab_id BIGINT NOT NULL,
                name TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE (tab_id, name)
            )
            """
        )
    except Exception:
        pass
    try:
        conn.execute(
            "ALTER TABLE monitoring_targets ADD COLUMN IF NOT EXISTS site_group_id BIGINT"
        )
    except Exception:
        pass


def init_db() -> None:
    db_runtime.init_postgres_schema()
    conn = get_conn()
    _ensure_monitoring_schema(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS monitoring_down_ack (
            id BIGSERIAL PRIMARY KEY,
            device_id BIGINT NOT NULL,
            down_since TEXT NOT NULL,
            acknowledged_by TEXT NOT NULL,
            acknowledged_at TEXT NOT NULL,
            ack_delay_seconds DOUBLE PRECISION,
            UNIQUE (device_id, down_since)
        )
        """
    )
    for stmt in (
        "ALTER TABLE monitoring_outages ADD COLUMN IF NOT EXISTS acked_by TEXT",
        "ALTER TABLE monitoring_outages ADD COLUMN IF NOT EXISTS acked_at TEXT",
        "ALTER TABLE monitoring_outages ADD COLUMN IF NOT EXISTS ack_delay_seconds DOUBLE PRECISION",
    ):
        conn.execute(stmt)
    n_tabs = conn.execute("SELECT COUNT(*) FROM monitoring_tabs").fetchone()[0]
    if int(n_tabs) == 0:
        conn.execute(
            """
            INSERT INTO monitoring_tabs (name, position, created_at, display_mode)
            VALUES ('Power Monitoring', 0, ?, 'flat')
            """,
            (_now(),),
        )
        conn.commit()
    try:
        conn.execute(
            "UPDATE monitoring_tabs SET display_mode = ? WHERE lower(trim(name)) = ? AND display_mode IS DISTINCT FROM ?",
            (TAB_DISPLAY_FLAT, "power monitoring", TAB_DISPLAY_FLAT),
        )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_monitoring_targets_tab_target
        ON monitoring_targets(tab_id, target)
        """
    )
    conn.commit()
    conn.close()


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def validate_target(target: str) -> str:
    t = (target or "").strip()
    if not t or len(t) > 253:
        raise ValueError("Invalid host or IP")
    if not TARGET_RE.match(t):
        raise ValueError("Invalid characters in host or IP")
    return t


def validate_name(name: str) -> str:
    n = (name or "").strip()
    if not n or len(n) > 120:
        raise ValueError("Name is required (max 120 characters)")
    return n


def validate_tab_name(name: str) -> str:
    n = (name or "").strip()
    if not n or len(n) > 80:
        raise ValueError("Tab name is required (max 80 characters)")
    return n


def _effective_tab_display_mode(name: Any, display_mode: Any) -> str:
    """
    Resolve UI/API display mode for a tab row.
    The default "Power Monitoring" tab is always flat (legacy rows may have high_sites set).
    """
    nm = str(name or "").strip().lower()
    if nm == "power monitoring":
        return TAB_DISPLAY_FLAT
    dm = str(display_mode or TAB_DISPLAY_FLAT).strip().lower()
    if dm not in (TAB_DISPLAY_FLAT, TAB_DISPLAY_HIGH_SITES):
        return TAB_DISPLAY_FLAT
    return dm


def list_tabs() -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT id, name, position, display_mode
        FROM monitoring_tabs
        ORDER BY position ASC, id ASC
        """
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["display_mode"] = _effective_tab_display_mode(d.get("name"), d.get("display_mode"))
        out.append(d)
    return out


def get_tab_display_mode(tab_id: int) -> str:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT name, display_mode FROM monitoring_tabs WHERE id = ?", (int(tab_id),)
        ).fetchone()
        if not row:
            return TAB_DISPLAY_FLAT
        return _effective_tab_display_mode(row.get("name"), row.get("display_mode"))
    finally:
        conn.close()


def list_site_groups(tab_id: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        if tab_id is not None:
            rows = conn.execute(
                """
                SELECT id, tab_id, name, position, created_at
                FROM monitoring_site_groups
                WHERE tab_id = ?
                ORDER BY position ASC, id ASC
                """,
                (int(tab_id),),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, tab_id, name, position, created_at
                FROM monitoring_site_groups
                ORDER BY tab_id ASC, position ASC, id ASC
                """
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_site_group(tab_id: int, name: str) -> int:
    name = validate_tab_name(name)  # reuse length rules
    tid = int(tab_id)
    if not tab_exists(tid):
        raise ValueError("Unknown tab")
    if get_tab_display_mode(tid) != TAB_DISPLAY_HIGH_SITES:
        raise ValueError("Tab is not in High Sites mode")
    conn = get_conn()
    try:
        ex = conn.execute(
            "SELECT id FROM monitoring_site_groups WHERE tab_id = ? AND lower(name) = lower(?)",
            (tid, name),
        ).fetchone()
        if ex:
            return int(ex[0])
        mx = conn.execute(
            "SELECT COALESCE(MAX(position), -1) FROM monitoring_site_groups WHERE tab_id = ?",
            (tid,),
        ).fetchone()[0]
        pos = int(mx) + 1
        row = conn.execute(
            """
            INSERT INTO monitoring_site_groups (tab_id, name, position, created_at)
            VALUES (?, ?, ?, ?)
            RETURNING id
            """,
            (tid, name, pos, _now()),
        ).fetchone()
        conn.commit()
        if not row:
            raise RuntimeError("Failed to create site group")
        return int(row[0])
    finally:
        conn.close()


def delete_site_group(group_id: int) -> bool:
    gid = int(group_id)
    conn = get_conn()
    try:
        cur = conn.execute("DELETE FROM monitoring_targets WHERE site_group_id = ?", (gid,))
        cur2 = conn.execute("DELETE FROM monitoring_site_groups WHERE id = ?", (gid,))
        conn.commit()
        return int(getattr(cur2, "rowcount", 0) or 0) > 0
    finally:
        conn.close()


def add_tab(name: str, display_mode: str = TAB_DISPLAY_FLAT) -> int:
    """Create a tab. display_mode is fixed for the lifetime of the tab (flat vs high_sites)."""
    name = validate_tab_name(name)
    dm = str(display_mode or "").strip().lower()
    if dm not in (TAB_DISPLAY_FLAT, TAB_DISPLAY_HIGH_SITES):
        raise ValueError("display_mode must be 'flat' or 'high_sites'")
    conn = get_conn()
    try:
        mx = conn.execute(
            "SELECT COALESCE(MAX(position), -1) FROM monitoring_tabs"
        ).fetchone()[0]
        pos = int(mx) + 1
        row = conn.execute(
            """
            INSERT INTO monitoring_tabs (name, position, created_at, display_mode)
            VALUES (?, ?, ?, ?)
            RETURNING id
            """,
            (name, pos, _now(), dm),
        ).fetchone()
        conn.commit()
        if not row:
            raise RuntimeError("Failed to create monitoring tab")
        return int(row[0])
    finally:
        conn.close()


def delete_tab(tab_id: int) -> bool:
    """
    Remove a monitoring tab and all devices / site groups / related rows under it.
    At least one tab must remain.
    """
    tid = int(tab_id)
    conn = get_conn()
    try:
        n_tabs = int(conn.execute("SELECT COUNT(*) FROM monitoring_tabs").fetchone()[0])
        if n_tabs <= 1:
            raise ValueError("Cannot delete the last monitoring tab")
        if not tab_exists(tid):
            return False
        conn.execute(
            """
            DELETE FROM monitoring_down_ack
            WHERE device_id IN (SELECT id FROM monitoring_targets WHERE tab_id = ?)
            """,
            (tid,),
        )
        conn.execute(
            """
            DELETE FROM monitoring_samples
            WHERE device_id IN (SELECT id FROM monitoring_targets WHERE tab_id = ?)
            """,
            (tid,),
        )
        conn.execute(
            """
            DELETE FROM monitoring_outages
            WHERE tab_id = ? OR device_id IN (SELECT id FROM monitoring_targets WHERE tab_id = ?)
            """,
            (tid, tid),
        )
        conn.execute("DELETE FROM monitoring_targets WHERE tab_id = ?", (tid,))
        conn.execute("DELETE FROM monitoring_site_groups WHERE tab_id = ?", (tid,))
        cur = conn.execute("DELETE FROM monitoring_tabs WHERE id = ?", (tid,))
        conn.commit()
        return int(getattr(cur, "rowcount", 0) or 0) > 0
    finally:
        conn.close()


def tab_exists(tab_id: int) -> bool:
    conn = get_conn()
    r = conn.execute(
        "SELECT id FROM monitoring_tabs WHERE id = ?", (int(tab_id),)
    ).fetchone()
    conn.close()
    return r is not None


def list_devices() -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT t.id, t.name, t.target, t.warn_latency_ms, t.tab_id, t.site_group_id,
               g.name AS site_group_name
        FROM monitoring_targets t
        LEFT JOIN monitoring_site_groups g ON g.id = t.site_group_id
        ORDER BY t.tab_id ASC, t.site_group_id NULLS LAST, g.name NULLS LAST,
                 t.name COLLATE NOCASE ASC, t.id ASC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_device(
    name: str,
    target: str,
    warn_latency_ms: Optional[float] = None,
    tab_id: Optional[int] = None,
    site_group_id: Optional[int] = None,
) -> int:
    name = validate_name(name)
    target = validate_target(target)
    if tab_id is None:
        raise ValueError("tab_id is required")
    tid = int(tab_id)
    if not tab_exists(tid):
        raise ValueError("Unknown tab")
    mode = get_tab_display_mode(tid)
    sgid: Optional[int] = None
    if site_group_id is not None:
        sgid = int(site_group_id)
    if mode == TAB_DISPLAY_HIGH_SITES:
        if sgid is None or sgid <= 0:
            raise ValueError("site_group_id is required for High Sites tabs")
    else:
        if sgid is not None and sgid > 0:
            raise ValueError("site_group_id is only allowed in High Sites mode")
        sgid = None

    if warn_latency_ms is None:
        w = DEFAULT_WARN_MS
    else:
        w = float(warn_latency_ms)
    if w < 1 or w > 60000:
        raise ValueError("Threshold must be between 1 and 60000 ms")

    conn = get_conn()
    try:
        if mode == TAB_DISPLAY_HIGH_SITES:
            gx = conn.execute(
                "SELECT id, tab_id FROM monitoring_site_groups WHERE id = ?",
                (int(sgid),),
            ).fetchone()
            if not gx:
                raise ValueError("Unknown site group")
            gtab = int(dict(gx).get("tab_id") or 0)
            if gtab != tid:
                raise ValueError("site_group_id does not belong to this tab")
        existing = conn.execute(
            "SELECT id FROM monitoring_targets WHERE tab_id = ? AND target = ?",
            (tid, target),
        ).fetchone()
        if existing:
            eid = int(existing[0])
            if sgid is not None:
                conn.execute(
                    """
                    UPDATE monitoring_targets
                    SET name = ?, warn_latency_ms = ?, site_group_id = ?
                    WHERE id = ?
                    """,
                    (name, w, sgid, eid),
                )
            else:
                conn.execute(
                    """
                    UPDATE monitoring_targets
                    SET name = ?, warn_latency_ms = ?
                    WHERE id = ?
                    """,
                    (name, w, eid),
                )
            conn.commit()
            return eid
        row = conn.execute(
            """
            INSERT INTO monitoring_targets (name, target, warn_latency_ms, created_at, tab_id, site_group_id)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (name, target, w, _now(), tid, sgid),
        ).fetchone()
        conn.commit()
        if not row:
            raise RuntimeError("Failed to create monitoring device")
        return int(row[0])
    finally:
        conn.close()


def delete_device(device_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM monitoring_targets WHERE id = ?", (int(device_id),))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0


def _split_space_tokens(s: str) -> List[str]:
    return [p for p in re.split(r"\s+", (s or "").strip()) if p]


def _parse_space_separated(s: str) -> Optional[Tuple[str, str, Optional[float]]]:
    """name target [warn_ms] separated by spaces (only if line has no tab, comma, or pipe)."""
    parts = _split_space_tokens(s)
    n = len(parts)
    if n <= 1:
        return None
    if n == 2:
        p0, p1 = parts[0], parts[1]
        try:
            w = float(p1)
        except (TypeError, ValueError):
            return (p0, p1, None)
        if IPV4_TOKEN_RE.match(p0):
            return (p0, p0, w)
        return (p0, p1, None)
    try:
        w = float(parts[-1])
    except (TypeError, ValueError):
        return (" ".join(parts[:-1]), parts[-1], None)
    return (" ".join(parts[:-2]), parts[-2], w)


def parse_import_line(line: str) -> Optional[Tuple[str, str, Optional[float]]]:
    """
    One line from a bulk import. Returns None to skip (blank, comment).
    Formats (first match wins):
      - tab:  name<TAB>ip  |  name<TAB>ip<TAB>warn_ms
      - pipe: name | ip  |  name | ip | warn_ms
      - csv:  name, ip  |  name, ip, warn_ms  (no commas in the name)
      - spaces: name ip [warn_ms]  (e.g. WN-TEST-2 10.10.10.2 50)
      - single token: used as both name and target (e.g. 8.8.8.8)
    """
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return None
    if "\t" in s:
        parts = [p.strip() for p in s.split("\t") if p.strip() != ""]
        if not parts:
            return None
        if len(parts) == 1:
            t = parts[0]
            return (t, t, None)
        if len(parts) == 2:
            return (parts[0], parts[1], None)
        try:
            w = float(parts[2])
        except (TypeError, ValueError):
            raise ValueError("invalid warn value (expected number in 3rd column)")
        return (parts[0], parts[1], w)
    if "|" in s:
        parts = [p.strip() for p in s.split("|") if p.strip() != ""]
        if not parts:
            return None
        if len(parts) == 1:
            t = parts[0]
            return (t, t, None)
        if len(parts) == 2:
            return (parts[0], parts[1], None)
        try:
            w = float(parts[2])
        except (TypeError, ValueError):
            raise ValueError("invalid warn value (expected number in 3rd segment)")
        return (parts[0], parts[1], w)
    if "," in s:
        parts = [p.strip() for p in s.split(",")]
        if len(parts) >= 3:
            try:
                w = float(parts[2])
            except (TypeError, ValueError):
                raise ValueError("invalid warn value (expected number in 3rd column)")
            return (parts[0], parts[1], w)
        if len(parts) == 2:
            return (parts[0], parts[1], None)
    if "\t" not in s and "|" not in s and "," not in s:
        sp = _parse_space_separated(s)
        if sp is not None:
            return sp
    return (s, s, None)


def _parse_hs_group_header(line: str) -> Optional[str]:
    """If line is ``[Bunker]`` style, return validated site name; else None."""
    s = (line or "").strip()
    if len(s) >= 2 and s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if inner:
            return validate_tab_name(inner)
    return None


def _import_devices_bulk_flat(
    tab_id: int,
    lines: List[str],
    default_warn_ms: Optional[float],
) -> Dict[str, Any]:
    tid = int(tab_id)
    created_ids: List[int] = []
    errors: List[Dict[str, Any]] = []
    skipped = 0
    for line_no, raw in enumerate(lines, start=1):
        try:
            parsed = parse_import_line(raw)
            if parsed is None:
                skipped += 1
                continue
            name, target, line_warn = parsed
            w_use = line_warn if line_warn is not None else default_warn_ms
            did = add_device(name, target, w_use, tab_id=tid)
            created_ids.append(did)
        except ValueError as e:
            errors.append({"line": line_no, "detail": str(e)})
    return {
        "all_succeeded": len(errors) == 0,
        "created": len(created_ids),
        "ids": created_ids,
        "skipped_lines": skipped,
        "errors": errors,
    }


def _import_devices_bulk_hs(
    tab_id: int,
    lines: List[str],
    default_warn_ms: Optional[float],
) -> Dict[str, Any]:
    tid = int(tab_id)
    created_ids: List[int] = []
    errors: List[Dict[str, Any]] = []
    skipped = 0
    current_group_id: Optional[int] = None
    for line_no, raw in enumerate(lines, start=1):
        try:
            s = (raw or "").strip()
            if not s or s.startswith("#"):
                skipped += 1
                continue
            hdr = _parse_hs_group_header(s)
            if hdr is not None:
                current_group_id = add_site_group(tid, hdr)
                continue
            if current_group_id is None:
                raise ValueError("add a [Site name] line before device rows (e.g. [Bunker])")
            parsed = parse_import_line(raw)
            if parsed is None:
                skipped += 1
                continue
            name, target, line_warn = parsed
            w_use = line_warn if line_warn is not None else default_warn_ms
            did = add_device(name, target, w_use, tab_id=tid, site_group_id=current_group_id)
            created_ids.append(did)
        except ValueError as e:
            errors.append({"line": line_no, "detail": str(e)})
    return {
        "all_succeeded": len(errors) == 0,
        "created": len(created_ids),
        "ids": created_ids,
        "skipped_lines": skipped,
        "errors": errors,
    }


def import_devices_bulk(
    tab_id: int,
    text: str,
    default_warn_ms: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Parse multi-line text and create devices on tab_id.
    For tabs in **high_sites** mode, lines may start a section with ``[Site name]``;
    following device lines belong to that site until the next ``[...]`` header.
    """
    tid = int(tab_id)
    if not tab_exists(tid):
        raise ValueError("Unknown tab")
    lines = (text or "").splitlines()
    if get_tab_display_mode(tid) == TAB_DISPLAY_HIGH_SITES:
        return _import_devices_bulk_hs(tid, lines, default_warn_ms)
    return _import_devices_bulk_flat(tid, lines, default_warn_ms)


def measure_ping(host: str, wait_sec: int = 2, count: Optional[int] = None) -> Tuple[str, Optional[float]]:
    """
    Returns (state, latency_ms):
      state: 'up' | 'down'
      latency_ms: round-trip ms when up (last reply in batch), else None

    With count > 1, uses one ping subprocess; Linux returns success if any packet got a reply.
    """
    host = (host or "").strip()
    if not host:
        return ("down", None)
    wait_sec = max(1, min(10, int(wait_sec)))
    n = PINGS_PER_SAMPLE if count is None else int(count)
    n = max(1, min(10, n))
    spacing = PING_SPACING_SEC
    # Allow time for inter-probe spacing + per-reply waits (Linux ping sends -c probes spaced by -i).
    timeout_sec = int((max(0, n - 1)) * spacing + n * (wait_sec + 2) + 10)
    timeout_sec = max(wait_sec + 6, min(120, timeout_sec))
    try:
        proc = subprocess.run(
            [
                "ping",
                "-c",
                str(n),
                "-i",
                str(spacing),
                "-W",
                str(wait_sec),
                host,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return ("down", None)
    except FileNotFoundError:
        return ("down", None)

    blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        return ("down", None)
    # Last successful reply time (predictable when some packets are lost).
    ms = None
    for m in TIME_MS_RE.finditer(blob):
        try:
            ms = float(m.group(1))
        except ValueError:
            continue
    if ms is None:
        return ("down", None)
    return ("up", ms)


def classify(latency_ms: Optional[float], warn_ms: float, up: bool) -> str:
    if not up or latency_ms is None:
        return "down"
    if latency_ms > float(warn_ms):
        return "warn"
    return "ok"


def _apply_down_hysteresis(
    device_id: int,
    warn_ms: float,
    raw_up: bool,
    latency_ms: Optional[float],
) -> Tuple[str, bool, Optional[float]]:
    """
    Map raw ping outcome to reported level/up/latency using consecutive-failure hysteresis.
    """
    did = int(device_id)
    thr = DOWN_AFTER_CONSECUTIVE_FAILS

    if raw_up:
        _DOWN_STREAK[did] = 0
        level = classify(latency_ms, warn_ms, True)
        _STABLE_OK_WARN[did] = level
        if latency_ms is not None:
            _LAST_GOOD_LATENCY_MS[did] = float(latency_ms)
        return level, True, latency_ms

    streak = _DOWN_STREAK.get(did, 0) + 1
    _DOWN_STREAK[did] = streak

    if streak >= thr:
        return "down", False, None

    held = _STABLE_OK_WARN.get(did, "warn")
    if held not in ("ok", "warn"):
        held = "warn"
    lag = _LAST_GOOD_LATENCY_MS.get(did)
    return held, True, lag


def _fetch_latest_sample_row(device_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT ts, latency_ms, level FROM monitoring_samples
            WHERE device_id = ?
            ORDER BY ts DESC LIMIT 1
            """,
            (int(device_id),),
        ).fetchone()
        if not row:
            return None
        ts, lat, lvl = row[0], row[1], row[2]
        return {"ts": ts, "latency_ms": lat, "level": lvl}
    finally:
        conn.close()


def _status_snapshot_stale_no_icmp(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """UI poll path when sampling is disabled: last persisted row per device, no ping."""
    rows: List[Dict[str, Any]] = []
    for d in devices:
        did = int(d["id"])
        row = dict(d)
        ls = _fetch_latest_sample_row(did)
        if ls:
            lvl = str(ls.get("level") or "down")
            lat = ls.get("latency_ms")
            try:
                lat_f = float(lat) if lat is not None else None
            except (TypeError, ValueError):
                lat_f = None
            row["latency_ms"] = lat_f
            row["level"] = lvl
            row["up"] = lvl != "down"
            row["sample_ts"] = ls.get("ts")
        else:
            row["latency_ms"] = None
            row["level"] = "unknown"
            row["up"] = False
            row["sample_ts"] = None
        row["sampling_paused"] = True
        rows.append(row)
    return rows


def _status_snapshot_inner() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Returns (device rows, web push alert events: kind \"down\" | \"up\")."""
    devices = list_devices()
    if not devices:
        with _TRANSITION_LOCK:
            _PREV_LEVELS.clear()
            _DOWN_STREAK.clear()
            _STABLE_OK_WARN.clear()
            _LAST_GOOD_LATENCY_MS.clear()
            _DOWN_SINCE.clear()
            _HS_GROUP_ALARM.clear()
        return [], []  # rows, push_events

    if not is_monitoring_sampling_enabled():
        return _status_snapshot_stale_no_icmp(devices), []

    def work(d: Dict[str, Any]) -> Dict[str, Any]:
        state, lat = measure_ping(d["target"])
        raw_up = state == "up"
        row = dict(d)
        row["raw_up"] = raw_up
        row["latency_ms"] = lat if raw_up else None
        return row

    if len(devices) == 1:
        raw_rows = [work(devices[0])]
    else:
        max_workers = min(16, len(devices))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            raw_rows = list(ex.map(work, devices))

    ts = _now()
    rows: List[Dict[str, Any]] = []
    push_events: List[Dict[str, Any]] = []
    with _TRANSITION_LOCK:
        seen = set()
        for r in raw_rows:
            did = int(r["id"])
            seen.add(did)
            raw_up = bool(r.get("raw_up"))
            lat = r.get("latency_ms")
            if isinstance(lat, float) or lat is None:
                pass
            else:
                try:
                    lat = float(lat)
                except (TypeError, ValueError):
                    lat = None
            warn = float(r.get("warn_latency_ms") or DEFAULT_WARN_MS)
            level, up, out_lat = _apply_down_hysteresis(did, warn, raw_up, lat)
            del r["raw_up"]
            r["up"] = up
            r["latency_ms"] = out_lat
            r["level"] = level

            try:
                hs_gid = int(r.get("site_group_id") or 0)
            except (TypeError, ValueError):
                hs_gid = 0
            in_high_site = hs_gid > 0

            lvl = str(level or "down")
            old = _PREV_LEVELS.get(did)
            if old is not None and old != lvl:
                entry = {
                    "ts": ts,
                    "device_id": did,
                    "name": str(r.get("name") or ""),
                    "target": str(r.get("target") or ""),
                    "tab_id": int(r.get("tab_id") or 0),
                    "old_level": old,
                    "new_level": lvl,
                }
                # Do not record → down here: live "currently down" list covers that.
                if lvl != "down":
                    _TRANSITION_LOG.appendleft(entry)
                elif lvl == "down":
                    if not in_high_site:
                        push_events.append(
                            {
                                "kind": "down",
                                "device_id": did,
                                "name": str(r.get("name") or ""),
                                "target": str(r.get("target") or ""),
                            }
                        )
                if old == "down" and lvl != "down":
                    down_started = _DOWN_SINCE.get(did)
                    duration_seconds = None
                    start_dt = _parse_iso_utc(down_started)
                    end_dt = _parse_iso_utc(ts)
                    if start_dt is not None and end_dt is not None:
                        duration_seconds = max(0.0, (end_dt - start_dt).total_seconds())
                    outage_entry = {
                        "ts": ts,
                        "device_id": did,
                        "name": str(r.get("name") or ""),
                        "target": str(r.get("target") or ""),
                        "tab_id": int(r.get("tab_id") or 0),
                        "down_since": down_started,
                        "recovered_at": ts,
                        "duration_seconds": duration_seconds,
                        "duration_text": _format_outage_duration(duration_seconds),
                    }
                    ack = _get_ack_for_outage(did, str(down_started or ""))
                    if ack:
                        outage_entry["acked_by"] = str(ack.get("acked_by") or "")
                        outage_entry["acked_at"] = str(ack.get("acked_at") or "")
                        outage_entry["ack_delay_seconds"] = ack.get("ack_delay_seconds")
                    _insert_outage_event(outage_entry)
                    if not in_high_site:
                        push_events.append(
                            {
                                "kind": "up",
                                "device_id": did,
                                "name": str(r.get("name") or ""),
                                "target": str(r.get("target") or ""),
                                "new_level": lvl,
                                "outage_duration_seconds": duration_seconds,
                                "outage_duration_text": outage_entry["duration_text"],
                            }
                        )
            if lvl == "down":
                if old != "down":
                    _DOWN_SINCE[did] = ts
                r["down_since"] = _DOWN_SINCE.get(did)
            else:
                _DOWN_SINCE.pop(did, None)

            _PREV_LEVELS[did] = lvl
            rows.append(r)

        members_by_gid: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for row in rows:
            try:
                ig = int(row.get("site_group_id") or 0)
            except (TypeError, ValueError):
                ig = 0
            if ig > 0:
                members_by_gid[ig].append(row)
        for gid, members in members_by_gid.items():
            gname = str(members[0].get("site_group_name") or "").strip() or f"Site {gid}"
            tab_id0 = int(members[0].get("tab_id") or 0)
            any_down = any(str(m.get("level") or "") == "down" for m in members)
            prev = bool(_HS_GROUP_ALARM.get(gid, False))
            if any_down and not prev:
                push_events.append(
                    {
                        "kind": "hs_down",
                        "site_group_id": gid,
                        "name": gname,
                        "tab_id": tab_id0,
                    }
                )
                _HS_GROUP_ALARM[gid] = True
            elif (not any_down) and prev:
                push_events.append(
                    {
                        "kind": "hs_up",
                        "site_group_id": gid,
                        "name": gname,
                        "tab_id": tab_id0,
                    }
                )
                _HS_GROUP_ALARM[gid] = False
            elif any_down:
                _HS_GROUP_ALARM[gid] = True
            else:
                _HS_GROUP_ALARM[gid] = False

        for stale in list(_PREV_LEVELS.keys()):
            if stale not in seen:
                del _PREV_LEVELS[stale]
        for stale in list(_DOWN_STREAK.keys()):
            if stale not in seen:
                del _DOWN_STREAK[stale]
        for stale in list(_STABLE_OK_WARN.keys()):
            if stale not in seen:
                del _STABLE_OK_WARN[stale]
        for stale in list(_LAST_GOOD_LATENCY_MS.keys()):
            if stale not in seen:
                del _LAST_GOOD_LATENCY_MS[stale]
        for stale in list(_DOWN_SINCE.keys()):
            if stale not in seen:
                del _DOWN_SINCE[stale]
    return rows, push_events


def status_snapshot() -> List[Dict[str, Any]]:
    rows, _ = _status_snapshot_inner()
    return rows


def status_snapshot_and_push_events() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Same as status_snapshot, plus down/up transition events for Web Push."""
    return _status_snapshot_inner()


def status_snapshot_and_down_events() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Alias for status_snapshot_and_push_events (name kept for older call sites)."""
    return status_snapshot_and_push_events()


def recent_transition_events() -> List[Dict[str, Any]]:
    """
    Rolling transition log (newest first). Does not include → down; those are implied
    by devices with level == down until they recover.
    """
    with _TRANSITION_LOCK:
        return list(_TRANSITION_LOG)


def recent_outage_events() -> List[Dict[str, Any]]:
    """Recovered outage log (newest first), persisted in PostgreSQL."""
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT ts, device_id, name, target, tab_id, down_since, recovered_at,
                   duration_seconds, duration_text, acked_by, acked_at, ack_delay_seconds
            FROM monitoring_outages
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            (int(_OUTAGE_LOG_MAX),),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _insert_outage_event(entry: Dict[str, Any]) -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO monitoring_outages (
                ts, device_id, name, target, tab_id, down_since, recovered_at, duration_seconds, duration_text,
                acked_by, acked_at, ack_delay_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(entry.get("ts") or _now()),
                int(entry.get("device_id") or 0),
                str(entry.get("name") or ""),
                str(entry.get("target") or ""),
                int(entry.get("tab_id") or 0),
                entry.get("down_since"),
                str(entry.get("recovered_at") or entry.get("ts") or _now()),
                entry.get("duration_seconds"),
                str(entry.get("duration_text") or ""),
                str(entry.get("acked_by") or ""),
                str(entry.get("acked_at") or ""),
                entry.get("ack_delay_seconds"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _get_ack_for_outage(device_id: int, down_since: str) -> Dict[str, Any]:
    ds = str(down_since or "").strip()
    if not ds:
        return {}
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT acknowledged_by, acknowledged_at, ack_delay_seconds
            FROM monitoring_down_ack
            WHERE device_id = ? AND down_since = ?
            LIMIT 1
            """,
            (int(device_id), ds),
        ).fetchone()
        if not row:
            return {}
        return {
            "acked_by": str(row["acknowledged_by"] or ""),
            "acked_at": str(row["acknowledged_at"] or ""),
            "ack_delay_seconds": row["ack_delay_seconds"],
        }
    finally:
        conn.close()


def annotate_down_ack(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not rows:
        return rows
    out: List[Dict[str, Any]] = []
    for r in rows:
        rr = dict(r)
        if str(rr.get("level") or "") == "down":
            ack = _get_ack_for_outage(int(rr.get("id") or 0), str(rr.get("down_since") or ""))
            rr["acknowledged_by"] = str(ack.get("acked_by") or "")
            rr["acknowledged_at"] = str(ack.get("acked_at") or "")
            rr["ack_delay_seconds"] = ack.get("ack_delay_seconds")
        out.append(rr)
    return out


def acknowledge_down(device_id: int, username: str) -> Dict[str, Any]:
    did = int(device_id)
    user = str(username or "").strip()
    if did <= 0:
        raise ValueError("Invalid device id")
    if not user:
        raise ValueError("Invalid username")
    rows = status_snapshot()
    d = next((x for x in rows if int(x.get("id") or 0) == did), None)
    if not d:
        raise ValueError("Device not found")
    if str(d.get("level") or "") != "down":
        raise ValueError("Device is not currently down")
    down_since = str(d.get("down_since") or "").strip()
    if not down_since:
        raise ValueError("No active outage window found")
    acked_at = _now()
    delay_seconds = None
    ds_dt = _parse_iso_utc(down_since)
    ack_dt = _parse_iso_utc(acked_at)
    if ds_dt is not None and ack_dt is not None:
        delay_seconds = max(0.0, (ack_dt - ds_dt).total_seconds())
    conn = get_conn()
    try:
        try:
            conn.execute(
                """
                INSERT INTO monitoring_down_ack(device_id, down_since, acknowledged_by, acknowledged_at, ack_delay_seconds)
                VALUES(?, ?, ?, ?, ?)
                """,
                (did, down_since, user, acked_at, delay_seconds),
            )
            conn.commit()
            return {
                "ok": True,
                "acked": True,
                "device_id": did,
                "down_since": down_since,
                "acknowledged_by": user,
                "acknowledged_at": acked_at,
                "ack_delay_seconds": delay_seconds,
            }
        except Exception:
            pass
        row = conn.execute(
            """
            SELECT acknowledged_by, acknowledged_at, ack_delay_seconds
            FROM monitoring_down_ack
            WHERE device_id = ? AND down_since = ?
            LIMIT 1
            """,
            (did, down_since),
        ).fetchone()
        return {
            "ok": True,
            "acked": False,
            "device_id": did,
            "down_since": down_since,
            "acknowledged_by": str(row["acknowledged_by"] or "") if row else "",
            "acknowledged_at": str(row["acknowledged_at"] or "") if row else "",
            "ack_delay_seconds": row["ack_delay_seconds"] if row else None,
        }
    finally:
        conn.close()


def record_sample_cycle() -> List[Dict[str, Any]]:
    """Record one timestamped sample row per device; returns Web Push alert events."""
    if not is_monitoring_sampling_enabled():
        return []
    rows, push_events = _status_snapshot_inner()
    if not rows:
        return push_events
    ts = _now()
    conn = get_conn()
    try:
        for r in rows:
            conn.execute(
                """
                INSERT INTO monitoring_samples (device_id, ts, latency_ms, level)
                VALUES (?, ?, ?, ?)
                """,
                (int(r["id"]), ts, r.get("latency_ms"), str(r.get("level") or "down")),
            )
        conn.commit()
    finally:
        conn.close()
    prune_old_samples(SAMPLE_RETENTION_HOURS)
    prune_old_outages(OUTAGE_RETENTION_DAYS)
    return push_events


def prune_old_samples(retention_hours: float) -> None:
    if retention_hours <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(hours=float(retention_hours))
    cutoff_s = cutoff.isoformat(timespec="seconds") + "Z"
    conn = get_conn()
    conn.execute("DELETE FROM monitoring_samples WHERE ts < ?", (cutoff_s,))
    conn.commit()
    conn.close()


def prune_old_outages(retention_days: float) -> None:
    if retention_days <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(days=float(retention_days))
    cutoff_s = cutoff.isoformat(timespec="seconds") + "Z"
    conn = get_conn()
    conn.execute("DELETE FROM monitoring_outages WHERE ts < ?", (cutoff_s,))
    conn.commit()
    conn.close()


def fetch_history(device_id: int, hours: float = 12.0) -> Optional[List[Dict[str, Any]]]:
    conn = get_conn()
    try:
        exists = conn.execute(
            "SELECT id FROM monitoring_targets WHERE id = ?", (int(device_id),)
        ).fetchone()
        if not exists:
            return None
        cutoff_dt = datetime.utcnow() - timedelta(hours=float(hours))
        cutoff_s = cutoff_dt.isoformat(timespec="seconds") + "Z"
        rows = conn.execute(
            """
            SELECT ts, latency_ms, level
            FROM monitoring_samples
            WHERE device_id = ? AND ts >= ?
            ORDER BY ts ASC
            """,
            (int(device_id), cutoff_s),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "ts": str(r["ts"]),
                    "latency_ms": r["latency_ms"],
                    "level": str(r["level"] or ""),
                }
            )
        return out
    finally:
        conn.close()
