# Backhaul link monitoring (Side A / Side B edge routers, IPAM DB)
import logging
import os
import re
import secrets
import threading
import socket
import sqlite3
import subprocess
from pathlib import Path
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import edge_routers
import ipam
import db_runtime
import monitoring

try:
    import psycopg
except ImportError:  # pragma: no cover
    psycopg = None

LOG = logging.getLogger("mtr.backhauls")

_STANDBY_SNMP_DISABLED_MSG = (
    "SNMP probes are disabled on standby (MONITORING_SAMPLING_ENABLED=0). "
    "Use Promote Standby or set MONITORING_SAMPLING_ENABLED=1 in .env.compose."
)


def _require_snmp_probes_enabled() -> None:
    """Block snmpget/snmpwalk to customer gear when live probing is off (DR standby)."""
    if not monitoring.is_monitoring_sampling_enabled():
        raise ValueError(_STANDBY_SNMP_DISABLED_MSG)

# UI utilisation: 80% warn, 90% crit (global; per-link only max_mbps is stored)
WARN_FRAC = float(os.getenv("BACKHAUL_WARN_FRAC", "0.80"))
CRIT_FRAC = float(os.getenv("BACKHAUL_CRIT_FRAC", "0.90"))

PREV_IFACE: Dict[str, Tuple[float, int, int]] = {}
_EXEC = ThreadPoolExecutor(max_workers=8)

# snmpwalk from ".1" walks mib-2 before enterprises (.1.3.6.1.4.1.*); keep high enough for vendor OIDs.
SNMP_WALK_MAX_ROWS_DEFAULT = int(os.getenv("SNMP_WALK_MAX_ROWS", "1200"))
SNMP_WALK_MAX_ROWS_CAP = int(os.getenv("SNMP_WALK_MAX_ROWS_CAP", "3000"))
# snmpwalk: whole-process timeout (large trees / slow links); agent -t/-r reduce random UDP timeouts.
SNMP_WALK_SUBPROCESS_TIMEOUT_SEC = float(os.getenv("SNMP_WALK_SUBPROCESS_TIMEOUT_SEC", "120"))
SNMP_WALK_AGENT_TIMEOUT_SEC = max(1, min(120, int(os.getenv("SNMP_WALK_AGENT_TIMEOUT_SEC", "5"))))
SNMP_WALK_AGENT_RETRIES = max(0, min(10, int(os.getenv("SNMP_WALK_AGENT_RETRIES", "2"))))
# snmptranslate per OID during walk (parallelized so total time stays under reverse-proxy limits).
SNMP_WALK_TRANSLATE_TIMEOUT_SEC = float(os.getenv("SNMP_WALK_TRANSLATE_TIMEOUT_SEC", "1.5"))
SNMP_WALK_TRANSLATE_WORKERS = max(1, min(32, int(os.getenv("SNMP_WALK_TRANSLATE_WORKERS", "12"))))

# Shorter monitor-traffic duration = faster overview (RouterOS accepts fractional seconds on v7).
def _monitor_duration_sec() -> float:
    return min(5.0, max(0.2, float(os.getenv("BACKHAUL_MONITOR_DURATION_SEC", "0.4"))))

IFACE_TYPE_OK = frozenset({"ether", "vlan"})

# Drop dynamic / tunnel / ppp family by name (in addition to type filter)
IFACE_NAME_EXCLUDE = re.compile(
    r"ppp|l2tp|pptp|ppoe|gre|eoip|ipip|6to4|wireguard|wg\s|veth|ovpn|sstp|l2",
    re.I,
)

NAME_RE = re.compile(r'\bname="([^"]+)"')
NAME_RE2 = re.compile(r"\bname=([A-Za-z0-9._:\-]+)\b")
TYPE_RE = re.compile(r'\btype="([^"]+)"')
TYPE_RE2 = re.compile(r"\btype=([A-Za-z0-9_]+)\b")
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

# Vendor MIBs uploaded via UI; snmptranslate searches here in addition to system MIBs.
SNMP_USER_MIB_DIR = os.getenv("SNMP_USER_MIB_DIR", "/app/data/snmp-user-mibs")
SNMP_USER_MIB_MAX_BYTES = int(os.getenv("SNMP_USER_MIB_MAX_BYTES", str(2 * 1024 * 1024)))
MIB_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\.(?:mib|txt|my)$")
# MODULE-IDENTITY / OBJECT IDENTIFIER assignments rooted at iso.org.dod.internet.private.enterprises (iana PEN).
MIB_ENTERPRISE_ASSIGN_RE = re.compile(r"::=\s*{\s*enterprises\s+(\d+)", re.I | re.MULTILINE)


def snmp_user_mib_dir() -> Path:
    return Path(SNMP_USER_MIB_DIR).expanduser()


def snmp_user_mib_dir_resolved() -> str:
    try:
        return str(snmp_user_mib_dir().resolve())
    except Exception:
        return SNMP_USER_MIB_DIR


def list_snmp_user_mibs() -> List[Dict[str, Any]]:
    d = snmp_user_mib_dir()
    if not d.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    try:
        for ent in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if not ent.is_file() or ent.name.startswith("."):
                continue
            try:
                st = ent.stat()
                out.append({"name": ent.name, "size": int(st.st_size), "mtime": int(st.st_mtime)})
            except OSError:
                continue
    except OSError:
        return []
    return out


def _sanitize_mib_filename(name: str) -> str:
    base = os.path.basename(str(name or "")).strip()
    if not MIB_FILENAME_RE.match(base):
        raise ValueError("MIB filename must end with .mib, .txt, or .my and use only safe characters")
    return base


def _looks_like_mib_text(head: str) -> bool:
    u = head.upper()
    return "DEFINITIONS" in u or "IMPORTS" in u or "MODULE-IDENTITY" in u or "::=" in head


def save_snmp_user_mib(filename: str, data: bytes) -> Dict[str, Any]:
    if len(data) > SNMP_USER_MIB_MAX_BYTES:
        raise ValueError(f"MIB file too large (max {SNMP_USER_MIB_MAX_BYTES} bytes)")
    fn = _sanitize_mib_filename(filename)
    head = data[:8192].decode("utf-8", errors="replace")
    if not _looks_like_mib_text(head):
        raise ValueError("File does not look like a MIB module (SMIv1/SMIv2 text)")
    dest_dir = snmp_user_mib_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / fn
    dest.write_bytes(data)
    return {"name": fn, "size": len(data)}


def delete_snmp_user_mib(filename: str) -> bool:
    fn = _sanitize_mib_filename(filename)
    dest = snmp_user_mib_dir() / fn
    try:
        dest.unlink()
        return True
    except FileNotFoundError:
        return False


def scan_uploaded_mibs_enterprise_roots() -> Tuple[List[str], List[Dict[str, Any]]]:
    """Scan all uploaded MIB text files for `::= { enterprises N ... }` assignments.

    Returns ``(flat_unique_roots, per_file_detail)`` where each detail row is
    ``{"file": "name.mib", "roots": [".1.3.6.1.4.1.N", ...]}``.
    """
    pens_global: set[int] = set()
    per_file: List[Dict[str, Any]] = []
    d = snmp_user_mib_dir()
    if not d.is_dir():
        return [], []
    suf = {".mib", ".txt", ".my"}
    try:
        for ent in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if not ent.is_file() or ent.name.startswith("."):
                continue
            if ent.suffix.lower() not in suf:
                continue
            try:
                text = ent.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            pens_file: set[int] = set()
            for m in MIB_ENTERPRISE_ASSIGN_RE.finditer(text):
                try:
                    n = int(m.group(1))
                except (TypeError, ValueError):
                    continue
                if 1 <= n <= 4_294_967_295:
                    pens_file.add(n)
                    pens_global.add(n)
            if pens_file:
                per_file.append(
                    {
                        "file": ent.name,
                        "roots": [f".1.3.6.1.4.1.{n}" for n in sorted(pens_file)],
                    }
                )
    except OSError:
        return [], []
    flat = [f".1.3.6.1.4.1.{n}" for n in sorted(pens_global)]
    return flat, per_file


def detect_vendor_base_oids_from_uploaded_mibs() -> List[str]:
    """Sorted unique enterprise roots across all uploaded MIBs (see ``scan_uploaded_mibs_enterprise_roots``)."""
    flat, _ = scan_uploaded_mibs_enterprise_roots()
    return flat


def _snmp_net_snmp_env() -> Dict[str, str]:
    """Net-SNMP on Debian disables MIB loading via snmp.conf (`mibs :`); set MIBS so translation works."""
    env = os.environ.copy()
    env["MIBS"] = "ALL"
    return env


def _snmp_user_mib_translate_prefix() -> Optional[str]:
    """Net-SNMP `-M` argument: `+DIR` prepends DIR to the MIB search path."""
    d = snmp_user_mib_dir()
    if not d.is_dir():
        return None
    try:
        has_file = any(p.is_file() for p in d.iterdir() if not p.name.startswith("."))
    except OSError:
        return None
    if not has_file:
        return None
    try:
        return "+" + str(d.resolve())
    except Exception:
        return "+" + str(d)


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def init_db() -> None:
    db_runtime.init_postgres_schema()
    conn = ipam.get_conn()
    try:
        # Ensure links table matches runtime code expectations.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backhaul_links (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                name TEXT NOT NULL,
                router_a_id BIGINT,
                router_b_id BIGINT,
                iface_a TEXT NOT NULL DEFAULT '',
                iface_b TEXT NOT NULL DEFAULT '',
                max_mbps DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(router_a_id) REFERENCES edge_routers(id) ON DELETE CASCADE,
                FOREIGN KEY(router_b_id) REFERENCES edge_routers(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS router_a_id BIGINT")
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS router_b_id BIGINT")
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS iface_a TEXT")
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS iface_b TEXT")
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS max_mbps DOUBLE PRECISION")
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS created_at TEXT")
        conn.execute("ALTER TABLE backhaul_links ADD COLUMN IF NOT EXISTS name TEXT")
        # Migrate old column naming from early postgres schema attempts.
        try:
            conn.execute("UPDATE backhaul_links SET router_a_id = a_router_id WHERE router_a_id IS NULL AND a_router_id IS NOT NULL")
        except Exception:
            pass
        try:
            conn.execute("UPDATE backhaul_links SET router_b_id = b_router_id WHERE router_b_id IS NULL AND b_router_id IS NOT NULL")
        except Exception:
            pass
        conn.execute("UPDATE backhaul_links SET iface_a = COALESCE(iface_a, '') WHERE iface_a IS NULL")
        conn.execute("UPDATE backhaul_links SET iface_b = COALESCE(iface_b, '') WHERE iface_b IS NULL")
        conn.execute("UPDATE backhaul_links SET max_mbps = COALESCE(max_mbps, 0) WHERE max_mbps IS NULL")
        conn.execute("UPDATE backhaul_links SET created_at = COALESCE(created_at, '') WHERE created_at IS NULL")
        conn.execute("UPDATE backhaul_links SET name = COALESCE(name, '') WHERE name IS NULL")

        # Ensure radios table accepts existing runtime inserts (no required link_id).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backhaul_radios (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                ssh_port INTEGER NOT NULL DEFAULT 22,
                ssh_user TEXT NOT NULL,
                ssh_password TEXT NOT NULL,
                snmp_port INTEGER NOT NULL DEFAULT 161,
                snmp_version TEXT NOT NULL DEFAULT '2c',
                snmp_community TEXT NOT NULL DEFAULT 'public',
                created_at TEXT NOT NULL DEFAULT '',
                command_results TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute("ALTER TABLE backhaul_radios ADD COLUMN IF NOT EXISTS command_results TEXT")
        conn.execute("UPDATE backhaul_radios SET command_results = '{}' WHERE command_results IS NULL")
        # Safe on fresh schema; ignore if link_id does not exist.
        try:
            conn.execute("ALTER TABLE backhaul_radios ALTER COLUMN link_id DROP NOT NULL")
        except Exception:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backhaul_radio_commands (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                radio_id BIGINT NOT NULL REFERENCES backhaul_radios(id) ON DELETE CASCADE,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backhaul_radio_oids (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                radio_id BIGINT NOT NULL REFERENCES backhaul_radios(id) ON DELETE CASCADE,
                oid TEXT NOT NULL,
                label TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # Older DBs may have added created_at NOT NULL without an application default — backfill and relax default.
        try:
            conn.execute(
                "ALTER TABLE backhaul_radio_oids ADD COLUMN IF NOT EXISTS created_at TEXT NOT NULL DEFAULT ''"
            )
        except Exception:
            try:
                conn.execute("ALTER TABLE backhaul_radio_oids ADD COLUMN IF NOT EXISTS created_at TEXT")
            except Exception:
                pass
        try:
            conn.execute(
                "UPDATE backhaul_radio_oids SET created_at = ? WHERE created_at IS NULL",
                (_now(),),
            )
        except Exception:
            pass
        try:
            conn.execute(
                "ALTER TABLE backhaul_radio_oids ALTER COLUMN created_at SET DEFAULT ''"
            )
        except Exception:
            pass
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backhaul_radio_samples (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                radio_id BIGINT NOT NULL REFERENCES backhaul_radios(id) ON DELETE CASCADE,
                ts TEXT NOT NULL,
                command_results TEXT
            )
            """
        )
        # Legacy minimal schema above; widen for SNMP RSSI / throughput snapshots (idempotent).
        for stmt in (
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS rssi_dbm DOUBLE PRECISION",
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS iface_count INTEGER",
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS total_rx_mbps DOUBLE PRECISION",
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS total_tx_mbps DOUBLE PRECISION",
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS raw_rssi TEXT",
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS raw_ifaces TEXT",
            "ALTER TABLE backhaul_radio_samples ADD COLUMN IF NOT EXISTS error TEXT",
        ):
            try:
                conn.execute(stmt)
            except Exception:
                pass
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backhaul_radio_metric_values (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                radio_id BIGINT NOT NULL REFERENCES backhaul_radios(id) ON DELETE CASCADE,
                ts TEXT NOT NULL,
                metric_key TEXT NOT NULL DEFAULT '',
                metric_label TEXT NOT NULL DEFAULT '',
                value DOUBLE PRECISION NOT NULL
            )
            """
        )
        # Deployments that added metric_key NOT NULL separately — backfill from metric_label.
        try:
            conn.execute(
                "ALTER TABLE backhaul_radio_metric_values ADD COLUMN IF NOT EXISTS metric_key TEXT"
            )
        except Exception:
            pass
        try:
            conn.execute(
                "UPDATE backhaul_radio_metric_values SET metric_key = COALESCE(metric_label, '') "
                "WHERE metric_key IS NULL OR metric_key = ''"
            )
        except Exception:
            pass
        try:
            conn.execute(
                "ALTER TABLE backhaul_radio_metric_values ALTER COLUMN metric_key SET DEFAULT ''"
            )
        except Exception:
            pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backhaul_rba ON backhaul_links(router_a_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backhaul_rbb ON backhaul_links(router_b_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backhaul_radio_cmd_radio ON backhaul_radio_commands(radio_id, position, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backhaul_radio_oids_radio ON backhaul_radio_oids(radio_id, position, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backhaul_radio_samples_radio_ts ON backhaul_radio_samples(radio_id, ts DESC)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_backhaul_radio_metric_values_rtv "
            "ON backhaul_radio_metric_values(radio_id, metric_label, ts DESC)"
        )
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_backhaul_radio_metric_mk "
                "ON backhaul_radio_metric_values(radio_id, metric_key, ts DESC)"
            )
        except Exception:
            pass
        conn.commit()
    finally:
        conn.close()
def _validate_name(n: str) -> str:
    s = (n or "").strip()
    if not s or len(s) > 120:
        raise ValueError("Name is required (max 120 characters)")
    return s


def _validate_mbps(m: Any) -> float:
    v = float(m)
    if v < 0.1 or v > 1_000_000:
        raise ValueError("max_mbps must be between 0.1 and 1,000,000")
    return v


def list_backhauls() -> List[Dict[str, Any]]:
    conn = ipam.get_conn()
    rows = conn.execute(
        """
        SELECT b.id, b.name, b.router_a_id, b.router_b_id, b.iface_a, b.iface_b, b.max_mbps, b.created_at,
               a.router_host AS host_a, b2.router_host AS host_b,
               la.name AS loc_a, lb.name AS loc_b
        FROM backhaul_links b
        JOIN edge_routers a ON a.id = b.router_a_id
        JOIN edge_routers b2 ON b2.id = b.router_b_id
        JOIN ipam_locations la ON la.id = a.location_id
        JOIN ipam_locations lb ON lb.id = b2.location_id
        ORDER BY b.name COLLATE NOCASE ASC, b.id ASC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_backhaul(
    name: str,
    router_a_id: int,
    router_b_id: int,
    iface_a: str,
    iface_b: str,
    max_mbps: Any,
) -> int:
    n = _validate_name(name)
    if int(router_a_id) == int(router_b_id):
        raise ValueError("Side A and Side B must be different routers")
    if not edge_routers.get_router_credentials(int(router_a_id)):
        raise ValueError("Unknown router (A)")
    if not edge_routers.get_router_credentials(int(router_b_id)):
        raise ValueError("Unknown router (B)")
    ia = (iface_a or "").strip()
    ib = (iface_b or "").strip()
    if not ia or not ib:
        raise ValueError("Interface A and B are required")
    m = _validate_mbps(max_mbps)
    conn = ipam.get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO backhaul_links
            (name, router_a_id, router_b_id, iface_a, iface_b, max_mbps, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (n, int(router_a_id), int(router_b_id), ia, ib, m, _now()),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def delete_backhaul(bid: int) -> bool:
    conn = ipam.get_conn()
    cur = conn.execute("DELETE FROM backhaul_links WHERE id = ?", (int(bid),))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0


def get_backhaul(bid: int) -> Optional[Dict[str, Any]]:
    conn = ipam.get_conn()
    row = conn.execute(
        """
        SELECT b.id, b.name, b.router_a_id, b.router_b_id, b.iface_a, b.iface_b, b.max_mbps, b.created_at,
               a.router_host AS host_a, b2.router_host AS host_b
        FROM backhaul_links b
        JOIN edge_routers a ON a.id = b.router_a_id
        JOIN edge_routers b2 ON b2.id = b.router_b_id
        WHERE b.id = ?
        """,
        (int(bid),),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _ping_ms(host: str) -> Optional[float]:
    h = (host or "").strip()
    if not h:
        return None
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", h],
            capture_output=True,
            text=True,
            timeout=4,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    m = re.search(r"time=([\d.]+)\s*ms", (proc.stdout or "") + "\n" + (proc.stderr or ""), re.I)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _ssh_timeout_sec() -> int:
    return min(20, max(5, int(float(os.getenv("BACKHAUL_SSH_TIMEOUT", "12")))))


def _mikrotik_connect(router_id: int) -> Tuple[Any, Optional[str]]:
    """Open one SSH session (caller must close). Returns (client, error)."""
    try:
        import paramiko  # type: ignore
    except ImportError:
        return None, "paramiko not installed"
    cred = edge_routers.get_router_credentials(router_id)
    if not cred:
        return None, "router not found"
    host = str(cred.get("router_host") or "").strip()
    port = int(cred.get("ssh_port") or 22)
    user = str(cred.get("ssh_user") or "").strip()
    pw = str(cred.get("ssh_password") or "")
    to = _ssh_timeout_sec()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=pw,
            timeout=to,
            banner_timeout=to,
            auth_timeout=to,
            look_for_keys=False,
            allow_agent=False,
        )
        return client, None
    except socket.timeout:
        try:
            client.close()
        except Exception:
            pass
        return None, "SSH timeout"
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return None, str(e).strip()[:400]


def _mikrotik_exec_client(client: Any, command: str) -> Tuple[Optional[str], Optional[str]]:
    """Run one command on an existing MikroTik SSH session."""
    if not client:
        return None, "no ssh client"
    to = _ssh_timeout_sec()
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=to)
        raw = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return raw, err or None
    except socket.timeout:
        return None, "SSH exec timeout"
    except Exception as e:
        return None, str(e).strip()[:400]


def _ssh_exec_mikrotik(router_id: int, command: str) -> Tuple[Optional[str], Optional[str]]:
    """Single command: connect, exec, disconnect (legacy helper)."""
    client, cerr = _mikrotik_connect(int(router_id))
    if not client:
        return None, cerr
    try:
        return _mikrotik_exec_client(client, command)
    finally:
        try:
            client.close()
        except Exception:
            pass


def _rate_token_to_bps(tok: str) -> float:
    """Parse one RouterOS monitor-traffic token like '27.8kbps', '149.4kbps', '0bps'."""
    s = (tok or "").strip().replace(" ", "")
    if not s:
        return 0.0
    sl = s.lower()
    if sl in ("0bps", "0bit/s", "0"):
        return 0.0
    m = re.match(r"^([\d.]+)\s*([kKmMgG]?)\s*bps$", sl)
    if not m:
        return 0.0
    val = float(m.group(1))
    u = (m.group(2) or "").upper()
    mul = {"": 1.0, "K": 1e3, "M": 1e6, "G": 1e9}.get(u, 1.0)
    return val * mul


def _monitor_line_total_bps(line: str) -> float:
    """Sum all rate tokens after ':' on one monitor-traffic line (handles multi-column output)."""
    if ":" not in line:
        return 0.0
    rhs = line.split(":", 1)[1]
    toks = re.findall(r"[\d.]+\s*[kKmMgG]?bps", rhs, flags=re.I)
    return sum(_rate_token_to_bps(t) for t in toks) if toks else 0.0


def _monitor_traffic_bps(client: Any, iface: str) -> Optional[Tuple[float, float]]:
    """
    Instantaneous rx/tx bits per second by running /interface monitor-traffic (RouterOS 6/7).
    Uses max(main, fp) per direction — main-path and fp-* rates overlap; summing doubles throughput.
    """
    safe = (iface or "").strip().replace('"', "")
    if not safe:
        return None
    esc = safe.replace("\\", "\\\\").replace('"', '\\"')
    dur = _monitor_duration_sec()
    ds = f"{dur:.2f}".rstrip("0").rstrip(".")
    cmds = [
        f'/interface monitor-traffic [find name="{esc}"] duration={ds}',
        f'/interface monitor-traffic [find name={safe}] duration={ds}',
        f'/interface monitor-traffic "{esc}" duration={ds}',
        f"/interface monitor-traffic {safe} duration={ds}",
    ]
    best: Optional[Tuple[float, float]] = None
    for cmd in cmds:
        raw, err = _mikrotik_exec_client(client, cmd)
        blob = (raw or "") + "\n" + (err or "")
        if not raw or "invalid" in blob.lower():
            continue
        rx_main = rx_fp = tx_main = tx_fp = 0.0
        saw = False
        for line in raw.splitlines():
            ls = line.strip().lower()
            if ls.startswith("rx-bits-per-second"):
                rx_main += _monitor_line_total_bps(line)
                saw = True
            elif ls.startswith("fp-rx-bits-per-second"):
                rx_fp += _monitor_line_total_bps(line)
                saw = True
            elif ls.startswith("tx-bits-per-second"):
                tx_main += _monitor_line_total_bps(line)
                saw = True
            elif ls.startswith("fp-tx-bits-per-second"):
                tx_fp += _monitor_line_total_bps(line)
                saw = True
        if saw:
            total_rx = max(rx_main, rx_fp)
            total_tx = max(tx_main, tx_fp)
            best = (total_rx, total_tx)
            break
    return best


def _parse_uint_output(text: Optional[str]) -> Optional[int]:
    """RouterOS `get value-name=` often prints a bare integer."""
    if not text:
        return None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if re.match(r"^\d+$", s):
            return int(s)
        if re.match(r"^[\d\s]+$", s):
            return int(re.sub(r"\s+", "", s))
        m = re.match(r"^value:\s*(\d+)\s*$", s, re.I)
        if m:
            return int(m.group(1))
    m = re.search(r"\b([\d\s]{1,40})\b", text)
    if m and re.match(r"^[\d\s]+$", m.group(1).strip()):
        return int(re.sub(r"\s+", "", m.group(1)))
    m = re.search(r"\b(\d{1,20})\b", text)
    if m:
        return int(m.group(1))
    return None


def _extract_rx_tx_flex(raw: Optional[str], iface: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse rx-byte / tx-byte from print stats, print detail, etc. (RouterOS 6/7)."""
    if not raw:
        return None, None
    blob = raw
    rx: Optional[int] = None
    tx: Optional[int] = None
    # Match main-path counters only; fp-rx-byte= contains "rx-byte=" — use (?<!fp-). Stats may use spaced ints.
    def _u(g: str) -> int:
        return int(re.sub(r"\s+", "", g.strip()))

    for pat in (
        r"(?<!fp-)rx-byte=([\d\s]+)",
        r"(?<!fp-)rx-byte[=:]\s*([\d\s]+)",
        r'"rx-byte"\s*:\s*"?([\d\s]+)',
        r"\bRX-BYTE\s+([\d\s]+)",
        r"(?<!fp-)rx-byte\s+([\d\s]+)",
    ):
        m = re.search(pat, blob, re.I)
        if m:
            rx = _u(m.group(1))
            break
    for pat in (
        r"(?<!fp-)tx-byte=([\d\s]+)",
        r"(?<!fp-)tx-byte[=:]\s*([\d\s]+)",
        r'"tx-byte"\s*:\s*"?([\d\s]+)',
        r"\bTX-BYTE\s+([\d\s]+)",
        r"(?<!fp-)tx-byte\s+([\d\s]+)",
    ):
        m = re.search(pat, blob, re.I)
        if m:
            tx = _u(m.group(1))
            break
    if rx is None or tx is None:
        for line in blob.splitlines():
            if iface.lower() not in line.lower():
                continue
            nums = [int(x) for x in re.findall(r"\b(\d{4,})\b", line)]
            if len(nums) >= 2:
                return nums[0], nums[1]
    # Merge fast-path counters (ROS7): combine with main using max per direction (not sum).
    rfp_m = re.search(r"fp-rx-byte=([\d\s]+)", blob, re.I)
    tfp_m = re.search(r"fp-tx-byte=([\d\s]+)", blob, re.I)
    if rfp_m:
        rfp = _u(rfp_m.group(1))
        rx = rfp if rx is None else max(rx, rfp)
    if tfp_m:
        tfp = _u(tfp_m.group(1))
        tx = tfp if tx is None else max(tx, tfp)
    return rx, tx


def _parse_interface_rows(text: str) -> List[Dict[str, str]]:
    """Best-effort parse RouterOS /interface print output."""
    out: List[Dict[str, str]] = []
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "Columns:" in line:
            continue
        nm = NAME_RE.search(line) or NAME_RE2.search(line)
        tp = TYPE_RE.search(line) or TYPE_RE2.search(line)
        if nm and tp:
            name = nm.group(1)
            typ = tp.group(1).lower().strip('"')
            out.append({"name": name, "type": typ})
    return out


def _iface_allowed(name: str, typ: str) -> bool:
    t = (typ or "").lower().strip()
    if t not in IFACE_TYPE_OK:
        return False
    if IFACE_NAME_EXCLUDE.search(name or ""):
        return False
    return True


def list_router_interfaces_filtered(router_id: int) -> Tuple[List[Dict[str, str]], Optional[str]]:
    if not monitoring.is_monitoring_sampling_enabled():
        return [], (
            "Live router polling disabled on standby (MONITORING_SAMPLING_ENABLED=0). "
            "Promote to primary to load interfaces."
        )
    cmds = [
        '/interface print detail without-paging where type="ether"',
        '/interface print detail without-paging where type="vlan"',
        '/interface print detail without-paging',
    ]
    merged: Dict[str, str] = {}
    last_err = None
    for cmd in cmds:
        raw, err = _ssh_exec_mikrotik(int(router_id), cmd)
        if err and not raw:
            last_err = err
            continue
        rows = _parse_interface_rows(raw or "")
        for r in rows:
            merged[r["name"]] = r["type"]
        if rows and cmd != cmds[-1]:
            break
    items = [{"name": n, "type": t} for n, t in sorted(merged.items(), key=lambda x: x[0].lower())]
    filtered = [x for x in items if _iface_allowed(x["name"], x["type"])]
    if not filtered and last_err:
        return [], last_err
    return filtered, None


def _read_iface_byte_counters(client: Any, safe: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """
    Cumulative rx-byte / tx-byte using one open SSH session.
    Merges fp-* fast-path counters with main rx/tx get values (ROS7 fast path).
    """
    find_bits = [
        f'[find name="{safe}"]',
        f"[find name={safe}]",
        f'[find default-name="{safe}"]',
        f"[find default-name={safe}]",
    ]

    # --- A) /interface get value-name=rx-byte|tx-byte|fp-rx-byte|fp-tx-byte ---
    for fb in find_bits:
        raw_rx, _ = _mikrotik_exec_client(client, f"/interface get {fb} value-name=rx-byte")
        raw_tx, _ = _mikrotik_exec_client(client, f"/interface get {fb} value-name=tx-byte")
        raw_fprx, _ = _mikrotik_exec_client(client, f"/interface get {fb} value-name=fp-rx-byte")
        raw_fptx, _ = _mikrotik_exec_client(client, f"/interface get {fb} value-name=fp-tx-byte")
        rv = _parse_uint_output(raw_rx)
        tv = _parse_uint_output(raw_tx)
        if rv is not None and tv is not None:
            fprv = _parse_uint_output(raw_fprx)
            fptv = _parse_uint_output(raw_fptx)
            if fprv is not None:
                rv = max(rv, fprv)
            if fptv is not None:
                tv = max(tv, fptv)
            return rv, tv, None

    # --- B) Print variants (ROS 7 stats tables + detail) ---
    esc = safe.replace("\\", "\\\\").replace('"', '\\"')
    print_cmds = [
        f'/interface print stats-detail without-paging where name="{esc}"',
        f'/interface print stats-detail without-paging where name={safe}',
        f'/interface print stats without-paging where name="{esc}"',
        f'/interface print stats without-paging where name={safe}',
        f'/interface print detail without-paging where name="{esc}"',
        f'/interface print detail without-paging where name={safe}',
        f'/interface ethernet print stats-detail without-paging where name="{esc}"',
        f'/interface vlan print stats-detail without-paging where name="{esc}"',
    ]

    last_err = None
    for cmd in print_cmds:
        raw, err = _mikrotik_exec_client(client, cmd)
        if err and not raw:
            last_err = last_err or err
            continue
        rx, tx = _extract_rx_tx_flex(raw, safe)
        if rx is not None and tx is not None:
            return rx, tx, None
        if raw and ("invalid" in (raw + (err or "")).lower()):
            continue
        last_err = last_err or err

    msg = (
        (last_err + " · ") if last_err else ""
    ) + "could not parse rx-byte/tx-byte — check interface name on RouterOS 7"

    raw_all, _ = _mikrotik_exec_client(client, "/interface print stats-detail without-paging")
    if raw_all:
        for ln in raw_all.splitlines():
            if safe not in ln:
                continue
            rx, tx = _extract_rx_tx_flex(ln, safe)
            if rx is not None and tx is not None:
                return rx, tx, None

    return None, None, msg.strip(" · ")


def _quick_iface_exists(router_id: int, iface: str) -> Optional[str]:
    """
    Fast SSH check that an interface exists on the router (no monitor-traffic / full counters).
    Used for Side B while Side A carries throughput sampling.
    """
    safe = (iface or "").strip().replace('"', "")
    if not safe:
        return "empty interface"
    client, cerr = _mikrotik_connect(int(router_id))
    if not client:
        return cerr or "SSH connect failed"
    esc = safe.replace("\\", "\\\\").replace('"', '\\"')
    find_bits = (
        f'[find name="{safe}"]',
        f"[find name={safe}]",
        f'[find default-name="{safe}"]',
        f"[find default-name={safe}]",
    )
    try:
        for fb in find_bits:
            raw, err = _mikrotik_exec_client(client, f"/interface get {fb} value-name=name")
            blob = ((raw or "") + "\n" + (err or "")).lower()
            if "invalid" in blob or "no such" in blob or "failure" in blob:
                continue
            if (raw or "").strip():
                return None
        raw_p, err_p = _mikrotik_exec_client(
            client, f'/interface print detail without-paging where name="{esc}"'
        )
        blob_p = ((raw_p or "") + "\n" + (err_p or "")).lower()
        if raw_p and safe in (raw_p or "") and "invalid" not in blob_p:
            return None
        return "interface not found on router"
    finally:
        try:
            client.close()
        except Exception:
            pass


def _poll_iface_side(
    router_id: int, iface: str
) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[float], Optional[float]]:
    """
    Byte counters plus optional instantaneous bps from monitor-traffic (one SSH session).
    Returns: rx_byte, tx_byte, err, instant_rx_bps, instant_tx_bps
    """
    safe = (iface or "").strip().replace('"', "")
    if not safe:
        return None, None, "empty interface", None, None

    client, cerr = _mikrotik_connect(int(router_id))
    if not client:
        return None, None, cerr or "SSH connect failed", None, None

    try:
        inst = _monitor_traffic_bps(client, safe)
        instant_rx = inst[0] if inst else None
        instant_tx = inst[1] if inst else None
        rx, tx, err = _read_iface_byte_counters(client, safe)
        return rx, tx, err, instant_rx, instant_tx
    finally:
        try:
            client.close()
        except Exception:
            pass


def _get_iface_rx_tx(router_id: int, iface: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """Cumulative rx-byte and tx-byte (no monitor-traffic); for API callers that only need counters."""
    safe = (iface or "").strip().replace('"', "")
    if not safe:
        return None, None, "empty interface"
    client, cerr = _mikrotik_connect(int(router_id))
    if not client:
        return None, None, cerr or "SSH connect failed"
    try:
        return _read_iface_byte_counters(client, safe)
    finally:
        try:
            client.close()
        except Exception:
            pass


def _bps_from_delta(
    key: str, rx: Optional[int], tx: Optional[int]
) -> Tuple[Optional[float], Optional[float]]:
    """Return approx rx-bps and tx-bps since last sample (same physical iface direction)."""
    if rx is None or tx is None:
        return None, None
    now = time.monotonic()
    prev = PREV_IFACE.get(key)
    PREV_IFACE[key] = (now, rx, tx)
    if prev is None:
        return None, None
    dt = now - prev[0]
    if dt <= 0:
        return None, None
    drx = rx - prev[1]
    dtx = tx - prev[2]
    if drx < 0:
        drx += 2**64
    if dtx < 0:
        dtx += 2**64
    rx_bps = max(0.0, drx * 8.0 / dt)
    tx_bps = max(0.0, dtx * 8.0 / dt)
    return rx_bps, tx_bps


def _util_level(max_bits: float, cap_bps: float) -> str:
    if cap_bps <= 0:
        return "unknown"
    u = max_bits / cap_bps
    if u >= CRIT_FRAC:
        return "crit"
    if u >= WARN_FRAC:
        return "warn"
    return "ok"


def live_snapshot_for_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Blocking: collect one snapshot for a single backhaul row."""
    bid = int(row["id"])
    rid_a = int(row["router_a_id"])
    iface_a_name = row["iface_a"]
    rid_b = int(row["router_b_id"])
    iface_b_name = row["iface_b"]
    host_b = row["host_b"]
    cap_mbps = float(row["max_mbps"])
    cap_bps = cap_mbps * 1e6

    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_ping = pool.submit(_ping_ms, host_b)
        fut_a = pool.submit(_poll_iface_side, rid_a, iface_a_name)
        fut_b = pool.submit(_quick_iface_exists, rid_b, iface_b_name)
        latency_ms = fut_ping.result()
        rx_a, tx_a, err_a, inst_rx_a, inst_tx_a = fut_a.result()
        err_b = fut_b.result()

    key_a = f"{bid}:a:{iface_a_name}"
    if inst_rx_a is not None and inst_tx_a is not None:
        rx_bps_a = inst_rx_a
        tx_bps_a = inst_tx_a
        if rx_a is not None and tx_a is not None:
            PREV_IFACE[key_a] = (time.monotonic(), rx_a, tx_a)
    else:
        rx_bps_a, tx_bps_a = _bps_from_delta(key_a, rx_a, tx_a)

    # A-side: toward B ~= tx on A iface; return path ~= rx on A iface (sym naming for UI)
    toward_b_bps = tx_bps_a
    return_a_bps = rx_bps_a

    toward_b_mb = (toward_b_bps / 1e6) if toward_b_bps is not None else None
    return_a_mb = (return_a_bps / 1e6) if return_a_bps is not None else None

    max_dir_bits = 0.0
    if toward_b_bps is not None:
        max_dir_bits = max(max_dir_bits, toward_b_bps)
    if return_a_bps is not None:
        max_dir_bits = max(max_dir_bits, return_a_bps)

    ssh_down = bool(err_a or err_b)
    ping_down = latency_ms is None
    down = ping_down or ssh_down

    if down:
        util = "down"
    elif toward_b_bps is None or return_a_bps is None:
        util = "unknown"
    else:
        util = _util_level(max_dir_bits, cap_bps)

    return {
        "latency_ms": latency_ms,
        "toward_b_mbps": toward_b_mb,
        "return_from_b_mbps": return_a_mb,
        "util_level": util,
        "iface_a_ok": err_a is None,
        "iface_b_ok": err_b is None,
        "iface_a_err": err_a,
        "iface_b_err": err_b,
        "warn_frac": WARN_FRAC,
        "crit_frac": CRIT_FRAC,
        "cap_mbps": cap_mbps,
    }


def overview_live() -> List[Dict[str, Any]]:
    rows = list_backhauls()
    if not rows:
        return []

    if not monitoring.is_monitoring_sampling_enabled():
        out_paused: List[Dict[str, Any]] = []
        for r in rows:
            row = dict(r)
            cap_mbps = float(row["max_mbps"])
            row["live"] = {
                "latency_ms": None,
                "toward_b_mbps": None,
                "return_from_b_mbps": None,
                "util_level": "unknown",
                "iface_a_ok": False,
                "iface_b_ok": False,
                "iface_a_err": None,
                "iface_b_err": None,
                "warn_frac": WARN_FRAC,
                "crit_frac": CRIT_FRAC,
                "cap_mbps": cap_mbps,
                "polling_paused": True,
            }
            out_paused.append(row)
        return out_paused

    futures: Dict[Any, int] = {}
    for r in rows:
        fut = _EXEC.submit(live_snapshot_for_row, dict(r))
        futures[fut] = int(r["id"])
    snap_by_id: Dict[int, Dict[str, Any]] = {}
    for fut in as_completed(futures):
        bid = futures[fut]
        try:
            snap_by_id[bid] = fut.result()
        except Exception as e:
            snap_by_id[bid] = {"error": str(e), "util_level": "unknown"}

    out: List[Dict[str, Any]] = []
    for r in rows:
        bid = int(r["id"])
        row = dict(r)
        row["live"] = snap_by_id.get(bid, {})
        out.append(row)
    return out


def update_max_mbps(bid: int, max_mbps: Any) -> bool:
    m = _validate_mbps(max_mbps)
    conn = ipam.get_conn()
    cur = conn.execute(
        "UPDATE backhaul_links SET max_mbps = ? WHERE id = ?", (m, int(bid))
    )
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0


def _validate_host(v: str) -> str:
    s = (v or "").strip()
    if not s or len(s) > 253:
        raise ValueError("Host is required")
    if not re.match(r"^[a-zA-Z0-9.\-:]+$", s):
        raise ValueError("Invalid host")
    return s


def _validate_port(v: Any) -> int:
    try:
        p = int(v)
    except (TypeError, ValueError) as e:
        raise ValueError("Invalid port (must be 1–65535)") from e
    if p < 1 or p > 65535:
        raise ValueError("Invalid port (must be 1–65535)")
    return p


def _coerce_scalar_int(row: Any) -> Optional[int]:
    """First column or id/lastval from a PgCompat Row (RETURNING / lastval())."""
    if row is None:
        return None
    try:
        v = row[0]
        if v is not None:
            return int(v)
    except Exception:
        pass
    if hasattr(row, "get"):
        for key in ("id", "lastval"):
            try:
                v = row.get(key)
                if v is not None:
                    return int(v)
            except Exception:
                continue
    return None


def _insert_returned_radio_id(cur: Any, row: Optional[Any]) -> int:
    rid = _coerce_scalar_int(row)
    if rid is not None:
        return rid
    cur.execute("SELECT lastval() AS id")
    row2 = cur.fetchone()
    rid = _coerce_scalar_int(row2)
    if rid is None:
        raise ValueError(
            "Could not read new radio id after insert (RETURNING/lastval empty). "
            "Check PostgreSQL driver and backhaul_radios schema."
        )
    return rid


def list_radios() -> List[Dict[str, Any]]:
    conn = ipam.get_conn()
    rows = conn.execute(
        """
        SELECT id, name, host, ssh_port, ssh_user, snmp_port, snmp_version, snmp_community, created_at
        FROM backhaul_radios
        ORDER BY name COLLATE NOCASE ASC, id ASC
        """
    ).fetchall()
    cmd_rows = conn.execute(
        """
        SELECT id, radio_id, label, command, position
        FROM backhaul_radio_commands
        ORDER BY radio_id ASC, position ASC, id ASC
        """
    ).fetchall()
    oid_rows = conn.execute(
        """
        SELECT id, radio_id, oid, label, position
        FROM backhaul_radio_oids
        ORDER BY radio_id ASC, position ASC, id ASC
        """
    ).fetchall()
    conn.close()
    by_radio: Dict[int, List[Dict[str, Any]]] = {}
    for r in cmd_rows:
        rr = dict(r)
        by_radio.setdefault(int(rr["radio_id"]), []).append(
            {"id": rr["id"], "label": rr["label"], "command": rr["command"], "position": rr["position"]}
        )
    out = []
    by_oid: Dict[int, List[Dict[str, Any]]] = {}
    for r in oid_rows:
        rr = dict(r)
        by_oid.setdefault(int(rr["radio_id"]), []).append(
            {"id": rr["id"], "oid": rr["oid"], "label": rr["label"], "position": rr["position"]}
        )
    for r in rows:
        d = dict(r)
        d["commands"] = by_radio.get(int(d["id"]), [])
        d["oids"] = by_oid.get(int(d["id"]), [])
        out.append(d)
    return out


def add_radio(payload: Dict[str, Any]) -> int:
    p = payload or {}
    name = _validate_name(str(p.get("name") or ""))
    host = _validate_host(str(p.get("host") or ""))
    port = 22
    user = ""
    pw = ""
    snmp_port = _validate_port(p.get("snmp_port") or 161)
    snmp_version = str(p.get("snmp_version") or "2c").strip().lower()
    if snmp_version not in ("1", "2c"):
        raise ValueError("SNMP version must be 1 or 2c")
    snmp_community = str(p.get("snmp_community") or "").strip()
    if not snmp_community:
        raise ValueError("SNMP community is required")
    norm_cmds: List[Tuple[str, str, int]] = []
    oids = p.get("oids")
    norm_oids: List[Tuple[str, str, int]] = []
    if isinstance(oids, list):
        for i, o in enumerate(oids):
            if not isinstance(o, dict):
                continue
            oid = str(o.get("oid") or "").strip()
            lab = str(o.get("label") or "").strip() or oid
            if not oid:
                continue
            norm_oids.append((oid[:200], lab[:120], i))
    if not norm_oids:
        raise ValueError("Select at least one SNMP OID to monitor")
    conn = ipam.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO backhaul_radios
            (name, host, ssh_port, ssh_user, ssh_password, snmp_port, snmp_version, snmp_community, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (name, host, port, user, pw, snmp_port, snmp_version, snmp_community, _now()),
        )
        row = cur.fetchone()
        rid = _insert_returned_radio_id(cur, row)
        # Radio monitoring is SNMP-first; SSH command rows are intentionally unused.
        for oid, lab, pos in norm_oids:
            cur.execute(
                """
                INSERT INTO backhaul_radio_oids (radio_id, oid, label, position, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (rid, oid, lab, pos, _now()),
            )
        conn.commit()
        return rid
    except ValueError:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        LOG.exception("add_radio database failure name=%s host=%s", name, host)
        if psycopg is not None and isinstance(e, psycopg.Error):
            diag = getattr(e, "diag", None)
            hint = getattr(diag, "message_primary", None) if diag else None
            msg = (hint or str(e)).strip()
            raise ValueError(msg[:800] if msg else "Database rejected radio row (see server logs).") from None
        raise
    finally:
        conn.close()


def _radio_exists(radio_id: int) -> bool:
    conn = ipam.get_conn()
    try:
        r = conn.execute("SELECT 1 FROM backhaul_radios WHERE id = ?", (int(radio_id),)).fetchone()
        return r is not None
    finally:
        conn.close()


def append_radio_oids(radio_id: int, payload_oids: Any) -> int:
    """Append SNMP OID rows; skips duplicates (same oid string already on this radio)."""
    rid = int(radio_id)
    if not _radio_exists(rid):
        raise ValueError("Radio not found")
    rows = _get_radio_oids(rid)
    have = {str(x.get("oid") or "").strip() for x in rows}
    max_pos = max((int(x.get("position") or 0) for x in rows), default=-1)
    norm: List[Tuple[str, str, int]] = []
    if isinstance(payload_oids, list):
        for i, o in enumerate(payload_oids):
            if not isinstance(o, dict):
                continue
            oid = str(o.get("oid") or "").strip()
            lab = str(o.get("label") or "").strip() or oid
            if not oid or oid in have:
                continue
            norm.append((oid[:200], lab[:120], max_pos + 1 + len(norm)))
            have.add(oid)
    if not norm:
        raise ValueError("No new OIDs to append (duplicates or empty list)")
    conn = ipam.get_conn()
    try:
        cur = conn.cursor()
        for oid, lab, pos in norm:
            cur.execute(
                """
                INSERT INTO backhaul_radio_oids (radio_id, oid, label, position, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (rid, oid, lab, pos, _now()),
            )
        conn.commit()
        return len(norm)
    finally:
        conn.close()


def update_radio_oid_label(radio_id: int, row_id: int, label: str) -> bool:
    lab = str(label or "").strip()
    if not lab:
        raise ValueError("Display name is required")
    if len(lab) > 120:
        raise ValueError("Display name max 120 characters")
    conn = ipam.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT oid FROM backhaul_radio_oids WHERE id = ? AND radio_id = ?",
            (int(row_id), int(radio_id)),
        )
        orow = cur.fetchone()
        oid_k = ""
        if orow:
            if hasattr(orow, "get"):
                oid_k = str(orow.get("oid") or "").strip()
            else:
                oid_k = str(orow[0] or "").strip()
        cur.execute(
            """
            UPDATE backhaul_radio_oids SET label = ?
            WHERE id = ? AND radio_id = ?
            """,
            (lab, int(row_id), int(radio_id)),
        )
        n = int(cur.rowcount or 0)
        if n > 0 and oid_k:
            cur.execute(
                """
                UPDATE backhaul_radio_metric_values SET metric_label = ?
                WHERE radio_id = ? AND metric_key = ?
                """,
                (lab, int(radio_id), oid_k[:200]),
            )
        conn.commit()
        return n > 0
    finally:
        conn.close()


def delete_radio_oid(radio_id: int, row_id: int) -> bool:
    """Remove one SNMP OID row from a radio and drop stored samples keyed by that OID string."""
    rid = int(radio_id)
    oid_row_id = int(row_id)
    conn = ipam.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT oid FROM backhaul_radio_oids WHERE id = ? AND radio_id = ?",
            (oid_row_id, rid),
        )
        fetch = cur.fetchone()
        oid_k = ""
        if fetch:
            if hasattr(fetch, "get"):
                oid_k = str(fetch.get("oid") or "").strip()
            else:
                oid_k = str(fetch[0] or "").strip()
        if not oid_k:
            return False
        cur.execute(
            "DELETE FROM backhaul_radio_metric_values WHERE radio_id = ? AND metric_key = ?",
            (rid, oid_k[:200]),
        )
        cur.execute(
            "DELETE FROM backhaul_radio_oids WHERE id = ? AND radio_id = ?",
            (oid_row_id, rid),
        )
        deleted = int(cur.rowcount or 0) > 0
        conn.commit()
        return deleted
    finally:
        conn.close()


def update_radio_name(radio_id: int, name: str) -> bool:
    n = _validate_name(str(name or ""))
    conn = ipam.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE backhaul_radios SET name = ? WHERE id = ?",
            (n, int(radio_id)),
        )
        conn.commit()
        return int(cur.rowcount or 0) > 0
    finally:
        conn.close()


def delete_radio(radio_id: int) -> bool:
    conn = ipam.get_conn()
    cur = conn.execute("DELETE FROM backhaul_radios WHERE id = ?", (int(radio_id),))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0


def _get_radio_secret_row(radio_id: int) -> Optional[Dict[str, Any]]:
    conn = ipam.get_conn()
    row = conn.execute(
        """
        SELECT id, name, host, ssh_port, ssh_user, ssh_password, snmp_port, snmp_version, snmp_community
        FROM backhaul_radios
        WHERE id = ?
        """,
        (int(radio_id),),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _get_radio_commands(radio_id: int) -> List[Dict[str, Any]]:
    conn = ipam.get_conn()
    rows = conn.execute(
        """
        SELECT id, label, command, position
        FROM backhaul_radio_commands
        WHERE radio_id = ?
        ORDER BY position ASC, id ASC
        """,
        (int(radio_id),),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _get_radio_oids(radio_id: int) -> List[Dict[str, Any]]:
    conn = ipam.get_conn()
    rows = conn.execute(
        """
        SELECT id, oid, label, position
        FROM backhaul_radio_oids
        WHERE radio_id = ?
        ORDER BY position ASC, id ASC
        """,
        (int(radio_id),),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _ssh_exec_host(
    host: str, port: int, username: str, password: str, command: str
) -> Tuple[Optional[str], Optional[str]]:
    def _clean_cli_text(s: str) -> str:
        t = ANSI_RE.sub("", s or "")
        # Remove common cursor/control leftovers while keeping regular line breaks.
        t = t.replace("\r", "\n")
        t = re.sub(r"\x08+", "", t)
        t = re.sub(r"\n{3,}", "\n\n", t)
        raw_lines = [ln.strip() for ln in t.split("\n")]
        cmd_norm = " ".join(str(command or "").strip().split()).lower()
        cleaned: List[str] = []
        for ln in raw_lines:
            if not ln:
                continue
            low = ln.lower()
            # Drop plain prompts such as WN-NTH-SVM(NTH)> and command echoes.
            if re.match(r"^[A-Za-z0-9_.:-]+(?:\([^)]+\))?>\s*$", ln):
                continue
            if low == cmd_norm:
                continue
            if ">" in ln:
                tail = ln.split(">", 1)[1].strip()
                if not tail:
                    continue
                if " ".join(tail.split()).lower() == cmd_norm:
                    continue
            cleaned.append(ln)
        return "\n".join(cleaned).strip()

    try:
        import paramiko  # type: ignore
    except ImportError:
        return None, "paramiko not installed"
    to = _ssh_timeout_sec()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=int(port),
            username=username,
            password=password,
            timeout=to,
            banner_timeout=to,
            auth_timeout=to,
            look_for_keys=False,
            allow_agent=False,
        )
        # Try direct exec first (works on Linux-like targets).
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=to)
            ch = stdout.channel
            ch.settimeout(float(to))
            end = time.monotonic() + float(to)
            out_chunks: List[bytes] = []
            err_chunks: List[bytes] = []
            while True:
                now = time.monotonic()
                if now >= end:
                    break
                had = False
                if ch.recv_ready():
                    out_chunks.append(ch.recv(65535))
                    had = True
                if ch.recv_stderr_ready():
                    err_chunks.append(ch.recv_stderr(65535))
                    had = True
                if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
                    break
                if not had:
                    time.sleep(0.05)
            out_text = b"".join(out_chunks).decode("utf-8", errors="replace")
            err_text = b"".join(err_chunks).decode("utf-8", errors="replace").strip()
            out_text = _clean_cli_text(out_text)
            err_text = _clean_cli_text(err_text)
            if out_text or err_text:
                return out_text, (err_text or None)
        except Exception:
            pass

        # Fallback: interactive shell CLI (common on radios / network gear).
        chan = client.invoke_shell(width=160, height=48)
        chan.settimeout(float(to))
        # Flush banner/prompt
        try:
            time.sleep(0.2)
            while chan.recv_ready():
                chan.recv(65535)
        except Exception:
            pass
        # Many network CLIs expect CRLF and may not emit output until prompt is refreshed.
        chan.send("\r\n")
        time.sleep(0.15)
        while chan.recv_ready():
            chan.recv(65535)
        chan.send(command + "\r\n")
        end = time.monotonic() + float(to)
        chunks: List[bytes] = []
        last_data = time.monotonic()
        while time.monotonic() < end:
            if chan.recv_ready():
                b = chan.recv(65535)
                chunks.append(b)
                # Handle pager prompts so long output can continue.
                lb = b.lower()
                if b"--more--" in lb or b" more " in lb:
                    try:
                        chan.send(" ")
                    except Exception:
                        pass
                last_data = time.monotonic()
            else:
                # If we already got output and it has gone idle, return it.
                if chunks and (time.monotonic() - last_data) > 0.4:
                    break
                time.sleep(0.05)
        if not chunks:
            # One more prompt nudge in case command completed silently but prompt never flushed.
            try:
                chan.send("\r\n")
                time.sleep(0.15)
                while chan.recv_ready():
                    chunks.append(chan.recv(65535))
            except Exception:
                pass
        txt = b"".join(chunks).decode("utf-8", errors="replace")
        txt = _clean_cli_text(txt)
        if txt:
            return txt, None
        return None, "Command timed out after login (auth likely succeeded; command may require different syntax)"
    except socket.timeout:
        return None, "SSH timeout"
    except Exception as e:
        return None, str(e)[:400]
    finally:
        try:
            client.close()
        except Exception:
            pass


def test_radio_command(payload: Dict[str, Any]) -> Dict[str, Any]:
    p = payload or {}
    host = _validate_host(str(p.get("host") or ""))
    port = _validate_port(p.get("ssh_port") or 22)
    user = str(p.get("ssh_user") or "").strip()
    pw = str(p.get("ssh_password") or "")
    cmd = str(p.get("command") or "").strip()
    if not user:
        raise ValueError("SSH user is required")
    if not pw:
        raise ValueError("SSH password is required")
    if not cmd:
        raise ValueError("Command is required")
    out, err = _ssh_exec_host(host, port, user, pw, cmd)
    return {
        "ok": True,
        "output": str(out or "")[:8000],
        "error": err,
    }


def _snmp_numeric_from_line(line: str) -> Optional[float]:
    """Parse Net-SNMP snmpwalk/snmpget text lines; many agents use Gauge (not Gauge32), Timeticks, STRING numbers."""
    s = str(line or "")
    m = re.search(
        r"=\s*(?:INTEGER|Integer32|Gauge32|Gauge|Unsigned32|Counter32|Counter64|UInteger32|Counter|Float|DOUBLE|Real)\s*:\s*([-+]?\d+(?:\.\d+)?)",
        s,
        re.I,
    )
    if m:
        return float(m.group(1))
    m = re.search(r"Timeticks\s*:\s*\(\s*(\d+)\s*\)", s, re.I)
    if m:
        return float(m.group(1))
    # Quoted STRING — numeric token not glued to letters (handles "-65 dBm", "SNR 22"; skips "v2.5")
    m = re.search(r'=\s*STRING:\s*"([^"]*)"', s)
    if m:
        inner = m.group(1).strip()
        md = re.search(r"(?<![A-Za-z])([-+]?\d+(?:\.\d+)?)\b", inner)
        if md:
            return float(md.group(1))
    # Unquoted STRING with optional trailing units (common on wireless gear)
    m = re.search(r"=\s*STRING:\s*([-+]?\d+(?:\.\d+)?)\b", s)
    if m:
        return float(m.group(1))
    m = re.search(r"\(([-+]?\d+(?:\.\d+)?)\)", s)
    if m:
        return float(m.group(1))
    m = re.search(r":\s*(-?\d+(?:\.\d+)?)\s*$", s)
    if m:
        return float(m.group(1))
    return None


def _snmp_translate_oid(oid: str, *, timeout_sec: float = 4.0) -> Optional[str]:
    o = _normalize_net_snmp_oid_text(str(oid or "").strip())
    if not o:
        return None
    mib_pre = _snmp_user_mib_translate_prefix()
    cmd = ["snmptranslate", "-m", "+ALL", "-IR", o]
    if mib_pre:
        cmd = ["snmptranslate", "-M", mib_pre, "-m", "+ALL", "-IR", o]
    try:
        pr = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(0.3, float(timeout_sec)),
            env=_snmp_net_snmp_env(),
        )
    except Exception:
        return None
    if pr.returncode != 0:
        return None
    out = (pr.stdout or "").strip()
    if not out:
        return None
    # Translation unchanged — treat as "no better name" only for purely numeric forms.
    if out == o:
        return o if "::" in o else None
    if "::" in out:
        return out
    return out


def _normalize_net_snmp_oid_text(oid: str) -> str:
    """Net-SNMP often prints ``iso.3.6.1…`` instead of ``.1.3.6.1…`` (root ``iso`` is ``.1``)."""
    o = str(oid or "").strip()
    if re.match(r"(?i)^iso\.", o):
        return ".1." + o[4:]
    return o


_NUMERIC_OID_ONLY_RE = re.compile(r"^(?:\.)?\d+(?:\.\d+)*$")


def _snmp_oid_to_numeric(oid: str, *, timeout_sec: float = 4.0) -> Optional[str]:
    """Resolve MIB/symbolic OID text to dotted-numeric form (leading dot). Used to dedupe walk rows."""
    o = _normalize_net_snmp_oid_text(str(oid or "").strip())
    if not o:
        return None
    if _NUMERIC_OID_ONLY_RE.match(o):
        return o if o.startswith(".") else f".{o}"
    mib_pre = _snmp_user_mib_translate_prefix()
    cmd = ["snmptranslate", "-On", "-m", "+ALL", o]
    if mib_pre:
        cmd = ["snmptranslate", "-M", mib_pre, "-On", "-m", "+ALL", o]
    try:
        pr = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(0.3, float(timeout_sec)),
            env=_snmp_net_snmp_env(),
        )
    except Exception:
        return None
    if pr.returncode != 0:
        return None
    out = (pr.stdout or "").strip()
    if not out:
        return None
    if not out.startswith("."):
        out = f".{out}"
    return out


def _canonical_walk_oid_key(oid: str) -> str:
    """Stable key for deduplicating snmpwalk lines that name the same object differently."""
    o = _normalize_net_snmp_oid_text(str(oid or "").strip())
    if not o:
        return ""
    if _NUMERIC_OID_ONLY_RE.match(o):
        return o if o.startswith(".") else f".{o}"
    n = _snmp_oid_to_numeric(o, timeout_sec=SNMP_WALK_TRANSLATE_TIMEOUT_SEC)
    return n if n else o


SNMP_PING_SYS_DESCR_OID = ".1.3.6.1.2.1.1.1.0"


def snmp_ping(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Single ``snmpget`` for ``sysDescr.0`` from the app server — same runtime path as Discover OIDs."""
    _require_snmp_probes_enabled()
    p = payload or {}
    host = _validate_host(str(p.get("host") or ""))
    port = _validate_port(p.get("snmp_port") or 161)
    version = str(p.get("snmp_version") or "2c").strip().lower()
    if version not in ("1", "2c"):
        raise ValueError("SNMP version must be 1 or 2c")
    community = str(p.get("snmp_community") or "").strip()
    if not community:
        raise ValueError("SNMP community is required")
    cmd = [
        "snmpget",
        "-v",
        version,
        "-c",
        community,
        "-t",
        "5",
        "-r",
        "2",
        f"{host}:{port}",
        SNMP_PING_SYS_DESCR_OID,
    ]
    LOG.info("snmp_ping cmd=%s", _redact_snmp_cmd(cmd))
    try:
        pr = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=25,
            env=_snmp_net_snmp_env(),
        )
    except FileNotFoundError:
        raise ValueError("snmpget is not installed on server (install package `snmp`)") from None
    except subprocess.TimeoutExpired:
        raise ValueError(
            "snmpget timed out — host unreachable, UDP 161 blocked, wrong IP/port, or SNMP disabled."
        ) from None
    out = (pr.stdout or "").strip()
    err = (pr.stderr or "").strip()
    line = out.splitlines()[0] if out else ""
    if pr.returncode != 0:
        tail = line or (err.splitlines()[-1] if err else "") or out or "snmpget failed"
        raise ValueError(str(tail)[:900])
    if not line:
        raise ValueError((err or "Empty snmpget response")[:900])
    return {"line": line[:2000], "oid": SNMP_PING_SYS_DESCR_OID}


def _redact_snmp_cmd(cmd: List[str]) -> str:
    """Log-safe snmpwalk/snmpget argv (SNMP community after ``-c`` redacted)."""
    out: List[str] = []
    i = 0
    while i < len(cmd):
        if i + 1 < len(cmd) and cmd[i] == "-c":
            out.extend(["-c", "***"])
            i += 2
            continue
        out.append(cmd[i])
        i += 1
    return " ".join(out)


def snmp_walk_candidates(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Run snmpwalk and return OID rows plus optional ``warning`` when output parses to zero candidates."""
    _require_snmp_probes_enabled()
    t_start = time.perf_counter()
    p = payload or {}
    host = _validate_host(str(p.get("host") or ""))
    port = _validate_port(p.get("snmp_port") or 161)
    version = str(p.get("snmp_version") or "2c").strip().lower()
    if version not in ("1", "2c"):
        raise ValueError("SNMP version must be 1 or 2c")
    community = str(p.get("snmp_community") or "").strip()
    if not community:
        raise ValueError("SNMP community is required")
    base_oid = str(p.get("base_oid") or ".1").strip() or ".1"
    try:
        max_rows = int(p.get("max_rows") or SNMP_WALK_MAX_ROWS_DEFAULT)
    except (TypeError, ValueError):
        max_rows = SNMP_WALK_MAX_ROWS_DEFAULT
    max_rows = max(50, min(max_rows, SNMP_WALK_MAX_ROWS_CAP))
    # Omit -On so snmpwalk prints symbolic OIDs when MIBs load; numeric-only walks break snmptranslate labels on some hosts.
    cmd = [
        "snmpwalk",
        "-v",
        version,
        "-c",
        community,
        "-t",
        str(SNMP_WALK_AGENT_TIMEOUT_SEC),
        "-r",
        str(SNMP_WALK_AGENT_RETRIES),
        f"{host}:{port}",
        base_oid,
    ]
    LOG.info(
        "snmp_walk start host=%s port=%s version=%s base_oid=%s max_rows=%s community_len=%s timeout_subproc=%s cmd=%s",
        host,
        port,
        version,
        base_oid,
        max_rows,
        len(community),
        SNMP_WALK_SUBPROCESS_TIMEOUT_SEC,
        _redact_snmp_cmd(cmd),
    )
    try:
        pr = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SNMP_WALK_SUBPROCESS_TIMEOUT_SEC,
            env=_snmp_net_snmp_env(),
        )
    except FileNotFoundError:
        LOG.error("snmp_walk snmpwalk binary missing (install package snmp)")
        raise ValueError("snmpwalk is not installed on server (install package `snmp`)")
    except subprocess.TimeoutExpired:
        LOG.error(
            "snmp_walk subprocess timeout host=%s base_oid=%s after=%ss",
            host,
            base_oid,
            SNMP_WALK_SUBPROCESS_TIMEOUT_SEC,
        )
        raise ValueError(
            "SNMP walk timed out — try a narrower base OID, or increase "
            "SNMP_WALK_SUBPROCESS_TIMEOUT_SEC / SNMP_WALK_AGENT_TIMEOUT_SEC / SNMP_WALK_AGENT_RETRIES on the server."
        )

    t_after_walk = time.perf_counter()
    stdout_text = pr.stdout or ""
    stderr_text = (pr.stderr or "").strip()
    lines = stdout_text.splitlines()
    LOG.info(
        "snmp_walk subprocess host=%s rc=%s stdout_lines=%s stderr_chars=%s walk_elapsed_s=%.2f",
        host,
        pr.returncode,
        len(lines),
        len(stderr_text),
        t_after_walk - t_start,
    )
    if stderr_text:
        LOG.warning("snmp_walk snmpwalk stderr host=%s: %s", host, stderr_text[:1200])
    if pr.returncode != 0 and not stdout_text.strip():
        err_blob = ((pr.stderr or "") + "\n" + (pr.stdout or "")).strip()[:400] or "SNMP walk failed"
        LOG.warning("snmp_walk failed host=%s rc=%s detail=%s", host, pr.returncode, err_blob[:500])
        raise ValueError(err_blob)
    if pr.returncode != 0 and stdout_text.strip():
        LOG.warning(
            "snmp_walk non-zero exit but stdout present host=%s rc=%s first_line=%s",
            host,
            pr.returncode,
            (lines[0][:200] if lines else ""),
        )

    prelim: List[Dict[str, Any]] = []
    seen = set()
    lines_with_eq = 0
    skipped_non_numeric = 0
    sample_non_numeric: List[str] = []
    for ln in lines:
        if "=" not in ln:
            continue
        lines_with_eq += 1
        oid = _normalize_net_snmp_oid_text(ln.split("=", 1)[0].strip())
        if not oid or oid in seen:
            continue
        num = _snmp_numeric_from_line(ln)
        if num is None:
            skipped_non_numeric += 1
            if len(sample_non_numeric) < 4:
                sample_non_numeric.append(ln.strip()[:220])
            continue
        seen.add(oid)
        prelim.append({"oid": oid, "sample_value": num, "line": ln.strip()[:220]})
        if len(prelim) >= max_rows:
            break

    if not prelim:
        warn_user = (
            "Walk finished but no lines matched the numeric parser "
            f"(stdout_lines={len(lines)}, lines_with_equals={lines_with_eq}, skipped_non_numeric={skipped_non_numeric}). "
            "This UI lists only scalar numeric samples; try a narrower base_oid or another subtree."
        )
        LOG.warning(
            "snmp_walk empty candidates host=%s base_oid=%s rc=%s stdout_lines=%s eq_lines=%s skipped_non_numeric=%s samples=%s",
            host,
            base_oid,
            pr.returncode,
            len(lines),
            lines_with_eq,
            skipped_non_numeric,
            sample_non_numeric,
        )
        if len(lines) <= 8:
            LOG.warning("snmp_walk stdout dump (short) host=%s: %s", host, stdout_text[:2000])
        return {"oids": [], "warning": warn_user}

    # snmpwalk may print the same object as both numeric and MIB-symbolic OIDs; dedupe by numeric form.
    try:
        with ThreadPoolExecutor(max_workers=SNMP_WALK_TRANSLATE_WORKERS) as pool:
            canon_keys = list(pool.map(_canonical_walk_oid_key, [r["oid"] for r in prelim]))
    except Exception:
        LOG.exception(
            "snmp_walk canonical OID phase failed host=%s base_oid=%s prelim_rows=%s workers=%s",
            host,
            base_oid,
            len(prelim),
            SNMP_WALK_TRANSLATE_WORKERS,
        )
        raise ValueError(
            "SNMP walk failed while normalizing OID keys (snmptranslate -On). Check server logs for traceback."
        ) from None

    merged_prelim: List[Dict[str, Any]] = []
    seen_canon: set[str] = set()
    for row, ck in zip(prelim, canon_keys):
        if not ck or ck in seen_canon:
            continue
        seen_canon.add(ck)
        nr = dict(row)
        nr["oid"] = ck
        merged_prelim.append(nr)
    prelim = merged_prelim

    def _enrich_walk_row(row: Dict[str, Any]) -> Dict[str, Any]:
        oid = row["oid"]
        sym = _snmp_translate_oid(oid, timeout_sec=SNMP_WALK_TRANSLATE_TIMEOUT_SEC)
        label = sym or oid
        return {
            "oid": oid,
            "label": label,
            "symbol": sym,
            "sample_value": row["sample_value"],
            "line": row["line"],
        }

    try:
        with ThreadPoolExecutor(max_workers=SNMP_WALK_TRANSLATE_WORKERS) as pool:
            enriched = list(pool.map(_enrich_walk_row, prelim))
    except Exception:
        LOG.exception(
            "snmp_walk translate phase failed host=%s base_oid=%s prelim_rows=%s workers=%s",
            host,
            base_oid,
            len(prelim),
            SNMP_WALK_TRANSLATE_WORKERS,
        )
        raise ValueError(
            "SNMP walk failed while resolving OID labels (snmptranslate). Check server logs for traceback."
        ) from None

    t_done = time.perf_counter()
    LOG.info(
        "snmp_walk success host=%s oids=%s translate_workers=%s walk_s=%.2f translate_s=%.2f total_s=%.2f",
        host,
        len(enriched),
        SNMP_WALK_TRANSLATE_WORKERS,
        t_after_walk - t_start,
        t_done - t_after_walk,
        t_done - t_start,
    )
    return {"oids": enriched, "warning": None}


# Background SNMP walk jobs — avoids nginx (and other proxies) closing long-lived POSTs with HTTP 504.
_SNMP_WALK_JOB_LOCK = threading.Lock()
_SNMP_WALK_JOBS: Dict[str, Dict[str, Any]] = {}
SNMP_WALK_JOB_RETENTION_SEC = float(os.getenv("SNMP_WALK_JOB_RETENTION_SEC", "1200"))


def _snmp_walk_jobs_prune() -> None:
    now = time.time()
    for jid, rec in list(_SNMP_WALK_JOBS.items()):
        if now - float(rec.get("started", now)) > SNMP_WALK_JOB_RETENTION_SEC:
            _SNMP_WALK_JOBS.pop(jid, None)


def snmp_walk_job_submit(payload: Dict[str, Any]) -> str:
    """Start snmpwalk + translate in a daemon thread; returns opaque job id for polling."""
    _require_snmp_probes_enabled()
    job_id = secrets.token_hex(16)
    started = time.time()
    with _SNMP_WALK_JOB_LOCK:
        _snmp_walk_jobs_prune()
        if len(_SNMP_WALK_JOBS) > 500:
            _SNMP_WALK_JOBS.clear()
        _SNMP_WALK_JOBS[job_id] = {"status": "running", "started": started}

    def _run() -> None:
        try:
            out = snmp_walk_candidates(payload)
            with _SNMP_WALK_JOB_LOCK:
                _SNMP_WALK_JOBS[job_id] = {
                    "status": "done",
                    "started": started,
                    "oids": out.get("oids") or [],
                    "warning": out.get("warning"),
                }
        except ValueError as e:
            with _SNMP_WALK_JOB_LOCK:
                _SNMP_WALK_JOBS[job_id] = {
                    "status": "error",
                    "started": started,
                    "detail": str(e),
                }
        except Exception:
            LOG.exception("snmp_walk background job failed job_id=%s", job_id)
            with _SNMP_WALK_JOB_LOCK:
                _SNMP_WALK_JOBS[job_id] = {
                    "status": "error",
                    "started": started,
                    "detail": "SNMP walk failed (see server logs).",
                }

    threading.Thread(target=_run, daemon=True).start()
    LOG.info("snmp_walk job submitted job_id=%s", job_id)
    return job_id


def snmp_walk_job_status(job_id: str) -> Dict[str, Any]:
    jid = str(job_id or "").strip()
    if not jid:
        raise ValueError("Missing job id")
    with _SNMP_WALK_JOB_LOCK:
        _snmp_walk_jobs_prune()
        rec = _SNMP_WALK_JOBS.get(jid)
        if not rec:
            raise ValueError("Unknown or expired job id — run Discover again.")
        return dict(rec)


def _snmp_get_selected_values(host: str, port: int, version: str, community: str, oids: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    oid_list = [str(x.get("oid") or "").strip() for x in oids if str(x.get("oid") or "").strip()]
    if not oid_list:
        return []
    cmd = ["snmpget", "-v", version, "-c", community, "-t", "2", "-r", "0", f"{host}:{port}"] + oid_list
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=_snmp_net_snmp_env())
    except Exception:
        return []
    lines = [ln for ln in (pr.stdout or "").splitlines() if "=" in ln]
    by_oid: Dict[str, str] = {}
    for ln in lines:
        by_oid[ln.split("=", 1)[0].strip()] = ln
    out: List[Dict[str, Any]] = []
    for i, o in enumerate(oids):
        oid = str(o.get("oid") or "").strip()
        label = str(o.get("label") or oid).strip()
        # snmpget returns lines in request order; OID text may differ (numeric vs symbolic).
        ln = lines[i] if i < len(lines) else by_oid.get(oid, "")
        if not ln:
            ln = by_oid.get(oid, "")
        v = _snmp_numeric_from_line(ln)
        out.append(
            {
                "label": label,
                "command": oid,
                "output": ln,
                "parsed_values": [{"label": label, "value": v}] if v is not None else [{"label": label, "value": None}],
                "error": None if ln else "no response",
            }
        )
    return out


def _parse_rate_to_mbps(s: str) -> Optional[float]:
    m = re.search(r"([-+]?\d+(?:\.\d+)?)\s*([kmg]?)(?:bps|bit/s|b/s)\b", (s or "").lower())
    if not m:
        return None
    v = float(m.group(1))
    u = (m.group(2) or "").lower()
    mul = {"": 1e-6, "k": 1e-3, "m": 1.0, "g": 1e3}.get(u, 1e-6)
    return v * mul


def _parse_rssi_dbm(text: str) -> Optional[float]:
    for pat in (
        r"\brssi\b[^-\d]*(-?\d+(?:\.\d+)?)\s*d?bm",
        r"\brx\s*level\b[^-\d]*(-?\d+(?:\.\d+)?)\s*d?bm",
        r"\bsignal\b[^-\d]*(-?\d+(?:\.\d+)?)\s*d?bm",
    ):
        m = re.search(pat, text or "", re.I)
        if m:
            return float(m.group(1))
    return None


def _parse_interface_rates(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not text:
        return out
    for ln in text.splitlines():
        line = ln.strip()
        if not line:
            continue
        if not re.search(r"\b(rx|tx)\b", line, re.I):
            continue
        if ":" in line:
            name = line.split(":", 1)[0].strip()
        else:
            name_m = re.search(r"^([A-Za-z0-9._/-]+)", line)
            name = name_m.group(1) if name_m else "iface"
        rx = None
        tx = None
        mrx = re.search(r"\brx\b[^0-9-]*([-+]?\d+(?:\.\d+)?\s*[kmg]?(?:bps|bit/s|b/s))", line, re.I)
        mtx = re.search(r"\btx\b[^0-9-]*([-+]?\d+(?:\.\d+)?\s*[kmg]?(?:bps|bit/s|b/s))", line, re.I)
        if mrx:
            rx = _parse_rate_to_mbps(mrx.group(1))
        if mtx:
            tx = _parse_rate_to_mbps(mtx.group(1))
        if rx is None and tx is None:
            rates = re.findall(r"[-+]?\d+(?:\.\d+)?\s*[kmg]?(?:bps|bit/s|b/s)", line, re.I)
            if len(rates) >= 2:
                rx = _parse_rate_to_mbps(rates[0])
                tx = _parse_rate_to_mbps(rates[1])
        if rx is None and tx is None:
            continue
        out.append({"name": name, "rx_mbps": rx, "tx_mbps": tx})
    return out


def _record_radio_sample(
    radio_id: int,
    ts: str,
    rssi_dbm: Optional[float],
    ifaces: List[Dict[str, Any]],
    total_rx: Optional[float],
    total_tx: Optional[float],
    raw_rssi: Optional[str],
    raw_ifaces: Optional[str],
    command_results: Optional[List[Dict[str, Any]]],
    error: Optional[str],
) -> None:
    conn = ipam.get_conn()
    try:
        conn.execute(
            """
            INSERT INTO backhaul_radio_samples
            (radio_id, ts, rssi_dbm, iface_count, total_rx_mbps, total_tx_mbps, raw_rssi, raw_ifaces, command_results, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(radio_id),
                ts,
                rssi_dbm,
                len(ifaces),
                total_rx,
                total_tx,
                (raw_rssi or "")[:4000],
                (raw_ifaces or "")[:8000],
                json.dumps(command_results or []),
                (error or "")[:500],
            ),
        )
        for cr in (command_results or []):
            if not isinstance(cr, dict):
                continue
            pvs = cr.get("parsed_values") or []
            if not isinstance(pvs, list):
                continue
            oid_hint = str(cr.get("command") or "").strip()
            for p in pvs:
                if not isinstance(p, dict):
                    continue
                lab = str(p.get("label") or "").strip()
                if not lab:
                    lab = oid_hint[:120] if oid_hint else ""
                if not lab:
                    lab = "metric"
                ml = lab[:120]
                # Stable series key = SNMP OID string (rename-safe); human label stored separately.
                mk = (oid_hint[:200] if oid_hint else ml).strip() or ml
                val = p.get("value")
                try:
                    fval = float(val) if val is not None else None
                except (TypeError, ValueError):
                    fval = None
                if fval is None:
                    continue
                conn.execute(
                    """
                    INSERT INTO backhaul_radio_metric_values (radio_id, ts, metric_key, metric_label, value)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (int(radio_id), ts, mk, ml, fval),
                )
        cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat(timespec="seconds") + "Z"
        conn.execute(
            "DELETE FROM backhaul_radio_samples WHERE radio_id = ? AND ts < ?",
            (int(radio_id), cutoff),
        )
        conn.execute(
            "DELETE FROM backhaul_radio_metric_values WHERE radio_id = ? AND ts < ?",
            (int(radio_id), cutoff),
        )
        conn.commit()
    finally:
        conn.close()


def radio_live_snapshot(radio: Dict[str, Any]) -> Dict[str, Any]:
    rid = int(radio["id"])
    ts = _now()
    oid_rows = _get_radio_oids(rid)
    command_results: List[Dict[str, Any]] = []
    raw_rssi = ""
    raw_if = ""
    err_parts: List[str] = []
    if oid_rows:
        command_results = _snmp_get_selected_values(
            str(radio["host"]),
            int(radio.get("snmp_port") or 161),
            str(radio.get("snmp_version") or "2c"),
            str(radio.get("snmp_community") or "public"),
            oid_rows,
        )
        for rr in command_results:
            out = str(rr.get("output") or "")
            low_lab = str(rr.get("label") or "").lower()
            if ("rssi" in low_lab or "cinr" in low_lab) and not raw_rssi:
                raw_rssi = out
            if ("iface" in low_lab or "throughput" in low_lab or "traffic" in low_lab or "rx" in low_lab or "tx" in low_lab) and not raw_if:
                raw_if = out
    else:
        err_parts.append("No SNMP OIDs selected for this radio")
    if not raw_rssi and command_results:
        raw_rssi = "\n".join([x.get("output") or "" for x in command_results])
    if not raw_if and command_results:
        raw_if = "\n".join([x.get("output") or "" for x in command_results])
    rssi = _parse_rssi_dbm(raw_rssi or "")
    ifaces = _parse_interface_rates(raw_if or "")
    total_rx = sum([(x.get("rx_mbps") or 0.0) for x in ifaces]) if ifaces else None
    total_tx = sum([(x.get("tx_mbps") or 0.0) for x in ifaces]) if ifaces else None
    err = " · ".join(err_parts) if err_parts else None
    _record_radio_sample(
        rid, ts, rssi, ifaces, total_rx, total_tx, raw_rssi, raw_if, command_results, err
    )
    return {
        "rssi_dbm": rssi,
        "interfaces": ifaces,
        "interface_count": len(ifaces),
        "total_rx_mbps": total_rx,
        "total_tx_mbps": total_tx,
        "commands": command_results,
        "error": err,
    }


def radios_overview_live() -> List[Dict[str, Any]]:
    rows = list_radios()
    if not rows:
        return []

    if not monitoring.is_monitoring_sampling_enabled():
        stub_live = {
            "rssi_dbm": None,
            "interfaces": [],
            "interface_count": 0,
            "total_rx_mbps": None,
            "total_tx_mbps": None,
            "commands": [],
            "error": None,
            "polling_paused": True,
        }
        return [dict(r, live=dict(stub_live)) for r in rows]

    secret_rows = []
    for r in rows:
        s = _get_radio_secret_row(int(r["id"]))
        if s:
            secret_rows.append(s)
    futures = { _EXEC.submit(radio_live_snapshot, r): r for r in secret_rows }
    by_id: Dict[int, Dict[str, Any]] = {}
    for fut in as_completed(futures):
        r = futures[fut]
        rid = int(r["id"])
        try:
            by_id[rid] = fut.result()
        except Exception as e:
            by_id[rid] = {"error": str(e)[:500], "interfaces": []}
    out: List[Dict[str, Any]] = []
    for r in rows:
        rr = dict(r)
        rr["live"] = by_id.get(int(r["id"]), {"interfaces": []})
        out.append(rr)
    return out


def _extract_first_number(text: str) -> Optional[float]:
    m = re.search(r"(-?\d+(?:\.\d+)?)", text or "")
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _parse_command_values(label: str, output: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    base = str(label or "").strip() or "Value"
    txt = str(output or "")
    seen = set()
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9_\-\/ ]{1,40})\s*[:=]\s*(-?\d+(?:\.\d+)?)", txt):
        k = " ".join(m.group(1).strip().split())
        try:
            v = float(m.group(2))
        except ValueError:
            continue
        if k.lower() in ("rx", "tx"):
            name = f"{base} {k.upper()}"
        else:
            name = k
        if name in seen:
            continue
        seen.add(name)
        out.append({"label": name, "value": v})
    mrx = re.search(r"\brx\b[^-\d]{0,12}(-?\d+(?:\.\d+)?)", txt, re.I)
    if mrx:
        nm = f"{base} RX"
        if nm not in seen:
            seen.add(nm)
            out.append({"label": nm, "value": float(mrx.group(1))})
    mtx = re.search(r"\btx\b[^-\d]{0,12}(-?\d+(?:\.\d+)?)", txt, re.I)
    if mtx:
        nm = f"{base} TX"
        if nm not in seen:
            seen.add(nm)
            out.append({"label": nm, "value": float(mtx.group(1))})
    if not out:
        fv = _extract_first_number(txt)
        if fv is not None:
            out.append({"label": base, "value": fv})
    return out


def _row_dict(r: Any) -> Dict[str, Any]:
    if r is None:
        return {}
    if hasattr(r, "keys"):
        return {str(k): r[k] for k in r.keys()}
    return dict(r)


def fetch_radio_history(radio_id: int, hours: float = 12.0) -> Optional[Dict[str, Any]]:
    """Return time series keyed by stable SNMP OID (`metric_key`), plus display titles from current oid rows."""
    conn = ipam.get_conn()
    try:
        exists = conn.execute(
            "SELECT id FROM backhaul_radios WHERE id = ?",
            (int(radio_id),),
        ).fetchone()
        if not exists:
            return None
        cutoff_dt = datetime.utcnow() - timedelta(hours=float(hours))
        cutoff_s = cutoff_dt.isoformat(timespec="seconds") + "Z"
        rows = conn.execute(
            """
            SELECT ts, metric_key, metric_label, value
            FROM backhaul_radio_metric_values
            WHERE radio_id = ? AND ts >= ?
            ORDER BY ts ASC, id ASC
            """,
            (int(radio_id), cutoff_s),
        ).fetchall()
        oid_rows = conn.execute(
            """
            SELECT oid, label FROM backhaul_radio_oids
            WHERE radio_id = ? ORDER BY position ASC, id ASC
            """,
            (int(radio_id),),
        ).fetchall()
        title_by_oid: Dict[str, str] = {}
        for orow in oid_rows:
            od = _row_dict(orow)
            o = str(od.get("oid") or "").strip()
            if not o:
                continue
            title_by_oid[o] = str(od.get("label") or o).strip()

        out_map: Dict[str, Dict[str, Optional[float]]] = {}
        last_label_for_key: Dict[str, str] = {}
        for r in rows:
            rr = _row_dict(r)
            ts = str(rr["ts"] or "")
            mk = str(rr.get("metric_key") or "").strip()
            ml = str(rr.get("metric_label") or "").strip()
            if not mk:
                mk = ml
            if not mk:
                continue
            val = rr.get("value")
            try:
                fv = float(val) if val is not None else None
            except (TypeError, ValueError):
                fv = None
            out_map.setdefault(ts, {})[mk] = fv
            if ml:
                last_label_for_key[mk] = ml

        # Charts should follow *current* SNMP OID selections only; history still contains rows for removed OIDs.
        monitored_order: List[str] = []
        for orow in oid_rows:
            od = _row_dict(orow)
            o = str(od.get("oid") or "").strip()
            if o:
                monitored_order.append(o)

        if monitored_order:
            all_keys = list(monitored_order)
            for ts in list(out_map.keys()):
                row = out_map[ts]
                out_map[ts] = {k: row.get(k) for k in monitored_order}
        else:
            all_keys = []
            seen_k = set()
            for ts in sorted(out_map.keys()):
                for k in out_map[ts].keys():
                    if k not in seen_k:
                        seen_k.add(k)
                        all_keys.append(k)

        labels: Dict[str, str] = {}
        for k in all_keys:
            labels[k] = title_by_oid.get(k) or last_label_for_key.get(k, k)

        points: List[Dict[str, Any]] = []
        for ts in sorted(out_map.keys()):
            points.append({"ts": ts, "values": out_map[ts]})

        return {"points": points, "labels": labels, "keys": all_keys}
    finally:
        conn.close()
