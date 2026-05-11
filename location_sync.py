# Location Sync: bulk Splynx ACTIVE customers + MAC (online session preferred), local cache.
import json as _json
from collections import defaultdict
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import db_runtime

DB_PATH = os.getenv("LOCATION_SYNC_DB_PATH", os.path.join("data", "location_sync.db"))

# Splynx API defaults (match typical v2 limits)
PAGE_SIZE = max(10, min(100, int(os.getenv("SPLYNX_CUSTOMER_PAGE_SIZE", "100"))))
ONLINE_PAGE_SIZE = max(10, min(100, int(os.getenv("SPLYNX_ONLINE_PAGE_SIZE", str(PAGE_SIZE)))))

# Pause between paginated requests (seconds) — reduces API pressure / rate limiting.
BATCH_PAUSE_SEC = float(os.getenv("SPLYNX_SYNC_BATCH_PAUSE_SEC", "0.15"))

# Bulk session table (historical sessions — used for “last session MAC” when offline).
SESSION_BULK_PATHS = [
    p.strip().lstrip("/")
    for p in os.getenv(
        "SPLYNX_SESSION_BULK_PATHS",
        "admin/customers/customer-session,"
        "admin/customers/custom-sessions,"
        "admin/customers/session",
    ).split(",")
    if p.strip()
]

ONLINE_SESSION_PATHS = [
    p.strip().lstrip("/")
    for p in os.getenv(
        "SPLYNX_ONLINE_SESSION_PATHS",
        "admin/customers/customers-online,"
        "admin/customers/customers-online/",
    ).split(",")
    if p.strip()
]

# After bulk paths, optionally merge GET admin/customers/customer/{id}/internet-services per
# customer — bulk lists often omit the 2nd+ service for the same customer_id.
# when_lte_one | always | never  (when_lte_one = fetch only if bulk returned 0–1 rows for that customer)
_MERGE_CUSTOMER_SERVICES_ENV = os.getenv(
    "SPLYNX_LOCATION_SYNC_MERGE_CUSTOMER_ENDPOINT", "when_lte_one"
).strip().lower()

# Bulk internet-service rows (multi-service MACs / PPP logins per customer).
SPLYNX_SERVICES_BULK_PATHS = [
    p.strip().lstrip("/")
    for p in os.getenv(
        "SPLYNX_LOCATION_SYNC_SERVICES_PATHS",
        "admin/customers/internet-services,"
        "admin/customers/services/internet",
    ).split(",")
    if p.strip()
]

# Extra per-customer calls when MAC still unknown (expensive at ~5000 users).
DEEP_MAC = os.getenv("SPLYNX_LOCATION_SYNC_DEEP_MAC", "0").strip() == "1"
DEEP_PAUSE_SEC = float(os.getenv("SPLYNX_SYNC_DEEP_PAUSE_SEC", "0.08"))

# Matches aa:bb:cc:dd:ee:ff / aa-bb-cc-dd-ee-ff inside any JSON/string.
_MAC_ANY_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
)

INTERVAL_SEC = max(3600, int(os.getenv("LOCATION_SYNC_INTERVAL_SEC", str(24 * 3600))))


def is_location_sync_scheduler_enabled() -> bool:
    """When false: no automated nightly sync loop (use on DR standby fed by DB clone). Manual Run sync still works."""
    v = (os.getenv("LOCATION_SYNC_SCHEDULER_ENABLED") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")

# If a worker crashes mid-sync or a request hangs, release the lock after this many seconds
# so "Run sync now" works again (see LOCATION_SYNC_LOCK_STALE_SEC).
SYNC_LOCK_STALE_SEC = max(120.0, float(os.getenv("LOCATION_SYNC_LOCK_STALE_SEC", "5400")))

_sync_lock = threading.Lock()
_sync_in_progress = False
_sync_started_monotonic: Optional[float] = None

SplynxGet = Callable[..., Any]


def _optional_customer_id_filter() -> Optional[Set[int]]:
    """If set (comma-separated ids), sync only merges those active customers — see run_full_sync warning."""
    raw = os.getenv("LOCATION_SYNC_ONLY_CUSTOMER_IDS", "").strip()
    if not raw:
        return None
    out: Set[int] = set()
    for part in raw.replace(" ", "").split(","):
        if part.isdigit():
            out.add(int(part))
    return out if out else None


def _ensure_db_dir() -> None:
    d = os.path.dirname(DB_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def get_conn() -> sqlite3.Connection:
    return db_runtime.get_conn("location_sync")


def init_db() -> None:
    if db_runtime.is_postgres():
        db_runtime.init_postgres_schema()
        conn = get_conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS location_sync_customer_directory (
                    customer_id INTEGER PRIMARY KEY,
                    customer_name TEXT,
                    status TEXT,
                    email TEXT,
                    phone TEXT,
                    mobile TEXT,
                    street_1 TEXT,
                    street_2 TEXT,
                    city TEXT,
                    state TEXT,
                    zip_code TEXT,
                    country TEXT,
                    address_text TEXT,
                    raw_json TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()
        return
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS location_sync_meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );
        """
    )
    _migrate_location_sync_customers(conn)
    _migrate_cross_ref_schema(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS location_sync_customer_directory (
            customer_id INTEGER PRIMARY KEY,
            customer_name TEXT,
            status TEXT,
            email TEXT,
            phone TEXT,
            mobile TEXT,
            street_1 TEXT,
            street_2 TEXT,
            city TEXT,
            state TEXT,
            zip_code TEXT,
            country TEXT,
            address_text TEXT,
            raw_json TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _migrate_location_sync_customers(conn: sqlite3.Connection) -> None:
    """One row per (customer_id, service_login) so multi-service customers get multiple MACs."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='location_sync_customers'"
    ).fetchone()
    if not row or not row[0]:
        conn.execute(
            """
            CREATE TABLE location_sync_customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                service_login TEXT NOT NULL DEFAULT '',
                customer_name TEXT,
                status TEXT,
                mac TEXT,
                mac_source TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(customer_id, service_login)
            );
            """
        )
        return
    ddl = str(row[0])
    if "service_login" in ddl:
        return
    conn.execute("ALTER TABLE location_sync_customers RENAME TO location_sync_customers_old")
    conn.execute(
        """
        CREATE TABLE location_sync_customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            service_login TEXT NOT NULL DEFAULT '',
            customer_name TEXT,
            status TEXT,
            mac TEXT,
            mac_source TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE(customer_id, service_login)
        );
        """
    )
    conn.execute(
        """
        INSERT INTO location_sync_customers
        (customer_id, service_login, customer_name, status, mac, mac_source, updated_at)
        SELECT customer_id, '', customer_name, status, mac, mac_source, updated_at
        FROM location_sync_customers_old
        """
    )
    conn.execute("DROP TABLE location_sync_customers_old")


def _migrate_cross_ref_schema(conn: sqlite3.Connection) -> None:
    """cross_ref keyed by router + customer + service login."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        ("location_sync_cross_ref",),
    ).fetchone()
    ddl = str(row[0]) if row and row[0] else ""
    if ddl and "service_login" in ddl:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_lsync_xref_router ON location_sync_cross_ref(router_id);"
        )
        return
    if ddl:
        conn.execute("DROP TABLE location_sync_cross_ref")
    conn.execute(
        """
        CREATE TABLE location_sync_cross_ref (
            router_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            service_login TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL,
            router_location TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (router_id, customer_id, service_login)
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_lsync_xref_router ON location_sync_cross_ref(router_id);"
    )


def _meta_set(k: str, v: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO location_sync_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        (k, v),
    )
    conn.commit()
    conn.close()


def _meta_get(k: str) -> Optional[str]:
    conn = get_conn()
    r = conn.execute("SELECT v FROM location_sync_meta WHERE k = ?", (k,)).fetchone()
    conn.close()
    return str(r["v"]) if r else None


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _normalize_list_payload(data: Any) -> List[Dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("data", "items", "customers", "records", "rows"):
            inner = data.get(key)
            if isinstance(inner, list):
                return [x for x in inner if isinstance(x, dict)]
    return []


def _safe_int(v: Any) -> Optional[int]:
    try:
        if v is None or isinstance(v, bool):
            return None
        return int(v)
    except Exception:
        return None


def _pause() -> None:
    if BATCH_PAUSE_SEC > 0:
        time.sleep(BATCH_PAUSE_SEC)


def _normalize_mac(raw: str) -> str:
    hx = re.sub(r"[^0-9A-Fa-f]", "", (raw or "").strip())
    if len(hx) != 12:
        return ""
    return ":".join(hx[i : i + 2].lower() for i in range(0, 12, 2))


def normalize_mac_for_lookup(raw: str) -> str:
    """Normalize MAC for dict keys (same logic as cache comparison)."""
    return _normalize_mac(raw)


def _looks_like_mac(s: str) -> bool:
    hx = re.sub(r"[^0-9A-Fa-f]", "", (s or "").strip())
    return len(hx) == 12


def _mac_scan_any(obj: Any) -> Optional[str]:
    """Find MAC anywhere in serialized JSON (catches uncommon Splynx keys)."""
    try:
        blob = _json.dumps(obj, ensure_ascii=False) if obj is not None else ""
    except Exception:
        blob = str(obj)
    for m in _MAC_ANY_RE.finditer(blob):
        norm = _normalize_mac(m.group(0))
        if norm:
            return norm
    return None


def _mac_from_record(rec: Any, depth: int = 0) -> Optional[str]:
    if depth > 3 or not isinstance(rec, dict):
        return None
    keys = (
        "mac",
        "mac_address",
        "cpe_mac",
        "calling_station_id",
        "calling-station-id",
        "Calling-Station-Id",
        "framed_mac",
        "Framed-Interface-Id",
        "wlan_mac",
        "dhcp_mac",
        "hardware_mac",
        "user_mac",
        "station_mac",
        "device_mac",
        "client_mac",
        "usr_mac",
    )
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and _looks_like_mac(v):
            m = _normalize_mac(v)
            if m:
                return m
    for v in rec.values():
        if isinstance(v, dict):
            m = _mac_from_record(v, depth + 1)
            if m:
                return m
        elif isinstance(v, list):
            for it in v[:20]:
                if isinstance(it, dict):
                    m = _mac_from_record(it, depth + 1)
                    if m:
                        return m
    return _mac_scan_any(rec)


def _session_time_score(rec: Dict[str, Any]) -> float:
    """Approximate sort key: newer session first."""
    for k in (
        "session_end",
        "date_end",
        "end",
        "end_date",
        "time_end",
        "stop",
        "date_stop",
        "disconnected",
        "session_stop",
        "to",
        "datetime_end",
        "created_at",
        "date_add",
        "start",
        "session_start",
        "date_start",
    ):
        v = rec.get(k)
        if v is None:
            continue
        sc = _parse_time_value(v)
        if sc > 0:
            return sc
    return 0.0


def _parse_time_value(v: Any) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if not s:
        return 0.0
    if s.isdigit():
        try:
            return float(int(s))
        except Exception:
            return 0.0
    try:
        from datetime import datetime as _dt

        if "T" in s or ("-" in s and len(s) >= 10):
            s2 = s.replace("Z", "+00:00")
            return _dt.fromisoformat(s2.replace(" ", "T")[:32]).timestamp()
    except Exception:
        pass
    return 0.0


def _session_customer_id(rec: Dict[str, Any]) -> Optional[int]:
    # Do not use generic "id" — that is usually the session row id, not customer_id.
    return (
        _safe_int(rec.get("customer_id"))
        or _safe_int(rec.get("id_customer"))
        or _safe_int(rec.get("customerId"))
        or _safe_int(rec.get("customer"))
    )


def _normalize_login_key(raw: str) -> str:
    return (raw or "").strip().lower()


def _session_login_key(rec: Dict[str, Any]) -> str:
    """Login / PPP name from an online or session-history row."""
    for k in (
        "login",
        "username",
        "user",
        "ppp_login",
        "ppp_username",
        "auth_login",
        "name",
        "customer_login",
        "customer-name",
        "customer_name",
    ):
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return _normalize_login_key(v)
    return ""


def _internet_service_id_from_record(rec: Dict[str, Any]) -> Optional[int]:
    """Splynx often ties sessions/MACs to a specific internet-service row."""
    for k in (
        "internet_service_id",
        "internet_services_id",
        "id_internet_service",
        "internet_service",
        "service_id",
        "id_service",
        "internetServiceId",
        "internet_serviceId",
    ):
        sid = _safe_int(rec.get(k))
        if sid:
            return sid
    inner = rec.get("internet_service")
    if isinstance(inner, dict):
        sid = _safe_int(inner.get("id"))
        if sid:
            return sid
    return None


def _service_login_key(svc: Dict[str, Any]) -> str:
    """
    Stable UNIQUE key per internet service row for DB + MAC correlation.

    Prefer numeric service id first so two active services under one customer that share
    the same PPP login string are not merged into one cache row during de-duplication.
    """
    sid = _safe_int(svc.get("id"))
    if sid:
        return f"id:{sid}"
    for k in ("login", "username", "user", "ppp_login", "auth_login"):
        v = svc.get(k)
        if isinstance(v, str) and v.strip():
            return _normalize_login_key(v)
    return ""


def _ppp_login_only_key(svc: Optional[Dict[str, Any]]) -> str:
    """Login fields only (no service id) — used to match customers-online rows keyed by PPP name."""
    if not svc:
        return ""
    for k in ("login", "username", "user", "ppp_login", "auth_login"):
        v = svc.get(k)
        if isinstance(v, str) and v.strip():
            return _normalize_login_key(v)
    return ""


def _merge_login_keys_for_mac_lookup(store_key: str, svc_dict: Optional[Dict[str, Any]]) -> List[str]:
    """Try storage key (often id:N) plus PPP login so online/session rows can match."""
    seen: set = set()
    out: List[str] = []
    for raw in (store_key, _ppp_login_only_key(svc_dict)):
        lk = _normalize_login_key(raw)
        if lk and lk not in seen:
            seen.add(lk)
            out.append(lk)
    return out if out else [""]


def _internet_service_row_active(svc: Dict[str, Any]) -> bool:
    st = str(svc.get("status") or svc.get("state") or "").lower().strip()
    if st in ("blocked", "inactive", "off", "disabled", "0", "cancelled", "canceled"):
        return False
    return True


def _customer_id_from_service_row(row: Dict[str, Any]) -> Optional[int]:
    cid = (
        _safe_int(row.get("customer_id"))
        or _safe_int(row.get("id_customer"))
        or _safe_int(row.get("customerId"))
        or _safe_int(row.get("customer"))
    )
    if cid:
        return cid
    c = row.get("customer")
    if isinstance(c, dict):
        return _safe_int(c.get("id") or c.get("customer_id") or c.get("customerId"))
    return None


def _dedupe_same_internet_service_id(lst: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove only duplicate rows that share the same Splynx internet-service id (two API paths)."""
    seen_ids: set = set()
    out: List[Dict[str, Any]] = []
    for svc in lst:
        sid = _safe_int(svc.get("id"))
        if sid:
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
        out.append(svc)
    return out


def _assign_unique_location_sync_login_keys(lst: List[Dict[str, Any]]) -> None:
    """
    Every bulk row becomes one cache row. When two services share the same login and have no id,
    _service_login_key collides — assign id:user#1 style keys instead of dropping the row.
    Sets _location_sync_login_key on each dict (used for DB service_login + MAC correlation).
    """
    seen: set = set()
    for idx, svc in enumerate(lst):
        base = _service_login_key(svc)
        if not base:
            base = f"_norowkey:{idx}"
        key = base
        suf = 0
        while key in seen:
            suf += 1
            key = f"{base}#{suf}"
        seen.add(key)
        svc["_location_sync_login_key"] = key


def _fetch_internet_services_by_customer(splynx_get: SplynxGet) -> Dict[int, List[Dict[str, Any]]]:
    """Bulk internet-service rows grouped by customer (merge endpoints; dedupe by service id only)."""
    merged: Dict[int, List[Dict[str, Any]]] = {}
    paths_hit: List[str] = []
    total_bulk_rows = 0
    for path in SPLYNX_SERVICES_BULK_PATHS:
        try:
            rows = _fetch_all_pages(splynx_get, path, PAGE_SIZE, None)
        except Exception:
            continue
        if not rows:
            continue
        paths_hit.append(path[:120])
        total_bulk_rows += len(rows)
        for r in rows:
            if not isinstance(r, dict):
                continue
            cid = _customer_id_from_service_row(r)
            if not cid:
                continue
            merged.setdefault(int(cid), []).append(r)
    _meta_set("location_sync_services_path_used", ";".join(paths_hit)[:500])
    _meta_set("location_sync_bulk_service_rows", str(total_bulk_rows))
    out: Dict[int, List[Dict[str, Any]]] = {}
    for cid, lst in merged.items():
        out[cid] = _dedupe_same_internet_service_id(lst)
    return out


def _fetch_customer_internet_services_detail(
    splynx_get: SplynxGet, cid: int
) -> List[Dict[str, Any]]:
    """Authoritative list of internet services for one customer (full multi-service rows)."""
    paths = (
        f"admin/customers/customer/{int(cid)}/internet-services",
        f"admin/customers/customer/{int(cid)}/internet-services/",
    )
    for path in paths:
        try:
            data = splynx_get(path, params=None)
            chunk = _normalize_list_payload(data)
            if chunk:
                return chunk
        except Exception:
            continue
    return []


def _merge_customer_endpoint_mode_should_fetch(bulk_row_count: int, mode: str) -> bool:
    m = (mode or "").strip().lower()
    if m in ("never", "0", "false", "no", "off"):
        return False
    if m in ("always", "1", "true", "yes", "all", "on"):
        return True
    return bulk_row_count <= 1


def merge_services_for_active_customers(
    splynx_get: SplynxGet,
    bulk_by_customer: Dict[int, List[Dict[str, Any]]],
    active_customer_ids: List[int],
    mode: str,
) -> Dict[int, List[Dict[str, Any]]]:
    """
    Combine bulk rows with per-customer internet-services where enabled, then assign cache keys.
    """
    out: Dict[int, List[Dict[str, Any]]] = {}
    fetched = 0
    detail_rows_in = 0
    for cid in active_customer_ids:
        cid_i = int(cid)
        bulk_part = list(bulk_by_customer.get(cid_i, []))
        n_bulk = len(bulk_part)
        rows = bulk_part
        if _merge_customer_endpoint_mode_should_fetch(n_bulk, mode):
            extra = _fetch_customer_internet_services_detail(splynx_get, cid_i)
            if extra:
                fetched += 1
                detail_rows_in += len(extra)
                rows = bulk_part + extra
            _pause()
        lst2 = _dedupe_same_internet_service_id(rows)
        _assign_unique_location_sync_login_keys(lst2)
        out[cid_i] = lst2
    _meta_set("location_sync_customer_service_fetches", str(fetched))
    _meta_set("location_sync_customer_service_detail_rows", str(detail_rows_in))
    _meta_set("location_sync_merge_customer_endpoint_mode", mode[:80])
    return out


def _mac_from_session_row(rec: Dict[str, Any]) -> Optional[str]:
    m = _mac_from_record(rec)
    if m:
        return m
    return _mac_scan_any(rec)


def _fetch_first_working_bulk_sessions(
    splynx_get: SplynxGet,
) -> Tuple[List[Dict[str, Any]], str]:
    """First path that returns at least one session row wins (full pagination on that path)."""
    last_err = ""
    for path in SESSION_BULK_PATHS:
        try:
            chunk = _fetch_all_pages(splynx_get, path, PAGE_SIZE, None)
            if chunk:
                _meta_set("last_session_bulk_path", path[:200])
                return chunk, path
        except Exception as e:
            last_err = str(e)
            continue
    _meta_set("last_session_bulk_error", last_err[:500])
    return [], ""


def _build_last_session_mac_maps(
    rows: List[Dict[str, Any]],
) -> Tuple[Dict[int, Tuple[str, float]], Dict[Tuple[int, str], Tuple[str, float]]]:
    """
    Per customer (cid) and per (cid, login) keep MAC from session row with highest time score.
    """
    best_cid: Dict[int, Tuple[str, float]] = {}
    best_cl: Dict[Tuple[int, str], Tuple[str, float]] = {}
    for rec in rows:
        if not isinstance(rec, dict):
            continue
        cid = _session_customer_id(rec)
        if not cid:
            continue
        mac = _mac_from_session_row(rec)
        if not mac:
            continue
        ts = _session_time_score(rec)
        lk = _session_login_key(rec)
        if lk:
            k = (int(cid), lk)
            prev = best_cl.get(k)
            if prev is None or ts >= prev[1]:
                best_cl[k] = (mac, ts)
        sid = _internet_service_id_from_record(rec)
        if sid:
            k_sid = (int(cid), f"id:{sid}")
            prev_s = best_cl.get(k_sid)
            if prev_s is None or ts >= prev_s[1]:
                best_cl[k_sid] = (mac, ts)
        prev_c = best_cid.get(int(cid))
        if prev_c is None or ts >= prev_c[1]:
            best_cid[int(cid)] = (mac, ts)
    return best_cid, best_cl


def _lookup_online_exact(
    cid: int,
    login_key: str,
    online: Dict[Tuple[int, str], Tuple[str, str]],
) -> Tuple[str, str]:
    lk = _normalize_login_key(login_key)
    if (cid, lk) in online:
        return online[(cid, lk)]
    if (cid, "") in online:
        return online[(cid, "")]
    return "", ""


def _consume_online_any_fallback(
    cid: int,
    pool: Dict[int, List[Tuple[str, str]]],
) -> Tuple[str, str]:
    lst = pool.get(cid)
    if lst:
        return lst.pop(0)
    return "", ""


def _pool_remove_mac_norm(
    pool: Dict[int, List[Tuple[str, str]]],
    cid: int,
    mac: str,
) -> None:
    """Stop fallback pool from handing out a MAC we already matched exactly."""
    if not mac:
        return
    want = normalize_mac_for_lookup(mac)
    if not want:
        return
    lst = pool.get(cid)
    if not lst:
        return
    for i, (m, _src) in enumerate(lst):
        if normalize_mac_for_lookup(m) == want:
            lst.pop(i)
            break


def _lookup_last_session_exact(
    cid: int,
    login_key: str,
    last_cl: Dict[Tuple[int, str], Tuple[str, float]],
) -> Tuple[str, str]:
    lk = _normalize_login_key(login_key)
    if lk and (cid, lk) in last_cl:
        return last_cl[(cid, lk)][0], "last_session"
    return "", ""


def _pick_last_session_customer_fallback(
    cid: int,
    last_cid: Dict[int, Tuple[str, float]],
) -> Tuple[str, str]:
    if cid in last_cid:
        return last_cid[cid][0], "last_session"
    return "", ""


def _customer_id_from(rec: Dict[str, Any]) -> Optional[int]:
    return _safe_int(rec.get("id") or rec.get("customer_id") or rec.get("customerId"))


def _customer_name_from(rec: Dict[str, Any]) -> str:
    return str(rec.get("name") or rec.get("full_name") or rec.get("company_name") or "").strip()


def _customer_status_from(rec: Dict[str, Any]) -> str:
    return str(rec.get("status") or rec.get("state") or "").strip()


def _first_text(rec: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for k in keys:
        v = rec.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _customer_directory_row(rec: Dict[str, Any], now_iso: str) -> Tuple[Any, ...]:
    cid = _customer_id_from(rec) or 0
    name = _customer_name_from(rec)
    status = _customer_status_from(rec)
    email = _first_text(rec, ("email", "mail"))
    phone = _first_text(rec, ("phone", "phone_number", "tel"))
    mobile = _first_text(rec, ("mobile", "mobile_number", "cellphone", "cell_phone"))
    street_1 = _first_text(rec, ("street_1", "street1", "address1", "address_line_1"))
    street_2 = _first_text(rec, ("street_2", "street2", "address2", "address_line_2"))
    city = _first_text(rec, ("city", "town"))
    state = _first_text(rec, ("state", "province", "region"))
    zip_code = _first_text(rec, ("zip_code", "zip", "postcode", "postal_code"))
    country = _first_text(rec, ("country",))
    address_parts = [p for p in (street_1, street_2, city, state, zip_code, country) if p]
    address_text = ", ".join(address_parts)
    raw_json = _json.dumps(rec, ensure_ascii=False)
    return (
        int(cid),
        name,
        status,
        email,
        phone,
        mobile,
        street_1,
        street_2,
        city,
        state,
        zip_code,
        country,
        address_text,
        raw_json,
        now_iso,
    )


def _is_active_status(st: str) -> bool:
    s = (st or "").lower().strip()
    if s in ("active", "on", "yes", "1", "enabled"):
        return True
    if s in ("new", "blocked", "inactive", "off", "disabled", "0", ""):
        return False
    # Unknown — treat as active only if looks positive
    return s == "active" or "activ" in s


def _build_search_params_active() -> Dict[str, str]:
    """PHP-style nested query for main_attributes status = active."""
    return {
        "main_attributes[status][0]": "=",
        "main_attributes[status][1]": "active",
    }


def _fetch_all_pages(
    splynx_get: SplynxGet,
    path: str,
    limit: int,
    extra_params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    offset = 0
    while True:
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if extra_params:
            params.update(extra_params)
        try:
            data = splynx_get(path, params=params)
        except Exception:
            raise
        chunk = _normalize_list_payload(data)
        if not chunk:
            break
        out.extend(chunk)
        if len(chunk) < limit:
            break
        offset += limit
        _pause()
    return out


def run_full_sync(splynx_get: SplynxGet) -> Tuple[bool, str]:
    """
    Pull ACTIVE customers (paginated) + online sessions (paginated), merge MACs, optional deep lookup.
    """
    global _sync_in_progress, _sync_started_monotonic
    with _sync_lock:
        if _sync_in_progress and _sync_started_monotonic is not None:
            if time.monotonic() - _sync_started_monotonic > SYNC_LOCK_STALE_SEC:
                _sync_in_progress = False
                _sync_started_monotonic = None
        if _sync_in_progress:
            return False, "Sync already running"
        _sync_in_progress = True
        _sync_started_monotonic = time.monotonic()

    err_msg = ""
    try:
        init_db()

        # --- 1) ACTIVE customers (paginated, max PAGE_SIZE per request) ---
        active_rows: List[Dict[str, Any]] = []
        try:
            extra = _build_search_params_active()
            active_rows = _fetch_all_pages(
                splynx_get, "admin/customers/customer", PAGE_SIZE, extra_params=extra
            )
        except Exception:
            active_rows = []
            _pause()
            all_rows = _fetch_all_pages(splynx_get, "admin/customers/customer", PAGE_SIZE, None)
            active_rows = [r for r in all_rows if _is_active_status(_customer_status_from(r))]

        # De-dupe by id
        by_id: Dict[int, Dict[str, Any]] = {}
        for r in active_rows:
            cid = _customer_id_from(r)
            if cid:
                by_id[cid] = r

        only_ids = _optional_customer_id_filter()
        if only_ids:
            by_id = {cid: rec for cid, rec in by_id.items() if cid in only_ids}
            _meta_set(
                "location_sync_only_customer_ids",
                ",".join(str(x) for x in sorted(only_ids))[:200],
            )
            if not by_id:
                return (
                    False,
                    "LOCATION_SYNC_ONLY_CUSTOMER_IDS did not match any active customers — sync aborted.",
                )
        else:
            _meta_set("location_sync_only_customer_ids", "")

        # --- 1b) Internet services per customer (bulk + optional per-customer detail for multi-service)
        bulk_svcs = _fetch_internet_services_by_customer(splynx_get)
        services_by_c = merge_services_for_active_customers(
            splynx_get,
            bulk_svcs,
            sorted(by_id.keys()),
            _MERGE_CUSTOMER_SERVICES_ENV,
        )

        # --- 2) Online sessions → MAC map keyed by (customer_id, login key) and by id:<internet_service_id>
        online_mac: Dict[Tuple[int, str], Tuple[str, str]] = {}
        online_any_pool: Dict[int, List[Tuple[str, str]]] = defaultdict(list)
        for path in ONLINE_SESSION_PATHS:
            try:
                online_rows = _fetch_all_pages(splynx_get, path, ONLINE_PAGE_SIZE, None)
            except Exception:
                continue
            if online_rows:
                _meta_set("online_session_path_used", path[:200])
            for row in online_rows:
                if not isinstance(row, dict):
                    continue
                cid = _session_customer_id(row) or _safe_int(row.get("customer"))
                if not cid:
                    continue
                cid_i = int(cid)
                lk = _session_login_key(row)
                m = _mac_from_session_row(row)
                if not m:
                    continue
                online_mac[(cid_i, lk)] = (m, "online")
                if not lk:
                    online_mac[(cid_i, "")] = (m, "online")
                sid = _internet_service_id_from_record(row)
                if sid:
                    online_mac[(cid_i, f"id:{sid}")] = (m, "online")
                online_any_pool[cid_i].append((m, "online_any"))

        # --- 2b) Bulk session history → newest MAC per (customer) and per (customer, login)
        last_cid_map: Dict[int, Tuple[str, float]] = {}
        last_cl_map: Dict[Tuple[int, str], Tuple[str, float]] = {}
        bulk_rows, _bulk_path = _fetch_first_working_bulk_sessions(splynx_get)
        if bulk_rows:
            last_cid_map, last_cl_map = _build_last_session_mac_maps(bulk_rows)
            _meta_set("last_session_bulk_row_count", str(len(bulk_rows)))
        else:
            _meta_set("last_session_bulk_row_count", "0")

        # --- 3) Merge (one cache row per active internet service when bulk data exists)
        merged: List[Tuple[int, str, str, str, str, str, str]] = []
        directory_rows: List[Tuple[Any, ...]] = []
        detail_cache: Dict[int, Any] = {}
        now_iso = _now_iso()

        for cid, rec in by_id.items():
            directory_rows.append(_customer_directory_row(rec, now_iso))
            name = _customer_name_from(rec)
            st = _customer_status_from(rec)
            svcs = [s for s in services_by_c.get(cid, []) if _internet_service_row_active(s)]
            n_svcs = len(svcs)

            service_jobs: List[Tuple[str, Optional[Dict[str, Any]]]] = []
            if not svcs:
                service_jobs.append(("", None))
            else:
                for svc in svcs:
                    sk = str(svc.get("_location_sync_login_key") or _service_login_key(svc))
                    service_jobs.append((sk, svc))

            for login_k, svc_dict in service_jobs:
                mac_v = ""
                src_v = ""
                keys_try = _merge_login_keys_for_mac_lookup(login_k, svc_dict)
                for lk_try in keys_try:
                    om, osrc = _lookup_online_exact(cid, lk_try, online_mac)
                    if om:
                        mac_v, src_v = om, osrc
                        _pool_remove_mac_norm(online_any_pool, cid, om)
                        break
                if not mac_v:
                    om, osrc = _consume_online_any_fallback(cid, online_any_pool)
                    if om:
                        mac_v, src_v = om, osrc
                if not mac_v:
                    for lk_try in keys_try:
                        lm, ls = _lookup_last_session_exact(cid, lk_try, last_cl_map)
                        if lm:
                            mac_v, src_v = lm, ls
                            break
                if not mac_v:
                    lm, ls = _pick_last_session_customer_fallback(cid, last_cid_map)
                    if lm:
                        mac_v, src_v = lm, ls
                if not mac_v and svc_dict:
                    mx = _mac_from_record(svc_dict)
                    if mx:
                        mac_v, src_v = mx, "internet_service"
                if not mac_v:
                    mx2 = _mac_from_record(rec)
                    if mx2:
                        mac_v, src_v = mx2, "list"
                if not mac_v and DEEP_MAC:
                    pd = max(DEEP_PAUSE_SEC, BATCH_PAUSE_SEC)
                    time.sleep(pd)
                    if svc_dict:
                        mx = _mac_from_record(svc_dict)
                        if mx:
                            mac_v, src_v = mx, "internet_service"
                    if not mac_v and n_svcs <= 1:
                        if cid not in detail_cache:
                            try:
                                detail_cache[cid] = splynx_get(f"admin/customers/customer/{cid}")
                            except Exception:
                                detail_cache[cid] = {}
                        det = detail_cache[cid]
                        if isinstance(det, dict):
                            mx = _mac_from_record(det)
                            if mx:
                                mac_v, src_v = mx, "customer_detail"
                        if not mac_v:
                            try:
                                time.sleep(pd)
                                rsv = splynx_get(f"admin/customers/customer/{cid}/internet-services")
                                for s in _normalize_list_payload(rsv):
                                    mx = _mac_from_record(s)
                                    if mx:
                                        mac_v, src_v = mx, "internet_service"
                                        break
                            except Exception:
                                pass

                merged.append((cid, login_k, name, st, mac_v or "", src_v or "", now_iso))

        # --- 4) Write DB ---
        conn = get_conn()
        try:
            conn.execute("DELETE FROM location_sync_customers")
            conn.execute("DELETE FROM location_sync_customer_directory")
            conn.executemany(
                """
                INSERT INTO location_sync_customers
                (customer_id, service_login, customer_name, status, mac, mac_source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                merged,
            )
            if directory_rows:
                conn.executemany(
                    """
                    INSERT INTO location_sync_customer_directory
                    (
                        customer_id, customer_name, status, email, phone, mobile,
                        street_1, street_2, city, state, zip_code, country,
                        address_text, raw_json, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    directory_rows,
                )
            conn.commit()
        finally:
            conn.close()

        _meta_set("last_sync_at", _now_iso())
        _meta_set("last_sync_count", str(len(merged)))
        _meta_set("last_sync_error", "")
        prune_cross_ref_orphans()
        ok_msg = f"Synced {len(merged)} rows (customer × active service)."
        if only_ids:
            ok_msg += (
                " Partial run (LOCATION_SYNC_ONLY_CUSTOMER_IDS): cache now contains ONLY those "
                "customers; all other cached rows were removed."
            )
        return True, ok_msg
    except Exception as e:
        err_msg = str(e)
        _meta_set("last_sync_error", err_msg[:2000])
        return False, err_msg
    finally:
        with _sync_lock:
            _sync_in_progress = False
            _sync_started_monotonic = None


def get_mac_customer_map() -> Dict[str, Tuple[int, str]]:
    """Normalized MAC -> (customer_id, service_login) for cache rows (last wins if duplicate MAC)."""
    init_db()
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT customer_id, service_login, mac FROM location_sync_customers
        WHERE mac IS NOT NULL AND TRIM(mac) != ''
        """
    ).fetchall()
    conn.close()
    out: Dict[str, Tuple[int, str]] = {}
    for r in rows:
        m = normalize_mac_for_lookup(str(r["mac"]))
        if m:
            sl = str(r["service_login"] if r["service_login"] is not None else "")
            out[m] = (int(r["customer_id"]), sl)
    return out


def replace_cross_ref_for_router(
    router_id: int,
    vendor: str,
    router_location: str,
    rows: List[Tuple[int, str, str]],
) -> None:
    """
    rows: (customer_id, service_login, updated_at). router_location is the edge router site name.
    Clears prior cross-ref rows for this router_id, then inserts the new set.
    """
    rid = int(router_id)
    v = (vendor or "").strip()
    loc = (router_location or "").strip()
    init_db()
    conn = get_conn()
    conn.execute("DELETE FROM location_sync_cross_ref WHERE router_id = ?", (rid,))
    if rows:
        conn.executemany(
            """
            INSERT INTO location_sync_cross_ref
            (router_id, customer_id, service_login, vendor, router_location, updated_at)
            VALUES (?,?,?,?,?,?)
            """,
            [(rid, t[0], t[1], v, loc, t[2]) for t in rows],
        )
    conn.commit()
    conn.close()


def prune_cross_ref_orphans() -> None:
    init_db()
    conn = get_conn()
    conn.execute(
        """
        DELETE FROM location_sync_cross_ref
        WHERE NOT EXISTS (
            SELECT 1 FROM location_sync_customers c
            WHERE c.customer_id = location_sync_cross_ref.customer_id
              AND c.service_login = location_sync_cross_ref.service_login
        )
        """
    )
    conn.commit()
    conn.close()


_LS_SELECT_FROM = """
FROM location_sync_customers c
"""

_LS_SELECT_COLS = """
SELECT c.id, c.customer_id, c.service_login, c.customer_name, c.status, c.mac, c.mac_source, c.updated_at,
       (SELECT x.vendor FROM location_sync_cross_ref x
        WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
        ORDER BY x.updated_at DESC LIMIT 1) AS cross_ref_vendor,
       (SELECT x.router_id FROM location_sync_cross_ref x
        WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
        ORDER BY x.updated_at DESC LIMIT 1) AS cross_ref_router_id,
       (SELECT x.router_location FROM location_sync_cross_ref x
        WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
        ORDER BY x.updated_at DESC LIMIT 1) AS cross_ref_location,
       (SELECT x.updated_at FROM location_sync_cross_ref x
        WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
        ORDER BY x.updated_at DESC LIMIT 1) AS cross_ref_at
"""


def list_cached(
    offset: int = 0,
    limit: int = 500,
    search: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    init_db()
    offset = max(0, int(offset))
    limit = max(1, min(5000, int(limit)))
    conn = get_conn()
    term = (search or "").strip()
    try:
        if term:
            if term.isdigit():
                wc = "%" + term + "%"
                tid: Optional[int] = None
                try:
                    tid = int(term)
                except ValueError:
                    tid = None
                if tid is not None:
                    cnt = conn.execute(
                        """
                        SELECT COUNT(*) FROM location_sync_customers c
                        WHERE c.customer_id = ? OR CAST(c.customer_id AS TEXT) LIKE ?
                           OR c.customer_name LIKE ? COLLATE NOCASE
                           OR IFNULL(c.mac,'') LIKE ? COLLATE NOCASE
                           OR IFNULL(c.service_login,'') LIKE ? COLLATE NOCASE
                           OR EXISTS (
                             SELECT 1 FROM location_sync_cross_ref x
                             WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
                               AND IFNULL(x.router_location,'') LIKE ? COLLATE NOCASE
                           )
                        """,
                        (tid, wc, wc, wc, wc, wc),
                    ).fetchone()[0]
                    rows = conn.execute(
                        _LS_SELECT_COLS
                        + _LS_SELECT_FROM
                        + """
                        WHERE c.customer_id = ? OR CAST(c.customer_id AS TEXT) LIKE ?
                           OR c.customer_name LIKE ? COLLATE NOCASE
                           OR IFNULL(c.mac,'') LIKE ? COLLATE NOCASE
                           OR IFNULL(c.service_login,'') LIKE ? COLLATE NOCASE
                           OR EXISTS (
                             SELECT 1 FROM location_sync_cross_ref x
                             WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
                               AND IFNULL(x.router_location,'') LIKE ? COLLATE NOCASE
                           )
                        ORDER BY c.customer_id ASC, c.service_login ASC, c.id ASC
                        LIMIT ? OFFSET ?
                        """,
                        (tid, wc, wc, wc, wc, wc, limit, offset),
                    ).fetchall()
                    return [dict(r) for r in rows], int(cnt)
            wc = "%" + term + "%"
            cnt = conn.execute(
                """
                SELECT COUNT(*) FROM location_sync_customers c
                WHERE CAST(c.customer_id AS TEXT) LIKE ?
                   OR c.customer_name LIKE ? COLLATE NOCASE
                   OR IFNULL(c.mac,'') LIKE ? COLLATE NOCASE
                   OR IFNULL(c.service_login,'') LIKE ? COLLATE NOCASE
                   OR EXISTS (
                     SELECT 1 FROM location_sync_cross_ref x
                     WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
                       AND IFNULL(x.router_location,'') LIKE ? COLLATE NOCASE
                   )
                """,
                (wc, wc, wc, wc, wc),
            ).fetchone()[0]
            rows = conn.execute(
                _LS_SELECT_COLS
                + _LS_SELECT_FROM
                + """
                WHERE CAST(c.customer_id AS TEXT) LIKE ?
                   OR c.customer_name LIKE ? COLLATE NOCASE
                   OR IFNULL(c.mac,'') LIKE ? COLLATE NOCASE
                   OR IFNULL(c.service_login,'') LIKE ? COLLATE NOCASE
                   OR EXISTS (
                     SELECT 1 FROM location_sync_cross_ref x
                     WHERE x.customer_id = c.customer_id AND x.service_login = c.service_login
                       AND IFNULL(x.router_location,'') LIKE ? COLLATE NOCASE
                   )
                ORDER BY c.customer_id ASC, c.service_login ASC, c.id ASC
                LIMIT ? OFFSET ?
                """,
                (wc, wc, wc, wc, wc, limit, offset),
            ).fetchall()
            return [dict(r) for r in rows], int(cnt)

        total = int(conn.execute("SELECT COUNT(*) FROM location_sync_customers").fetchone()[0])
        rows = conn.execute(
            _LS_SELECT_COLS
            + _LS_SELECT_FROM
            + """
            ORDER BY c.customer_id ASC, c.service_login ASC, c.id ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows], total
    finally:
        conn.close()


def get_status() -> Dict[str, Any]:
    global _sync_in_progress, _sync_started_monotonic
    init_db()
    running_sec: Optional[int] = None
    with _sync_lock:
        if _sync_in_progress and _sync_started_monotonic is not None:
            if time.monotonic() - _sync_started_monotonic > SYNC_LOCK_STALE_SEC:
                _sync_in_progress = False
                _sync_started_monotonic = None
        if _sync_in_progress and _sync_started_monotonic is not None:
            running_sec = int(time.monotonic() - _sync_started_monotonic)
    return {
        "last_sync_at": _meta_get("last_sync_at"),
        "last_sync_count": _meta_get("last_sync_count"),
        "last_error": _meta_get("last_sync_error") or "",
        "in_progress": _sync_in_progress,
        "sync_running_seconds": running_sec,
        "sync_lock_stale_sec": int(SYNC_LOCK_STALE_SEC),
        "scheduler_enabled": is_location_sync_scheduler_enabled(),
        "interval_hours": round(INTERVAL_SEC / 3600.0, 2),
        "deep_mac_enabled": DEEP_MAC,
        "page_size": PAGE_SIZE,
        "online_session_path_used": _meta_get("online_session_path_used") or "",
        "last_session_bulk_path": _meta_get("last_session_bulk_path") or "",
        "last_session_bulk_row_count": _meta_get("last_session_bulk_row_count") or "",
        "last_session_bulk_error": _meta_get("last_session_bulk_error") or "",
        "last_cross_ref_at": _meta_get("last_cross_ref_at") or "",
        "last_cross_ref_stats": _meta_get("last_cross_ref_stats") or "",
        "location_sync_services_path_used": _meta_get("location_sync_services_path_used") or "",
        "merge_customer_endpoint": _MERGE_CUSTOMER_SERVICES_ENV,
        "location_sync_bulk_service_rows": _meta_get("location_sync_bulk_service_rows") or "",
        "location_sync_customer_service_fetches": _meta_get("location_sync_customer_service_fetches") or "",
        "location_sync_customer_service_detail_rows": _meta_get("location_sync_customer_service_detail_rows") or "",
        "location_sync_merge_customer_endpoint_mode": _meta_get("location_sync_merge_customer_endpoint_mode") or "",
        "location_sync_only_customer_ids": _meta_get("location_sync_only_customer_ids") or "",
    }


def get_cached_customer(customer_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    cid = int(customer_id or 0)
    if cid <= 0:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT customer_id, customer_name, status, email, phone, mobile,
                   street_1, street_2, city, state, zip_code, country,
                   address_text, updated_at, raw_json
            FROM location_sync_customer_directory
            WHERE customer_id = ?
            LIMIT 1
            """,
            (cid,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_customer_directory(offset: int = 0, limit: int = 200, search: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
    init_db()
    off = max(0, int(offset))
    lim = max(1, min(1000, int(limit)))
    term = (search or "").strip()
    conn = get_conn()
    try:
        if term:
            wc = "%" + term + "%"
            total = int(
                conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM location_sync_customer_directory d
                    WHERE CAST(d.customer_id AS TEXT) LIKE ?
                       OR IFNULL(d.customer_name, '') LIKE ? COLLATE NOCASE
                       OR IFNULL(d.address_text, '') LIKE ? COLLATE NOCASE
                       OR IFNULL(d.email, '') LIKE ? COLLATE NOCASE
                       OR IFNULL(d.phone, '') LIKE ? COLLATE NOCASE
                       OR IFNULL(d.mobile, '') LIKE ? COLLATE NOCASE
                    """,
                    (wc, wc, wc, wc, wc, wc),
                ).fetchone()[0]
            )
            rows = conn.execute(
                """
                SELECT customer_id, customer_name, status, email, phone, mobile,
                       street_1, street_2, city, state, zip_code, country,
                       address_text, updated_at
                FROM location_sync_customer_directory d
                WHERE CAST(d.customer_id AS TEXT) LIKE ?
                   OR IFNULL(d.customer_name, '') LIKE ? COLLATE NOCASE
                   OR IFNULL(d.address_text, '') LIKE ? COLLATE NOCASE
                   OR IFNULL(d.email, '') LIKE ? COLLATE NOCASE
                   OR IFNULL(d.phone, '') LIKE ? COLLATE NOCASE
                   OR IFNULL(d.mobile, '') LIKE ? COLLATE NOCASE
                ORDER BY d.customer_id ASC
                LIMIT ? OFFSET ?
                """,
                (wc, wc, wc, wc, wc, wc, lim, off),
            ).fetchall()
            return [dict(r) for r in rows], total
        total = int(conn.execute("SELECT COUNT(*) FROM location_sync_customer_directory").fetchone()[0])
        rows = conn.execute(
            """
            SELECT customer_id, customer_name, status, email, phone, mobile,
                   street_1, street_2, city, state, zip_code, country,
                   address_text, updated_at
            FROM location_sync_customer_directory
            ORDER BY customer_id ASC
            LIMIT ? OFFSET ?
            """,
            (lim, off),
        ).fetchall()
        return [dict(r) for r in rows], total
    finally:
        conn.close()


def sync_is_running() -> bool:
    global _sync_in_progress, _sync_started_monotonic
    with _sync_lock:
        if _sync_in_progress and _sync_started_monotonic is not None:
            if time.monotonic() - _sync_started_monotonic > SYNC_LOCK_STALE_SEC:
                _sync_in_progress = False
                _sync_started_monotonic = None
        return _sync_in_progress
