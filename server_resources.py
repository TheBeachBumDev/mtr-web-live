# Host resource snapshot for the Resources dashboard (Linux-first; optional psutil).
import concurrent.futures
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import auth_users
import db_runtime
import compose_control

# Admin-only HTML routes (not in PAGE_DEFINITIONS / Users RBAC list).
_ADMIN_ONLY_PATHS: Tuple[str, ...] = ("/users", "/audit-log")

# RBAC page_key → docker-compose `services:` name (see docker-compose.yml). Update when you split a tab to its own container.
PAGE_KEY_COMPOSE_SERVICE: Dict[str, str] = {
    "home": "core",
    "mtr_live": "mtr_live",
    "download_test": "download_test",
    "fieldtech": "fieldtech",
    "ipam": "ipam",
    "monitoring": "monitoring",
    "routers": "routers",
    "backhauls": "backhauls",
    "stock_management": "stock_management",
    "sales_log": "stock_management",
    "purchase_orders": "purchase_orders",
    "whatsapp_signups": "whatsapp_signups",
    "backups": "core",
    "firewall": "core",
    "location_sync": "location_sync",
    "resources": "core",
}

# Row order in Resources → Modules and services (app stacks first, then infra tail).
_COMPOSE_SERVICE_TOPOLOGY_ORDER: Tuple[str, ...] = (
    "core",
    "mtr_live",
    "download_test",
    "fieldtech",
    "ipam",
    "location_sync",
    "monitoring",
    "routers",
    "backhauls",
    "stock_management",
    "purchase_orders",
    "whatsapp_signups",
)

# Per compose service: container/upstream must match docker-compose.yml publish ports on loopback.
_COMPOSE_SERVICE_META: Dict[str, Dict[str, str]] = {
    "core": {
        "container": "mtr-core",
        "upstream": "127.0.0.1:9002",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/* (role-scoped on core container)",
    },
    "mtr_live": {
        "container": "mtr-live",
        "upstream": "127.0.0.1:9009",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/traffic*, /api/runs*, /api/active*, /api/pdf_summary*, /ws/mtr*",
    },
    "download_test": {
        "container": "mtr-download-test",
        "upstream": "127.0.0.1:9010",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/traffic*, /download/purchase-orders-user-guide*",
    },
    "fieldtech": {
        "container": "mtr-fieldtech",
        "upstream": "127.0.0.1:9011",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/fieldtech*",
    },
    "ipam": {
        "container": "mtr-ipam",
        "upstream": "127.0.0.1:9012",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/ipam*",
    },
    "location_sync": {
        "container": "mtr-location-sync",
        "upstream": "127.0.0.1:9008",
        "data": "PostgreSQL (shared, local customer directory cache)",
        "path_extra": ", /api/location-sync",
    },
    "monitoring": {
        "container": "mtr-monitoring",
        "upstream": "127.0.0.1:9004",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/monitoring, /api/push",
    },
    "routers": {
        "container": "mtr-routers",
        "upstream": "127.0.0.1:9003",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/routers",
    },
    "backhauls": {
        "container": "mtr-backhauls",
        "upstream": "127.0.0.1:9005",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/backhauls",
    },
    "stock_management": {
        "container": "mtr-stock-management",
        "upstream": "127.0.0.1:9006",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/stock*",
    },
    "purchase_orders": {
        "container": "mtr-purchase-orders",
        "upstream": "127.0.0.1:9007",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/po*",
    },
    "whatsapp_signups": {
        "container": "mtr-whatsapp-signups",
        "upstream": "127.0.0.1:9013",
        "data": "PostgreSQL (shared)",
        "path_extra": ", /api/whatsapp-signups*",
    },
}

_CPU_WARN = float(os.getenv("RESOURCE_CPU_WARN", "75"))
_CPU_CRIT = float(os.getenv("RESOURCE_CPU_CRIT", "90"))
_MEM_WARN = float(os.getenv("RESOURCE_MEM_WARN", "80"))
_MEM_CRIT = float(os.getenv("RESOURCE_MEM_CRIT", "92"))
_DISK_WARN = float(os.getenv("RESOURCE_DISK_WARN", "82"))
_DISK_CRIT = float(os.getenv("RESOURCE_DISK_CRIT", "93"))
# Compared to raw 1m load unless RESOURCE_LOAD_PER_CORE=1 (then value is load / CPU count).
_LOAD_WARN = float(os.getenv("RESOURCE_LOAD_WARN", "1.0"))
_LOAD_CRIT = float(os.getenv("RESOURCE_LOAD_CRIT", "2.0"))
_LOAD_PER_CORE = os.getenv("RESOURCE_LOAD_PER_CORE", "1").strip() == "1"
# Bound blocking Docker / DB calls so /api/resources cannot hang the browser poll forever.
_COMPOSE_STATUS_TIMEOUT = float(os.getenv("RESOURCE_COMPOSE_TIMEOUT_SEC", "10"))
_POSTGRES_STATS_TIMEOUT = float(os.getenv("RESOURCE_POSTGRES_TIMEOUT_SEC", "8"))


def _safe_float_metric(x: Any) -> Optional[float]:
    """Avoid TypeError/ValueError crashing /api/resources when metrics are NaN or malformed."""
    if x is None:
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


# Comma-separated mount paths to report (default: root only).
_DISK_PATHS_RAW = os.getenv("RESOURCE_DISK_PATHS", "/").strip()


def _level(v: float, warn: float, crit: float, *, higher_is_worse: bool = True) -> str:
    if higher_is_worse:
        if v >= crit:
            return "crit"
        if v >= warn:
            return "warn"
    else:
        if v <= crit:
            return "crit"
        if v <= warn:
            return "warn"
    return "ok"


def _disk_paths() -> List[str]:
    parts = [p.strip() for p in _DISK_PATHS_RAW.split(",") if p.strip()]
    return parts or ["/"]


def _read_proc_stat_cpu() -> Optional[Tuple[int, int]]:
    """Return (total jiffies, idle jiffies) from aggregate cpu line."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline()
    except OSError:
        return None
    if not line.startswith("cpu "):
        return None
    parts = line.split()
    if len(parts) < 5:
        return None
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    total = sum(nums)
    return total, idle


def _cpu_percent_linux(interval: float = 0.12) -> Optional[float]:
    a = _read_proc_stat_cpu()
    if not a:
        return None
    time.sleep(interval)
    b = _read_proc_stat_cpu()
    if not b:
        return None
    dt = b[0] - a[0]
    di = b[1] - a[1]
    if dt <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (1.0 - di / dt)))


def _mem_linux() -> Tuple[Optional[float], Optional[int], Optional[int]]:
    """Return (used_percent, used_bytes, total_bytes) using MemAvailable when present."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return None, None, None
    kv = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, rest = line.split(":", 1)
        kv[k.strip()] = rest.strip()
    try:
        total_kb = int(kv.get("MemTotal", "0").split()[0])
    except (IndexError, ValueError):
        total_kb = 0
    if total_kb <= 0:
        return None, None, None
    avail_kb = None
    if "MemAvailable" in kv:
        try:
            avail_kb = int(kv["MemAvailable"].split()[0])
        except (IndexError, ValueError):
            avail_kb = None
    if avail_kb is None:
        try:
            free_kb = int(kv.get("MemFree", "0").split()[0])
            buffers = int(kv.get("Buffers", "0").split()[0])
            cached = int(kv.get("Cached", "0").split()[0])
            avail_kb = free_kb + buffers + cached
        except (IndexError, ValueError):
            avail_kb = 0
    used_kb = max(0, total_kb - avail_kb)
    pct = 100.0 * used_kb / total_kb
    unit = 1024
    return pct, used_kb * unit, total_kb * unit


def _loadavg_unix() -> Optional[Tuple[float, float, float]]:
    try:
        return os.getloadavg()
    except (AttributeError, OSError):
        pass
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (OSError, IndexError, ValueError):
        return None


def _uptime_sec_linux() -> Optional[float]:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _disk_usage(path: str) -> Optional[Dict[str, Any]]:
    try:
        import shutil

        u = shutil.disk_usage(path)
        pct = 100.0 * (u.total - u.free) / u.total if u.total > 0 else 0.0
        return {
            "path": path,
            "percent_used": round(pct, 1),
            "free_gb": round(u.free / 1e9, 2),
            "total_gb": round(u.total / 1e9, 2),
            "status": _level(pct, _DISK_WARN, _DISK_CRIT),
        }
    except OSError:
        return None


def _postgres_stats() -> Optional[Dict[str, Any]]:
    """Live Postgres metrics when DB_BACKEND=postgres (same DSN as app)."""
    if not db_runtime.is_postgres():
        return None
    try:
        conn = db_runtime.get_conn("postgres")
        try:
            row = conn.execute(
                """
                SELECT
                  pg_size_pretty(pg_database_size(current_database())) AS pretty,
                  pg_database_size(current_database())::bigint AS bytes
                """
            ).fetchone()
            pretty = str(row[0]) if row else None
            nbytes = int(row[1]) if row and row[1] is not None else None
            nconn = conn.execute(
                """
                SELECT COUNT(*)::bigint
                FROM pg_stat_activity
                WHERE datname = current_database()
                """
            ).fetchone()
            connections = int(nconn[0]) if nconn and nconn[0] is not None else None
            mig = None
            try:
                mrow = conn.execute(
                    "SELECT COUNT(*)::bigint FROM schema_migrations"
                ).fetchone()
                mig = int(mrow[0]) if mrow and mrow[0] is not None else None
            except Exception:
                pass
            return {
                "database": os.getenv("POSTGRES_DB", "mtr"),
                "host": os.getenv("POSTGRES_HOST", "postgres"),
                "port": os.getenv("POSTGRES_PORT", "5432"),
                "size_pretty": pretty,
                "size_bytes": nbytes,
                "connections": connections,
                "schema_migrations": mig,
            }
        finally:
            conn.close()
    except Exception as e:
        return {"error": str(e)}


def _postgres_stats_bounded() -> Optional[Dict[str, Any]]:
    """Same as _postgres_stats but cannot block the request indefinitely."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_postgres_stats)
        try:
            return fut.result(timeout=_POSTGRES_STATS_TIMEOUT)
        except concurrent.futures.TimeoutError:
            logging.warning(
                "server_resources: Postgres stats timed out after %ss", _POSTGRES_STATS_TIMEOUT
            )
            return {"error": f"Postgres metrics timed out after {_POSTGRES_STATS_TIMEOUT:g}s"}
        except Exception as e:
            return {"error": str(e)[:500]}


def _compose_services_status_bounded() -> Dict[str, Any]:
    """Docker compose listing can stall if the engine is wedged; never block the HTTP poll forever."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(compose_control.compose_services_status)
        try:
            return fut.result(timeout=_COMPOSE_STATUS_TIMEOUT)
        except concurrent.futures.TimeoutError:
            logging.warning(
                "server_resources: compose_services_status timed out after %ss",
                _COMPOSE_STATUS_TIMEOUT,
            )
            return {
                "_error": (
                    f"Compose runtime status timed out after {_COMPOSE_STATUS_TIMEOUT:g}s "
                    "(Docker API slow or stuck)."
                )[:500]
            }
        except Exception as e:
            return {"_error": str(e)[:500]}


def _path_sort_key(path: str) -> Tuple[int, str]:
    """Stable sort: root path first, then alphabetically."""
    if path == "/":
        return (0, path)
    return (1, path)


def _topology_rows_from_page_definitions() -> List[Dict[str, Any]]:
    """
    One table row per Compose app service. Tab labels come from PAGE_DEFINITIONS, grouped by
    PAGE_KEY_COMPOSE_SERVICE (not one mega «core» row for every product name).
    """
    grouped: Dict[str, List[Tuple[str, str]]] = {}
    for key, label in auth_users.PAGE_DEFINITIONS:
        svc = PAGE_KEY_COMPOSE_SERVICE.get(key, "core")
        grouped.setdefault(svc, []).append((key, label))

    rows: List[Dict[str, Any]] = []
    for svc in _COMPOSE_SERVICE_TOPOLOGY_ORDER:
        items = grouped.get(svc) or []
        if not items:
            continue
        meta = _COMPOSE_SERVICE_META.get(svc)
        if not meta:
            continue
        labels = ", ".join(lab for _, lab in items)
        if svc == "core":
            labels += ", Users (admin), Audit log (admin)"
        paths_set: Set[str] = set()
        for k, _ in items:
            paths_set.add(auth_users.page_landing_path(k))
        if svc == "core":
            paths_set.update(_ADMIN_ONLY_PATHS)
        ordered_paths = sorted(paths_set, key=_path_sort_key)
        paths_str = ", ".join(ordered_paths) + meta.get("path_extra", "")
        rows.append(
            {
                "module": labels,
                "service": svc,
                "container": meta["container"],
                "upstream": meta["upstream"],
                "paths": paths_str,
                "data": meta["data"],
            }
        )
    return rows


# Infrastructure not tied to a single RBAC page row (edge proxy + datastores).
_MODULE_TOPOLOGY_INFRA: List[Dict[str, Any]] = [
    {
        "module": "Nginx (or other reverse proxy)",
        "service": "host / edge",
        "container": "n/a (not defined in compose)",
        "upstream": "proxies to 127.0.0.1:9002–9012",
        "paths": "TLS + path routing to app services",
        "data": "n/a",
    },
    {
        "module": "PostgreSQL",
        "service": "postgres",
        "container": "mtr-postgres",
        "upstream": "internal 5432",
        "paths": "n/a",
        "data": "Docker volume postgres_data",
    },
    {
        "module": "Redis",
        "service": "redis",
        "container": "mtr-redis",
        "upstream": "internal 6379",
        "paths": "n/a",
        "data": "Docker volume redis_data",
    },
]


# UI: Docker service + loopback port per area; runtime status matches `service` to compose_services.
MODULE_TOPOLOGY: List[Dict[str, Any]] = _topology_rows_from_page_definitions() + _MODULE_TOPOLOGY_INFRA


def _snapshot_psutil() -> Optional[Dict[str, Any]]:
    try:
        import psutil  # type: ignore
    except ImportError:
        return None

    cpu = float(psutil.cpu_percent(interval=0.15))
    vm = psutil.virtual_memory()
    mem_pct = float(vm.percent)
    mem_used = int(vm.used)
    mem_total = int(vm.total)
    swap_pct: Optional[float] = None
    try:
        sm = psutil.swap_memory()
        if sm.total > 0:
            swap_pct = float(sm.percent)
    except Exception:
        pass

    disks: List[Dict[str, Any]] = []
    for p in _disk_paths():
        try:
            u = psutil.disk_usage(p)
            pct = float(u.percent)
            disks.append(
                {
                    "path": p,
                    "percent_used": round(pct, 1),
                    "free_gb": round(u.free / 1e9, 2),
                    "total_gb": round(u.total / 1e9, 2),
                    "status": _level(pct, _DISK_WARN, _DISK_CRIT),
                }
            )
        except OSError:
            disks.append({"path": p, "error": "unreadable"})

    try:
        load_t = os.getloadavg()
    except OSError:
        load_t = None
    boot = psutil.boot_time()
    uptime_sec = max(0.0, time.time() - boot)

    return {
        "source": "psutil",
        "cpu_percent": round(cpu, 1),
        "mem_percent": round(mem_pct, 1),
        "mem_used_bytes": mem_used,
        "mem_total_bytes": mem_total,
        "swap_percent": round(swap_pct, 1) if swap_pct is not None else None,
        "disks": disks,
        "loadavg": [round(load_t[0], 2), round(load_t[1], 2), round(load_t[2], 2)] if load_t else None,
        "uptime_sec": round(uptime_sec, 1),
    }


def _snapshot_stdlib_linux() -> Dict[str, Any]:
    cpu = _cpu_percent_linux()
    mem_pct, mem_used, mem_total = _mem_linux()
    disks = []
    for p in _disk_paths():
        d = _disk_usage(p)
        if d:
            disks.append(d)
    la = _loadavg_unix()
    uptime = _uptime_sec_linux()
    out: Dict[str, Any] = {
        "source": "proc",
        "cpu_percent": round(cpu, 1) if cpu is not None else None,
        "mem_percent": round(mem_pct, 1) if mem_pct is not None else None,
        "mem_used_bytes": mem_used,
        "mem_total_bytes": mem_total,
        "swap_percent": None,
        "disks": disks,
        "loadavg": [round(la[0], 2), round(la[1], 2), round(la[2], 2)] if la else None,
        "uptime_sec": round(uptime, 1) if uptime is not None else None,
    }
    return out


def _snapshot_core() -> Dict[str, Any]:
    """
    One-shot host metrics for the dashboard. Prefer psutil when installed for best accuracy.
    """
    host = ""
    try:
        import socket

        host = socket.gethostname()
    except Exception:
        pass

    data: Dict[str, Any]
    try:
        data = _snapshot_psutil() or _snapshot_stdlib_linux()
    except Exception:
        logging.exception("server_resources: metrics collection failed")
        data = {
            "source": "none",
            "cpu_percent": None,
            "mem_percent": None,
            "mem_used_bytes": None,
            "mem_total_bytes": None,
            "swap_percent": None,
            "disks": [],
            "loadavg": None,
            "uptime_sec": None,
        }

    cpu_f = _safe_float_metric(data.get("cpu_percent"))
    mem_f = _safe_float_metric(data.get("mem_percent"))
    cpu_st = _level(cpu_f, _CPU_WARN, _CPU_CRIT) if cpu_f is not None else "unknown"
    mem_st = _level(mem_f, _MEM_WARN, _MEM_CRIT) if mem_f is not None else "unknown"

    disk_st_list = [d.get("status") for d in data.get("disks") or [] if isinstance(d, dict)]
    worst_disk = "ok"
    for s in disk_st_list:
        if s == "crit":
            worst_disk = "crit"
            break
        if s == "warn" and worst_disk != "crit":
            worst_disk = "warn"

    la = data.get("loadavg")
    load_st = "ok"
    if isinstance(la, (list, tuple)) and len(la) >= 1:
        l1_raw = _safe_float_metric(la[0])
        if l1_raw is None:
            load_st = "unknown"
        else:
            l1 = l1_raw
            if _LOAD_PER_CORE:
                ncpu_ld = max(1, (os.cpu_count() or 1))
                l1 = l1 / ncpu_ld
            load_st = _level(l1, _LOAD_WARN, _LOAD_CRIT)
    elif la is None:
        load_st = "unknown"

    order = {"ok": 0, "unknown": 1, "warn": 2, "crit": 3}
    overall = "ok"
    for st in (cpu_st, mem_st, worst_disk, load_st):
        if st in order and order[st] > order[overall]:
            overall = st

    pg = _postgres_stats_bounded()
    compose_modules = _compose_services_status_bounded()
    ncpu = max(1, (os.cpu_count() or 1))
    return {
        "ok": True,
        "hostname": host,
        "cpu_count": ncpu,
        "thresholds": {
            "cpu_warn": _CPU_WARN,
            "cpu_crit": _CPU_CRIT,
            "mem_warn": _MEM_WARN,
            "mem_crit": _MEM_CRIT,
            "disk_warn": _DISK_WARN,
            "disk_crit": _DISK_CRIT,
            "load_warn": _LOAD_WARN,
            "load_crit": _LOAD_CRIT,
            "load_per_core": _LOAD_PER_CORE,
        },
        "metrics": data,
        "status": {
            "cpu": cpu_st,
            "memory": mem_st,
            "disk_worst": worst_disk,
            "load": load_st,
            "overall": overall,
        },
        # Match db_runtime (normalized at import); do not re-read raw env here — avoids drift vs the live app.
        "db_backend": db_runtime.DB_BACKEND,
        "postgres_mode": db_runtime.is_postgres(),
        "postgres": pg,
        "module_topology": MODULE_TOPOLOGY,
        "compose_services": compose_modules,
        "storage_note": "Primary data store is PostgreSQL.",
    }


def snapshot() -> Dict[str, Any]:
    """Never raise — a 500 here blanks the entire Resources page (all panels use this JSON)."""
    try:
        return _snapshot_core()
    except Exception as e:
        logging.exception("server_resources.snapshot failed")
        ncpu = max(1, (os.cpu_count() or 1))
        err = str(e)
        return {
            "ok": False,
            "error": err,
            "hostname": "",
            "cpu_count": ncpu,
            "thresholds": {
                "cpu_warn": _CPU_WARN,
                "cpu_crit": _CPU_CRIT,
                "mem_warn": _MEM_WARN,
                "mem_crit": _MEM_CRIT,
                "disk_warn": _DISK_WARN,
                "disk_crit": _DISK_CRIT,
                "load_warn": _LOAD_WARN,
                "load_crit": _LOAD_CRIT,
                "load_per_core": _LOAD_PER_CORE,
            },
            "metrics": {
                "source": "error",
                "cpu_percent": None,
                "mem_percent": None,
                "disks": [],
                "loadavg": None,
            },
            "status": {
                "cpu": "unknown",
                "memory": "unknown",
                "disk_worst": "unknown",
                "load": "unknown",
                "overall": "unknown",
            },
            "db_backend": db_runtime.DB_BACKEND,
            "postgres_mode": db_runtime.is_postgres(),
            "postgres": {"error": err},
            "module_topology": MODULE_TOPOLOGY,
            "compose_services": {"_error": err[:500]},
            "storage_note": "Primary data store is PostgreSQL.",
        }
