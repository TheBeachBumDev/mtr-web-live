# Docker Compose helpers for admin-only stack operations from mtr-core (docker.sock mounted).
# Runtime status and per-service restarts use the Docker Engine HTTP API (docker PyPI package) so we do not
# depend on a `docker` CLI binary inside the container. Full stack rebuild still shells out to docker compose.
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

ENGINE_UNAVAILABLE_MSG = (
    "Cannot talk to the Docker engine on this host. For the core container, mount the host socket "
    "as /var/run/docker.sock (see docker-compose.yml). Runtime status uses the API, not the docker CLI."
)

CLI_MISSING_MSG = (
    "Compose CLI not found. Full rebuild needs either `docker compose` (Compose v2 plugin) or "
    "`docker-compose` on the host, or set DOCKER_BIN to the docker binary (e.g. /usr/bin/docker)."
)

ROOT_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = os.getenv("COMPOSE_FILE", str(ROOT_DIR / "docker-compose.yml"))
COMPOSE_PROJECT_NAME = os.getenv("COMPOSE_PROJECT_NAME", "mtr-web-live")

# Compose service keys from docker-compose.yml (not container_name).
ALLOWED_SERVICES = frozenset(
    {
        "core",
        "mtr_live",
        "download_test",
        "fieldtech",
        "ipam",
        "monitoring",
        "location_sync",
        "routers",
        "backhauls",
        "stock_management",
        "purchase_orders",
        "whatsapp_signups",
        "postgres",
        "redis",
    }
)
_SERVICE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,48}$")

_LEVEL_RANK = {"crit": 3, "warn": 2, "unknown": 1, "ok": 0}


def compose_project_dir() -> str:
    return str(Path(COMPOSE_FILE).resolve().parent)


def _docker_bin() -> Optional[str]:
    """Resolve docker executable for subprocess fallbacks (restart CLI, full rebuild)."""
    explicit = (os.environ.get("DOCKER_BIN") or "").strip()
    if explicit:
        try:
            rp = os.path.realpath(explicit)
            if os.path.isfile(rp):
                return rp
        except OSError:
            pass
    # Prefer well-known paths first (PATH inside uvicorn/cron is often minimal; os.access(X_OK) can lie on some mounts).
    candidates: List[str] = []
    candidates.extend(
        (
            "/usr/bin/docker",
            "/bin/docker",
            "/usr/local/bin/docker",
            "/snap/bin/docker",
        )
    )
    w = shutil.which("docker")
    if w:
        candidates.append(w)
    seen: Set[str] = set()
    for p in candidates:
        if not p or p in seen:
            continue
        seen.add(p)
        try:
            if os.path.isfile(p):
                return os.path.realpath(p)
        except OSError:
            continue
    return None


def _docker_compose_standalone_bin() -> Optional[str]:
    """Docker Compose v1 binary (`docker-compose`), present in the stock Dockerfile."""
    for cand in (
        shutil.which("docker-compose"),
        "/usr/bin/docker-compose",
        "/usr/local/bin/docker-compose",
    ):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _compose_env() -> dict:
    env = os.environ.copy()
    b = _docker_bin()
    if not b:
        return env
    d = os.path.dirname(b)
    if not d:
        return env
    path = env.get("PATH", "")
    parts = [x for x in path.split(os.pathsep) if x]
    if d not in parts:
        env["PATH"] = d + os.pathsep + path if path else d
    return env


def _compose_base() -> Optional[List[str]]:
    """
    argv prefix for compose file ops: either `docker compose -f … -p …` or `docker-compose -f … -p …`.
    Debian `docker.io` may ship without the Compose v2 plugin; the image also installs `docker-compose` (v1).
    """
    suffix = ["-f", COMPOSE_FILE, "-p", COMPOSE_PROJECT_NAME]
    env = _compose_env()
    db = _docker_bin()
    if db:
        try:
            r = subprocess.run(
                [db, "compose", "version"],
                cwd=compose_project_dir(),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode == 0:
                return [db, "compose", *suffix]
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass
    standalone = _docker_compose_standalone_bin()
    if standalone:
        return [standalone, *suffix]
    if db:
        return [db, "compose", *suffix]
    return None


def validate_service_name(service: str) -> str:
    s = (service or "").strip()
    if not _SERVICE_RE.match(s) or s not in ALLOWED_SERVICES:
        raise ValueError("Unknown or invalid compose service name")
    return s


def _infer_health(status_line: str) -> str:
    sl = (status_line or "").lower()
    if "(healthy)" in sl:
        return "healthy"
    if "(unhealthy)" in sl:
        return "unhealthy"
    if "(starting)" in sl:
        return "starting"
    return ""


def _status_level(state: str, health: str) -> str:
    st = (state or "").lower()
    h = (health or "").lower()
    if st == "running":
        if h == "unhealthy":
            return "crit"
        if h == "healthy":
            return "ok"
        if h == "starting":
            return "warn"
        return "ok"
    if st in ("exited", "dead", "removing"):
        return "crit"
    if st in ("paused", "restarting"):
        return "warn"
    return "unknown"


def _merge_level(a: str, b: str) -> str:
    return a if _LEVEL_RANK.get(a, 0) >= _LEVEL_RANK.get(b, 0) else b


def _compose_services_status_engine() -> Optional[Dict[str, Any]]:
    """Fill compose_services from the Docker Engine API (no docker CLI)."""
    try:
        import docker
    except Exception:
        # Broken deps (e.g. pyOpenSSL / urllib3 mismatch) raise AttributeError, not ImportError.
        # Fall back to CLI path instead of crashing /api/resources.
        return None
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        return {"_error": f"{ENGINE_UNAVAILABLE_MSG} ({e})"[:500]}

    want_proj = (COMPOSE_PROJECT_NAME or "").strip().lower()
    out: Dict[str, Any] = {}
    try:
        for c in client.containers.list(all=True):
            labels = c.labels or {}
            proj = (labels.get("com.docker.compose.project") or "").strip().lower()
            if not proj or proj != want_proj:
                continue
            svc = (labels.get("com.docker.compose.service") or "").strip()
            if not svc:
                continue
            st = c.attrs.get("State") or {}
            state = (c.status or st.get("Status") or "unknown").lower()
            health_obj = st.get("Health") or {}
            health = (health_obj.get("Status") or "").strip().lower()
            if not health:
                health = _infer_health(state)
            name = (getattr(c, "name", None) or (c.attrs.get("Name") or "")).lstrip("/")
            status_line = (st.get("Status") or "") or ""
            disp_parts: List[str] = []
            if state:
                disp_parts.append(state)
            if health:
                disp_parts.append(health)
            elif status_line:
                disp_parts.append(status_line)
            display = " · ".join(disp_parts) if disp_parts else (status_line or "unknown")
            level = _status_level(state, health)
            rec = {
                "container": name,
                "state": state or "unknown",
                "health": health or None,
                "status_line": status_line,
                "display": display,
                "level": level,
            }
            if svc not in out:
                out[svc] = rec
            else:
                prev = out[svc]
                out[svc] = {
                    **prev,
                    "level": _merge_level(level, prev.get("level", "unknown")),
                    "display": prev.get("display") + "; " + display if prev.get("display") else display,
                }
    except Exception as e:
        return {"_error": str(e)[:500]}
    return out


def _compose_services_status_cli() -> Dict[str, Any]:
    """Legacy: docker compose ps JSON (requires docker CLI)."""
    base = _compose_base()
    if not base:
        return {"_error": CLI_MISSING_MSG}
    cmd = base + ["ps", "-a", "--format", "json"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=compose_project_dir(),
            env=_compose_env(),
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
    except FileNotFoundError:
        return {"_error": CLI_MISSING_MSG}
    except Exception as e:
        return {"_error": str(e)[:500]}
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "compose ps failed").strip()
        return {"_error": err[:500]}
    raw_out = (proc.stdout or "").strip()
    parsed_rows: List[Dict[str, Any]] = []
    if raw_out.startswith("["):
        try:
            arr = json.loads(raw_out)
            if isinstance(arr, list):
                parsed_rows = [x for x in arr if isinstance(x, dict)]
        except json.JSONDecodeError:
            parsed_rows = []
    if not parsed_rows:
        for line in raw_out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed_rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out: Dict[str, Any] = {}
    for row in parsed_rows:
        svc = str(row.get("Service") or "").strip()
        if not svc:
            continue
        state = str(row.get("State") or "").strip().lower()
        status_line = str(row.get("Status") or "").strip()
        health = str(row.get("Health") or "").strip().lower()
        if not health:
            health = _infer_health(status_line)
        name = str(row.get("Name") or "").strip()
        disp_parts = [state] if state else []
        if health:
            disp_parts.append(health)
        elif status_line:
            disp_parts.append(status_line)
        display = " · ".join(disp_parts) if disp_parts else (status_line or "unknown")
        out[svc] = {
            "container": name,
            "state": state or "unknown",
            "health": health or None,
            "status_line": status_line,
            "display": display,
            "level": _status_level(state, health),
        }
    return out


def compose_services_status() -> Dict[str, Any]:
    """
    Per-compose-service runtime status. Prefer Docker Engine API (socket); fall back to `docker compose ps`.
    """
    eng = _compose_services_status_engine()
    if eng is not None and "_error" not in eng:
        return eng
    cli = _compose_services_status_cli()
    if "_error" not in cli:
        return cli
    if eng is not None and "_error" in eng:
        return {"_error": eng["_error"]}
    return cli


def restart_service_async(service: str) -> str:
    """Restart one compose service via Engine API, else `docker compose restart`."""
    s = validate_service_name(service)
    try:
        import docker

        client = docker.from_env()
        client.ping()
        want_proj = (COMPOSE_PROJECT_NAME or "").strip().lower()
        restarted = False
        for c in client.containers.list(all=True):
            labels = c.labels or {}
            if (labels.get("com.docker.compose.project") or "").strip().lower() != want_proj:
                continue
            if (labels.get("com.docker.compose.service") or "").strip() != s:
                continue
            c.restart(timeout=10)
            restarted = True
        if restarted:
            return s
    except Exception:
        pass

    base = _compose_base()
    if not base:
        raise RuntimeError(ENGINE_UNAVAILABLE_MSG + " " + CLI_MISSING_MSG)
    cmd = base + ["restart", s]
    subprocess.Popen(
        cmd,
        cwd=compose_project_dir(),
        env=_compose_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return s


def rebuild_stack_async() -> None:
    """Fire-and-forget full stack rebuild (requires docker compose CLI)."""
    base = _compose_base()
    if not base:
        raise RuntimeError(CLI_MISSING_MSG)
    cmd = base + ["up", "-d", "--build", "--force-recreate"]
    subprocess.Popen(
        cmd,
        cwd=compose_project_dir(),
        env=_compose_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
