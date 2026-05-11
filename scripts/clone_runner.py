import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.wall_clock import wall_clock_iso


ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT_DIR / "scripts" / "clone_rebuild.sh"
STATE_DIR = Path(os.getenv("CLONE_STATE_DIR", str(ROOT_DIR / "data" / "clone-runs")))
STATE_DIR.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()
_active_run_id: Optional[str] = None
_runs_mem: Dict[str, Dict[str, Any]] = {}


def _now_iso() -> str:
    """Wall-clock timestamps for clone logs (see scripts.wall_clock)."""
    return wall_clock_iso()


def _run_path(run_id: str) -> Path:
    return STATE_DIR / f"{run_id}.json"


def _save(state: Dict[str, Any]) -> None:
    run_id = str(state.get("run_id") or "")
    if not run_id:
        return
    _run_path(run_id).write_text(json.dumps(state, indent=2), encoding="utf-8")


def _append_event(state: Dict[str, Any], kind: str, message: str) -> None:
    ev = {"ts": _now_iso(), "kind": kind, "message": str(message)}
    state.setdefault("events", []).append(ev)
    state["updated_at"] = _now_iso()
    _save(state)


def _redact(msg: str) -> str:
    out = str(msg or "")
    for key in (
        "POSTGRES_PASSWORD",
        "SESSION_SECRET",
        "FIREWALL_AGENT_TOKEN",
        "SMTP_PASSWORD",
        "SPLYNX_API_SECRET",
        "SPLYNX_API_KEY",
        "APP_USERS",
    ):
        out = out.replace(key, f"{key}=***")
    return out


def _runner(state: Dict[str, Any], argv: List[str]) -> None:
    global _active_run_id
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        state["pid"] = int(proc.pid)
        _save(state)
        assert proc.stdout is not None
        for line in proc.stdout:
            raw = line.rstrip("\n")
            safe = _redact(raw)
            if safe.startswith("PHASE "):
                state["phase"] = safe.split(" ", 1)[1].strip()
                _append_event(state, "phase", state["phase"])
            else:
                _append_event(state, "log", safe)
        rc = proc.wait()
        state["exit_code"] = int(rc)
        state["finished_at"] = _now_iso()
        state["status"] = "completed" if rc == 0 else "failed"
        _save(state)
    except Exception as e:
        state["status"] = "failed"
        state["finished_at"] = _now_iso()
        state["error"] = str(e)
        _append_event(state, "error", str(e))
        _save(state)
    finally:
        with _lock:
            _active_run_id = None


def start_clone(
    *,
    target_host: str,
    target_user: str,
    target_port: int,
    target_dir: str,
    ssh_key_path: str = "",
    confirm_phrase: str,
    dry_run: bool = False,
    override_text: str = "",
    host_fingerprint: str = "",
    profile: str = "full",
    services: Optional[List[str]] = None,
) -> Dict[str, Any]:
    # Only full clone is supported end-to-end; ignore legacy kwargs (old schedules, env wrappers).
    profile = "full"
    services = []
    global _active_run_id
    with _lock:
        if _active_run_id:
            raise RuntimeError("A clone run is already in progress")
        run_id = "clone-" + uuid.uuid4().hex[:12]
        state: Dict[str, Any] = {
            "run_id": run_id,
            "status": "running",
            "phase": "queued",
            "started_at": _now_iso(),
            "updated_at": _now_iso(),
            "target_host": str(target_host or "").strip(),
            "target_user": str(target_user or "").strip() or "root",
            "target_port": int(target_port or 22),
            "target_dir": str(target_dir or "").strip(),
            "dry_run": bool(dry_run),
            "host_fingerprint": str(host_fingerprint or "").strip(),
            "profile": str(profile or "full").strip() or "full",
            "services": [str(s).strip() for s in (services or []) if str(s).strip()],
            "events": [],
        }
        _runs_mem[run_id] = state
        _active_run_id = run_id
        _save(state)

    override_file = ""
    if str(override_text or "").strip():
        override_file = str(STATE_DIR / f"{run_id}.override.env")
        Path(override_file).write_text(str(override_text), encoding="utf-8")

    argv = [
        "bash",
        str(SCRIPT_PATH),
        "--target-host",
        str(target_host),
        "--target-user",
        state["target_user"],
        "--target-port",
        str(state["target_port"]),
        "--target-dir",
        state["target_dir"],
        "--confirm",
        str(confirm_phrase),
        "--run-id",
        run_id,
    ]
    if str(ssh_key_path or "").strip():
        argv.extend(["--ssh-key", str(ssh_key_path).strip()])
    if dry_run:
        argv.append("--dry-run")
    if override_file:
        argv.extend(["--override-file", override_file])
    if state.get("host_fingerprint"):
        argv.extend(["--host-fingerprint", str(state["host_fingerprint"])])
    if state.get("profile"):
        argv.extend(["--profile", str(state["profile"])])
    prof = str(state.get("profile") or "full")
    if state.get("services") and prof in ("services_only", "services_plus_db"):
        argv.extend(["--services", ",".join(state["services"])])

    t = threading.Thread(target=_runner, args=(state, argv), daemon=True)
    t.start()
    return state


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    rid = str(run_id or "").strip()
    if not rid:
        return None
    st = _runs_mem.get(rid)
    if st:
        return st
    p = _run_path(rid)
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            _runs_mem[rid] = data
            return data
        except Exception:
            return None
    return None


def list_runs(limit: int = 20) -> List[Dict[str, Any]]:
    """
    Merge JSON files on disk with in-memory runs. Previously only disk was listed, so a run that
    existed only in memory (or right after start before a successful re-read) could disappear from
    the UI until restart re-synced from disk.
    """
    by_id: Dict[str, Dict[str, Any]] = {}
    try:
        for p in sorted(STATE_DIR.glob("clone-*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                rid = str(data.get("run_id") or p.stem).strip()
                if rid:
                    by_id[rid] = data
            except Exception:
                continue
    except Exception:
        pass
    with _lock:
        for rid, st in _runs_mem.items():
            if rid and isinstance(st, dict):
                # Prefer fresher in-memory copy (active run events).
                by_id[str(rid)] = st

    def _ts(d: Dict[str, Any]) -> str:
        return str(d.get("started_at") or d.get("updated_at") or "")

    rows = sorted(by_id.values(), key=_ts, reverse=True)
    lim = max(1, min(100, int(limit)))
    return rows[:lim]


def active_run_id() -> str:
    with _lock:
        return str(_active_run_id or "")
