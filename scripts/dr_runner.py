import json
import os
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from scripts.wall_clock import wall_clock_iso

ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT_DIR / "scripts" / "dr_promote.sh"
STATE_DIR = ROOT_DIR / "data" / "dr-runs"
STATE_DIR.mkdir(parents=True, exist_ok=True)
MODE_PATH = ROOT_DIR / "data" / "dr_mode.json"

_lock = threading.Lock()
_active: Optional[str] = None
_runs: Dict[str, Dict[str, Any]] = {}


def _now() -> str:
    """Same as clone_runner wall-clock (see scripts.wall_clock)."""
    return wall_clock_iso()


def _save(st: Dict[str, Any]) -> None:
    rid = str(st.get("run_id") or "")
    if rid:
        (STATE_DIR / f"{rid}.json").write_text(json.dumps(st, indent=2), encoding="utf-8")


def _append(st: Dict[str, Any], kind: str, msg: str) -> None:
    st.setdefault("events", []).append({"ts": _now(), "kind": kind, "message": str(msg)})
    st["updated_at"] = _now()
    _save(st)


def _runner(st: Dict[str, Any]) -> None:
    global _active
    try:
        p = subprocess.Popen(
            ["bash", str(SCRIPT_PATH), "PROMOTE STANDBY"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        st["pid"] = int(p.pid)
        _save(st)
        assert p.stdout is not None
        for line in p.stdout:
            line = line.rstrip("\n")
            if line.startswith("PHASE "):
                st["phase"] = line.split(" ", 1)[1].strip()
                _append(st, "phase", st["phase"])
            else:
                _append(st, "log", line)
        rc = int(p.wait())
        st["exit_code"] = rc
        st["finished_at"] = _now()
        st["status"] = "completed" if rc == 0 else "failed"
        _save(st)
    except Exception as e:
        st["status"] = "failed"
        st["finished_at"] = _now()
        _append(st, "error", str(e))
        _save(st)
    finally:
        with _lock:
            _active = None


def promote(confirm_phrase: str) -> Dict[str, Any]:
    global _active
    if str(confirm_phrase or "").strip() != "PROMOTE STANDBY":
        raise RuntimeError("Confirmation phrase must be: PROMOTE STANDBY")
    with _lock:
        if _active:
            raise RuntimeError("A DR promotion run is already in progress")
        rid = "dr-" + uuid.uuid4().hex[:10]
        st: Dict[str, Any] = {
            "run_id": rid,
            "status": "running",
            "phase": "queued",
            "started_at": _now(),
            "updated_at": _now(),
            "events": [],
        }
        _active = rid
        _runs[rid] = st
        _save(st)
    t = threading.Thread(target=_runner, args=(st,), daemon=True)
    t.start()
    return st


def active_run_id() -> str:
    with _lock:
        return str(_active or "")


def latest_run() -> Optional[Dict[str, Any]]:
    rows = sorted(STATE_DIR.glob("dr-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not rows:
        return None
    try:
        return json.loads(rows[0].read_text(encoding="utf-8"))
    except Exception:
        return None


def mode_status() -> Dict[str, Any]:
    if not MODE_PATH.is_file():
        return {"role": "standby", "promoted_at": ""}
    try:
        raw = json.loads(MODE_PATH.read_text(encoding="utf-8"))
        return {"role": str(raw.get("role") or "standby"), "promoted_at": str(raw.get("promoted_at") or "")}
    except Exception:
        return {"role": "standby", "promoted_at": ""}
