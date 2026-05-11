import json
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT_DIR / "data" / "clone-schedule.json"
STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "hour": 0,
    "minute": 0,
    "profile": "full",
    "services": [],
    "target_host": "",
    "target_user": "root",
    "target_port": 22,
    "target_dir": "",
    "ssh_key_path": "",
    "host_fingerprint": "",
    "override_text": "",
}


def _normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(DEFAULTS)
    out.update(raw or {})
    out["enabled"] = bool(out.get("enabled"))
    out["hour"] = max(0, min(23, int(out.get("hour") or 0)))
    out["minute"] = max(0, min(59, int(out.get("minute") or 0)))
    # Only full clone is supported (UI and scheduler).
    out["profile"] = "full"
    out["services"] = []
    out["target_host"] = str(out.get("target_host") or "").strip()
    out["target_user"] = str(out.get("target_user") or "root").strip() or "root"
    out["target_port"] = max(1, min(65535, int(out.get("target_port") or 22)))
    out["target_dir"] = str(out.get("target_dir") or "").strip()
    out["ssh_key_path"] = str(out.get("ssh_key_path") or "").strip()
    out["host_fingerprint"] = str(out.get("host_fingerprint") or "").strip()
    out["override_text"] = str(out.get("override_text") or "")
    return out


def get() -> Dict[str, Any]:
    if not STATE_PATH.is_file():
        return dict(DEFAULTS)
    try:
        raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return dict(DEFAULTS)
    return _normalize(raw if isinstance(raw, dict) else {})


def set_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _normalize(payload if isinstance(payload, dict) else {})
    STATE_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg

