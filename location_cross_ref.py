# Cross-reference Location Sync MACs with live router PPP sessions — set Location = router site.
import json as _json
import os
import re
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import edge_routers
import location_sync

CROSS_REF_VENDORS: List[Dict[str, str]] = [
    {"id": "mikrotik", "label": "Mikrotik RouterOS"},
]

SSH_TIMEOUT_SEC = float(os.getenv("CROSS_REF_SSH_TIMEOUT_SEC", "90"))
SSH_TIMEOUT_SEC = max(15.0, min(300.0, SSH_TIMEOUT_SEC))

def list_vendors() -> List[Dict[str, str]]:
    return list(CROSS_REF_VENDORS)


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _caller_id_patterns() -> Tuple[str, ...]:
    """RouterOS keys seen on PPP active (version / config dependent)."""
    return (
        r"caller-id",
        r"calling-station-id",
        r"remote-caller-id",
        r"radius-calling-station-id",
    )


def _extract_session_name_from_block(block: str) -> Optional[str]:
    """RouterOS PPP active session user/name (often login or comment)."""
    m = re.search(r'\bname=(?:"([^"]*)"|([^ \r\n]+))', block)
    if m:
        val = (m.group(1) or m.group(2) or "").strip()
        return val or None
    return None


def _extract_callers_from_block(block: str) -> Optional[str]:
    for key in _caller_id_patterns():
        m = re.search(
            rf"{re.escape(key)}\s*=\s*(?:(?:\"([^\"]*)\")|([^ \r\n]+))",
            block,
            re.I,
        )
        if m:
            val = (m.group(1) or m.group(2) or "").strip()
            if val:
                return val
    m = re.search(
        r"(?:calling-station-id|caller-id|mac-address)\s*[:=]\s*(?:(?:\"([^\"]*)\")|(\S+))",
        block,
        re.I,
    )
    if m:
        val = (m.group(1) or m.group(2) or "").strip()
        if val:
            return val
    return None


def _extract_all_callers_from_raw(text: str) -> List[str]:
    """Fallback: pull every caller-style field from the full CLI blob (handles odd wrapping)."""
    out: List[str] = []
    for key in _caller_id_patterns():
        for m in re.finditer(
            rf"{re.escape(key)}\s*=\s*(?:(?:\"([^\"]*)\")|([^ \r\n;]+))",
            text,
            re.I,
        ):
            val = (m.group(1) or m.group(2) or "").strip()
            if val:
                out.append(val)
    return out


def _mac_like_tokens_from_lines(text: str) -> List[Tuple[str, Optional[str]]]:
    """Last resort: MAC-shaped tokens per line; pair with name= on same line when present."""
    found: List[Tuple[str, Optional[str]]] = []
    mac_re = re.compile(
        r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])",
        re.I,
    )
    for line in text.splitlines():
        nm = _extract_session_name_from_block(line)
        for m in mac_re.finditer(line):
            found.append((m.group(0), nm))
    return found


def _parse_mikrotik_ppp_sessions(text: str) -> List[Dict[str, Optional[str]]]:
    """Parse PPP active CLI output — caller-id / RADIUS fields hold the subscriber MAC."""
    out: List[Dict[str, Optional[str]]] = []
    t = (text or "").strip()
    if not t:
        return out

    parts = re.split(r"\r?\n(?=\s*\d+\s)", t)
    for block in parts:
        b = block.strip()
        if not b:
            continue
        caller = _extract_callers_from_block(b)
        if caller:
            nm = _extract_session_name_from_block(b)
            out.append({"caller_id": caller, "session_name": nm})

    if out:
        return out

    seen_caller: set = set()
    for raw in _extract_all_callers_from_raw(t):
        if raw in seen_caller:
            continue
        seen_caller.add(raw)
        out.append({"caller_id": raw, "session_name": None})

    if out:
        return out

    seen_mac_tok: set = set()
    for mac_tok, nm in _mac_like_tokens_from_lines(t):
        if mac_tok in seen_mac_tok:
            continue
        seen_mac_tok.add(mac_tok)
        out.append({"caller_id": mac_tok, "session_name": nm})

    return out


def _ssh_exec(client: Any, cmd: str) -> Tuple[str, str]:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT_SEC)
    raw = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return raw, err


def _mikrotik_ppp_active_ssh(cred: Dict[str, Any]) -> Tuple[List[Dict[str, Optional[str]]], Optional[str], Dict[str, Any]]:
    """
    Returns (sessions, error, meta). Tries several RouterOS paths / print styles.
    """
    try:
        import paramiko  # type: ignore
    except ImportError:
        return [], "paramiko not installed", {}

    host = str(cred.get("router_host") or "").strip()
    port = int(cred.get("ssh_port") or 22)
    user = str(cred.get("ssh_user") or "").strip()
    pw = str(cred.get("ssh_password") or "")

    if not host or not user:
        return [], "Missing router host or SSH user", {}

    commands = [
        "/ip ppp active print detail without-paging",
        "/ip ppp active print without-paging",
        "/ppp active print detail without-paging",
        "/ppp active print without-paging",
    ]
    meta: Dict[str, Any] = {"commands_tried": []}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=pw,
            timeout=SSH_TIMEOUT_SEC,
            banner_timeout=SSH_TIMEOUT_SEC,
            auth_timeout=SSH_TIMEOUT_SEC,
            look_for_keys=False,
            allow_agent=False,
        )
        last_raw = ""
        last_err = ""
        sessions: List[Dict[str, Optional[str]]] = []
        for cmd in commands:
            meta["commands_tried"].append(cmd)
            raw, err = _ssh_exec(client, cmd)
            last_raw, last_err = raw, err
            sessions = _parse_mikrotik_ppp_sessions(raw)
            if sessions:
                meta["command_used"] = cmd
                meta["raw_chars"] = len(raw or "")
                client.close()
                return sessions, None, meta
        client.close()
        blob = (last_raw + last_err).lower()
        if "invalid" in blob or "no such" in blob or "syntax error" in blob:
            return [], (last_err or last_raw or "PPP active commands failed")[:600], meta
        meta["raw_chars"] = len(last_raw or "")
        meta["command_used"] = commands[0]
        # Empty PPP table is valid — return [] without error so stats can explain 0 matches.
        return [], None, meta
    except socket.timeout:
        try:
            client.close()
        except Exception:
            pass
        return [], "SSH timed out reading PPP active sessions", meta
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return [], str(e).strip()[:500], meta


def run_cross_reference(router_id: int, vendor: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    PPP active sessions on the router → MAC match to Location Sync cache → store that router's
    IPAM location name (edge site) per customer. Does not read or write antenna IPs in IPAM.
    """
    vid = (vendor or "").strip().lower()
    if not any(v["id"] == vid for v in CROSS_REF_VENDORS):
        return False, f"Unknown vendor: {vendor}", {}

    cred = edge_routers.get_router_credentials(router_id)
    if not cred:
        return False, "Router not found", {}

    router_location = str(cred.get("location_name") or "").strip()

    sessions: List[Dict[str, Optional[str]]]
    err: Optional[str]
    ssh_meta: Dict[str, Any] = {}
    if vid == "mikrotik":
        sessions, err, ssh_meta = _mikrotik_ppp_active_ssh(cred)
        if err:
            out = dict(ssh_meta)
            out["hint"] = "SSH or RouterOS command failed — check user permissions and menu path."
            return False, err, out
    else:
        return False, "Vendor not implemented", {}

    mac_map = location_sync.get_mac_customer_map()
    stats: Dict[str, Any] = {
        "sessions": len(sessions),
        "matched_customers": 0,
        "skipped_no_mac": 0,
        "invalid_caller_not_mac": 0,
        "not_in_location_sync": 0,
        "location_sync_mac_entries": len(mac_map),
        "unique_router_macs_normalized": 0,
    }
    stats.update(ssh_meta)

    rows: List[Tuple[int, str, str]] = []
    seen_row: set = set()
    seen_norm: set = set()
    unmatched_sessions: List[Dict[str, str]] = []

    for s in sessions:
        session_name = (s.get("session_name") or "").strip()
        raw_caller = (s.get("caller_id") or "").strip()
        if not raw_caller:
            stats["skipped_no_mac"] += 1
            continue
        norm = location_sync.normalize_mac_for_lookup(raw_caller)
        if not norm:
            stats["invalid_caller_not_mac"] += 1
            continue
        seen_norm.add(norm)
        pair = mac_map.get(norm)
        if not pair:
            stats["not_in_location_sync"] += 1
            unmatched_sessions.append(
                {
                    "ppp_name": session_name,
                    "mac_normalized": norm,
                    "caller_id_raw": raw_caller,
                }
            )
            continue
        cid, svc_login = pair
        dedupe_key = (int(cid), str(svc_login or ""), norm)
        if dedupe_key in seen_row:
            continue
        seen_row.add(dedupe_key)

        ts = _now_iso()
        rows.append((int(cid), str(svc_login or ""), ts))
        stats["matched_customers"] += 1

    stats["unique_router_macs_normalized"] = len(seen_norm)

    if stats["location_sync_mac_entries"] == 0:
        stats["hint"] = 'Location Sync has no MACs yet — click "Run sync now" before cross-reference.'
    elif stats["sessions"] == 0 and stats.get("raw_chars", 0) > 0:
        stats["hint"] = (
            "Router returned output but no caller-id/MAC lines were parsed. "
            "Try RouterOS CLI manually: /ip ppp active print detail"
        )
    elif stats["sessions"] > 0 and stats["matched_customers"] == 0:
        if stats["not_in_location_sync"] > 0:
            stats["hint"] = (
                "PPP MACs were found but none match MACs in Location Sync — run Splynx sync first, "
                "or MAC format may differ from Splynx online/session MAC."
            )
        elif stats["invalid_caller_not_mac"] > 0:
            stats["hint"] = (
                "caller-id on the router is not a MAC (often a username). "
                "Enable sending Calling-Station-Id / MAC on PPP or check RADIUS."
            )

    location_sync.replace_cross_ref_for_router(int(router_id), vid, router_location, rows)
    location_sync._meta_set("last_cross_ref_at", _now_iso())

    stats["unmatched_count"] = len(unmatched_sessions)
    stats["unmatched_sessions"] = unmatched_sessions

    meta_stats = {k: v for k, v in stats.items() if k not in ("unmatched_sessions",)}
    location_sync._meta_set("last_cross_ref_stats", _json.dumps(meta_stats))

    ok_msg = (
        f"Cross-reference: {stats['matched_customers']} matched of {stats['sessions']} PPP rows parsed "
        f"({stats['unique_router_macs_normalized']} unique MACs on router, "
        f"{stats['location_sync_mac_entries']} MACs in Location Sync cache)."
    )
    if stats.get("unmatched_count"):
        ok_msg += f" — {stats['unmatched_count']} on router but not in Location Sync DB (see dialog)."
    if stats.get("hint"):
        ok_msg += " — " + stats["hint"]
    return True, ok_msg, stats
