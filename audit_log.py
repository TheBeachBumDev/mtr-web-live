"""
Append-only audit events for security and operations (PostgreSQL).

Never log passwords, TOTP secrets, API keys, or session tokens in detail_json.

Security notes:
- client_ip uses X-Forwarded-For only when TRUST_PROXY_HEADERS=1; a misconfigured
  proxy allows clients to spoof IPs in the audit trail—terminate TLS at a trusted proxy.
- record() failures are logged (not raised) so a broken audit DB cannot take down the app;
  monitor logs for "audit_log insert failed".
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import db_runtime

_SAFE_PRE = re.compile(r"^[a-zA-Z0-9._-]+$")

TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "0").strip() == "1"

_LOG = logging.getLogger(__name__)

_MAX_EVT = 120
_MAX_ACTOR = 120
_MAX_TARGET = 512
_MAX_OFF = 50_000

def _clamp_event_type(s: str) -> str:
    """Strip control chars; event names are code-supplied, not end-user text."""
    t = "".join(c for c in (s or "").strip()[:_MAX_EVT] if c.isprintable())
    return t if t else "audit.empty"


def _clamp_str(s: Optional[str], n: int) -> str:
    if s is None:
        return ""
    return str(s)[:n]


def _safe_like_prefix(param: str) -> Optional[str]:
    """Return pattern for LIKE 'prefix%' only if prefix has no LIKE wildcards."""
    s = (param or "").strip()[:_MAX_EVT]
    if not s or "%" in s or "_" in s or not _SAFE_PRE.match(s):
        return None
    return s + "%"


def client_ip_from_request(request: Any) -> str:
    """Best-effort client IP; respects X-Forwarded-For when TRUST_PROXY_HEADERS=1."""
    try:
        if TRUST_PROXY_HEADERS:
            xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            if xff:
                return xff[:128]
        if request.client and request.client.host:
            return str(request.client.host)[:128]
    except Exception:
        pass
    return ""


def audit_context(request: Any) -> Dict[str, Any]:
    """Extract actor + HTTP metadata from an authenticated FastAPI request."""
    un = ""
    uid: Optional[int] = None
    try:
        un = getattr(request.state, "username", "") or ""
        raw_id = getattr(request.state, "user_id", None)
        if raw_id is not None and int(raw_id) > 0:
            uid = int(raw_id)
    except Exception:
        pass
    try:
        path = request.url.path or ""
        ua = (request.headers.get("user-agent") or "")[:512]
    except Exception:
        path, ua = "", ""
    return {
        "actor_username": un,
        "actor_user_id": uid,
        "client_ip": client_ip_from_request(request),
        "user_agent": ua,
        "request_path": path[:512],
    }


def record(
    *,
    event_type: str,
    actor_username: str = "",
    actor_user_id: Optional[int] = None,
    success: bool = True,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_path: Optional[str] = None,
) -> None:
    """Persist one audit row. Swallows errors so logging never breaks requests."""
    try:
        if not db_runtime.is_postgres():
            return
        evt = _clamp_event_type(event_type)
        dj = json.dumps(detail or {}, separators=(",", ":"), default=str)
        if len(dj) > 16000:
            dj = json.dumps({"truncated": True, "preview": dj[:8000]}, separators=(",", ":"))
        conn = db_runtime.get_conn("postgres")
        conn.execute(
            """
            INSERT INTO audit_events (
              actor_username, actor_user_id, event_type, target_type, target_id,
              success, client_ip, user_agent, request_path, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _clamp_str(actor_username, _MAX_ACTOR),
                actor_user_id,
                evt,
                _clamp_str(target_type, 80),
                _clamp_str(target_id, _MAX_TARGET),
                1 if success else 0,
                (client_ip or "")[:128],
                (user_agent or "")[:512],
                (request_path or "")[:512],
                dj,
            ),
        )
        conn.commit()
        conn.close()
    except Exception as ex:
        _LOG.warning("audit_log insert failed: %s", ex, exc_info=False)


def record_request(
    request: Any,
    event_type: str,
    *,
    success: bool = True,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    actor_username_override: Optional[str] = None,
    actor_user_id_override: Optional[int] = None,
) -> None:
    ctx = audit_context(request)
    if actor_username_override is not None:
        ctx["actor_username"] = actor_username_override
    if actor_user_id_override is not None:
        ctx["actor_user_id"] = actor_user_id_override
    record(
        event_type=event_type,
        success=success,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        actor_username=ctx["actor_username"],
        actor_user_id=ctx["actor_user_id"],
        client_ip=ctx["client_ip"],
        user_agent=ctx["user_agent"],
        request_path=ctx["request_path"],
    )


def list_events(
    *,
    limit: int = 100,
    offset: int = 0,
    event_type_prefix: str = "",
    actor_username: str = "",
) -> List[Dict[str, Any]]:
    """Admin-only listing (newest first)."""
    lim = max(1, min(500, int(limit)))
    off = max(0, min(_MAX_OFF, int(offset)))
    conn = db_runtime.get_conn("postgres")
    try:
        sel = (
            "SELECT id, created_at, actor_username, actor_user_id, event_type, "
            "target_type, target_id, success, client_ip, user_agent, request_path, detail_json "
            "FROM audit_events"
        )
        ep = (event_type_prefix or "").strip()[:_MAX_EVT]
        au = (actor_username or "").strip()[:_MAX_ACTOR]
        like_pat = _safe_like_prefix(ep)
        if ep and au and like_pat:
            cur = conn.execute(
                sel + " WHERE event_type LIKE ? AND LOWER(actor_username) = LOWER(?) ORDER BY id DESC LIMIT ? OFFSET ?",
                (like_pat, au, lim, off),
            )
        elif ep and au and not like_pat:
            cur = conn.execute(sel + " WHERE 1=0 ORDER BY id DESC LIMIT ? OFFSET ?", (lim, off))
        elif ep and like_pat:
            cur = conn.execute(
                sel + " WHERE event_type LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (like_pat, lim, off),
            )
        elif ep and not like_pat:
            cur = conn.execute(sel + " WHERE 1=0 ORDER BY id DESC LIMIT ? OFFSET ?", (lim, off))
        elif au:
            cur = conn.execute(
                sel + " WHERE LOWER(actor_username) = LOWER(?) ORDER BY id DESC LIMIT ? OFFSET ?",
                (au, lim, off),
            )
        else:
            cur = conn.execute(sel + " ORDER BY id DESC LIMIT ? OFFSET ?", (lim, off))
        rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            dj_raw = str(r["detail_json"] or "{}")
            try:
                dj = json.loads(dj_raw)
            except Exception:
                dj = {"_raw": dj_raw[:1000]}
            out.append(
                {
                    "id": int(r["id"]),
                    "created_at": str(r["created_at"]),
                    "actor_username": str(r["actor_username"] or ""),
                    "actor_user_id": int(r["actor_user_id"]) if r["actor_user_id"] is not None else None,
                    "event_type": str(r["event_type"] or ""),
                    "target_type": str(r["target_type"] or ""),
                    "target_id": str(r["target_id"] or ""),
                    "success": bool(int(r["success"] or 0)),
                    "client_ip": str(r["client_ip"] or ""),
                    "user_agent": str(r["user_agent"] or ""),
                    "request_path": str(r["request_path"] or ""),
                    "detail": dj,
                }
            )
        return out
    finally:
        conn.close()


def init_db() -> None:
    """Ensure table exists when migrations have not run yet (dev safety)."""
    if not db_runtime.is_postgres():
        return
    try:
        conn = db_runtime.get_conn("postgres")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
              id BIGSERIAL PRIMARY KEY,
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              actor_username TEXT NOT NULL DEFAULT '',
              actor_user_id INTEGER,
              event_type TEXT NOT NULL,
              target_type TEXT,
              target_id TEXT,
              success SMALLINT NOT NULL DEFAULT 1,
              client_ip TEXT,
              user_agent TEXT,
              request_path TEXT,
              detail_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
