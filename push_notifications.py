# Web Push (VAPID) subscriptions + delivery for monitoring down alerts.
import base64
import json
import logging
import os
import sqlite3
import sys
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
import auth_users
import db_runtime

_log = logging.getLogger(__name__)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

DB_PATH = os.getenv("WEB_PUSH_DB_PATH", os.path.join("data", "web_push.db"))

# mailto URL for VAPID JWT "sub" claim (required by push services).
VAPID_CONTACT = os.getenv("PUSH_VAPID_CONTACT", "mailto:admins@localhost").strip()
PRIVATE_KEY_PATH = os.path.join(os.path.dirname(DB_PATH) or ".", "vapid_private.pem")


def _ensure_dirs() -> None:
    d = os.path.dirname(DB_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _conn():
    return db_runtime.get_conn("web_push")


def init_db() -> None:
    if db_runtime.is_postgres():
        db_runtime.init_postgres_schema()
        return
    _ensure_dirs()
    conn = _conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS web_push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def _ensure_vapid_private_pem() -> str:
    """Return path to PEM file; generate P-256 key once if missing."""
    _ensure_dirs()
    pk_dir = os.path.dirname(PRIVATE_KEY_PATH)
    if pk_dir and not os.path.exists(pk_dir):
        os.makedirs(pk_dir, exist_ok=True)
    if not os.path.isfile(PRIVATE_KEY_PATH):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(pem)
    return PRIVATE_KEY_PATH


def get_vapid_public_key_b64url() -> str:
    """Browser applicationServerKey: uncompressed SECP256R1 point, base64url (no padding)."""
    path = _ensure_vapid_private_pem()
    with open(path, "rb") as f:
        pem = f.read()
    key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return base64.urlsafe_b64encode(pub).decode("ascii").rstrip("=")


def save_subscription(username: str, subscription: Dict[str, Any]) -> None:
    endpoint = str((subscription or {}).get("endpoint") or "").strip()
    keys = (subscription or {}).get("keys") or {}
    p256dh = str(keys.get("p256dh") or "").strip()
    auth = str(keys.get("auth") or "").strip()
    if not endpoint or not p256dh or not auth:
        raise ValueError("Invalid subscription payload")

    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    raw = (username or "").strip()
    row = auth_users.get_user_by_username(raw) if raw else None
    canonical = str(row["username"]) if row else raw
    conn = _conn()
    try:
        conn.execute("DELETE FROM web_push_subscriptions WHERE endpoint = ?", (endpoint,))
        conn.execute(
            """
            INSERT INTO web_push_subscriptions (username, endpoint, p256dh, auth, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                canonical,
                endpoint,
                p256dh,
                auth,
                ts,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def delete_subscription_for_user(username: str, endpoint: str) -> None:
    endpoint = str(endpoint or "").strip()
    if not endpoint:
        return
    conn = _conn()
    try:
        conn.execute(
            "DELETE FROM web_push_subscriptions WHERE endpoint = ? AND lower(username) = lower(?)",
            (endpoint, (username or "").strip()),
        )
        conn.commit()
    finally:
        conn.close()


def delete_subscription_by_endpoint(endpoint: str) -> None:
    endpoint = str(endpoint or "").strip()
    if not endpoint:
        return
    conn = _conn()
    try:
        conn.execute("DELETE FROM web_push_subscriptions WHERE endpoint = ?", (endpoint,))
        conn.commit()
    finally:
        conn.close()


def delete_all_for_username(username: str) -> None:
    conn = _conn()
    try:
        conn.execute(
            "DELETE FROM web_push_subscriptions WHERE lower(username) = lower(?)",
            ((username or "").strip(),),
        )
        conn.commit()
    finally:
        conn.close()


def _iter_subscriptions(usernames: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    conn = _conn()
    conn.row_factory = sqlite3.Row
    try:
        users = [str(u or "").strip() for u in (usernames or []) if str(u or "").strip()]
        if users:
            lowered = [u.lower() for u in users]
            placeholders = ",".join("?" for _ in lowered)
            rows = conn.execute(
                f"SELECT endpoint, p256dh, auth FROM web_push_subscriptions WHERE lower(username) IN ({placeholders})",
                tuple(lowered),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT endpoint, p256dh, auth FROM web_push_subscriptions"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _send_one(
    endpoint: str,
    p256dh: str,
    auth: str,
    payload_bytes: bytes,
    vapid_pem_path: str,
) -> Optional[int]:
    """Returns HTTP status or None on failure to parse."""
    try:
        from pywebpush import webpush
    except ImportError:
        return None

    subscription_info = {"endpoint": endpoint, "keys": {"p256dh": p256dh, "auth": auth}}
    try:
        webpush(
            subscription_info=subscription_info,
            data=payload_bytes.decode("utf-8"),
            vapid_private_key=vapid_pem_path,
            vapid_claims={"sub": VAPID_CONTACT},
            timeout=15,
        )
        return 201
    except Exception as e:
        resp = getattr(e, "response", None)
        if resp is not None:
            code = getattr(resp, "status_code", None)
            try:
                code = int(code)
            except (TypeError, ValueError):
                code = None
            if code == 410:
                delete_subscription_by_endpoint(endpoint)
            return code
        return None


def _worker(events: List[Dict[str, Any]]) -> None:
    if not events:
        return
    try:
        _ensure_vapid_private_pem()
    except Exception:
        return
    subs = _iter_subscriptions()
    if not subs:
        return
    vapid_path = PRIVATE_KEY_PATH
    for ev in events:
        name = str(ev.get("name") or "Device")
        tgt = str(ev.get("target") or "")
        did = ev.get("device_id")
        kind = str(ev.get("kind") or "down")
        if kind == "up":
            nl = str(ev.get("new_level") or "ok")
            outage_text = str(ev.get("outage_duration_text") or "").strip()
            title = f"Monitoring: {name} OK"
            if outage_text:
                body = f"{tgt} — back online ({nl}) after {outage_text} down"
            else:
                body = f"{tgt} — back online ({nl})"
            tag = f"mtr-up-{did}"
        else:
            title = f"Monitoring: {name} down"
            body = f"{tgt} — no ICMP reply"
            tag = f"mtr-down-{did}"
        payload = json.dumps(
            {
                "title": title,
                "body": body,
                "tag": tag,
                "requireInteraction": True,
            }
        ).encode("utf-8")
        for s in subs:
            ep = str(s.get("endpoint") or "")
            if not ep:
                continue
            _send_one(ep, str(s["p256dh"]), str(s["auth"]), payload, vapid_path)


def send_monitoring_push_events(events: List[Dict[str, Any]]) -> None:
    """Non-blocking: Web Push for down and recovery (up) transitions."""
    if not events:
        return
    t = threading.Thread(target=_worker, args=(events,), daemon=True)
    t.start()


def send_user_push(username: str, title: str, body: str, tag: str = "mtr-app", url: str = "/") -> None:
    """Non-blocking: push a single generic notification to one subscribed username."""
    user = str(username or "").strip()
    if not user:
        return
    row = auth_users.get_user_by_username(user)
    if row:
        user = str(row.get("username") or user)

    def _run():
        try:
            _ensure_vapid_private_pem()
        except Exception:
            return
        subs = _iter_subscriptions([user])
        if not subs:
            _log.warning(
                "Web push skipped: no subscription for username=%r (user must enable browser push once, "
                "usually from Monitoring → Background push).",
                user,
            )
            return
        payload = json.dumps(
            {
                "title": str(title or "MTR Notification"),
                "body": str(body or ""),
                "tag": str(tag or "mtr-app"),
                "requireInteraction": True,
                "url": str(url or "/"),
            }
        ).encode("utf-8")
        vapid_path = PRIVATE_KEY_PATH
        for s in subs:
            ep = str(s.get("endpoint") or "")
            if not ep:
                continue
            _send_one(ep, str(s.get("p256dh") or ""), str(s.get("auth") or ""), payload, vapid_path)

    threading.Thread(target=_run, daemon=True).start()


# Backward-compatible name
send_device_down_push = send_monitoring_push_events


def push_configuration_status() -> Dict[str, Any]:
    """
    Report whether Web Push can run in *this* process (same Python as uvicorn/systemd).
    If pywebpush was installed for another interpreter, ok is False with a concrete hint.
    """
    out: Dict[str, Any] = {
        "ok": False,
        "detail": "",
        "python_executable": sys.executable,
    }
    try:
        import pywebpush  # noqa: F401
    except ImportError as e:
        out["detail"] = (
            "pywebpush is not installed for the Python that is running this app: "
            f"{sys.executable}. ({e}) "
            f"Fix: {sys.executable!r} -m pip install 'pywebpush>=1.14,<2' then restart the service."
        )
        return out
    except Exception as e:
        out["detail"] = str(e)
        return out
    try:
        _ensure_vapid_private_pem()
    except Exception as e:
        out["detail"] = f"Could not create or read VAPID key at {PRIVATE_KEY_PATH!r}: {e}"
        return out
    out["ok"] = True
    return out


def is_configured() -> bool:
    return bool(push_configuration_status().get("ok"))


def subscription_user_counts() -> List[Dict[str, Any]]:
    """Return username -> active subscription count."""
    conn = _conn()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT username, COUNT(*) AS subscription_count, MAX(created_at) AS latest_created_at
            FROM web_push_subscriptions
            GROUP BY username
            ORDER BY username ASC
            """
        ).fetchall()
        return [
            {
                "username": str(r["username"] or ""),
                "subscription_count": int(r["subscription_count"] or 0),
                "latest_created_at": str(r["latest_created_at"] or ""),
            }
            for r in rows
        ]
    finally:
        conn.close()
