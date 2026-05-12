import hashlib
import html as html_lib
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import purchase_orders
from notifications.po_email import _abs_url


TOKEN_TTL_DAYS = int(os.getenv("PO_EMAIL_ACTION_TOKEN_DAYS", "14") or "14")


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def ensure_po_email_action_tokens_table(c) -> None:
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS po_email_action_tokens (
            token_hash TEXT PRIMARY KEY,
            purchase_order_id BIGINT NOT NULL,
            user_id BIGINT NOT NULL,
            action TEXT NOT NULL,
            notification_id BIGINT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        )
        """
    )


def _token_expires_at() -> str:
    return (datetime.utcnow() + timedelta(days=max(1, TOKEN_TTL_DAYS))).isoformat(timespec="seconds") + "Z"


def _action_url(raw_token: str) -> str:
    return _abs_url(f"/po/email-action/{raw_token}")


def issue_po_email_action_tokens(
    po_id: int,
    user_id: int,
    notification_id: Optional[int] = None,
) -> Dict[str, str]:
    if int(po_id or 0) <= 0 or int(user_id or 0) <= 0:
        return {"view": _abs_url(f"/purchase-orders?po_id={int(po_id or 0)}")}
    c = purchase_orders._conn()
    try:
        ensure_po_email_action_tokens_table(c)
        created_at = purchase_orders._now()
        expires_at = _token_expires_at()
        links: Dict[str, str] = {}
        for action in ("approve", "decline", "postpone"):
            raw = secrets.token_urlsafe(32)
            c.execute(
                """
                INSERT INTO po_email_action_tokens(
                  token_hash, purchase_order_id, user_id, action, notification_id, created_at, expires_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _hash_token(raw),
                    int(po_id),
                    int(user_id),
                    action,
                    int(notification_id) if notification_id else None,
                    created_at,
                    expires_at,
                ),
            )
            links[action] = _action_url(raw)
        links["view"] = _abs_url(f"/purchase-orders?po_id={int(po_id)}")
        c.commit()
        return links
    finally:
        c.close()


def _lookup_token(raw_token: str) -> Optional[Dict[str, Any]]:
    token = str(raw_token or "").strip()
    if not token:
        return None
    c = purchase_orders._conn()
    try:
        row = c.execute(
            """
            SELECT token_hash, purchase_order_id, user_id, action, notification_id, expires_at, used_at
            FROM po_email_action_tokens
            WHERE token_hash = ?
            """,
            (_hash_token(token),),
        ).fetchone()
        if not row:
            return None
        return {
            "purchase_order_id": int(row["purchase_order_id"]),
            "user_id": int(row["user_id"]),
            "action": str(row["action"] or ""),
            "notification_id": int(row["notification_id"]) if row["notification_id"] is not None else None,
            "expires_at": str(row["expires_at"] or ""),
            "used_at": str(row["used_at"] or ""),
        }
    finally:
        c.close()


def _mark_token_used(raw_token: str) -> None:
    c = purchase_orders._conn()
    try:
        c.execute(
            "UPDATE po_email_action_tokens SET used_at = ? WHERE token_hash = ?",
            (purchase_orders._now(), _hash_token(str(raw_token or "").strip())),
        )
        c.commit()
    finally:
        c.close()


def _token_error(row: Optional[Dict[str, Any]]) -> str:
    if not row:
        return "This email action link is invalid or has expired."
    if str(row.get("used_at") or "").strip():
        return "This email action link has already been used."
    expires_at = str(row.get("expires_at") or "").strip()
    if expires_at and expires_at <= purchase_orders._now():
        return "This email action link has expired."
    return ""


def get_email_action_context(raw_token: str) -> Tuple[Optional[Dict[str, Any]], str]:
    row = _lookup_token(raw_token)
    err = _token_error(row)
    if err:
        return None, err
    assert row is not None
    try:
        po = purchase_orders.get_po(int(row["purchase_order_id"]))
    except ValueError:
        return None, "Purchase order not found."
    return {"token_row": row, "po": po}, ""


def execute_email_action(raw_token: str, payload: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, str]:
    row = _lookup_token(raw_token)
    err = _token_error(row)
    if err:
        return False, err, ""
    assert row is not None
    action = str(row.get("action") or "").strip().lower()
    po_id = int(row["purchase_order_id"])
    user_id = int(row["user_id"])
    data = payload or {}
    comments = str(data.get("comments") or "").strip()
    try:
        if action == "approve":
            status = purchase_orders.approve_step(po_id, user_id, comments)
            _mark_token_used(raw_token)
            return True, f"Purchase order approved. Current status: {status}.", "approved"
        if action == "decline":
            if not comments:
                return False, "Comments are required when declining a PO.", ""
            purchase_orders.reject_po(po_id, user_id, comments)
            _mark_token_used(raw_token)
            return True, "Purchase order declined.", "rejected"
        if action == "postpone":
            resume_at = str(data.get("resume_at") or "").strip()
            if not comments:
                return False, "Comments are required when postponing a PO.", ""
            purchase_orders.postpone_po(po_id, user_id, comments, resume_at)
            _mark_token_used(raw_token)
            return True, "Purchase order postponed.", "postponed"
        return False, "Unsupported email action.", ""
    except ValueError as exc:
        return False, str(exc), ""


def build_action_links_for_notification(notification: Dict[str, Any]) -> Dict[str, str]:
    po_id = int(notification.get("purchase_order_id") or 0)
    user_id = int(notification.get("user_id") or 0)
    notification_id = int(notification.get("id") or 0) or None
    return issue_po_email_action_tokens(po_id, user_id, notification_id=notification_id)


def render_email_action_page(
    token: str,
    po: Dict[str, Any],
    action: str,
    *,
    message: str = "",
    error: str = "",
) -> str:
    po_label = html_lib.escape(str(po.get("po_number") or f"#{po.get('id')}"))
    supplier = html_lib.escape(str(po.get("supplier_name") or "-"))
    total = po.get("total")
    action_key = str(action or "").strip().lower()
    title = {
        "approve": f"Approve {po_label}",
        "decline": f"Decline {po_label}",
        "postpone": f"Postpone {po_label}",
    }.get(action_key, f"Purchase order {po_label}")
    default_resume = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d")
    body_fields = ""
    if action_key == "approve":
        body_fields = (
            "<label style=\"display:block;margin:12px 0 6px;\">Optional comment</label>"
            f"<textarea name=\"comments\" rows=\"3\" style=\"width:100%;max-width:520px;\"></textarea>"
            "<p style=\"margin:16px 0 0;\"><button type=\"submit\" name=\"confirm\" value=\"1\">Confirm approval</button></p>"
        )
    elif action_key == "decline":
        body_fields = (
            "<label style=\"display:block;margin:12px 0 6px;\">Reason for declining</label>"
            f"<textarea name=\"comments\" rows=\"4\" required style=\"width:100%;max-width:520px;\"></textarea>"
            "<p style=\"margin:16px 0 0;\"><button type=\"submit\" name=\"confirm\" value=\"1\">Confirm decline</button></p>"
        )
    elif action_key == "postpone":
        body_fields = (
            "<label style=\"display:block;margin:12px 0 6px;\">Resume on</label>"
            f"<input type=\"date\" name=\"resume_at\" value=\"{default_resume}\" required />"
            "<label style=\"display:block;margin:12px 0 6px;\">Reason for postponing</label>"
            f"<textarea name=\"comments\" rows=\"4\" required style=\"width:100%;max-width:520px;\"></textarea>"
            "<p style=\"margin:16px 0 0;\"><button type=\"submit\" name=\"confirm\" value=\"1\">Confirm postpone</button></p>"
        )
    else:
        body_fields = "<p>This action is not supported.</p>"
    notice = ""
    if error:
        notice = f"<p style=\"color:#b91c1c;\">{html_lib.escape(error)}</p>"
    elif message:
        notice = f"<p style=\"color:#15803d;\">{html_lib.escape(message)}</p>"
    view_url = _abs_url(f"/purchase-orders?po_id={int(po.get('id') or 0)}")
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>"
        + title
        + "</title></head><body style=\"font-family:Segoe UI,Arial,sans-serif;padding:2rem;max-width:720px;\">"
        f"<h1 style=\"margin-top:0;\">{title}</h1>"
        f"<p>Supplier: {supplier}<br>Total: R {total}</p>"
        + notice
        + (f"<form method=\"post\" action=\"/po/email-action/{token}\">" + body_fields + "</form>" if not message else "")
        + (f"<p style=\"margin-top:18px;\"><a href=\"{view_url}\">Open purchase order</a></p>" if view_url else "")
        + "</body></html>"
    )
