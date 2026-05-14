import json
from typing import Dict

import purchase_orders
import push_notifications
from notifications.channels.email_smtp import send_email
from notifications.channels.whatsapp import send_whatsapp
from notifications.po_email import APPROVAL_EMAIL_EVENTS, build_approval_email, sample_po_for_email
from po_email_actions import build_action_links_for_notification


def _po_step_name(po: Dict) -> str:
    step = int(po.get("current_approval_step") or 0)
    approvals = list(po.get("approvals") or [])
    if step > 0:
        for row in approvals:
            if int(row.get("step_number") or 0) == step:
                return str(row.get("step_name") or "Approver")
    for row in approvals:
        if str(row.get("status") or "") == "pending":
            return str(row.get("step_name") or "Approver")
    return "Approver"


def _hydrate_po_email_notification(notification: Dict) -> Dict:
    if str(notification.get("channel") or "").strip().lower() != "email":
        return notification
    if str(notification.get("event_type") or "") not in APPROVAL_EMAIL_EVENTS:
        return notification
    po_id = int(notification.get("purchase_order_id") or 0)
    if po_id > 0:
        try:
            po = purchase_orders.get_po(po_id)
        except ValueError:
            return notification
        action_links = build_action_links_for_notification(notification)
    else:
        po = sample_po_for_email()
        action_links = build_action_links_for_notification(notification)
    title, plain, html_body, view_url = build_approval_email(po, _po_step_name(po), action_links)
    out = dict(notification)
    out["title"] = title
    out["message"] = plain
    out["html_body"] = html_body
    out["action_url"] = view_url
    return out


def dispatch_notification(notification: Dict) -> bool:
    """Return True if this row was claimed for dispatch (caller may count as handled). False if still pending elsewhere."""
    nid = int(notification.get("id") or 0)
    channel = str(notification.get("channel") or "").strip().lower()
    if nid <= 0:
        return False
    if not purchase_orders.claim_notification_for_dispatch(nid):
        return False
    # In-app notifications are persisted by row creation; mark as sent immediately.
    if channel == "app":
        if not purchase_orders.notification_row_is_dispatching(nid):
            return True
        user_id = int(notification.get("user_id") or 0)
        username = _username_for_user_id(user_id)
        if username:
            try:
                push_notifications.send_user_push(
                    username=username,
                    title=str(notification.get("title") or "MTR Notification"),
                    body=str(notification.get("message") or ""),
                    tag=f"po-{int(notification.get('purchase_order_id') or 0)}",
                    url=str(notification.get("action_url") or "/purchase-orders"),
                    require_push_po=True,
                    require_push_monitoring=None,
                )
            except Exception:
                pass
        purchase_orders.mark_notification_state(nid, "sent", provider_message_id="", response_body="in_app")
        return True
    if channel == "email":
        if not purchase_orders.notification_row_is_dispatching(nid):
            return True
        pref = _notification_user_pref(int(notification.get("user_id") or 0))
        payload = _hydrate_po_email_notification(notification)
        ok, mid, body = send_email(payload, str(pref.get("email") or ""))
        purchase_orders.mark_notification_state(nid, "sent" if ok else "failed", provider_message_id=mid, response_body=body)
        return True
    if channel == "whatsapp":
        if not purchase_orders.notification_row_is_dispatching(nid):
            return True
        pref = _notification_user_pref(int(notification.get("user_id") or 0))
        ok, mid, body = send_whatsapp(notification, str(pref.get("whatsapp_number") or ""))
        purchase_orders.mark_notification_state(nid, "sent" if ok else "failed", provider_message_id=mid, response_body=body)
        return True
    purchase_orders.mark_notification_state(nid, "failed", response_body=f"unknown channel: {channel}")
    return True


def _notification_user_pref(user_id: int) -> Dict:
    # Tiny adapter to avoid exposing DB internals here.
    po = purchase_orders._conn()  # type: ignore[attr-defined]
    try:
        row = po.execute(
            """
            SELECT user_id, email, whatsapp_number
            FROM user_notification_preferences
            WHERE user_id = ?
            """,
            (int(user_id),),
        ).fetchone()
        if not row:
            return {}
        return {
            "user_id": int(row["user_id"]),
            "email": str(row["email"] or ""),
            "whatsapp_number": str(row["whatsapp_number"] or ""),
        }
    finally:
        po.close()


def _username_for_user_id(user_id: int) -> str:
    if int(user_id or 0) <= 0:
        return ""
    po = purchase_orders._conn()  # type: ignore[attr-defined]
    try:
        row = po.execute("SELECT username FROM app_users WHERE id = ?", (int(user_id),)).fetchone()
        return str((row or {}).get("username") or "").strip() if row else ""
    finally:
        po.close()


def dispatch_due_notifications(limit: int = 100) -> Dict:
    due = purchase_orders.fetch_due_notifications(limit=limit)
    sent = 0
    failed = 0
    skipped = 0
    for n in due:
        try:
            if dispatch_notification(n):
                sent += 1
            else:
                skipped += 1
        except Exception as e:
            failed += 1
            try:
                purchase_orders.mark_notification_state(int(n.get("id") or 0), "failed", response_body=str(e))
            except Exception:
                pass
    return {"total": len(due), "processed": sent, "failed": failed, "skipped": skipped}
