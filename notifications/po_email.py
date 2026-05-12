import html
import os
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple


APPROVAL_EMAIL_EVENTS = {
    "approval_required",
    "approval_reminder_4h",
    "approval_reminder_24h",
    "approval_escalation_48h",
    "test_po_approval",
}


def public_base_url() -> str:
    for key in ("MTR_PUBLIC_BASE_URL", "PUBLIC_BASE_URL"):
        value = (os.getenv(key, "") or "").strip().rstrip("/")
        if value:
            return value
    return ""


def _abs_url(path: str) -> str:
    path = str(path or "").strip()
    if not path:
        return ""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    base = public_base_url()
    return f"{base}{path}" if base else path


def _money(v: Any) -> str:
    try:
        return f"{Decimal(str(v or 0)):.2f}"
    except Exception:
        return "0.00"


def _esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def sample_po_for_email() -> Dict[str, Any]:
    return {
        "id": 0,
        "po_number": "PO-DEV-SAMPLE",
        "status": "pending_manager",
        "requested_by_username": "sample.user",
        "supplier_name": "Sample Supplier Ltd",
        "department_name": "Procurement",
        "category": "Hardware",
        "date_required": "2026-05-20",
        "urgency": "standard",
        "notes": "Development sample purchase order for email preview.",
        "subtotal": 10826.09,
        "tax": 1623.91,
        "total": 12450.00,
        "items": [
            {
                "description": "Ubiquiti UniFi AP",
                "quantity": 4,
                "unit_price": 2100.00,
                "tax_rate": 15,
                "tax_amount": 1260.00,
                "line_total": 9660.00,
            },
            {
                "description": "Cat6 cable drum (305m)",
                "quantity": 1,
                "unit_price": 1166.09,
                "tax_rate": 15,
                "tax_amount": 174.91,
                "line_total": 1341.00,
            },
        ],
    }


def _items_table_html(items: List[Dict[str, Any]]) -> str:
    rows = []
    for item in items or []:
        rows.append(
            "<tr>"
            f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{_esc(item.get('description'))}</td>"
            f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:right;\">{_esc(item.get('quantity'))}</td>"
            f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:right;\">R {_money(item.get('unit_price'))}</td>"
            f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:right;\">R {_money(item.get('tax_amount'))}</td>"
            f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:right;\">R {_money(item.get('line_total'))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append(
            "<tr><td colspan=\"5\" style=\"padding:10px;color:#6b7280;\">No line items on this purchase order.</td></tr>"
        )
    return (
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" "
        "style=\"border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;\">"
        "<thead><tr style=\"background:#f8fafc;\">"
        "<th align=\"left\" style=\"padding:8px 10px;font-size:12px;color:#475569;\">Description</th>"
        "<th align=\"right\" style=\"padding:8px 10px;font-size:12px;color:#475569;\">Qty</th>"
        "<th align=\"right\" style=\"padding:8px 10px;font-size:12px;color:#475569;\">Unit</th>"
        "<th align=\"right\" style=\"padding:8px 10px;font-size:12px;color:#475569;\">Tax</th>"
        "<th align=\"right\" style=\"padding:8px 10px;font-size:12px;color:#475569;\">Line total</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _items_table_plain(items: List[Dict[str, Any]]) -> str:
    lines = ["Line items:"]
    if not items:
        lines.append("- (none)")
        return "\n".join(lines)
    for item in items:
        lines.append(
            f"- {item.get('description') or '-'} | qty {item.get('quantity')} | "
            f"unit R {_money(item.get('unit_price'))} | line R {_money(item.get('line_total'))}"
        )
    return "\n".join(lines)


def _button_row(links: Dict[str, str]) -> str:
    buttons = []
    specs = [
        ("approve", "Approve", "#15803d", "#ffffff"),
        ("decline", "Decline", "#b91c1c", "#ffffff"),
        ("postpone", "Postpone", "#b45309", "#ffffff"),
        ("view", "Open PO", "#1d4ed8", "#ffffff"),
    ]
    for key, label, bg, fg in specs:
        href = str(links.get(key) or "").strip()
        if not href:
            continue
        buttons.append(
            f"<a href=\"{_esc(href)}\" style=\"display:inline-block;margin:0 8px 8px 0;padding:10px 14px;"
            f"background:{bg};color:{fg};text-decoration:none;border-radius:6px;font-weight:600;\">{_esc(label)}</a>"
        )
    if not buttons:
        return ""
    return (
        "<p style=\"margin:18px 0 8px;font-size:14px;color:#111827;\">Actions</p>"
        + "".join(buttons)
        + "<p style=\"margin:10px 0 0;font-size:12px;color:#6b7280;\">"
        "Approve is one step. Decline and postpone open a short confirmation page for required comments.</p>"
    )


def build_approval_email(
    po: Dict[str, Any],
    step_name: str,
    action_links: Optional[Dict[str, str]] = None,
) -> Tuple[str, str, str, str]:
    po_number = str(po.get("po_number") or f"#{po.get('id')}")
    title = f"PO Approval Required: {po_number}"
    view_path = f"/purchase-orders?po_id={int(po.get('id') or 0)}"
    links = dict(action_links or {})
    if "view" not in links:
        links["view"] = _abs_url(view_path)
    summary_rows = [
        ("PO number", po_number),
        ("Approval step", step_name or "-"),
        ("Supplier", po.get("supplier_name") or "-"),
        ("Department", po.get("department_name") or "-"),
        ("Requested by", po.get("requested_by_username") or "-"),
        ("Category", po.get("category") or "-"),
        ("Date required", po.get("date_required") or "-"),
        ("Urgency", po.get("urgency") or "-"),
    ]
    summary_html = "".join(
        f"<tr><td style=\"padding:6px 10px;color:#6b7280;width:160px;\">{_esc(label)}</td>"
        f"<td style=\"padding:6px 10px;color:#111827;\">{_esc(value)}</td></tr>"
        for label, value in summary_rows
    )
    notes = str(po.get("notes") or "").strip()
    notes_html = (
        f"<p style=\"margin:16px 0 0;font-size:14px;color:#111827;\"><strong>Notes</strong><br>{_esc(notes)}</p>"
        if notes
        else ""
    )
    html_body = (
        "<div style=\"font-family:Segoe UI,Arial,sans-serif;color:#111827;max-width:720px;\">"
        "<h2 style=\"margin:0 0 8px;font-size:20px;\">Purchase order approval required</h2>"
        "<p style=\"margin:0 0 16px;color:#4b5563;\">Please review the purchase order below and choose an action.</p>"
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" "
        "style=\"border-collapse:collapse;margin:0 0 16px;\"><tbody>"
        + summary_html
        + "</tbody></table>"
        + _items_table_html(list(po.get("items") or []))
        + "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" "
        "style=\"border-collapse:collapse;margin:16px 0 0;\"><tbody>"
        f"<tr><td style=\"padding:6px 10px;color:#6b7280;\">Subtotal</td><td style=\"padding:6px 10px;text-align:right;\">R {_money(po.get('subtotal'))}</td></tr>"
        f"<tr><td style=\"padding:6px 10px;color:#6b7280;\">Tax</td><td style=\"padding:6px 10px;text-align:right;\">R {_money(po.get('tax'))}</td></tr>"
        f"<tr><td style=\"padding:6px 10px;color:#111827;font-weight:700;\">Total</td>"
        f"<td style=\"padding:6px 10px;text-align:right;font-weight:700;\">R {_money(po.get('total'))}</td></tr>"
        "</tbody></table>"
        + notes_html
        + _button_row(links)
        + "</div>"
    )
    plain_lines = [
        title,
        "",
        f"Approval step: {step_name or '-'}",
        f"Supplier: {po.get('supplier_name') or '-'}",
        f"Department: {po.get('department_name') or '-'}",
        f"Requested by: {po.get('requested_by_username') or '-'}",
        f"Total: R {_money(po.get('total'))}",
        "",
        _items_table_plain(list(po.get("items") or [])),
    ]
    if notes:
        plain_lines.extend(["", f"Notes: {notes}"])
    plain_lines.append("")
    plain_lines.append("Actions:")
    for key, label in (("approve", "Approve"), ("decline", "Decline"), ("postpone", "Postpone"), ("view", "Open PO")):
        href = str(links.get(key) or "").strip()
        if href:
            plain_lines.append(f"- {label}: {href}")
    plain_body = "\n".join(plain_lines)
    return title, plain_body, html_body, links.get("view") or view_path
