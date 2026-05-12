import os
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, Tuple


def _smtp_transport_mode(port: int, use_tls: bool) -> Tuple[bool, bool]:
    ssl_env = (os.getenv("SMTP_SSL", "") or "").strip()
    if ssl_env == "1":
        return True, False
    if ssl_env == "0":
        return False, use_tls
    if int(port) == 465:
        return True, False
    return False, use_tls


def _smtp_settings() -> Tuple[str, int, str, str, str, bool]:
    host = (os.getenv("SMTP_HOST", "") or "").strip()
    port = int((os.getenv("SMTP_PORT", "587") or "587").strip() or "587")
    user = (os.getenv("SMTP_USER", "") or "").strip()
    password = (os.getenv("SMTP_PASS", "") or "").strip()
    from_addr = (os.getenv("SMTP_FROM", user or "noreply@localhost") or "noreply@localhost").strip()
    use_tls = (os.getenv("SMTP_TLS", "1") or "1").strip() == "1"
    return host, port, user, password, from_addr, use_tls


def _send_message(msg: EmailMessage) -> Tuple[bool, str, str]:
    host, port, user, password, _, use_tls = _smtp_settings()
    if not host:
        return False, "", "SMTP_HOST not configured"
    use_ssl, use_starttls = _smtp_transport_mode(port, use_tls)
    try:
        if use_ssl:
            client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            client = smtplib.SMTP(host, port, timeout=10)
        with client as s:
            if use_starttls:
                s.starttls()
            if user:
                s.login(user, password)
            res = s.send_message(msg)
            if res:
                return False, "", str(res)
        return True, "", ""
    except Exception as e:
        return False, "", str(e)


def send_email(notification: Dict, destination_email: str) -> Tuple[bool, str, str]:
    _, _, _, _, from_addr, _ = _smtp_settings()
    if not destination_email:
        return False, "", "No destination email"
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = destination_email
    msg["Subject"] = str(notification.get("title") or "PO Notification")
    body = str(notification.get("message") or "")
    html_body = str(notification.get("html_body") or "").strip()
    action = str(notification.get("action_url") or "")
    if action and not html_body:
        body = body + "\n\nAction: " + action
    if html_body:
        msg.set_content(body or "Purchase order notification")
        msg.add_alternative(html_body, subtype="html")
    else:
        msg.set_content(body)
    return _send_message(msg)


def send_po_invoice_email(
    destination_email: str,
    po: Dict[str, Any],
    pdf_bytes: bytes,
    filename: str,
) -> Tuple[bool, str, str]:
    _, _, _, _, from_addr, _ = _smtp_settings()
    if not destination_email:
        return False, "", "No destination email"
    if not pdf_bytes:
        return False, "", "No invoice PDF attached"
    po_number = str(po.get("po_number") or po.get("id") or "").strip() or "PO"
    supplier = str(po.get("supplier_name") or "-").strip() or "-"
    total = po.get("total")
    try:
        total_text = f"R {float(total or 0):,.2f}"
    except Exception:
        total_text = str(total or "-")
    subject = f"Wibernet purchase order invoice: {po_number}"
    body = (
        f"Attached is purchase order {po_number} for {supplier}.\n"
        f"Total: {total_text}\n"
    )
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = destination_email
    msg["Subject"] = subject
    msg.set_content(body)
    safe_name = str(filename or "Wibernet-invoice.pdf").strip() or "Wibernet-invoice.pdf"
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=safe_name)
    return _send_message(msg)
