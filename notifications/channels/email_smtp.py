import os
import smtplib
from email.message import EmailMessage
from typing import Dict, Tuple


def _smtp_transport_mode(port: int, use_tls: bool) -> Tuple[bool, bool]:
    ssl_env = (os.getenv("SMTP_SSL", "") or "").strip()
    if ssl_env == "1":
        return True, False
    if ssl_env == "0":
        return False, use_tls
    if int(port) == 465:
        return True, False
    return False, use_tls


def send_email(notification: Dict, destination_email: str) -> Tuple[bool, str, str]:
    host = (os.getenv("SMTP_HOST", "") or "").strip()
    port = int((os.getenv("SMTP_PORT", "587") or "587").strip() or "587")
    user = (os.getenv("SMTP_USER", "") or "").strip()
    password = (os.getenv("SMTP_PASS", "") or "").strip()
    from_addr = (os.getenv("SMTP_FROM", user or "noreply@localhost") or "noreply@localhost").strip()
    use_tls = (os.getenv("SMTP_TLS", "1") or "1").strip() == "1"
    if not host:
        return False, "", "SMTP_HOST not configured"
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
