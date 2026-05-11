import os
import smtplib
from email.message import EmailMessage
from typing import Dict, Tuple


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
    action = str(notification.get("action_url") or "")
    if action:
        body = body + "\n\nAction: " + action
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            if use_tls:
                s.starttls()
            if user:
                s.login(user, password)
            res = s.send_message(msg)
            if res:
                return False, "", str(res)
        return True, "", ""
    except Exception as e:
        return False, "", str(e)
