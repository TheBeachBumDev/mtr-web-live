import os
from typing import Dict, Tuple

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


def send_whatsapp(notification: Dict, number: str) -> Tuple[bool, str, str]:
    provider = (os.getenv("WHATSAPP_PROVIDER", "none") or "none").strip().lower()
    if not number:
        return False, "", "No destination number"
    text = f"{notification.get('title')}\n{notification.get('message')}"
    action = str(notification.get("action_url") or "")
    if action:
        text = text + f"\nApprove: {action}"
    if provider in ("", "none", "disabled"):
        return False, "", "WhatsApp provider disabled"
    if requests is None:
        return False, "", "requests dependency unavailable"
    if provider == "twilio":
        sid = (os.getenv("TWILIO_ACCOUNT_SID", "") or "").strip()
        token = (os.getenv("TWILIO_AUTH_TOKEN", "") or "").strip()
        from_number = (os.getenv("TWILIO_WHATSAPP_FROM", "") or "").strip()
        if not sid or not token or not from_number:
            return False, "", "Twilio credentials missing"
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        try:
            r = requests.post(
                url,
                data={"From": from_number, "To": number, "Body": text},
                auth=(sid, token),
                timeout=12,
            )
            if r.status_code < 300:
                try:
                    mid = str((r.json() or {}).get("sid") or "")
                except Exception:
                    mid = ""
                return True, mid, r.text[:800]
            return False, "", r.text[:800]
        except Exception as e:
            return False, "", str(e)
    if provider == "meta":
        token = (os.getenv("WHATSAPP_META_TOKEN", "") or "").strip()
        phone_id = (os.getenv("WHATSAPP_META_PHONE_ID", "") or "").strip()
        if not token or not phone_id:
            return False, "", "Meta WhatsApp credentials missing"
        url = f"https://graph.facebook.com/v20.0/{phone_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to": number,
            "type": "text",
            "text": {"preview_url": False, "body": text},
        }
        try:
            r = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=12)
            if r.status_code < 300:
                try:
                    mid = str(((r.json() or {}).get("messages") or [{}])[0].get("id") or "")
                except Exception:
                    mid = ""
                return True, mid, r.text[:800]
            return False, "", r.text[:800]
        except Exception as e:
            return False, "", str(e)
    return False, "", f"Unsupported provider: {provider}"
