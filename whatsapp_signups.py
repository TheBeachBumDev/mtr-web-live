import base64
import io
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import db_runtime
import qrcode


def _conn():
    return db_runtime.get_conn("whatsapp_signups")


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _phone_digits(raw: str) -> str:
    v = re.sub(r"\D+", "", str(raw or ""))
    if v.startswith("00"):
        v = v[2:]
    return v


def _qr_data_uri(link: str) -> str:
    img = qrcode.make(link)
    out = io.BytesIO()
    img.save(out, format="PNG")
    return "data:image/png;base64," + base64.b64encode(out.getvalue()).decode("ascii")


def init_db() -> None:
    c = _conn()
    try:
        if db_runtime.is_postgres():
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signups (
                    id BIGSERIAL PRIMARY KEY,
                    full_name TEXT NOT NULL DEFAULT '',
                    phone_number TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    consent_given INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'received',
                    created_by_user_id BIGINT,
                    created_by_username TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    invite_token TEXT,
                    invite_link TEXT,
                    invite_qr_data_uri TEXT,
                    opted_in_at TEXT
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signups_created_at ON whatsapp_signups(created_at DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signups_status ON whatsapp_signups(status)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signups_phone ON whatsapp_signups(phone_number)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_settings (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_events (
                    id BIGSERIAL PRIMARY KEY,
                    provider_event_id TEXT,
                    wa_id TEXT,
                    from_phone TEXT,
                    profile_name TEXT,
                    event_type TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'received',
                    message_text TEXT NOT NULL DEFAULT '',
                    interactive_json TEXT NOT NULL DEFAULT '{}',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_events_created ON whatsapp_signup_events(created_at DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_events_from_phone ON whatsapp_signup_events(from_phone)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_records (
                    id BIGSERIAL PRIMARY KEY,
                    event_id BIGINT,
                    from_phone TEXT NOT NULL DEFAULT '',
                    full_name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    id_number TEXT NOT NULL DEFAULT '',
                    address_line TEXT NOT NULL DEFAULT '',
                    suburb TEXT NOT NULL DEFAULT '',
                    city TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    raw_form_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_records_created ON whatsapp_signup_records(created_at DESC)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    from_phone TEXT NOT NULL,
                    wa_id TEXT NOT NULL DEFAULT '',
                    profile_name TEXT NOT NULL DEFAULT '',
                    step_key TEXT NOT NULL DEFAULT '',
                    data_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_whatsapp_signup_sessions_phone_active ON whatsapp_signup_sessions(from_phone, status)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_campaigns (
                    id BIGSERIAL PRIMARY KEY,
                    campaign_code TEXT NOT NULL,
                    invite_link TEXT NOT NULL,
                    qr_data_uri TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_campaigns_created ON whatsapp_signup_campaigns(created_at DESC)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_campaign_defs (
                    id BIGSERIAL PRIMARY KEY,
                    campaign_code TEXT NOT NULL UNIQUE,
                    trigger_text TEXT NOT NULL,
                    welcome_text TEXT NOT NULL DEFAULT 'Welcome to Wibernet signup.',
                    success_text TEXT NOT NULL DEFAULT 'Thank you. Your signup has been submitted successfully.',
                    flow_json TEXT NOT NULL DEFAULT '[]',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_campaign_defs_active ON whatsapp_signup_campaign_defs(active)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_splynx_pushes (
                    id BIGSERIAL PRIMARY KEY,
                    record_id BIGINT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'dry_run',
                    status TEXT NOT NULL DEFAULT 'pending',
                    request_json TEXT NOT NULL DEFAULT '{}',
                    response_json TEXT NOT NULL DEFAULT '{}',
                    error_text TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_splynx_pushes_record ON whatsapp_signup_splynx_pushes(record_id, created_at DESC)")
        else:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL DEFAULT '',
                    phone_number TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    consent_given INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'received',
                    created_by_user_id INTEGER,
                    created_by_username TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    invite_token TEXT,
                    invite_link TEXT,
                    invite_qr_data_uri TEXT,
                    opted_in_at TEXT
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signups_created_at ON whatsapp_signups(created_at DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signups_status ON whatsapp_signups(status)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signups_phone ON whatsapp_signups(phone_number)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_settings (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider_event_id TEXT,
                    wa_id TEXT,
                    from_phone TEXT,
                    profile_name TEXT,
                    event_type TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'received',
                    message_text TEXT NOT NULL DEFAULT '',
                    interactive_json TEXT NOT NULL DEFAULT '{}',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_events_created ON whatsapp_signup_events(created_at DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_events_from_phone ON whatsapp_signup_events(from_phone)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER,
                    from_phone TEXT NOT NULL DEFAULT '',
                    full_name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    id_number TEXT NOT NULL DEFAULT '',
                    address_line TEXT NOT NULL DEFAULT '',
                    suburb TEXT NOT NULL DEFAULT '',
                    city TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    raw_form_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_records_created ON whatsapp_signup_records(created_at DESC)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_phone TEXT NOT NULL,
                    wa_id TEXT NOT NULL DEFAULT '',
                    profile_name TEXT NOT NULL DEFAULT '',
                    step_key TEXT NOT NULL DEFAULT '',
                    data_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_whatsapp_signup_sessions_phone_active ON whatsapp_signup_sessions(from_phone, status)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_code TEXT NOT NULL,
                    invite_link TEXT NOT NULL,
                    qr_data_uri TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_campaigns_created ON whatsapp_signup_campaigns(created_at DESC)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_campaign_defs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_code TEXT NOT NULL UNIQUE,
                    trigger_text TEXT NOT NULL,
                    welcome_text TEXT NOT NULL DEFAULT 'Welcome to Wibernet signup.',
                    success_text TEXT NOT NULL DEFAULT 'Thank you. Your signup has been submitted successfully.',
                    flow_json TEXT NOT NULL DEFAULT '[]',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_campaign_defs_active ON whatsapp_signup_campaign_defs(active)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS whatsapp_signup_splynx_pushes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id INTEGER NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'dry_run',
                    status TEXT NOT NULL DEFAULT 'pending',
                    request_json TEXT NOT NULL DEFAULT '{}',
                    response_json TEXT NOT NULL DEFAULT '{}',
                    error_text TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_signup_splynx_pushes_record ON whatsapp_signup_splynx_pushes(record_id, created_at DESC)")
        c.commit()
    finally:
        c.close()


def get_settings() -> Dict[str, Any]:
    defaults = {
        "provider": "meta",
        "business_number": _phone_digits(os.getenv("WHATSAPP_BUSINESS_NUMBER", "")),
        "verify_token": os.getenv("WHATSAPP_VERIFY_TOKEN", ""),
        "phone_number_id": os.getenv("WHATSAPP_PHONE_NUMBER_ID", ""),
        "flow_id": os.getenv("WHATSAPP_FLOW_ID", ""),
        "signup_message_template": (
            os.getenv("WHATSAPP_SIGNUP_MESSAGE_TEMPLATE", "")
            or "SIGNUP WITH WIBERNET!"
        ),
        "access_token": os.getenv("WHATSAPP_ACCESS_TOKEN", ""),
        "field_mapping_json": json.dumps(
            {
                "full_name": "full_name",
                "email": "email",
                "address_line": "address_line",
                "suburb": "suburb",
                "notes": "notes",
            },
            ensure_ascii=True,
        ),
        "splynx_enabled": os.getenv("WHATSAPP_SPLYNX_ENABLED", "0"),
        "splynx_dry_run": os.getenv("WHATSAPP_SPLYNX_DRY_RUN", "1"),
        "splynx_lead_path": os.getenv("WHATSAPP_SPLYNX_LEAD_PATH", "admin/customers/customer"),
        "splynx_default_location_id": os.getenv("WHATSAPP_SPLYNX_DEFAULT_LOCATION_ID", ""),
        "splynx_default_status": os.getenv("WHATSAPP_SPLYNX_DEFAULT_STATUS", "lead"),
    }
    c = _conn()
    try:
        rows = c.execute("SELECT k, v FROM whatsapp_signup_settings").fetchall()
        out = dict(defaults)
        for r in rows:
            k = str(r["k"] or "")
            if k in out:
                out[k] = str(r["v"] or "")
        return out
    finally:
        c.close()


def save_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "provider",
        "business_number",
        "verify_token",
        "phone_number_id",
        "flow_id",
        "signup_message_template",
        "field_mapping_json",
        "access_token",
        "splynx_enabled",
        "splynx_dry_run",
        "splynx_lead_path",
        "splynx_default_location_id",
        "splynx_default_status",
    }
    vals = {k: str((settings or {}).get(k) or "").strip() for k in allowed}
    vals["business_number"] = _phone_digits(vals.get("business_number", ""))
    if not vals["signup_message_template"]:
        vals["signup_message_template"] = "SIGNUP WITH WIBERNET!"
    if not vals["field_mapping_json"]:
        vals["field_mapping_json"] = get_settings().get("field_mapping_json") or "{}"
    c = _conn()
    try:
        ts = _now()
        for k, v in vals.items():
            c.execute(
                """
                INSERT INTO whatsapp_signup_settings(k, v, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at
                """,
                (k, v, ts),
            )
        c.commit()
        return get_settings()
    finally:
        c.close()


def generate_qr(campaign: str) -> Dict[str, Any]:
    settings = get_settings()
    campaign_clean = (campaign or "default").strip()[:80].upper()
    msg_tpl = str(settings.get("signup_message_template") or "Hi, I want to sign up. Campaign: {campaign}")
    message = msg_tpl.replace("{campaign}", campaign_clean)
    for cd in list_campaign_defs():
        if str(cd.get("campaign_code") or "").strip().upper() == campaign_clean:
            trig = str(cd.get("trigger_text") or "").strip()
            if trig:
                message = trig
            break
    business = _phone_digits(str(settings.get("business_number") or ""))
    if not business:
        raise ValueError("Set business number in configuration first")
    link = f"https://wa.me/{business}?text={quote(message)}"
    qr = _qr_data_uri(link)
    c = _conn()
    try:
        ts = _now()
        cur = c.execute(
            """
            INSERT INTO whatsapp_signup_campaigns(campaign_code, invite_link, qr_data_uri, created_at)
            VALUES(?, ?, ?, ?)
            RETURNING id
            """,
            (campaign_clean, link, qr, ts),
        )
        cid = int(cur.fetchone()[0])
        c.commit()
        return {"id": cid, "campaign": campaign_clean, "link": link, "qr_data_uri": qr, "created_at": ts}
    finally:
        c.close()


def list_campaigns(limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
    lim = max(1, min(50, int(limit)))
    off = max(0, int(offset))
    c = _conn()
    try:
        rows = c.execute(
            """
            SELECT id, campaign_code, invite_link, qr_data_uri, created_at
            FROM whatsapp_signup_campaigns
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (lim, off),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "campaign_code": str(r["campaign_code"] or ""),
                "invite_link": str(r["invite_link"] or ""),
                "qr_data_uri": str(r["qr_data_uri"] or ""),
                "created_at": str(r["created_at"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def count_campaigns() -> int:
    c = _conn()
    try:
        row = c.execute("SELECT COUNT(*) AS n FROM whatsapp_signup_campaigns").fetchone()
        return int(row["n"] or 0) if row else 0
    finally:
        c.close()


def list_campaign_defs() -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute(
            """
            SELECT id, campaign_code, trigger_text, welcome_text, success_text, flow_json, active, created_at, updated_at
            FROM whatsapp_signup_campaign_defs
            ORDER BY campaign_code ASC, id ASC
            """
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            flow_raw = str(r["flow_json"] or "[]")
            try:
                flow = json.loads(flow_raw)
                if not isinstance(flow, list):
                    flow = []
            except Exception:
                flow = []
            out.append(
                {
                    "id": int(r["id"]),
                    "campaign_code": str(r["campaign_code"] or ""),
                    "trigger_text": str(r["trigger_text"] or ""),
                    "welcome_text": str(r["welcome_text"] or ""),
                    "success_text": str(r["success_text"] or ""),
                    "flow": flow,
                    "active": int(r["active"] or 0) == 1,
                    "created_at": str(r["created_at"] or ""),
                    "updated_at": str(r["updated_at"] or ""),
                }
            )
        return out
    finally:
        c.close()


def save_campaign_def(
    campaign_code: str,
    trigger_text: str,
    welcome_text: str,
    success_text: str,
    flow: List[Dict[str, Any]],
    active: bool = True,
    campaign_id: int = 0,
) -> Dict[str, Any]:
    code = str(campaign_code or "").strip().upper()
    trig = str(trigger_text or "").strip()
    if len(code) < 2:
        raise ValueError("Campaign code is required")
    if len(trig) < 2:
        raise ValueError("Trigger text is required")
    flow_list = flow if isinstance(flow, list) else []
    if not flow_list:
        raise ValueError("At least one question step is required")
    sanitized_steps: List[Dict[str, Any]] = []
    for step in flow_list:
        if not isinstance(step, dict):
            continue
        key = str(step.get("field_key") or "").strip()
        q = str(step.get("question_text") or "").strip()
        stype = str(step.get("type") or "text").strip().lower()
        if not key or not q:
            continue
        if stype not in ("text", "email", "number", "multiple_choice"):
            stype = "text"
        entry: Dict[str, Any] = {
            "field_key": key,
            "question_text": q,
            "type": stype,
            "required": bool(step.get("required", True)),
        }
        if stype == "multiple_choice":
            opts_raw = step.get("options") or []
            opts: List[Dict[str, Any]] = []
            if isinstance(opts_raw, list):
                for o in opts_raw:
                    if not isinstance(o, dict):
                        continue
                    k = str(o.get("key") or "").strip()
                    label = str(o.get("label") or "").strip()
                    value = str(o.get("value") or label).strip()
                    if not k or not label:
                        continue
                    opts.append({"key": k, "label": label, "value": value})
            if not opts:
                raise ValueError(f"Multiple choice step '{key}' needs options")
            entry["options"] = opts
        sanitized_steps.append(entry)
    if not sanitized_steps:
        raise ValueError("No valid question steps found")
    flow_json = json.dumps(sanitized_steps, ensure_ascii=True)
    c = _conn()
    try:
        ts = _now()
        cid = int(campaign_id or 0)
        if cid > 0:
            cur = c.execute(
                """
                UPDATE whatsapp_signup_campaign_defs
                SET campaign_code = ?, trigger_text = ?, welcome_text = ?, success_text = ?, flow_json = ?, active = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    code,
                    trig,
                    str(welcome_text or "").strip() or "Welcome to Wibernet signup.",
                    str(success_text or "").strip() or "Thank you. Your signup has been submitted successfully.",
                    flow_json,
                    1 if active else 0,
                    ts,
                    cid,
                ),
            )
            if int(cur.rowcount or 0) == 0:
                raise ValueError("Campaign not found")
        else:
            cur = c.execute(
                """
                INSERT INTO whatsapp_signup_campaign_defs(
                    campaign_code, trigger_text, welcome_text, success_text, flow_json, active, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                (
                    code,
                    trig,
                    str(welcome_text or "").strip() or "Welcome to Wibernet signup.",
                    str(success_text or "").strip() or "Thank you. Your signup has been submitted successfully.",
                    flow_json,
                    1 if active else 0,
                    ts,
                    ts,
                ),
            )
            cid = int(cur.fetchone()[0])
        c.commit()
        return {"id": cid, "campaign_code": code}
    finally:
        c.close()


def _norm_text(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(s or "").lower())


def _format_multiple_choice_prompt(question: str, options: Any) -> str:
    prompt = str(question or "").strip() or "Choose one option"
    if not isinstance(options, list) or not options:
        return prompt
    lines = [
        f"{str(o.get('key') or '').strip()} - {str(o.get('label') or '').strip()}"
        for o in options
        if isinstance(o, dict) and str(o.get("key") or "").strip()
    ]
    if not lines:
        return prompt
    return prompt + "\n" + "\n".join(lines)


def _resolve_multiple_choice_answer(msg: str, options: Any) -> Optional[str]:
    raw = _clean_inbound_text(msg)
    if not raw or not isinstance(options, list):
        return None
    norm = _norm_text(raw)

    if re.fullmatch(r"\d+", raw):
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            opt = options[idx]
            if isinstance(opt, dict):
                picked = str(opt.get("value") or opt.get("label") or opt.get("key") or "").strip()
                if picked:
                    return picked

    prefix = re.split(r"\s*[-–:]\s*", raw, maxsplit=1)[0].strip()
    if prefix and prefix != raw:
        nested = _resolve_multiple_choice_answer(prefix, options)
        if nested:
            return nested

    for opt in options:
        if not isinstance(opt, dict):
            continue
        key = str(opt.get("key") or "").strip()
        label = str(opt.get("label") or "").strip()
        value = str(opt.get("value") or label or key).strip()
        if not key and not label:
            continue
        key_norm = _norm_text(key)
        label_norm = _norm_text(label)
        value_norm = _norm_text(value)
        if raw in {key, label, value}:
            return value
        if norm and norm in {key_norm, label_norm, value_norm}:
            return value
    return None


def _clean_inbound_text(msg: str) -> str:
    s = str(msg or "").strip()
    s = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", s)
    return s.strip()


def _inbound_message_text(m0: Dict[str, Any]) -> str:
    mtype = str((m0 or {}).get("type") or "")
    if mtype == "text":
        return _clean_inbound_text(str(((m0.get("text") or {}).get("body")) or ""))
    if mtype == "interactive":
        inter = (m0 or {}).get("interactive") or {}
        itype = str(inter.get("type") or "")
        if itype == "button_reply":
            br = inter.get("button_reply") or {}
            return _clean_inbound_text(str(br.get("id") or br.get("title") or ""))
        if itype == "list_reply":
            lr = inter.get("list_reply") or {}
            return _clean_inbound_text(str(lr.get("id") or lr.get("title") or ""))
        nfm = inter.get("nfm_reply") or {}
        return _clean_inbound_text(str(nfm.get("body") or ""))
    return ""


def _flow_steps_for_session(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    cid = int(data.get("__campaign_id") or 0)
    if cid > 0:
        for cd in list_campaign_defs():
            if int(cd.get("id") or 0) == cid:
                flow = cd.get("flow")
                if isinstance(flow, list) and flow:
                    data["__flow_steps"] = flow
                    return flow
    flow = data.get("__flow_steps")
    if isinstance(flow, list) and flow:
        return flow
    return list(_SIGNUP_STEPS)


def _session_needs_flow_reset(data: Dict[str, Any]) -> bool:
    flow = data.get("__flow_steps")
    return not isinstance(flow, list) or not flow


def find_campaign_by_trigger(message_text: str) -> Optional[Dict[str, Any]]:
    norm = _norm_text(message_text)
    if not norm:
        return None
    for campaign in list_campaign_defs():
        if not bool(campaign.get("active")):
            continue
        if _norm_text(str(campaign.get("trigger_text") or "")) == norm:
            return campaign
    return None


def list_events(search: str = "", limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
    needle = (search or "").strip().lower()
    lim = max(1, min(500, int(limit)))
    off = max(0, int(offset))
    c = _conn()
    try:
        vals: List[Any] = []
        where = ""
        if needle:
            where = (
                " WHERE "
                "strpos(lower(COALESCE(from_phone,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(profile_name,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(message_text,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(event_type,'')), ?) > 0"
            )
            vals.extend([needle, needle, needle, needle])
        rows = c.execute(
            f"""
            SELECT id, provider_event_id, wa_id, from_phone, profile_name, event_type, status,
                   message_text, interactive_json, payload_json, created_at
            FROM whatsapp_signup_events
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(vals + [lim, off]),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "provider_event_id": str(r["provider_event_id"] or ""),
                "wa_id": str(r["wa_id"] or ""),
                "from_phone": str(r["from_phone"] or ""),
                "profile_name": str(r["profile_name"] or ""),
                "event_type": str(r["event_type"] or ""),
                "status": str(r["status"] or "received"),
                "message_text": str(r["message_text"] or ""),
                "interactive_json": str(r["interactive_json"] or "{}"),
                "payload_json": str(r["payload_json"] or "{}"),
                "created_at": str(r["created_at"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def count_events(search: str = "") -> int:
    needle = (search or "").strip().lower()
    c = _conn()
    try:
        vals: List[Any] = []
        where = ""
        if needle:
            where = (
                " WHERE "
                "strpos(lower(COALESCE(from_phone,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(profile_name,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(message_text,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(event_type,'')), ?) > 0"
            )
            vals.extend([needle, needle, needle, needle])
        row = c.execute(
            f"SELECT COUNT(*) AS n FROM whatsapp_signup_events {where}",
            tuple(vals),
        ).fetchone()
        return int(row["n"] or 0) if row else 0
    finally:
        c.close()


def list_records(search: str = "", limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
    needle = (search or "").strip().lower()
    lim = max(1, min(500, int(limit)))
    off = max(0, int(offset))
    c = _conn()
    try:
        vals: List[Any] = []
        where = ""
        if needle:
            where = (
                " WHERE "
                "strpos(lower(COALESCE(from_phone,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(full_name,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(email,'')), ?) > 0 OR "
                "strpos(lower(COALESCE(id_number,'')), ?) > 0"
            )
            vals.extend([needle, needle, needle, needle])
        rows = c.execute(
            f"""
            SELECT id, event_id, from_phone, full_name, email, id_number, address_line, suburb, city, notes, raw_form_json, created_at
            FROM whatsapp_signup_records
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(vals + [lim, off]),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "event_id": int(r["event_id"]) if r["event_id"] is not None else None,
                "from_phone": str(r["from_phone"] or ""),
                "full_name": str(r["full_name"] or ""),
                "email": str(r["email"] or ""),
                "id_number": str(r["id_number"] or ""),
                "address_line": str(r["address_line"] or ""),
                "suburb": str(r["suburb"] or ""),
                "city": str(r["city"] or ""),
                "notes": str(r["notes"] or ""),
                "raw_form_json": str(r["raw_form_json"] or "{}"),
                "created_at": str(r["created_at"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def get_record(record_id: int) -> Optional[Dict[str, Any]]:
    rid = int(record_id or 0)
    if rid <= 0:
        return None
    c = _conn()
    try:
        row = c.execute(
            """
            SELECT id, event_id, from_phone, full_name, email, id_number, address_line, suburb, city, notes, raw_form_json, created_at
            FROM whatsapp_signup_records
            WHERE id = ?
            """,
            (rid,),
        ).fetchone()
        if not row:
            return None
        return {
            "id": int(row["id"]),
            "event_id": int(row["event_id"]) if row["event_id"] is not None else None,
            "from_phone": str(row["from_phone"] or ""),
            "full_name": str(row["full_name"] or ""),
            "email": str(row["email"] or ""),
            "id_number": str(row["id_number"] or ""),
            "address_line": str(row["address_line"] or ""),
            "suburb": str(row["suburb"] or ""),
            "city": str(row["city"] or ""),
            "notes": str(row["notes"] or ""),
            "raw_form_json": str(row["raw_form_json"] or "{}"),
            "created_at": str(row["created_at"] or ""),
        }
    finally:
        c.close()


def list_splynx_push_attempts(record_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    rid = int(record_id or 0)
    lim = max(1, min(100, int(limit)))
    c = _conn()
    try:
        rows = c.execute(
            """
            SELECT id, record_id, mode, status, request_json, response_json, error_text, created_at
            FROM whatsapp_signup_splynx_pushes
            WHERE record_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (rid, lim),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "record_id": int(r["record_id"]),
                "mode": str(r["mode"] or ""),
                "status": str(r["status"] or ""),
                "request_json": str(r["request_json"] or "{}"),
                "response_json": str(r["response_json"] or "{}"),
                "error_text": str(r["error_text"] or ""),
                "created_at": str(r["created_at"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def _splynx_enabled_env() -> bool:
    return bool(
        (os.getenv("SPLYNX_API_BASE") or "").strip()
        and (os.getenv("SPLYNX_API_KEY") or "").strip()
        and (os.getenv("SPLYNX_API_SECRET") or "").strip()
    )


def _splynx_build_payload(record: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    full_name = str(record.get("full_name") or "").strip()
    parts = [p for p in full_name.split(" ") if p]
    first_name = parts[0] if parts else ""
    last_name = " ".join(parts[1:]) if len(parts) > 1 else ""
    payload = {
        "name": full_name,
        "email": str(record.get("email") or "").strip(),
        "phone": _phone_digits(str(record.get("from_phone") or "")),
        "street_1": str(record.get("address_line") or "").strip(),
        "city": str(record.get("city") or "").strip(),
        "notes": str(record.get("notes") or "").strip(),
        "first_name": first_name,
        "last_name": last_name,
        "custom_fields": {
            "source": "whatsapp_signup",
            "record_id": int(record.get("id") or 0),
            "campaign_note": str(record.get("notes") or "").strip(),
        },
    }
    loc = str(settings.get("splynx_default_location_id") or "").strip()
    if loc.isdigit():
        payload["location_id"] = int(loc)
    st = str(settings.get("splynx_default_status") or "").strip()
    if st:
        payload["status"] = st
    return payload


def _splynx_post_json(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    base = (os.getenv("SPLYNX_API_BASE") or "").strip().rstrip("/")
    key = (os.getenv("SPLYNX_API_KEY") or "").strip()
    sec = (os.getenv("SPLYNX_API_SECRET") or "").strip()
    if not (base and key and sec):
        raise ValueError("Splynx env credentials are not configured")
    token = base64.b64encode(f"{key}:{sec}".encode("utf-8")).decode("ascii")
    url = f"{base}/{str(path or '').lstrip('/')}"
    data = json.dumps(payload or {}, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "MTR-WhatsApp-Signups",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            out = json.loads(raw) if raw else {}
            if not isinstance(out, dict):
                out = {"raw": raw}
            return {"ok": True, "status_code": int(getattr(resp, "status", 200) or 200), "body": out}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"ok": False, "status_code": int(getattr(e, "code", 0) or 0), "body_raw": body[:2000]}
    except Exception as e:
        return {"ok": False, "status_code": 0, "body_raw": str(e)}


def push_record_to_splynx(record_id: int) -> Dict[str, Any]:
    record = get_record(int(record_id or 0))
    if not record:
        raise ValueError("Record not found")
    settings = get_settings()
    payload = _splynx_build_payload(record, settings)
    enabled = str(settings.get("splynx_enabled") or "0").strip() in ("1", "true", "yes")
    dry_run = str(settings.get("splynx_dry_run") or "1").strip() in ("1", "true", "yes")
    mode = "dry_run" if (not enabled or dry_run) else "live"
    path = str(settings.get("splynx_lead_path") or "admin/customers/customer").strip().lstrip("/")
    response: Dict[str, Any]
    status = "dry_run"
    err = ""
    if mode == "live":
        if not _splynx_enabled_env():
            status = "failed"
            err = "Splynx env credentials are not configured on server"
            response = {"ok": False, "detail": err}
        else:
            response = _splynx_post_json(path, payload)
            status = "ok" if bool(response.get("ok")) else "failed"
            if not bool(response.get("ok")):
                err = str(response.get("body_raw") or "Splynx request failed")
    else:
        response = {"ok": True, "detail": "Dry run only; no write sent to Splynx"}
    c = _conn()
    try:
        c.execute(
            """
            INSERT INTO whatsapp_signup_splynx_pushes(
                record_id, mode, status, request_json, response_json, error_text, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(record["id"]),
                mode,
                status,
                json.dumps(payload, ensure_ascii=True),
                json.dumps(response, ensure_ascii=True),
                err,
                _now(),
            ),
        )
        c.commit()
    finally:
        c.close()
    return {
        "ok": status in ("ok", "dry_run"),
        "mode": mode,
        "status": status,
        "record_id": int(record["id"]),
        "request_payload": payload,
        "response": response,
        "error": err,
    }


def webhook_health() -> Dict[str, Any]:
    c = _conn()
    try:
        last = c.execute(
            """
            SELECT id, event_type, status, created_at, from_phone
            FROM whatsapp_signup_events
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """
        ).fetchone()
        counts = c.execute("SELECT COUNT(*) AS n FROM whatsapp_signup_events").fetchone()
        rec_counts = c.execute("SELECT COUNT(*) AS n FROM whatsapp_signup_records").fetchone()
        return {
            "ok": True,
            "events_total": int(counts["n"] or 0) if counts else 0,
            "records_total": int(rec_counts["n"] or 0) if rec_counts else 0,
            "last_event": {
                "id": int(last["id"]) if last else None,
                "event_type": str(last["event_type"] or "") if last else "",
                "status": str(last["status"] or "") if last else "",
                "from_phone": str(last["from_phone"] or "") if last else "",
                "created_at": str(last["created_at"] or "") if last else "",
            } if last else None,
        }
    finally:
        c.close()


def update_record_details(record_id: int, address_line: str, suburb: str, notes: str) -> bool:
    rid = int(record_id or 0)
    if rid <= 0:
        raise ValueError("Invalid record id")
    c = _conn()
    try:
        cur = c.execute(
            """
            UPDATE whatsapp_signup_records
            SET address_line = ?, suburb = ?, notes = ?
            WHERE id = ?
            """,
            (
                str(address_line or "").strip(),
                str(suburb or "").strip(),
                str(notes or "").strip(),
                rid,
            ),
        )
        c.commit()
        return int(cur.rowcount or 0) > 0
    finally:
        c.close()


def _extract_message_event(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        entries = payload.get("entry") or []
        for entry in entries:
            changes = (entry or {}).get("changes") or []
            for change in changes:
                value = (change or {}).get("value") or {}
                contacts = value.get("contacts") or []
                messages = value.get("messages") or []
                statuses = value.get("statuses") or []
                profile_name = ""
                wa_id = ""
                if contacts:
                    c0 = contacts[0] or {}
                    profile_name = str((c0.get("profile") or {}).get("name") or "")
                    wa_id = str(c0.get("wa_id") or "")
                if messages:
                    m0 = messages[0] or {}
                    mtype = str(m0.get("type") or "")
                    msg_text = ""
                    interactive_json = {}
                    if mtype in ("text", "interactive"):
                        if mtype == "interactive":
                            interactive_json = m0.get("interactive") or {}
                        msg_text = _inbound_message_text(m0)
                    return {
                        "provider_event_id": str(m0.get("id") or ""),
                        "wa_id": wa_id,
                        "from_phone": str(m0.get("from") or wa_id),
                        "profile_name": profile_name,
                        "event_type": "message_" + (mtype or "unknown"),
                        "status": "received",
                        "message_text": msg_text,
                        "interactive_json": interactive_json,
                    }
                if statuses:
                    s0 = statuses[0] or {}
                    return {
                        "provider_event_id": str(s0.get("id") or ""),
                        "wa_id": str(s0.get("recipient_id") or ""),
                        "from_phone": str(s0.get("recipient_id") or ""),
                        "profile_name": "",
                        "event_type": "status_" + str(s0.get("status") or "unknown"),
                        "status": str(s0.get("status") or "unknown"),
                        "message_text": "",
                        "interactive_json": {},
                    }
    except Exception:
        return None
    return None


def ingest_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    evt = _extract_message_event(payload or {})
    c = _conn()
    try:
        ts = _now()
        if not evt:
            c.execute(
                """
                INSERT INTO whatsapp_signup_events(
                    provider_event_id, wa_id, from_phone, profile_name, event_type, status,
                    message_text, interactive_json, payload_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("", "", "", "", "unknown", "received", "", "{}", json.dumps(payload or {}, ensure_ascii=True), ts),
            )
            c.commit()
            return {"stored": 1, "recognized": False}
        cur = c.execute(
            """
            INSERT INTO whatsapp_signup_events(
                provider_event_id, wa_id, from_phone, profile_name, event_type, status,
                message_text, interactive_json, payload_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                str(evt.get("provider_event_id") or ""),
                str(evt.get("wa_id") or ""),
                str(evt.get("from_phone") or ""),
                str(evt.get("profile_name") or ""),
                str(evt.get("event_type") or ""),
                str(evt.get("status") or "received"),
                str(evt.get("message_text") or ""),
                json.dumps(evt.get("interactive_json") or {}, ensure_ascii=True),
                json.dumps(payload or {}, ensure_ascii=True),
                ts,
            ),
        )
        event_id = int(cur.fetchone()[0])
        # Attempt to map interactive form response into normalized signup records.
        try:
            mapping = json.loads(str(get_settings().get("field_mapping_json") or "{}"))
            if not isinstance(mapping, dict):
                mapping = {}
        except Exception:
            mapping = {}
        form_data: Dict[str, Any] = {}
        try:
            nfm = (evt.get("interactive_json") or {}).get("nfm_reply") or {}
            raw = nfm.get("response_json")
            if isinstance(raw, str) and raw.strip():
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    form_data = parsed
            elif isinstance(raw, dict):
                form_data = raw
        except Exception:
            form_data = {}
        if form_data:
            def val_for(target: str) -> str:
                src = str(mapping.get(target) or target).strip()
                return str(form_data.get(src) or "").strip()
            c.execute(
                """
                INSERT INTO whatsapp_signup_records(
                    event_id, from_phone, full_name, email, id_number, address_line, suburb, city, notes, raw_form_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    str(evt.get("from_phone") or ""),
                    val_for("full_name"),
                    val_for("email"),
                    val_for("id_number"),
                    val_for("address_line"),
                    val_for("suburb"),
                    val_for("city"),
                    val_for("notes"),
                    json.dumps(form_data, ensure_ascii=True),
                    ts,
                ),
            )
        _process_conversational_signup(c, evt)
        c.commit()
        return {"stored": 1, "recognized": True}
    finally:
        c.close()


_SIGNUP_STEPS = [
    {"field_key": "full_name", "question_text": "Awesome. What is your full name?", "type": "text", "required": True},
    {"field_key": "address_line", "question_text": "Great. What is your street address?", "type": "text", "required": True},
    {"field_key": "email", "question_text": "Great. What is your email address?", "type": "email", "required": True},
]


def _session_by_phone(c, from_phone: str):
    return c.execute(
        """
        SELECT id, from_phone, wa_id, profile_name, step_key, data_json, status, created_at, updated_at
        FROM whatsapp_signup_sessions
        WHERE from_phone = ? AND status = 'active'
        ORDER BY id DESC LIMIT 1
        """,
        (str(from_phone or ""),),
    ).fetchone()


def _send_whatsapp_text(to_phone: str, message: str) -> None:
    _ = send_test_message(str(to_phone or ""), str(message or ""), use_template=False)


def send_test_message(
    to_phone: str,
    message: str,
    use_template: bool = True,
    template_name: str = "hello_world",
    template_language: str = "en_US",
) -> Dict[str, Any]:
    cfg = get_settings()
    phone_number_id = str(cfg.get("phone_number_id") or "").strip()
    token = str(cfg.get("access_token") or "").strip()
    dst = _phone_digits(to_phone or "")
    if not phone_number_id:
        return {"ok": False, "detail": "Missing phone_number_id in config"}
    if not token:
        return {"ok": False, "detail": "Missing access_token in config"}
    if not dst:
        return {"ok": False, "detail": "Missing destination phone"}
    if not str(message or "").strip():
        return {"ok": False, "detail": "Message is empty"}
    if use_template:
        body = {
            "messaging_product": "whatsapp",
            "to": dst,
            "type": "template",
            "template": {
                "name": str(template_name or "hello_world"),
                "language": {"code": str(template_language or "en_US")},
            },
        }
    else:
        body = {
            "messaging_product": "whatsapp",
            "to": dst,
            "type": "text",
            "text": {"body": str(message)},
        }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"https://graph.facebook.com/v20.0/{phone_number_id}/messages",
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            payload = {}
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {"raw": raw}
            return {"ok": True, "response": payload}
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return {"ok": False, "detail": f"HTTP {getattr(e, 'code', '?')}", "body": b[:800]}
    except urllib.error.URLError as e:
        return {"ok": False, "detail": f"Network error: {e}"}
    except Exception as e:
        return {"ok": False, "detail": f"Send failed: {e}"}


def _process_conversational_signup(c, evt: Dict[str, Any]) -> None:
    if not str(evt.get("event_type") or "").startswith("message_"):
        return
    from_phone = str(evt.get("from_phone") or "").strip()
    if not from_phone:
        return
    msg = _clean_inbound_text(str(evt.get("message_text") or ""))
    norm = _norm_text(msg)
    session = _session_by_phone(c, from_phone)
    ts = _now()

    matched_campaign = find_campaign_by_trigger(msg)
    default_kickoff = (
        "signupwithwibernet" in norm
        or "wibernetsignup" in norm
        or norm in {"signup", "start", "hi", "hello"}
    )
    kickoff = bool(matched_campaign) or default_kickoff

    def _start_session(flow_steps: List[Dict[str, Any]], campaign: Optional[Dict[str, Any]]) -> None:
        if not isinstance(flow_steps, list) or not flow_steps:
            flow_steps = list(_SIGNUP_STEPS)
        first_step = flow_steps[0] if isinstance(flow_steps[0], dict) else _SIGNUP_STEPS[0]
        first_key = str(first_step.get("field_key") or "full_name")
        first_prompt = str(first_step.get("question_text") or "What is your full name?")
        if str(first_step.get("type") or "").strip().lower() == "multiple_choice":
            first_prompt = _format_multiple_choice_prompt(first_prompt, first_step.get("options"))
        welcome_text = (
            str((campaign or {}).get("welcome_text") or "").strip()
            if campaign
            else "Welcome to Wibernet signup."
        ) or "Welcome to Wibernet signup."
        meta = {
            "__flow_steps": flow_steps,
            "__step_index": 0,
            "__campaign_id": int((campaign or {}).get("id") or 0),
            "__campaign_code": str((campaign or {}).get("campaign_code") or ""),
        }
        if session:
            c.execute(
                """
                UPDATE whatsapp_signup_sessions
                SET wa_id = ?, profile_name = ?, step_key = ?, data_json = ?, status = 'active', updated_at = ?
                WHERE id = ?
                """,
                (
                    str(evt.get("wa_id") or ""),
                    str(evt.get("profile_name") or ""),
                    first_key,
                    json.dumps(meta, ensure_ascii=True),
                    ts,
                    int(session["id"]),
                ),
            )
        else:
            c.execute(
                """
                INSERT INTO whatsapp_signup_sessions(from_phone, wa_id, profile_name, step_key, data_json, status, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    from_phone,
                    str(evt.get("wa_id") or ""),
                    str(evt.get("profile_name") or ""),
                    first_key,
                    json.dumps(meta, ensure_ascii=True),
                    ts,
                    ts,
                ),
            )
        send_or_log(from_phone, welcome_text, "kickoff_welcome")
        send_or_log(from_phone, first_prompt, "kickoff_first_question")

    def send_or_log(phone: str, text: str, context: str) -> bool:
        rs = send_test_message(str(phone or ""), str(text or ""), use_template=False)
        if bool(rs.get("ok")):
            return True
        c.execute(
            """
            INSERT INTO whatsapp_signup_events(
                provider_event_id, wa_id, from_phone, profile_name, event_type, status,
                message_text, interactive_json, payload_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "",
                str(evt.get("wa_id") or ""),
                str(phone or ""),
                str(evt.get("profile_name") or ""),
                "bot_send_failed",
                "failed",
                f"{context}: {str(rs.get('detail') or 'send failed')}",
                "{}",
                json.dumps(rs, ensure_ascii=True),
                _now(),
            ),
        )
        return False

    if not session and kickoff:
        flow_steps = matched_campaign.get("flow") if matched_campaign else list(_SIGNUP_STEPS)
        if not isinstance(flow_steps, list) or not flow_steps:
            flow_steps = list(_SIGNUP_STEPS)
        _start_session(flow_steps, matched_campaign)
        return

    if session and kickoff:
        existing: Dict[str, Any] = {}
        try:
            parsed = json.loads(str(session["data_json"] or "{}"))
            if isinstance(parsed, dict):
                existing = parsed
        except Exception:
            existing = {}
        if _session_needs_flow_reset(existing):
            flow_steps = matched_campaign.get("flow") if matched_campaign else list(_SIGNUP_STEPS)
            if not isinstance(flow_steps, list) or not flow_steps:
                flow_steps = list(_SIGNUP_STEPS)
            _start_session(flow_steps, matched_campaign)
            return

    if not session:
        return

    try:
        data_json = str(session["data_json"] or "{}")
        data = json.loads(data_json)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    step_key = str(session["step_key"] or "")
    flow_steps = _flow_steps_for_session(data)
    idx = int(data.get("__step_index") or 0)
    if idx < 0 or idx >= len(flow_steps):
        idx = next((i for i, x in enumerate(flow_steps) if str((x or {}).get("field_key") or "") == step_key), 0)
    current_step = flow_steps[idx] if idx < len(flow_steps) and isinstance(flow_steps[idx], dict) else _SIGNUP_STEPS[0]
    current_key = str(current_step.get("field_key") or step_key or "full_name")
    stype = str(current_step.get("type") or "text").strip().lower()
    answer = msg
    if stype == "multiple_choice":
        options = current_step.get("options") or []
        mapped = _resolve_multiple_choice_answer(msg, options)
        if mapped is None:
            retry = _format_multiple_choice_prompt(
                str(current_step.get("question_text") or "Choose one option"),
                options,
            )
            retry = retry + "\n\nReply with the option number (e.g. 2) or the option label."
            send_or_log(from_phone, retry, "multiple_choice_retry")
            return
        answer = mapped
    if msg:
        data[current_key] = answer

    if idx + 1 < len(flow_steps):
        next_step = flow_steps[idx + 1] if isinstance(flow_steps[idx + 1], dict) else {}
        next_key = str(next_step.get("field_key") or "full_name")
        next_prompt = str(next_step.get("question_text") or "Next question")
        if str(next_step.get("type") or "").strip().lower() == "multiple_choice":
            next_prompt = _format_multiple_choice_prompt(next_prompt, next_step.get("options"))
        data["__step_index"] = idx + 1
        c.execute(
            "UPDATE whatsapp_signup_sessions SET step_key = ?, data_json = ?, updated_at = ? WHERE id = ?",
            (next_key, json.dumps(data, ensure_ascii=True), ts, int(session["id"])),
        )
        send_or_log(from_phone, next_prompt, "next_question")
        return

    full_name = str(data.get("full_name") or "").strip()
    success_text = "Thank you. Your signup has been submitted successfully."
    cid = int(data.get("__campaign_id") or 0)
    if cid > 0:
        for cd in list_campaign_defs():
            if int(cd.get("id") or 0) == cid:
                success_text = str(cd.get("success_text") or "").strip() or success_text
                break
    c.execute(
        """
        INSERT INTO whatsapp_signup_records(
            event_id, from_phone, full_name, email, id_number, address_line, suburb, city, notes, raw_form_json, created_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            None,
            from_phone,
            full_name,
            str(data.get("email") or ""),
            "",
            str(data.get("address_line") or ""),
            "",
            "",
            f"Captured via conversational signup flow ({str(data.get('__campaign_code') or 'default')})",
            json.dumps(data, ensure_ascii=True),
            ts,
        ),
    )
    c.execute("UPDATE whatsapp_signup_sessions SET status = 'completed', data_json = ?, updated_at = ? WHERE id = ?", (json.dumps(data, ensure_ascii=True), ts, int(session["id"])))
    send_or_log(from_phone, success_text, "completion")
