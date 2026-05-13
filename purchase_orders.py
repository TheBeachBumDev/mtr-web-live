import json
import os
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import db_runtime

PO_STATUS_DRAFT = "draft"
PO_STATUS_SUBMITTED = "submitted"
PO_STATUS_PENDING_MANAGER = "pending_manager"
PO_STATUS_PENDING_FINANCE = "pending_finance"
PO_STATUS_PENDING_DIRECTOR = "pending_director"
PO_STATUS_APPROVED = "approved"
PO_STATUS_SENT = "sent_to_supplier"
PO_STATUS_RECEIVED = "received"
PO_STATUS_PARTIAL = "partially_received"
PO_STATUS_CLOSED = "closed"
PO_STATUS_REJECTED = "rejected"
PO_STATUS_CHANGES = "changes_requested"
PO_STATUS_POSTPONED = "postponed"
PO_STATUS_CANCELLED = "cancelled"

STATUS_SEQUENCE: Tuple[str, ...] = (
    PO_STATUS_DRAFT,
    PO_STATUS_SUBMITTED,
    PO_STATUS_PENDING_MANAGER,
    PO_STATUS_PENDING_FINANCE,
    PO_STATUS_PENDING_DIRECTOR,
    PO_STATUS_APPROVED,
    PO_STATUS_SENT,
    PO_STATUS_PARTIAL,
    PO_STATUS_RECEIVED,
    PO_STATUS_CLOSED,
)

TERMINAL_STATUSES = {PO_STATUS_REJECTED, PO_STATUS_CANCELLED, PO_STATUS_CLOSED}
EDITABLE_STATUSES = {PO_STATUS_DRAFT, PO_STATUS_CHANGES}
DELETABLE_STATUSES = {PO_STATUS_DRAFT, PO_STATUS_CHANGES, PO_STATUS_REJECTED, PO_STATUS_CANCELLED}

REMINDER_4H = int(os.getenv("PO_REMINDER_4H_SEC", "14400"))
REMINDER_24H = int(os.getenv("PO_REMINDER_24H_SEC", "86400"))
REMINDER_48H = int(os.getenv("PO_REMINDER_48H_SEC", "172800"))
PO_DOCS_DIR = os.getenv("PO_DOCS_DIR", "/app/data/po-docs")
PO_ATTACHMENTS_DIR = os.getenv("PO_ATTACHMENTS_DIR", "/app/data/po-attachments")
PO_REQUEST_TYPES = {"stock_item", "customer_item", "reserve_stock_hs", "custom", "quote_import"}
PO_PAYMENT_STATUSES = {"paid", "unpaid"}
PO_URGENCY = {"urgent", "asap", "standard"}
# Default VAT fraction (e.g. South Africa 15%). Used when persisting new lines and when inferring legacy rows saved with tax_rate=0.
PO_DEFAULT_VAT_FRAC = Decimal("0.15")


def _is_manual_po_request_type(request_type: str) -> bool:
    return str(request_type or "").strip().lower() in {"custom", "quote_import"}


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _to_decimal(v: Any) -> Decimal:
    if isinstance(v, Decimal):
        return v
    try:
        return Decimal(str(v))
    except Exception:
        return Decimal("0")


def _money(v: Any) -> Decimal:
    return _to_decimal(v).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _conn():
    return db_runtime.get_conn("po")


def _ensure_dir(path: str) -> None:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _json(v: Any) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=True)


def _status_for_step(step_name: str) -> str:
    key = (step_name or "").strip().lower()
    if "manager" in key:
        return PO_STATUS_PENDING_MANAGER
    if "finance" in key:
        return PO_STATUS_PENDING_FINANCE
    if "director" in key:
        return PO_STATUS_PENDING_DIRECTOR
    return PO_STATUS_SUBMITTED


def init_db() -> None:
    _ensure_dir(PO_DOCS_DIR)
    _ensure_dir(PO_ATTACHMENTS_DIR)
    c = _conn()
    try:
        # Postgres parity: ensure department catalog + PO text department field exist.
        try:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS po_departments (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS department_name TEXT")
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS supplier_display_name TEXT")
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS request_type TEXT NOT NULL DEFAULT 'stock_item'")
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS customer_id BIGINT")
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS payment_status TEXT")
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS date_required TEXT")
            c.execute("ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS urgency TEXT NOT NULL DEFAULT 'standard'")
            for col, typ in (
                ("postponed_by_user_id", "BIGINT"),
                ("postponed_at", "TEXT"),
                ("resume_at", "TEXT"),
                ("resume_from_status", "TEXT"),
                ("resume_from_step", "INTEGER"),
                ("postponed_comment", "TEXT"),
            ):
                c.execute(f"ALTER TABLE purchase_orders ADD COLUMN IF NOT EXISTS {col} {typ}")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS po_role_assignments (
                    role_key TEXT PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                    backup_user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS po_department_role_assignments (
                    id BIGSERIAL PRIMARY KEY,
                    department_id BIGINT NOT NULL REFERENCES po_departments(id) ON DELETE CASCADE,
                    role_key TEXT NOT NULL,
                    user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                    backup_user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (department_id, role_key)
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS po_notification_settings (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            from po_email_actions import ensure_po_email_action_tokens_table

            ensure_po_email_action_tokens_table(c)
        except Exception:
            pass
        c.commit()
        _seed_rules(c)
        _seed_departments(c)
        _seed_role_assignments(c)
        _seed_notification_settings(c)
        c.commit()
    finally:
        c.close()


def _seed_rules(c) -> None:
    n = int(c.execute("SELECT COUNT(*) FROM approval_rules").fetchone()[0])
    if n > 0:
        return
    user_rows = c.execute(
        "SELECT id, username, is_admin FROM app_users ORDER BY is_admin DESC, id ASC"
    ).fetchall()
    if not user_rows:
        return
    manager_id = int(user_rows[0]["id"])
    finance_id = int(user_rows[1]["id"]) if len(user_rows) > 1 else manager_id
    director_id = int(user_rows[2]["id"]) if len(user_rows) > 2 else finance_id
    ts = _now()
    seed = [
        ("Default <5k Manager", 1, 0, 4999.99, None, None, 1, "Manager", manager_id, None, ts, ts),
        ("Default 5k-25k Manager", 1, 5000, 25000, None, None, 1, "Manager", manager_id, None, ts, ts),
        ("Default 5k-25k Finance", 1, 5000, 25000, None, None, 2, "Finance", finance_id, manager_id, ts, ts),
        ("Default >25k Manager", 1, 25000.01, None, None, None, 1, "Manager", manager_id, None, ts, ts),
        ("Default >25k Finance", 1, 25000.01, None, None, None, 2, "Finance", finance_id, manager_id, ts, ts),
        ("Default >25k Director", 1, 25000.01, None, None, None, 3, "Director", director_id, finance_id, ts, ts),
    ]
    c.executemany(
        """
        INSERT INTO approval_rules(
            name, active, min_total, max_total, department_id, category,
            step_number, step_name, approver_user_id, backup_approver_user_id,
            created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        seed,
    )


def _seed_departments(c) -> None:
    n = int(c.execute("SELECT COUNT(*) FROM po_departments").fetchone()[0])
    if n > 0:
        return
    ts = _now()
    for name in ("Procurement", "Operations", "Finance"):
        try:
            c.execute(
                "INSERT INTO po_departments(name, active, created_at, updated_at) VALUES(?, 1, ?, ?)",
                (name, ts, ts),
            )
        except Exception:
            pass


def _seed_role_assignments(c) -> None:
    n = int(c.execute("SELECT COUNT(*) FROM po_role_assignments").fetchone()[0])
    users = c.execute("SELECT id FROM app_users ORDER BY is_admin DESC, id ASC").fetchall()
    if not users:
        return
    manager_id = int(users[0]["id"])
    finance_id = int(users[1]["id"]) if len(users) > 1 else manager_id
    director_id = int(users[2]["id"]) if len(users) > 2 else finance_id
    ts = _now()
    if n == 0:
        c.executemany(
            "INSERT INTO po_role_assignments(role_key, user_id, backup_user_id, updated_at) VALUES(?, ?, ?, ?)",
            [
                ("manager", manager_id, None, ts),
                ("finance", finance_id, manager_id, ts),
                ("director", director_id, finance_id, ts),
            ],
        )
    dep_n = int(c.execute("SELECT COUNT(*) FROM po_department_role_assignments").fetchone()[0])
    if dep_n > 0:
        return
    deps = c.execute("SELECT id FROM po_departments WHERE active = 1").fetchall()
    for d in deps:
        did = int(d["id"])
        try:
            c.executemany(
                """
                INSERT INTO po_department_role_assignments(department_id, role_key, user_id, backup_user_id, updated_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                [
                    (did, "manager", manager_id, None, ts),
                    (did, "finance", finance_id, manager_id, ts),
                    (did, "director", director_id, finance_id, ts),
                ],
            )
        except Exception:
            pass


def _seed_notification_settings(c) -> None:
    ts = _now()
    defaults = {
        "reminder_4h_sec": str(int(REMINDER_4H)),
        "escalation_24h_sec": str(int(REMINDER_24H)),
        "backup_48h_sec": str(int(REMINDER_48H)),
    }
    for k, v in defaults.items():
        row = c.execute("SELECT v FROM po_notification_settings WHERE k = ?", (k,)).fetchone()
        if not row:
            c.execute(
                "INSERT INTO po_notification_settings(k, v, updated_at) VALUES(?, ?, ?)",
                (k, v, ts),
            )


def list_suppliers() -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute("SELECT id, name FROM stock_suppliers ORDER BY name COLLATE NOCASE ASC").fetchall()
        return [{"id": int(r["id"]), "name": str(r["name"])} for r in rows]
    finally:
        c.close()


def list_departments() -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute(
            "SELECT id, name FROM po_departments WHERE active = 1 ORDER BY name COLLATE NOCASE ASC"
        ).fetchall()
        return [{"id": int(r["id"]), "name": str(r["name"])} for r in rows]
    finally:
        c.close()


def list_approval_rules() -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute(
            """
            SELECT r.id, r.name, r.active, r.min_total, r.max_total, r.department_id, d.name AS department_name,
                   r.category, r.step_number, r.step_name, r.approver_user_id, u.username AS approver_username,
                   r.backup_approver_user_id, ub.username AS backup_approver_username
            FROM approval_rules r
            LEFT JOIN po_departments d ON d.id = r.department_id
            LEFT JOIN app_users u ON u.id = r.approver_user_id
            LEFT JOIN app_users ub ON ub.id = r.backup_approver_user_id
            ORDER BY r.step_number ASC, r.id ASC
            """
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "name": str(r["name"] or ""),
                "active": int(r["active"] or 0) == 1,
                "min_total": float(_money(r["min_total"] or 0)),
                "max_total": float(_money(r["max_total"])) if r["max_total"] is not None else None,
                "department_id": int(r["department_id"]) if r["department_id"] is not None else None,
                "department_name": str(r["department_name"] or ""),
                "category": str(r["category"] or ""),
                "step_number": int(r["step_number"]),
                "step_name": str(r["step_name"] or ""),
                "approver_user_id": int(r["approver_user_id"]),
                "approver_username": str(r["approver_username"] or ""),
                "backup_approver_user_id": int(r["backup_approver_user_id"]) if r["backup_approver_user_id"] is not None else None,
                "backup_approver_username": str(r["backup_approver_username"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def list_approver_users() -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute(
            "SELECT id, username, is_admin FROM app_users ORDER BY username COLLATE NOCASE ASC"
        ).fetchall()
        return [
            {"id": int(r["id"]), "username": str(r["username"]), "is_admin": int(r["is_admin"] or 0) == 1}
            for r in rows
        ]
    finally:
        c.close()


def list_role_assignments(department_id: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
    c = _conn()
    try:
        dep_id = int(department_id or 0)
        if dep_id > 0:
            rows = c.execute(
                """
                SELECT ra.role_key, ra.user_id, u.username AS username,
                       ra.backup_user_id, ub.username AS backup_username
                FROM po_department_role_assignments ra
                LEFT JOIN app_users u ON u.id = ra.user_id
                LEFT JOIN app_users ub ON ub.id = ra.backup_user_id
                WHERE ra.department_id = ?
                """,
                (dep_id,),
            ).fetchall()
        else:
            rows = c.execute(
                """
                SELECT ra.role_key, ra.user_id, u.username AS username,
                       ra.backup_user_id, ub.username AS backup_username
                FROM po_role_assignments ra
                LEFT JOIN app_users u ON u.id = ra.user_id
                LEFT JOIN app_users ub ON ub.id = ra.backup_user_id
                """
            ).fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            out[str(r["role_key"])] = {
                "user_id": int(r["user_id"]),
                "username": str(r["username"] or ""),
                "backup_user_id": int(r["backup_user_id"]) if r["backup_user_id"] is not None else None,
                "backup_username": str(r["backup_username"] or ""),
            }
        return out
    finally:
        c.close()


def set_role_assignment(role_key: str, user_id: int, backup_user_id: Optional[int], department_id: Optional[int] = None) -> bool:
    rk = (role_key or "").strip().lower()
    if rk not in {"manager", "finance", "director"}:
        raise ValueError("Invalid role key")
    c = _conn()
    try:
        ts = _now()
        dep_id = int(department_id or 0)
        if dep_id > 0:
            c.execute(
                """
                INSERT INTO po_department_role_assignments(department_id, role_key, user_id, backup_user_id, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(department_id, role_key) DO UPDATE SET
                  user_id = excluded.user_id,
                  backup_user_id = excluded.backup_user_id,
                  updated_at = excluded.updated_at
                """,
                (dep_id, rk, int(user_id), int(backup_user_id) if backup_user_id else None, ts),
            )
        else:
            c.execute(
                """
                INSERT INTO po_role_assignments(role_key, user_id, backup_user_id, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(role_key) DO UPDATE SET
                  user_id = excluded.user_id,
                  backup_user_id = excluded.backup_user_id,
                  updated_at = excluded.updated_at
                """,
                (rk, int(user_id), int(backup_user_id) if backup_user_id else None, ts),
            )
        c.commit()
        return True
    except Exception:
        raise ValueError("Could not save role assignment") from None
    finally:
        c.close()


def add_approval_rule(
    name: str,
    min_total: float,
    max_total: Optional[float],
    department_id: Optional[int],
    category: str,
    step_number: int,
    step_name: str,
    approver_user_id: int,
    backup_approver_user_id: Optional[int],
    active: bool = True,
) -> int:
    nm = (name or "").strip() or "Rule"
    sn = (step_name or "").strip()
    if not sn:
        raise ValueError("Step name required")
    if int(step_number) <= 0:
        raise ValueError("Step number must be > 0")
    c = _conn()
    try:
        ts = _now()
        cur = c.execute(
            """
            INSERT INTO approval_rules(
              name, active, min_total, max_total, department_id, category,
              step_number, step_name, approver_user_id, backup_approver_user_id,
              created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                nm,
                1 if active else 0,
                float(_money(min_total)),
                float(_money(max_total)) if max_total is not None else None,
                int(department_id) if department_id else None,
                (category or "").strip(),
                int(step_number),
                sn,
                int(approver_user_id),
                int(backup_approver_user_id) if backup_approver_user_id else None,
                ts,
                ts,
            ),
        )
        rule_id = int(cur.fetchone()[0])
        c.commit()
        return rule_id
    except Exception:
        raise ValueError("Could not create approval rule") from None
    finally:
        c.close()


def delete_approval_rule(rule_id: int) -> bool:
    c = _conn()
    try:
        cur = c.execute("DELETE FROM approval_rules WHERE id = ?", (int(rule_id),))
        c.commit()
        return int(cur.rowcount or 0) > 0
    finally:
        c.close()


def add_department(name: str) -> int:
    nm = (name or "").strip()
    if len(nm) < 2 or len(nm) > 120:
        raise ValueError("Department name must be 2-120 characters")
    c = _conn()
    try:
        ts = _now()
        cur = c.execute(
            "INSERT INTO po_departments(name, active, created_at, updated_at) VALUES(?, 1, ?, ?) RETURNING id",
            (nm, ts, ts),
        )
        dep_id = int(cur.fetchone()[0])
        c.commit()
        return dep_id
    except Exception:
        raise ValueError("Department already exists or invalid") from None
    finally:
        c.close()


def _calc_line_item(item: Dict[str, Any]) -> Dict[str, Any]:
    # Business rule: PO quantities are whole units only.
    qty_raw = _to_decimal(item.get("quantity", 0))
    try:
        qty = Decimal(int(qty_raw.to_integral_value(rounding=ROUND_HALF_UP)))
    except Exception:
        qty = Decimal("1")
    if qty < 1:
        qty = Decimal("1")
    unit = _money(item.get("unit_price", 0))
    tax_rate = _to_decimal(item.get("tax_rate", 0))
    if tax_rate > 1:
        tax_rate = tax_rate / Decimal("100")
    subtotal = (qty * unit).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    tax_amount = (subtotal * tax_rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    line_total = subtotal + tax_amount
    return {
        "description": str(item.get("description") or "").strip(),
        "quantity": float(qty),
        "unit_price": float(unit),
        "tax_rate": float(tax_rate),
        "tax_amount": float(tax_amount),
        "line_total": float(line_total),
    }


def _po_item_row_for_response(r: Any) -> Dict[str, Any]:
    """Build one line item for API, PDF, and emails.

    Amounts are always derived from stored ex-VAT ``unit_price`` (the Inc/Ex UI toggle only affects how
    users type values before save; the database always holds the ex-VAT unit). ``tax_rate`` and per-line
    tax follow ``_calc_line_item``.

    Legacy rows were often saved with ``tax_rate`` 0 and no per-line tax; if the stored ``line_total``
    equals the ex-VAT subtotal (within rounding), we infer ``PO_DEFAULT_VAT_FRAC`` for display so PDFs
    and emails show VAT like the header totals.
    """
    desc = str(r["description"] or "")
    qty = r["quantity"]
    unit = r["unit_price"]
    tr = r["tax_rate"]
    stored_line = _money(r["line_total"] or 0)
    cooked = _calc_line_item({"description": desc, "quantity": qty, "unit_price": unit, "tax_rate": tr})
    if float(cooked["tax_rate"]) <= 0 and float(cooked["tax_amount"]) <= 0:
        sub_ex = _money(cooked["quantity"]) * _money(cooked["unit_price"])
        if sub_ex > 0 and stored_line <= sub_ex + Decimal("0.02"):
            cooked = _calc_line_item({"description": desc, "quantity": qty, "unit_price": unit, "tax_rate": PO_DEFAULT_VAT_FRAC})
    return {
        "id": int(r["id"]),
        "description": desc,
        "quantity": float(cooked["quantity"]),
        "unit_price": float(_money(cooked["unit_price"])),
        "tax_rate": float(cooked["tax_rate"]),
        "tax_amount": float(_money(cooked["tax_amount"])),
        "line_total": float(_money(cooked["line_total"])),
        "created_at": str(r["created_at"] or ""),
    }


def _calc_totals(items: Iterable[Dict[str, Any]]) -> Tuple[Decimal, Decimal, Decimal, List[Dict[str, Any]]]:
    out: List[Dict[str, Any]] = []
    subtotal = Decimal("0")
    tax = Decimal("0")
    for i in items:
        row = _calc_line_item(i)
        if not row["description"]:
            continue
        out.append(row)
        subtotal += _money(row["quantity"]) * _money(row["unit_price"])
        tax += _money(row["tax_amount"])
    subtotal = _money(subtotal)
    tax = _money(tax)
    total = _money(subtotal + tax)
    return subtotal, tax, total, out


def _po_row(c, po_id: int):
    return c.execute(
        """
        SELECT
          po.*,
          COALESCE(su.name, po.supplier_display_name) AS supplier_name,
          COALESCE(po.department_name, d.name) AS department_name,
          u.username AS requested_by_username,
          pu.username AS postponed_by_username
        FROM purchase_orders po
        LEFT JOIN stock_suppliers su ON su.id = po.supplier_id
        LEFT JOIN ipam_locations d ON d.id = po.department_id
        LEFT JOIN app_users u ON u.id = po.requested_by_user_id
        LEFT JOIN app_users pu ON pu.id = po.postponed_by_user_id
        WHERE po.id = ?
        """,
        (int(po_id),),
    ).fetchone()


def _log_status(c, po_id: int, actor_user_id: Optional[int], action: str, from_status: Optional[str], to_status: Optional[str], comments: str = "", meta: Optional[Dict[str, Any]] = None):
    c.execute(
        """
        INSERT INTO purchase_order_status_log(
          purchase_order_id, actor_user_id, action, from_status, to_status, comments, meta_json, created_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(po_id),
            int(actor_user_id) if actor_user_id else None,
            str(action),
            from_status,
            to_status,
            comments or "",
            _json(meta or {}),
            _now(),
        ),
    )


def _apply_implicit_channels(c, user_id: int) -> List[str]:
    row = c.execute(
        """
        SELECT notify_app, notify_email, notify_whatsapp
        FROM user_notification_preferences
        WHERE user_id = ?
        """,
        (int(user_id),),
    ).fetchone()
    if not row:
        return ["app", "email"]
    out: List[str] = []
    if int(row["notify_app"] or 0) == 1:
        out.append("app")
    if int(row["notify_email"] or 0) == 1:
        out.append("email")
    if int(row["notify_whatsapp"] or 0) == 1:
        out.append("whatsapp")
    return out or ["app"]


def _approval_required_notification_content(
    po_id: int,
    po_number: str,
    total: Decimal,
    supplier_name: str,
    step_name: str,
) -> Tuple[str, str, str]:
    title = "PO Approval Required"
    url = f"/purchase-orders?po_id={int(po_id)}"
    msg = f"PO {po_number} | Amount: R{total:.2f} | Supplier: {supplier_name or '-'} | Step: {step_name}"
    return title, msg, url


def _cancel_pending_approval_notifications(c, po_id: int) -> None:
    """Stop reminders/escalations hitting approvers after decline/changes/etc."""
    ts = _now()
    c.execute(
        """
        UPDATE notifications
        SET state = 'failed', failed_at = ?
        WHERE purchase_order_id = ? AND state = 'pending'
          AND event_type IN (
            'approval_required',
            'approval_reminder_4h',
            'approval_reminder_24h',
            'approval_escalation_48h'
          )
        """,
        (ts, int(po_id)),
    )


def _enqueue_notifications_for_approval(c, po_id: int, po_number: str, total: Decimal, supplier_name: str, approver_id: int, step_name: str) -> None:
    now = datetime.utcnow()
    channels = _apply_implicit_channels(c, approver_id)
    title, msg, url = _approval_required_notification_content(
        int(po_id), po_number, total, supplier_name, step_name
    )
    rem4, rem24, rem48 = _load_notification_timing(c)
    for ch in channels:
        c.execute(
            """
            INSERT INTO notifications(
              user_id, purchase_order_id, event_type, title, message, action_url, channel, schedule_at, state, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (int(approver_id), int(po_id), "approval_required", title, msg, url, ch, _now(), _now()),
        )
        # reminders
        for sec, et in ((rem4, "approval_reminder_4h"), (rem24, "approval_reminder_24h"), (rem48, "approval_escalation_48h")):
            schedule_at = (now + timedelta(seconds=int(sec))).isoformat(timespec="seconds") + "Z"
            c.execute(
                """
                INSERT INTO notifications(
                  user_id, purchase_order_id, event_type, title, message, action_url, channel, schedule_at, state, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (int(approver_id), int(po_id), et, title, msg, url, ch, schedule_at, _now()),
            )


def _enqueue_requester_update_notification(
    c,
    po_id: int,
    requester_user_id: int,
    status_label: str,
    comments: str,
) -> None:
    channels = _apply_implicit_channels(c, requester_user_id)
    title = f"PO #{po_id} {status_label}"
    msg = f"Your purchase order #{po_id} has been marked as {status_label}."
    if str(comments or "").strip():
        msg += f" Comments: {str(comments).strip()}"
    url = f"/purchase-orders?po_id={int(po_id)}"
    for ch in channels:
        c.execute(
            """
            INSERT INTO notifications(
              user_id, purchase_order_id, event_type, title, message, action_url, channel, schedule_at, state, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (int(requester_user_id), int(po_id), "po_status_update", title, msg, url, ch, _now(), _now()),
        )


def _load_rules(c, total: Decimal, department_id: Optional[int], category: str) -> List[Dict[str, Any]]:
    rows = c.execute(
        """
        SELECT id, min_total, max_total, department_id, category, step_number, step_name, approver_user_id, backup_approver_user_id
        FROM approval_rules
        WHERE active = 1
        ORDER BY step_number ASC, id ASC
        """
    ).fetchall()
    dep_role_map: Dict[str, Dict[str, Any]] = {}
    if int(department_id or 0) > 0:
        dep_rows = c.execute(
            """
            SELECT role_key, user_id, backup_user_id
            FROM po_department_role_assignments
            WHERE department_id = ?
            """,
            (int(department_id),),
        ).fetchall()
        dep_role_map = {
            str(rr["role_key"] or "").strip().lower(): {
                "user_id": int(rr["user_id"]),
                "backup_user_id": int(rr["backup_user_id"]) if rr["backup_user_id"] is not None else None,
            }
            for rr in dep_rows
        }
    out: List[Dict[str, Any]] = []
    for r in rows:
        mn = _to_decimal(r["min_total"] or 0)
        mx = _to_decimal(r["max_total"]) if r["max_total"] is not None else None
        if total < mn:
            continue
        if mx is not None and total > mx:
            continue
        rid = int(r["department_id"]) if r["department_id"] is not None else None
        if rid is not None and int(department_id or 0) != rid:
            continue
        rc = str(r["category"] or "").strip().lower()
        if rc and rc != str(category or "").strip().lower():
            continue
        step_name = str(r["step_name"])
        role_key = step_name.strip().lower()
        approver_user_id = int(r["approver_user_id"])
        backup_approver_user_id = int(r["backup_approver_user_id"]) if r["backup_approver_user_id"] is not None else None
        if role_key in dep_role_map:
            approver_user_id = int(dep_role_map[role_key]["user_id"])
            backup_approver_user_id = dep_role_map[role_key]["backup_user_id"]
        out.append(
            {
                "step_number": int(r["step_number"]),
                "step_name": step_name,
                "approver_user_id": approver_user_id,
                "backup_approver_user_id": backup_approver_user_id,
            }
        )
    if out:
        return out
    # fallback to first admin
    admin = c.execute("SELECT id FROM app_users WHERE is_admin = 1 ORDER BY id ASC LIMIT 1").fetchone()
    if admin:
        return [{"step_number": 1, "step_name": "Manager", "approver_user_id": int(admin["id"]), "backup_approver_user_id": None}]
    return []


def _next_po_number(c) -> str:
    y = datetime.utcnow().year
    row = c.execute("SELECT last_seq FROM po_number_sequences WHERE year = ?", (y,)).fetchone()
    now = _now()
    if row:
        seq = int(row["last_seq"]) + 1
        c.execute("UPDATE po_number_sequences SET last_seq = ?, updated_at = ? WHERE year = ?", (seq, now, y))
    else:
        seq = 1
        c.execute("INSERT INTO po_number_sequences(year, last_seq, updated_at) VALUES(?, ?, ?)", (y, seq, now))
    return f"PO-{y}-{seq:04d}"


def _resolve_po_header(
    c,
    request_type: str,
    supplier_id: Optional[int],
    department_id: Optional[int],
    department_name_in: str,
    supplier_name_in: str,
) -> Tuple[Optional[int], str, Optional[int], str]:
    rt = str(request_type or "").strip().lower()
    if rt not in PO_REQUEST_TYPES:
        raise ValueError("Request type is required")
    if _is_manual_po_request_type(rt):
        department_name = str(department_name_in or "").strip()
        if not department_name:
            raise ValueError("Department is required")
        supplier_display_name = str(supplier_name_in or "").strip()
        if not supplier_display_name:
            raise ValueError("Supplier is required")
        return None, department_name, None, supplier_display_name
    if not department_id:
        raise ValueError("Department is required")
    dr = c.execute("SELECT name FROM po_departments WHERE id = ? AND active = 1", (int(department_id),)).fetchone()
    department_name = str(dr["name"]) if dr else ""
    if not department_name:
        raise ValueError("Valid department is required")
    return (int(supplier_id) if supplier_id else None), department_name, None, ""


def _resolve_po_request_fields(
    request_type: str,
    customer_id: Optional[int],
    payment_status: str,
    date_required: str,
    urgency: str,
) -> Tuple[Optional[int], str, str, str]:
    rt = str(request_type or "").strip().lower()
    if _is_manual_po_request_type(rt):
        return None, "", "", "standard"
    cid = int(customer_id or 0) if customer_id not in (None, "") else 0
    pay = str(payment_status or "").strip().lower()
    if rt == "customer_item":
        if cid <= 0:
            raise ValueError("Customer ID is required for Customer Item")
        if pay not in PO_PAYMENT_STATUSES:
            raise ValueError("Paid/Unpaid is required for Customer Item")
    else:
        cid = 0
        pay = ""
    drq = str(date_required or "").strip()
    if not drq:
        raise ValueError("Date required is mandatory")
    urg = str(urgency or "").strip().lower()
    if urg not in PO_URGENCY:
        raise ValueError("Urgency is required")
    return (cid if cid > 0 else None), pay, drq, urg


def create_draft(
    requested_by_user_id: int,
    supplier_id: Optional[int],
    department_id: Optional[int],
    category: str,
    notes: str,
    request_type: str,
    customer_id: Optional[int],
    payment_status: str,
    date_required: str,
    urgency: str,
    items: List[Dict[str, Any]],
    tax_override: Optional[float] = None,
    department_name: str = "",
    supplier_name: str = "",
) -> int:
    subtotal, tax, total, cooked = _calc_totals(items)
    if tax_override is not None:
        tax = _money(tax_override)
        total = _money(subtotal + tax)
    c = _conn()
    try:
        supplier_id, department_name, _, supplier_display_name = _resolve_po_header(
            c,
            request_type,
            supplier_id,
            department_id,
            department_name,
            supplier_name,
        )
        rt = str(request_type or "").strip().lower()
        cid, pay, drq, urg = _resolve_po_request_fields(
            rt,
            customer_id,
            payment_status,
            date_required,
            urgency,
        )
        ts = _now()
        cur = c.execute(
            """
            INSERT INTO purchase_orders(
          requested_by_user_id, supplier_id, supplier_display_name, department_id, department_name, status, subtotal, tax, total, notes, category, request_type, customer_id, payment_status, date_required, urgency, current_approval_step, created_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            RETURNING id
            """,
            (
                int(requested_by_user_id),
                supplier_id,
                supplier_display_name or None,
                None,
                department_name,
                PO_STATUS_DRAFT,
                float(subtotal),
                float(tax),
                float(total),
                notes or "",
                category or "",
                rt,
                cid,
                pay,
                drq,
                urg,
                ts,
            ),
        )
        po_id = int(cur.fetchone()[0])
        if cooked:
            c.executemany(
                """
                INSERT INTO purchase_order_items(
                  purchase_order_id, description, quantity, unit_price, tax_rate, tax_amount, line_total, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        po_id,
                        r["description"],
                        r["quantity"],
                        r["unit_price"],
                        r["tax_rate"],
                        r["tax_amount"],
                        r["line_total"],
                        ts,
                    )
                    for r in cooked
                ],
            )
        _log_status(c, po_id, requested_by_user_id, "created", None, PO_STATUS_DRAFT)
        c.commit()
        return po_id
    finally:
        c.close()


def update_draft(
    po_id: int,
    actor_user_id: int,
    supplier_id: Optional[int],
    department_id: Optional[int],
    category: str,
    notes: str,
    request_type: str,
    customer_id: Optional[int],
    payment_status: str,
    date_required: str,
    urgency: str,
    items: List[Dict[str, Any]],
    tax_override: Optional[float] = None,
    department_name: str = "",
    supplier_name: str = "",
) -> bool:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        status = str(po["status"] or "")
        if status not in EDITABLE_STATUSES:
            raise ValueError("PO is locked for edits")
        if int(po["requested_by_user_id"]) != int(actor_user_id):
            raise ValueError("Only requester can edit this PO")
        subtotal, tax, total, cooked = _calc_totals(items)
        if tax_override is not None:
            tax = _money(tax_override)
            total = _money(subtotal + tax)
        supplier_id, department_name, _, supplier_display_name = _resolve_po_header(
            c,
            request_type,
            supplier_id,
            department_id,
            department_name,
            supplier_name,
        )
        rt = str(request_type or "").strip().lower()
        cid, pay, drq, urg = _resolve_po_request_fields(
            rt,
            customer_id,
            payment_status,
            date_required,
            urgency,
        )
        c.execute(
            """
            UPDATE purchase_orders
            SET supplier_id = ?, supplier_display_name = ?, department_id = ?, department_name = ?, category = ?, notes = ?, request_type = ?, customer_id = ?, payment_status = ?, date_required = ?, urgency = ?, subtotal = ?, tax = ?, total = ?
            WHERE id = ?
            """,
            (
                supplier_id,
                supplier_display_name or None,
                None,
                department_name,
                category or "",
                notes or "",
                rt,
                cid,
                pay,
                drq,
                urg,
                float(subtotal),
                float(tax),
                float(total),
                int(po_id),
            ),
        )
        c.execute("DELETE FROM purchase_order_items WHERE purchase_order_id = ?", (int(po_id),))
        ts = _now()
        if cooked:
            c.executemany(
                """
                INSERT INTO purchase_order_items(
                  purchase_order_id, description, quantity, unit_price, tax_rate, tax_amount, line_total, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (int(po_id), r["description"], r["quantity"], r["unit_price"], r["tax_rate"], r["tax_amount"], r["line_total"], ts)
                    for r in cooked
                ],
            )
        _log_status(c, po_id, actor_user_id, "updated", status, status)
        c.commit()
        return True
    finally:
        c.close()


def submit_po(po_id: int, actor_user_id: int) -> bool:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        if int(po["requested_by_user_id"]) != int(actor_user_id):
            raise ValueError("Only requester can submit this PO")
        status = str(po["status"] or "")
        if status not in EDITABLE_STATUSES:
            raise ValueError("PO already submitted")
        if not str(po["department_name"] or "").strip():
            raise ValueError("Department is required before submission")
        total = _money(po["total"] or 0)
        rules = _load_rules(c, total, int(po["department_id"]) if po["department_id"] is not None else None, str(po["category"] or ""))
        if not rules:
            raise ValueError("No approval rules available")
        po_number = _next_po_number(c)
        submitted_at = _now()
        first_step = min(int(r["step_number"]) for r in rules)
        first = [r for r in rules if int(r["step_number"]) == first_step][0]
        next_status = _status_for_step(str(first["step_name"]))
        c.execute("DELETE FROM purchase_order_approvals WHERE purchase_order_id = ?", (int(po_id),))
        for r in rules:
            c.execute(
                """
                INSERT INTO purchase_order_approvals(
                  purchase_order_id, step_number, step_name, approver_user_id, backup_approver_user_id, status, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    int(po_id),
                    int(r["step_number"]),
                    str(r["step_name"]),
                    int(r["approver_user_id"]),
                    int(r["backup_approver_user_id"]) if r["backup_approver_user_id"] else None,
                    submitted_at,
                    submitted_at,
                ),
            )
        c.execute(
            """
            UPDATE purchase_orders
            SET po_number = ?, status = ?, submitted_at = ?, current_approval_step = ?
            WHERE id = ?
            """,
            (po_number, next_status, submitted_at, int(first_step), int(po_id)),
        )
        _log_status(c, po_id, actor_user_id, "submitted", status, next_status, meta={"po_number": po_number})
        first_step_rows = c.execute(
            """
            SELECT approver_user_id, step_name
            FROM purchase_order_approvals
            WHERE purchase_order_id = ? AND step_number = ?
            """,
            (int(po_id), int(first_step)),
        ).fetchall()
        supplier_name = str(po["supplier_name"] or "")
        for fr in first_step_rows:
            _enqueue_notifications_for_approval(c, po_id, po_number, total, supplier_name, int(fr["approver_user_id"]), str(fr["step_name"]))
        c.commit()
        return True
    finally:
        c.close()


def _complete_step_if_ready(c, po_id: int, step_number: int) -> bool:
    open_rows = c.execute(
        """
        SELECT COUNT(*) AS n
        FROM purchase_order_approvals
        WHERE purchase_order_id = ? AND step_number = ? AND status = 'pending'
        """,
        (int(po_id), int(step_number)),
    ).fetchone()
    return int(open_rows["n"] or 0) == 0


def _pending_approval_row_for_actor(
    c: Any,
    po_id: int,
    step: int,
    actor_user_id: int,
    *,
    force_admin: bool,
) -> Optional[Any]:
    """Row on the current step this actor may act on: primary approver or backup. If force_admin, any pending row on the step."""
    pid = int(po_id)
    st = int(step)
    aid = int(actor_user_id)
    row = c.execute(
        """
        SELECT id
        FROM purchase_order_approvals
        WHERE purchase_order_id = ? AND step_number = ? AND status = 'pending'
          AND (approver_user_id = ? OR (backup_approver_user_id IS NOT NULL AND backup_approver_user_id = ?))
        ORDER BY id ASC
        LIMIT 1
        """,
        (pid, st, aid, aid),
    ).fetchone()
    if row or not force_admin:
        return row
    return c.execute(
        """
        SELECT id
        FROM purchase_order_approvals
        WHERE purchase_order_id = ? AND step_number = ? AND status = 'pending'
        ORDER BY id ASC
        LIMIT 1
        """,
        (pid, st),
    ).fetchone()


def approve_step(po_id: int, actor_user_id: int, comments: str = "", force_admin: bool = False) -> str:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        if str(po["status"]) in TERMINAL_STATUSES:
            return str(po["status"])
        step = int(po["current_approval_step"] or 0)
        row = _pending_approval_row_for_actor(c, int(po_id), step, int(actor_user_id), force_admin=force_admin)
        if not row:
            raise ValueError("No pending approval assigned to this user")
        ts = _now()
        c.execute(
            """
            UPDATE purchase_order_approvals
            SET status = 'approved', approved_at = ?, comments = ?, updated_at = ?
            WHERE id = ?
            """,
            (ts, comments or "", ts, int(row["id"])),
        )
        current_status = str(po["status"])
        if _complete_step_if_ready(c, po_id, step):
            nxt = c.execute(
                """
                SELECT MIN(step_number) AS step_number
                FROM purchase_order_approvals
                WHERE purchase_order_id = ? AND status = 'pending'
                """,
                (int(po_id),),
            ).fetchone()
            if nxt and nxt["step_number"] is not None:
                nstep = int(nxt["step_number"])
                nrow = c.execute(
                    """
                    SELECT step_name, approver_user_id
                    FROM purchase_order_approvals
                    WHERE purchase_order_id = ? AND step_number = ?
                    """,
                    (int(po_id), nstep),
                ).fetchall()
                next_status = _status_for_step(str(nrow[0]["step_name"])) if nrow else PO_STATUS_SUBMITTED
                c.execute(
                    "UPDATE purchase_orders SET status = ?, current_approval_step = ? WHERE id = ?",
                    (next_status, nstep, int(po_id)),
                )
                po_number = str(po["po_number"] or "")
                total = _money(po["total"] or 0)
                supplier_name = str(po["supplier_name"] or "")
                for rr in nrow:
                    _enqueue_notifications_for_approval(c, po_id, po_number, total, supplier_name, int(rr["approver_user_id"]), str(rr["step_name"]))
                _log_status(c, po_id, actor_user_id, "approved_step", current_status, next_status, comments, meta={"step": step})
                current_status = next_status
            else:
                c.execute(
                    "UPDATE purchase_orders SET status = ?, approved_at = ?, current_approval_step = 0 WHERE id = ?",
                    (PO_STATUS_APPROVED, ts, int(po_id)),
                )
                _log_status(c, po_id, actor_user_id, "approved", current_status, PO_STATUS_APPROVED, comments, meta={"step": step})
                current_status = PO_STATUS_APPROVED
                _cancel_pending_approval_notifications(c, int(po_id))
                rid = int(po["requested_by_user_id"] or 0)
                if rid > 0:
                    _enqueue_requester_update_notification(
                        c,
                        po_id=int(po_id),
                        requester_user_id=rid,
                        status_label="fully approved — all approval steps complete",
                        comments=comments,
                    )
        else:
            _log_status(c, po_id, actor_user_id, "approved_step_partial", current_status, current_status, comments, meta={"step": step})
        c.commit()
        return current_status
    finally:
        c.close()


def reject_po(po_id: int, actor_user_id: int, comments: str, force_admin: bool = False) -> bool:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        step = int(po["current_approval_step"] or 0)
        row = _pending_approval_row_for_actor(c, int(po_id), step, int(actor_user_id), force_admin=force_admin)
        if not row:
            raise ValueError("No pending approval assigned to this user")
        ts = _now()
        c.execute(
            "UPDATE purchase_order_approvals SET status = 'rejected', rejected_at = ?, comments = ?, updated_at = ? WHERE id = ?",
            (ts, comments or "", ts, int(row["id"])),
        )
        from_status = str(po["status"] or "")
        c.execute("UPDATE purchase_orders SET status = ?, current_approval_step = 0 WHERE id = ?", (PO_STATUS_REJECTED, int(po_id)))
        _log_status(c, po_id, actor_user_id, "rejected", from_status, PO_STATUS_REJECTED, comments)
        _cancel_pending_approval_notifications(c, int(po_id))
        rid = int(po["requested_by_user_id"] or 0)
        if rid > 0:
            _enqueue_requester_update_notification(
                c,
                po_id=int(po_id),
                requester_user_id=rid,
                status_label="declined",
                comments=comments,
            )
        c.commit()
        return True
    finally:
        c.close()


def request_changes(po_id: int, actor_user_id: int, comments: str, force_admin: bool = False) -> bool:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        step = int(po["current_approval_step"] or 0)
        row = _pending_approval_row_for_actor(c, int(po_id), step, int(actor_user_id), force_admin=force_admin)
        if not row:
            raise ValueError("No pending approval assigned to this user")
        ts = _now()
        c.execute(
            "UPDATE purchase_order_approvals SET comments = ?, updated_at = ? WHERE id = ?",
            (comments or "", ts, int(row["id"])),
        )
        from_status = str(po["status"] or "")
        c.execute("UPDATE purchase_orders SET status = ?, current_approval_step = 0 WHERE id = ?", (PO_STATUS_CHANGES, int(po_id)))
        _log_status(c, po_id, actor_user_id, "changes_requested", from_status, PO_STATUS_CHANGES, comments)
        _cancel_pending_approval_notifications(c, int(po_id))
        rq = int(po["requested_by_user_id"] or 0)
        if rq > 0:
            _enqueue_requester_update_notification(
                c,
                po_id=int(po_id),
                requester_user_id=rq,
                status_label="on hold",
                comments=comments,
            )
        c.commit()
        return True
    finally:
        c.close()


def _normalize_resume_date(raw: Any) -> str:
    s = str(raw or "").strip()
    if not s:
        raise ValueError("Resume date is required")
    if len(s) >= 10:
        s = s[:10]
    try:
        datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Resume date must be YYYY-MM-DD") from None
    return s


def postpone_po(
    po_id: int,
    actor_user_id: int,
    comments: str,
    resume_at: str,
    force_admin: bool = False,
) -> bool:
    """Admin postpones approval: status postponed, snapshot step for automatic resume on resume_at (local calendar date)."""
    cmt = (comments or "").strip()
    if not cmt:
        raise ValueError("Comments are required when postponing a PO")
    resume_day = _normalize_resume_date(resume_at)
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        step = int(po["current_approval_step"] or 0)
        row = _pending_approval_row_for_actor(c, int(po_id), step, int(actor_user_id), force_admin=force_admin)
        if not row:
            raise ValueError("No pending approval assigned to this user")
        ts = _now()
        c.execute(
            "UPDATE purchase_order_approvals SET comments = ?, updated_at = ? WHERE id = ?",
            (cmt, ts, int(row["id"])),
        )
        from_status = str(po["status"] or "")
        prev_step = int(step)
        if prev_step <= 0:
            raise ValueError("Invalid approval step for postpone")
        c.execute(
            """
            UPDATE purchase_orders SET
              status = ?,
              current_approval_step = 0,
              postponed_by_user_id = ?,
              postponed_at = ?,
              resume_at = ?,
              resume_from_status = ?,
              resume_from_step = ?,
              postponed_comment = ?
            WHERE id = ?
            """,
            (
                PO_STATUS_POSTPONED,
                int(actor_user_id),
                ts,
                resume_day,
                from_status,
                prev_step,
                cmt,
                int(po_id),
            ),
        )
        _log_status(
            c,
            po_id,
            actor_user_id,
            "postponed",
            from_status,
            PO_STATUS_POSTPONED,
            cmt,
            meta={"resume_at": resume_day},
        )
        _cancel_pending_approval_notifications(c, int(po_id))
        rq = int(po["requested_by_user_id"] or 0)
        if rq > 0:
            _enqueue_requester_update_notification(
                c,
                po_id=int(po_id),
                requester_user_id=rq,
                status_label=f"postponed until {resume_day}",
                comments=cmt,
            )
        c.commit()
        return True
    finally:
        c.close()


def _resume_one_postponed_po(c: Any, po_id: int) -> bool:
    po = _po_row(c, po_id)
    if not po:
        return False
    if str(po["status"] or "").lower() != PO_STATUS_POSTPONED:
        return False
    prev_status = str(po["resume_from_status"] or "").strip()
    prev_step = int(po["resume_from_step"] or 0)
    if not prev_status or prev_step <= 0:
        return False
    ts = _now()
    c.execute(
        """
        UPDATE purchase_orders SET
          status = ?,
          current_approval_step = ?,
          postponed_by_user_id = NULL,
          postponed_at = NULL,
          resume_at = NULL,
          resume_from_status = NULL,
          resume_from_step = NULL,
          postponed_comment = NULL
        WHERE id = ?
        """,
        (prev_status, prev_step, int(po_id)),
    )
    po_number = str(po["po_number"] or "")
    total = _money(po["total"] or 0)
    supplier_name = str(po["supplier_name"] or "")
    nrows = c.execute(
        """
        SELECT approver_user_id, step_name
        FROM purchase_order_approvals
        WHERE purchase_order_id = ? AND step_number = ? AND status = 'pending'
        """,
        (int(po_id), prev_step),
    ).fetchall()
    for nr in nrows:
        _enqueue_notifications_for_approval(
            c,
            int(po_id),
            po_number,
            total,
            supplier_name,
            int(nr["approver_user_id"]),
            str(nr["step_name"] or ""),
        )
    _log_status(
        c,
        po_id,
        None,
        "postponed_resume",
        PO_STATUS_POSTPONED,
        prev_status,
        "Automatically resumed after postpone date",
        meta={"resume_at": str(po["resume_at"] or "")},
    )
    rq = int(po["requested_by_user_id"] or 0)
    if rq > 0:
        _enqueue_requester_update_notification(
            c,
            po_id=int(po_id),
            requester_user_id=rq,
            status_label="resumed — pending approval again",
            comments="This PO was postponed and has been automatically returned to the approval queue.",
        )
    return True


def resume_due_postponed_pos() -> List[int]:
    """Return PO ids that were resumed (resume_at date is today or earlier)."""
    c = _conn()
    resumed: List[int] = []
    try:
        rows = c.execute(
            """
            SELECT id FROM purchase_orders
            WHERE lower(status) = lower(?)
              AND resume_at IS NOT NULL AND btrim(resume_at::text) <> ''
              AND (substring(btrim(resume_at::text) from 1 for 10))::date <= CURRENT_DATE
            """,
            (PO_STATUS_POSTPONED,),
        ).fetchall()
        for r in rows:
            pid = int(r["id"])
            try:
                if _resume_one_postponed_po(c, pid):
                    resumed.append(pid)
                    c.commit()
            except Exception:
                c.rollback()
    finally:
        c.close()
    return resumed


def update_lifecycle_status(po_id: int, actor_user_id: int, target_status: str, comments: str = "") -> bool:
    target = str(target_status or "").strip().lower()
    if target not in {PO_STATUS_SENT, PO_STATUS_RECEIVED, PO_STATUS_PARTIAL, PO_STATUS_CLOSED, PO_STATUS_CANCELLED}:
        raise ValueError("Unsupported status transition")
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        from_status = str(po["status"] or "")
        if target == PO_STATUS_SENT and from_status != PO_STATUS_APPROVED:
            raise ValueError("PO must be approved before sending")
        if target in {PO_STATUS_RECEIVED, PO_STATUS_PARTIAL} and from_status not in {PO_STATUS_SENT, PO_STATUS_PARTIAL}:
            raise ValueError("PO must be sent before receiving")
        if target == PO_STATUS_CLOSED and from_status not in {PO_STATUS_RECEIVED, PO_STATUS_PARTIAL}:
            raise ValueError("PO can only be closed after receiving")
        ts = _now()
        closed_at = ts if target == PO_STATUS_CLOSED else None
        c.execute(
            "UPDATE purchase_orders SET status = ?, closed_at = COALESCE(?, closed_at) WHERE id = ?",
            (target, closed_at, int(po_id)),
        )
        _log_status(c, po_id, actor_user_id, "status_update", from_status, target, comments)
        c.commit()
        return True
    finally:
        c.close()


def add_attachment(po_id: int, actor_user_id: int, file_name: str, file_path: str, mime_type: str) -> int:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        if str(po["status"] or "") not in EDITABLE_STATUSES:
            raise ValueError("Attachments are locked after submission")
        cur = c.execute(
            """
            INSERT INTO purchase_order_attachments(
              purchase_order_id, file_name, file_path, mime_type, uploaded_by_user_id, created_at
            ) VALUES(?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (int(po_id), file_name, file_path, mime_type or "", int(actor_user_id), _now()),
        )
        attachment_id = int(cur.fetchone()[0])
        _log_status(c, po_id, actor_user_id, "attachment_added", str(po["status"]), str(po["status"]), meta={"file": file_name})
        c.commit()
        return attachment_id
    finally:
        c.close()


def _po_list_where(
    see_all_pos: bool,
    user_id: int,
    status: str,
    search: str,
) -> Tuple[List[str], List[Any]]:
    where: List[str] = []
    vals: List[Any] = []
    if status:
        where.append("po.status = ?")
        vals.append(status.strip().lower())
    if not see_all_pos:
        where.append("po.requested_by_user_id = ?")
        vals.append(int(user_id))
    needle = (search or "").strip().lower()
    if needle:
        where.append(
            "("
            "strpos(lower(CAST(po.id AS TEXT)), ?) > 0 OR "
            "strpos(lower(COALESCE(po.po_number,'')), ?) > 0 OR "
            "strpos(lower(COALESCE(po.status,'')), ?) > 0 OR "
            "strpos(lower(COALESCE(su.name,'')), ?) > 0 OR "
            "strpos(lower(COALESCE(po.department_name,'')), ?) > 0 OR "
            "strpos(lower(COALESCE(d.name,'')), ?) > 0 OR "
            "strpos(lower(COALESCE(u.username,'')), ?) > 0"
            ")"
        )
        vals.extend([needle] * 7)
    return where, vals


def count_pos(
    see_all_pos: bool,
    user_id: int,
    status: str = "",
    search: str = "",
) -> int:
    c = _conn()
    try:
        where, vals = _po_list_where(see_all_pos, user_id, status, search)
        sql = """
            SELECT COUNT(*) AS n
            FROM purchase_orders po
            LEFT JOIN stock_suppliers su ON su.id = po.supplier_id
            LEFT JOIN po_departments d ON d.id = po.department_id
            LEFT JOIN app_users u ON u.id = po.requested_by_user_id
        """
        if where:
            sql += " WHERE " + " AND ".join(where)
        row = c.execute(sql, tuple(vals)).fetchone()
        return int(row["n"] or 0)
    finally:
        c.close()


def list_pos(
    username: str,
    see_all_pos: bool,
    user_id: int,
    status: str = "",
    limit: int = 200,
    offset: int = 0,
    search: str = "",
) -> List[Dict[str, Any]]:
    c = _conn()
    try:
        where, vals = _po_list_where(see_all_pos, user_id, status, search)
        sql = """
            SELECT po.id, po.po_number, po.status, po.total, po.created_at, po.submitted_at, po.current_approval_step,
                   po.request_type, po.customer_id, po.payment_status, po.date_required, po.urgency,
                   po.resume_at, po.postponed_at,
                   COALESCE(su.name, po.supplier_display_name) AS supplier_name, COALESCE(po.department_name, d.name) AS department_name, u.username AS requested_by_username
            FROM purchase_orders po
            LEFT JOIN stock_suppliers su ON su.id = po.supplier_id
            LEFT JOIN po_departments d ON d.id = po.department_id
            LEFT JOIN app_users u ON u.id = po.requested_by_user_id
        """
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY po.created_at DESC LIMIT ? OFFSET ?"
        lim = max(1, min(500, int(limit)))
        off = max(0, int(offset))
        vals.append(lim)
        vals.append(off)
        rows = c.execute(sql, tuple(vals)).fetchall()
        return [
            {
                "id": int(r["id"]),
                "po_number": str(r["po_number"] or ""),
                "status": str(r["status"]),
                "total": float(_money(r["total"] or 0)),
                "created_at": str(r["created_at"] or ""),
                "submitted_at": str(r["submitted_at"] or ""),
                "current_approval_step": int(r["current_approval_step"] or 0),
                "request_type": str(r["request_type"] or "stock_item"),
                "customer_id": int(r["customer_id"]) if r["customer_id"] is not None else None,
                "payment_status": str(r["payment_status"] or ""),
                "date_required": str(r["date_required"] or ""),
                "urgency": str(r["urgency"] or "standard"),
                "supplier_name": str(r["supplier_name"] or ""),
                "department_name": str(r["department_name"] or ""),
                "requested_by_username": str(r["requested_by_username"] or ""),
                "resume_at": str(r["resume_at"] or "") if r["resume_at"] is not None else "",
                "postponed_at": str(r["postponed_at"] or "") if r["postponed_at"] is not None else "",
            }
            for r in rows
        ]
    finally:
        c.close()


def get_po(po_id: int) -> Dict[str, Any]:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        items = c.execute(
            """
            SELECT id, description, quantity, unit_price, tax_rate, tax_amount, line_total, created_at
            FROM purchase_order_items WHERE purchase_order_id = ? ORDER BY id ASC
            """,
            (int(po_id),),
        ).fetchall()
        approvals = c.execute(
            """
            SELECT pa.id, pa.step_number, pa.step_name, pa.approver_user_id, u.username AS approver_username,
                   pa.backup_approver_user_id, ub.username AS backup_approver_username,
                   pa.status, pa.approved_at, pa.rejected_at, pa.comments
            FROM purchase_order_approvals pa
            LEFT JOIN app_users u ON u.id = pa.approver_user_id
            LEFT JOIN app_users ub ON ub.id = pa.backup_approver_user_id
            WHERE pa.purchase_order_id = ?
            ORDER BY pa.step_number ASC, pa.id ASC
            """,
            (int(po_id),),
        ).fetchall()
        logs = c.execute(
            """
            SELECT lg.id, lg.action, lg.from_status, lg.to_status, lg.comments, lg.meta_json, lg.created_at,
                   u.username AS actor_username
            FROM purchase_order_status_log lg
            LEFT JOIN app_users u ON u.id = lg.actor_user_id
            WHERE lg.purchase_order_id = ?
            ORDER BY lg.created_at DESC, lg.id DESC
            """,
            (int(po_id),),
        ).fetchall()
        attachments = c.execute(
            """
            SELECT id, file_name, file_path, mime_type, created_at
            FROM purchase_order_attachments
            WHERE purchase_order_id = ?
            ORDER BY id DESC
            """,
            (int(po_id),),
        ).fetchall()
        docs = c.execute(
            """
            SELECT id, version_no, file_name, file_path, size_bytes, sha256, created_at, is_current
            FROM po_documents
            WHERE purchase_order_id = ?
            ORDER BY version_no DESC
            """,
            (int(po_id),),
        ).fetchall()
        return {
            "id": int(po["id"]),
            "po_number": str(po["po_number"] or ""),
            "status": str(po["status"]),
            "requested_by_user_id": int(po["requested_by_user_id"]),
            "requested_by_username": str(po["requested_by_username"] or ""),
            "supplier_id": int(po["supplier_id"]) if po["supplier_id"] is not None else None,
            "supplier_name": str(po["supplier_name"] or ""),
            "department_id": int(po["department_id"]) if po["department_id"] is not None else None,
            "department_name": str(po["department_name"] or ""),
            "subtotal": float(_money(po["subtotal"] or 0)),
            "tax": float(_money(po["tax"] or 0)),
            "total": float(_money(po["total"] or 0)),
            "notes": str(po["notes"] or ""),
            "category": str(po["category"] or ""),
            "request_type": str(po["request_type"] or "stock_item"),
            "customer_id": int(po["customer_id"]) if po["customer_id"] is not None else None,
            "payment_status": str(po["payment_status"] or ""),
            "date_required": str(po["date_required"] or ""),
            "urgency": str(po["urgency"] or "standard"),
            "current_approval_step": int(po["current_approval_step"] or 0),
            "pdf_path": str(po["pdf_path"] or ""),
            "created_at": str(po["created_at"] or ""),
            "submitted_at": str(po["submitted_at"] or ""),
            "approved_at": str(po["approved_at"] or ""),
            "closed_at": str(po["closed_at"] or ""),
            "postponed_by_user_id": int(po["postponed_by_user_id"]) if po.get("postponed_by_user_id") is not None else None,
            "postponed_by_username": str(po.get("postponed_by_username") or ""),
            "postponed_at": str(po.get("postponed_at") or ""),
            "resume_at": str(po.get("resume_at") or ""),
            "resume_from_status": str(po.get("resume_from_status") or ""),
            "resume_from_step": int(po["resume_from_step"]) if po.get("resume_from_step") is not None else None,
            "postponed_comment": str(po.get("postponed_comment") or ""),
            "items": [_po_item_row_for_response(r) for r in items],
            "approvals": [
                {
                    "id": int(r["id"]),
                    "step_number": int(r["step_number"]),
                    "step_name": str(r["step_name"]),
                    "approver_user_id": int(r["approver_user_id"]),
                    "approver_username": str(r["approver_username"] or ""),
                    "backup_approver_user_id": int(r["backup_approver_user_id"]) if r["backup_approver_user_id"] is not None else None,
                    "backup_approver_username": str(r["backup_approver_username"] or ""),
                    "status": str(r["status"]),
                    "approved_at": str(r["approved_at"] or ""),
                    "rejected_at": str(r["rejected_at"] or ""),
                    "comments": str(r["comments"] or ""),
                }
                for r in approvals
            ],
            "status_log": [
                {
                    "id": int(r["id"]),
                    "action": str(r["action"]),
                    "from_status": str(r["from_status"] or ""),
                    "to_status": str(r["to_status"] or ""),
                    "comments": str(r["comments"] or ""),
                    "meta_json": str(r["meta_json"] or "{}"),
                    "created_at": str(r["created_at"] or ""),
                    "actor_username": str(r["actor_username"] or ""),
                }
                for r in logs
            ],
            "attachments": [
                {
                    "id": int(r["id"]),
                    "file_name": str(r["file_name"]),
                    "file_path": str(r["file_path"]),
                    "mime_type": str(r["mime_type"] or ""),
                    "created_at": str(r["created_at"] or ""),
                }
                for r in attachments
            ],
            "documents": [
                {
                    "id": int(r["id"]),
                    "version_no": int(r["version_no"]),
                    "file_name": str(r["file_name"]),
                    "file_path": str(r["file_path"]),
                    "size_bytes": int(r["size_bytes"] or 0),
                    "sha256": str(r["sha256"] or ""),
                    "created_at": str(r["created_at"] or ""),
                    "is_current": int(r["is_current"] or 0) == 1,
                }
                for r in docs
            ],
        }
    finally:
        c.close()


def next_document_version(po_id: int) -> int:
    c = _conn()
    try:
        row = c.execute(
            "SELECT COALESCE(MAX(version_no), 0) AS n FROM po_documents WHERE purchase_order_id = ?",
            (int(po_id),),
        ).fetchone()
        return int(row["n"] or 0) + 1
    finally:
        c.close()


def save_po_pdf(po_id: int, actor_user_id: int, file_name: str, file_path: str, data_bytes: bytes) -> int:
    version = next_document_version(po_id)
    digest = sha256(data_bytes).hexdigest()
    size_bytes = len(data_bytes or b"")
    c = _conn()
    try:
        c.execute("UPDATE po_documents SET is_current = 0 WHERE purchase_order_id = ?", (int(po_id),))
        cur = c.execute(
            """
            INSERT INTO po_documents(
              purchase_order_id, version_no, file_name, file_path, size_bytes, sha256, created_by_user_id, created_at, is_current
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 1)
            RETURNING id
            """,
            (
                int(po_id),
                int(version),
                file_name,
                file_path,
                int(size_bytes),
                digest,
                int(actor_user_id),
                _now(),
            ),
        )
        doc_id = int(cur.fetchone()[0])
        c.execute("UPDATE purchase_orders SET pdf_path = ? WHERE id = ?", (file_path, int(po_id)))
        _log_status(c, po_id, actor_user_id, "pdf_generated", None, None, meta={"version": version, "path": file_path})
        c.commit()
        return doc_id
    finally:
        c.close()


def fetch_due_notifications(limit: int = 100) -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute(
            """
            SELECT n.id, n.user_id, n.purchase_order_id, n.event_type, n.title, n.message, n.action_url, n.channel, n.schedule_at, u.username
            FROM notifications n
            LEFT JOIN app_users u ON u.id = n.user_id
            WHERE n.state = 'pending' AND n.schedule_at <= ?
            ORDER BY n.schedule_at ASC, n.id ASC
            LIMIT ?
            """,
            (_now(), max(1, min(500, int(limit)))),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "user_id": int(r["user_id"]),
                "purchase_order_id": int(r["purchase_order_id"]) if r["purchase_order_id"] is not None else None,
                "event_type": str(r["event_type"]),
                "title": str(r["title"]),
                "message": str(r["message"]),
                "action_url": str(r["action_url"] or ""),
                "channel": str(r["channel"]),
                "schedule_at": str(r["schedule_at"]),
                "username": str(r["username"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def mark_notification_state(notification_id: int, status: str, provider_message_id: str = "", response_body: str = "") -> None:
    st = status.strip().lower()
    if st not in {"sent", "delivered", "read", "failed"}:
        st = "failed"
    c = _conn()
    try:
        ts = _now()
        sent_at = ts if st in {"sent", "delivered", "read"} else None
        delivered_at = ts if st in {"delivered", "read"} else None
        read_at = ts if st == "read" else None
        failed_at = ts if st == "failed" else None
        c.execute(
            """
            UPDATE notifications
            SET state = ?, sent_at = COALESCE(?, sent_at), delivered_at = COALESCE(?, delivered_at),
                read_at = COALESCE(?, read_at), failed_at = COALESCE(?, failed_at)
            WHERE id = ?
            """,
            (st, sent_at, delivered_at, read_at, failed_at, int(notification_id)),
        )
        row = c.execute(
            "SELECT user_id, purchase_order_id, channel FROM notifications WHERE id = ?",
            (int(notification_id),),
        ).fetchone()
        if row:
            c.execute(
                """
                INSERT INTO notification_logs(
                  notification_id, user_id, purchase_order_id, channel, status, provider_message_id, response_body,
                  sent_at, delivered_at, read_at, failed_at, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(notification_id),
                    int(row["user_id"]),
                    int(row["purchase_order_id"]) if row["purchase_order_id"] is not None else None,
                    str(row["channel"]),
                    st,
                    provider_message_id or "",
                    response_body or "",
                    sent_at,
                    delivered_at,
                    read_at,
                    failed_at,
                    ts,
                ),
            )
        c.commit()
    finally:
        c.close()


def sync_user_notification_contact(user_id: int, email: str = "", mobile: str = "") -> bool:
    c = _conn()
    try:
        ts = _now()
        c.execute(
            """
            INSERT INTO user_notification_preferences(
              user_id, notify_app, notify_email, notify_whatsapp, email, whatsapp_number, updated_at
            ) VALUES(?, 1, 1, 0, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              email = excluded.email,
              whatsapp_number = excluded.whatsapp_number,
              updated_at = excluded.updated_at
            """,
            (int(user_id), (email or "").strip(), (mobile or "").strip(), ts),
        )
        c.commit()
        return True
    finally:
        c.close()


def delete_po(po_id: int, actor_user_id: int, force: bool = False) -> bool:
    c = _conn()
    try:
        po = _po_row(c, po_id)
        if not po:
            raise ValueError("PO not found")
        status = str(po["status"] or "")
        if not force and status not in DELETABLE_STATUSES:
            raise ValueError(f"PO cannot be deleted in status '{status}'")
        # Clean up files best-effort.
        paths = c.execute(
            "SELECT file_path FROM po_documents WHERE purchase_order_id = ? UNION ALL SELECT file_path FROM purchase_order_attachments WHERE purchase_order_id = ?",
            (int(po_id), int(po_id)),
        ).fetchall()
        c.execute("DELETE FROM purchase_orders WHERE id = ?", (int(po_id),))
        c.commit()
        for p in paths:
            try:
                fp = str(p["file_path"] or "")
                if fp and os.path.isfile(fp):
                    os.remove(fp)
            except Exception:
                pass
        return True
    finally:
        c.close()


def _load_notification_timing(c) -> Tuple[int, int, int]:
    rows = c.execute(
        "SELECT k, v FROM po_notification_settings WHERE k IN ('reminder_4h_sec','escalation_24h_sec','backup_48h_sec')"
    ).fetchall()
    d = {str(r["k"]): str(r["v"]) for r in rows}
    def _ival(k: str, fallback: int) -> int:
        try:
            v = int(d.get(k, str(fallback)))
            return max(60, v)
        except Exception:
            return int(fallback)
    return (
        _ival("reminder_4h_sec", REMINDER_4H),
        _ival("escalation_24h_sec", REMINDER_24H),
        _ival("backup_48h_sec", REMINDER_48H),
    )


def get_notification_settings() -> Dict[str, Any]:
    c = _conn()
    try:
        rem4, rem24, rem48 = _load_notification_timing(c)
        return {
            "reminder_4h_sec": int(rem4),
            "escalation_24h_sec": int(rem24),
            "backup_48h_sec": int(rem48),
        }
    finally:
        c.close()


def set_notification_settings(reminder_4h_sec: int, escalation_24h_sec: int, backup_48h_sec: int) -> bool:
    c = _conn()
    try:
        ts = _now()
        for k, v in (
            ("reminder_4h_sec", max(60, int(reminder_4h_sec))),
            ("escalation_24h_sec", max(60, int(escalation_24h_sec))),
            ("backup_48h_sec", max(60, int(backup_48h_sec))),
        ):
            c.execute(
                """
                INSERT INTO po_notification_settings(k, v, updated_at) VALUES(?, ?, ?)
                ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at
                """,
                (k, str(v), ts),
            )
        c.commit()
        return True
    finally:
        c.close()


def list_user_notification_preferences() -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rows = c.execute(
            """
            SELECT u.id AS user_id, u.username, u.email AS user_email, u.mobile AS user_mobile,
                   COALESCE(p.notify_app, 1) AS notify_app,
                   COALESCE(p.notify_email, 1) AS notify_email,
                   COALESCE(p.notify_whatsapp, 0) AS notify_whatsapp,
                   COALESCE(p.email, u.email, '') AS email,
                   COALESCE(p.whatsapp_number, u.mobile, '') AS whatsapp_number
            FROM app_users u
            LEFT JOIN user_notification_preferences p ON p.user_id = u.id
            ORDER BY u.username COLLATE NOCASE ASC
            """
        ).fetchall()
        return [
            {
                "user_id": int(r["user_id"]),
                "username": str(r["username"] or ""),
                "notify_app": int(r["notify_app"] or 0) == 1,
                "notify_email": int(r["notify_email"] or 0) == 1,
                "notify_whatsapp": int(r["notify_whatsapp"] or 0) == 1,
                "email": str(r["email"] or ""),
                "whatsapp_number": str(r["whatsapp_number"] or ""),
                "user_email": str(r["user_email"] or ""),
                "user_mobile": str(r["user_mobile"] or ""),
            }
            for r in rows
        ]
    finally:
        c.close()


def set_user_notification_preference(
    user_id: int,
    notify_app: bool,
    notify_email: bool,
    notify_whatsapp: bool,
    email: str,
    whatsapp_number: str,
) -> bool:
    c = _conn()
    try:
        ts = _now()
        c.execute(
            """
            INSERT INTO user_notification_preferences(
              user_id, notify_app, notify_email, notify_whatsapp, email, whatsapp_number, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              notify_app = excluded.notify_app,
              notify_email = excluded.notify_email,
              notify_whatsapp = excluded.notify_whatsapp,
              email = excluded.email,
              whatsapp_number = excluded.whatsapp_number,
              updated_at = excluded.updated_at
            """,
            (
                int(user_id),
                1 if notify_app else 0,
                1 if notify_email else 0,
                1 if notify_whatsapp else 0,
                (email or "").strip(),
                (whatsapp_number or "").strip(),
                ts,
            ),
        )
        c.commit()
        return True
    finally:
        c.close()


def enqueue_test_notification(user_id: int, channel: str, actor_username: str = "admin") -> Tuple[int, Dict[str, str]]:
    ch = (channel or "app").strip().lower()
    if ch not in {"app", "email", "whatsapp"}:
        ch = "app"
    if ch == "email":
        title, message, action_url = _approval_required_notification_content(
            0,
            "PO-DEV-SAMPLE",
            Decimal("12450.00"),
            "Sample Supplier Ltd",
            "Manager",
        )
        event_type = "test_po_approval"
    else:
        title = "PO Test Notification"
        message = f"Test notification from PO settings by {actor_username}"
        action_url = "/purchase-orders"
        event_type = "test"
    c = _conn()
    try:
        cur = c.execute(
            """
            INSERT INTO notifications(
              user_id, purchase_order_id, event_type, title, message, action_url, channel, schedule_at, state, created_at
            ) VALUES(?, NULL, ?, ?, ?, ?, ?, ?, 'pending', ?)
            RETURNING id
            """,
            (
                int(user_id),
                event_type,
                title,
                message,
                action_url,
                ch,
                _now(),
                _now(),
            ),
        )
        nid = int(cur.fetchone()[0])
        c.commit()
        return nid, {"title": title, "message": message, "action_url": action_url}
    finally:
        c.close()
