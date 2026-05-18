import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
import json

import db_runtime


PRE_ALLOCATION_HOLD_DAYS = 14


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _expires_after_days(days: int) -> str:
    return (datetime.utcnow() + timedelta(days=max(1, int(days)))).isoformat(timespec="seconds") + "Z"


def _parse_utc_iso(ts: str) -> Optional[datetime]:
    s = str(ts or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).replace(tzinfo=None)
    except Exception:
        return None


def _conn() -> sqlite3.Connection:
    return db_runtime.get_conn("stock")


def _is_unique_violation(exc: BaseException) -> bool:
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    name = type(exc).__name__
    if name in {"UniqueViolation", "UniqueViolationError", "IntegrityError"}:
        return True
    msg = str(exc).lower()
    return "unique" in msg or "duplicate key" in msg


def _ensure_stock_vendor_unique_includes_misc(conn: Any) -> None:
    """Postgres: drop legacy UNIQUE(supplier_id, name) so misc + serialized can share a vendor name."""
    if not db_runtime.is_postgres():
        return
    conn.execute(
        "ALTER TABLE stock_supplier_vendors DROP CONSTRAINT IF EXISTS stock_supplier_vendors_supplier_id_name_key"
    )
    row = conn.execute(
        """
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        WHERE t.relname = 'stock_supplier_vendors'
          AND c.conname = 'stock_supplier_vendors_supplier_id_name_is_misc_key'
        LIMIT 1
        """
    ).fetchone()
    if not row:
        conn.execute(
            """
            ALTER TABLE stock_supplier_vendors
            ADD CONSTRAINT stock_supplier_vendors_supplier_id_name_is_misc_key
            UNIQUE (supplier_id, name, is_misc)
            """
        )


def _ipam_conn() -> sqlite3.Connection:
    return db_runtime.get_conn("ipam")


def list_ipam_locations() -> List[Dict[str, Any]]:
    conn = _ipam_conn()
    try:
        rows = conn.execute("SELECT id, name FROM ipam_locations ORDER BY name ASC").fetchall()
        return [{"id": int(r["id"]), "name": str(r["name"] or "")} for r in rows]
    finally:
        conn.close()


def _resolve_assignment_target(
    assignment_target: str,
    customer_id: Optional[int] = None,
    customer_name: str = "",
    customer_address: str = "",
    location_id: Optional[int] = None,
) -> Dict[str, Any]:
    tgt = str(assignment_target or "customer").strip().lower()
    if tgt not in ("customer", "high_site", "pre_allocate"):
        raise ValueError("Invalid assignment target")
    if tgt in ("customer", "pre_allocate"):
        cid = int(customer_id or 0)
        cname = str(customer_name or "").strip()
        caddr = str(customer_address or "").strip()
        if cid <= 0:
            raise ValueError("Invalid customer id")
        if not cname:
            raise ValueError("Customer name required")
        return {
            "target": tgt,
            "customer_id": cid,
            "customer_name": cname,
            "customer_address": caddr,
            "location_id": None,
            "location_name": "",
        }
    lid = int(location_id or 0)
    if lid <= 0:
        raise ValueError("High Site location required")
    conn = _ipam_conn()
    try:
        row = conn.execute("SELECT id, name FROM ipam_locations WHERE id = ?", (lid,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise ValueError("High Site location not found")
    lname = str(row["name"] or "").strip()
    if not lname:
        raise ValueError("High Site location not found")
    return {
        "target": "high_site",
        "customer_id": None,
        "customer_name": lname,
        "customer_address": "",
        "location_id": int(row["id"]),
        "location_name": lname,
    }


def _iso_to_day(ts: str) -> str:
    s = str(ts or "").strip()
    return s[:10] if s else ""


def _day_in_range(day: str, start_day: str, end_day: str) -> bool:
    if not day:
        return False
    return start_day <= day <= end_day


def init_db() -> None:
    conn = _conn()
    try:
        if db_runtime.is_postgres():
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_suppliers (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_supplier_vendors (
                    id BIGSERIAL PRIMARY KEY,
                    supplier_id BIGINT NOT NULL REFERENCES stock_suppliers(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    is_misc INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE (supplier_id, name, is_misc)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_vendor_products (
                    id BIGSERIAL PRIMARY KEY,
                    vendor_id BIGINT NOT NULL REFERENCES stock_supplier_vendors(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (vendor_id, name)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_product_items (
                    id BIGSERIAL PRIMARY KEY,
                    product_id BIGINT NOT NULL REFERENCES stock_vendor_products(id) ON DELETE CASCADE,
                    serial_number TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    value_ex_vat DOUBLE PRECISION,
                    batch_invoice_number TEXT,
                    date_in_stock TEXT,
                    date_issued TEXT,
                    quotation_no TEXT,
                    invoice_no TEXT,
                    client_customer_id BIGINT,
                    client_name TEXT,
                    address TEXT,
                    technician_user_ids_json TEXT,
                    technician_names_json TEXT,
                    comment TEXT,
                    lifecycle_status TEXT NOT NULL DEFAULT 'new',
                    assigned_customer_id BIGINT,
                    assigned_customer_name TEXT,
                    assigned_customer_address TEXT,
                    assigned_customer_invoice_number TEXT,
                    assignment_target TEXT NOT NULL DEFAULT 'customer',
                    assigned_location_id BIGINT,
                    assigned_location_name TEXT,
                    assigned_at TEXT,
                    returned_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_item_lifecycle_log (
                    id BIGSERIAL PRIMARY KEY,
                    item_id BIGINT NOT NULL REFERENCES stock_product_items(id) ON DELETE CASCADE,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT,
                    customer_id BIGINT,
                    customer_name TEXT,
                    customer_address TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_scrapped_log (
                    id BIGSERIAL PRIMARY KEY,
                    item_id BIGINT NOT NULL,
                    serial_number TEXT NOT NULL,
                    product_name TEXT NOT NULL,
                    vendor_name TEXT NOT NULL,
                    customer_id BIGINT,
                    customer_name TEXT,
                    customer_address TEXT,
                    reason TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_misc_product_lots (
                    id BIGSERIAL PRIMARY KEY,
                    product_id BIGINT NOT NULL REFERENCES stock_vendor_products(id) ON DELETE CASCADE,
                    invoice_number TEXT,
                    quantity_in DOUBLE PRECISION NOT NULL,
                    quantity_remaining DOUBLE PRECISION NOT NULL,
                    date_in_stock TEXT,
                    value_ex_vat DOUBLE PRECISION,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_misc_item_assignments (
                    id BIGSERIAL PRIMARY KEY,
                    product_name TEXT NOT NULL,
                    quantity DOUBLE PRECISION NOT NULL,
                    signed_out_at TEXT NOT NULL,
                    customer_id BIGINT,
                    customer_name TEXT,
                    customer_address TEXT,
                    assignment_target TEXT NOT NULL DEFAULT 'customer',
                    assigned_location_id BIGINT,
                    assigned_location_name TEXT,
                    customer_invoice_number TEXT,
                    comment TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_misc_item_assignment_lot_usage (
                    id BIGSERIAL PRIMARY KEY,
                    assignment_id BIGINT NOT NULL REFERENCES stock_misc_item_assignments(id) ON DELETE CASCADE,
                    lot_id BIGINT NOT NULL REFERENCES stock_misc_product_lots(id) ON DELETE RESTRICT,
                    invoice_number TEXT,
                    quantity_used DOUBLE PRECISION NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            for stmt in (
                "ALTER TABLE stock_misc_product_lots ADD COLUMN IF NOT EXISTS value_ex_vat DOUBLE PRECISION",
                "ALTER TABLE stock_supplier_vendors ADD COLUMN IF NOT EXISTS is_misc INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS value_ex_vat DOUBLE PRECISION",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS batch_invoice_number TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS date_in_stock TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS date_issued TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS quotation_no TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS invoice_no TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS client_customer_id BIGINT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS client_name TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS address TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS technician_user_ids_json TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS technician_names_json TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS comment TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'new'",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_customer_id BIGINT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_customer_name TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_customer_address TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_customer_invoice_number TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assignment_target TEXT NOT NULL DEFAULT 'customer'",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_location_id BIGINT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_location_name TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS assigned_at TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS returned_at TEXT",
                "ALTER TABLE stock_product_items ADD COLUMN IF NOT EXISTS pre_allocated_expires_at TEXT",
            ):
                conn.execute(stmt)
            for stmt in (
                "ALTER TABLE stock_misc_item_assignments ADD COLUMN IF NOT EXISTS assignment_target TEXT NOT NULL DEFAULT 'customer'",
                "ALTER TABLE stock_misc_item_assignments ADD COLUMN IF NOT EXISTS assigned_location_id BIGINT",
                "ALTER TABLE stock_misc_item_assignments ADD COLUMN IF NOT EXISTS assigned_location_name TEXT",
            ):
                conn.execute(stmt)
            _ensure_stock_vendor_unique_includes_misc(conn)
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_suppliers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_supplier_vendors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    supplier_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    is_misc INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE (supplier_id, name, is_misc),
                    FOREIGN KEY (supplier_id) REFERENCES stock_suppliers(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_vendor_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vendor_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (vendor_id, name),
                    FOREIGN KEY (vendor_id) REFERENCES stock_supplier_vendors(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_product_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    serial_number TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    value_ex_vat REAL,
                    batch_invoice_number TEXT,
                    date_in_stock TEXT,
                    date_issued TEXT,
                    quotation_no TEXT,
                    invoice_no TEXT,
                    client_customer_id INTEGER,
                    client_name TEXT,
                    address TEXT,
                    technician_user_ids_json TEXT,
                    technician_names_json TEXT,
                    comment TEXT,
                    lifecycle_status TEXT NOT NULL DEFAULT 'new',
                    assigned_customer_id INTEGER,
                    assigned_customer_name TEXT,
                    assigned_customer_address TEXT,
                    assigned_customer_invoice_number TEXT,
                    assignment_target TEXT NOT NULL DEFAULT 'customer',
                    assigned_location_id INTEGER,
                    assigned_location_name TEXT,
                    assigned_at TEXT,
                    returned_at TEXT,
                    FOREIGN KEY (product_id) REFERENCES stock_vendor_products(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_item_lifecycle_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT,
                    customer_id INTEGER,
                    customer_name TEXT,
                    customer_address TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (item_id) REFERENCES stock_product_items(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_scrapped_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    serial_number TEXT NOT NULL,
                    product_name TEXT NOT NULL,
                    vendor_name TEXT NOT NULL,
                    customer_id INTEGER,
                    customer_name TEXT,
                    customer_address TEXT,
                    reason TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_misc_product_lots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    invoice_number TEXT,
                    quantity_in REAL NOT NULL,
                    quantity_remaining REAL NOT NULL,
                    date_in_stock TEXT,
                    value_ex_vat REAL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES stock_vendor_products(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_misc_item_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_name TEXT NOT NULL,
                    quantity REAL NOT NULL,
                    signed_out_at TEXT NOT NULL,
                    customer_id INTEGER,
                    customer_name TEXT,
                    customer_address TEXT,
                    assignment_target TEXT NOT NULL DEFAULT 'customer',
                    assigned_location_id INTEGER,
                    assigned_location_name TEXT,
                    customer_invoice_number TEXT,
                    comment TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stock_misc_item_assignment_lot_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assignment_id INTEGER NOT NULL,
                    lot_id INTEGER NOT NULL,
                    invoice_number TEXT,
                    quantity_used REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (assignment_id) REFERENCES stock_misc_item_assignments(id) ON DELETE CASCADE,
                    FOREIGN KEY (lot_id) REFERENCES stock_misc_product_lots(id)
                )
                """
            )
            cols = conn.execute("PRAGMA table_info(stock_product_items)").fetchall()
            existing = {str(r["name"]) for r in cols}
            vcols = conn.execute("PRAGMA table_info(stock_supplier_vendors)").fetchall()
            vexisting = {str(r["name"]) for r in vcols}
            if "is_misc" not in vexisting:
                conn.execute("ALTER TABLE stock_supplier_vendors ADD COLUMN is_misc INTEGER NOT NULL DEFAULT 0")
            for coldef in (
                ("value_ex_vat", "REAL"),
                ("batch_invoice_number", "TEXT"),
                ("date_in_stock", "TEXT"),
                ("date_issued", "TEXT"),
                ("quotation_no", "TEXT"),
                ("invoice_no", "TEXT"),
                ("client_customer_id", "INTEGER"),
                ("client_name", "TEXT"),
                ("address", "TEXT"),
                ("technician_user_ids_json", "TEXT"),
                ("technician_names_json", "TEXT"),
                ("comment", "TEXT"),
                ("lifecycle_status", "TEXT NOT NULL DEFAULT 'new'"),
                ("assigned_customer_id", "INTEGER"),
                ("assigned_customer_name", "TEXT"),
                ("assigned_customer_address", "TEXT"),
                ("assigned_customer_invoice_number", "TEXT"),
                ("assignment_target", "TEXT NOT NULL DEFAULT 'customer'"),
                ("assigned_location_id", "INTEGER"),
                ("assigned_location_name", "TEXT"),
                ("assigned_at", "TEXT"),
                ("returned_at", "TEXT"),
                ("pre_allocated_expires_at", "TEXT"),
            ):
                if coldef[0] not in existing:
                    conn.execute(f"ALTER TABLE stock_product_items ADD COLUMN {coldef[0]} {coldef[1]}")
            misc_assign_cols = conn.execute("PRAGMA table_info(stock_misc_item_assignments)").fetchall()
            misc_assign_existing = {str(r["name"]) for r in misc_assign_cols}
            for coldef in (
                ("assignment_target", "TEXT NOT NULL DEFAULT 'customer'"),
                ("assigned_location_id", "INTEGER"),
                ("assigned_location_name", "TEXT"),
            ):
                if coldef[0] not in misc_assign_existing:
                    conn.execute(f"ALTER TABLE stock_misc_item_assignments ADD COLUMN {coldef[0]} {coldef[1]}")
            misc_cols = conn.execute("PRAGMA table_info(stock_misc_product_lots)").fetchall()
            misc_existing = {str(r["name"]) for r in misc_cols}
            if "value_ex_vat" not in misc_existing:
                conn.execute("ALTER TABLE stock_misc_product_lots ADD COLUMN value_ex_vat REAL")
        conn.commit()
        n = int(conn.execute("SELECT COUNT(*) FROM stock_suppliers").fetchone()[0])
        if n == 0:
            ts = _now()
            conn.execute("INSERT INTO stock_suppliers(name, created_at) VALUES(?, ?)", ("Scoop", ts))
            conn.execute("INSERT INTO stock_suppliers(name, created_at) VALUES(?, ?)", ("Miro", ts))
            conn.commit()
        # Ensure default vendors exist under each supplier.
        supplier_rows = conn.execute("SELECT id FROM stock_suppliers").fetchall()
        for row in supplier_rows:
            sid = int(row["id"])
            for vendor_name in ("Cambium", "Cudy"):
                try:
                    conn.execute(
                        "INSERT INTO stock_supplier_vendors(supplier_id, name, created_at) VALUES(?, ?, ?)",
                        (sid, vendor_name, _now()),
                    )
                except Exception:
                    # Ignore duplicates / existing seed rows.
                    pass
        conn.commit()
    finally:
        conn.close()


def _expire_due_pre_allocations(conn: sqlite3.Connection) -> int:
    now = datetime.utcnow()
    rows = conn.execute(
        """
        SELECT id, assigned_customer_id, assigned_customer_name, assigned_customer_address, pre_allocated_expires_at
        FROM stock_product_items
        WHERE COALESCE(lifecycle_status, '') = 'pre_allocated'
          AND COALESCE(pre_allocated_expires_at, '') <> ''
        """
    ).fetchall()
    expired = 0
    ts = _now()
    for row in rows:
        expires_at = _parse_utc_iso(str(row["pre_allocated_expires_at"] or ""))
        if expires_at is None or expires_at > now:
            continue
        iid = int(row["id"])
        conn.execute(
            """
            UPDATE stock_product_items
            SET lifecycle_status = 'new',
                assigned_customer_id = NULL,
                assigned_customer_name = NULL,
                assigned_customer_address = NULL,
                assigned_customer_invoice_number = NULL,
                assignment_target = 'customer',
                assigned_location_id = NULL,
                assigned_location_name = NULL,
                assigned_at = NULL,
                pre_allocated_expires_at = NULL
            WHERE id = ?
            """,
            (iid,),
        )
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, 'pre_allocation_expired', 'pre_allocated', 'new', ?, ?, ?, ?)
            """,
            (
                iid,
                int(row["assigned_customer_id"]) if row["assigned_customer_id"] is not None else None,
                str(row["assigned_customer_name"] or ""),
                str(row["assigned_customer_address"] or ""),
                ts,
            ),
        )
        expired += 1
    return expired


def list_suppliers() -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        _expire_due_pre_allocations(conn)
        conn.commit()
        suppliers = conn.execute(
            "SELECT id, name, created_at FROM stock_suppliers ORDER BY name COLLATE NOCASE ASC"
        ).fetchall()
        vendor_rows = conn.execute(
            """
            SELECT id, supplier_id, name, is_misc, created_at
            FROM stock_supplier_vendors
            ORDER BY name COLLATE NOCASE ASC
            """
        ).fetchall()
        product_rows = conn.execute(
            """
            SELECT id, vendor_id, name, created_at
            FROM stock_vendor_products
            ORDER BY name COLLATE NOCASE ASC
            """
        ).fetchall()
        item_rows = conn.execute(
            """
            SELECT
                id, product_id, serial_number, created_at,
                value_ex_vat,
                batch_invoice_number, date_in_stock, date_issued, quotation_no, invoice_no,
                client_customer_id, client_name, address,
                technician_user_ids_json, technician_names_json, comment,
                lifecycle_status,
                assigned_customer_id, assigned_customer_name, assigned_customer_address,
                assigned_customer_invoice_number, assigned_at, pre_allocated_expires_at
            FROM stock_product_items
            WHERE COALESCE(lifecycle_status, 'new') <> 'assigned'
            ORDER BY created_at DESC
            """
        ).fetchall()
        item_map: Dict[int, List[Dict[str, Any]]] = {}
        for ir in item_rows:
            pid = int(ir["product_id"])
            item_map.setdefault(pid, []).append(
                {
                    "id": int(ir["id"]),
                    "serial_number": str(ir["serial_number"]),
                    "created_at": str(ir["created_at"]),
                    "value_ex_vat": float(ir["value_ex_vat"]) if ir["value_ex_vat"] is not None else None,
                    "batch_invoice_number": str(ir["batch_invoice_number"] or ""),
                    "date_in_stock": str(ir["date_in_stock"] or ""),
                    "date_issued": str(ir["date_issued"] or ""),
                    "quotation_no": str(ir["quotation_no"] or ""),
                    "invoice_no": str(ir["invoice_no"] or ""),
                    "client_customer_id": int(ir["client_customer_id"]) if ir["client_customer_id"] is not None else None,
                    "client_name": str(ir["client_name"] or ""),
                    "address": str(ir["address"] or ""),
                    "technician_user_ids": json.loads(str(ir["technician_user_ids_json"] or "[]")),
                    "technician_names": json.loads(str(ir["technician_names_json"] or "[]")),
                    "comment": str(ir["comment"] or ""),
                    "lifecycle_status": str(ir["lifecycle_status"] or "new"),
                    "pre_allocated_customer_id": int(ir["assigned_customer_id"]) if ir["assigned_customer_id"] is not None else None,
                    "pre_allocated_customer_name": str(ir["assigned_customer_name"] or ""),
                    "pre_allocated_customer_address": str(ir["assigned_customer_address"] or ""),
                    "pre_allocated_customer_invoice_number": str(ir["assigned_customer_invoice_number"] or ""),
                    "pre_allocated_at": str(ir["assigned_at"] or ""),
                    "pre_allocated_expires_at": str(ir["pre_allocated_expires_at"] or ""),
                }
            )
        misc_lot_rows = conn.execute(
            """
            SELECT id, product_id, invoice_number, quantity_in, quantity_remaining, date_in_stock, value_ex_vat, created_at
            FROM stock_misc_product_lots
            WHERE quantity_remaining > 0
            ORDER BY created_at ASC, id ASC
            """
        ).fetchall()
        misc_lot_map: Dict[int, List[Dict[str, Any]]] = {}
        for lr in misc_lot_rows:
            pid = int(lr["product_id"])
            misc_lot_map.setdefault(pid, []).append(
                {
                    "id": int(lr["id"]),
                    "invoice_number": str(lr["invoice_number"] or ""),
                    "quantity_in": float(lr["quantity_in"] or 0),
                    "quantity_remaining": float(lr["quantity_remaining"] or 0),
                    "date_in_stock": str(lr["date_in_stock"] or ""),
                    "value_ex_vat": float(lr["value_ex_vat"]) if lr["value_ex_vat"] is not None else None,
                    "created_at": str(lr["created_at"] or ""),
                }
            )
        vendor_has_misc_lots: Dict[int, bool] = {}
        product_map: Dict[int, List[Dict[str, Any]]] = {}
        for pr in product_rows:
            vid = int(pr["vendor_id"])
            pid = int(pr["id"])
            items = item_map.get(pid, [])
            if pid in misc_lot_map:
                vendor_has_misc_lots[vid] = True
            product_map.setdefault(vid, []).append(
                {
                    "id": pid,
                    "name": str(pr["name"]),
                    "created_at": str(pr["created_at"]),
                    "is_misc": False,
                    "stock_level": len(items),
                    "quantity_available": None,
                    "lots": [],
                    "items": items,
                }
            )
        vendor_map: Dict[int, List[Dict[str, Any]]] = {}
        vendor_misc_map: Dict[int, bool] = {}
        for vr in vendor_rows:
            sid = int(vr["supplier_id"])
            vid = int(vr["id"])
            vendor_misc_map[vid] = bool(int(vr["is_misc"] or 0))
            vendor_map.setdefault(sid, []).append(
                {
                    "id": vid,
                    "name": str(vr["name"]),
                    "is_misc": bool(int(vr["is_misc"] or 0)),
                    "created_at": str(vr["created_at"]),
                    "products": product_map.get(vid, []),
                }
            )
        for sid, vendors in vendor_map.items():
            for v in vendors:
                vid = int(v.get("id") or 0)
                is_misc_vendor = bool(v.get("is_misc")) or bool(vendor_has_misc_lots.get(vid))
                if not is_misc_vendor:
                    continue
                v["is_misc"] = True
                for p in v.get("products", []):
                    pid = int(p.get("id") or 0)
                    lots = misc_lot_map.get(pid, [])
                    p["is_misc"] = True
                    p["lots"] = lots
                    p["items"] = []
                    p["quantity_available"] = round(sum(float(x.get("quantity_remaining") or 0) for x in lots), 4)
                    p["stock_level"] = int(p["quantity_available"])
        out: List[Dict[str, Any]] = []
        for r in suppliers:
            sid = int(r["id"])
            out.append(
                {
                    "id": sid,
                    "name": str(r["name"]),
                    "created_at": str(r["created_at"]),
                    "vendors": vendor_map.get(sid, []),
                }
            )
        return out
    finally:
        conn.close()


def add_supplier(name: str) -> int:
    nm = (name or "").strip()
    if len(nm) < 2 or len(nm) > 120:
        raise ValueError("Supplier name must be 2-120 characters")
    conn = _conn()
    try:
        ts = _now()
        conn.execute(
            "INSERT INTO stock_suppliers(name, created_at) VALUES(?, ?)",
            (nm, ts),
        )
        conn.commit()
        row = conn.execute("SELECT id FROM stock_suppliers WHERE name = ?", (nm,)).fetchone()
        return int(row["id"]) if row else 0
    except sqlite3.IntegrityError:
        raise ValueError("Supplier already exists") from None
    finally:
        conn.close()


def rename_supplier(supplier_id: int, name: str) -> bool:
    sid = int(supplier_id)
    nm = (name or "").strip()
    if sid <= 0:
        raise ValueError("Invalid supplier id")
    if len(nm) < 2 or len(nm) > 120:
        raise ValueError("Supplier name must be 2-120 characters")
    conn = _conn()
    try:
        cur = conn.execute("UPDATE stock_suppliers SET name = ? WHERE id = ?", (nm, sid))
        conn.commit()
        if int(cur.rowcount or 0) == 0:
            raise ValueError("Supplier not found")
        return True
    except sqlite3.IntegrityError:
        raise ValueError("Supplier already exists") from None
    finally:
        conn.close()


def add_vendor(supplier_id: int, name: str, is_misc: bool = False) -> int:
    sid = int(supplier_id)
    nm = (name or "").strip()
    if sid <= 0:
        raise ValueError("Invalid supplier id")
    if len(nm) < 2 or len(nm) > 120:
        raise ValueError("Vendor name must be 2-120 characters")
    conn = _conn()
    try:
        chk = conn.execute("SELECT id FROM stock_suppliers WHERE id = ?", (sid,)).fetchone()
        if not chk:
            raise ValueError("Supplier not found")
        ts = _now()
        conn.execute(
            "INSERT INTO stock_supplier_vendors(supplier_id, name, is_misc, created_at) VALUES(?, ?, ?, ?)",
            (sid, nm, 1 if is_misc else 0, ts),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id FROM stock_supplier_vendors WHERE supplier_id = ? AND name = ? AND is_misc = ?",
            (sid, nm, 1 if is_misc else 0),
        ).fetchone()
        return int(row["id"]) if row else 0
    except Exception as e:
        if _is_unique_violation(e):
            kind = "miscellaneous" if is_misc else "serialized"
            raise ValueError(
                f"A {kind} vendor named '{nm}' already exists for this supplier"
            ) from None
        raise
    finally:
        conn.close()


def rename_vendor(vendor_id: int, name: str) -> bool:
    vid = int(vendor_id)
    nm = (name or "").strip()
    if vid <= 0:
        raise ValueError("Invalid vendor id")
    if len(nm) < 2 or len(nm) > 120:
        raise ValueError("Vendor name must be 2-120 characters")
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT supplier_id, is_misc FROM stock_supplier_vendors WHERE id = ?",
            (vid,),
        ).fetchone()
        if not row:
            raise ValueError("Vendor not found")
        sid = int(row["supplier_id"])
        misc_flag = int(row["is_misc"] or 0)
        conn.execute(
            "UPDATE stock_supplier_vendors SET name = ? WHERE id = ?",
            (nm, vid),
        )
        conn.commit()
        dup = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM stock_supplier_vendors
            WHERE supplier_id = ? AND name = ? AND is_misc = ? AND id <> ?
            """,
            (sid, nm, misc_flag, vid),
        ).fetchone()
        if int(dup["n"] or 0) > 0:
            kind = "miscellaneous" if misc_flag else "serialized"
            raise ValueError(f"A {kind} vendor named '{nm}' already exists for this supplier")
        return True
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Vendor already exists for this supplier") from None
        raise
    finally:
        conn.close()


def add_product(vendor_id: int, name: str) -> int:
    vid = int(vendor_id)
    nm = (name or "").strip()
    if vid <= 0:
        raise ValueError("Invalid vendor id")
    if len(nm) < 2 or len(nm) > 180:
        raise ValueError("Product name must be 2-180 characters")
    conn = _conn()
    try:
        chk = conn.execute("SELECT id FROM stock_supplier_vendors WHERE id = ?", (vid,)).fetchone()
        if not chk:
            raise ValueError("Vendor not found")
        ts = _now()
        conn.execute(
            "INSERT INTO stock_vendor_products(vendor_id, name, created_at) VALUES(?, ?, ?)",
            (vid, nm, ts),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id FROM stock_vendor_products WHERE vendor_id = ? AND name = ?",
            (vid, nm),
        ).fetchone()
        return int(row["id"]) if row else 0
    except sqlite3.IntegrityError:
        raise ValueError("Product already exists for this vendor") from None
    finally:
        conn.close()


def rename_product(product_id: int, name: str) -> bool:
    pid = int(product_id)
    nm = (name or "").strip()
    if pid <= 0:
        raise ValueError("Invalid product id")
    if len(nm) < 2 or len(nm) > 180:
        raise ValueError("Product name must be 2-180 characters")
    conn = _conn()
    try:
        row = conn.execute("SELECT vendor_id FROM stock_vendor_products WHERE id = ?", (pid,)).fetchone()
        if not row:
            raise ValueError("Product not found")
        vid = int(row["vendor_id"])
        conn.execute("UPDATE stock_vendor_products SET name = ? WHERE id = ?", (nm, pid))
        conn.commit()
        dup = conn.execute(
            "SELECT COUNT(*) AS n FROM stock_vendor_products WHERE vendor_id = ? AND name = ?",
            (vid, nm),
        ).fetchone()
        if int(dup["n"] or 0) > 1:
            raise ValueError("Product already exists for this vendor")
        return True
    except sqlite3.IntegrityError:
        raise ValueError("Product already exists for this vendor") from None
    finally:
        conn.close()


def add_product_item(product_id: int, serial_number: str) -> int:
    return add_product_items_batch(
        product_id=product_id,
        batch_invoice_number="",
        items=[
            {
                "serial_number": serial_number,
                "date_issued": "",
                "quotation_no": "",
                "invoice_no": "",
                "client_customer_id": None,
                "client_name": "",
                "address": "",
                "technician_user_ids": [],
                "technician_names": [],
                "comment": "",
            }
        ],
    )[0]


def add_product_items_batch(product_id: int, batch_invoice_number: str, items: List[Dict[str, Any]]) -> List[int]:
    pid = int(product_id)
    if pid <= 0:
        raise ValueError("Invalid product id")
    inv = (batch_invoice_number or "").strip()
    if len(inv) > 200:
        raise ValueError("Invoice Number must be 0-200 characters")
    if not isinstance(items, list) or not items:
        raise ValueError("At least one line item is required")
    conn = _conn()
    try:
        chk = conn.execute(
            """
            SELECT p.id, COALESCE(v.is_misc, 0) AS is_misc
            FROM stock_vendor_products p
            JOIN stock_supplier_vendors v ON v.id = p.vendor_id
            WHERE p.id = ?
            """,
            (pid,),
        ).fetchone()
        if not chk:
            raise ValueError("Product not found")
        if int(chk["is_misc"] or 0) == 1:
            raise ValueError("Use miscellaneous quantity entry for this product")
        item_ids: List[int] = []
        for raw in items:
            sn = str((raw or {}).get("serial_number") or "").strip()
            if len(sn) < 2 or len(sn) > 200:
                raise ValueError("Serial number must be 2-200 characters")
            date_issued = str((raw or {}).get("date_issued") or "").strip()
            quotation_no = str((raw or {}).get("quotation_no") or "").strip()
            invoice_no = str((raw or {}).get("invoice_no") or "").strip()
            client_customer_id = (raw or {}).get("client_customer_id")
            client_name = str((raw or {}).get("client_name") or "").strip()
            address = str((raw or {}).get("address") or "").strip()
            tech_ids = list((raw or {}).get("technician_user_ids") or [])
            tech_names = list((raw or {}).get("technician_names") or [])
            comment = str((raw or {}).get("comment") or "").strip()
            value_ex_vat_raw = (raw or {}).get("value_ex_vat")
            if value_ex_vat_raw in (None, ""):
                value_ex_vat = None
            else:
                try:
                    value_ex_vat = float(value_ex_vat_raw)
                except Exception:
                    raise ValueError("Value ex VAT must be a number")
                if value_ex_vat < 0:
                    raise ValueError("Value ex VAT must be >= 0")
            ts = _now()
            date_in_stock = ts[:10]
            conn.execute(
                """
                INSERT INTO stock_product_items(
                    product_id, serial_number, created_at, value_ex_vat, batch_invoice_number, date_in_stock, date_issued,
                    quotation_no, invoice_no, client_customer_id, client_name, address,
                    technician_user_ids_json, technician_names_json, comment, lifecycle_status
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pid,
                    sn,
                    ts,
                    value_ex_vat,
                    inv,
                    date_in_stock,
                    date_issued,
                    quotation_no,
                    invoice_no,
                    int(client_customer_id) if client_customer_id not in (None, "", 0, "0") else None,
                    client_name,
                    address,
                    json.dumps([int(v) for v in tech_ids if str(v).strip() != ""]),
                    json.dumps([str(v).strip() for v in tech_names if str(v).strip()]),
                    comment,
                    "new",
                ),
            )
            row = conn.execute(
                "SELECT id FROM stock_product_items WHERE serial_number = ?",
                (sn,),
            ).fetchone()
            if row:
                item_ids.append(int(row["id"]))
        conn.commit()
        return item_ids
    except sqlite3.IntegrityError:
        raise ValueError("Serial number already exists") from None
    finally:
        conn.close()


def add_misc_product_lot(
    product_id: int,
    invoice_number: str,
    quantity: float,
    date_in_stock: str = "",
    value_ex_vat: Optional[Any] = None,
) -> int:
    pid = int(product_id)
    inv = (invoice_number or "").strip()
    if pid <= 0:
        raise ValueError("Invalid product id")
    try:
        qty = float(quantity)
    except Exception:
        raise ValueError("Quantity must be a number")
    if qty <= 0:
        raise ValueError("Quantity must be > 0")
    if len(inv) > 200:
        raise ValueError("Invoice Number must be 0-200 characters")
    dis = (date_in_stock or "").strip() or _now()[:10]
    vex: Optional[float] = None
    if value_ex_vat is not None and str(value_ex_vat).strip() != "":
        try:
            vex = float(value_ex_vat)
        except Exception:
            raise ValueError("Value ex VAT must be a number") from None
        if vex < 0:
            raise ValueError("Value ex VAT must be >= 0")
    conn = _conn()
    try:
        chk = conn.execute(
            """
            SELECT p.id, COALESCE(v.is_misc, 0) AS is_misc
            FROM stock_vendor_products p
            JOIN stock_supplier_vendors v ON v.id = p.vendor_id
            WHERE p.id = ?
            """,
            (pid,),
        ).fetchone()
        if not chk:
            raise ValueError("Product not found")
        if int(chk["is_misc"] or 0) != 1:
            raise ValueError("Product is not under a Miscellaneous vendor")
        ts = _now()
        conn.execute(
            """
            INSERT INTO stock_misc_product_lots(
                product_id, invoice_number, quantity_in, quantity_remaining, date_in_stock, value_ex_vat, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (pid, inv, qty, qty, dis, vex, ts),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id FROM stock_misc_product_lots WHERE product_id = ? ORDER BY id DESC LIMIT 1",
            (pid,),
        ).fetchone()
        return int(row["id"]) if row else 0
    finally:
        conn.close()


def rename_item(item_id: int, serial_number: str) -> bool:
    iid = int(item_id)
    sn = (serial_number or "").strip()
    if iid <= 0:
        raise ValueError("Invalid item id")
    if len(sn) < 2 or len(sn) > 200:
        raise ValueError("Serial number must be 2-200 characters")
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE stock_product_items SET serial_number = ? WHERE id = ?",
            (sn, iid),
        )
        conn.commit()
        if int(cur.rowcount or 0) == 0:
            raise ValueError("Item not found")
        return True
    except sqlite3.IntegrityError:
        raise ValueError("Serial number already exists") from None
    finally:
        conn.close()


def list_product_names_for_supplier(supplier_id: int) -> List[str]:
    sid = int(supplier_id)
    if sid <= 0:
        return []
    conn = _conn()
    try:
        rows = conn.execute(
            """
            SELECT DISTINCT p.name AS product_name
            FROM stock_supplier_vendors v
            JOIN stock_vendor_products p ON p.vendor_id = v.id
            WHERE v.supplier_id = ?
            ORDER BY p.name COLLATE NOCASE ASC
            """,
            (sid,),
        ).fetchall()
        return [str(r["product_name"]) for r in rows if str(r["product_name"] or "").strip()]
    finally:
        conn.close()


def list_product_catalog_for_supplier(supplier_id: int) -> List[Dict[str, Any]]:
    sid = int(supplier_id)
    if sid <= 0:
        return []
    conn = _conn()
    try:
        rows = conn.execute(
            """
            SELECT
                p.id AS product_id,
                p.name AS product_name,
                (
                    SELECT i.value_ex_vat
                    FROM stock_product_items i
                    WHERE i.product_id = p.id
                      AND COALESCE(i.lifecycle_status, 'new') <> 'assigned'
                      AND i.value_ex_vat IS NOT NULL
                    ORDER BY i.created_at DESC, i.id DESC
                    LIMIT 1
                ) AS unit_price,
                (
                    SELECT COUNT(*)
                    FROM stock_product_items i
                    WHERE i.product_id = p.id
                      AND COALESCE(i.lifecycle_status, 'new') <> 'assigned'
                ) AS available_stock
            FROM stock_supplier_vendors v
            JOIN stock_vendor_products p ON p.vendor_id = v.id
            WHERE v.supplier_id = ?
            ORDER BY p.name COLLATE NOCASE ASC
            """,
            (sid,),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "product_id": int(r["product_id"]),
                    "name": str(r["product_name"] or ""),
                    "unit_price": float(r["unit_price"]) if r["unit_price"] is not None else None,
                    "available_stock": int(r["available_stock"] or 0),
                }
            )
        return out
    finally:
        conn.close()


def list_assigned_stock_by_vendor() -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(
            """
            SELECT
                i.id, i.serial_number, i.value_ex_vat, i.comment, i.assigned_at, i.lifecycle_status,
                i.assigned_customer_id, i.assigned_customer_name, i.assigned_customer_address, i.assigned_customer_invoice_number,
                COALESCE(i.assignment_target, 'customer') AS assignment_target,
                i.assigned_location_id, i.assigned_location_name,
                p.name AS product_name,
                v.id AS vendor_id, v.name AS vendor_name
            FROM stock_product_items i
            JOIN stock_vendor_products p ON p.id = i.product_id
            JOIN stock_supplier_vendors v ON v.id = p.vendor_id
            WHERE COALESCE(i.lifecycle_status, 'new') = 'assigned'
            ORDER BY v.name COLLATE NOCASE ASC, i.assigned_at DESC, i.id DESC
            """
        ).fetchall()
        grouped: Dict[int, Dict[str, Any]] = {}
        for r in rows:
            vid = int(r["vendor_id"])
            box = grouped.get(vid)
            if not box:
                box = {"vendor_id": vid, "vendor_name": str(r["vendor_name"] or ""), "items": []}
                grouped[vid] = box
            box["items"].append(
                {
                    "item_id": int(r["id"]),
                    "serial_number": str(r["serial_number"] or ""),
                    "product_name": str(r["product_name"] or ""),
                    "value_ex_vat": float(r["value_ex_vat"]) if r["value_ex_vat"] is not None else None,
                    "comment": str(r["comment"] or ""),
                    "assigned_at": str(r["assigned_at"] or ""),
                    "customer_id": int(r["assigned_customer_id"]) if r["assigned_customer_id"] is not None else None,
                    "customer_name": str(r["assigned_customer_name"] or ""),
                    "customer_address": str(r["assigned_customer_address"] or ""),
                    "customer_invoice_number": str(r["assigned_customer_invoice_number"] or ""),
                    "assignment_target": str(r["assignment_target"] or "customer"),
                    "location_id": int(r["assigned_location_id"]) if r["assigned_location_id"] is not None else None,
                    "location_name": str(r["assigned_location_name"] or ""),
                    "lifecycle_status": str(r["lifecycle_status"] or "assigned"),
                }
            )
        return list(grouped.values())
    finally:
        conn.close()


def list_misc_products_for_assignment() -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(
            """
            SELECT p.name AS product_name, SUM(l.quantity_remaining) AS qty
            FROM stock_misc_product_lots l
            JOIN stock_vendor_products p ON p.id = l.product_id
            JOIN stock_supplier_vendors v ON v.id = p.vendor_id
            WHERE COALESCE(v.is_misc, 0) = 1
              AND l.quantity_remaining > 0
            GROUP BY p.name
            ORDER BY p.name COLLATE NOCASE ASC
            """
        ).fetchall()
        return [
            {
                "product_name": str(r["product_name"] or ""),
                "quantity_available": float(r["qty"] or 0),
            }
            for r in rows
            if str(r["product_name"] or "").strip()
        ]
    finally:
        conn.close()


def assign_misc_item_to_customer(
    product_name: str,
    quantity: float,
    customer_id: int = 0,
    customer_name: str = "",
    customer_address: str = "",
    customer_invoice_number: str = "",
    comment: str = "",
    assignment_target: str = "customer",
    location_id: Optional[int] = None,
) -> int:
    pname = (product_name or "").strip()
    if len(pname) < 1:
        raise ValueError("Product name required")
    try:
        qty = float(quantity)
    except Exception:
        raise ValueError("Quantity must be a number")
    if qty <= 0:
        raise ValueError("Quantity must be > 0")
    target = _resolve_assignment_target(
        assignment_target=assignment_target,
        customer_id=customer_id,
        customer_name=customer_name,
        customer_address=customer_address,
        location_id=location_id,
    )
    cinv = (customer_invoice_number or "").strip()
    cmt = (comment or "").strip()
    conn = _conn()
    try:
        lots = conn.execute(
            """
            SELECT l.id, l.invoice_number, l.quantity_remaining
            FROM stock_misc_product_lots l
            JOIN stock_vendor_products p ON p.id = l.product_id
            JOIN stock_supplier_vendors v ON v.id = p.vendor_id
            WHERE COALESCE(v.is_misc, 0) = 1
              AND LOWER(p.name) = LOWER(?)
              AND l.quantity_remaining > 0
            ORDER BY l.created_at ASC, l.id ASC
            """,
            (pname,),
        ).fetchall()
        available = sum(float(r["quantity_remaining"] or 0) for r in lots)
        if available + 1e-9 < qty:
            raise ValueError(f"Insufficient quantity for {pname}. Available: {available:g}")
        ts = _now()
        conn.execute(
            """
            INSERT INTO stock_misc_item_assignments(
                product_name, quantity, signed_out_at, customer_id, customer_name, customer_address,
                assignment_target, assigned_location_id, assigned_location_name, customer_invoice_number, comment
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pname,
                qty,
                ts,
                target["customer_id"],
                target["customer_name"],
                target["customer_address"],
                target["target"],
                target["location_id"],
                target["location_name"],
                cinv,
                cmt,
            ),
        )
        aid_row = conn.execute("SELECT id FROM stock_misc_item_assignments ORDER BY id DESC LIMIT 1").fetchone()
        assignment_id = int(aid_row["id"]) if aid_row else 0
        remaining = qty
        for lot in lots:
            if remaining <= 0:
                break
            lot_id = int(lot["id"])
            lot_rem = float(lot["quantity_remaining"] or 0)
            if lot_rem <= 0:
                continue
            used = lot_rem if lot_rem <= remaining else remaining
            new_rem = lot_rem - used
            conn.execute(
                "UPDATE stock_misc_product_lots SET quantity_remaining = ? WHERE id = ?",
                (new_rem, lot_id),
            )
            conn.execute(
                """
                INSERT INTO stock_misc_item_assignment_lot_usage(
                    assignment_id, lot_id, invoice_number, quantity_used, created_at
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (assignment_id, lot_id, str(lot["invoice_number"] or ""), used, ts),
            )
            remaining -= used
        conn.commit()
        return assignment_id
    finally:
        conn.close()


def list_assigned_stock_items() -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        serial_rows = conn.execute(
            """
            SELECT
                i.id, i.serial_number, i.assigned_at, i.assigned_customer_id, i.assigned_customer_name,
                i.assigned_customer_address, i.assigned_customer_invoice_number, i.batch_invoice_number,
                COALESCE(i.assignment_target, 'customer') AS assignment_target,
                i.assigned_location_id, i.assigned_location_name,
                i.lifecycle_status, i.returned_at,
                p.name AS product_name
            FROM stock_product_items i
            JOIN stock_vendor_products p ON p.id = i.product_id
            WHERE COALESCE(i.lifecycle_status, 'new') = 'assigned'
               OR (
                    COALESCE(i.lifecycle_status, 'new') = 'returned'
                    AND (i.assigned_customer_id IS NOT NULL OR i.assigned_location_id IS NOT NULL)
                  )
            ORDER BY i.assigned_at ASC, i.id ASC
            """
        ).fetchall()
        misc_rows = conn.execute(
            """
            SELECT id, product_name, quantity, signed_out_at, customer_id, customer_name, customer_address, customer_invoice_number
                 , COALESCE(assignment_target, 'customer') AS assignment_target, assigned_location_id, assigned_location_name
            FROM stock_misc_item_assignments
            ORDER BY signed_out_at DESC, id DESC
            """
        ).fetchall()
        usage_rows = conn.execute(
            """
            SELECT u.assignment_id, u.invoice_number, u.quantity_used, l.value_ex_vat AS lot_value_ex_vat
            FROM stock_misc_item_assignment_lot_usage u
            LEFT JOIN stock_misc_product_lots l ON l.id = u.lot_id
            ORDER BY u.id ASC
            """
        ).fetchall()
        usage_map: Dict[int, List[Dict[str, Any]]] = {}
        for u in usage_rows:
            aid = int(u["assignment_id"])
            usage_map.setdefault(aid, []).append(
                {
                    "invoice_number": str(u["invoice_number"] or ""),
                    "quantity_used": float(u["quantity_used"] or 0),
                    "value_ex_vat": float(u["lot_value_ex_vat"]) if u["lot_value_ex_vat"] is not None else None,
                }
            )
        out: List[Dict[str, Any]] = []
        for r in serial_rows:
            life = str(r["lifecycle_status"] or "new")
            out.append(
                {
                    "kind": "serialized",
                    "item_id": int(r["id"]),
                    "product_name": str(r["product_name"] or ""),
                    "serial_number": str(r["serial_number"] or ""),
                    "signed_out_at": str(r["assigned_at"] or ""),
                    "customer_id": int(r["assigned_customer_id"]) if r["assigned_customer_id"] is not None else None,
                    "customer_name": str(r["assigned_customer_name"] or ""),
                    "customer_address": str(r["assigned_customer_address"] or ""),
                    "customer_invoice_number": str(r["assigned_customer_invoice_number"] or ""),
                    "assignment_target": str(r["assignment_target"] or "customer"),
                    "location_id": int(r["assigned_location_id"]) if r["assigned_location_id"] is not None else None,
                    "location_name": str(r["assigned_location_name"] or ""),
                    "source_invoice_number": str(r["batch_invoice_number"] or ""),
                    "lifecycle_status": life,
                    "returned_at": str(r["returned_at"] or "") if life == "returned" else "",
                }
            )
        for r in misc_rows:
            aid = int(r["id"])
            out.append(
                {
                    "kind": "misc",
                    "assignment_id": aid,
                    "product_name": str(r["product_name"] or ""),
                    "quantity": float(r["quantity"] or 0),
                    "signed_out_at": str(r["signed_out_at"] or ""),
                    "customer_id": int(r["customer_id"]) if r["customer_id"] is not None else None,
                    "customer_name": str(r["customer_name"] or ""),
                    "customer_address": str(r["customer_address"] or ""),
                    "customer_invoice_number": str(r["customer_invoice_number"] or ""),
                    "assignment_target": str(r["assignment_target"] or "customer"),
                    "location_id": int(r["assigned_location_id"]) if r["assigned_location_id"] is not None else None,
                    "location_name": str(r["assigned_location_name"] or ""),
                    "lot_usage": usage_map.get(aid, []),
                }
            )
        return out
    finally:
        conn.close()


def list_scrapped_log(limit: int = 200) -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(
            """
            SELECT id, item_id, serial_number, product_name, vendor_name, customer_id, customer_name, customer_address, reason, created_at
            FROM stock_scrapped_log
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(1000, int(limit))),),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "item_id": int(r["item_id"]),
                "serial_number": str(r["serial_number"] or ""),
                "product_name": str(r["product_name"] or ""),
                "vendor_name": str(r["vendor_name"] or ""),
                "customer_id": int(r["customer_id"]) if r["customer_id"] is not None else None,
                "customer_name": str(r["customer_name"] or ""),
                "customer_address": str(r["customer_address"] or ""),
                "reason": str(r["reason"] or ""),
                "created_at": str(r["created_at"] or ""),
            }
            for r in rows
        ]
    finally:
        conn.close()


def assign_item_to_customer(
    item_id: int,
    customer_id: int = 0,
    customer_name: str = "",
    customer_address: str = "",
    customer_invoice_number: str = "",
    assignment_target: str = "customer",
    location_id: Optional[int] = None,
) -> bool:
    iid = int(item_id)
    target = _resolve_assignment_target(
        assignment_target=assignment_target,
        customer_id=customer_id,
        customer_name=customer_name,
        customer_address=customer_address,
        location_id=location_id,
    )
    cinv = (customer_invoice_number or "").strip()
    if iid <= 0:
        raise ValueError("Invalid item id")
    conn = _conn()
    try:
        row = conn.execute("SELECT lifecycle_status FROM stock_product_items WHERE id = ?", (iid,)).fetchone()
        if not row:
            raise ValueError("Item not found")
        prev = str(row["lifecycle_status"] or "new")
        if prev == "assigned":
            raise ValueError("Item is already assigned")
        ts = _now()
        conn.execute(
            """
            UPDATE stock_product_items
            SET lifecycle_status = 'assigned',
                assigned_customer_id = ?,
                assigned_customer_name = ?,
                assigned_customer_address = ?,
                assigned_customer_invoice_number = ?,
                assignment_target = ?,
                assigned_location_id = ?,
                assigned_location_name = ?,
                assigned_at = ?,
                returned_at = NULL,
                pre_allocated_expires_at = NULL
            WHERE id = ?
            """,
            (
                target["customer_id"],
                target["customer_name"],
                target["customer_address"],
                cinv,
                target["target"],
                target["location_id"],
                target["location_name"],
                ts,
                iid,
            ),
        )
        action = "assigned_to_high_site" if target["target"] == "high_site" else "assigned_to_customer"
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, ?, ?, 'assigned', ?, ?, ?, ?)
            """,
            (
                iid,
                action,
                prev,
                target["customer_id"],
                target["location_name"] if target["target"] == "high_site" else target["customer_name"],
                target["customer_address"],
                ts,
            ),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def pre_allocate_item_to_customer(
    item_id: int,
    customer_id: int = 0,
    customer_name: str = "",
    customer_address: str = "",
    customer_invoice_number: str = "",
) -> bool:
    iid = int(item_id)
    target = _resolve_assignment_target(
        assignment_target="pre_allocate",
        customer_id=customer_id,
        customer_name=customer_name,
        customer_address=customer_address,
    )
    cinv = (customer_invoice_number or "").strip()
    if iid <= 0:
        raise ValueError("Invalid item id")
    conn = _conn()
    try:
        _expire_due_pre_allocations(conn)
        row = conn.execute("SELECT lifecycle_status FROM stock_product_items WHERE id = ?", (iid,)).fetchone()
        if not row:
            raise ValueError("Item not found")
        prev = str(row["lifecycle_status"] or "new")
        if prev == "assigned":
            raise ValueError("Item is already assigned")
        if prev == "pre_allocated":
            raise ValueError("Item is already pre-allocated")
        ts = _now()
        expires_at = _expires_after_days(PRE_ALLOCATION_HOLD_DAYS)
        conn.execute(
            """
            UPDATE stock_product_items
            SET lifecycle_status = 'pre_allocated',
                assigned_customer_id = ?,
                assigned_customer_name = ?,
                assigned_customer_address = ?,
                assigned_customer_invoice_number = ?,
                assignment_target = 'pre_allocate',
                assigned_location_id = NULL,
                assigned_location_name = NULL,
                assigned_at = ?,
                returned_at = NULL,
                pre_allocated_expires_at = ?
            WHERE id = ?
            """,
            (
                target["customer_id"],
                target["customer_name"],
                target["customer_address"],
                cinv,
                ts,
                expires_at,
                iid,
            ),
        )
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, 'pre_allocated_to_customer', ?, 'pre_allocated', ?, ?, ?, ?)
            """,
            (
                iid,
                prev,
                target["customer_id"],
                target["customer_name"],
                target["customer_address"],
                ts,
            ),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def release_pre_allocated_item(item_id: int) -> bool:
    iid = int(item_id)
    if iid <= 0:
        raise ValueError("Invalid item id")
    conn = _conn()
    try:
        _expire_due_pre_allocations(conn)
        row = conn.execute(
            """
            SELECT lifecycle_status, assigned_customer_id, assigned_customer_name, assigned_customer_address
            FROM stock_product_items WHERE id = ?
            """,
            (iid,),
        ).fetchone()
        if not row:
            raise ValueError("Item not found")
        prev = str(row["lifecycle_status"] or "new")
        if prev != "pre_allocated":
            raise ValueError("Only pre-allocated items can be returned to stock")
        ts = _now()
        conn.execute(
            """
            UPDATE stock_product_items
            SET lifecycle_status = 'new',
                assigned_customer_id = NULL,
                assigned_customer_name = NULL,
                assigned_customer_address = NULL,
                assigned_customer_invoice_number = NULL,
                assignment_target = 'customer',
                assigned_location_id = NULL,
                assigned_location_name = NULL,
                assigned_at = NULL,
                pre_allocated_expires_at = NULL
            WHERE id = ?
            """,
            (iid,),
        )
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, 'pre_allocation_released', 'pre_allocated', 'new', ?, ?, ?, ?)
            """,
            (
                iid,
                int(row["assigned_customer_id"]) if row["assigned_customer_id"] is not None else None,
                str(row["assigned_customer_name"] or ""),
                str(row["assigned_customer_address"] or ""),
                ts,
            ),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def return_item_to_stock(item_id: int) -> bool:
    iid = int(item_id)
    if iid <= 0:
        raise ValueError("Invalid item id")
    conn = _conn()
    try:
        row = conn.execute(
            """
            SELECT lifecycle_status, assigned_customer_id, assigned_customer_name, assigned_customer_address
            FROM stock_product_items WHERE id = ?
            """,
            (iid,),
        ).fetchone()
        if not row:
            raise ValueError("Item not found")
        prev = str(row["lifecycle_status"] or "new")
        if prev != "assigned":
            raise ValueError("Only assigned items can be returned")
        ts = _now()
        conn.execute(
            """
            UPDATE stock_product_items
            SET lifecycle_status = 'returned',
                returned_at = ?
            WHERE id = ?
            """,
            (ts, iid),
        )
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, 'returned_from_customer', ?, 'returned', ?, ?, ?, ?)
            """,
            (
                iid,
                prev,
                int(row["assigned_customer_id"]) if row["assigned_customer_id"] is not None else None,
                str(row["assigned_customer_name"] or ""),
                str(row["assigned_customer_address"] or ""),
                ts,
            ),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def scrap_assigned_item(item_id: int, reason: str = "") -> bool:
    iid = int(item_id)
    if iid <= 0:
        raise ValueError("Invalid item id")
    rs = (reason or "").strip()
    conn = _conn()
    try:
        row = conn.execute(
            """
            SELECT
                i.id, i.lifecycle_status, i.serial_number, i.assigned_customer_id, i.assigned_customer_name, i.assigned_customer_address,
                p.name AS product_name, v.name AS vendor_name
            FROM stock_product_items i
            JOIN stock_vendor_products p ON p.id = i.product_id
            JOIN stock_supplier_vendors v ON v.id = p.vendor_id
            WHERE i.id = ?
            """,
            (iid,),
        ).fetchone()
        if not row:
            raise ValueError("Item not found")
        prev = str(row["lifecycle_status"] or "new")
        if prev != "assigned":
            raise ValueError("Only assigned items can be scrapped")
        ts = _now()
        conn.execute(
            """
            INSERT INTO stock_scrapped_log(
                item_id, serial_number, product_name, vendor_name, customer_id, customer_name, customer_address, reason, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                iid,
                str(row["serial_number"] or ""),
                str(row["product_name"] or ""),
                str(row["vendor_name"] or ""),
                int(row["assigned_customer_id"]) if row["assigned_customer_id"] is not None else None,
                str(row["assigned_customer_name"] or ""),
                str(row["assigned_customer_address"] or ""),
                rs,
                ts,
            ),
        )
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, 'scrapped', ?, 'scrapped', ?, ?, ?, ?)
            """,
            (
                iid,
                prev,
                int(row["assigned_customer_id"]) if row["assigned_customer_id"] is not None else None,
                str(row["assigned_customer_name"] or ""),
                str(row["assigned_customer_address"] or ""),
                ts,
            ),
        )
        conn.execute("DELETE FROM stock_product_items WHERE id = ?", (iid,))
        conn.commit()
        return True
    finally:
        conn.close()


def mark_item_rma(item_id: int) -> bool:
    iid = int(item_id)
    if iid <= 0:
        raise ValueError("Invalid item id")
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT lifecycle_status, assigned_customer_id, assigned_customer_name, assigned_customer_address FROM stock_product_items WHERE id = ?",
            (iid,),
        ).fetchone()
        if not row:
            raise ValueError("Item not found")
        if str(row["lifecycle_status"] or "") != "assigned":
            raise ValueError("Only assigned items can be marked RMA")
        ts = _now()
        conn.execute(
            """
            INSERT INTO stock_item_lifecycle_log(
                item_id, action, from_status, to_status, customer_id, customer_name, customer_address, created_at
            ) VALUES(?, 'rma_requested', 'assigned', 'assigned', ?, ?, ?, ?)
            """,
            (
                iid,
                int(row["assigned_customer_id"]) if row["assigned_customer_id"] is not None else None,
                str(row["assigned_customer_name"] or ""),
                str(row["assigned_customer_address"] or ""),
                ts,
            ),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def sales_log_series(start_day: str, end_day: str, product_query: str = "") -> Dict[str, Any]:
    start_day = str(start_day or "").strip()
    end_day = str(end_day or "").strip()
    if not start_day or not end_day or len(start_day) != 10 or len(end_day) != 10:
        raise ValueError("Invalid date range")
    if end_day < start_day:
        raise ValueError("End date cannot be before start date")

    pq = str(product_query or "").strip().lower()
    conn = _conn()
    try:
        products: Dict[str, Dict[str, Any]] = {}
        day_set: Set[str] = set()

        def ensure_product(name: str) -> Dict[str, Any]:
            key = str(name or "").strip() or "(Unnamed product)"
            row = products.get(key)
            if row is None:
                row = {
                    "product_name": key,
                    "booked_in": {},
                    "booked_out": {},
                    "booked_in_value": {},
                    "booked_out_value": {},
                    "total_in": 0.0,
                    "total_out": 0.0,
                    "total_in_value": 0.0,
                    "total_out_value": 0.0,
                }
                products[key] = row
            return row

        serial_rows = conn.execute(
            """
            SELECT p.name AS product_name, i.created_at, i.assigned_at, i.value_ex_vat
            FROM stock_product_items i
            JOIN stock_vendor_products p ON p.id = i.product_id
            """
        ).fetchall()
        for r in serial_rows:
            name = str(r["product_name"] or "")
            if pq and pq not in name.lower():
                continue
            item = ensure_product(name)
            in_day = _iso_to_day(str(r["created_at"] or ""))
            if _day_in_range(in_day, start_day, end_day):
                item["booked_in"][in_day] = float(item["booked_in"].get(in_day, 0.0)) + 1.0
                item["total_in"] = float(item["total_in"]) + 1.0
                unit_val = float(r["value_ex_vat"] or 0.0)
                if unit_val > 0:
                    item["booked_in_value"][in_day] = float(item["booked_in_value"].get(in_day, 0.0)) + unit_val
                    item["total_in_value"] = float(item["total_in_value"]) + unit_val
                day_set.add(in_day)
            out_day = _iso_to_day(str(r["assigned_at"] or ""))
            if _day_in_range(out_day, start_day, end_day):
                item["booked_out"][out_day] = float(item["booked_out"].get(out_day, 0.0)) + 1.0
                item["total_out"] = float(item["total_out"]) + 1.0
                unit_val = float(r["value_ex_vat"] or 0.0)
                if unit_val > 0:
                    item["booked_out_value"][out_day] = float(item["booked_out_value"].get(out_day, 0.0)) + unit_val
                    item["total_out_value"] = float(item["total_out_value"]) + unit_val
                day_set.add(out_day)

        misc_in_rows = conn.execute(
            """
            SELECT p.name AS product_name, l.created_at, l.quantity_in, l.value_ex_vat
            FROM stock_misc_product_lots l
            JOIN stock_vendor_products p ON p.id = l.product_id
            """
        ).fetchall()
        for r in misc_in_rows:
            name = str(r["product_name"] or "")
            if pq and pq not in name.lower():
                continue
            day = _iso_to_day(str(r["created_at"] or ""))
            if not _day_in_range(day, start_day, end_day):
                continue
            qty = float(r["quantity_in"] or 0.0)
            if qty <= 0:
                continue
            item = ensure_product(name)
            item["booked_in"][day] = float(item["booked_in"].get(day, 0.0)) + qty
            item["total_in"] = float(item["total_in"]) + qty
            unit_val = float(r["value_ex_vat"] or 0.0)
            if unit_val > 0:
                line_val = qty * unit_val
                item["booked_in_value"][day] = float(item["booked_in_value"].get(day, 0.0)) + line_val
                item["total_in_value"] = float(item["total_in_value"]) + line_val
            day_set.add(day)

        misc_out_rows = conn.execute(
            """
            SELECT
                a.product_name,
                a.signed_out_at,
                a.quantity,
                COALESCE(SUM(COALESCE(u.quantity_used, 0) * COALESCE(l.value_ex_vat, 0)), 0) AS line_value_ex_vat
            FROM stock_misc_item_assignments a
            LEFT JOIN stock_misc_item_assignment_lot_usage u ON u.assignment_id = a.id
            LEFT JOIN stock_misc_product_lots l ON l.id = u.lot_id
            GROUP BY a.id, a.product_name, a.signed_out_at, a.quantity
            """
        ).fetchall()
        for r in misc_out_rows:
            name = str(r["product_name"] or "")
            if pq and pq not in name.lower():
                continue
            day = _iso_to_day(str(r["signed_out_at"] or ""))
            if not _day_in_range(day, start_day, end_day):
                continue
            qty = float(r["quantity"] or 0.0)
            if qty <= 0:
                continue
            item = ensure_product(name)
            item["booked_out"][day] = float(item["booked_out"].get(day, 0.0)) + qty
            item["total_out"] = float(item["total_out"]) + qty
            line_val = float(r["line_value_ex_vat"] or 0.0)
            if line_val > 0:
                item["booked_out_value"][day] = float(item["booked_out_value"].get(day, 0.0)) + line_val
                item["total_out_value"] = float(item["total_out_value"]) + line_val
            day_set.add(day)

        days = sorted(day_set)
        rows: List[Dict[str, Any]] = []
        for name in sorted(products.keys(), key=lambda x: x.lower()):
            it = products[name]
            if float(it["total_in"]) <= 0 and float(it["total_out"]) <= 0:
                continue
            rows.append(
                {
                    "product_name": name,
                    "total_in": round(float(it["total_in"]), 4),
                    "total_out": round(float(it["total_out"]), 4),
                    "total_in_value": round(float(it["total_in_value"]), 2),
                    "total_out_value": round(float(it["total_out_value"]), 2),
                    "series": [
                        {
                            "day": d,
                            "booked_in": round(float(it["booked_in"].get(d, 0.0)), 4),
                            "booked_out": round(float(it["booked_out"].get(d, 0.0)), 4),
                            "booked_in_value": round(float(it["booked_in_value"].get(d, 0.0)), 2),
                            "booked_out_value": round(float(it["booked_out_value"].get(d, 0.0)), 2),
                        }
                        for d in days
                    ],
                }
            )
        return {"days": days, "products": rows}
    finally:
        conn.close()
