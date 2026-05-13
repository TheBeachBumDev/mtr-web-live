# Application users + per-page permissions.
import hashlib
import json
import os
import secrets
import sqlite3
import base64
import hmac
import struct
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
import db_runtime

DB_PATH = os.getenv("AUTH_DB_PATH", os.path.join("data", "auth.db"))

_PBKDF2_PREFIX = "pbkdf2_sha256$"

# Stable keys for RBAC (match main.py routing). When you add a tab: add a row here, add
# auth_users.page_landing_path, routes in main.py, and set server_resources.PAGE_KEY_COMPOSE_SERVICE
# to the correct docker-compose service (or it defaults to "core").
PAGE_DEFINITIONS: List[Tuple[str, str]] = [
    # `home` -> `/` (global landing). `mtr_live` -> `/mtr-live` (hop charts / live dashboard).
    ("home", "Home"),
    ("mtr_live", "MTR Live"),
    ("download_test", "Download Test"),
    ("fieldtech", "Field Tech"),
    ("ipam", "IPAM"),
    ("monitoring", "Monitoring"),
    ("routers", "Routers"),
    ("backhauls", "Backhauls"),
    ("stock_management", "Stock Management"),
    ("sales_log", "Sales Log"),
    ("purchase_orders", "Purchase Orders"),
    ("whatsapp_signups", "Whatsapp Signups"),
    ("backups", "Backups"),
    ("firewall", "Firewall"),
    ("location_sync", "Location Sync"),
    ("resources", "Resources"),
]

PAGE_KEYS: Tuple[str, ...] = tuple(p[0] for p in PAGE_DEFINITIONS)
ALL_PAGE_KEYS: Set[str] = set(PAGE_KEYS)


def page_landing_path(page_key: str) -> str:
    """
    Primary URL for each RBAC page key. Must match the GET routes in main.py.
    When you add a row to PAGE_DEFINITIONS, add the path here and the route.
    """
    return {
        "home": "/",
        "mtr_live": "/mtr-live",
        "download_test": "/download-test",
        "fieldtech": "/fieldtech",
        "ipam": "/ipam",
        "monitoring": "/monitoring",
        "routers": "/routers",
        "backhauls": "/backhauls",
        "stock_management": "/stock-management",
        "sales_log": "/sales-log",
        "purchase_orders": "/purchase-orders",
        "whatsapp_signups": "/whatsapp-signups",
        "backups": "/backups",
        "firewall": "/firewall",
        "location_sync": "/location-sync",
        "resources": "/resources",
    }.get(page_key, "/")

# Optional RBAC expansions applied at session/nav time (stored pages_json is authoritative).
IMPLICIT_PAGE_GRANTS: Tuple[Tuple[Set[str], Set[str]], ...] = ()

_APP_USER = os.getenv("APP_USER", "admin")
_APP_PASS = os.getenv("APP_PASS", "change-me")


def _env_forced_admins() -> Set[str]:
    """
    Comma-separated usernames in AUTH_ADMIN_USERS always get admin (session + Users tab).
    Case-insensitive. Use if DB is_admin got out of sync.
    """
    raw = os.getenv("AUTH_ADMIN_USERS", "").strip()
    if not raw:
        return set()
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def _env_super_admins() -> Set[str]:
    """
    Comma-separated usernames in AUTH_SUPER_ADMIN_USERS are super-admins.
    Super-admin is for privileged runtime controls (role override/testing flows).
    """
    raw = os.getenv("AUTH_SUPER_ADMIN_USERS", "").strip()
    if not raw:
        return set()
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def user_is_super_admin(username: str) -> bool:
    sn = (username or "").strip().lower()
    if not sn:
        return False
    return sn in _env_super_admins()


def _row_admin_flag(row: Any) -> bool:
    """is_admin can be int or string; avoid bool('0') === True bugs."""
    if row is None:
        return False
    try:
        v = row["is_admin"]
    except (KeyError, IndexError, TypeError):
        return False
    if v is None:
        return False
    try:
        return int(v) == 1
    except (TypeError, ValueError):
        return str(v).strip().lower() in ("1", "true", "yes")


def _is_admin_effective(username: str, row: Optional[Dict[str, Any]]) -> bool:
    sn = (username or "").strip().lower()
    if sn in _env_forced_admins():
        return True
    if row is not None and _row_admin_flag(row):
        return True
    return False


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _ensure_dir() -> None:
    d = os.path.dirname(DB_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _conn() -> sqlite3.Connection:
    return db_runtime.get_conn("auth")


def hash_password(plain: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 390_000
    dk = hashlib.pbkdf2_hmac(
        "sha256", (plain or "").encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"{_PBKDF2_PREFIX}{iterations}${salt}${dk.hex()}"


def verify_password_hash(plain: str, stored: str) -> bool:
    stored = (stored or "").strip()
    if not stored.startswith(_PBKDF2_PREFIX):
        return secrets.compare_digest(plain, stored)
    try:
        _, it_s, salt, hexhash = stored.split("$", 3)
        it = int(it_s)
        dk = hashlib.pbkdf2_hmac(
            "sha256", plain.encode("utf-8"), salt.encode("utf-8"), it
        )
        return secrets.compare_digest(dk.hex(), hexhash)
    except Exception:
        return False


def init_db() -> None:
    if db_runtime.is_postgres():
        db_runtime.init_postgres_schema()
        conn = _conn()
        try:
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS email TEXT")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS mobile TEXT")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS twofa_enabled INTEGER NOT NULL DEFAULT 0")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS twofa_secret TEXT")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS twofa_temp_secret TEXT")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS twofa_backup_codes_json TEXT NOT NULL DEFAULT '[]'")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS twofa_exempt INTEGER NOT NULL DEFAULT 0")
            conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS po_admin INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()
        conn = _conn()
        n = int(conn.execute("SELECT COUNT(*) FROM app_users").fetchone()[0])
        conn.close()
        if n == 0:
            _bootstrap_from_env()
        _grant_home_to_non_admins_missing_it()
        return
    conn = _conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            pages_json TEXT NOT NULL DEFAULT '[]',
            email TEXT,
            mobile TEXT,
            twofa_enabled INTEGER NOT NULL DEFAULT 0,
            twofa_secret TEXT,
            twofa_temp_secret TEXT,
            twofa_backup_codes_json TEXT NOT NULL DEFAULT '[]',
            twofa_exempt INTEGER NOT NULL DEFAULT 0,
            po_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    try:
        cols = conn.execute("PRAGMA table_info(app_users)").fetchall()
        names = {str(r["name"]) for r in cols}
        if "email" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN email TEXT")
        if "mobile" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN mobile TEXT")
        if "twofa_enabled" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN twofa_enabled INTEGER NOT NULL DEFAULT 0")
        if "twofa_secret" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN twofa_secret TEXT")
        if "twofa_temp_secret" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN twofa_temp_secret TEXT")
        if "twofa_backup_codes_json" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN twofa_backup_codes_json TEXT NOT NULL DEFAULT '[]'")
        if "twofa_exempt" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN twofa_exempt INTEGER NOT NULL DEFAULT 0")
        if "po_admin" not in names:
            conn.execute("ALTER TABLE app_users ADD COLUMN po_admin INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass
    conn.commit()
    n = int(conn.execute("SELECT COUNT(*) FROM app_users").fetchone()[0])
    conn.close()
    if n == 0:
        _bootstrap_from_env()
    _grant_home_to_non_admins_missing_it()


def _bootstrap_from_env() -> None:
    """First run: create an admin from APP_USER / APP_PASS if set."""
    u = (_APP_USER or "").strip()
    p = _APP_PASS or ""
    if not u or not p:
        return
    try:
        create_user(
            u,
            p,
            is_admin=True,
            pages=list(PAGE_KEYS),
            _internal_bootstrap=True,
        )
    except ValueError:
        pass


def _parse_pages_json(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(x) for x in data if str(x) in ALL_PAGE_KEYS]
    except json.JSONDecodeError:
        pass
    return []


def _grant_home_to_non_admins_missing_it() -> None:
    """
    Idempotent: add page key `home` for non-admins who lack it so `/` remains the
    default landing (same key as the Users / permissions UI).
    """
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT id, pages_json FROM app_users WHERE is_admin = 0"
        ).fetchall()
        ts = _now()
        for r in rows:
            uid = int(r["id"])
            pages = _parse_pages_json(str(r["pages_json"] or "[]"))
            if "home" in pages:
                continue
            new_pages = sorted(set(pages) | {"home"})
            conn.execute(
                "UPDATE app_users SET pages_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(new_pages), ts, uid),
            )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        conn.close()


def list_users() -> List[Dict[str, Any]]:
    conn = _conn()
    rows = conn.execute(
        "SELECT id, username, is_admin, po_admin, pages_json, email, mobile, twofa_enabled, twofa_exempt, created_at FROM app_users ORDER BY username COLLATE NOCASE ASC"
    ).fetchall()
    conn.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        pages = _parse_pages_json(str(r["pages_json"] or "[]"))
        out.append(
            {
                "id": int(r["id"]),
                "username": str(r["username"]),
                "is_admin": _row_admin_flag(r),
                "po_admin": int(r.get("po_admin", 0) or 0) == 1,
                "pages": pages,
                "email": str(r["email"] or ""),
                "mobile": str(r["mobile"] or ""),
                "twofa_enabled": int(r["twofa_enabled"] or 0) == 1,
                "twofa_exempt": int(r["twofa_exempt"] or 0) == 1,
                "created_at": str(r["created_at"]),
            }
        )
    return out


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    u = (username or "").strip()
    if not u:
        return None
    conn = _conn()
    row = conn.execute(
        "SELECT id, username, password_hash, is_admin, po_admin, pages_json, email, mobile, twofa_enabled, twofa_secret, twofa_temp_secret, twofa_backup_codes_json, twofa_exempt FROM app_users WHERE username = ? COLLATE NOCASE",
        (u,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    ia = _row_admin_flag(row)
    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "password_hash": str(row["password_hash"]),
        "is_admin": ia,
        "pages": _parse_pages_json(str(row["pages_json"] or "[]")),
        "email": str(row["email"] or ""),
        "mobile": str(row["mobile"] or ""),
        "twofa_enabled": int(row["twofa_enabled"] or 0) == 1,
        "twofa_secret": str(row["twofa_secret"] or ""),
        "twofa_temp_secret": str(row["twofa_temp_secret"] or ""),
        "twofa_backup_codes_json": str(row["twofa_backup_codes_json"] or "[]"),
        "twofa_exempt": int(row["twofa_exempt"] or 0) == 1,
        "po_admin": int(row.get("po_admin", 0) or 0) == 1,
    }


def get_user_by_id(uid: int) -> Optional[Dict[str, Any]]:
    conn = _conn()
    row = conn.execute(
        "SELECT id, username, password_hash, is_admin, po_admin, pages_json, email, mobile, twofa_enabled, twofa_secret, twofa_temp_secret, twofa_backup_codes_json, twofa_exempt FROM app_users WHERE id = ?",
        (int(uid),),
    ).fetchone()
    conn.close()
    if not row:
        return None
    ia = _row_admin_flag(row)
    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "password_hash": str(row["password_hash"]),
        "is_admin": ia,
        "pages": _parse_pages_json(str(row["pages_json"] or "[]")),
        "email": str(row["email"] or ""),
        "mobile": str(row["mobile"] or ""),
        "twofa_enabled": int(row["twofa_enabled"] or 0) == 1,
        "twofa_secret": str(row["twofa_secret"] or ""),
        "twofa_temp_secret": str(row["twofa_temp_secret"] or ""),
        "twofa_backup_codes_json": str(row["twofa_backup_codes_json"] or "[]"),
        "twofa_exempt": int(row["twofa_exempt"] or 0) == 1,
        "po_admin": int(row.get("po_admin", 0) or 0) == 1,
    }


def verify_password(username: str, password: str) -> bool:
    """Password check against sqlite app_users only (no APP_PASS / APP_USERS env login)."""
    row = get_user_by_username(username)
    if not row:
        return False
    return verify_password_hash(password or "", row["password_hash"])


def user_is_admin(username: str) -> bool:
    row = get_user_by_username(username)
    return _is_admin_effective(username, row)


def session_permissions(username: str) -> Tuple[bool, Set[str]]:
    """
    Returns (is_admin, allowed_page_keys).
    DB admins have full access. AUTH_ADMIN_USERS can force admin when the DB flag is wrong.
    """
    un = (username or "").strip()
    row = get_user_by_username(un)
    if _is_admin_effective(un, row):
        return True, set(ALL_PAGE_KEYS)
    if row:
        allowed = set(row.get("pages") or [])
        for sources, grants in IMPLICIT_PAGE_GRANTS:
            if allowed.intersection(sources):
                allowed.update(grants)
        # Home (`/`) is always allowed for every signed-in user (default landing).
        allowed.add("home")
        return False, allowed
    return False, set()


def user_can_access(username: str, page_key: str) -> bool:
    if page_key == "users_admin":
        return user_is_admin(username)
    if user_is_admin(username):
        return True
    _is_adm, allowed = session_permissions(username)
    return page_key in allowed


def create_user(
    username: str,
    password: str,
    *,
    is_admin: bool = False,
    po_admin: bool = False,
    pages: Optional[List[str]] = None,
    email: str = "",
    mobile: str = "",
    _internal_bootstrap: bool = False,
) -> int:
    u = (username or "").strip()
    if len(u) < 2 or len(u) > 80:
        raise ValueError("Username length 2–80")
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters")
    hp = hash_password(password)
    pg_set = sorted(set(pages or []) & ALL_PAGE_KEYS)
    if not is_admin:
        pg_set = sorted(set(pg_set) | {"home"})
    pg = json.dumps(pg_set)
    ts = _now()
    po_adm = 1 if po_admin else 0
    conn = _conn()
    try:
        if db_runtime.is_postgres():
            cur = conn.execute(
                """
                INSERT INTO app_users (username, password_hash, is_admin, po_admin, pages_json, email, mobile, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                (u, hp, 1 if is_admin else 0, po_adm, pg, (email or "").strip(), (mobile or "").strip(), ts, ts),
            )
            uid = int(cur.fetchone()[0])
        else:
            cur = conn.execute(
                """
                INSERT INTO app_users (username, password_hash, is_admin, po_admin, pages_json, email, mobile, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (u, hp, 1 if is_admin else 0, po_adm, pg, (email or "").strip(), (mobile or "").strip(), ts, ts),
            )
            uid = int(cur.lastrowid)
        conn.commit()
        return uid
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists") from None
    finally:
        conn.close()


def update_user(
    uid: int,
    *,
    password: Optional[str] = None,
    is_admin: Optional[bool] = None,
    po_admin: Optional[bool] = None,
    pages: Optional[List[str]] = None,
    email: Optional[str] = None,
    mobile: Optional[str] = None,
    twofa_exempt: Optional[bool] = None,
) -> bool:
    uid = int(uid)
    conn = _conn()
    row = conn.execute("SELECT id, is_admin FROM app_users WHERE id = ?", (uid,)).fetchone()
    if not row:
        conn.close()
        return False
    if is_admin is False and int(row["is_admin"]) == 1:
        n_admins = int(
            conn.execute("SELECT COUNT(*) FROM app_users WHERE is_admin = 1").fetchone()[0]
        )
        if n_admins <= 1:
            conn.close()
            raise ValueError("cannot remove admin flag from the last admin")
    parts: List[str] = []
    vals: List[Any] = []
    if password is not None:
        if len(password) < 6:
            conn.close()
            raise ValueError("Password must be at least 6 characters")
        parts.append("password_hash = ?")
        vals.append(hash_password(password))
    if is_admin is not None:
        parts.append("is_admin = ?")
        vals.append(1 if is_admin else 0)
    if po_admin is not None:
        parts.append("po_admin = ?")
        vals.append(1 if po_admin else 0)
    if pages is not None:
        pg_set = sorted(set(pages) & ALL_PAGE_KEYS)
        will_admin = bool(int(row["is_admin"]))
        if is_admin is not None:
            will_admin = bool(is_admin)
        if not will_admin:
            pg_set = sorted(set(pg_set) | {"home"})
        parts.append("pages_json = ?")
        vals.append(json.dumps(pg_set))
    if email is not None:
        parts.append("email = ?")
        vals.append((email or "").strip())
    if mobile is not None:
        parts.append("mobile = ?")
        vals.append((mobile or "").strip())
    if twofa_exempt is not None:
        parts.append("twofa_exempt = ?")
        vals.append(1 if bool(twofa_exempt) else 0)
    if not parts:
        conn.close()
        return True
    parts.append("updated_at = ?")
    vals.append(_now())
    vals.append(uid)
    conn.execute(
        f"UPDATE app_users SET {', '.join(parts)} WHERE id = ?", vals
    )
    conn.commit()
    conn.close()
    return True


def delete_user(uid: int) -> Tuple[bool, Optional[str]]:
    uid = int(uid)
    conn = _conn()
    row = conn.execute(
        "SELECT id, is_admin FROM app_users WHERE id = ?", (uid,)
    ).fetchone()
    if not row:
        conn.close()
        return False, "not found"
    if int(row["is_admin"]) == 1:
        n_admins = conn.execute(
            "SELECT COUNT(*) FROM app_users WHERE is_admin = 1"
        ).fetchone()[0]
        if int(n_admins) <= 1:
            conn.close()
            return False, "cannot delete the last admin"
    conn.execute("DELETE FROM app_users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return True, None


def count_admins() -> int:
    conn = _conn()
    n = int(conn.execute("SELECT COUNT(*) FROM app_users WHERE is_admin = 1").fetchone()[0])
    conn.close()
    return n


def _b32_no_padding(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").replace("=", "")


def generate_totp_secret() -> str:
    return _b32_no_padding(secrets.token_bytes(20))


def _totp_code(secret_b32: str, for_counter: int) -> str:
    s = (secret_b32 or "").strip().upper()
    if not s:
        return ""
    pad = "=" * ((8 - (len(s) % 8)) % 8)
    key = base64.b32decode(s + pad, casefold=True)
    msg = struct.pack(">Q", int(for_counter))
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code_int:06d}"


def verify_totp_code(secret_b32: str, code: str, window: int = 1, interval_sec: int = 30) -> bool:
    c = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(c) != 6:
        return False
    now_counter = int(time.time()) // int(interval_sec)
    for shift in range(-int(window), int(window) + 1):
        if secrets.compare_digest(_totp_code(secret_b32, now_counter + shift), c):
            return True
    return False


def set_user_twofa_temp_secret(user_id: int, secret: str) -> bool:
    conn = _conn()
    try:
        conn.execute(
            "UPDATE app_users SET twofa_temp_secret = ?, updated_at = ? WHERE id = ?",
            ((secret or "").strip(), _now(), int(user_id)),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def reset_user_twofa(user_id: int) -> bool:
    conn = _conn()
    try:
        row = conn.execute("SELECT id FROM app_users WHERE id = ?", (int(user_id),)).fetchone()
        if not row:
            return False
        conn.execute(
            """
            UPDATE app_users
            SET twofa_enabled = 0,
                twofa_secret = NULL,
                twofa_temp_secret = NULL,
                twofa_backup_codes_json = '[]',
                updated_at = ?
            WHERE id = ?
            """,
            (_now(), int(user_id)),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def enable_user_twofa(user_id: int, secret: str, backup_codes: List[str]) -> bool:
    hashes = [hash_password(str(c)) for c in (backup_codes or []) if str(c).strip()]
    conn = _conn()
    try:
        conn.execute(
            """
            UPDATE app_users
            SET twofa_enabled = 1,
                twofa_secret = ?,
                twofa_temp_secret = '',
                twofa_backup_codes_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            ((secret or "").strip(), json.dumps(hashes), _now(), int(user_id)),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def consume_user_backup_code(user_id: int, code: str) -> bool:
    c = str(code or "").strip()
    if not c:
        return False
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT twofa_backup_codes_json FROM app_users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if not row:
            return False
        hashes = []
        try:
            hashes = list(json.loads(str(row["twofa_backup_codes_json"] or "[]")))
        except Exception:
            hashes = []
        kept = []
        used = False
        for h in hashes:
            hs = str(h or "")
            if (not used) and verify_password_hash(c, hs):
                used = True
                continue
            kept.append(hs)
        if not used:
            return False
        conn.execute(
            "UPDATE app_users SET twofa_backup_codes_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(kept), _now(), int(user_id)),
        )
        conn.commit()
        return True
    finally:
        conn.close()
