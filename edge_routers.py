# Edge router inventory (SSH credentials stored encrypted in ipam.db)
import base64
import hashlib
import os
import re
import socket
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.fernet import Fernet

import ipam

HOST_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]%]+$")


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _fernet() -> Fernet:
    env_key = os.getenv("ROUTER_SECRET_KEY", "").strip()
    if env_key:
        try:
            return Fernet(env_key.encode("ascii"))
        except Exception:
            pass
    sess = os.getenv("SESSION_SECRET", "").encode("utf-8")
    if not sess:
        sess = b"mtr-web-live-dev-session-signing-key-not-for-production"
    digest = hashlib.sha256(sess).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def _encrypt_password(plain: str) -> bytes:
    return _fernet().encrypt((plain or "").encode("utf-8"))


def _decrypt_password(blob: bytes) -> str:
    return _fernet().decrypt(blob).decode("utf-8")


def validate_router_host(host: str) -> str:
    h = (host or "").strip()
    if not h or len(h) > 253:
        raise ValueError("Router IP or hostname is required")
    if not HOST_RE.match(h):
        raise ValueError("Invalid characters in router address")
    return h


def validate_ssh_user(user: str) -> str:
    u = (user or "").strip()
    if not u or len(u) > 128:
        raise ValueError("SSH username is required (max 128 characters)")
    return u


def validate_ssh_port(port: Any) -> int:
    if port is None or port == "":
        return 22
    p = int(port)
    if p < 1 or p > 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    return p


def location_exists(location_id: int) -> bool:
    conn = ipam.get_conn()
    r = conn.execute(
        "SELECT id FROM ipam_locations WHERE id = ?", (int(location_id),)
    ).fetchone()
    conn.close()
    return r is not None


def _location_lookup_maps() -> Tuple[Dict[str, int], Set[int]]:
    """Lowercase location name -> id; set of valid ids."""
    conn = ipam.get_conn()
    rows = conn.execute("SELECT id, name FROM ipam_locations").fetchall()
    conn.close()
    by_name: Dict[str, int] = {}
    ids: Set[int] = set()
    for r in rows:
        ids.add(int(r["id"]))
        nm = (r["name"] or "").strip().lower()
        if nm:
            by_name[nm] = int(r["id"])
    return by_name, ids


def resolve_location_token(
    token: str, name_to_id: Dict[str, int], valid_ids: Set[int]
) -> Optional[int]:
    """Match IPAM location by numeric id or exact name (case-insensitive)."""
    t = (token or "").strip()
    if not t:
        return None
    if t.isdigit():
        i = int(t)
        if i in valid_ids:
            return i
        return None
    return name_to_id.get(t.lower())


def list_routers() -> List[Dict[str, Any]]:
    conn = ipam.get_conn()
    rows = conn.execute(
        """
        SELECT r.id, r.location_id, l.name AS location_name, r.router_host,
               r.ssh_port, r.ssh_user, r.created_at
        FROM edge_routers r
        JOIN ipam_locations l ON l.id = r.location_id
        ORDER BY l.name COLLATE NOCASE ASC, r.router_host COLLATE NOCASE ASC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_router(
    location_id: int,
    router_host: str,
    ssh_user: str,
    ssh_password: str,
    ssh_port: Any = None,
) -> int:
    lid = int(location_id)
    if not location_exists(lid):
        raise ValueError("Unknown location")
    host = validate_router_host(router_host)
    user = validate_ssh_user(ssh_user)
    pw = ssh_password if ssh_password is not None else ""
    if not pw:
        raise ValueError("SSH password is required")
    port = validate_ssh_port(ssh_port)
    enc = _encrypt_password(pw)

    conn = ipam.get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO edge_routers (location_id, router_host, ssh_port, ssh_user, ssh_password_enc, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (lid, host, port, user, enc, _now()),
        )
        conn.commit()
        return int(cur.lastrowid)
    except sqlite3.IntegrityError:
        raise ValueError("A router with this address already exists for this location")
    finally:
        conn.close()


def delete_router(router_id: int) -> bool:
    conn = ipam.get_conn()
    cur = conn.execute("DELETE FROM edge_routers WHERE id = ?", (int(router_id),))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0


def _router_columns(parts: List[str]) -> Tuple[str, Optional[str], Optional[str], Optional[int]]:
    """1–4 fields: host | host,user | host,user,password | + port."""
    cols = [p for p in parts if p != ""]
    n = len(cols)
    if n == 0:
        raise ValueError("empty line")
    if n == 1:
        return (cols[0], None, None, None)
    if n == 2:
        try:
            p = int(cols[1])
            if 1 <= p <= 65535:
                return (cols[0], None, None, p)
        except ValueError:
            pass
        return (cols[0], cols[1], None, None)
    if n == 3:
        return (cols[0], cols[1], cols[2], None)
    if n == 4:
        try:
            pt = int(cols[3])
            if 1 <= pt <= 65535:
                return (cols[0], cols[1], cols[2], pt)
        except ValueError:
            pass
        raise ValueError("4th column must be SSH port (1–65535)")
    raise ValueError("too many columns (max: host, user, password, port)")


def _split_space_router(s: str) -> List[str]:
    return [p for p in re.split(r"\s+", (s or "").strip()) if p != ""]


def _split_import_tokens(s: str) -> List[str]:
    raw = (s or "").strip()
    if not raw:
        return []
    if "\t" in raw:
        return [p.strip() for p in raw.split("\t") if p.strip() != ""]
    if "|" in raw:
        return [p.strip() for p in raw.split("|") if p.strip() != ""]
    if "," in raw:
        return [p.strip() for p in raw.split(",") if p.strip() != ""]
    return _split_space_router(raw)


def _consume_location_prefix(
    parts: List[str],
    name_to_id: Dict[str, int],
    valid_ids: Set[int],
) -> Tuple[Optional[int], List[str]]:
    """
    If the line starts with an IPAM location (name or numeric id), strip it and return the rest.
    Location names may be several words when separated by spaces (longest match against IPAM names).
    """
    if len(parts) < 2:
        return None, parts
    max_end = min(len(parts) - 1, 16)
    for end in range(max_end, 0, -1):
        phrase = " ".join(parts[:end]).strip().lower()
        if phrase in name_to_id:
            return name_to_id[phrase], parts[end:]
    tid = resolve_location_token(parts[0], name_to_id, valid_ids)
    if tid is not None:
        return tid, parts[1:]
    return None, parts


def _parse_router_import_row(
    s: str, name_to_id: Dict[str, int], valid_ids: Set[int]
) -> Optional[Tuple[Optional[int], str, Optional[str], Optional[str], Optional[int]]]:
    """
    Optional leading column(s): IPAM location (exact name, case-insensitive, or numeric id).
    Remaining columns: host [, user [, password [, port]]] as in _router_columns.
    """
    raw = (s or "").strip()
    if not raw or raw.startswith("#"):
        return None
    parts = _split_import_tokens(raw)
    if not parts:
        return None
    loc_opt, rest = _consume_location_prefix(parts, name_to_id, valid_ids)
    host, u, pw, pt = _router_columns(rest)
    return (loc_opt, host, u, pw, pt)


def import_routers_bulk(
    text: str,
    default_ssh_user: str = "",
    default_ssh_password: str = "",
    default_ssh_port: Optional[int] = None,
    default_location_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Create routers from lines. Each line may start with an IPAM location name (or id), then
    router host / SSH fields. If the line has no location prefix, default_location_id is used
    (must be set in that case).
    """
    if default_location_id is not None and not location_exists(int(default_location_id)):
        raise ValueError("Unknown default location")

    name_to_id, valid_ids = _location_lookup_maps()

    default_user = (default_ssh_user or "").strip()
    default_pw = default_ssh_password if default_ssh_password is not None else ""
    default_port_val = (
        validate_ssh_port(default_ssh_port) if default_ssh_port is not None else 22
    )

    created_ids: List[int] = []
    errors: List[Dict[str, Any]] = []
    skipped = 0

    lines = (text or "").splitlines()
    for line_no, raw in enumerate(lines, start=1):
        try:
            parsed = _parse_router_import_row(raw, name_to_id, valid_ids)
            if parsed is None:
                skipped += 1
                continue
            loc_opt, host, opt_user, opt_pw, opt_port = parsed
            lid_use = loc_opt if loc_opt is not None else (
                int(default_location_id) if default_location_id is not None else None
            )
            if lid_use is None:
                raise ValueError(
                    "no location — pick a default in the form or put the IPAM location first on each line"
                )
            if not location_exists(int(lid_use)):
                raise ValueError("Unknown location")
            u = (opt_user.strip() if opt_user is not None else "") or default_user
            pw = opt_pw if opt_pw is not None else default_pw
            port_use = (
                validate_ssh_port(opt_port) if opt_port is not None else default_port_val
            )
            if not u:
                raise ValueError("SSH user required (column or default)")
            if not pw:
                raise ValueError("SSH password required (column or default)")
            rid = add_router(int(lid_use), host, u, pw, port_use)
            created_ids.append(rid)
        except ValueError as e:
            errors.append({"line": line_no, "detail": str(e)})

    return {
        "all_succeeded": len(errors) == 0,
        "created": len(created_ids),
        "ids": created_ids,
        "skipped_lines": skipped,
        "errors": errors,
    }


def get_router_credentials(router_id: int) -> Optional[Dict[str, Any]]:
    """Decrypt credentials for server-side automation (SSH). Not for JSON APIs."""
    conn = ipam.get_conn()
    row = conn.execute(
        """
        SELECT r.id, r.location_id, r.router_host, r.ssh_port, r.ssh_user, r.ssh_password_enc,
               l.name AS location_name
        FROM edge_routers r
        JOIN ipam_locations l ON l.id = r.location_id
        WHERE r.id = ?
        """,
        (int(router_id),),
    ).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["ssh_password"] = _decrypt_password(d.pop("ssh_password_enc"))
    except Exception:
        d["ssh_password"] = ""
    return d


def test_ssh_connection(router_id: int) -> Tuple[bool, str]:
    """Try password SSH login; returns (success, human message). Blocking I/O."""
    try:
        import paramiko  # type: ignore
    except ImportError:
        return False, "SSH test unavailable: install paramiko on the server"

    cred = get_router_credentials(router_id)
    if not cred:
        return False, "Router not found"
    pw = cred.get("ssh_password") or ""
    if not pw:
        return False, "Could not decrypt stored password"

    host = str(cred.get("router_host") or "").strip()
    port = validate_ssh_port(cred.get("ssh_port"))
    user = str(cred.get("ssh_user") or "").strip()

    timeout = float(os.getenv("SSH_TEST_TIMEOUT_SEC", "20"))
    timeout = max(5.0, min(120.0, timeout))

    # Stage 1: verify plain TCP connectivity first for clearer diagnostics.
    try:
        probe = socket.create_connection((host, port), timeout=6.0)
        probe.close()
    except socket.timeout:
        return False, "TCP connect timed out (routing/firewall path issue)"
    except OSError as e:
        return False, "TCP connect failed: " + str(e).strip()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=pw,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        t = client.get_transport()
        ok = bool(t and t.is_active())
        banner = ""
        try:
            if t:
                banner = (t.remote_version or "").strip()
        except Exception:
            banner = ""
        client.close()
        if ok:
            tail = (" — " + banner[:100]) if banner else ""
            return True, "SSH authentication succeeded." + tail
        return False, "SSH connected but transport did not activate"
    except paramiko.AuthenticationException:
        try:
            client.close()
        except Exception:
            pass
        return False, "Authentication failed (check user and password)"
    except paramiko.SSHException as e:
        try:
            client.close()
        except Exception:
            pass
        return False, "SSH error: " + str(e).strip()
    except socket.timeout:
        try:
            client.close()
        except Exception:
            pass
        return False, "SSH handshake/auth timed out (TCP reachable; check SSH service/auth settings)"
    except OSError as e:
        try:
            client.close()
        except Exception:
            pass
        return False, "Network error: " + str(e).strip()
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return False, str(e).strip()
