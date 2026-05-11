#!/usr/bin/env python3
"""
One-off: create or reset a super-admin user (full page access + is_admin).

Usage (from project root):
  python3 scripts/bootstrap_admin.py <username> <password>

Does not store secrets in the repo — pass credentials on the command line or via env.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auth_users  # noqa: E402


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/bootstrap_admin.py <username> <password>", file=sys.stderr)
        sys.exit(2)
    username = (sys.argv[1] or "").strip()
    password = sys.argv[2] or ""
    if len(username) < 2:
        print("Username too short.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 6:
        print("Password must be at least 6 characters.", file=sys.stderr)
        sys.exit(1)

    auth_users.init_db()
    row = auth_users.get_user_by_username(username)
    all_pages = list(auth_users.PAGE_KEYS)

    if row:
        auth_users.update_user(
            int(row["id"]),
            password=password,
            is_admin=True,
            pages=all_pages,
        )
        print(f"Updated user {username!r}: admin, password reset, all tabs enabled.")
    else:
        auth_users.create_user(
            username,
            password,
            is_admin=True,
            pages=all_pages,
        )
        print(f"Created admin user {username!r} with full access.")


if __name__ == "__main__":
    main()
