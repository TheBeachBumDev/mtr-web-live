#!/usr/bin/env python3
"""
Repair purchase_order_items rows tagged customer_item without per-line customer_id.

Legacy po_line_request_type_backfill_v1 copied header request_type onto lines but not
customer_id. This script (and purchase_orders.init_db on startup) fixes that in two steps:
  1. Copy PO header customer_id / payment_status onto matching lines.
  2. Demote remaining invalid customer_item rows to stock_item.

Usage (from repo root on the host, after pull + rebuild purchase_orders):
  bash scripts/po_line_customer_hygiene.sh              # audit (dry-run)
  PO_HYGIENE_CONFIRM=YES bash scripts/po_line_customer_hygiene.sh --apply

Inside the purchase_orders container:
  python3 /app/scripts/po_line_customer_hygiene.py --dry-run
  PO_HYGIENE_CONFIRM=YES python3 /app/scripts/po_line_customer_hygiene.py --apply

Idempotent: sets po_notification_settings.po_line_customer_hygiene_v1 when apply succeeds.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import purchase_orders  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="PO line customer_id hygiene (legacy backfill fix).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Audit only: report counts, do not UPDATE (default unless --apply).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Run UPDATEs. Requires PO_HYGIENE_CONFIRM=YES unless --force-marker-skip is set.",
    )
    parser.add_argument(
        "--force-marker-skip",
        action="store_true",
        help="Apply even if po_line_customer_hygiene_v1 marker already exists (re-run repairs).",
    )
    args = parser.parse_args()

    dry_run = not args.apply
    if args.apply and not args.force_marker_skip:
        if os.getenv("PO_HYGIENE_CONFIRM", "").strip().upper() != "YES":
            print(
                "Refusing --apply: set PO_HYGIENE_CONFIRM=YES (or use --dry-run to audit only).",
                file=sys.stderr,
            )
            sys.exit(2)

    c = purchase_orders._conn()
    try:
        result = purchase_orders.hygiene_invalid_customer_item_lines(
            c,
            dry_run=dry_run,
            skip_marker=args.force_marker_skip,
        )
        if not dry_run and not result.get("skipped") and not result.get("error"):
            c.commit()
        else:
            c.rollback()
    finally:
        c.close()

    print(json.dumps(result, indent=2, sort_keys=True))

    if result.get("error"):
        sys.exit(1)
    if dry_run and int(result.get("bad_lines_before") or 0) > 0:
        print(
            "\nTo apply: PO_HYGIENE_CONFIRM=YES bash scripts/po_line_customer_hygiene.sh --apply",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
