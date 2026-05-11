"""Best-effort quote PDF/image text extraction for purchase order draft suggestions."""
from __future__ import annotations

import io
import re
from typing import Any, Dict, List, Optional, Tuple

MAX_QUOTE_BYTES = 8 * 1024 * 1024
_ALLOWED_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/bmp",
    "image/tiff",
}

_SKIP_LINE_RE = re.compile(
    r"^(quote|quotation|tax\s*invoice|invoice|pro\s*forma|purchase\s*order|"
    r"page\s+\d+\s+of\s+\d+|tel:|phone:|email:|vat\s*no|reg\.?\s*no).*$",
    re.I,
)
_MONEY_RE = re.compile(r"R?\s*[\d,]+\.\d{2}")
_LINE_ITEM_RE = re.compile(
    r"^(?P<desc>.+?)\s+(?P<qty>\d+(?:\.\d+)?)\s+(?P<unit>R?\s*[\d,]+\.\d{2})\s+(?P<line>R?\s*[\d,]+\.\d{2})\s*$",
    re.I,
)
_QTY_PRICE_RE = re.compile(
    r"^(?P<desc>.+?)\s+(?P<qty>\d+(?:\.\d+)?)\s+[@x]\s*(?P<unit>R?\s*[\d,]+\.\d{2})\s*$",
    re.I,
)


def _money_float(raw: str) -> float:
    s = (raw or "").strip().replace(",", "")
    if s.upper().startswith("R"):
        s = s[1:].strip()
    try:
        return round(float(s), 2)
    except ValueError:
        return 0.0


def _normalize_lines(text: str) -> List[str]:
    out: List[str] = []
    for raw in (text or "").replace("\r", "\n").split("\n"):
        line = re.sub(r"\s+", " ", raw).strip()
        if line:
            out.append(line)
    return out


def _extract_pdf_text(blob: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise ValueError("PDF parser is not available on this server.") from e
    reader = PdfReader(io.BytesIO(blob))
    parts: List[str] = []
    for page in reader.pages:
        parts.append(page.extract_text() or "")
    return "\n".join(parts).strip()


def _guess_supplier(lines: List[str]) -> str:
    for line in lines[:12]:
        if _SKIP_LINE_RE.match(line):
            continue
        if len(line) < 3 or len(line) > 120:
            continue
        if _MONEY_RE.search(line):
            continue
        return line
    return ""


def _parse_line_items(lines: List[str]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen = set()
    for line in lines:
        if _SKIP_LINE_RE.match(line):
            continue
        low = line.lower()
        if any(k in low for k in ("subtotal", "sub-total", "total", "vat", "tax", "bank", "account")):
            continue
        m = _LINE_ITEM_RE.match(line) or _QTY_PRICE_RE.match(line)
        if not m:
            continue
        desc = (m.group("desc") or "").strip(" -:\t")
        qty = max(1, int(round(float(m.group("qty")))))
        unit = _money_float(m.group("unit"))
        if not desc or unit <= 0:
            continue
        key = (desc.lower(), qty, unit)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "description": desc[:240],
                "quantity": qty,
                "unit_price": unit,
            }
        )
    return items[:40]


def _suggestion_from_text(text: str, filename: str) -> Tuple[Dict[str, Any], List[str]]:
    warnings: List[str] = []
    lines = _normalize_lines(text)
    if not lines:
        warnings.append("No readable text was found in this file.")
        return (
            {
                "supplier_name": "",
                "department_name": "",
                "notes": f"Quote upload: {filename}",
                "items": [],
            },
            warnings,
        )

    supplier = _guess_supplier(lines)
    items = _parse_line_items(lines)
    if not items:
        warnings.append("No line items were detected automatically. Add items manually.")
    if not supplier:
        warnings.append("Supplier name was not detected automatically.")

    notes = f"Imported from quote: {filename}"
    return (
        {
            "supplier_name": supplier,
            "department_name": "",
            "notes": notes,
            "items": items,
        },
        warnings,
    )


def parse_quote_upload(filename: str, content_type: str, blob: bytes) -> Dict[str, Any]:
    safe_name = (filename or "quote").strip() or "quote"
    if not blob:
        raise ValueError("Uploaded file is empty.")
    if len(blob) > MAX_QUOTE_BYTES:
        raise ValueError("Quote file is too large (max 8 MB).")

    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    lower_name = safe_name.lower()
    is_pdf = ctype == "application/pdf" or lower_name.endswith(".pdf")
    is_image = ctype.startswith("image/") or lower_name.endswith((".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff"))

    if is_pdf:
        text = _extract_pdf_text(blob)
        suggestion, warnings = _suggestion_from_text(text, safe_name)
        return {
            "suggestion": suggestion,
            "warnings": warnings,
            "parser": "pdf_text",
        }

    if is_image:
        return {
            "suggestion": {
                "supplier_name": "",
                "department_name": "",
                "notes": f"Quote upload (image): {safe_name}",
                "items": [],
            },
            "warnings": [
                "Image OCR is not enabled yet. PDF quotes with selectable text work best.",
            ],
            "parser": "image_unsupported",
        }

    if ctype and ctype not in _ALLOWED_TYPES:
        raise ValueError("Unsupported file type. Upload a PDF or image quote.")
    raise ValueError("Unsupported file type. Upload a PDF or image quote.")
