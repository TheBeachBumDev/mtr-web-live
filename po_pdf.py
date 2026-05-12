import io
import os
import re
from typing import Any, Dict, List, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

COMPANY_LINES = (
    "Wibersolutions (PTY) Ltd",
    "Unit 3 Southern Cross Village",
    "Capricorn Park",
    "Muizenberg 7950",
    "VAT registration: 4650279450",
)


def purchase_order_pdf_filename(po: Dict[str, Any]) -> str:
    po_number = str(po.get("po_number") or "").strip()
    if not po_number:
        po_number = f"PO-{int(po.get('id') or 0)}"
    safe = re.sub(r"[^\w\-.]+", "-", po_number).strip("-") or "draft"
    return f"Wibernet-{safe}.pdf"


def po_invoice_recipients() -> List[str]:
    raw = (os.getenv("PO_INVOICE_EMAIL", "creditors@wibersolutions.co.za") or "").strip()
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def deliver_po_invoice_email(po: Dict[str, Any], pdf_bytes: bytes, filename: str) -> Tuple[bool, str]:
    recipients = po_invoice_recipients()
    if not recipients:
        return False, "No invoice recipients configured"
    from notifications.channels.email_smtp import send_po_invoice_email

    last_error = ""
    for recipient in recipients:
        ok, _, err = send_po_invoice_email(recipient, po, pdf_bytes, filename)
        if not ok:
            last_error = err or f"Failed sending invoice to {recipient}"
            break
    if last_error:
        return False, last_error
    return True, ""


def build_purchase_order_pdf(po: Dict[str, Any]) -> bytes:
    def _money(v: Any) -> str:
        try:
            return f"R {float(v or 0):,.2f}"
        except Exception:
            return "R 0.00"

    def _txt(v: Any) -> str:
        return str(v or "-")

    def _draw_logo(c: canvas.Canvas, page_w: float, page_h: float, margin: float) -> None:
        logo_candidates = (
            "/app/static/Wibernet-logo.png",
            os.path.join(os.getcwd(), "static", "Wibernet-logo.png"),
        )
        logo_path = next((p for p in logo_candidates if os.path.isfile(p)), "")
        if logo_path:
            try:
                img = ImageReader(logo_path)
                iw, ih = img.getSize()
                target_w = 42 * mm
                scale = target_w / float(iw or 1)
                target_h = float(ih or 1) * scale
                x = page_w - margin - target_w
                y = page_h - margin - target_h + 2 * mm
                c.drawImage(img, x, y, width=target_w, height=target_h, preserveAspectRatio=True, mask="auto")
                return
            except Exception:
                pass
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(colors.HexColor("#0b5ea8"))
        c.drawRightString(page_w - margin, page_h - margin + 1 * mm, "WIBERNET")
        c.setFillColor(colors.black)

    def _box_row(c: canvas.Canvas, x: float, y: float, key: str, val: str, width: float) -> float:
        c.setFillColor(colors.HexColor("#f7f9fc"))
        c.rect(x, y - 7 * mm, width, 7 * mm, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#4a5568"))
        c.setFont("Helvetica-Bold", 8)
        c.drawString(x + 2 * mm, y - 4.8 * mm, key)
        c.setFillColor(colors.black)
        c.setFont("Helvetica", 9)
        c.drawRightString(x + width - 2 * mm, y - 4.8 * mm, val[:80])
        return y - 7.5 * mm

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    x = 14 * mm
    right = w - 14 * mm
    y = h - 16 * mm

    _draw_logo(c, w, h, x)
    company_y = y
    c.setFont("Helvetica-Bold", 10)
    c.drawString(x, company_y, COMPANY_LINES[0])
    company_y -= 4.5 * mm
    c.setFont("Helvetica", 8.5)
    c.setFillColor(colors.HexColor("#334155"))
    for line in COMPANY_LINES[1:]:
        c.drawString(x, company_y, line)
        company_y -= 4.2 * mm
    c.setFillColor(colors.black)
    y = company_y - 6 * mm

    c.setFont("Helvetica-Bold", 18)
    c.drawString(x, y, "Purchase Order")
    c.setFillColor(colors.HexColor("#4a5568"))
    c.setFont("Helvetica", 9)
    c.drawString(x, y - 6 * mm, f"PO Number: {_txt(po.get('po_number'))}")
    c.drawString(x, y - 10.5 * mm, f"Generated: {_txt(po.get('created_at'))}")
    c.setFillColor(colors.black)
    y -= 16 * mm

    # Header card
    card_w = right - x
    c.setStrokeColor(colors.HexColor("#d9e2ec"))
    c.roundRect(x, y - 33 * mm, card_w, 33 * mm, 2 * mm, fill=0, stroke=1)
    left_x = x + 2 * mm
    right_x = x + card_w / 2 + 1 * mm
    row_y = y - 2 * mm
    left_w = card_w / 2 - 3 * mm
    right_w = left_w
    row_y = _box_row(c, left_x, row_y, "Supplier", _txt(po.get("supplier_name")), left_w)
    row_y = _box_row(c, left_x, row_y, "Department", _txt(po.get("department_name")), left_w)
    row_y = _box_row(c, right_x, y - 2 * mm, "Requested By", _txt(po.get("requested_by_username")), right_w)
    row_y = _box_row(c, right_x, row_y, "Status", _txt(po.get("status")).replace("_", " ").title(), right_w)
    y -= 38 * mm

    c.setFont("Helvetica-Bold", 10)
    c.drawString(x, y, "Line Items")
    y -= 7 * mm

    # Table header
    c.setFillColor(colors.HexColor("#0f172a"))
    c.rect(x, y - 6.5 * mm, right - x, 6.5 * mm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 8)
    cols = [x + 2 * mm, x + 108 * mm, x + 125 * mm, x + 150 * mm, x + 178 * mm]
    c.drawString(cols[0], y - 4.5 * mm, "Description")
    c.drawRightString(cols[1], y - 4.5 * mm, "Qty")
    c.drawRightString(cols[2], y - 4.5 * mm, "Unit")
    c.drawRightString(cols[3], y - 4.5 * mm, "Tax")
    c.drawRightString(cols[4], y - 4.5 * mm, "Total")
    c.setFillColor(colors.black)
    y -= 9 * mm

    c.setFont("Helvetica", 8.5)
    items: List[Dict[str, Any]] = list(po.get("items") or [])
    stripe = False
    for it in items:
        if y < 36 * mm:
            c.showPage()
            y = h - 20 * mm
            c.setFont("Helvetica", 8.5)
        if stripe:
            c.setFillColor(colors.HexColor("#f8fafc"))
            c.rect(x, y - 5.8 * mm, right - x, 6 * mm, fill=1, stroke=0)
            c.setFillColor(colors.black)
        stripe = not stripe
        c.drawString(cols[0], y - 4.0 * mm, _txt(it.get("description"))[:72])
        c.drawRightString(cols[1], y - 4.0 * mm, _txt(it.get("quantity")))
        c.drawRightString(cols[2], y - 4.0 * mm, _money(it.get("unit_price")))
        c.drawRightString(cols[3], y - 4.0 * mm, _money(it.get("tax_amount")))
        c.drawRightString(cols[4], y - 4.0 * mm, _money(it.get("line_total")))
        y -= 6.2 * mm

    y -= 2 * mm
    c.setStrokeColor(colors.HexColor("#cbd5e1"))
    c.line(x, y, right, y)
    y -= 10 * mm
    c.setFont("Helvetica", 10)
    c.drawRightString(right - 36 * mm, y, "Subtotal:")
    c.setFont("Helvetica-Bold", 10)
    c.drawRightString(right, y, _money(po.get("subtotal")))
    y -= 6 * mm
    c.setFont("Helvetica", 10)
    c.drawRightString(right - 36 * mm, y, "Tax:")
    c.setFont("Helvetica-Bold", 10)
    c.drawRightString(right, y, _money(po.get("tax")))
    y -= 6 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawRightString(right - 36 * mm, y, "Total:")
    c.drawRightString(right, y, _money(po.get("total")))

    notes = _txt(po.get("notes"))
    if notes and notes != "-":
        y -= 12 * mm
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x, y, "Notes")
        y -= 5 * mm
        c.setFont("Helvetica", 8.5)
        c.setFillColor(colors.HexColor("#334155"))
        c.drawString(x, y, notes[:140])
        c.setFillColor(colors.black)

    c.save()
    out = buf.getvalue()
    buf.close()
    return out
