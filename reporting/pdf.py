# Author: TK
# Date: 04-03-2026
# Purpose: Professional and clean report generator

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from datetime import datetime

def build_pdf_report(scan, results: dict, out_path: str):
    c = canvas.Canvas(out_path, pagesize=LETTER)
    w, h = LETTER

    y = h - 1 * inch
    c.setFont("Helvetica-Bold", 16)
    c.drawString(1*inch, y, "Mini-nessus Web - Vulnerability Report")
    
    y -= 0.35*inch
    c.setFont("Helvetica", 10)
    c.drawString(1*inch, y, f"Target: {results['target']}")
    y -= 0.2*inch
    c.drawString(1*inch, y, f"Scan_ID: {scan.id}    Profile: {scan.profile}    Status: {scan.status}")
    y -= 0.2*inch
    c.drawString(1*inch, y, f"Created: {scan.created_at}    Finished: {scan.finished_at}")

    y -= 0.35*inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1*inch, y, "Executive Summary")
    y -= 0.2*inch
    c.setFont("Helvetica", 10)
    open_ports = results.get("open_ports", [])
    c.drawString(1*inch, y, f"Open ports found: {' , '.join(map(str, open_ports)) if open_ports else 'None'}")

    y -= 0.35*inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1*inch, y, "FIndings")
    y -= 0.25*inch

    c.setFont("Helvetica", 10)
    for f in results.get("findings", []):
        if y < 1.2*inch:
            c.showPage()
            y = h - 1*inch
            c.setFont("Helvetica", 10)

        line = f"[{f['severity']}] Port {f.get('port')} ({f.get('service')}): {f['issue']}"

        c.drawString(1*inch, y, line[:110])
        y -= 0.18*inch
        rec = f"Possible Fixes: {f['recommendation']}"
        c.drawString(1.1*inch, y, rec[:110])
        y -= 0.25*inch

    y -= 0.2*inch
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(1*inch, 0.8*inch, "Lab-only tool. Use only on systems you own or are authorized to test.")
    c.save()


