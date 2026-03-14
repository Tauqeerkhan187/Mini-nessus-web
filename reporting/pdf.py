# Author: TK
# Date: 04-03-2026
# Purpose: Professional and clean vulnerability assessment report.

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from datetime import datetime

SEVERITY_COLORS = {
        "CRITICAL": HexColor("#DC2626"), #Red
        "HIGH": HexColor("#EA580C"), #Orange
        "MEDIUM": HexColor("#CA8A04"), #Yellow-brown
        "LOW": HexColor("#2563EB"), #Blue
        "INFO": HexColor("#6B7280"), #Gray
    }

def build_pdf_report(scan, results: dict, out_path: str):
    c = canvas.Canvas(out_path, pagesize=LETTER)
    w, h = LETTER
    margin = 1 * inch

    y = h - 1.2 * inch

    # Title bar

    c.setFillColor(HexColor("#1E293B"))
    c.rect(0, y - 10, w, 50, fill=True, stroke=False)
    c.setFillColor(HexColor("#FFFFFF"))
    c.setFont("Helvetica-Bold", 20)
    c.drawString(margin, y + 5, "Mini-Nessus - Vulnerability Assessment Report")

    # Sub
    y -= 0.5 * inch
    c.setFillColor(HexColor("#1E293B"))
    c.setFont("Helvetica", 11)
    c.drawString(margin, y, f"Target: {results['target']}")
    y -= 0,22 * inch
    c.drawString(margin, y, f"Scan ID: {scan.id}   Profile: {scan.profile}   Status: {scan.status}")
    y -= 0,22 * inch
    c.drawString(margin, y, f"Started: {scan.started_at or 'N/A'}  Completed: {scan.finished_at or 'N/A'}")

    # Executive Summary
    y -= 0.5 * inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "Executive Summary")
    y -= 0.05 * inch
    c.setStrokeColor(HexColor("#3BB2F6"))
    c.line(margin, y, margin + 2 * inch, y)

    y -= 0.3 * inch
    c.setFont("Helvetica", 10)
    c.setFillColor(HexColor("#374151"))

    stats = results.get("stats", {})
    open_ports = results.get("open_ports", [])

    summary_lines = [
            f"Ports scanned: {stats.get('ports_scanned', 'N/A')}",
            f"Open ports found: {len(open_ports)} ({', '.join(map(str, open_ports)) if open_ports else 'None'})",
            f"Total findings: {stats.get('finding_count', 0)}",
            "",
            f"Critical: {stats.get('critical_count', 0)}  "
            f"High: {stats.get('high_count', 0)}  "
            f"Medium: {stats.get('medium_count', 0)}  "
            f"Low: {stats.get('low_count', 0)}",

        ]

    for line in summary_lines:
        c.drawString(margin, y, line)
        y -= 0.2 * inch

    # Severity bar chart
    y -= 0.15 * inch
    bar_x = margin
    bar_height = 14
    max_width = 3 * inch
    total_findings = max(stats.get("finding_count", 1), 1)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats.get(f"{sev.lower()}_count", 0)
        bar_w = max((count / total_findings) * max_width, 0)

        # Label
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(SEVERITY_COLORS.get(sev, HexColor("#6B7280")))
        c.drawString(bar_x, y + 2, f"{sev}")

        # Bar
        c.setFillColor(SEVERITY_COLORS.get(sev, HexColor("6B7280")))
        c.rect(bar_x + 1.0 * inch, y, bar_w, bar_height, fill=True, stroke=False)

        # Count
        c.setFillColor(HexColor("#374151"))
        c.setFont("Helvetica", 9)
        c.drawString(bar_x + 1.0 * inch + bar_w + 5, y +2, str(count))

        y -= 0.25 * inch

    # Detailed Findings
    y -= 0.3 * inch
    c.setFillColor(HexColor("1E293B"))
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "Detailed Findings")
    y -= 0.05 * inch
    c.setStrokeColor(HexColor("#3B82F6"))
    c.line(margin, y, margin + 2 * inch, y)
    y -= 0.3 * inch

    findings = results.get("findings", [])
    for i, f in enumerate(findings, 1):
        # Check if we need a new page
        if y < 1.5 * inch:
            c.showPage()
            y = h - 1 * inch

        sev = f.get("severity", "LOW")
        sev_color = SEVERITY_COLORS.get(sev, HexColor("#6B7280"))

        # Severity badge
        c.setFillColor(sev_color)
        c.roundRect(margin, y - 3, 65, 16, 3, fill=True, stroke=False)
        c.setFillColor(HexColor("#FFFFFF"))
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(margin + 32.5, y + 1, sev)

        # Finding title
        c.setFillColor(HexColor("#1E293B"))
        c.setFont("Helvetica-Bold", 10)
        port_str = f"Port {f.get('port', '?')}" if f.get("port") else ""
        svc_str = f" ({f.get('service', '')})" if f.get("service") else ""
        c.drawString(margin + 75, y, f"#{i}  {port_str}{svc_str}")

        y -= 0.22 * inch

        # CVE ID
        cve = f.get("cve")
        if cve:
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(HexColor("#7C3AED"))
            c.drawString(margin + 0.2 * inch, y, cve)
            y -= 0.18 * inch

        # Issue desc
        c.setFont("Helvetica", 9)
        c.setFillColor(HexColor("#374151"))
        issue_text = f.get("issue", "")
        # word wrap at ~90 chars
        while issue_text:
            line = issue_text[:100]
            c.drawString(margin + 0.2 * inch, y, line)
            issue_text = issue_text[100:]
            y -= 0.16 * inch

        # vers info
        ver = f.get("version", "")
        if ver:
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColor(HexColor("#6B7280"))
            c.drawString(margin + 0.2 * inch, y, f"Detected version: {ver}")
            y -= 0.16 * inch

        # Recommedation
        c.setFont("Helvetica", 9)
        c.setFillColor(HexColor("#065F46"))
        rec = f"Fix: {f.get('recommendation', 'N/A')}"
        while rec:
            line = rec[:100]
            c.drawString(margin + 0.2 * inch, y, line)
            rec = rec[100:]
            y -= 0.16 * inch

        y -= 0.15 * inch # gap between findings

    # Footer
    if y < 1.2 * inch:
        c.showPage()
        y = h - 1 * inch

    y -= 0.3 * inch
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(HexColor("#1E293B"))
    c.drawString(margin, y, "Disclaimer")
    y -= 0.25 * inch
    c.setFont("Helvetica-Oblique", 8)
    c.setFillColor(HexColor("#6B7280"))
    disclaimer_lines = [
            "This scan was performed in controlled lab environment on authorized targets only."
            "Findings are based on banner analysis and version heuristics, not authenticated checks."
            "False positives are possible. Verify findings manually before taking remediation action."
            "This tool is for educational and authorized testing purposes only."

    ]

    for line in disclaimer_lines:
        c.drawString(margin, y, line)
        y -= 0.16 * inch


    c.save()


