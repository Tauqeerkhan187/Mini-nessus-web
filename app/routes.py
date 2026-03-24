# Author: TK
# Date: 24-03-2026
# Purpose: Web routes for dashboard, scan creation, scan viewing, PDF download, and dashboard API

import os

from flask import (
    Blueprint,
    current_app,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    flash,
    jsonify,
)
from sqlalchemy import func

from app import db
from app.models import Scan, Finding
from app.tasks import run_scan_task

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("index.html", scans=scans)


@bp.get("/api/dashboard")
def dashboard_data():
    severity_counts = dict(
        Finding.query.with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )

    scan_timeline = [
        {
            "id": scan.id,
            "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "status": scan.status,
        }
        for scan in Scan.query.order_by(Scan.created_at.asc()).all()
    ]

    return jsonify({
        "severity_counts": severity_counts,
        "scan_timeline": scan_timeline,
    })


@bp.get("/scan/new")
def new_scan():
    return render_template(
        "new_scan.html",
        allowed=current_app.config["ALLOWED_CIDR"],
    )


@bp.post("/scan/new")
def create_scan():
    target = request.form.get("target", "").strip()
    ports = request.form.get("ports", "").strip()
    profile = request.form.get("profile", "quick").strip()

    ssh_user = request.form.get("ssh_user", "").strip()
    ssh_pass = request.form.get("ssh_pass", "").strip()

    if not target:
        flash("Target is required.", "error")
        return redirect(url_for("main.new_scan"))

    if profile not in ("quick", "full"):
        profile = "quick"

    scan = Scan(
        target=target,
        ports=ports or "",
        profile=profile,
        status="queued",
        ssh_user=ssh_user or None,
        auth_enabled=bool(ssh_user and ssh_pass),
    )

    db.session.add(scan)
    db.session.commit()

    task = run_scan_task.delay(
        scan.id,
        ssh_user or None,
        ssh_pass or None,
    )

    scan.celery_task_id = task.id
    db.session.commit()

    return redirect(url_for("main.view_scan", scan_id=scan.id))


@bp.get("/scan/<int:scan_id>")
def view_scan(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return ("Scan not found", 404)

    return render_template("scan.html", scan=scan)


@bp.get("/scan/<int:scan_id>/pdf")
def download_pdf(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return ("Scan not found", 404)

    pdf_path = os.path.join(current_app.instance_path, f"scan_{scan.id}.pdf")

    if not os.path.exists(pdf_path):
        flash("PDF not generated yet. The scan may still be running or may have failed.", "error")
        return redirect(url_for("main.view_scan", scan_id=scan.id))

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"scan_{scan.id}_report.pdf",
    )
