# Author: TK
# Date: 05-03-2026
# Purpose: Web routes and endpoints. UI logic (connects UI, database, celery)

import os
from flask import Blueprint, current_app, render_template, request, redirect, url_for, send_file, flash
from app import db
from app.models import Scan
from app.tasks import run_scan_task

bp = Blueprint("main", __name__)

@bp.get("/")
def index():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("index.html", scans=scans)

@bp.get("/scan/new")
def new_scan():
    return render_template("new_scan.html", allowed=current_app.config["ALLOWED_CIDR"])

@bp.post("/scan/new")
def create_scan():
    target = request.form.get("target", "").strip()
    ports = request.form.get("ports", "").strip()
    profile = request.form.get("profile", "quick").strip()

    if not target:
        flash("Target is required.", "error")
        return redirect(url_for("main.new_scan"))

    scan = Scan(target=target, ports=ports or "", profile=profile, status="queued")
    db.session.add(scan)
    db.session.commit()

    task = run_scan.task.delay(scan.id)
    scan.celery_task_id = task.id
    db.session.commit()

    return redirect(url_for("main.view_scan", scan_id=scan.id))

@bp.get("/scan/<int:scan_id>")
def view_scan(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return ("Not found", 404)
    return render_template("scan.html", scan=scan)

@bp.get("/scan/<int:scan_id>/pdf")
def download_pdf(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return ("Not found", 404)

    pdf_path = f"{current_app.instance_path}/scan_{scan.id}.pdf"
    if not os.path.exists(pdf_path):
        flash("PDF not generated yet (scan still running or failed).", "error")
        return redirect(url_for("main.view_scan", scan_id=scan.id))

    return send_file(pdf_path, as_attachment=True, download_name=f"scan_{scan.id}_report.pdf")

