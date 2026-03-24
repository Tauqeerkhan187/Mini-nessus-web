# Author:TK
# Date: 03-03-2026
# Purpose: db schema definition, scan for scan job, finiding for individual vulnerabilities

from datetime import datetime
from . import db

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    ports = db.Column(db.String(255), nullable=False) # example "22, 80, 443"
    profile = db.Column(db.String(50), nullable=False, default="quick")
    status = db.Column(db.String(50), nullable=False, default="queued") # queued/running/done/failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    error = db.Column(db.Text, nullable=True)

    celery_task_id = db.Column(db.String(128), nullable=True)

    ssh_user = db.Column(db.String(100), nullable=True)

    ssh_pass = db.Column(db.String(255), nullable=True)

    findings = db.relationship("Finding", backref="scan", cascade="all, delete-orphan", lazy=True)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False)

    port = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(100), nullable=True)
    banner = db.Column(db.Text, nullable=True)

    issue = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # LOW/MEDIUM/HIGH/CRITICAL
    recommendation = db.Column(db.Text, nullable=False)


