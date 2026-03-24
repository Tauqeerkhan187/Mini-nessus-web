# Author: TK
# Date: 04-03-2026
# Purpose: tasks for app

from datetime import datetime
from app.celery_app import celery
from app import create_app, db
from app.models import Scan, Finding

from scanner.engine import run_scan
from reporting.pdf import build_pdf_report

@celery.task(bind=True)
def run_scan_task(self, scan_id: int, ssh_user: str | None = None, ssh_pass: str | None = None):
    app = create_app()
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {"ok": False, "error": "Scan not found"}

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.session.commit()

        try:
            # Execute scan engine
            results = run_scan(
                    target=scan.target,
                    ports_csv=scan.ports,
                    profile=scan.profile,
                    allowed_cidr=app.config["ALLOWED_CIDR"],
                    ssh_username=scan.ssh_user or "",
                    ssh_password=scan.ssh_pass or "",
                    )

            # Store findings
            Finding.query.filter_by(scan_id=scan.id).delete()
            for f in results["findings"]:
                db.session.add(Finding(
                    scan_id=scan.id,
                    port=f.get("port"),
                    service=f.get("service"),
                    banner=f.get("banner"),
                    version=f.get("version"),
                    issue=f["issue"],
                    severity=f["severity"],
                    recommendation=f["recommendation"],
                    cve=f.get("cve"),
                    ))
                
            scan.status = "done"
            scan.finished_at = datetime.utcnow()
            db.session.commit()

                # Generate PDF into instance folder
            pdf_path = f"{app.instance_path}/scan_{scan.id}.pdf"
            build_pdf_report(scan, results, pdf_path)

            return {"ok": True, "scan_id": scan.id, "pdf_path": pdf_path}

        except Exception as e:
            import traceback
            traceback.print_exc()
            scan.status = "failed"
            scan.error = str(e)
            scan.finished_at = datetime.utcnow()
            db.session.commit()
            return {"ok": False, "error": str(e)}

