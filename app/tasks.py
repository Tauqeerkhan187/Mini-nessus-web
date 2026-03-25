# Author: TK
# Date: 04-03-2026
# Purpose: Celery tasks for running scans and storing results

from datetime import datetime

from app.celery_app import celery
from app import create_app, db
from app.models import Scan, Finding

from scanner.engine import run_scan
from reporting.pdf import build_pdf_report
from scanner.scoring import calculate_scan_risk

@celery.task(bind=True)
def run_scan_task(
    self,
    scan_id: int,
    ssh_user: str | None = None,
    ssh_pass: str | None = None,
):
    app = create_app()

    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {"ok": False, "error": "Scan not found"}

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.error = None
        db.session.commit()

        try:
            results = run_scan(
                target=scan.target,
                ports_csv=scan.ports,
                profile=scan.profile,
                allowed_cidr=app.config["ALLOWED_CIDR"],
                ssh_username=ssh_user or "",
                ssh_password=ssh_pass or "",
            )

            risk_score, risk_level = calculate_risk_score(results["findings"])
            scan.risk_score = risk_score
            scan.risk_level = risk_level

            # Remove any previous findings for this scan
            Finding.query.filter_by(scan_id=scan.id).delete()

            # Save new findings
            for finding in results["findings"]:
                db.session.add(
                    Finding(
                        scan_id=scan.id,
                        port=finding.get("port"),
                        service=finding.get("service"),
                        banner=finding.get("banner"),
                        version=finding.get("version"),
                        issue=finding["issue"],
                        severity=finding["severity"],
                        recommendation=finding["recommendation"],
                        cve=finding.get("cve"),
                        cvss_score=finding.get("cvss_score", 0.0),
                        cvss_vector=finding.get("cvss_vector"),
                        impact=finding.get("impact"),
                        rule_key=finding.get("rule_key"),
                    )
                )

            scan.status = "done"
            scan.finished_at = datetime.utcnow()
            db.session.commit()

            # Generate PDF report
            pdf_path = f"{app.instance_path}/scan_{scan.id}.pdf"
            build_pdf_report(scan, results, pdf_path)

            return {
                "ok": True,
                "scan_id": scan.id,
                "pdf_path": pdf_path,
            }

        except Exception as e:
            import traceback
            traceback.print_exc()

            scan.status = "failed"
            scan.error = str(e)
            scan.finished_at = datetime.utcnow()
            db.session.commit()

            return {"ok": False, "error": str(e)}
