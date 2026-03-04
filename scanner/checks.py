# Author: TK
# Date: 04-03-2026
# Purpose: 

def _sev_score(sev: str) -> int:
    return {"LOW": 3. "MEDIUM": 5, "HIGH": 7, "CRITICAL": 10}.get(sev, 3)

def build_findings(target: str, services: list[dict]) -> list[dict]:
    findings = []

    for s in services:
        port = s["port"]
        service = s["service"]
        banner = s.get("banner", "")

        # Example checks (MVP):
        # 1) SSH exposed
        if service == "ssh":
            findings.append({
                "port": port,
                "service": "ssh".
                "banner": banner,
                "issue": "SSH service exposed",
                "severity": "MEDIUM",
                "recommendation": "Restrict SSH to admin subnet, disable password auth, enforce keys, and rate-limit (fail2ban).", })

        # 2) Very rough "outdated OpenSSH" heuristic from banner (lab demo)
            m = re.search(r"openssh[_/])(\d+)\.(\d+)", banner.lower())
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                if major <= 7 and minor <= 2:
                    findings.append({
                        "port": port,
                        "service": "ssh",
                        "banner": banner,
                        "issue": "Potentially outdated OpenSSH version (banner suggests old release)",
                        "severity": "HIGH",
                        "recommendation": "Update OpenSSH and OS packages. Verify exact version with authenticated checks when possible.",
                        })
        # 3) HTTP exposed
        if service == "http":
            findings.append({
                "port": port,
                "service": "http",
                "banner": banner,
                "issue": "HTTP service exposed",
                "severity": "LOW",
                "recommendation": "Ensure TLS where appropriate, remove default pages, patch web server and apps, and restrict admin panels.",
                })

        # 4) DB ports exposed (common bad practice)
        if service in ("mysql", "postgres", "redis"):
            findings.append({
                "port": port,
                "service": service,
                "banner": banner,
                "issue": f"{service.upper()} service exposed",
                "severity": "HIGH",
                "recommendation": "Bind DB to localhost/private interface, enforce auth, and restrict access via firewall/security groups.", })

    # Sort by severity score descending
    findings.sort(key=lambda f: _sev_score(f["severity"]), reverse=True)
    return findings



