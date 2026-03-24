# Author: TK
# Date: 04-03-2026
# Purpose: validates target, run threaded port scan, grab banners on open ports, etc.

import ipaddress
from scanner.portscan import threaded_port_scan
from scanner.banners import grab_banner, guess_service, extract_version
from scanner.checks import build_findings
from scanner.ssh_checks import run_authenticated_checks

COMMON_PORTS_QUICK = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

COMMON_PORTS_FULL = list(range(1, 1025)) 

def _enforce_allowed(target: str, allowed_cidr: str):
    """
    Safety check, refuse to scan anything outside the kab network. 
    """

    net = ipaddress.ip_network(allowed_cidr, strict=False)
    ip = ipaddress.ip_address(target)
    if ip not in net:
        raise ValueError(
                f"Target {target} is outside allowed CIDR {allowed_cidr}."
                f"This scanner is restricted to lab networks only."
                )

def _parse_ports(ports_csv: str, profile: str) -> list[int]:
    """ Parse user-provided port list or use defaults based on profile."""

    if ports_csv.strip():
        return sorted({int(p.strip()) for p in ports_csv.split(",") if p.strip().isdigit()})

    return COMMON_PORTS_QUICK if profile == "quick" else COMMON_PORTS_FULL

def run_scan(target: str, ports_csv: str, profile: str, allowed_cidr: str) -> dict:
    """ Execute a full vulnerability scan against a target."""

    _enforce_allowed(target, allowed_cidr) # safety check

    ports = _parse_ports(ports_csv, profile) # determines which ports to scan

    open_ports = threaded_port_scan(target, ports, timeout=0.6, workers=200)

    services = []
    for port in open_ports:
        banner = grab_banner(target, port)
        service = guess_service(port, banner)
        version = extract_version(service, banner)

        services.append({
            "port": port,
            "service": service,
            "banner": banner,
            "version": version,
            })

    findings = build_findings(target, services)

    # Authenticated checks (only if creds provided)
    if ssh_username:
        auth_findings = run_authenticated_checks(
                target=target,
                port=22,
                username=ssh_username,
                password=ssh_password,
            )

            findings.extend(auth_findings)

    # re-sort after adding auth findings
    findings.sort(key=lambda f: (-_sev_score(f["severity"]), f.get("port", 0)))

    stats = {
            "ports_scanned": len(ports),
            "open_count": len(open_ports),
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low_count": sum(1 for f in findings if f["severity"] == "LOW"),

            }

    return {
            "target": target,
            "open_ports": open_ports,
            "services": services,
            "findings": findings,
            "stats": stats,

           }

