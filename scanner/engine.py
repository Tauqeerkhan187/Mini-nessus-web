# Author: TK
# Date: 04-03-2026
# Purpose: Validate target, run threaded port scan, grab banners, identify services, and generate findings

import ipaddress

from scanner.portscan import threaded_port_scan
from scanner.banners import grab_banner, guess_service, extract_version
from scanner.checks import build_findings, _sev_score
from scanner.ssh_checks import run_authenticated_checks


COMMON_PORTS_QUICK = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
    3306, 3389, 5432, 5900, 6379, 8080, 8443
]

COMMON_PORTS_FULL = list(range(1, 1025))


def _enforce_allowed(target: str, allowed_cidr: str) -> None:
    """
    Safety check: refuse to scan anything outside the lab network.
    """
    net = ipaddress.ip_network(allowed_cidr, strict=False)
    ip = ipaddress.ip_address(target)

    if ip not in net:
        raise ValueError(
            f"Target {target} is outside allowed CIDR {allowed_cidr}. "
            "This scanner is restricted to lab networks only."
        )


def _parse_ports(ports_csv: str, profile: str) -> list[int]:
    """
    Parse user-provided port list or use defaults based on the selected profile.
    """
    if ports_csv.strip():
        return sorted(
            {
                int(p.strip())
                for p in ports_csv.split(",")
                if p.strip().isdigit()
            }
        )

    return COMMON_PORTS_QUICK if profile == "quick" else COMMON_PORTS_FULL


def run_scan(
    target: str,
    ports_csv: str,
    profile: str,
    allowed_cidr: str,
    ssh_username: str = "",
    ssh_password: str = "",
) -> dict:
    """
    Execute a full vulnerability scan against a target.
    """
    _enforce_allowed(target, allowed_cidr)

    ports = _parse_ports(ports_csv, profile)

    open_ports = threaded_port_scan(
        target=target,
        ports=ports,
        timeout=0.6,
        workers=200,
    )

    services = []
    for port in open_ports:
        banner = grab_banner(target, port)
        service = guess_service(port, banner)
        version = extract_version(service, banner)

        services.append(
            {
                "port": port,
                "service": service,
                "banner": banner,
                "version": version,
            }
        )

    findings = build_findings(target, services)

    # Authenticated SSH checks only if both username and password are provided
    if ssh_username and ssh_password and 22 in open_ports:
        auth_findings = run_authenticated_checks(
            target=target,
            port=22,
            username=ssh_username,
            password=ssh_password,
        )
        findings.extend(auth_findings)

    # Re-sort after adding auth findings
    findings.sort(
        key=lambda finding: (-_sev_score(finding["severity"]), finding.get("port") or 0)
    )

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
