# Author: TK
# Date: 04-03-2026
# Purpose: modular engine for scanner

import ipaddress
from scanner.portscan import threaded_port_scan
from scanner.banners import grab_banner, guess_service
from scanner.checks import build_findings

COMMON_PORTS_QUICK = [22, 80, 443, 21, 25, 110, 143, 3306, 5432, 6379, 8080]
COMMON_PORTS_FULL = list(range(1, 1025)) # light ver due to hardware restraints

def _enforce_allowed(target: str, allowed_cidr: str):
    net = ipaddress.ip_network(allowed_cidr, strict=False)
    ip = ipaddress.ip_address(target)
    if ip not in net:
        raise ValueError(f"Target {target} is outside allowed CIDR {allowed_cidr} (lab-only).")

def _parse_ports(ports_csv: str, profile: str):
    if ports_csv.strip():
        return sorted({int(p.strip()) for p in ports_csv.split(",") if p.strip()})
    return COMMON_PORTS_QUICK if profile == "quick" else COMMON_PORTS_FULL

def run_scan(target: str, ports_csv: str, profile: str, allowed_cidr: str):
    _enforce_allowed(target, allowed_cidr)
    ports = _parse_ports(ports_csv, profile)

    open_ports = threaded_port_scan(target, ports, timeout=0.6, workers=200)

    services = []
    for port in open_ports:
        banner = grab_banner(target, port)
        service = guess_service(port, banner)
        services.append({"port": port, "service": service, "banner": banner})

    findings = build_findings(target, services)

    return {
            "target": target,
            "open_ports": open_ports,
            "services": services,
            "findings": findings,

        }

