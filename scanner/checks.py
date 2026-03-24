# Author: TK
# Date: 05-03-2026
# Purpose: CVE detection and Enhanced vulnerability checks.
# Note: This is a curated subset of CVEs for lab demonstration. real scanners use feeds from NVD.

import re
from packaging import version as pkg_version

CVE_DATABASE = {
        "OpenSSH": [
            {
                "max_affected": "7.2",
                "cve": "CVE-2016-6515",
                "severity": "HIGH",
                "description": "OpenSSH before 7.3 allows DoS via long passowrds when using SHA-256/SHA-512 hashing.",
                "fix": "Upgrade OpenSSH to 7.3 or later.",

            },
            {
                "max_affected": "7.6",
                "cve": "CVE-2018-15473",
                "severity": "MEDIUM",
                "description": "OpenSSH through 7.7 allows username enumeration via timing side-channel.",
                "fix": "Upgrade OpenSSH to 7.8 or later.",

            },
            {
                "max_affected": "8.3",
                "cve": "CVE-2021-28041",
                "severity": "HIGH",
                "description": "OpenSSH before 8.4 has a double-free in ssh-agent PKCS#11 support.",
                "fix": "Upgrade OpenSSH to 8.4 or later.",

            },
            {
                "max_affected": "8.9",
                "cve": "CVE-2023-38408",
                "severity": "CRITICAL",
                "description": "OpenSSH before 9.3p2 has a remote code execution vulnerability in ssh-agent forwarding.",
                "fix": "Upgrade OpenSSH to 9.3p2 or later. Disable agent forwarding if not needed.",

            },
            {
                "max_affected": "9.7",
                "cve": "CVE-2024-6387",
                "severity": "CRITICAL",
                "description": "RegreSSHion: OpenSSH before 9.8 has a signal handler race condition allowing unauthenticated RCE on glibc-based Linux.",
                "fix": "Upgrade OpenSSH to 9.8 or later immediately.",

            },
        ],
        "Apache": [
            {
                "max_affected": "2.4.49",
                "cve": "CVE-2021-41773",
                "severity": "CRITICAL",
                "description": "Apache 2.4.50 insufficient fix for CVE-2021-41773, still allows path traversal and RCE.",
                "fix": "Upgrade Apache to 2.4.51 or later.",

            },
            {
                "max_affected": "2.4.53",
                "cve": "CVE-2022-31813",
                "severity": "HIGH",
                "description": "Apache before 2.4.54 may not send X-Forwaded-* headers, allowing IP-based auth bypass.",
                "Fix": "Upgrade Apache to 2.4.54 or later.",
            },
        ],
        "nginx": [
                {
                    "max_affected": "1.20.0",
                    "cve": "CVE-2021-23017",
                    "severity": "HIGH",
                    "description": "nginx before 1.20.1 has a DNS resolver off-by-one heap write vulnerability.",
                    "fix": "Upgrade nginx to 1.20.1 or later.",

                },
        ],

        "vsFTPd": [
            {
                "max_affected": "2.3.4",
                "cve": "CVE-2011-2523",
                "severity": "CRITICAL",
                "description": "vsFTPd 2.3.4 contains a backdoor allowing remote command execution via :) in username.",
                "fix": "Upgrade vsFTPd to 3.0.0 or later. Verify binary integrity.",

            },
        ],
        "ProFTPD": [
                {
                    "max_affected": "1.3.5",
                    "cve": "CVE-2015-3306",
                    "severity": "CRITICAL",
                    "description": "ProFTPD before 1.3.5e allows remote code execution via SITE CPFR/CPTO commands.",
                    "fix": "Upgrade ProFTPD to 1.3.5e or later.",

                },
            ],
    }

# -- Severity Scoring ---

SEVERITY_SCORES = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 5,
        "LOW": 3,
        "INFO": 1,

    }

def _sev_score(severity: str) -> int:
    return SEVERITY_SCORES.get(severity.upper(), 3)

def _parse_version(version_str: str) -> str:
    """ Extract just the numeric version from strings like 'OpenSSH_8.9p1' or 'Apache/2.4.49'. """
    match = re.search(r"([\d]+(?:\.[\d]+)*)", version_str)
    if match:
        return match.group(1)
    return ""

def _is_vulnerable(detected_version: str, max_affected: str) -> bool:
    """ Check if detected version is <= max_affected version."""
    try:
        return pkg_version.parse(detected_version) <= pkg_version.parse(max_affected)

    except Exception:
        return False

def _match_software(version_string: str) -> tuple[str, str]:
    """
    Given a version string like 'OpenSSh_8.9p1' or 'Apache/2.4.49',
    return (software_name, numeric_ver).
    """

    version_lower = version_string.lower()

    for software_name in CVE_DATABASE:
        if software_name.lower() in version_lower:
            numeric = _parse_version(version_string)
            return software_name, numeric

    return "", ""

# MAIN CHECK ENGINE

def build_findings(target: str, services: list[dict]) -> list[dict]:
    """
    Analyze discovered services and produce vulnerability findings.

    Each service dict has: port, service, banner, version

    Returns list of findings sorted by severity (worst first).

    """
    findings = []

    for svc in services:
        port = svc["port"]
        service = svc["service"]
        banner = svc.get("banner", "")
        version_str = svc.get("version", "")

        # CVE-based checks
        if version_str:
            software, numeric_ver = _match_software(version_str)

            if software and numeric_ver:
                cve_entries = CVE_DATABASE.get(software, [])

                for entry in cve_entries:
                    if _is_vulnerable(numeric_ver, entry["max_affected"]):
                        findings.append({
                            "port": port,
                            "service": service,
                            "banner": banner,
                            "version": version_str,
                            "cve": entry.get("cve", ""),
                            "issue": f"{entry.get('cve', 'UNKNOWN')}: {entry.get('description', '')[:120]}",
                            "severity": entry["severity"],
                            "recommendation": entry["fix"],

                        })

        # Service exposure checks (baseline findings)
        if service == "ssh":
            findings.append({
                "port": port,
                "service": "ssh",
                "banner": banner,
                "version": version_str,
                "cve": None,
                "issue": "SSH service exposed to network",
                "severity": "MEDIUM",
                "recommendation": "Restrict SSH access to admin subnet. Disable password auth and enforce key-based login. Use fail2ban."

            })

        elif service == "http":
            findings.append({
                "port": port,
                "service": "http",
                "banner": banner,
                "version": version_str,
                "cve": None,
                "issue": "HTTP service exposed",
                "severity": "LOW",
                "recommendation": "Enforce HTTPS/TLS. Remove default pages. Restrict admin panels. Keep web server patched.",

                })  

        elif service == "ftp":
            findings.append({
                "port": port,
                "service": "ftp",
                "banner": banner,
                "version": version_str,
                "cve": None,
                "issue": "FTP service exposed (unencrpyted file transfer protocol)",
                "severity": "HIGH",
                "recommendation": "Replace FTP with SFTP or SCP. If FTP is required, enforce TLS (FTPS) and restrict access.",

            })

        elif service == "telnet":
            findings.append({
                "port": port,
                "service": "telnet",
                "banner": banner,
                "version": version_str,
                "cve": None,
                "issue": "Telnet service exposed (sends credentials in plaintext)",
                    "severity": "CRITICAL",
                    "recommendation": "Disable Telnet immediately. Use SSH for remote access.",
            })

        elif service in ("mysql", "postgres", "redis"):
            findings.append({
                "port": port,
                "service": service,
                "banner": banner,
                "version": version_str,
                "cve": None,
                "issue": f"{service.upper()} database service exposed to network",
                "severity": "HIGH",
                "recommendation": f"Bind {service} to localhost only. Enforce authentication. Restrict access via firewall rules.",
            })

    # Sort: Highest severity first, then by port
    findings.sort(key=lambda f: (-_sev_score(f["severity"]), f.get("port", 0)))

    return findings



