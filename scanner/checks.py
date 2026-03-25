# Author: TK
# Date: 24-03-2026
# Purpose: Rule-based findings engine with CVE matching and baseline exposure checks

import re
from packaging import version as pkg_version
from scanner.scoring import enrich_finding

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 5,
    "LOW": 3,
    "INFO": 1,
}


def _sev_score(severity: str) -> int:
    return SEVERITY_SCORES.get((severity or "").upper(), 3)

def calculate_risk_score(findings: list[dict]) -> tuple[int, str]:
    score = sum(_sev_score(f.get("severity", "")) for f in findings)

    if score >= 50:
        level = "CRITICAL"
    elif score >= 30:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


CVE_DATABASE = {
    "OpenSSH": [
        {
            "max_affected": "7.2",
            "cve": "CVE-2016-6515",
            "severity": "HIGH",
            "description": "OpenSSH before 7.3 allows denial of service via long passwords when using SHA-256/SHA-512 password hashing.",
            "fix": "Upgrade OpenSSH to 7.3 or later.",
        },
        {
            "max_affected": "7.7",
            "cve": "CVE-2018-15473",
            "severity": "MEDIUM",
            "description": "OpenSSH through 7.7 may allow username enumeration via timing differences.",
            "fix": "Upgrade OpenSSH to 7.8 or later.",
        },
        {
            "max_affected": "8.3",
            "cve": "CVE-2021-28041",
            "severity": "HIGH",
            "description": "OpenSSH before 8.4 contains a double-free issue in ssh-agent PKCS#11 support.",
            "fix": "Upgrade OpenSSH to 8.4 or later.",
        },
        {
            "max_affected": "9.3",
            "cve": "CVE-2023-38408",
            "severity": "CRITICAL",
            "description": "OpenSSH before 9.3p2 may allow code execution through ssh-agent forwarding and PKCS#11 handling.",
            "fix": "Upgrade OpenSSH to 9.3p2 or later and disable agent forwarding unless required.",
        },
        {
            "max_affected": "9.7",
            "cve": "CVE-2024-6387",
            "severity": "CRITICAL",
            "description": "RegreSSHion: OpenSSH before 9.8 contains a signal handler race condition that may permit unauthenticated remote code execution on glibc-based Linux systems.",
            "fix": "Upgrade OpenSSH to 9.8 or later immediately.",
        },
    ],
    "Apache": [
        {
            "max_affected": "2.4.49",
            "cve": "CVE-2021-41773",
            "severity": "CRITICAL",
            "description": "Apache HTTP Server 2.4.49 is vulnerable to path traversal and possible remote code execution.",
            "fix": "Upgrade Apache to 2.4.51 or later.",
        },
        {
            "max_affected": "2.4.50",
            "cve": "CVE-2021-42013",
            "severity": "CRITICAL",
            "description": "Apache HTTP Server 2.4.50 is vulnerable to path traversal and possible remote code execution due to an incomplete fix for CVE-2021-41773.",
            "fix": "Upgrade Apache to 2.4.51 or later.",
        },
        {
            "max_affected": "2.4.53",
            "cve": "CVE-2022-31813",
            "severity": "HIGH",
            "description": "Apache before 2.4.54 may improperly forward X-Forwarded-* headers, which can contribute to access-control bypass in some deployments.",
            "fix": "Upgrade Apache to 2.4.54 or later.",
        },
    ],
    "nginx": [
        {
            "max_affected": "1.20.0",
            "cve": "CVE-2021-23017",
            "severity": "HIGH",
            "description": "nginx before 1.20.1 contains a DNS resolver off-by-one heap write vulnerability.",
            "fix": "Upgrade nginx to 1.20.1 or later.",
        },
    ],
    "vsFTPd": [
        {
            "max_affected": "2.3.4",
            "cve": "CVE-2011-2523",
            "severity": "CRITICAL",
            "description": "vsFTPd 2.3.4 contains a malicious backdoor allowing remote command execution.",
            "fix": "Upgrade vsFTPd and verify binary integrity.",
        },
    ],
    "ProFTPD": [
        {
            "max_affected": "1.3.5",
            "cve": "CVE-2015-3306",
            "severity": "CRITICAL",
            "description": "ProFTPD before 1.3.5e may allow remote code execution via SITE CPFR/CPTO.",
            "fix": "Upgrade ProFTPD to 1.3.5e or later.",
        },
    ],
    "Redis": [
        {
            "max_affected": "999.999.999",
            "cve": None,
            "severity": "CRITICAL",
            "description": "Redis exposed to the network is commonly exploitable if unauthenticated or weakly protected.",
            "fix": "Bind Redis to localhost or a trusted interface only. Enable authentication and firewall restrictions.",
        },
    ],
    "MySQL": [
        {
            "max_affected": "999.999.999",
            "cve": None,
            "severity": "HIGH",
            "description": "MySQL exposed to the network increases attack surface and risk of brute-force or misconfiguration abuse.",
            "fix": "Restrict MySQL to trusted hosts only, use strong authentication, and limit exposure with firewall rules.",
        },
    ],
}


BASELINE_RULES = {
    "ssh": {
        "severity": "MEDIUM",
        "issue": "SSH service exposed to network",
        "recommendation": "Restrict SSH access to trusted admin subnets, disable password authentication where possible, and enforce key-based login.",
    },
    "http": {
        "severity": "LOW",
        "issue": "HTTP service exposed",
        "recommendation": "Enforce HTTPS where appropriate, remove default pages, restrict admin panels, and keep the web server patched.",
    },
    "ftp": {
        "severity": "HIGH",
        "issue": "FTP service exposed (plaintext protocol)",
        "recommendation": "Replace FTP with SFTP/SCP or enforce FTPS if FTP is unavoidable.",
    },
    "telnet": {
        "severity": "CRITICAL",
        "issue": "Telnet service exposed (plaintext credentials and session data)",
        "recommendation": "Disable Telnet immediately and replace it with SSH.",
    },
    "mysql": {
        "severity": "HIGH",
        "issue": "MySQL service exposed to network",
        "recommendation": "Restrict MySQL access to trusted systems only and enforce firewall restrictions.",
    },
    "postgres": {
        "severity": "HIGH",
        "issue": "PostgreSQL service exposed to network",
        "recommendation": "Restrict PostgreSQL access to trusted systems only and enforce firewall restrictions.",
    },
    "redis": {
        "severity": "CRITICAL",
        "issue": "Redis service exposed to network",
        "recommendation": "Bind Redis to localhost or a trusted interface only, enable authentication, and restrict access with firewall rules.",
    },
}


def _parse_numeric_version(version_string: str) -> str:
    if not version_string:
        return ""
    match = re.search(r"(\d+(?:\.\d+)+)", version_string)
    return match.group(1) if match else ""


def _match_vendor(version_string: str) -> tuple[str, str]:
    """
    Return (vendor_name, numeric_version) if the banner/version matches
    something in the local CVE database.
    """
    if not version_string:
        return "", ""

    lowered = version_string.lower()

    for vendor_name in CVE_DATABASE:
        if vendor_name.lower() in lowered:
            return vendor_name, _parse_numeric_version(version_string)

    return "", ""


def _version_is_affected(detected_version: str, max_affected: str) -> bool:
    try:
        return pkg_version.parse(detected_version) <= pkg_version.parse(max_affected)
    except Exception:
        return False

def _normalize_severity(severity: str) -> str:
    sev = (severity or "").strip().upper()

    mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",
    }

    return mapping.get(sev, "Low")


def _make_finding(
    *,
    rule_key: str | None,
    port: int | None,
    service: str | None,
    banner: str | None,
    version: str | None,
    issue: str,
    severity: str,
    recommendation: str,
    cve: str | None = None,
) -> dict:
    finding = {
        "port": port,
        "service": service,
        "banner": banner or "",
        "version": version or "",
        "cve": cve,
        "issue": issue,
        "severity": severity,
        "recommendation": recommendation,
    }

    if rule_key:
        finding["rule_key"] = rule_key
        finding = enrich_finding(rule_key, finding)

    return finding


def _apply_baseline_rule(service: str, port: int, banner: str, version: str) -> list[dict]:
    rule = BASELINE_RULES.get(service)
    if not rule:
        return []

    baseline_rule_keys = {
        "ssh": "ssh_weak_config",
        "http": "http_no_tls",
        "ftp": "ftp_exposed",
        "telnet": "telnet_exposed",
        "mysql": "mysql_exposed",
        "postgres": "postgres_exposed",
        "redis": "redis_exposed",
    }

    return [
        _make_finding(
            rule_key=baseline_rule_keys.get(service),
            port=port,
            service=service,
            banner=banner,
            version=version,
            issue=rule["issue"],
            severity=rule["severity"],
            recommendation=rule["recommendation"],
            cve=None,
        )
    ]


def _apply_cve_rules(service: str, port: int, banner: str, version: str) -> list[dict]:
    cve_rule_keys = {
        "OpenSSH": "ssh_known_cve",
        "Apache": "http_known_cve",
        "nginx": "http_known_cve",
        "vsFTPd": "ftp_known_cve",
        "ProFTPD": "ftp_known_cve",
        "Redis": "redis_exposed",
        "MySQL": "mysql_exposed",
    }

    findings = []


    vendor_name, numeric_version = _match_vendor(version)
    if not vendor_name or not numeric_version:
        return findings

    for entry in CVE_DATABASE.get(vendor_name, []):
        if _version_is_affected(numeric_version, entry["max_affected"]):
            issue_text = entry["description"]
            if entry.get("cve"):
                issue_text = f"{entry['cve']}: {issue_text}"

            findings.append(
                _make_finding(
                    rule_key=cve_rule_keys.get(vendor_name),
                    port=port,
                    service=service,
                    banner=banner,
                    version=version,
                    issue=issue_text,
                    severity=entry["severity"],
                    recommendation=entry["fix"],
                    cve=entry.get("cve"),
                )
            )

    return findings


def build_findings(target: str, services: list[dict]) -> list[dict]:
    findings: list[dict] = []

    for svc in services:
        port = svc.get("port")
        service = (svc.get("service") or "").lower()
        banner = svc.get("banner", "")
        version = svc.get("version", "")

        # 1. Baseline exposure findings
        findings.extend(_apply_baseline_rule(service, port, banner, version))

        # 2. Version/CVE findings
        findings.extend(_apply_cve_rules(service, port, banner, version))

    findings.sort(key=lambda f: (-_sev_score(f["severity"]), f.get("port") or 0))
    return findings
