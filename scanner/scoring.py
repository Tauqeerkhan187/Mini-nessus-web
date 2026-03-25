# Author: TK
# Date: 25-03-2026
# Purpose: assign CVSS style score + severity + impact


import math

AV_VALUES = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

AC_VALUES = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

PR_VALUES = {
    "U": {  # Scope Unchanged
        "N": 0.85,
        "L": 0.62,
        "H": 0.27,
    },
    "C": {  # Scope Changed
        "N": 0.85,
        "L": 0.68,
        "H": 0.50,
    },
}

UI_VALUES = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

CIA_VALUES = {
    "N": 0.00,  # None
    "L": 0.22,  # Low
    "H": 0.56,  # High
}


# -----------------------------------------
# Map your scanner rules -> CVSS-style data
# Add one entry per finding rule you use
# -----------------------------------------
RULE_PROFILES = {
    "telnet_exposed": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "H", "A": "L"
        },
        "impact": "Telnet sends credentials and session data in cleartext, which makes interception and remote compromise much easier on untrusted networks.",
    },
    "redis_exposed": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "H", "A": "H"
        },
        "impact": "An exposed Redis instance can allow unauthorized data access, tampering, or abuse for remote code execution depending on configuration.",
    },
    "mysql_exposed": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "L", "A": "L"
        },
        "impact": "An internet-exposed MySQL service increases the chance of brute-force attacks, data leakage, and unauthorized database access.",
    },
    "ftp_exposed": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "L", "I": "L", "A": "N"
        },
        "impact": "Plain FTP is insecure because credentials and transferred data can be exposed to interception if encryption is not enforced.",
    },
    "anonymous_ftp_enabled": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "L", "I": "L", "A": "N"
        },
        "impact": "Anonymous FTP can expose internal files to anyone and may also allow unauthorized uploads depending on server configuration.",
    },
    "http_no_tls": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R",
            "S": "U", "C": "L", "I": "L", "A": "N"
        },
        "impact": "Serving sensitive content over HTTP instead of HTTPS allows traffic interception, credential theft, and content tampering in transit.",
    },
    "http_missing_security_headers": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R",
            "S": "U", "C": "L", "I": "L", "A": "N"
        },
        "impact": "Missing security headers can make browser-based attacks like clickjacking, MIME confusion, or script abuse easier.",
    },
    "ssh_weak_config": {
        "metrics": {
            "AV": "N", "AC": "H", "PR": "N", "UI": "N",
            "S": "U", "C": "L", "I": "L", "A": "N"
        },
        "impact": "Weak SSH configuration reduces resistance to brute force, downgrade, or policy bypass attempts and makes administrative access harder to defend.",
    },
    "default_credentials_risk": {
        "metrics": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "H", "A": "H"
        },
        "impact": "Default credentials can let an attacker gain immediate unauthorized access, often with administrative control over the service.",
    },
}


# Fallback so old rules don't break instantly
LEGACY_SEVERITY_TO_CVSS = {
    "Critical": 9.0,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 3.0,
    "Info": 0.0,
}


def round_up_1_decimal(value: float) -> float:
    return math.ceil(value * 10) / 10.0


def cvss_severity(score: float) -> str:
    if score == 0:
        return "Info"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def build_cvss_vector(metrics: dict) -> str:
    return (
        f"CVSS:3.1/"
        f"AV:{metrics['AV']}/"
        f"AC:{metrics['AC']}/"
        f"PR:{metrics['PR']}/"
        f"UI:{metrics['UI']}/"
        f"S:{metrics['S']}/"
        f"C:{metrics['C']}/"
        f"I:{metrics['I']}/"
        f"A:{metrics['A']}"
    )


def calculate_cvss_base_score(metrics: dict) -> float:
    av = AV_VALUES[metrics["AV"]]
    ac = AC_VALUES[metrics["AC"]]
    pr = PR_VALUES[metrics["S"]][metrics["PR"]]
    ui = UI_VALUES[metrics["UI"]]
    c = CIA_VALUES[metrics["C"]]
    i = CIA_VALUES[metrics["I"]]
    a = CIA_VALUES[metrics["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if metrics["S"] == "U":
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    return round_up_1_decimal(base_score)


def enrich_finding(rule_key: str, finding: dict) -> dict:
    """
    Adds:
    - cvss_score
    - cvss_vector
    - impact
    - normalized severity from CVSS
    - rule_key
    """
    profile = RULE_PROFILES.get(rule_key)

    if profile:
        metrics = profile["metrics"]
        score = calculate_cvss_base_score(metrics)
        finding["rule_key"] = rule_key
        finding["cvss_score"] = score
        finding["cvss_vector"] = build_cvss_vector(metrics)
        finding["impact"] = profile["impact"]
        finding["severity"] = cvss_severity(score)
        return finding

    # fallback for unmapped old rules
    fallback_score = LEGACY_SEVERITY_TO_CVSS.get(finding.get("severity", "Info"), 0.0)
    finding["rule_key"] = rule_key
    finding["cvss_score"] = fallback_score
    finding["cvss_vector"] = None
    finding["impact"] = finding.get("impact", "Impact explanation not mapped yet.")
    finding["severity"] = cvss_severity(fallback_score)
    return finding


def calculate_scan_risk(findings: list[dict]) -> tuple[float, str]:
    """
    Keeps your Scan.risk_score on a 0-100 scale,
    but now derives it from CVSS-style finding scores.
    """
    if not findings:
        return 0.0, "Info"

    scores = sorted(
        [float(f.get("cvss_score", 0.0)) for f in findings],
        reverse=True
    )

    max_score = scores[0]
    top_n = scores[:5]
    avg_top = sum(top_n) / len(top_n)

    critical_count = sum(1 for s in scores if s >= 9.0)
    high_count = sum(1 for s in scores if 7.0 <= s < 9.0)

    # Weighted toward the worst issue, but still reacts to multiple serious findings
    scan_score_10 = min(
        10.0,
        (max_score * 0.7) +
        (avg_top * 0.3) +
        min(1.5, critical_count * 0.4 + high_count * 0.2)
    )

    scan_score_100 = round(scan_score_10 * 10, 1)

    if scan_score_10 == 0:
        level = "Info"
    elif scan_score_10 <= 3.9:
        level = "Low"
    elif scan_score_10 <= 6.9:
        level = "Medium"
    elif scan_score_10 <= 8.9:
        level = "High"
    else:
        level = "Critical"

    return scan_score_100, level
