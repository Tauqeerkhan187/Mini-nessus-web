# Author: TK
# Date: 24-03-2025
# Purpose: Runs Authenticated SSH checks requires valid SSH creds, only use on systems you own or are authorized to test.

import paramiko


def _run_command(client: paramiko.SSHClient, cmd: str) -> str:
    """Execute a command over SSH and return stdout."""
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
        return stdout.read().decode(errors="ignore").strip()
    except Exception:
        return ""


def _connect(target: str, port: int, username: str, password: str) -> paramiko.SSHClient | None:
    """Establish SSH connection. Returns client or None."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=target,
            port=port,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        return client
    except Exception:
        return None


def check_ssh_config(client: paramiko.SSHClient) -> list[dict]:
    """Check /etc/ssh/sshd_config for weak settings."""
    findings = []
    config = _run_command(client, "cat /etc/ssh/sshd_config")

    if not config:
        return findings

    lines = config.lower().split("\n")
    config_dict = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                config_dict[parts[0]] = parts[1]

    # Check: Password authentication enabled
    if config_dict.get("passwordauthentication", "yes") == "yes":
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] SSH password authentication is enabled",
            "severity": "MEDIUM",
            "recommendation": "Disable PasswordAuthentication in sshd_config and enforce key-based login.",
        })

    # Check: Root login allowed
    root_login = config_dict.get("permitrootlogin", "prohibit-password")
    if root_login in ("yes", "without-password", "prohibit-password"):
        severity = "HIGH" if root_login == "yes" else "MEDIUM"
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": f"[AUTH] SSH root login is set to '{root_login}'",
            "severity": severity,
            "recommendation": "Set PermitRootLogin to 'no' in sshd_config. Use sudo for privilege escalation.",
        })

    # Check: X11 forwarding enabled
    if config_dict.get("x11forwarding", "no") == "yes":
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] SSH X11 forwarding is enabled",
            "severity": "LOW",
            "recommendation": "Disable X11Forwarding unless required. It increases attack surface.",
        })

    # Check: Empty passwords allowed
    if config_dict.get("permitemptypasswords", "no") == "yes":
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] SSH allows empty passwords",
            "severity": "CRITICAL",
            "recommendation": "Set PermitEmptyPasswords to 'no' immediately.",
        })

    # Check: Protocol 1 enabled (very old systems)
    if config_dict.get("protocol", "2") == "1":
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] SSH Protocol 1 is enabled (insecure and deprecated)",
            "severity": "CRITICAL",
            "recommendation": "Set Protocol to 2 in sshd_config.",
        })

    return findings


def check_outdated_packages(client: paramiko.SSHClient) -> list[dict]:
    """Check for available security updates."""
    findings = []

    # Try apt (Debian/Ubuntu)
    updates = _run_command(client, "apt list --upgradable 2>/dev/null | grep -i security | head -20")

    if updates:
        count = len(updates.strip().split("\n"))
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": f"[AUTH] {count} security update(s) available on target system",
            "severity": "HIGH" if count > 5 else "MEDIUM",
            "recommendation": f"Run 'sudo apt update && sudo apt upgrade' to apply {count} pending security patches.",
        })

    # Check specific critical packages
    openssh_ver = _run_command(client, "dpkg -l openssh-server 2>/dev/null | grep '^ii' | awk '{print $3}'")
    if openssh_ver:
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": openssh_ver,
            "cve": None,
            "issue": f"[AUTH] Installed OpenSSH package version: {openssh_ver}",
            "severity": "INFO",
            "recommendation": "Verify this version against known CVEs. Keep packages updated.",
        })

    return findings


def check_weak_users(client: paramiko.SSHClient) -> list[dict]:
    """Check for users with empty passwords or weak configurations."""
    findings = []

    # Find users with empty password field in /etc/shadow
    shadow = _run_command(client, "sudo cat /etc/shadow 2>/dev/null")
    if shadow:
        for line in shadow.split("\n"):
            parts = line.split(":")
            if len(parts) >= 2:
                username = parts[0]
                password_hash = parts[1]
                if password_hash == "" or password_hash == "!":
                    continue  # locked or no password set (normal)
                if password_hash == "!!":
                    continue  # password not set yet
                # Very short hash might indicate weak password
    else:
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] Cannot read /etc/shadow (insufficient privileges for full audit)",
            "severity": "INFO",
            "recommendation": "Run scanner with sudo-capable credentials for complete user audit.",
        })

    # Check for users with UID 0 (besides root)
    passwd = _run_command(client, "awk -F: '$3 == 0 && $1 != \"root\"' /etc/passwd")
    if passwd:
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": f"[AUTH] Non-root user(s) with UID 0 found: {passwd.split(':')[0]}",
            "severity": "CRITICAL",
            "recommendation": "Remove UID 0 from non-root accounts. Only root should have UID 0.",
        })

    return findings


def check_filesystem(client: paramiko.SSHClient) -> list[dict]:
    """Check for dangerous file permissions."""
    findings = []

    # World-writable files in sensitive directories
    world_writable = _run_command(
        client,
        "find /etc /usr -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -10"
    )
    if world_writable:
        count = len(world_writable.strip().split("\n"))
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": f"[AUTH] {count} world-writable file(s) found in /etc or /usr",
            "severity": "HIGH",
            "recommendation": "Remove world-write permissions: chmod o-w <file>. Review each file.",
        })

    # Check /etc/passwd permissions
    passwd_perms = _run_command(client, "stat -c '%a' /etc/passwd")
    if passwd_perms and int(passwd_perms) > 644:
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": f"[AUTH] /etc/passwd has excessive permissions ({passwd_perms})",
            "severity": "MEDIUM",
            "recommendation": "Set /etc/passwd to 644: chmod 644 /etc/passwd",
        })

    return findings


def check_firewall(client: paramiko.SSHClient) -> list[dict]:
    """Check if firewall is active."""
    findings = []

    # Check ufw
    ufw_status = _run_command(client, "sudo ufw status 2>/dev/null")
    if "inactive" in ufw_status.lower() or "disabled" in ufw_status.lower():
        findings.append({
            "port": 22,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] Host firewall (ufw) is not active",
            "severity": "HIGH",
            "recommendation": "Enable ufw: sudo ufw enable. Configure rules to allow only necessary traffic.",
        })
    elif not ufw_status:
        # Try iptables
        iptables = _run_command(client, "sudo iptables -L -n 2>/dev/null | grep -c 'ACCEPT\\|DROP\\|REJECT'")
        try:
            rule_count = int(iptables)
        except ValueError:
            rule_count = 0

        if rule_count <= 3:
            findings.append({
                "port": 22,
                "service": "ssh",
                "banner": "",
                "version": "",
                "cve": None,
                "issue": "[AUTH] No significant firewall rules detected (iptables)",
                "severity": "HIGH",
                "recommendation": "Configure iptables or install ufw to restrict network access.",
            })

    return findings


def run_authenticated_checks(
    target: str,
    port: int = 22,
    username: str = "",
    password: str = "",
) -> list[dict]:
    """
    Main entry point. Connects via SSH and runs all authenticated checks.
    Returns list of findings.
    """
    if not username:
        return []

    client = _connect(target, port, username, password)
    if not client:
        return [{
            "port": port,
            "service": "ssh",
            "banner": "",
            "version": "",
            "cve": None,
            "issue": "[AUTH] Failed to authenticate via SSH (bad credentials or connection refused)",
            "severity": "INFO",
            "recommendation": "Verify SSH credentials. Ensure the target allows password authentication.",
        }]

    try:
        findings = []
        findings.extend(check_ssh_config(client))
        findings.extend(check_outdated_packages(client))
        findings.extend(check_weak_users(client))
        findings.extend(check_filesystem(client))
        findings.extend(check_firewall(client))
        return findings
    finally:
        client.close()
