# Author: TK
# Date: 24-03-2026
# Purpose: Grab service banners, identify services, and extract versions

import re
import socket


def grab_banner(target: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((target, port))

            # HTTP-like services usually need a request first
            if port in (80, 8080, 8000, 5000, 3000, 443, 8443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")

            data = s.recv(2048)
            return data.decode(errors="ignore").strip()

    except Exception:
        return ""


def guess_service(port: int, banner: str) -> str:
    b = (banner or "").lower()

    if "ssh" in b or port == 22:
        return "ssh"
    if "http" in b or "apache" in b or "nginx" in b or port in (80, 443, 8080, 8000, 5000, 3000, 8443):
        return "http"
    if "ftp" in b or "vsftpd" in b or "proftpd" in b or port == 21:
        return "ftp"
    if "telnet" in b or port == 23:
        return "telnet"
    if "mysql" in b or "mariadb" in b or port == 3306:
        return "mysql"
    if "postgres" in b or "postgresql" in b or port == 5432:
        return "postgres"
    if "redis" in b or port == 6379:
        return "redis"
    if "smtp" in b or port == 25:
        return "smtp"

    return "unknown"


def extract_version(service: str, banner: str) -> str:
    if not banner:
        return ""

    # Common version extraction patterns
    patterns = [
        r"(OpenSSH[_/\-][^\s]+)",
        r"(Apache[/][^\s]+)",
        r"(nginx[/][^\s]+)",
        r"(vsFTPd[\s/][^\s]+)",
        r"(ProFTPD[\s/][^\s]+)",
        r"(Redis[\s/][^\s]+)",
        r"(MariaDB[\s/][^\s]+)",
        r"(MySQL[\s/][^\s]+)",
        r"(PostgreSQL[\s/][^\s]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)

    # Fallback for Apache-style server headers
    generic = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
    if generic:
        return generic.group(1).strip()

    return ""
