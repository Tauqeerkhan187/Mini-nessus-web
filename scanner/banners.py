# Author: TK
# Date: 04-03-2026
# Purpose: banner grabbing and service detection. Connects to open ports and guesses service type.

import socket

def grab_banner(target: str, port: int) -> str:
    """
    Connect to a port and attempt to read the service banner. 
    For HTTP ports, sends a HEAD request to trigger a response.
    for other ports (SSH, FTP, SMTP), the service usually talks first.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
            s.settimeout(2.0)
            s.connect((target, port))

            # SSH usually talks first; HTTP needs request.
            if port in (80, 443, 8080, 8000, 8443, 5000, 3000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            
            data = s.recv(2048)
            return data.decode(errors="ignore").strip()

    except Exception:
        return ""

def guess_service(port: int, banner: str) -> str:
    """
    Identify the service running on a port using banner + port heuristics.
    Returns a service name string.
    """
    b = (banner or "").lower()

    if "ssh" in b or port in (22, 2222):
        return "ssh"

    if any (kw in b for kw in ["http/", "html", "apache", "nginx", "iis"]):
        return "http"

    if port in (80, 443, 8080, 8000, 8443, 5000, 3000, 8888):
        return "http"

    if "ftp" in b or port == 21:
        return "ftp"

    if "smtp" in b or "mail" in b or port == 25:
        return "smtp"

    if "mysql" in b or port == 3306:
        return "mysql"

    if port == 5432:
        return "postgres"

    if port == 6379:
        return "redis"
    
    if port == 23:
        return "telnet"

    return "unknown"

def extract_version(service: str, banner: str) -> str:
    """
    Parse the banner to extract software name + version string.

    Returns a string like "OpenSSH_8.9" or "Apache/2.4.49" or "" if unknown. """

    if not banner:
        return ""

    patterns = {
            "ssh": [
                r"(OpenSSH[_/][\d.p]+)",  # OpenSSH_8.9p1
                r"(dropbear[_/][\d]+)",   # dropbear _2020.81

            ],

            "http": [
                r"(Apache/[\d.]+)",       # Apache/2.4.49
                r"(nginx/[\d.]+)",        # nginx/1.18.0
                r"(Microsoft-IIS/[\d.]+)",# Microsoft-IIS/10.0
                r"(lighttpd/[\d.]+)",     # lighttpd/1.4.59

            ],

            "ftp": [
                r"(vsFTPd\s+[\d.]+)",     # vsFTPd 3.0.3
                r"(ProFTPD\s+[\d.]+)",    # ProFTPD 1.3.5
                r"(Pure-FTPd)",           # Pure-FTPd

            ],

            "smtp": [
                r"(Postfix)",
                r"(Exim\s+[\d.]+)", 

            ],

            "mysql": [
                r"([\d.]+)-MariaDB",      # 10.5.12-MariaDB
                r"[\d.]+)",               # 8.0.27
            ],

            "redis": [
                r"redis_version:([\d.]+)",

            ],

        }

    service_patterns = patterns.get(service, [])
    for pattern in service_patterns:
        match = re.search(patter, banner, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        return ""


