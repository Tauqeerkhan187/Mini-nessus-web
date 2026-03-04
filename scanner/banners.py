# Author: TK
# Date: 04-03-2026
# Purpose: banner grabbing and service detection. Connects to open ports and guesses service type.

import socket

def grab_banner(target: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
            s.settimeout(1.0)
            s.connect((target, port))

            # SSH usually talks first; HTTP needs request.
            if port in (80, 8080, 8000, 5000, 3000, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            data = s.recv(1024)
            return data.decode(errors="ignore").strip()
        except Exception:
            return ""

def guess_service(port: int, banner: str) -> str:
    b = (banner or "").lower()
    if "ssh" in b or port in (22, 2222):
        return "ssh"
    if "http" in b or port in (80, 8080, 8000, 5000, 3000, 443):
        return "http"
    if port == 21:
        return "ftp"
    if port == 25:
        return "smtp"
    if port == 3306:
        return "mysql"
    if port == 5432:
        return "postgres"
    if port == 6379:
        return "redis"
    return "unknown"
