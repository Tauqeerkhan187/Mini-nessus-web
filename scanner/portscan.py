# Author: TK
# Date: 04-03-2026
# Purpose: code for port scanning

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def _check(target: str, port: int, timeout: float) -> int | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
            soc.settimeout(timeout)
            soc.connect((target, port))
            return port

    except Exception:
        return None

def threaded_port_scan(target: str, ports: list[int], timeout: float = 0.6, workers: int = 200) -> list[int]:
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_check, target, p, timeout) for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)
    return sorted(open_ports)
