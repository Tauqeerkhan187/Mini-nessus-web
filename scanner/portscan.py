# Author: TK
# Date: 04-03-2026
# Purpose: Threaded TCP port scanner. Detects open TCP ports (network reconnaissance layer).
# Update: updated scanner, new scanner scans 200 threads in 5 sec, mimics a real scanner.

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def _check_port(target: str, port: int, timeout: float) -> int | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
            soc.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                return port

            return None

    except Exception:
        return None

def threaded_port_scan(target: str, ports: list[int], timeout: float = 0.6, workers: int = 200, progress_callback = None,) -> list[int]:
    """
    Scan multiple ports in parallel using a thread pool.
    """
    open_ports = []
    total = len(ports)
    scanned = 0

    with ThreadPoolExecutor(max_workers=min(workers, total)) as executor:
        # Submit all port checks at once.
        future_to_port = {
                executor.submit(_check_port, target, port, timeout): port
                for port in ports
                }

        # Collect results as they complete
        for future in as_completed(future_to_port):
            scanned += 1
            result = future.result()

            if result is not None:
                open_ports.append(result)

            # Report progress if callback provided
            if progress_callback and scanned % 50 == 0:
                progress_callback(scanned, total)

    return sorted(open_ports)

