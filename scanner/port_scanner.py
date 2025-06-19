# scanner/port_scanner.py

import socket

def scan_ports(target, start_port, end_port, timeout=1):
    open_ports = []

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": f"Cannot resolve hostname: {target}"}

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()

    return {
        "target": target,
        "open_ports": open_ports,
        "total_scanned": end_port - start_port + 1
    }

