# scanner/tcp_ip_scanner.py

import socket
import ipaddress

def scan_network_range(network_cidr, port=80, timeout=1):
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as ve:
        return {"error": str(ve)}

    results = []
    for ip in network.hosts():
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                results.append(str(ip))
        except:
            pass

    return {
        "status": "Completed",
        "findings": f"{len(results)} active hosts found",
        "active_hosts": results
    }
