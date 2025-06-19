# scanner/ssh_scanner.py

import socket

def ssh_check_host(host, port=22, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "status": "Completed",
                "findings": f"SSH service is accessible on {host}:{port}"
            }
    except Exception as e:
        return {
            "status": "Failed",
            "findings": f"Could not reach SSH on {host}:{port} - {str(e)}"
        }
