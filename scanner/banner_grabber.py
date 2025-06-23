# scanner/banner_grabber.py
import socket

def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            return {"ip": ip, "port": port, "banner": banner or "No banner detected"}
    except Exception as e:
        return {"ip": ip, "port": port, "error": str(e)}
