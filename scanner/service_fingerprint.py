import socket

COMMON_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    445: "SMB"
}

def guess_protocol_and_fingerprint(ip, port, timeout=3):
    guessed_protocol = COMMON_PROTOCOLS.get(port, "Unknown")
    fingerprint = ""

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if guessed_protocol == "HTTP":
                sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
                fingerprint = sock.recv(1024).decode(errors='ignore')
            elif guessed_protocol in ("SMTP", "FTP", "SSH"):
                fingerprint = sock.recv(1024).decode(errors='ignore')
            elif guessed_protocol == "DNS":
                fingerprint = "No direct fingerprint - use packet-based sniffing"
            else:
                sock.sendall(b"\r\n")
                fingerprint = sock.recv(1024).decode(errors='ignore')
    except Exception as e:
        fingerprint = f"Error: {str(e)}"

    return guessed_protocol, fingerprint.strip() or "No response"
