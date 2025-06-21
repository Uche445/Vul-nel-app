import socket
import paramiko
from .ssh_vuln_defs import scan_ssh_config_for_vulns

def ssh_check_host(host, port=22, timeout=3, username=None, password=None):
    ssh_status = {}
    findings = []

    # Step 1: Check port
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ssh_status["status"] = "Completed"
            findings.append(f"SSH service is accessible on {host}:{port}")
    except Exception as e:
        return {
            "status": "Failed",
            "findings": [f"Could not reach SSH on {host}:{port} - {str(e)}"]
        }

    # Step 2: If credentials provided, log in and read config
    if username and password:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)

            stdin, stdout, stderr = client.exec_command('cat /etc/ssh/sshd_config')
            config_text = stdout.read().decode()

            if config_text:
                ssh_vulns = scan_ssh_config_for_vulns(config_text)
                for vuln in ssh_vulns:
                    findings.append(vuln)
            else:
                findings.append("Could not read /etc/ssh/sshd_config.")

            client.close()
        except Exception as e:
            findings.append(f"SSH login or config read failed: {str(e)}")
    else:
        findings.append("No SSH credentials provided. Skipping vulnerability scan.")

    return {
        "status": ssh_status.get("status", "Completed"),
        "findings": findings
    }
