# scanner/ssh_vuln_defs.py

import re

ssh_vulnerabilities = {
    "sshv1_enabled": {
        "title": "SSHv1 Protocol Enabled",
        "description": "The SSH server supports SSH version 1, which is outdated and insecure.",
        "cve": ["CVE-2001-0144"],
        "remediation": "Disable SSHv1 by setting 'Protocol 2' in /etc/ssh/sshd_config and restart the SSH service."
    },
    "root_login_permitted": {
        "title": "Root Login Enabled",
        "description": "Direct root login over SSH is allowed.",
        "cve": ["CVE-2008-0166"],
        "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
    },
    "password_auth_enabled": {
        "title": "Password Authentication Enabled",
        "description": "Password-based SSH authentication is enabled.",
        "cve": ["CVE-2018-15473"],
        "remediation": "Use SSH keys and disable password login in sshd_config."
    },
    "weak_ciphers_used": {
        "title": "Weak SSH Ciphers/Algorithms Detected",
        "description": "SSH server supports weak ciphers.",
        "cve": ["CVE-2016-0777", "CVE-2016-0778"],
        "remediation": "Update allowed ciphers and algorithms in sshd_config."
    },
    "no_idle_timeout": {
        "title": "Idle SSH Sessions Not Terminated",
        "description": "No timeout configured for idle SSH sessions.",
        "cve": [],
        "remediation": "Set 'ClientAliveInterval' and 'ClientAliveCountMax'."
    }
}

def parse_sshd_config(config_text):
    lines = config_text.splitlines()
    config = {}

    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            parts = re.split(r'\s+', line, 1)
            if len(parts) == 2:
                key, value = parts
                config[key.lower()] = value.strip()
    
    return config

def scan_ssh_config_for_vulns(config_text):
    config = parse_sshd_config(config_text)
    results = []

    if config.get("protocol", "2") != "2":
        results.append(ssh_vulnerabilities["sshv1_enabled"])

    if config.get("permitrootlogin", "no").lower() != "no":
        results.append(ssh_vulnerabilities["root_login_permitted"])

    if config.get("passwordauthentication", "no").lower() != "no":
        results.append(ssh_vulnerabilities["password_auth_enabled"])

    weak_ciphers = ["3des-cbc", "aes128-cbc", "arcfour"]
    if "ciphers" in config:
        ciphers = config["ciphers"].lower()
        if any(weak in ciphers for weak in weak_ciphers):
            results.append(ssh_vulnerabilities["weak_ciphers_used"])

    if "clientaliveinterval" not in config or "clientalivecountmax" not in config:
        results.append(ssh_vulnerabilities["no_idle_timeout"])

    return results
