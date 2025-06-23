import requests

# Local fallback CVE database
CVE_DATABASE = {
    "smb": [
        {
            "cve": "CVE-2017-0144",
            "title": "EternalBlue (SMBv1)",
            "severity": "Critical",
            "description": "Allows remote code execution via SMBv1 on unpatched Windows systems.",
            "remediation": "Disable SMBv1 and apply the latest Windows updates."
        },
        {
            "cve": "CVE-2020-0796",
            "title": "SMBGhost",
            "severity": "High",
            "description": "Remote code execution via SMBv3 compression.",
            "remediation": "Apply March 2020 Windows updates and disable SMBv3 compression if not needed."
        }
    ],
    "openssh": [
        {
            "cve": "CVE-2018-15473",
            "title": "OpenSSH User Enumeration",
            "severity": "Medium",
            "description": "Allows remote attackers to enumerate users via crafted authentication requests.",
            "remediation": "Upgrade OpenSSH to latest secure version and disable verbose auth logs."
        }
    ]
}

def query_nvd_api(keyword, max_results=5):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={max_results}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve")
            if not cve:
                continue
            cve_id = cve.get("id")
            description = cve.get("descriptions", [{}])[0].get("value", "No description available.")
            severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "Unknown")
            results.append({
                "cve": cve_id,
                "title": f"NVD Match for {keyword}",
                "description": description,
                "severity": severity,
                "remediation": "Refer to CVE details and apply vendor patches."
            })
        return results
    except requests.RequestException as e:
        return [{
            "cve": "N/A",
            "title": "NVD API Error",
            "description": str(e),
            "severity": "Unknown",
            "remediation": "Try again later or check your network."
        }]

def map_banner_to_cves(banner):
    if not isinstance(banner, str):
        return []

    banner_lower = banner.lower()
    local_results = []

    if "smb" in banner_lower or "microsoft-ds" in banner_lower:
        local_results = CVE_DATABASE["smb"]
    elif "openssh" in banner_lower:
        local_results = CVE_DATABASE["openssh"]

    nvd_results = query_nvd_api(banner_lower)
    return local_results + nvd_results
