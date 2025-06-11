import requests
from base64 import urlsafe_b64encode

VT_API_KEY = "API-KEY"
ABUSEIPDB_API_KEY = "API-KEY"
ALIENVAULT_API_KEY = "API-KEY"
URLSCAN_API_KEY = "API-KEY"

VT_BASE_URL = "https://www.virustotal.com/api/v3"
def query_virustotal(ioc_value, ioc_type):
    headers = {"x-apikey": VT_API_KEY}

    if ioc_type == "ip":
        url = f"{VT_BASE_URL}/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"{VT_BASE_URL}/domains/{ioc_value}"
    elif ioc_type == "url":
        encoded = urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
        url = f"{VT_BASE_URL}/urls/{encoded}"
    elif ioc_type == "hash":
        url = f"{VT_BASE_URL}/files/{ioc_value}"
    else:
        return None

    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        return {"source": "VirusTotal", "value": ioc_value, **stats}
    else:
        return {"source": "VirusTotal", "value": ioc_value, "error": r.status_code}

def query_abuseipdb(ip):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()["data"]
        return {
            "source": "AbuseIPDB",
            "value": ip,
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "totalReports": data.get("totalReports", 0),
            "isWhitelisted": data.get("isWhitelisted", False)
        }
    else:
       return {"source": "AbuseIPDB", "value": ip, "error": r.status_code}


def query_alienvault(ioc_value, ioc_type):
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    endpoint_map = {
        "ip": "IPv4",
        "domain": "domain",
        "hostname": "hostname",
       "hash": "file"
    }

    if ioc_type not in endpoint_map:
        return {"source": "AlienVault", "value": ioc_value, "error": "unsupported_type"}

    url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint_map[ioc_type]}/{ioc_value}/general"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        pulse_info = r.json().get("pulse_info", {})
        return {
            "source": "AlienVault",
            "value": ioc_value,
            "count": pulse_info.get("count", 0),
            "pulses": [p["name"] for p in pulse_info.get("pulses", [])]
        }
    else:
        return {"source": "AlienVault", "value": ioc_value, "error": r.status_code}


def query_urlscan(domain):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    r = requests.get(search_url, headers=headers)
    if r.status_code == 200:
        results = r.json().get("results", [])
        return {
            "source": "URLScan",
            "value": domain,
            "seen": len(results),
            "first_seen": results[0]["task"]["time"] if results else None
        }
    else:
        return {"source": "URLScan", "value": domain, "error": r.status_code}

def multi_cti_lookup(ioc_value, ioc_type):
    results = []

    if ioc_type in ["ip", "domain", "url", "hash"]:
        vt = query_virustotal(ioc_value, ioc_type)
        if vt: results.append(vt)
 
    if ioc_type == "ip":
         results.append(query_abuseipdb(ioc_value))

    if ioc_type in ["ip", "domain", "hash"]:
        results.append(query_alienvault(ioc_value, ioc_type))
   
    if ioc_type == "domain":
        results.append(query_urlscan(ioc_value))


    return results
