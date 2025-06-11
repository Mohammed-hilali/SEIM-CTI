import time
import json
import re
import os
from datetime import datetime
from threat_intel import multi_cti_lookup

WAZUH_ALERT_DIR = "/var/ossec/logs/cti_suspect"


EVENT_IOC_MAP = {
    "1": ("hash", "hashes"),
    "3": ("ip", "destinationIp"),
    "6": ("hash", "hashes"),
    "7": ("hash", "hashes"),
    "15": ("hash", "hashes"),
    "22": ("domain", "queryName"),
    "23": ("hash", "hashes"),
    "24": ("hash", "hashes"),
    "25": ("hash", "hashes"),
}

def extract_ioc(alert):
    agent_info = alert.get('agent', {})
    agent_name = agent_info.get('name')
    agent_id = agent_info.get('id')

    def extract_from_eventdata():
        event_id = alert.get('data', {}).get('win', {}).get('system', {}).get('eventID')
        if not event_id:
            return []

        ioc_type, field = EVENT_IOC_MAP.get(event_id, (None, None))
        if not ioc_type or not field:
            return []

        eventdata = alert.get('data', {}).get('win', {}).get('eventdata', {})
        ioc_value = eventdata.get(field)

        if isinstance(ioc_value, bytes):
            ioc_value = ioc_value.decode()

        if isinstance(ioc_value, list):
            return [(ioc_type, val) for val in ioc_value]
        elif ioc_value:
            return [(ioc_type, ioc_value)]
        return []

    def extract_with_regex():
        text_fields = []
        win = alert.get('data', {}).get('win', {})
        eventdata = win.get('eventdata', {})
        message = win.get('sysmon', {}).get('message', '')
        full_log = alert.get('full_log', '')

        if isinstance(eventdata, dict):
            text_fields += [str(v) for v in eventdata.values()]
        text_fields.append(message)
        text_fields.append(full_log)
        text = ' '.join(text_fields)

        iocs = []
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
        url_matches = re.findall(r'https?://[^\s"\'<>]+', text)
        hash_matches = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)

        iocs += [('ip', ip) for ip in ip_matches]
        iocs += [('url', url) for url in url_matches]
        iocs += [('hash', h) for h in hash_matches]

        return iocs

    extract_methods = [extract_from_eventdata, extract_with_regex]

    for method in extract_methods:
        try:
            iocs = method()
            if iocs:
                return {
                    "agent_name": agent_name,
                    "agent_id": agent_id,
                    "iocs": iocs
                }
        except Exception as e:
            print(f"[!] Erreur dans la méthode {method.__name__} : {e}")
            continue

    return {
        "agent_name": agent_name,
        "agent_id": agent_id,
        "iocs": []
    }

def is_suspicious(entry):
    """Analyse intelligente du résultat CTI pour détecter les menaces potentielles."""
    source = entry.get("source", "").lower()

    if source == "virustotal":
        malicious = entry.get("malicious", 0)
        suspicious = entry.get("suspicious", 0)
        harmless = entry.get("harmless", 0)
        undetected = entry.get("undetected", 0)
        total_votes = malicious + suspicious + harmless + undetected

        return malicious > 0 or (suspicious > 0 and malicious + suspicious > harmless)

    elif source == "abuseipdb":
        abuse_score = entry.get("abuseConfidenceScore", 0)
        total_reports = entry.get("totalReports", 0)
        is_whitelisted = entry.get("isWhitelisted", False)

        return not is_whitelisted and (abuse_score >= 50 or total_reports >= 10)

    elif source == "alienvault":
        pulses = entry.get("pulses", [])
        tags = entry.get("tags", [])
        count = entry.get("count", 0)

        return count > 0 and (len(pulses) > 0 or any(tag.lower() in ["malware", "phishing", "c2", "apt"] for tag in tags))

    elif source == "urlscan":
        verdicts = entry.get("verdicts", {})
        seen = entry.get("seen", 0)

        is_dangerous = verdicts.get("overall", {}).get("score", 0) > 0
        malicious_tags = verdicts.get("overall", {}).get("malicious", False)

        return is_dangerous or malicious_tags or seen > 100

    elif source == "threatfox":
        threat_type = entry.get("threat_type", "").lower()
        confidence = entry.get("confidence_level", 0)

        return threat_type in ["malware", "c2", "phishing"] and confidence >= 70

    return False


def analyze_and_save_alert(alert_result, agent_name, alert_id):
    """Analyse les résultats CTI et sauvegarde ceux considérés comme alertes."""
    findings = []

    for entry in alert_result:
        if is_suspicious(entry):
            findings.append(entry)

    if findings:

        alert_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent": agent_name,
            "alert_id": alert_id,
            "suspicious_iocs": findings
        }


        print(f"[ALERTE SAUVEGARDÉE] Fichier créé : {alert_data}")
    else:
        print("[INFO] Aucun IOC suspect détecté, aucune alerte sauvegardée.")


def alert_processor(alert):
        print("[ALERT] Alerte reçue :", alert)

        data = extract_ioc(alert)
        agent_name = data.get("agent_name", "unknown")
        agent_id = data.get("agent_id", "unknown")
        iocs = data.get("iocs", [])

        print("[INFO] IOCs extraits :", iocs)

        result_list = []
        for ioc_type, ioc_value in iocs:
            print(f"[CTI] Vérification de {ioc_type.upper()} : {ioc_value}")
            results = multi_cti_lookup(ioc_value, ioc_type)
            result_list.extend(results)

        print(f"[RESULTAT FINAL POUR L'ALERTE VIENT DE agent: {agent_name} avec l'ID: {agent_id}] :")
        print(json.dumps({"alert_result": result_list}, indent=2))

        analyze_and_save_alert(result_list, agent_name, agent_id)

        time.sleep(1)
        return {"alert_result": result_list}

