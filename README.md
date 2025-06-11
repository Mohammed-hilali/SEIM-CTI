Project Overview:
   In this project, I present two methods to integrate Cyber Threat Intelligence (CTI) into the Wazuh SIEM platform:
1- Native Integration using Wazuh's built-in support for VirusTotal.
2- Custom Integration through a Flask API that dynamically interacts with multiple CTI sources 
such as VirusTotal, URLScan, AbuseIPDB, and AlienVault OTX.
   Additionally, I demonstrate how to build a complete home SOC (Security Operations Center) lab using Wazuh 
as the SIEM solution and Sysmon to collect logs from Windows machines.The lab is based on a small architecture 
that you can expand and customize based on your needs—for example, by integrating AI to automate threat detection, 
or by connecting other ecosystems to improve visibility and control in your custom security infrastructure.


Security Information and Event Management with Cyber Threat Intelligence
📌 Project Goals
- Analyze Wazuh alerts in real time (especially from Sysmon logs).
- Automatically extract IOCs (IPs, hashes, domains, URLs).
- Query multiple CTI platforms to enrich alerts.
- Automate response actions (blocking, alert tagging).

🧱 Project Architecture
Native Integration using Wazuh's built-in support for VirusTotal:
![image](https://github.com/user-attachments/assets/817f2d61-0062-4082-a757-37d9effb3d20)
   One of the most straightforward integrations available in Wazuh is with VirusTotal—a popular
online service that aggregates antivirus scan results and threat intelligence data from multiple sources.
Wazuh facilitates VirusTotal integration through pre-built scripts, decoders, and rules,
which simplifies the process considerably. Specifically:
File Integrity Monitoring (FIM), Pre-existing Scripts, Decoders and Rules,Alert Enrichment and Operational Benefits (This integration helps reduce false positives)

First, we need to enable File Integrity Monitoring (FIM) on important directories such as /tmp/malware. 
![image](https://github.com/user-attachments/assets/7ed874e5-4045-444d-adf9-f0563ad6ff4f)
When a change occurs in the monitored directory, FIM generates an alert and
sends it to the Wazuh manager along with the necessary file hashes. This alert then trig-gers the VirusTotal integration script, 
for integration we use the file ossec.conf with this configuration :
![image](https://github.com/user-attachments/assets/d3e2f18b-e086-4ba3-ba74-5c01350d4ec5)



Custom Integration through a Flask API:
![image](https://github.com/user-attachments/assets/07bc9cde-43d0-4174-9a19-058dbc87ac59)

