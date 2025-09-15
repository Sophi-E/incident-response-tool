# 🛡️ SOC Alert System

A lightweight Python-based security monitoring and incident alerting system.  
It analyses logs, detects suspicious activity, and sends **real-time alerts to Discord** via webhooks.

---

## 🚀 Features
- ✅ Monitors logs for suspicious activity (failed logins, scanning, brute-force attempts, etc.)  
- ✅ Configurable rules for detection and thresholds
- ✅ Integrates with:
      - VirusTotal – IP reputation and malware checks
      - IPinfo – geolocation and ASN data
      - AbuseIPDB – reported abuse history 
- ✅ Sends **real-time Discord alerts** when incidents occur  
- ✅ Easy to extend with new detection logic or alert channels  
- ✅ Supports simulation mode for safe testing  

---

## 📦 Requirements
- Python 3.9+
- requests

### Quick Start
  Clone the repository:
  ```bash
   git clone https://github.com/Sophi-E/incident-response-tool
  ```
  ```bash
  cd incident-response-tool
  ```  
 Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```
 Run tool
  ```bash
 python incident-response.py
 ```
 Sample Output
  ```bash
   2025-09-15 10:22:45 INFO 🚨 Incident detected: {'type': 'failed_login', 'ip': '192.168.1.55', 'count': 7}
   2025-09-15 10:22:45 INFO 🔍 Threat intel: {'reputation': 'suspicious', 'recommendation': 'BLOCK'}
   2025-09-15 10:22:45 INFO 💾 Incident logged with id=42
   2025-09-15 10:22:45 INFO 🛑 Responder action: blocked 192.168.1.55
  ```
  Discord Alert
  ```bash
  🚨 Incident Detected
  Type: failed_login
  IP: 192.168.1.55
  Count: 7
  User: root
  First Seen: 2025-09-15 10:15:21
  Last Seen: 2025-09-15 10:22:45
  ```
 
## 🛠️ Tech Stack
- Python 3.10+
- SQLite (incidents DB)
- Discord Webhooks for alerting
- VirusTotal, IPinfo, AbuseIPDB APIs

## 🚀 Roadmap / Ideas

- [ ] Add email alerting option
- [ ] Support additional log sources (nginx, firewall, etc.)
- [ ] Correlation rules (e.g., multiple attack types from the same IP)
- [ ] Web dashboard (Flask/FastAPI + React)


