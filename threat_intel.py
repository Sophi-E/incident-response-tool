"""
ThreatIntel - optional enrichment using VirusTotal, IPinfo, AbuseIPDB.
All calls are safe-guarded and return partial results on failure.
"""

import requests
import time

class ThreatIntel:
    def __init__(self, cfg):
        self.vt_key = (cfg or {}).get("virustotal_api_key") or ""
        self.ipinfo_key = (cfg or {}).get("ipinfo_api_key") or ""
        self.abuseipdb_key = (cfg or {}).get("abuseipdb_api_key") or ""
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "IRAT/1.0"})

    def enrich_ip(self, ip):
        """
        Returns a dictionary with available results:
          {
            "virustotal": {"malicious_count": int, ...},
            "ipinfo": {...},
            "abuseipdb": {...}
          }
        """
        out = {}
        try:
            if self.vt_key:
                out["virustotal"] = self._vt_ip_report(ip)
        except Exception:
            out["virustotal_error"] = True

        try:
            if self.ipinfo_key:
                out["ipinfo"] = self._ipinfo_lookup(ip)
        except Exception:
            out["ipinfo_error"] = True

        try:
            if self.abuseipdb_key:
                out["abuseipdb"] = self._abuseipdb_check(ip)
        except Exception:
            out["abuseipdb_error"] = True

        return out

    def _vt_ip_report(self, ip):
        # VirusTotal v3 domain/ip endpoint
        headers = {"x-apikey": self.vt_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        resp = self.session.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return {"error": f"vt_status_{resp.status_code}"}
        data = resp.json().get("data", {}).get("attributes", {})
        # count positive vendors if available
        last_analysis = data.get("last_analysis_stats", {}) or {}
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        return {"malicious_count": malicious, "suspicious_count": suspicious, "raw": last_analysis}

    def _ipinfo_lookup(self, ip):
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if self.ipinfo_key:
            url += f"?token={self.ipinfo_key}"
        resp = self.session.get(url, headers=headers, timeout=6)
        if resp.status_code != 200:
            return {"error": f"ipinfo_status_{resp.status_code}"}
        return resp.json()

    def _abuseipdb_check(self, ip):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = self.session.get(url, headers=headers, params=params, timeout=8)
        if resp.status_code != 200:
            return {"error": f"abuseipdb_status_{resp.status_code}"}
        return resp.json().get("data", {})
