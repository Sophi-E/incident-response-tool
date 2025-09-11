from typing import Any, Dict
import requests
import logging

log = logging.getLogger(__name__)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            s = value.strip()
            if s == "":
                return default
            # handle values like "85" or "85.0"
            return int(float(s))
    except Exception:
        return default
    return default


class ThreatIntel:
    def __init__(self, config: Dict[str, Any]):
        cfg = config or {}
        self.vt_key = cfg.get("virustotal_api_key") or ""
        self.ipinfo_key = cfg.get("ipinfo_api_key") or ""
        self.abuseipdb_key = cfg.get("abuseipdb_api_key") or ""
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "IRAT/1.0"})

    # ----------------------------
    # VirusTotal IP Lookup
    # ----------------------------
    def _query_virustotal(self, ip: str) -> Dict[str, Any]:
        if not self.vt_key:
            return {}
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_key}
            resp = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                return {"error": f"vt_status_{resp.status_code}"}
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {}) or {}
            # normalise keys we use
            return {
                "malicious_count": _safe_int(stats.get("malicious")),
                "suspicious_count": _safe_int(stats.get("suspicious")),
                "raw": stats,
            }
        except Exception as e:
            log.warning("VirusTotal lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    # ----------------------------
    # IPInfo Lookup
    # ----------------------------
    def _query_ipinfo(self, ip: str) -> Dict[str, Any]:
        if not self.ipinfo_key:
            return {}
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if self.ipinfo_key:
                url += f"?token={self.ipinfo_key}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return {"error": f"ipinfo_status_{resp.status_code}"}
            data = resp.json()
            return {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "org": data.get("org"),
                "raw": data,
            }
        except Exception as e:
            log.warning("IPInfo lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    # ----------------------------
    # AbuseIPDB Lookup
    # ----------------------------
    def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.abuseipdb_key:
            return {}
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            resp = self.session.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code != 200:
                return {"error": f"abuseipdb_status_{resp.status_code}"}
            data = resp.json().get("data", {}) or {}
            return {
                "abuseConfidenceScore": _safe_int(data.get("abuseConfidenceScore")),
                "totalReports": _safe_int(data.get("totalReports")),
                "isp": data.get("isp"),
                "countryCode": data.get("countryCode"),
                "raw": data,
            }
        except Exception as e:
            log.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    # ----------------------------
    # Main Enrichment
    # ----------------------------
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        vt = {}
        ipi = {}
        abuse = {}

        try:
            if self.vt_key:
                vt = self._query_virustotal(ip) or {}
        except Exception as e:
            log.warning("VirusTotal call failed for %s: %s", ip, e)
            vt = {"error": str(e)}

        try:
            if self.ipinfo_key:
                ipi = self._query_ipinfo(ip) or {}
        except Exception as e:
            log.warning("IPInfo call failed for %s: %s", ip, e)
            ipi = {"error": str(e)}

        try:
            if self.abuseipdb_key:
                abuse = self._query_abuseipdb(ip) or {}
        except Exception as e:
            log.warning("AbuseIPDB call failed for %s: %s", ip, e)
            abuse = {"error": str(e)}

        # Threat scoring (all ints)
        score = 0

        # VirusTotal: malicious_count * 2 + suspicious_count
        vt_mal = _safe_int(vt.get("malicious_count"))
        vt_susp = _safe_int(vt.get("suspicious_count"))
        if vt_mal > 0:
            score += vt_mal * 2
        if vt_susp > 0:
            score += vt_susp

        # AbuseIPDB: weighted buckets
        abuse_conf = _safe_int(abuse.get("abuseConfidenceScore"))
        abuse_reports = _safe_int(abuse.get("totalReports"))
        if abuse_conf >= 80:
            score += 40
        elif abuse_conf >= 50:
            score += 20
        elif abuse_conf > 0:
            score += 5

        if abuse_reports >= 50:
            score += 30
        elif abuse_reports >= 20:
            score += 15
        elif abuse_reports > 0:
            score += 5

        # IPInfo: hosting/cloud providers get a small increase (common for attack sources)
        org = ipi.get("org") or ""
        if isinstance(org, str):
            org_l = org.lower()
            if any(kw in org_l for kw in ("digitalocean", "linode", "amazon", "aws", "google", "azure", "hetzner")):
                score += 10

        # Final recommendation
        if score >= 70:
            recommendation = "BLOCK"
        elif score >= 40:
            recommendation = "ALERT"
        elif score >= 10:
            recommendation = "MONITOR"
        else:
            recommendation = "ALLOW"

        return {
            "ip": ip,
            "virustotal": vt,
            "ipinfo": ipi,
            "abuseipdb": abuse,
            "score": int(score),
            "recommendation": recommendation,
        }
