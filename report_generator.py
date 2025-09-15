import time
import json
from tabulate import tabulate
from collections import Counter


class ReportGenerator:
    def __init__(self, db, out_path="./daily_report.md"):
        self.db = db
        self.out_path = out_path

    def _get_recommendation(self, vt_mal, abuse_score):
        if vt_mal > 0 or abuse_score > 50:
            return "BLOCK"
        elif abuse_score > 10:
            return "MONITOR"
        else:
            return "ALLOW"

    def build_report(self):
        incidents = self.db.list_incidents(limit=1000)
        lines = []
        lines.append("# Daily Incident Report\n")
        lines.append(f"Generated: {time.asctime()}\n")

        if not incidents:
            lines.append("No incidents recorded.\n")
        else:
            # --- Summary Stats ---
            total_incidents = len(incidents)
            unique_ips = len(set([i["ip"] for i in incidents]))
            type_counts = Counter([i["type"] for i in incidents])

            block_count = 0
            monitor_count = 0

            lines.append("## Summary\n")
            lines.append(f"- Total incidents: {total_incidents}")
            lines.append(f"- Unique IPs: {unique_ips}")
            if type_counts:
                common_attack, common_count = type_counts.most_common(1)[0]
                lines.append(f"- Most common attack: {common_attack} ({common_count} times)")
            lines.append("")

            # --- Detailed Incident Table ---
            table = []
            top_malicious = []

            for i in sorted(incidents, key=lambda x: x["last_seen"], reverse=True):
                try:
                    intel_dict = (
                        (i.get("intel_json") and json.loads(i.get("intel_json"))) or {}
                    )
                    vt = intel_dict.get("virustotal", {})
                    abuse = intel_dict.get("abuseipdb", {})
                    ipinfo = intel_dict.get("ipinfo", {})

                    vt_mal = vt.get("malicious_count", 0)
                    vt_susp = vt.get("suspicious_count", 0)
                    abuse_score = abuse.get("abuseConfidenceScore", 0)
                    country = ipinfo.get("country", "N/A")
                    city = ipinfo.get("city", "N/A")

                    recommendation = self._get_recommendation(vt_mal, abuse_score)
                    if recommendation == "BLOCK":
                        block_count += 1
                    elif recommendation == "MONITOR":
                        monitor_count += 1

                    intel_summary = (
                        f"VT_mal={vt_mal}, VT_susp={vt_susp}, AbuseScore={abuse_score}"
                    )

                    # Track malicious for summary
                    if vt_mal > 0 or abuse_score > 10:
                        top_malicious.append(
                            {
                                "ip": i["ip"],
                                "vt_mal": vt_mal,
                                "abuse_score": abuse_score,
                                "country": country,
                                "last_seen": i["last_seen"],
                                "intel": intel_summary,
                                "recommendation": recommendation,
                            }
                        )
                except Exception:
                    intel_summary = "N/A"
                    country = "N/A"
                    city = "N/A"
                    recommendation = "ALLOW"

                table.append(
                    [
                        i["id"],
                        i["ip"],
                        i["type"],
                        i["count"],
                        i["first_seen"],
                        i["last_seen"],
                        country,
                        city,
                        intel_summary,
                        recommendation,
                    ]
                )

            # Update summary counts with block/monitor
            lines.append(f"- Block recommendations: {block_count} ({round((block_count/total_incidents)*100, 1)}%)")
            lines.append(f"- Monitor recommendations: {monitor_count} ({round((monitor_count/total_incidents)*100, 1)}%)\n")

            lines.append("### Incidents by Type\n")
            lines.append(tabulate(type_counts.items(), headers=["Type", "Count"]))
            lines.append("")

            lines.append("## Detailed Incidents\n")
            lines.append(
                tabulate(
                    table,
                    headers=[
                        "ID",
                        "IP",
                        "Type",
                        "Count",
                        "First Seen",
                        "Last Seen",
                        "Country",
                        "City",
                        "Intel",
                        "Recommendation",
                    ],
                )
            )
            lines.append("")

            # --- Top Malicious Section ---
            if top_malicious:
                lines.append("## Top Malicious IPs\n")
                top_malicious.sort(
                    key=lambda x: (x["vt_mal"], x["abuse_score"]), reverse=True
                )
                top_table = [
                    [
                        t["ip"],
                        t["vt_mal"],
                        t["abuse_score"],
                        t["country"],
                        t["last_seen"],
                    ]
                    for t in top_malicious[:10]
                ]
                lines.append(
                    tabulate(
                        top_table,
                        headers=[
                            "IP",
                            "VT Malicious",
                            "AbuseIPDB Score",
                            "Country",
                            "Last Seen",
                        ],
                    )
                )
                lines.append("")

                # Narrative summaries
                lines.append("## Narrative Summaries\n")
                for t in top_malicious[:5]:
                    lines.append(
                        f"**{t['ip']}** ({t['country']})  \n"
                        f"- Intel: {t['intel']}  \n"
                        f"- Recommendation: {t['recommendation']}\n"
                    )

        # --- Write to file ---
        with open(self.out_path, "w") as fh:
            fh.write("\n".join(lines))

    def daily_report_worker(self):
        while True:
            try:
                self.build_report()
            except Exception as e:
                print(f"[ReportGenerator] Error: {e}")
            time.sleep(60 * 60 * 24)
