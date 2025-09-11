import time
import os
import json
from tabulate import tabulate
from collections import Counter, defaultdict


class ReportGenerator:
    def __init__(self, db, out_path="./daily_report.md"):
        self.db = db
        self.out_path = out_path

    def build_report(self):
        incidents = self.db.list_incidents(limit=1000)
        lines = []
        lines.append("# Daily Incident Report\n")
        lines.append(f"Generated: {time.asctime()}\n")

        if not incidents:
            lines.append("No incidents recorded.\n")
        else:
            # --- Summary Stats ---
            lines.append("## Summary\n")
            type_counts = Counter([i["type"] for i in incidents])
            lines.append("### Incidents by Type\n")
            lines.append(tabulate(type_counts.items(), headers=["Type", "Count"]))
            lines.append("")

            # --- Detailed Incident Table ---
            table = []
            top_malicious = []
            for i in incidents:
                intel_summary = ""
                try:
                    intel_dict = (
                        (i.get("intel_json") and json.loads(i.get("intel_json"))) or {}
                    )
                    vt = intel_dict.get("virustotal", {})
                    abuse = intel_dict.get("abuseipdb", {})
                    vt_mal = vt.get("malicious_count", 0)
                    vt_susp = vt.get("suspicious_count", 0)
                    abuse_score = abuse.get("abuseConfidenceScore", 0)
                    intel_summary = (
                        f"VT_mal={vt_mal}, VT_susp={vt_susp}, AbuseScore={abuse_score}"
                    )

                    # Keep track of high malicious IPs
                    if vt_mal > 0 or abuse_score > 50:
                        top_malicious.append(
                            {
                                "ip": i["ip"],
                                "vt_mal": vt_mal,
                                "abuse_score": abuse_score,
                                "last_seen": i["last_seen"],
                            }
                        )
                except Exception:
                    intel_summary = "N/A"

                table.append(
                    [
                        i["id"],
                        i["ip"],
                        i["type"],
                        i["count"],
                        i["first_seen"],
                        i["last_seen"],
                        intel_summary,
                    ]
                )

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
                        "Intel",
                    ],
                )
            )
            lines.append("")

            # --- Top Malicious Section ---
            if top_malicious:
                lines.append("## Top Malicious IPs\n")
                # Sort by severity (VT malicious first, then abuse score)
                top_malicious.sort(
                    key=lambda x: (x["vt_mal"], x["abuse_score"]), reverse=True
                )
                top_table = [
                    [
                        t["ip"],
                        t["vt_mal"],
                        t["abuse_score"],
                        t["last_seen"],
                    ]
                    for t in top_malicious[:10]
                ]
                lines.append(
                    tabulate(
                        top_table,
                        headers=["IP", "VT Malicious", "AbuseIPDB Score", "Last Seen"],
                    )
                )
                lines.append("")

        with open(self.out_path, "w") as fh:
            fh.write("\n".join(lines))

    def daily_report_worker(self):
        # very simple loop: generate report once every 24 hours
        while True:
            try:
                self.build_report()
            except Exception as e:
                print(f"[ReportGenerator] Error: {e}")
            time.sleep(24 * 3600)
