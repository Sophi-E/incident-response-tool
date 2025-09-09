"""
Very simple report generator that writes recent incidents to a Markdown file.
Designed to be run periodically (daily or on demand).
"""

import time
import os
from tabulate import tabulate

class ReportGenerator:
    def __init__(self, db, out_path="./daily_report.md"):
        self.db = db
        self.out_path = out_path

    def build_report(self):
        incidents = self.db.list_incidents(limit=500)
        lines = []
        lines.append("# Daily Incident Report\n")
        lines.append(f"Generated: {time.asctime()}\n")
        if not incidents:
            lines.append("No incidents recorded.\n")
        else:
            table = []
            for i in incidents:
                intel = ""
                try:
                    intel_dict = (i.get("intel_json") and __import__("json").loads(i.get("intel_json"))) or {}
                    vt = intel_dict.get("virustotal", {})
                    intel = f"vt_malicious={vt.get('malicious_count')}"
                except Exception:
                    intel = ""
                table.append([i["id"], i["ip"], i["type"], i["count"], i["first_seen"], i["last_seen"], intel])
            lines.append("## Incidents\n")
            lines.append(tabulate(table, headers=["id", "ip", "type", "count", "first_seen", "last_seen", "intel"]))
            lines.append("\n")
        with open(self.out_path, "w") as fh:
            fh.write("\n".join(lines))

    def daily_report_worker(self):
        # very simple loop: generate report once every 24 hours
        while True:
            try:
                self.build_report()
            except Exception:
                pass
            time.sleep(24 * 3600)
