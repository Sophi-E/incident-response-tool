#!/usr/bin/env python3
"""
Main entry point for the Incident Response Automation Tool (IRAT).
"""

import time
import threading
import logging
import yaml
import os
from log_monitor import LogMonitor
from responder import Responder
from incident_db import IncidentDB
from report_generator import ReportGenerator
from threat_intel import ThreatIntel

LOG = logging.getLogger("irat")
LOG.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
LOG.addHandler(handler)


def load_config(path="config.yaml"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r") as fh:
        cfg = yaml.safe_load(fh)
    return cfg


def start_services(cfg):
    db = IncidentDB(cfg.get("database_path", "./incidents.db"))
    responder = Responder(cfg.get("responder", {}), db=db)
    ti = ThreatIntel(cfg.get("threat_intel", {}))
    lm = LogMonitor(
        path=cfg.get("log_path"),
        callback=lambda ev: handle_event(ev, cfg, db, responder, ti),
        poll_interval=cfg.get("monitor_interval_secs", 1.0),
        detection_config=cfg.get("detection", {}),
    )

    return lm, db, responder


def handle_event(event, cfg, db, responder, ti):
    LOG.info("🚨 Incident detected: %s", event)

    # --- Threat Intel Enrichment ---
    intel = {}
    try:
        intel = ti.enrich_ip(event["ip"])
        LOG.info("🔍 Threat intel: %s", intel)
    except Exception as e:
        LOG.warning("Threat intel enrichment failed: %s", e)

    incident = {
        "type": event["type"],
        "ip": event["ip"],
        "count": event.get("count", 0),
        "first_seen": event.get("first_seen"),
        "last_seen": event.get("last_seen"),
        "user": event.get("user"),
        "raw_lines": "\n".join(event.get("raw_lines", [])[:20]),
        "intel": intel,
    }

    # --- Save incident ---
    incident_id = db.insert_incident(incident)
    LOG.info("💾 Incident logged with id=%s", incident_id)

    # --- Response policy ---
    should_block = False
    if intel.get("recommendation") == "BLOCK":
        should_block = True

    if event.get("count", 0) >= cfg.get("detection", {}).get("failed_login_threshold", 5):
        should_block = True

    if should_block:
        action = responder.block_ip(event["ip"], reason="auto-detect - brute force / intel")
        db.mark_incident_action(incident_id, action)
        LOG.info("🛑 Responder action: %s", action)
    else:
        LOG.info("⚠️ No auto-block triggered for %s", event["ip"])
        responder.notify(event, intel)



def run_forever(cfg):
    lm, db, responder = start_services(cfg)
    try:
        LOG.info("Starting log monitor...")
        lm.start()
        LOG.info("Log monitor running. Press Ctrl+C to stop.")
        # daily report generator thread (every 24 hours), simple example: run once per day at midnight could be added.
        report_gen = ReportGenerator(db, cfg.get("daily_report_path", "./daily_report.md"))
        report_thread = threading.Thread(target=report_gen.daily_report_worker, daemon=True)
        report_thread.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        LOG.info("Shutting down...")
        lm.stop()
    except Exception as e:
        LOG.exception("Unexpected error: %s", e)
        lm.stop()


if __name__ == "__main__":
    cfg = load_config("config.yaml")
    run_forever(cfg)
