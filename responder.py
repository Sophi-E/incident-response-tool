"""
Responder - takes actions (block IP, notify) based on incidents.
By default operates in simulate mode. If you set simulate: false and run with privileges,
it will attempt to execute configured block_command on the system shell.
"""

import subprocess
import shlex
import logging
import json
import requests

LOG = logging.getLogger("responder")
LOG.setLevel(logging.INFO)
LOG.addHandler(logging.StreamHandler())

class Responder:
    def __init__(self, cfg=None, db=None):
        cfg = cfg or {}
        self.simulate = bool(cfg.get("simulate", True))
        self.block_command = cfg.get("block_command", "ufw deny from {ip}")
        self.webhook = cfg.get("webhook_url")
        self.db = db

    def block_ip(self, ip, reason="auto-block"):
        """
        Block the IP. If simulate, just returns the action dict and logs it.
        If not simulate, runs the configured command template.
        """
        action = {"action": "block", "ip": ip, "reason": reason, "timestamp": None, "result": None}
        action["timestamp"] = __import__("datetime").datetime.utcnow().isoformat()
        try:
            if self.simulate:
                action["result"] = "simulated"
                LOG.info("[SIMULATE] block ip %s (reason=%s)", ip, reason)
            else:
                cmd = self.block_command.format(ip=ip)
                LOG.info("Executing block command: %s", cmd)
                args = shlex.split(cmd)
                proc = subprocess.run(args, capture_output=True, text=True, timeout=20)
                action["result"] = {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
                LOG.info("Block result: %s", action["result"])
            # optionally notify
            self.notify_block(action)
        except Exception as e:
            LOG.exception("Failed to block ip %s: %s", ip, e)
            action["result"] = {"error": str(e)}
        return action

    def notify_block(self, action):
        """
        Notify via webhook if configured.
        """
        if not self.webhook:
            return
        try:
            payload = {"type": "block", "action": action}
            requests.post(self.webhook, json=payload, timeout=6)
        except Exception:
            LOG.exception("Webhook notify failed")

    def notify(self, event, intel=None):
        """
        General notification for non-block events (webhook).
        """
        if not self.webhook:
            return
        try:
            payload = {"type": "alert", "event": event, "intel": intel}
            requests.post(self.webhook, json=payload, timeout=6)
        except Exception:
            LOG.exception("Webhook notify failed")
