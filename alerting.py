import requests
import logging
from typing import Optional

LOG = logging.getLogger("irat")

class DiscordAlert:
    def __init__(self, cfg: dict):
        self.enabled: bool = cfg.get("enabled", False)
        self.webhook_url: Optional[str] = cfg.get("webhook_url")

        if self.enabled and not self.webhook_url:
            raise ValueError("Discord alerting enabled but no webhook_url provided.")

    def send(self, message: str):
        if not self.enabled:
            LOG.debug("Discord alerting disabled, skipping.")
            return

        if not self.webhook_url:
            LOG.error("Webhook URL is missing, cannot send alert.")
            return

        payload = {"content": message}
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            if resp.status_code != 204:
                LOG.error("Failed to send Discord alert: %s %s", resp.status_code, resp.text)
        except Exception as e:
            LOG.error("Error sending Discord alert: %s", e)
