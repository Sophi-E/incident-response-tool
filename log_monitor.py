"""
LogMonitor - tail a file and detect suspicious patterns such as repeated failed SSH logins,
port scans, and sensitive file access.
"""

import time
import os
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

# Regex patterns
SSH_FAILED_REGEX = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
SSH_ACCEPTED_REGEX = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


class LogMonitor:
    def __init__(self, path, callback, poll_interval=1.0, detection_config=None):
        self.path = path
        self.callback = callback
        self.poll_interval = float(poll_interval or 1.0)
        self._stop_event = threading.Event()
        self.thread = None

        cfg = detection_config or {}
        self.threshold = int(cfg.get("failed_login_threshold", 5))
        self.window_seconds = int(cfg.get("failed_login_window_seconds", 60))
        self.portscan_keyword = cfg.get("port_scan_keyword", "Nmap scan detected")
        self.sensitive_file_keyword = cfg.get("sensitive_file_keyword", "/etc/passwd")

        # per-ip deque of (timestamp, user, raw_line)
        self.failed_store = defaultdict(deque)

    def _tail_generator(self, file):
        file.seek(0, os.SEEK_END)
        while not self._stop_event.is_set():
            line = file.readline()
            if not line:
                time.sleep(self.poll_interval)
                continue
            yield line.rstrip("\n")

    def _process_line(self, line):
        now_ts = datetime.now(timezone.utc).timestamp()

        # -------------------
        # Rule 1: SSH failed logins
        # -------------------
        m = SSH_FAILED_REGEX.search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")
            dq = self.failed_store[ip]
            dq.append((now_ts, user, line))
            # purge old entries outside window
            cutoff = now_ts - self.window_seconds
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            if len(dq) >= self.threshold:
                first_ts = dq[0][0]
                last_ts = dq[-1][0]
                event = {
                    "type": "failed_login",
                    "ip": ip,
                    "count": len(dq),
                    "first_seen": datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat(),
                    "last_seen": datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat(),
                    "user": dq[-1][1],
                    "raw_lines": [x[2] for x in dq],
                }
                self.failed_store[ip].clear()  # reset after detection
                return event

        # -------------------
        # Rule 2: Port scan keyword
        # -------------------
        if self.portscan_keyword and self.portscan_keyword in line:
            return {
                "type": "port_scan",
                "ip": "unknown",
                "count": 1,
                "first_seen": datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(),
                "last_seen": datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(),
                "user": None,
                "raw_lines": [line],
            }

        # -------------------
        # Rule 3: Sensitive file access
        # -------------------
        if self.sensitive_file_keyword and self.sensitive_file_keyword in line:
            return {
                "type": "sensitive_file_access",
                "ip": "unknown",
                "count": 1,
                "first_seen": datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(),
                "last_seen": datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(),
                "user": None,
                "raw_lines": [line],
            }

        return None

    def start(self):
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"log file does not exist: {self.path}")

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            with open(self.path, "r", errors="ignore") as fh:
                gen = self._tail_generator(fh)
                for line in gen:
                    if self._stop_event.is_set():
                        break
                    try:
                        ev = self._process_line(line)
                        if ev:
                            # callback handled in separate thread to avoid blocking
                            threading.Thread(target=self.callback, args=(ev,), daemon=True).start()
                    except Exception:
                        continue  # keep monitoring even if one line breaks
        except Exception as e:
            raise  # bubble up for main handler

    def stop(self):
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
