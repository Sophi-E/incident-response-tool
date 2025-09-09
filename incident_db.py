"""
Simple SQLite wrapper for incidents.
"""

import sqlite3
import json
import threading
import datetime

class IncidentDB:
    def __init__(self, path="./incidents.db"):
        self.path = path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    ip TEXT,
                    count INTEGER,
                    first_seen TEXT,
                    last_seen TEXT,
                    user TEXT,
                    raw_lines TEXT,
                    intel_json TEXT,
                    created_at TEXT,
                    action_json TEXT
                )
                """
            )

    def _conn(self):
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def insert_incident(self, data):
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO incidents (type, ip, count, first_seen, last_seen, user, raw_lines, intel_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    data.get("type"),
                    data.get("ip"),
                    int(data.get("count") or 0),
                    data.get("first_seen"),
                    data.get("last_seen"),
                    data.get("user"),
                    data.get("raw_lines"),
                    json.dumps(data.get("intel", {})),
                    datetime.datetime.utcnow().isoformat(),
                ),
            )
            return cur.lastrowid

    def mark_incident_action(self, incident_id, action_dict):
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE incidents SET action_json = ? WHERE id = ?",
                (json.dumps(action_dict), incident_id),
            )

    def list_incidents(self, limit=100):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
