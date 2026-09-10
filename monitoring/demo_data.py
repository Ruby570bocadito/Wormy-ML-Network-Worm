"""
Demo data provider for the Wormy web dashboard.

Serves a realistic, clearly-labelled synthetic engagement so the dashboard
can be evaluated, screenshotted and demonstrated without touching any real
network. Nothing here performs I/O beyond the loopback interface.

Usage:
    python -m monitoring.web_dashboard --demo
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

_NOW = datetime.now(timezone.utc)


def _ago(minutes: int) -> datetime:
    return _NOW - timedelta(minutes=minutes)


class _DemoHostMonitor:
    """Minimal stand-in exposing the attributes the dashboard reads."""

    def __init__(self):
        self.hosts = {
            "10.20.0.10": SimpleNamespace(
                os_guess="Ubuntu 22.04 LTS",
                status="infected",
                health_score=97.4,
                detection_risk=6.1,
                cpu_usage=12.3,
                memory_usage=41.8,
                payload_variant="poly-A7f2",
                infected_at=_ago(118),
                last_beacon=_ago(1),
                activity_log=[object()] * 214,
                credentials_found=[("svc-backup", "Br3ach3d!"), ("deploy", "Summ3r2023!")],
                lateral_movement_history=[
                    {"target": "10.20.0.15", "technique": "ssh_key_reuse", "success": True},
                    {"target": "10.20.0.22", "technique": "smb_creds", "success": True},
                ],
            ),
            "10.20.0.15": SimpleNamespace(
                os_guess="Debian 12",
                status="infected",
                health_score=93.0,
                detection_risk=9.7,
                cpu_usage=8.9,
                memory_usage=36.2,
                payload_variant="poly-C11d",
                infected_at=_ago(74),
                last_beacon=_ago(2),
                activity_log=[object()] * 96,
                credentials_found=[("admin", "P@ssw0rd1")],
                lateral_movement_history=[
                    {"target": "10.20.0.30", "technique": "telnet_default", "success": False},
                ],
            ),
            "10.20.0.22": SimpleNamespace(
                os_guess="Windows Server 2019",
                status="infected",
                health_score=88.5,
                detection_risk=14.2,
                cpu_usage=23.6,
                memory_usage=57.4,
                payload_variant="poly-B3e9",
                infected_at=_ago(41),
                last_beacon=_ago(1),
                activity_log=[object()] * 143,
                credentials_found=[],
                lateral_movement_history=[],
            ),
            "10.20.0.30": SimpleNamespace(
                os_guess="CentOS Stream 9",
                status="monitored",
                health_score=99.1,
                detection_risk=2.4,
                cpu_usage=4.1,
                memory_usage=22.7,
                payload_variant="-",
                infected_at=None,
                last_beacon=None,
                activity_log=[object()] * 12,
                credentials_found=[],
                lateral_movement_history=[],
            ),
        }

    def get_activity_feed(self, limit: int = 50):
        feed = [
            {
                "timestamp": _ago(1).isoformat(),
                "type": "beacon",
                "host_ip": "10.20.0.22",
                "details": "C2 beacon ok (HTTPS, jitter 0.18)",
            },
            {
                "timestamp": _ago(2).isoformat(),
                "type": "beacon",
                "host_ip": "10.20.0.10",
                "details": "C2 beacon ok (HTTPS, jitter 0.11)",
            },
            {
                "timestamp": _ago(3).isoformat(),
                "type": "credential",
                "host_ip": "10.20.0.10",
                "details": "found credential pair svc-backup via config dump",
            },
            {
                "timestamp": _ago(6).isoformat(),
                "type": "lateral",
                "host_ip": "10.20.0.15",
                "details": "attempted ssh_key_reuse -> 10.20.0.30 (blocked by lab policy)",
            },
            {
                "timestamp": _ago(9).isoformat(),
                "type": "propagation",
                "host_ip": "10.20.0.22",
                "details": "exploit chain smb+creds succeeded, payload poly-B3e9 implanted",
            },
            {
                "timestamp": _ago(12).isoformat(),
                "type": "scan",
                "host_ip": "10.20.0.30",
                "details": "port scan: 22,80,443 open; OS guess CentOS Stream 9",
            },
            {
                "timestamp": _ago(15).isoformat(),
                "type": "beacon",
                "host_ip": "10.20.0.15",
                "details": "C2 beacon ok (HTTPS, jitter 0.22)",
            },
            {
                "timestamp": _ago(18).isoformat(),
                "type": "rl",
                "host_ip": "-",
                "details": "DQN action=3 (lateral via SSH) reward=+1.2 epsilon=0.31",
            },
            {
                "timestamp": _ago(24).isoformat(),
                "type": "propagation",
                "host_ip": "10.20.0.15",
                "details": "exploit chain ssh+weak_password succeeded",
            },
            {
                "timestamp": _ago(31).isoformat(),
                "type": "scan",
                "host_ip": "10.20.0.22",
                "details": "smb signing disabled, MS17-010 candidate",
            },
        ]
        return feed[:limit]

    def get_statistics(self):
        return {
            "hosts_tracked": len(self.hosts),
            "infected": sum(1 for h in self.hosts.values() if h.status == "infected"),
            "avg_health": round(
                sum(h.health_score for h in self.hosts.values()) / len(self.hosts), 1
            ),
            "avg_detection_risk": round(
                sum(h.detection_risk for h in self.hosts.values()) / len(self.hosts), 1
            ),
        }


class _DemoCredManager:
    def get_discovered_credentials(self):
        return [
            ("svc-backup", "Br3ach3d!"),
            ("deploy", "Summ3r2023!"),
            ("admin", "P@ssw0rd1"),
        ]


class _DemoIdsEvasion:
    def get_statistics(self):
        return {
            "signature_checks": 342,
            "signatures_evaded": 329,
            "evasion_rate": 0.962,
            "rate_limit_delays": 57,
            "jitter_recalibrations": 12,
        }


class _DemoConfig:
    network = SimpleNamespace(target_ranges=["10.20.0.0/24"])


class DemoWorm:
    """Duck-typed WormCore stand-in: 100% synthetic, zero network activity."""

    def __init__(self):
        self.running = True
        self.dry_run = True
        self.demo = True
        self.start_time = _ago(120)
        self.infected_hosts = {"10.20.0.10", "10.20.0.15", "10.20.0.22"}
        self.failed_targets = {"10.20.0.99"}
        self.config = _DemoConfig()
        self.host_monitor = _DemoHostMonitor()
        self.cred_manager = _DemoCredManager()
        self.ids_evasion = _DemoIdsEvasion()
        self.stats = {
            "total_hosts_discovered": 254,
            "vulnerabilities_found": 47,
            "exploit_chains_built": 18,
            "lateral_movements": 6,
            "lateral_success": 4,
            "brute_force_attempts": 812,
            "brute_force_successes": 9,
            "credentials_discovered": 3,
            "c2_beacons": 118,
            "polymorphic_mutations": 27,
        }
        self.scan_results = [
            {
                "ip": "10.20.0.10",
                "os_guess": "Ubuntu 22.04 LTS",
                "open_ports": [22, 80, 443],
                "vulnerabilities": [
                    {
                        "cve": "CVE-2023-38545",
                        "name": "curl SOCKS5 heap overflow",
                        "severity": "HIGH",
                        "cvss": 8.8,
                        "description": "lab-only vulnerable curl build",
                    },
                    {
                        "cve": "CVE-2021-3156",
                        "name": "sudo heap overflow (Baron Samedit)",
                        "severity": "HIGH",
                        "cvss": 7.8,
                        "description": "vulnerable sudo 1.8.31 in lab image",
                    },
                ],
            },
            {
                "ip": "10.20.0.15",
                "os_guess": "Debian 12",
                "open_ports": [22, 5432],
                "vulnerabilities": [
                    {
                        "cve": "N/A",
                        "name": "weak ssh password policy",
                        "severity": "MEDIUM",
                        "cvss": 5.3,
                        "description": "password auth enabled, common credentials",
                    },
                ],
            },
            {
                "ip": "10.20.0.22",
                "os_guess": "Windows Server 2019",
                "open_ports": [445, 3389],
                "vulnerabilities": [
                    {
                        "cve": "MS17-010",
                        "name": "SMBv1 EternalBlue",
                        "severity": "CRITICAL",
                        "cvss": 9.3,
                        "description": "metasploitable-style lab target",
                    },
                ],
            },
            {
                "ip": "10.20.0.30",
                "os_guess": "CentOS Stream 9",
                "open_ports": [22, 80, 443],
                "vulnerabilities": [],
            },
        ]
