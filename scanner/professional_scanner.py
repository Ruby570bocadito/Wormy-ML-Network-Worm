"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Professional Service Detection Scanner
Deep service fingerprinting, version detection, protocol probing,
and vulnerability assessment.
"""


import asyncio
import os
import re
import socket
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class ServiceDetector:
    """
    Professional service detection engine

    Features:
    - Protocol probing for 50+ services
    - Version extraction from banners
    - SSL/TLS detection
    - Service-specific fingerprinting
    - Confidence scoring
    """

    # Protocol probes for service detection
    PROBES = {
        21: {"name": "FTP", "send": None, "expect": b"220"},
        22: {"name": "SSH", "send": None, "expect": b"SSH"},
        23: {"name": "Telnet", "send": None, "expect": None},
        25: {"name": "SMTP", "send": b"EHLO test\r\n", "expect": b"250"},
        53: {"name": "DNS", "send": None, "expect": None},
        80: {"name": "HTTP", "send": b"GET / HTTP/1.0\r\nHost: test\r\n\r\n", "expect": b"HTTP"},
        110: {"name": "POP3", "send": None, "expect": b"+OK"},
        135: {"name": "MSRPC", "send": None, "expect": None},
        139: {"name": "NetBIOS", "send": None, "expect": None},
        143: {"name": "IMAP", "send": b"a001 CAPABILITY\r\n", "expect": b"* OK"},
        443: {"name": "HTTPS", "send": None, "expect": None},
        445: {"name": "SMB", "send": None, "expect": None},
        993: {"name": "IMAPS", "send": None, "expect": None},
        995: {"name": "POP3S", "send": None, "expect": None},
        1433: {"name": "MSSQL", "send": None, "expect": None},
        1521: {"name": "Oracle", "send": None, "expect": None},
        2049: {"name": "NFS", "send": None, "expect": None},
        3306: {"name": "MySQL", "send": None, "expect": None},
        3389: {"name": "RDP", "send": None, "expect": None},
        5432: {"name": "PostgreSQL", "send": b"\x00\x00\x00\x08\x04\xd2\x16\x2f", "expect": None},
        5900: {"name": "VNC", "send": None, "expect": b"RFB"},
        6379: {"name": "Redis", "send": b"*1\r\n$4\r\nPING\r\n", "expect": b"+PONG"},
        8080: {
            "name": "HTTP-Alt",
            "send": b"GET / HTTP/1.0\r\nHost: test\r\n\r\n",
            "expect": b"HTTP",
        },
        8443: {"name": "HTTPS-Alt", "send": None, "expect": None},
        9200: {
            "name": "Elasticsearch",
            "send": b"GET / HTTP/1.0\r\n\r\n",
            "expect": b"elasticsearch",
        },
        10250: {"name": "Kubelet", "send": b"GET / HTTP/1.0\r\n\r\n", "expect": None},
        27017: {"name": "MongoDB", "send": None, "expect": None},
        2375: {"name": "Docker", "send": b"GET /version HTTP/1.0\r\n\r\n", "expect": b"ApiVersion"},
        6443: {"name": "Kubernetes", "send": None, "expect": None},
    }

    # Version extraction patterns
    VERSION_PATTERNS = {
        "SSH": re.compile(r"SSH[_\-]?([\d.]+)[\s\-]*(.*)", re.IGNORECASE),
        "FTP": re.compile(r"[\d]+\s+([\w\s\-]+)[\s\(]*([\d.]+)", re.IGNORECASE),
        "HTTP": re.compile(r"Server:\s*([\w\-/.]+)[\s]*", re.IGNORECASE),
        "SMTP": re.compile(r"220\s+(.*)", re.IGNORECASE),
        "MySQL": re.compile(r"[\d]+\.[\d]+\.[\d]+[\s\-]*(.*)", re.IGNORECASE),
        "PostgreSQL": re.compile(r"PostgreSQL[\s]?([\d.]+)", re.IGNORECASE),
        "Redis": re.compile(r"Redis[\s]?v?([\d.]+)", re.IGNORECASE),
        "MongoDB": re.compile(r"MongoDB[\s]?v?([\d.]+)", re.IGNORECASE),
        "Elasticsearch": re.compile(r"Elasticsearch[\s]?([\d.]+)", re.IGNORECASE),
        "VNC": re.compile(r"RFB[\s]?([\d.]+)", re.IGNORECASE),
        "SMB": re.compile(r"(Windows[\s\w]+)", re.IGNORECASE),
        "Docker": re.compile(r"ApiVersion[\s:]*([\d.]+)", re.IGNORECASE),
    }

    def detect_service(self, ip: str, port: int, timeout: float = 3.0) -> Dict:
        """
        Detect service on a port with version extraction

        Returns:
            {service, version, banner, confidence, protocol}
        """
        probe = self.PROBES.get(port)
        if not probe:
            return {
                "service": "unknown",
                "version": "",
                "banner": "",
                "confidence": 0.3,
                "protocol": "tcp",
            }

        banner = ""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Read initial banner
            try:
                banner_bytes = sock.recv(512)
                if banner_bytes:
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass

            # Send probe if defined
            if probe["send"]:
                try:
                    sock.send(probe["send"])
                    sock.settimeout(2)
                    resp = sock.recv(512)
                    if resp:
                        banner = resp.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

            sock.close()

        except Exception as e:
            logger.debug(f"Service detection failed for {ip}:{port}: {e}")

        # Extract version
        version = ""
        confidence = 0.5
        service_name = probe["name"]

        for svc_name, pattern in self.VERSION_PATTERNS.items():
            if svc_name.lower() in service_name.lower() or svc_name.lower() in banner.lower():
                match = pattern.search(banner)
                if match:
                    version = match.group(1).strip()
                    confidence = 0.9
                    break

        # If no version found but we have a banner
        if not version and banner:
            ver_match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", banner)
            if ver_match:
                version = ver_match.group(0)
                confidence = 0.7

        # If no banner at all
        if not banner:
            confidence = 0.4

        return {
            "service": service_name,
            "version": version,
            "banner": banner,
            "confidence": confidence,
            "protocol": "tcp",
        }

    def detect_ssl(self, ip: str, port: int, timeout: float = 3.0) -> Dict:
        """Detect SSL/TLS on a port"""
        try:
            import ssl

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            try:
                wrapped = context.wrap_socket(sock, server_hostname=ip)
                cert = wrapped.getpeercert()
                cipher = wrapped.cipher()
                wrapped.close()

                return {
                    "ssl": True,
                    "version": wrapped.version(),
                    "cipher": cipher[0] if cipher else "",
                    "cert": cert,
                }
            except ssl.SSLError:
                return {"ssl": False}
            except Exception:
                return {"ssl": False}
        except ImportError:
            return {"ssl": False}
        except Exception:
            return {"ssl": False}


class ProfessionalScanner:
    """
    Professional network scanner with:
    - Async port scanning
    - Deep service detection
    - OS fingerprinting
    - Vulnerability assessment
    - Smart target prioritization
    """

    def __init__(self, max_concurrency: int = 100, timeout: float = 2.0):
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.service_detector = ServiceDetector()

        # Common ports by category
        self.port_categories = {
            "essential": [22, 80, 443],
            "windows": [135, 139, 445, 3389, 5985, 5986],
            "linux": [22, 631, 2049, 111],
            "database": [1433, 3306, 5432, 6379, 27017, 1521],
            "web": [80, 443, 8080, 8443, 8888, 9090],
            "mail": [25, 110, 143, 465, 587, 993, 995],
            "infrastructure": [53, 161, 162, 389, 636, 88, 10250, 6443, 2375],
            "remote": [22, 23, 3389, 5900, 5901, 5902, 5903],
        }

    def get_ports_for_scan(self, categories: List[str] = None) -> List[int]:
        """Get port list based on categories"""
        if not categories:
            categories = ["essential", "windows", "linux", "database", "web", "remote"]

        ports = set()
        for cat in categories:
            ports.update(self.port_categories.get(cat, []))

        return sorted(ports)

    async def scan_host(
        self, ip: str, ports: List[int] = None, categories: List[str] = None
    ) -> Dict:
        """
        Scan a single host with full service detection

        Returns:
            Complete host information dict
        """
        if ports is None:
            ports = self.get_ports_for_scan(categories)

        result = {
            "ip": ip,
            "open_ports": [],
            "services": {},
            "banners": {},
            "os_guess": "Unknown",
            "vulnerability_score": 0,
            "hostname": "",
            "ssl_info": {},
            "scan_time": 0,
        }

        start_time = time.time()

        # Phase 1: Port scan
        open_ports = await self._scan_ports_async(ip, ports)
        result["open_ports"] = open_ports

        if not open_ports:
            result["scan_time"] = time.time() - start_time
            return result

        # Phase 2: Service detection
        for port in open_ports:
            service_info = self.service_detector.detect_service(ip, port, self.timeout)
            result["services"][str(port)] = service_info["service"]
            if service_info["version"]:
                result["services"][
                    str(port)
                ] = f"{service_info['service']}/{service_info['version']}"
            if service_info["banner"]:
                result["banners"][str(port)] = service_info["banner"]

            # SSL detection for common ports
            if port in [443, 8443, 993, 995, 465, 587, 636, 8080]:
                ssl_info = self.service_detector.detect_ssl(ip, port)
                if ssl_info.get("ssl"):
                    result["ssl_info"][str(port)] = ssl_info

        # Phase 3: OS detection
        result["os_guess"] = self._detect_os(ip, open_ports, result["banners"])

        # Phase 4: Vulnerability scoring
        result["vulnerability_score"] = self._calculate_vuln_score(
            open_ports, result["banners"], result["services"]
        )

        result["scan_time"] = time.time() - start_time
        return result

    async def _scan_ports_async(self, ip: str, ports: List[int]) -> List[int]:
        """Async port scan"""
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def check_port(port):
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except Exception:
                    return None

        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks)

        return sorted([r for r in results if r is not None])

    def _detect_os(self, ip: str, ports: List[int], banners: Dict) -> str:
        """Detect OS from ports and banners"""
        # Banner-based detection
        for port_str, banner in banners.items():
            bl = banner.lower()
            if any(x in bl for x in ["windows", "microsoft", "iis", "smb"]):
                return "Windows"
            if any(x in bl for x in ["linux", "ubuntu", "debian", "centos", "openssh"]):
                return "Linux"
            if any(x in bl for x in ["cisco", "juniper", "fortinet"]):
                return "Network Device"

        # Port-based detection
        win_ports = {135, 139, 445, 3389, 5985, 5986}
        lin_ports = {22, 631, 2049, 111}

        win_count = sum(1 for p in ports if p in win_ports)
        lin_count = sum(1 for p in ports if p in lin_ports)

        if win_count > lin_count and win_count >= 2:
            return "Windows"
        if lin_count > win_count:
            return "Linux"
        if 23 in ports:
            return "Network Device"

        return "Unknown"

    def _calculate_vuln_score(self, ports: List[int], banners: Dict, services: Dict) -> int:
        """Calculate vulnerability score"""
        score = 0

        # High-risk ports
        high_risk = {
            21: 20,
            23: 25,
            445: 30,
            3389: 20,
            3306: 25,
            5432: 25,
            6379: 30,
            27017: 25,
            9200: 25,
            2375: 35,
            10250: 30,
            6443: 25,
            161: 15,
        }

        for port in ports:
            score += high_risk.get(port, 5)

        # Banner-based detection
        for banner in banners.values():
            bl = banner.lower()
            if any(x in bl for x in ["vulnerable", "outdated", "eol", "default"]):
                score += 20
            if any(x in bl for x in ["ms17-010", "eternalblue", "log4j", "cve-2021"]):
                score += 40

        # Version-based CVE matching
        for port_str, service in services.items():
            port = int(port_str) if str(port_str).isdigit() else 0
            cve_score = self._check_known_vuln_versions(service, port)
            score += cve_score

        return min(score, 100)

    @staticmethod
    def _check_known_vuln_versions(service_str: str, port: int) -> int:
        """Check for known vulnerable versions"""
        score = 0
        version_match = re.search(r"([\d]+)\.([\d]+)", service_str)
        if not version_match:
            return 0

        major = int(version_match.group(1))
        minor = int(version_match.group(2))

        vuln_checks = {
            22: [("OpenSSH", 7, 4, 15)],
            80: [("Apache", 2, 4, 10), ("nginx", 1, 17, 10)],
            445: [("SMB", 1, 0, 30)],
            3306: [("MySQL", 5, 5, 15)],
            5432: [("PostgreSQL", 9, 5, 15)],
            9200: [("Elasticsearch", 1, 0, 25)],
            8080: [("Tomcat", 8, 5, 20), ("Jenkins", 2, 0, 25)],
        }

        if port in vuln_checks:
            for name, vuln_major, vuln_minor, points in vuln_checks[port]:
                if name.lower() in service_str.lower():
                    if major < vuln_major or (major == vuln_major and minor <= vuln_minor):
                        score += points

        return score

    async def scan_network(
        self,
        targets: List[str],
        ports: List[int] = None,
        categories: List[str] = None,
        callback=None,
        progress_callback=None,
        show_progress: bool = True,
    ) -> List[Dict]:
        """
        Scan multiple targets

        Args:
            targets: List of IPs or CIDR ranges
            ports: Specific ports to scan
            categories: Port categories
            callback: Optional callback per host
            show_progress: Show visual progress bar

        Returns:
            List of host results
        """
        import ipaddress

        # Expand targets
        all_ips = []
        for target in targets:
            try:
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                    all_ips.extend(str(ip) for ip in network.hosts())
                else:
                    all_ips.append(target)
            except ValueError:
                logger.warning(f"Invalid target: {target}")

        logger.info(f"Scanning {len(all_ips)} hosts on {len(ports) if ports else 'default'} ports")

        results = []
        scanned = 0
        found = 0
        total = len(all_ips)

        for ip in all_ips:
            try:
                host_result = await self.scan_host(ip, ports, categories)
                if host_result["open_ports"]:
                    results.append(host_result)
                    found += 1
                    if callback:
                        callback(host_result)
            except Exception as e:
                logger.debug(f"Scan error for {ip}: {e}")

            scanned += 1

            if progress_callback:
                progress_callback(scanned, total, found)
            elif show_progress:
                self._print_progress(scanned, total, found)

        if show_progress and not progress_callback:
            print()  # New line after progress bar

        return results

    def _print_progress(self, scanned: int, total: int, found: int):
        """Print visual progress bar"""
        pct = (scanned / max(total, 1)) * 100
        bar_len = 40
        filled = int(bar_len * scanned // max(total, 1))
        bar = "█" * filled + "░" * (bar_len - filled)
        print(
            f"\r  [{bar}] {pct:5.1f}%  {scanned}/{total} hosts  |  Found: {found}",
            end="",
            flush=True,
        )
