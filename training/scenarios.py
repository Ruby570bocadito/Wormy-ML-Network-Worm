"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Realistic Training Scenarios
Training environments that simulate real-world network topologies
with actual service configurations, vulnerability distributions,
and realistic attack surfaces.

Scenarios:
1. Small Office (10 hosts) - Basic network with common misconfigurations
2. Enterprise Network (30 hosts) - Multi-subnet with AD, servers, workstations
3. Datacenter (50 hosts) - Server-heavy with databases, web apps, containers
4. Cloud Infrastructure (40 hosts) - Modern cloud with microservices
5. IoT/OT Network (25 hosts) - Industrial IoT with vulnerable devices
6. Mixed Environment (60 hosts) - Realistic corporate network
"""


import os
import random
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl_engine import NetworkEnvironment, PropagationAgent
from utils.logger import logger


class RealisticScenario:
    """Base class for realistic training scenarios"""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.hosts = []
        self.network_topology = {}

    def generate(self) -> List[Dict]:
        """Generate the scenario - returns list of host dicts"""
        raise NotImplementedError

    def get_expected_infections(self) -> int:
        """Expected number of infectable hosts in this scenario"""
        raise NotImplementedError


class SmallOfficeScenario(RealisticScenario):
    """
    Small Office Network (10 hosts)
    Realistic: Router, file server, 5 workstations, printer, WiFi AP, guest WiFi
    Vulnerabilities: Default creds on printer, unpatched file server, weak WiFi
    """

    def __init__(self):
        super().__init__("Small Office", "10-host office network with common misconfigurations")

    def generate(self) -> List[Dict]:
        self.hosts = [
            {
                "id": 0,
                "ip": "192.168.1.1",
                "subnet": 0,
                "os_guess": "Network Device",
                "open_ports": [22, 80, 443],
                "vulnerability": 30,
                "difficulty": 8,
                "reachable": True,
                "is_high_value": False,
                "credentials": 0,
                "hop_distance": 0,
                "services": {"22": "SSH", "80": "HTTP", "443": "HTTPS"},
                "banners": {"80": "RouterOS"},
            },
            {
                "id": 1,
                "ip": "192.168.1.10",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [445, 139, 3389, 135],
                "vulnerability": 75,
                "difficulty": 3,
                "reachable": True,
                "is_high_value": True,
                "credentials": 5,
                "hop_distance": 1,
                "services": {"445": "SMB", "139": "NetBIOS", "3389": "RDP", "135": "RPC"},
                "banners": {"445": "Windows Server 2019"},
            },
            {
                "id": 2,
                "ip": "192.168.1.20",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [445, 139, 3389],
                "vulnerability": 60,
                "difficulty": 5,
                "reachable": True,
                "is_high_value": False,
                "credentials": 2,
                "hop_distance": 1,
                "services": {"445": "SMB", "139": "NetBIOS", "3389": "RDP"},
                "banners": {},
            },
            {
                "id": 3,
                "ip": "192.168.1.30",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [445, 139],
                "vulnerability": 50,
                "difficulty": 6,
                "reachable": True,
                "is_high_value": False,
                "credentials": 1,
                "hop_distance": 1,
                "services": {"445": "SMB", "139": "NetBIOS"},
                "banners": {},
            },
            {
                "id": 4,
                "ip": "192.168.1.40",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [445, 139],
                "vulnerability": 45,
                "difficulty": 6,
                "reachable": True,
                "is_high_value": False,
                "credentials": 1,
                "hop_distance": 2,
                "services": {"445": "SMB", "139": "NetBIOS"},
                "banners": {},
            },
            {
                "id": 5,
                "ip": "192.168.1.50",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [445, 139],
                "vulnerability": 40,
                "difficulty": 7,
                "reachable": True,
                "is_high_value": False,
                "credentials": 0,
                "hop_distance": 2,
                "services": {"445": "SMB", "139": "NetBIOS"},
                "banners": {},
            },
            {
                "id": 6,
                "ip": "192.168.1.60",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [445, 139],
                "vulnerability": 35,
                "difficulty": 7,
                "reachable": True,
                "is_high_value": False,
                "credentials": 0,
                "hop_distance": 2,
                "services": {"445": "SMB", "139": "NetBIOS"},
                "banners": {},
            },
            {
                "id": 7,
                "ip": "192.168.1.100",
                "subnet": 0,
                "os_guess": "Network Device",
                "open_ports": [23, 80, 443],
                "vulnerability": 80,
                "difficulty": 2,
                "reachable": True,
                "is_high_value": False,
                "credentials": 3,
                "hop_distance": 1,
                "services": {"23": "Telnet", "80": "HTTP", "443": "HTTPS"},
                "banners": {"80": "HP Printer"},
            },
            {
                "id": 8,
                "ip": "192.168.1.200",
                "subnet": 0,
                "os_guess": "Linux",
                "open_ports": [22, 80],
                "vulnerability": 55,
                "difficulty": 5,
                "reachable": True,
                "is_high_value": False,
                "credentials": 2,
                "hop_distance": 1,
                "services": {"22": "SSH", "80": "HTTP"},
                "banners": {"80": "WiFi AP"},
            },
            {
                "id": 9,
                "ip": "192.168.1.250",
                "subnet": 1,
                "os_guess": "Linux",
                "open_ports": [22, 80],
                "vulnerability": 30,
                "difficulty": 8,
                "reachable": False,
                "is_high_value": False,
                "credentials": 0,
                "hop_distance": 3,
                "services": {"22": "SSH", "80": "HTTP"},
                "banners": {},
            },
        ]
        return self.hosts

    def get_expected_infections(self) -> int:
        return 7  # Router, file server, 4 workstations, printer, WiFi AP


class EnterpriseScenario(RealisticScenario):
    """
    Enterprise Network (30 hosts)
    Realistic: AD domain, DCs, file servers, DB servers, web servers, workstations,
    DMZ with public-facing servers, management network
    """

    def __init__(self):
        super().__init__(
            "Enterprise Network",
            "30-host multi-subnet enterprise with AD, servers, workstations, DMZ",
        )

    def generate(self) -> List[Dict]:
        hosts = []
        host_id = 0

        # Subnet 0: Management (DC, DNS, monitoring)
        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.0.10",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [53, 88, 135, 139, 389, 445, 636, 3268, 3269],
                "vulnerability": 70,
                "difficulty": 4,
                "reachable": True,
                "is_high_value": True,
                "credentials": 8,
                "hop_distance": 0,
                "services": {"53": "DNS", "88": "Kerberos", "389": "LDAP", "445": "SMB"},
                "banners": {"445": "Windows Server 2019 DC"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.0.11",
                "subnet": 0,
                "os_guess": "Windows",
                "open_ports": [53, 88, 135, 389, 445],
                "vulnerability": 65,
                "difficulty": 5,
                "reachable": True,
                "is_high_value": True,
                "credentials": 5,
                "hop_distance": 1,
                "services": {"53": "DNS", "88": "Kerberos", "445": "SMB"},
                "banners": {},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.0.20",
                "subnet": 0,
                "os_guess": "Linux",
                "open_ports": [22, 161, 514],
                "vulnerability": 40,
                "difficulty": 7,
                "reachable": True,
                "is_high_value": False,
                "credentials": 2,
                "hop_distance": 1,
                "services": {"22": "SSH", "161": "SNMP"},
                "banners": {},
            }
        )
        host_id += 1

        # Subnet 1: Servers (file, DB, web, mail)
        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.1.10",
                "subnet": 1,
                "os_guess": "Windows",
                "open_ports": [445, 139, 3389, 135],
                "vulnerability": 80,
                "difficulty": 2,
                "reachable": True,
                "is_high_value": True,
                "credentials": 10,
                "hop_distance": 1,
                "services": {"445": "SMB", "139": "NetBIOS", "3389": "RDP"},
                "banners": {"445": "Windows Server 2016"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.1.20",
                "subnet": 1,
                "os_guess": "Linux",
                "open_ports": [22, 3306],
                "vulnerability": 75,
                "difficulty": 3,
                "reachable": True,
                "is_high_value": True,
                "credentials": 5,
                "hop_distance": 2,
                "services": {"22": "SSH", "3306": "MySQL"},
                "banners": {"3306": "MySQL 5.7"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.1.30",
                "subnet": 1,
                "os_guess": "Linux",
                "open_ports": [22, 5432],
                "vulnerability": 70,
                "difficulty": 4,
                "reachable": True,
                "is_high_value": True,
                "credentials": 4,
                "hop_distance": 2,
                "services": {"22": "SSH", "5432": "PostgreSQL"},
                "banners": {"5432": "PostgreSQL 12"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.1.40",
                "subnet": 1,
                "os_guess": "Linux",
                "open_ports": [22, 8080, 8443],
                "vulnerability": 65,
                "difficulty": 5,
                "reachable": True,
                "is_high_value": False,
                "credentials": 3,
                "hop_distance": 2,
                "services": {"22": "SSH", "8080": "HTTP-Alt", "8443": "HTTPS-Alt"},
                "banners": {"8080": "Apache Tomcat/9.0"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.1.50",
                "subnet": 1,
                "os_guess": "Linux",
                "open_ports": [22, 25, 110, 143, 587],
                "vulnerability": 55,
                "difficulty": 6,
                "reachable": True,
                "is_high_value": False,
                "credentials": 2,
                "hop_distance": 2,
                "services": {"22": "SSH", "25": "SMTP", "110": "POP3", "143": "IMAP"},
                "banners": {},
            }
        )
        host_id += 1

        # Subnet 2: Workstations (15 Windows workstations)
        for i in range(15):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.0.2.{100+i}",
                    "subnet": 2,
                    "os_guess": "Windows",
                    "open_ports": [445, 139, 3389],
                    "vulnerability": 40 + random.randint(-10, 20),
                    "difficulty": 5 + random.randint(0, 3),
                    "reachable": random.random() > 0.1,
                    "is_high_value": i == 0,  # First workstation is high-value
                    "credentials": random.randint(0, 3),
                    "hop_distance": 2 + (i // 5),
                    "services": {"445": "SMB", "139": "NetBIOS", "3389": "RDP"},
                    "banners": {},
                }
            )
            host_id += 1

        # Subnet 3: DMZ (web servers, public-facing)
        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.3.10",
                "subnet": 3,
                "os_guess": "Linux",
                "open_ports": [22, 80, 443],
                "vulnerability": 85,
                "difficulty": 2,
                "reachable": True,
                "is_high_value": True,
                "credentials": 5,
                "hop_distance": 3,
                "services": {"22": "SSH", "80": "HTTP", "443": "HTTPS"},
                "banners": {"80": "Apache/2.4.49"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.3.20",
                "subnet": 3,
                "os_guess": "Linux",
                "open_ports": [22, 80, 443],
                "vulnerability": 80,
                "difficulty": 3,
                "reachable": True,
                "is_high_value": True,
                "credentials": 4,
                "hop_distance": 3,
                "services": {"22": "SSH", "80": "HTTP", "443": "HTTPS"},
                "banners": {"80": "nginx/1.17.0"},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.3.30",
                "subnet": 3,
                "os_guess": "Linux",
                "open_ports": [22, 8080],
                "vulnerability": 75,
                "difficulty": 4,
                "reachable": True,
                "is_high_value": False,
                "credentials": 3,
                "hop_distance": 3,
                "services": {"22": "SSH", "8080": "HTTP-Alt"},
                "banners": {"8080": "Jenkins 2.289"},
            }
        )
        host_id += 1

        # Subnet 4: Isolated (backup, monitoring)
        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.4.10",
                "subnet": 4,
                "os_guess": "Linux",
                "open_ports": [22, 873],
                "vulnerability": 60,
                "difficulty": 5,
                "reachable": False,
                "is_high_value": True,
                "credentials": 5,
                "hop_distance": 4,
                "services": {"22": "SSH", "873": "rsync"},
                "banners": {},
            }
        )
        host_id += 1

        hosts.append(
            {
                "id": host_id,
                "ip": "10.0.4.20",
                "subnet": 4,
                "os_guess": "Linux",
                "open_ports": [22, 3000, 9090],
                "vulnerability": 50,
                "difficulty": 6,
                "reachable": False,
                "is_high_value": False,
                "credentials": 2,
                "hop_distance": 4,
                "services": {"22": "SSH", "3000": "Grafana", "9090": "Prometheus"},
                "banners": {},
            }
        )
        host_id += 1

        self.hosts = hosts
        return hosts

    def get_expected_infections(self) -> int:
        return 22  # Most hosts except isolated ones


class DatacenterScenario(RealisticScenario):
    """
    Datacenter Network (50 hosts)
    Server-heavy: web farms, DB clusters, load balancers, containers, storage
    """

    def __init__(self):
        super().__init__("Datacenter", "50-host datacenter with web farms, DB clusters, containers")

    def generate(self) -> List[Dict]:
        hosts = []
        host_id = 0

        # Load balancers
        for i in range(2):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.0.{10+i}",
                    "subnet": 0,
                    "os_guess": "Linux",
                    "open_ports": [22, 80, 443, 8443],
                    "vulnerability": 60,
                    "difficulty": 5,
                    "reachable": True,
                    "is_high_value": True,
                    "credentials": 3,
                    "hop_distance": 0,
                    "services": {"22": "SSH", "80": "HTTP", "443": "HTTPS"},
                    "banners": {"80": "HAProxy"},
                }
            )
            host_id += 1

        # Web farm (10 servers)
        for i in range(10):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.1.{20+i}",
                    "subnet": 1,
                    "os_guess": "Linux",
                    "open_ports": [22, 80, 443, 8080],
                    "vulnerability": 55 + random.randint(-10, 15),
                    "difficulty": 5 + random.randint(0, 3),
                    "reachable": True,
                    "is_high_value": i < 3,
                    "credentials": random.randint(1, 4),
                    "hop_distance": 1,
                    "services": {"22": "SSH", "80": "HTTP", "443": "HTTPS", "8080": "HTTP-Alt"},
                    "banners": {"80": "Apache/2.4.41" if i % 2 == 0 else "nginx/1.18"},
                }
            )
            host_id += 1

        # Database cluster (8 servers)
        for i in range(8):
            port_svc = {22: "SSH"}
            if i < 3:
                port_svc[3306] = "MySQL"
            elif i < 6:
                port_svc[5432] = "PostgreSQL"
            else:
                port_svc[6379] = "Redis"

            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.2.{30+i}",
                    "subnet": 2,
                    "os_guess": "Linux",
                    "open_ports": list(port_svc.keys()),
                    "vulnerability": 70 + random.randint(-10, 10),
                    "difficulty": 3 + random.randint(0, 3),
                    "reachable": True,
                    "is_high_value": True,
                    "credentials": random.randint(2, 6),
                    "hop_distance": 2,
                    "services": port_svc,
                    "banners": {},
                }
            )
            host_id += 1

        # Container hosts (10 servers with Docker)
        for i in range(10):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.3.{40+i}",
                    "subnet": 3,
                    "os_guess": "Linux",
                    "open_ports": [22, 2375, 2376, 8080],
                    "vulnerability": 80 + random.randint(-10, 10),
                    "difficulty": 2 + random.randint(0, 2),
                    "reachable": True,
                    "is_high_value": i < 5,
                    "credentials": random.randint(1, 3),
                    "hop_distance": 2,
                    "services": {"22": "SSH", "2375": "Docker", "2376": "Docker-TLS"},
                    "banners": {},
                }
            )
            host_id += 1

        # Storage (5 NAS/SAN)
        for i in range(5):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.4.{50+i}",
                    "subnet": 4,
                    "os_guess": "Linux",
                    "open_ports": [22, 2049, 445, 873],
                    "vulnerability": 65 + random.randint(-10, 10),
                    "difficulty": 4 + random.randint(0, 3),
                    "reachable": random.random() > 0.2,
                    "is_high_value": True,
                    "credentials": random.randint(2, 5),
                    "hop_distance": 3,
                    "services": {"22": "SSH", "2049": "NFS", "445": "SMB"},
                    "banners": {},
                }
            )
            host_id += 1

        # Management (5 servers)
        for i in range(5):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.5.{60+i}",
                    "subnet": 5,
                    "os_guess": "Linux",
                    "open_ports": [22, 3000, 9090, 9200],
                    "vulnerability": 50 + random.randint(-10, 10),
                    "difficulty": 5 + random.randint(0, 3),
                    "reachable": random.random() > 0.3,
                    "is_high_value": i == 0,
                    "credentials": random.randint(1, 4),
                    "hop_distance": 3,
                    "services": {
                        "22": "SSH",
                        "3000": "Grafana",
                        "9090": "Prometheus",
                        "9200": "Elasticsearch",
                    },
                    "banners": {},
                }
            )
            host_id += 1

        # Unreachable/isolated (10 hosts)
        for i in range(10):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"172.16.6.{70+i}",
                    "subnet": 6,
                    "os_guess": "Linux",
                    "open_ports": [22, 80],
                    "vulnerability": 30 + random.randint(-10, 10),
                    "difficulty": 7 + random.randint(0, 2),
                    "reachable": False,
                    "is_high_value": False,
                    "credentials": 0,
                    "hop_distance": 5,
                    "services": {"22": "SSH", "80": "HTTP"},
                    "banners": {},
                }
            )
            host_id += 1

        self.hosts = hosts
        return hosts

    def get_expected_infections(self) -> int:
        return 35  # Most except isolated ones


class CloudScenario(RealisticScenario):
    """
    Cloud Infrastructure (40 hosts)
    Modern cloud: microservices, API gateways, container orchestration, managed services
    """

    def __init__(self):
        super().__init__(
            "Cloud Infrastructure", "40-host cloud with microservices, containers, managed services"
        )

    def generate(self) -> List[Dict]:
        hosts = []
        host_id = 0

        # API Gateway
        hosts.append(
            {
                "id": host_id,
                "ip": "10.10.0.10",
                "subnet": 0,
                "os_guess": "Linux",
                "open_ports": [22, 443, 8443],
                "vulnerability": 50,
                "difficulty": 6,
                "reachable": True,
                "is_high_value": True,
                "credentials": 3,
                "hop_distance": 0,
                "services": {"22": "SSH", "443": "HTTPS"},
                "banners": {"443": "Kong API Gateway"},
            }
        )
        host_id += 1

        # Microservices (15 services)
        for i in range(15):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.10.1.{20+i}",
                    "subnet": 1,
                    "os_guess": "Linux",
                    "open_ports": [22, 8080, 9090],
                    "vulnerability": 45 + random.randint(-10, 20),
                    "difficulty": 5 + random.randint(0, 3),
                    "reachable": True,
                    "is_high_value": i < 3,
                    "credentials": random.randint(0, 2),
                    "hop_distance": 1,
                    "services": {"22": "SSH", "8080": "HTTP-Alt", "9090": "Prometheus"},
                    "banners": {},
                }
            )
            host_id += 1

        # Kubernetes cluster (6 nodes)
        for i in range(6):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.10.2.{40+i}",
                    "subnet": 2,
                    "os_guess": "Linux",
                    "open_ports": [22, 6443, 10250, 2379],
                    "vulnerability": 70 + random.randint(-10, 10),
                    "difficulty": 3 + random.randint(0, 2),
                    "reachable": True,
                    "is_high_value": i < 3,
                    "credentials": random.randint(2, 5),
                    "hop_distance": 2,
                    "services": {"22": "SSH", "6443": "Kubernetes", "10250": "Kubelet"},
                    "banners": {},
                }
            )
            host_id += 1

        # Managed databases (5)
        for i in range(5):
            svc = {22: "SSH"}
            if i < 2:
                svc[3306] = "MySQL"
            elif i < 4:
                svc[5432] = "PostgreSQL"
            else:
                svc[27017] = "MongoDB"

            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.10.3.{50+i}",
                    "subnet": 3,
                    "os_guess": "Linux",
                    "open_ports": list(svc.keys()),
                    "vulnerability": 60 + random.randint(-10, 15),
                    "difficulty": 4 + random.randint(0, 3),
                    "reachable": True,
                    "is_high_value": True,
                    "credentials": random.randint(2, 4),
                    "hop_distance": 2,
                    "services": svc,
                    "banners": {},
                }
            )
            host_id += 1

        # CI/CD (4 servers)
        for i in range(4):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.10.4.{60+i}",
                    "subnet": 4,
                    "os_guess": "Linux",
                    "open_ports": [22, 8080, 443],
                    "vulnerability": 65 + random.randint(-10, 10),
                    "difficulty": 4 + random.randint(0, 3),
                    "reachable": True,
                    "is_high_value": i == 0,
                    "credentials": random.randint(2, 5),
                    "hop_distance": 2,
                    "services": {"22": "SSH", "8080": "HTTP-Alt"},
                    "banners": {"8080": "Jenkins" if i == 0 else "GitLab"},
                }
            )
            host_id += 1

        # Monitoring (4)
        for i in range(4):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.10.5.{70+i}",
                    "subnet": 5,
                    "os_guess": "Linux",
                    "open_ports": [22, 3000, 9090, 9200, 5601],
                    "vulnerability": 55 + random.randint(-10, 10),
                    "difficulty": 5 + random.randint(0, 3),
                    "reachable": random.random() > 0.2,
                    "is_high_value": False,
                    "credentials": random.randint(1, 3),
                    "hop_distance": 3,
                    "services": {
                        "22": "SSH",
                        "3000": "Grafana",
                        "9090": "Prometheus",
                        "9200": "Elasticsearch",
                        "5601": "Kibana",
                    },
                    "banners": {},
                }
            )
            host_id += 1

        # Isolated (6)
        for i in range(6):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"10.10.6.{80+i}",
                    "subnet": 6,
                    "os_guess": "Linux",
                    "open_ports": [22],
                    "vulnerability": 30,
                    "difficulty": 8,
                    "reachable": False,
                    "is_high_value": False,
                    "credentials": 0,
                    "hop_distance": 5,
                    "services": {"22": "SSH"},
                    "banners": {},
                }
            )
            host_id += 1

        self.hosts = hosts
        return hosts

    def get_expected_infections(self) -> int:
        return 30


class IoTScenario(RealisticScenario):
    """
    IoT/OT Network (25 hosts)
    Industrial IoT: PLCs, sensors, cameras, SCADA, building automation
    """

    def __init__(self):
        super().__init__(
            "IoT/OT Network",
            "25-host industrial IoT with PLCs, cameras, SCADA, building automation",
        )

    def generate(self) -> List[Dict]:
        hosts = []
        host_id = 0

        # SCADA/Control servers
        for i in range(3):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"192.168.100.{10+i}",
                    "subnet": 0,
                    "os_guess": "Windows",
                    "open_ports": [22, 445, 3389, 502],
                    "vulnerability": 85,
                    "difficulty": 2,
                    "reachable": True,
                    "is_high_value": True,
                    "credentials": 5,
                    "hop_distance": 0,
                    "services": {"22": "SSH", "445": "SMB", "3389": "RDP", "502": "Modbus"},
                    "banners": {"445": "Windows 7"},
                }
            )
            host_id += 1

        # PLCs (8 devices)
        for i in range(8):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"192.168.100.{20+i}",
                    "subnet": 0,
                    "os_guess": "Network Device",
                    "open_ports": [23, 80, 502, 44818],
                    "vulnerability": 90,
                    "difficulty": 1,
                    "reachable": True,
                    "is_high_value": i < 3,
                    "credentials": 3,
                    "hop_distance": 1,
                    "services": {"23": "Telnet", "80": "HTTP", "502": "Modbus"},
                    "banners": {"80": "Siemens PLC"},
                }
            )
            host_id += 1

        # Cameras (6)
        for i in range(6):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"192.168.100.{30+i}",
                    "subnet": 1,
                    "os_guess": "Linux",
                    "open_ports": [23, 80, 554, 8000],
                    "vulnerability": 80,
                    "difficulty": 2,
                    "reachable": True,
                    "is_high_value": False,
                    "credentials": 2,
                    "hop_distance": 1,
                    "services": {"23": "Telnet", "80": "HTTP", "554": "RTSP"},
                    "banners": {"80": "Hikvision Camera"},
                }
            )
            host_id += 1

        # Building automation (4)
        for i in range(4):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"192.168.100.{40+i}",
                    "subnet": 1,
                    "os_guess": "Linux",
                    "open_ports": [22, 80, 47808],
                    "vulnerability": 70,
                    "difficulty": 3,
                    "reachable": True,
                    "is_high_value": False,
                    "credentials": 2,
                    "hop_distance": 2,
                    "services": {"22": "SSH", "80": "HTTP", "47808": "BACnet"},
                    "banners": {},
                }
            )
            host_id += 1

        # Sensors (4)
        for i in range(4):
            hosts.append(
                {
                    "id": host_id,
                    "ip": f"192.168.100.{50+i}",
                    "subnet": 2,
                    "os_guess": "Network Device",
                    "open_ports": [161, 162],
                    "vulnerability": 60,
                    "difficulty": 4,
                    "reachable": random.random() > 0.2,
                    "is_high_value": False,
                    "credentials": 1,
                    "hop_distance": 2,
                    "services": {"161": "SNMP", "162": "SNMP-Trap"},
                    "banners": {},
                }
            )
            host_id += 1

        # Isolated management
        hosts.append(
            {
                "id": host_id,
                "ip": "192.168.100.100",
                "subnet": 3,
                "os_guess": "Linux",
                "open_ports": [22, 443],
                "vulnerability": 40,
                "difficulty": 7,
                "reachable": False,
                "is_high_value": True,
                "credentials": 3,
                "hop_distance": 4,
                "services": {"22": "SSH", "443": "HTTPS"},
                "banners": {},
            }
        )
        host_id += 1

        self.hosts = hosts
        return hosts

    def get_expected_infections(self) -> int:
        return 20  # Most IoT devices are vulnerable


# Scenario registry
SCENARIOS = {
    "small_office": SmallOfficeScenario,
    "enterprise": EnterpriseScenario,
    "datacenter": DatacenterScenario,
    "cloud": CloudScenario,
    "iot": IoTScenario,
}


def get_scenario(name: str) -> RealisticScenario:
    """Get a training scenario by name"""
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}. Available: {list(SCENARIOS.keys())}")
    return SCENARIOS[name]()


def get_all_scenarios() -> List[RealisticScenario]:
    """Get all available training scenarios"""
    return [cls() for cls in SCENARIOS.values()]


def get_scenario_names() -> List[str]:
    """Get list of available scenario names"""
    return list(SCENARIOS.keys())
