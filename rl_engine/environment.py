"""
RL Engine v2.0 - Simulated network environment
Enhance: 15 features per host state space with realistic topology simulation.
"""

import random
from typing import Dict, List, Tuple

import numpy as np


class NetworkEnvironment:
    def __init__(self, network_size: int = 20, max_steps: int = 100, max_state_size: int = None):
        self.network_size = network_size
        self.max_steps = max_steps
        self.max_state_size = max_state_size
        self.current_step = 0

        self.hosts = []
        self.infected = []
        self.detected = False

        self._generate_network()

    def _generate_network(self):
        subnets = [0, 1, 2]
        for i in range(self.network_size):
            subnet = subnets[i % len(subnets)]
            host = {
                "id": i,
                "ip": f"192.168.{subnet}.{i+10}",
                "subnet": subnet,
                "vulnerability": random.randint(20, 100),
                "difficulty": random.randint(1, 10),
                "reachable": random.random() > 0.2,
                "ports": random.sample([22, 80, 443, 445, 3389, 3306, 8080], random.randint(1, 4)),
                "os": random.choice(["Windows", "Linux", "Linux", "Windows"]),
                "is_high_value": random.random() < 0.15,
                "credentials": random.randint(0, 5),
                "hop_distance": random.randint(1, 4),
            }
            self.hosts.append(host)

    def reset(self) -> np.ndarray:
        self.current_step = 0
        self.infected = [0]
        self.detected = False

        for host in self.hosts:
            host["infected"] = host["id"] == 0

        return self._get_state()

    def _get_state(self) -> np.ndarray:
        state = []
        top_ports = [
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
        ]

        for host in self.hosts:
            vuln = host["vulnerability"] / 100.0
            difficulty = host["difficulty"] / 10.0
            is_infected = 1.0 if host.get("infected", False) else 0.0
            port_count = len(host.get("ports", [])) / 10.0
            is_windows = 1.0 if host.get("os") == "Windows" else 0.0
            is_linux = 1.0 if host.get("os") == "Linux" else 0.0
            is_high_value = 1.0 if host.get("is_high_value", False) else 0.0
            credentials = host.get("credentials", 0) / 5.0
            hop_dist = host.get("hop_distance", 1) / 5.0
            subnet = host.get("subnet", 0) / 3.0

            host_ports = host.get("ports", [])
            port_features = [1.0 if p in host_ports else 0.0 for p in top_ports[:5]]

            features = [
                vuln,
                difficulty,
                is_infected,
                port_count,
                is_windows,
                is_linux,
                is_high_value,
                credentials,
                hop_dist,
                subnet,
                *port_features,
            ]
            state.extend(features)

        features_per_host = 15
        target_size = self.max_state_size or (self.network_size * features_per_host)
        while len(state) < target_size:
            state.append(0.0)

        return np.array(state[:target_size], dtype=np.float32)

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        self.current_step += 1

        if action >= len(self.hosts):
            return self._get_state(), -1, True, {"infected_count": len(self.infected)}

        target = self.hosts[action]

        if target.get("infected", False):
            return self._get_state(), -2, False, {"infected_count": len(self.infected)}

        if not target.get("reachable", True):
            return self._get_state(), -3, False, {"infected_count": len(self.infected)}

        success_prob = (target["vulnerability"] / 100.0) * (1 - target["difficulty"] / 20.0)

        if random.random() < success_prob:
            target["infected"] = True
            self.infected.append(action)

            reward = 20

            if target.get("is_high_value", False):
                reward += 15

            reward += target["vulnerability"] / 5
            reward += target.get("credentials", 0) * 3
            reward += len(target.get("ports", []))

            detection_prob = 0.05 + (target["difficulty"] / 100.0)
            if random.random() < detection_prob:
                self.detected = True
                reward -= 10

            if len(self.infected) >= self.network_size * 0.8:
                reward += 5
        else:
            reward = -5

        reward -= 0.5

        done = self.current_step >= self.max_steps or len(self.infected) >= self.network_size

        return (
            self._get_state(),
            reward,
            done,
            {
                "infected_count": len(self.infected),
                "detected": self.detected,
                "high_value": target.get("is_high_value", False),
                "credentials_found": target.get("credentials", 0),
            },
        )

    def get_available_actions(self) -> List[int]:
        return [i for i, h in enumerate(self.hosts) if not h.get("infected", False)]
