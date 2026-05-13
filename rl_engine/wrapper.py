"""
RL Engine v2.0 - Real-world wrapper for RL agent
Bridges trained agent with live scan results for target selection.
"""
from typing import List, Dict, Optional

from .dqn_agent import PropagationAgent


class RealWorldPropagationAgent:
    def __init__(self, agent: PropagationAgent, action_size: int):
        self.agent = agent
        self.action_size = action_size
        self.scan_results = []
        self.infected_hosts = set()

    def update_state(self, scan_results: List[Dict], infected_hosts: set):
        self.scan_results = scan_results
        self.infected_hosts = infected_hosts

    def select_next_target(self, use_thompson: bool = False) -> Optional[Dict]:
        if not self.scan_results:
            return None

        available_targets = [
            t for t in self.scan_results
            if t['ip'] not in self.infected_hosts
        ]

        if not available_targets:
            return None

        state = self._build_state(available_targets)

        if use_thompson and hasattr(self.agent, 'ts_act') and hasattr(self.agent, 'ensemble') and self.agent.ensemble:
            action = self.agent.ts_act(state)
        else:
            action = self.agent.act(state)

        if action < len(available_targets):
            return available_targets[action]

        return max(available_targets, key=lambda x: x.get('vulnerability_score', 0))

    def _build_state(self, targets: List[Dict]) -> List[float]:
        state = []
        features_per_host = 15
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379]

        for target in targets[:self.action_size]:
            vuln = target.get('vulnerability_score', 50) / 100.0
            port_count = len(target.get('open_ports', [])) / 20.0
            is_windows = 1.0 if target.get('os_guess') == 'Windows' else 0.0
            is_linux = 1.0 if target.get('os_guess') in ('Linux', 'Unix') else 0.0
            is_infected = 1.0 if target.get('ip') in self.infected_hosts else 0.0
            open_ports = target.get('open_ports', [])
            port_bits = [1.0 if p in open_ports else 0.0 for p in top_ports[:5]]
            cred_count = min(target.get('credential_count', 0) / 10.0, 1.0)
            prev_attempts = min(target.get('exploit_attempts', 0) / 5.0, 1.0)
            prev_success = target.get('exploit_success_rate', 0.5)
            strategic_value = target.get('strategic_value', 0.5)
            detection_risk = target.get('detection_risk', 0.3)
            hop_dist = min(target.get('hop_distance', 1) / 5.0, 1.0)

            host_features = [
                vuln, port_count, is_windows, is_linux, is_infected,
                *port_bits,
                cred_count, prev_attempts, prev_success,
                strategic_value, detection_risk, hop_dist,
            ]
            state.extend(host_features)

        while len(state) < self.action_size * features_per_host:
            state.append(0.0)

        return state[:self.action_size * features_per_host]

    def provide_feedback(self, target: Dict, success: bool, reward: float):
        if not self.scan_results:
            return

        available = [t for t in self.scan_results if t['ip'] not in self.infected_hosts]
        target_idx = None
        for i, t in enumerate(available):
            if t.get('ip') == target.get('ip'):
                target_idx = i
                break

        if target_idx is None:
            return

        state = self._build_state(available)
        # Next state removes the target from available (either infected or failed)
        next_available = [t for t in available if t['ip'] != target.get('ip')]
        next_state = self._build_state(next_available)
        done = False

        self.agent.remember(state, target_idx, reward, next_state, done)

        if len(self.agent.memory) >= 16:
            self.agent.replay(batch_size=16)
