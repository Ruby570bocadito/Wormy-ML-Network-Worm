"""
RL Engine v2.0 - Real-world wrapper for RL agent
Bridges trained agent with live scan results for target selection.
"""

from typing import Dict, List, Optional

from .dqn_agent import PropagationAgent
from .features import FEATURES_PER_HOST, build_state


class RealWorldPropagationAgent:
    def __init__(self, agent: PropagationAgent, action_size: int):
        expected_state = action_size * FEATURES_PER_HOST
        if getattr(agent, "state_size", expected_state) != expected_state:
            raise ValueError(
                f"Agent state_size ({agent.state_size}) does not match "
                f"action_size * {FEATURES_PER_HOST} ({expected_state}). "
                "Rebuild the agent or retrain the model: features must be "
                "identical between training and inference."
            )
        self.agent = agent
        self.action_size = action_size
        self.scan_results = []
        self.infected_hosts = set()
        self.failed_hosts: set = set()

    def update_state(self, scan_results: List[Dict], infected_hosts: set, failed_hosts: set = None):
        self.scan_results = scan_results
        self.infected_hosts = infected_hosts
        if failed_hosts is not None:
            self.failed_hosts = failed_hosts

    def select_next_target(self, use_thompson: bool = False) -> Optional[Dict]:
        if not self.scan_results:
            return None

        available_targets = [
            t
            for t in self.scan_results
            if t["ip"] not in self.infected_hosts and t["ip"] not in self.failed_hosts
        ]

        if not available_targets:
            return None

        state = self._build_state(available_targets)

        if (
            use_thompson
            and hasattr(self.agent, "ts_act")
            and hasattr(self.agent, "ensemble")
            and self.agent.ensemble
        ):
            action = self.agent.ts_act(state)
        else:
            action = self.agent.act(state)

        if action < len(available_targets):
            return available_targets[action]

        return max(available_targets, key=lambda x: x.get("vulnerability_score", 0))

    def _build_state(self, targets: List[Dict]) -> List[float]:
        """Build state with the canonical feature builder.

        IMPORTANT: this uses the exact same feature semantics as
        rl_engine/environment.py during training, so the Q-network
        sees inputs with the meaning it was trained on.
        """
        return build_state(targets, self.action_size, self.infected_hosts)

    def provide_feedback(self, target: Dict, success: bool, reward: float):
        if not self.scan_results:
            return

        available = [
            t
            for t in self.scan_results
            if t["ip"] not in self.infected_hosts and t["ip"] not in self.failed_hosts
        ]
        target_idx = None
        for i, t in enumerate(available):
            if t.get("ip") == target.get("ip"):
                target_idx = i
                break

        if target_idx is None:
            return

        # Track failures so select_next_target() stops re-picking dead targets
        if not success and target.get("ip"):
            self.failed_hosts.add(target["ip"])

        state = self._build_state(available)
        # Next state removes the target from available (either infected or failed)
        next_available = [t for t in available if t["ip"] != target.get("ip")]
        next_state = self._build_state(next_available)
        done = not success

        self.agent.remember(state, target_idx, reward, next_state, done)

        # Train every N feedbacks instead of on every single step:
        # replay() is expensive (two forward passes + backward) and doing
        # it per-event dominated the propagation loop latency.
        self._feedback_count = getattr(self, "_feedback_count", 0) + 1
        if self._feedback_count % 8 == 0 and len(self.agent.memory) >= 32:
            self.agent.replay(batch_size=32)
