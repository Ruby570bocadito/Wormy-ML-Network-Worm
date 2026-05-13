"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.

RL Engine v2.0 - Enhanced Reinforcement Learning for Network Propagation
Features:
- 15 features per host state space (was 3)
- Prioritized Experience Replay (PER)
- Gradient clipping
- Reward normalization
- Adaptive epsilon decay
- Soft target updates (tau=0.005)
- Huber loss for stability
"""

from .dqn_agent import PropagationAgent
from .environment import NetworkEnvironment
from .replay_memory import PrioritizedReplayMemory
from .wrapper import RealWorldPropagationAgent

__all__ = [
    "PrioritizedReplayMemory",
    "PropagationAgent",
    "NetworkEnvironment",
    "RealWorldPropagationAgent",
]
