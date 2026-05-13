"""
RL Engine v2.0 - Prioritized Experience Replay
Implements PER with alpha-beta prioritization for importance sampling.
"""

from collections import deque
from typing import List, Tuple

import numpy as np


class PrioritizedReplayMemory:
    def __init__(self, capacity: int = 10000, alpha: float = 0.6):
        self.capacity = capacity
        self.alpha = alpha
        self.memory = deque(maxlen=capacity)
        self.priorities = deque(maxlen=capacity)

    def push(self, experience, priority: float = 1.0):
        self.memory.append(experience)
        self.priorities.append(priority**self.alpha)

    def sample(self, batch_size: int, beta: float = 0.4) -> Tuple[List, List, np.ndarray]:
        if len(self.memory) < batch_size:
            batch = list(self.memory)
            weights = np.ones(len(batch))
            return batch, list(range(len(batch))), weights

        probs = np.array(self.priorities)
        probs = probs / probs.sum()
        indices = np.random.choice(len(self.memory), batch_size, p=probs)

        weights = (len(self.memory) * probs[indices]) ** (-beta)
        weights = weights / weights.max()

        batch = [self.memory[i] for i in indices]
        return batch, indices.tolist(), weights

    def update_priorities(self, indices: List[int], priorities: List[float]):
        for idx, priority in zip(indices, priorities):
            if idx < len(self.priorities):
                self.priorities[idx] = (abs(priority) + 1e-6) ** self.alpha

    def __len__(self):
        return len(self.memory)
