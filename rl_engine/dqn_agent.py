"""
RL Engine v2.0 - DQN Agent for network propagation
Features: Prioritized Experience Replay, gradient clipping,
reward normalization, adaptive epsilon decay, soft target updates, Huber loss.
"""

import random
from collections import deque
from typing import List, Optional

import numpy as np

from .replay_memory import PrioritizedReplayMemory


class PropagationAgent:
    def __init__(
        self, state_size: int, action_size: int, use_dqn: bool = True, use_per: bool = True
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.use_dqn = use_dqn
        self.use_per = use_per

        if use_per:
            self.memory = PrioritizedReplayMemory(capacity=10000, alpha=0.6)
        else:
            self.memory = deque(maxlen=10000)

        self.gamma = 0.99
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.997
        self.learning_rate = 0.0005
        self.gradient_clip = 1.0
        self.beta_start = 0.4
        self.beta_frames = 100000
        self.frame_idx = 0

        self.reward_mean = 0.0
        self.reward_std = 1.0
        self.reward_count = 0
        self.reward_m2 = 0.0

        self.q_network = None
        self.target_network = None

        self._build_model()

    def _build_model(self):
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers

            model = keras.Sequential(
                [
                    layers.Dense(128, activation="relu", input_shape=(self.state_size,)),
                    layers.Dropout(0.1),
                    layers.Dense(128, activation="relu"),
                    layers.Dropout(0.1),
                    layers.Dense(64, activation="relu"),
                    layers.Dense(self.action_size, activation="linear"),
                ]
            )

            model.compile(
                optimizer=keras.optimizers.Adam(
                    learning_rate=self.learning_rate, clipnorm=self.gradient_clip
                ),
                loss=tf.keras.losses.Huber(delta=1.0),
            )

            self.q_network = model
            self.target_network = keras.models.clone_model(model)
            self.target_network.build()
            self.target_network.set_weights(model.get_weights())

        except ImportError:
            try:
                import torch
                import torch.nn as nn
                import torch.optim as optim

                class DQNNetwork(nn.Module):
                    def __init__(self, state_size, action_size):
                        super().__init__()
                        self.fc = nn.Sequential(
                            nn.Linear(state_size, 128),
                            nn.ReLU(),
                            nn.Dropout(0.1),
                            nn.Linear(128, 128),
                            nn.ReLU(),
                            nn.Dropout(0.1),
                            nn.Linear(128, 64),
                            nn.ReLU(),
                            nn.Linear(64, action_size),
                        )

                    def forward(self, x):
                        return self.fc(x)

                self.q_network = DQNNetwork(self.state_size, self.action_size)
                self.target_network = DQNNetwork(self.state_size, self.action_size)
                self.target_network.load_state_dict(self.q_network.state_dict())
                self.optimizer = optim.Adam(self.q_network.parameters(), lr=self.learning_rate)
                self.criterion = nn.SmoothL1Loss()
                self.use_torch = True
                self._torch = torch

            except ImportError:
                self.q_network = None
                self.target_network = None

    def normalize_reward(self, reward: float) -> float:
        self.reward_count += 1
        delta = reward - self.reward_mean
        self.reward_mean += delta / self.reward_count
        self.reward_m2 += delta * (reward - self.reward_mean)
        self.reward_std = max(np.sqrt(self.reward_m2 / self.reward_count), 1e-6)
        if self.reward_std < 1e-6:
            self.reward_std = 1.0
        return (reward - self.reward_mean) / self.reward_std

    def act(self, state: List[float], available_actions: List[int] = None) -> int:
        if random.random() < self.epsilon:
            if available_actions:
                return random.choice(available_actions)
            return random.randint(0, self.action_size - 1)

        if self.q_network is not None:
            state_array = np.array(state).reshape(1, -1)

            if hasattr(self, "use_torch") and self.use_torch:
                with self._torch.no_grad():
                    q_values = (
                        self.q_network(self._torch.FloatTensor(state_array)).detach().numpy()[0]
                    )
            else:
                q_values = self.q_network.predict(state_array, verbose=0)[0]

            if available_actions:
                masked_q = np.full(self.action_size, float("-inf"))
                for action in available_actions:
                    masked_q[action] = q_values[action]
                return int(np.argmax(masked_q))

            return int(np.argmax(q_values))

        if available_actions:
            return random.choice(available_actions)

        return random.randint(0, self.action_size - 1)

    def ts_act(self, state: List[float], available_actions: List[int] = None) -> int:
        """Thompson Sampling action selection via bootstrapped ensemble.

        Maintains an ensemble of Q-networks. At each decision:
        1. Randomly sample one network from the ensemble
        2. Act greedily w.r.t. that network's Q-values

        This provides Bayesian exploration without epsilon decay.
        """
        if not hasattr(self, "ensemble") or not self.ensemble:
            return self.act(state, available_actions)

        if available_actions is None:
            available_actions = list(range(self.action_size))

        # Sample a network uniformly from ensemble
        network = random.choice(self.ensemble)
        state_array = np.array(state).reshape(1, -1)

        if hasattr(self, "use_torch") and self.use_torch:
            with self._torch.no_grad():
                q_values = network(self._torch.FloatTensor(state_array)).detach().numpy()[0]
        else:
            q_values = network.predict(state_array, verbose=0)[0]

        masked_q = np.full(self.action_size, float("-inf"))
        for action in available_actions:
            masked_q[action] = q_values[action]
        return int(np.argmax(masked_q))

    def remember(self, state, action, reward, next_state, done):
        priority = abs(reward) + 1.0

        if self.use_per and hasattr(self.memory, "push"):
            self.memory.push((state, action, reward, next_state, done), priority)
        else:
            self.memory.append((state, action, reward, next_state, done))

    def step_epsilon_decay(self):
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
            self.epsilon = max(self.epsilon, self.epsilon_min)

    def replay(self, batch_size: int = 32):
        mem_len = len(self.memory)
        if mem_len < batch_size or self.q_network is None:
            return None

        beta = min(
            1.0, self.beta_start + self.frame_idx * (1.0 - self.beta_start) / self.beta_frames
        )
        self.frame_idx += 1

        if self.use_per and hasattr(self.memory, "sample"):
            batch, indices, weights = self.memory.sample(batch_size, beta)
        else:
            batch = random.sample(self.memory, batch_size)
            indices = list(range(batch_size))
            weights = np.ones(batch_size)

        states = np.array([exp[0] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        actions = np.array([exp[1] for exp in batch])
        rewards = np.array([self.normalize_reward(exp[2]) for exp in batch])
        dones = np.array([exp[4] for exp in batch])

        if hasattr(self, "use_torch") and self.use_torch:
            states_tensor = self._torch.FloatTensor(states)
            next_states_tensor = self._torch.FloatTensor(next_states)

            with self._torch.no_grad():
                next_q = self.target_network(next_states_tensor).detach().numpy()

            current_q = self.q_network(states_tensor).detach().numpy()

            for i in range(batch_size):
                if dones[i]:
                    current_q[i][actions[i]] = rewards[i]
                else:
                    current_q[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q[i])

            self.optimizer.zero_grad()
            output = self.q_network(states_tensor)
            loss = self.criterion(output, self._torch.FloatTensor(current_q))
            loss.backward()

            self._torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), self.gradient_clip)
            self.optimizer.step()

            if self.use_per and hasattr(self.memory, "update_priorities"):
                td_errors = np.abs(
                    current_q[range(batch_size), actions]
                    - (rewards + self.gamma * np.max(next_q, axis=1) * (1 - dones))
                )
                self.memory.update_priorities(indices, td_errors.tolist())

            return loss.item()
        else:
            current_q = self.q_network.predict(states, verbose=0)
            next_q = self.target_network.predict(next_states, verbose=0)

            for i in range(batch_size):
                if dones[i]:
                    current_q[i][actions[i]] = rewards[i]
                else:
                    current_q[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q[i])

            history = self.q_network.fit(
                states, current_q, sample_weight=weights, epochs=1, verbose=0
            )

            if self.use_per and hasattr(self.memory, "update_priorities"):
                td_errors = np.abs(
                    current_q[range(batch_size), actions]
                    - (rewards + self.gamma * np.max(next_q, axis=1) * (1 - dones))
                )
                self.memory.update_priorities(indices, td_errors.tolist())

            return history.history["loss"][0]

    def init_ensemble(self, n_networks: int = 5):
        """Create bootstrapped ensemble for Thompson Sampling."""
        self.ensemble = []
        self.ensemble_n = n_networks
        self.ensemble_memories = []
        for _ in range(n_networks):
            if hasattr(self, "use_torch") and self.use_torch:
                net = self.q_network.__class__(self.state_size, self.action_size)
                net.load_state_dict(self.q_network.state_dict())
                self.ensemble.append(net)
            else:
                import tensorflow as tf
                from tensorflow import keras

                net = keras.models.clone_model(self.q_network)
                net.build()
                net.set_weights(self.q_network.get_weights())
                net.compile(
                    optimizer=tf.keras.optimizers.Adam(
                        learning_rate=self.learning_rate, clipnorm=self.gradient_clip
                    ),
                    loss=tf.keras.losses.Huber(delta=1.0),
                )
                self.ensemble.append(net)
            self.ensemble_memories.append([])

    def replay_ensemble(self, batch_size: int = 32):
        """Train ensemble members with bootstrapped samples."""
        if not hasattr(self, "ensemble") or not self.ensemble:
            return None
        mem_len = len(self.memory)
        if mem_len < batch_size or self.q_network is None:
            return None

        losses = []
        for i, net in enumerate(self.ensemble):
            mem = self.ensemble_memories[i]
            if len(mem) < batch_size:
                batch = random.sample(self.memory, batch_size)
            else:
                batch = random.sample(mem, batch_size)

            states = np.array([exp[0] for exp in batch])
            next_states = np.array([exp[3] for exp in batch])
            actions = np.array([exp[1] for exp in batch])
            rewards = np.array([self.normalize_reward(exp[2]) for exp in batch])
            dones = np.array([exp[4] for exp in batch])

            if hasattr(self, "use_torch") and self.use_torch:
                states_tensor = self._torch.FloatTensor(states)
                next_states_tensor = self._torch.FloatTensor(next_states)
                with self._torch.no_grad():
                    next_q = self.target_network(next_states_tensor).detach().numpy()
                current_q = net(states_tensor).detach().numpy()
                for j in range(batch_size):
                    if dones[j]:
                        current_q[j][actions[j]] = rewards[j]
                    else:
                        current_q[j][actions[j]] = rewards[j] + self.gamma * np.max(next_q[j])
                loss = self.criterion(net(states_tensor), self._torch.FloatTensor(current_q))
                loss.backward()
                losses.append(loss.item())
            else:
                current_q = net.predict(states, verbose=0)
                next_q = self.target_network.predict(next_states, verbose=0)
                for j in range(batch_size):
                    if dones[j]:
                        current_q[j][actions[j]] = rewards[j]
                    else:
                        current_q[j][actions[j]] = rewards[j] + self.gamma * np.max(next_q[j])
                history = net.fit(states, current_q, epochs=1, verbose=0)
                losses.append(history.history["loss"][0])

            # Bootstrap: add to this ensemble member's memory
            for exp in batch:
                if random.random() < 0.8:
                    self.ensemble_memories[i].append(exp)

        return np.mean(losses) if losses else None

    def update_target_model(self, tau=0.005):
        if self.target_network is not None and self.q_network is not None:
            if hasattr(self, "use_torch") and self.use_torch:
                target_state = self.target_network.state_dict()
                source_state = self.q_network.state_dict()
                for key in target_state:
                    target_state[key] = tau * source_state[key] + (1 - tau) * target_state[key]
                self.target_network.load_state_dict(target_state)
            else:
                target_weights = self.target_network.get_weights()
                source_weights = self.q_network.get_weights()
                soft_weights = [
                    tau * s + (1 - tau) * t for s, t in zip(source_weights, target_weights)
                ]
                self.target_network.set_weights(soft_weights)

    def save(self, path: str):
        if self.q_network is not None:
            if hasattr(self, "use_torch") and self.use_torch:
                self._torch.save(
                    {
                        "model_state_dict": self.q_network.state_dict(),
                        "optimizer_state_dict": self.optimizer.state_dict(),
                        "epsilon": self.epsilon,
                        "reward_mean": self.reward_mean,
                        "reward_std": self.reward_std,
                        "reward_m2": self.reward_m2,
                    },
                    path,
                )
            else:
                self.q_network.save(path)

    def load(self, path: str):
        if self.q_network is not None:
            if hasattr(self, "use_torch") and self.use_torch:
                checkpoint = self._torch.load(path)
                self.q_network.load_state_dict(checkpoint["model_state_dict"])
                self.target_network.load_state_dict(checkpoint["model_state_dict"])
                if "optimizer_state_dict" in checkpoint:
                    self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
                if "epsilon" in checkpoint:
                    self.epsilon = checkpoint["epsilon"]
                if "reward_mean" in checkpoint:
                    self.reward_mean = checkpoint["reward_mean"]
                if "reward_std" in checkpoint:
                    self.reward_std = checkpoint["reward_std"]
                if "reward_m2" in checkpoint:
                    self.reward_m2 = checkpoint["reward_m2"]
            else:
                self.q_network.load_weights(path)
                self.target_network.set_weights(self.q_network.get_weights())

    def get_stats(self) -> dict:
        return {
            "epsilon": self.epsilon,
            "epsilon_min": self.epsilon_min,
            "epsilon_decay": self.epsilon_decay,
            "gamma": self.gamma,
            "learning_rate": self.learning_rate,
            "memory_size": len(self.memory),
            "memory_capacity": (
                self.memory.maxlen if hasattr(self.memory, "maxlen") else len(self.memory)
            ),
            "frame_idx": self.frame_idx,
            "reward_mean": self.reward_mean,
            "reward_std": self.reward_std,
            "reward_count": self.reward_count,
            "use_dqn": self.use_dqn,
            "use_per": self.use_per,
            "state_size": self.state_size,
            "action_size": self.action_size,
            "model_loaded": self.q_network is not None,
        }
