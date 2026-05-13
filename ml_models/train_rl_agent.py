"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Train RL Agent for Network Propagation
Curriculum learning, best model saving, early stopping, hyperparameter tuning
"""


import json
import os
import sys
from datetime import datetime

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl_engine import NetworkEnvironment, PropagationAgent


class CurriculumScheduler:
    """Gradually increases environment complexity during training"""

    def __init__(self, phases):
        """
        phases: list of (network_size, max_steps, episodes) tuples
        Example: [(5, 30, 200), (10, 50, 300), (20, 80, 500), (50, 100, 1000)]
        """
        self.phases = phases
        self.current_phase = 0
        self.episode_in_phase = 0

    def get_environment_params(self):
        """Get current phase environment parameters"""
        if self.current_phase >= len(self.phases):
            net_size, max_steps, _ = self.phases[-1]
        else:
            net_size, max_steps, _ = self.phases[self.current_phase]
        return net_size, max_steps

    def advance(self):
        """Move to next phase if current is complete"""
        if self.current_phase < len(self.phases):
            _, _, episodes = self.phases[self.current_phase]
            self.episode_in_phase += 1
            if self.episode_in_phase >= episodes:
                self.current_phase += 1
                self.episode_in_phase = 0
                return True
        return False

    @property
    def is_complete(self):
        return self.current_phase >= len(self.phases)

    @property
    def total_episodes(self):
        return sum(p[2] for p in self.phases)

    @property
    def completed_episodes(self):
        completed = sum(p[2] for p in self.phases[: self.current_phase])
        return completed + self.episode_in_phase


def train_agent_curriculum(
    phases=None, save_dir="saved/rl_agent", early_stop_patience=200, checkpoint_interval=100
):
    """
    Train RL agent with curriculum learning

    Args:
        phases: List of (network_size, max_steps, episodes)
        save_dir: Directory to save models
        early_stop_patience: Stop if no improvement for N episodes
        checkpoint_interval: Save checkpoint every N episodes
    """
    if phases is None:
        phases = [
            (5, 30, 200),
            (10, 50, 300),
            (20, 80, 500),
            (50, 100, 1000),
        ]

    scheduler = CurriculumScheduler(phases)

    print("=" * 60)
    print("RL AGENT TRAINING - CURRICULUM LEARNING")
    print("=" * 60)
    print(f"Phases: {len(phases)}")
    for i, (net, steps, eps) in enumerate(phases):
        print(f"  Phase {i+1}: network={net}, steps={steps}, episodes={eps}")
    print(f"Total episodes: {scheduler.total_episodes}")
    print(f"Save dir: {save_dir}")
    print("=" * 60 + "\n")

    os.makedirs(save_dir, exist_ok=True)

    # Initialize agent for largest network
    max_net = max(p[0] for p in phases)
    state_size = max_net * 15  # 15 features per host
    action_size = max_net
    agent = PropagationAgent(state_size, action_size, use_dqn=True)

    # Training metrics
    rewards_history = []
    infections_history = []
    detection_history = []
    epsilon_history = []

    # Best model tracking
    best_reward = float("-inf")
    best_episode = 0
    no_improve_count = 0

    # Training loop
    while not scheduler.is_complete:
        net_size, max_steps = scheduler.get_environment_params()
        env = NetworkEnvironment(network_size=net_size, max_steps=max_steps)

        state = env.reset()
        total_reward = 0
        done = False

        while not done:
            available = env.get_available_actions()
            if available:
                action = agent.act(state, available_actions=available)
            else:
                action = agent.act(state)

            next_state, reward, done, info = env.step(action)
            agent.remember(state, action, reward, next_state, done)
            agent.replay()
            agent.step_epsilon_decay()

            state = next_state
            total_reward += reward

        rewards_history.append(total_reward)
        infections_history.append(info["infected_count"])
        detection_history.append(1 if env.detected else 0)
        epsilon_history.append(agent.epsilon)

        # Soft target update (tau=0.005)
        agent.update_target_model(tau=0.005)

        # Check for improvement
        window = min(50, len(rewards_history))
        avg_reward = np.mean(rewards_history[-window:])

        if avg_reward > best_reward:
            best_reward = avg_reward
            best_episode = scheduler.completed_episodes
            no_improve_count = 0

            # Save best model
            best_path = os.path.join(save_dir, "best_model.h5")
            agent.save(best_path)
        else:
            no_improve_count += 1

        # Early stopping
        if no_improve_count >= early_stop_patience:
            print(f"\nEarly stopping at episode {scheduler.completed_episodes}")
            print(f"No improvement for {early_stop_patience} episodes")
            break

        # Checkpoint
        if scheduler.completed_episodes % checkpoint_interval == 0:
            ckpt_path = os.path.join(save_dir, f"checkpoint_{scheduler.completed_episodes}.h5")
            agent.save(ckpt_path)

            window = min(50, len(rewards_history))
            avg_r = np.mean(rewards_history[-window:])
            avg_i = np.mean(infections_history[-window:])
            det_r = np.mean(detection_history[-window:])

            print(
                f"\n[Checkpoint {scheduler.completed_episodes}] Phase {scheduler.current_phase + 1}/{len(phases)}"
            )
            print(
                f"  Net: {net_size} hosts | Avg Reward: {avg_r:.2f} | Avg Infected: {avg_i:.1f}/{net_size}"
            )
            print(
                f"  Detection: {det_r*100:.1f}% | Epsilon: {agent.epsilon:.3f} | Best: {best_reward:.2f} (ep {best_episode})"
            )

        scheduler.advance()

    # Save final model
    final_path = os.path.join(save_dir, "final_model.h5")
    agent.save(final_path)

    # Save training metadata
    metadata = {
        "best_reward": float(best_reward),
        "best_episode": best_episode,
        "total_episodes": scheduler.completed_episodes,
        "final_epsilon": float(agent.epsilon),
        "phases": phases,
        "timestamp": datetime.now().isoformat(),
    }
    meta_path = os.path.join(save_dir, "training_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"Total episodes: {scheduler.completed_episodes}")
    print(f"Best reward: {best_reward:.2f} (episode {best_episode})")
    print(f"Final epsilon: {agent.epsilon:.3f}")
    print(f"Best model: {os.path.join(save_dir, 'best_model.h5')}")
    print(f"Final model: {final_path}")
    print(f"Metadata: {meta_path}")
    print("=" * 60 + "\n")

    return agent, rewards_history, infections_history, detection_history


def train_agent_simple(episodes=500, network_size=20, save_path="saved/rl_agent.h5"):
    """Simple training without curriculum (backward compatible)"""
    phases = [(network_size, 100, episodes)]
    agent, rewards, infections, detections = train_agent_curriculum(
        phases=phases,
        save_dir=os.path.dirname(save_path) or "saved",
        early_stop_patience=200,
        checkpoint_interval=50,
    )
    return agent


def evaluate_agent(agent_path, episodes=100, network_size=20):
    """Evaluate trained agent"""
    print("\n" + "=" * 60)
    print("AGENT EVALUATION")
    print("=" * 60)

    env = NetworkEnvironment(network_size=network_size, max_steps=100)

    state_size = network_size * 15
    action_size = network_size
    agent = PropagationAgent(state_size, action_size, use_dqn=True)
    agent.load(agent_path)
    agent.epsilon = 0.0

    total_rewards = []
    total_infections = []
    total_detections = 0

    for episode in range(episodes):
        state = env.reset()
        done = False
        episode_reward = 0

        while not done:
            available = env.get_available_actions()
            action = agent.act(state, available_actions=available)
            next_state, reward, done, info = env.step(action)
            state = next_state
            episode_reward += reward

        total_rewards.append(episode_reward)
        total_infections.append(info["infected_count"])
        if env.detected:
            total_detections += 1

    print(f"\nEvaluation Results ({episodes} episodes):")
    print(f"  Avg Reward: {np.mean(total_rewards):.2f} +/- {np.std(total_rewards):.2f}")
    print(f"  Avg Infections: {np.mean(total_infections):.1f} +/- {np.std(total_infections):.1f}")
    print(f"  Detection Rate: {total_detections/episodes*100:.1f}%")
    print(f"  Coverage: {np.mean(total_infections)/network_size*100:.1f}%")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train RL Agent")
    parser.add_argument("--episodes", type=int, default=1000)
    parser.add_argument("--network-size", type=int, default=20)
    parser.add_argument("--save-dir", type=str, default="saved/rl_agent")
    parser.add_argument("--curriculum", action="store_true", help="Use curriculum learning")
    parser.add_argument("--evaluate", type=str, help="Path to agent to evaluate")
    parser.add_argument("--eval-episodes", type=int, default=100)
    parser.add_argument("--early-stop", type=int, default=200, help="Early stop patience")

    args = parser.parse_args()

    if args.evaluate:
        evaluate_agent(args.evaluate, args.eval_episodes, args.network_size)
    elif args.curriculum:
        train_agent_curriculum(
            save_dir=args.save_dir,
            early_stop_patience=args.early_stop,
        )
    else:
        train_agent_simple(
            args.episodes, args.network_size, os.path.join(args.save_dir, "final_model.h5")
        )
