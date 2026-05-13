"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Realistic Training Engine
Trains the RL agent on realistic network scenarios with:
- Multiple scenario types (office, enterprise, datacenter, cloud, IoT)
- Scenario variation (randomized vulnerabilities, ports, credentials)
- Curriculum learning (easy → hard scenarios)
- Auto-training on first run
- Model persistence and loading
- Online learning improvements
"""


import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl_engine import NetworkEnvironment, PropagationAgent
from training.scenarios import (
    RealisticScenario,
    get_all_scenarios,
    get_scenario,
    get_scenario_names,
)
from utils.logger import logger


class RealisticTrainer:
    """
    Trains RL agent on realistic scenarios with curriculum learning

    Features:
    - Realistic network topologies (not random)
    - Scenario variation (randomized within realistic bounds)
    - Curriculum: easy → hard scenarios
    - Early stopping
    - Best model saving
    - Training metadata
    """

    def __init__(self, save_dir: str = "saved/rl_agent"):
        self.save_dir = save_dir
        os.makedirs(save_dir, exist_ok=True)

        # Training state
        self.best_reward = float("-inf")
        self.best_model_path = os.path.join(save_dir, "best_model.h5")
        self.final_model_path = os.path.join(save_dir, "final_model.h5")
        self.metadata_path = os.path.join(save_dir, "training_metadata.json")

        # Curriculum order: easy → hard
        self.curriculum_order = ["small_office", "enterprise", "datacenter", "cloud", "iot"]

        # Training config
        self.episodes_per_scenario = {
            "small_office": 100,
            "enterprise": 200,
            "datacenter": 300,
            "cloud": 250,
            "iot": 200,
        }

        self.max_steps_per_scenario = {
            "small_office": 30,
            "enterprise": 60,
            "datacenter": 80,
            "cloud": 70,
            "iot": 50,
        }

        # Metrics
        self.training_history = {
            "rewards": [],
            "infections": [],
            "detections": [],
            "scenarios": [],
            "episodes": [],
        }

        self.agent = None
        self.is_trained = False

    def train(
        self,
        scenarios: List[str] = None,
        total_episodes: int = None,
        early_stop_patience: int = 200,
        checkpoint_interval: int = 100,
    ) -> Dict:
        """
        Train the RL agent on realistic scenarios

        Args:
            scenarios: List of scenario names (None = all in curriculum order)
            total_episodes: Override total episodes (None = use per-scenario defaults)
            early_stop_patience: Stop if no improvement for N episodes
            checkpoint_interval: Save checkpoint every N episodes

        Returns:
            Training results dict
        """
        if scenarios is None:
            scenarios = self.curriculum_order

        # Initialize agent with fixed sizes matching worm_core
        state_size = 300  # 20 hosts * 15 features (matching worm_core)
        action_size = 50

        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)

        # Try to load existing model
        if os.path.exists(self.best_model_path):
            try:
                self.agent.load(self.best_model_path)
                logger.info(f"Loaded existing model from {self.best_model_path}")
            except Exception as e:
                logger.warning(f"Failed to load existing model: {e}")

        logger.info("=" * 60)
        logger.info("REALISTIC RL TRAINING")
        logger.info("=" * 60)
        logger.info(f"Scenarios: {scenarios}")
        logger.info(f"Agent: state={state_size}, action={action_size}")
        logger.info(f"Save dir: {self.save_dir}")
        logger.info("=" * 60)

        total_episodes_run = 0
        no_improve_count = 0
        start_time = time.time()

        for scenario_name in scenarios:
            scenario = get_scenario(scenario_name)
            n_episodes = total_episodes or self.episodes_per_scenario.get(scenario_name, 100)
            max_steps = self.max_steps_per_scenario.get(scenario_name, 50)

            logger.info(f"\n{'='*60}")
            logger.info(f"SCENARIO: {scenario.name}")
            logger.info(f"Description: {scenario.description}")
            logger.info(f"Episodes: {n_episodes}, Max steps: {max_steps}")
            logger.info(f"Expected infections: {scenario.get_expected_infections()}")
            logger.info(f"{'='*60}")

            for episode in range(n_episodes):
                # Generate scenario with variation
                hosts = scenario.generate()
                env = NetworkEnvironment(
                    network_size=len(hosts),
                    max_steps=max_steps,
                )

                # Override environment hosts with realistic data
                env.hosts = hosts

                state = env.reset()
                if hasattr(state, "tolist"):
                    state = state.tolist()
                # Ensure state is the right size
                while len(state) < state_size:
                    state.append(0.0)
                state = state[:state_size]

                total_reward = 0
                done = False

                while not done:
                    available = env.get_available_actions()
                    if available:
                        action = self.agent.act(state, available_actions=available)
                    else:
                        action = self.agent.act(state)

                    next_state, reward, done, info = env.step(action)
                    if hasattr(next_state, "tolist"):
                        next_state = next_state.tolist()
                    while len(next_state) < state_size:
                        next_state.append(0.0)
                    next_state = next_state[:state_size]

                    self.agent.remember(state, action, reward, next_state, done)
                    self.agent.replay()

                    state = next_state
                    total_reward += reward

                # Track metrics
                self.training_history["rewards"].append(total_reward)
                self.training_history["infections"].append(info.get("infected_count", 0))
                self.training_history["detections"].append(1 if env.detected else 0)
                self.training_history["scenarios"].append(scenario_name)
                self.training_history["episodes"].append(total_episodes_run)

                total_episodes_run += 1

                # Soft target update
                self.agent.update_target_model(tau=0.005)

                # Check improvement
                window = min(50, len(self.training_history["rewards"]))
                avg_reward = np.mean(self.training_history["rewards"][-window:])

                if avg_reward > self.best_reward:
                    self.best_reward = avg_reward
                    no_improve_count = 0

                    # Save best model
                    try:
                        self.agent.save(self.best_model_path)
                    except Exception as e:
                        logger.debug(f"Failed to save best model: {e}")
                else:
                    no_improve_count += 1

                # Early stopping
                if no_improve_count >= early_stop_patience:
                    logger.info(f"Early stopping at episode {total_episodes_run}")
                    logger.info(f"No improvement for {early_stop_patience} episodes")
                    break

                # Checkpoint
                if total_episodes_run % checkpoint_interval == 0:
                    avg_r = np.mean(self.training_history["rewards"][-window:])
                    avg_i = np.mean(self.training_history["infections"][-window:])
                    det_r = np.mean(self.training_history["detections"][-window:])

                    logger.info(
                        f"[Checkpoint {total_episodes_run}] "
                        f"Avg Reward: {avg_r:.2f} | "
                        f"Avg Infected: {avg_i:.1f}/{len(hosts)} | "
                        f"Detection: {det_r*100:.1f}% | "
                        f"Best: {self.best_reward:.2f}"
                    )

                    # Save checkpoint
                    ckpt_path = os.path.join(self.save_dir, f"checkpoint_{total_episodes_run}.h5")
                    try:
                        self.agent.save(ckpt_path)
                    except Exception as e:
                        logger.debug(f"Failed to save checkpoint: {e}")

                # Progress logging
                if episode > 0 and episode % 50 == 0:
                    avg_r = np.mean(self.training_history["rewards"][-50:])
                    avg_i = np.mean(self.training_history["infections"][-50:])
                    logger.debug(
                        f"  Episode {episode}/{n_episodes}: "
                        f"Avg Reward: {avg_r:.2f}, Avg Infected: {avg_i:.1f}"
                    )

            if no_improve_count >= early_stop_patience:
                break

        # Save final model
        try:
            self.agent.save(self.final_model_path)
        except Exception as e:
            logger.warning(f"Failed to save final model: {e}")

        # Save training metadata
        elapsed = time.time() - start_time
        metadata = {
            "best_reward": float(self.best_reward),
            "total_episodes": total_episodes_run,
            "final_epsilon": float(self.agent.epsilon),
            "scenarios_trained": scenarios,
            "elapsed_seconds": elapsed,
            "timestamp": datetime.now().isoformat(),
            "history_summary": {
                "avg_reward_last_100": (
                    float(np.mean(self.training_history["rewards"][-100:]))
                    if len(self.training_history["rewards"]) >= 100
                    else None
                ),
                "avg_infections_last_100": (
                    float(np.mean(self.training_history["infections"][-100:]))
                    if len(self.training_history["infections"]) >= 100
                    else None
                ),
            },
        }

        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        self.is_trained = True

        logger.info("\n" + "=" * 60)
        logger.info("TRAINING COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Total episodes: {total_episodes_run}")
        logger.info(f"Best reward: {self.best_reward:.2f}")
        logger.info(f"Final epsilon: {self.agent.epsilon:.3f}")
        logger.info(f"Time: {elapsed:.1f}s")
        logger.info(f"Best model: {self.best_model_path}")
        logger.info(f"Final model: {self.final_model_path}")
        logger.info(f"Metadata: {self.metadata_path}")
        logger.info("=" * 60)

        return metadata

    def load_model(self, path: str = None) -> bool:
        """Load a trained model"""
        if path is None:
            path = self.best_model_path

        if not os.path.exists(path):
            logger.warning(f"Model not found: {path}")
            return False

        try:
            # Determine state/action size from metadata
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path) as f:
                    meta = json.load(f)
                # We need to infer sizes - use defaults
                state_size = 300
                action_size = 50
            else:
                state_size = 300
                action_size = 50

            self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
            self.agent.load(path)
            self.agent.epsilon = 0.05  # Low exploration for inference
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def needs_training(self) -> bool:
        """Check if training is needed (no model exists)"""
        return not os.path.exists(self.best_model_path)

    def get_training_status(self) -> Dict:
        """Get training status"""
        if os.path.exists(self.metadata_path):
            with open(self.metadata_path) as f:
                meta = json.load(f)
            return {
                "trained": True,
                "best_reward": meta.get("best_reward", 0),
                "total_episodes": meta.get("total_episodes", 0),
                "timestamp": meta.get("timestamp", ""),
                "scenarios": meta.get("scenarios_trained", []),
            }
        return {
            "trained": False,
            "best_reward": 0,
            "total_episodes": 0,
            "timestamp": "",
            "scenarios": [],
        }


def auto_train_if_needed(save_dir: str = "saved/rl_agent") -> bool:
    """
    Automatically train the RL agent if no model exists

    Returns:
        True if training was performed, False if model already exists
    """
    trainer = RealisticTrainer(save_dir)

    if not trainer.needs_training():
        status = trainer.get_training_status()
        logger.info(f"Model already exists (trained {status['total_episodes']} episodes)")
        return False

    logger.info("No pre-trained model found. Starting auto-training...")
    logger.info(
        "This will train on realistic scenarios: small_office → enterprise → datacenter → cloud → iot"
    )
    logger.info("Training may take several minutes...")

    metadata = trainer.train(
        early_stop_patience=300,
        checkpoint_interval=100,
    )

    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Realistic RL Training")
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=None,
        help="Scenario names (default: all in curriculum order)",
    )
    parser.add_argument(
        "--episodes",
        type=int,
        default=None,
        help="Episodes per scenario (default: scenario-specific)",
    )
    parser.add_argument("--save-dir", type=str, default="saved/rl_agent", help="Save directory")
    parser.add_argument("--early-stop", type=int, default=300, help="Early stop patience")
    parser.add_argument("--list-scenarios", action="store_true", help="List available scenarios")
    parser.add_argument("--status", action="store_true", help="Show training status")

    args = parser.parse_args()

    if args.list_scenarios:
        print("Available scenarios:")
        for name in get_scenario_names():
            s = get_scenario(name)
            print(f"  {name}: {s.description} ({s.get_expected_infections()} expected infections)")
        sys.exit(0)

    if args.status:
        trainer = RealisticTrainer(args.save_dir)
        status = trainer.get_training_status()
        print(f"Training status: {'TRAINED' if status['trained'] else 'NOT TRAINED'}")
        if status["trained"]:
            print(f"  Best reward: {status['best_reward']:.2f}")
            print(f"  Episodes: {status['total_episodes']}")
            print(f"  Scenarios: {status['scenarios']}")
            print(f"  Trained at: {status['timestamp']}")
        sys.exit(0)

    auto_train_if_needed(args.save_dir)
