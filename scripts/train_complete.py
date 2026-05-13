#!/usr/bin/env python3
"""
Wormy ML Network Worm v3.0 - Complete Auto-Training Script
Trains the RL Brain v2.0 across all 5 realistic scenarios with curriculum learning.

Usage:
    python3 scripts/train_complete.py              # Full curriculum training
    python3 scripts/train_complete.py --scenario small_office  # Single scenario
    python3 scripts/train_complete.py --episodes 200            # Custom episodes
    python3 scripts/train_complete.py --status                  # Show training status
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import warnings

warnings.filterwarnings("ignore")

from rl_engine import NetworkEnvironment, PropagationAgent
from training.scenarios import get_scenario, get_scenario_names


def print_header():
    print("=" * 70)
    print("WORMY ML NETWORK WORM v3.0 - RL BRAIN TRAINING")
    print("=" * 70)


def print_status():
    """Show current training status"""
    model_path = "saved/rl_agent/best_model.h5"
    meta_path = "saved/rl_agent/training_metadata.json"

    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        print(f"\nCurrent Model Status:")
        print(f'  Scenarios trained: {", ".join(meta.get("scenarios_trained", []))}')
        print(f'  Total episodes: {meta.get("total_episodes", 0)}')
        print(f'  Best reward: {meta.get("best_reward", 0):.1f}')
        print(
            f'  Avg reward (last 10): {meta.get("avg_reward_last_10", meta.get("avg_reward_last_5", 0)):.1f}'
        )
        print(f'  Final epsilon: {meta.get("final_epsilon", 1.0):.4f}')
        print(f'  Training time: {meta.get("training_time_seconds", 0):.0f}s')

    if os.path.exists(model_path):
        size = os.path.getsize(model_path)
        print(f"  Model file: {model_path} ({size/1024:.1f} KB)")
    else:
        print(f"  No trained model found")
    print()


def train_scenario(scenario_name: str, episodes: int = 50, load_existing: bool = True):
    """Train on a single scenario"""
    scenario = get_scenario(scenario_name)
    hosts = scenario.generate()

    env = NetworkEnvironment(network_size=len(hosts), max_steps=20)
    env.hosts = hosts
    state = env.reset()
    state_size = len(state)
    action_size = len(env.hosts)

    # Create or load agent
    agent = PropagationAgent(
        state_size=state_size, action_size=action_size, use_dqn=True, use_per=True
    )

    if load_existing:
        model_path = "saved/rl_agent/best_model.h5"
        if os.path.exists(model_path):
            try:
                agent.load(model_path)
                print(f"    Loaded existing model")
            except Exception:
                pass

    print(
        f"  Scenario: {scenario.name} ({len(hosts)} hosts, state={state_size}, action={action_size})"
    )

    start = time.time()
    rewards, infections = [], []

    for episode in range(episodes):
        state = env.reset()
        total_reward = 0
        done = False
        steps = 0

        while not done:
            available = env.get_available_actions()
            action = (
                agent.act(state, available_actions=available) if available else agent.act(state)
            )
            next_state, reward, done, info = env.step(action)
            agent.remember(state, action, reward, next_state, done)
            agent.step_epsilon_decay()

            if steps % 4 == 0 and len(agent.memory) >= 16:
                agent.replay(batch_size=16)
            agent.update_target_model(tau=0.005)

            state = next_state
            total_reward += reward
            steps += 1

        rewards.append(total_reward)
        infections.append(info.get("infected_count", 0))

        if (episode + 1) % 10 == 0:
            avg_r = sum(rewards[-10:]) / 10
            avg_i = sum(infections[-10:]) / 10
            elapsed = time.time() - start
            print(
                f"    Ep {episode+1}/{episodes} | R: {avg_r:.1f} | I: {avg_i:.1f}/{len(hosts)} | eps: {agent.epsilon:.3f} | {elapsed:.0f}s"
            )

    elapsed = time.time() - start
    avg_first = sum(rewards[: min(10, len(rewards))]) / min(10, len(rewards))
    avg_last = sum(rewards[-min(10, len(rewards)) :]) / min(10, len(rewards))

    print(f"  Completed in {elapsed:.0f}s")
    print(f"  Avg reward (first 10): {avg_first:.1f}")
    print(f"  Avg reward (last 10): {avg_last:.1f}")
    print(f'  Improvement: {"+" if avg_last > avg_first else ""}{avg_last-avg_first:.1f}')

    return agent, {
        "scenario": scenario_name,
        "episodes": episodes,
        "best_reward": float(max(rewards)),
        "avg_reward_first_10": float(avg_first),
        "avg_reward_last_10": float(avg_last),
        "final_epsilon": float(agent.epsilon),
        "training_time": elapsed,
        "state_size": state_size,
        "action_size": action_size,
    }


def main():
    parser = argparse.ArgumentParser(description="Train Wormy RL Brain v2.0")
    parser.add_argument("--scenario", type=str, help="Train specific scenario")
    parser.add_argument("--episodes", type=int, default=50, help="Episodes per scenario")
    parser.add_argument("--status", action="store_true", help="Show training status")
    args = parser.parse_args()

    if args.status:
        print_header()
        print_status()
        return

    print_header()
    print_status()

    if args.scenario:
        scenarios = [args.scenario]
    else:
        scenarios = get_scenario_names()

    print(f"Scenarios: {scenarios}")
    print(f"Episodes per scenario: {args.episodes}")
    print(f"=" * 70)

    all_results = []
    total_start = time.time()

    for i, scenario_name in enumerate(scenarios):
        print(f"\n[{i+1}/{len(scenarios)}] Training: {scenario_name}")
        agent, result = train_scenario(scenario_name, args.episodes, load_existing=(i > 0))
        all_results.append(result)

        # Save after each scenario
        os.makedirs("saved/rl_agent", exist_ok=True)
        agent.save("saved/rl_agent/best_model.h5")

        # Update metadata
        meta = {
            "best_reward": result["best_reward"],
            "avg_reward_first_10": result["avg_reward_first_10"],
            "avg_reward_last_10": result["avg_reward_last_10"],
            "total_episodes": sum(r["episodes"] for r in all_results),
            "final_epsilon": result["final_epsilon"],
            "scenarios_trained": [r["scenario"] for r in all_results],
            "state_size": result["state_size"],
            "action_size": result["action_size"],
            "training_time_seconds": time.time() - total_start,
            "timestamp": time.time(),
        }
        with open("saved/rl_agent/training_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

    total_elapsed = time.time() - total_start
    print(f'\n{"=" * 70}')
    print(f"TRAINING COMPLETE")
    print(f'{"=" * 70}')
    print(f"Total time: {total_elapsed:.0f}s ({total_elapsed/60:.1f} minutes)")
    print(f"Scenarios trained: {len(scenarios)}")
    print(f"Model saved: saved/rl_agent/best_model.h5")
    print(f"Metadata: saved/rl_agent/training_metadata.json")
    print(f'{"=" * 70}')


if __name__ == "__main__":
    main()
