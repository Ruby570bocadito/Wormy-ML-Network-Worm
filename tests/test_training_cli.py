"""Regression tests for the training CLI flag wiring.

`wormy train rl --episodes N --scenarios ...` used to silently ignore
every flag and launch the full default curriculum (5 scenarios x default
episodes). These tests pin the contract: explicit flags must reach
RealisticTrainer.train().
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import training.realistic_training as rt


class TestTrainingFlagWiring(unittest.TestCase):
    def test_explicit_flags_reach_trainer(self):
        with (
            mock.patch.object(rt, "RealisticTrainer") as trainer_cls,
            mock.patch.object(rt, "auto_train_if_needed") as auto,
        ):
            trainer = trainer_cls.return_value
            trainer.get_training_status.return_value = {
                "total_episodes": 2,
                "best_reward": 157.5,
                "trained": True,
            }
            argv = [
                "realistic_training",
                "--episodes",
                "2",
                "--scenarios",
                "small_office",
                "--early-stop",
                "50",
                "--save-dir",
                "/tmp/xyz",
            ]
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                rt.main_cli()
            trainer_cls.assert_called_once_with("/tmp/xyz")
            trainer.train.assert_called_once_with(
                scenarios=["small_office"],
                total_episodes=2,
                early_stop_patience=50,
                checkpoint_interval=100,
            )
            auto.assert_not_called()

    def test_no_flags_still_uses_auto_training(self):
        with (
            mock.patch.object(rt, "RealisticTrainer"),
            mock.patch.object(rt, "auto_train_if_needed") as auto,
        ):
            with mock.patch.object(sys, "argv", ["realistic_training"]):
                rt.main_cli()  # no SystemExit: falls through to auto_train
            auto.assert_called_once()

    def test_status_mode_does_not_train(self):
        with (
            mock.patch.object(rt, "RealisticTrainer") as trainer_cls,
            mock.patch.object(rt, "auto_train_if_needed") as auto,
        ):
            trainer_cls.return_value.get_training_status.return_value = {
                "trained": False,
                "total_episodes": 0,
                "best_reward": 0,
            }
            with (
                mock.patch.object(sys, "argv", ["realistic_training", "--status"]),
                self.assertRaises(SystemExit),
            ):
                rt.main_cli()
            trainer_cls.return_value.train.assert_not_called()
            auto.assert_not_called()

    def test_list_scenarios_does_not_train(self):
        with (
            mock.patch.object(rt, "RealisticTrainer") as trainer_cls,
            mock.patch.object(rt, "auto_train_if_needed") as auto,
        ):
            with (
                mock.patch.object(sys, "argv", ["realistic_training", "--list-scenarios"]),
                self.assertRaises(SystemExit),
            ):
                rt.main_cli()
            trainer_cls.assert_not_called()
            auto.assert_not_called()


if __name__ == "__main__":
    unittest.main()
