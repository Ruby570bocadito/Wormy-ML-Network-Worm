"""Tests for the effective-configuration surface (worm_core/config_show.py
and the shared apply_profile() helper in worm_core/config_profiles.py).

Covers: profile application semantics (section resolution order, returned
override keys, unknown profiles), WormCoreBase._apply_profile delegation,
rendering (sections, profile markers, kill-switch transparency), --json
output shape, target override preview and config error handling.
"""

import io
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from configs.config import Config
from worm_core import config_show
from worm_core.config_profiles import CONFIG_PROFILES, apply_profile


def _capture():
    console = Console(file=io.StringIO(), force_terminal=False, width=120)
    patcher = mock.patch.object(config_show, "console", console)
    return console, patcher


def _args(**kw):
    base = {"action": "show", "config": None, "profile": None, "target": None, "json": False}
    base.update(kw)
    return SimpleNamespace(**base)


class TestApplyProfileHelper(unittest.TestCase):
    def test_stealth_applies_across_sections(self):
        cfg = Config()
        applied = apply_profile(cfg, "stealth")
        self.assertEqual(cfg.propagation.max_infections, 10)
        self.assertEqual(cfg.propagation.propagation_delay, 10.0)
        self.assertTrue(cfg.evasion.stealth_mode)
        self.assertTrue(cfg.evasion.randomize_timing)
        self.assertEqual(cfg.evasion.max_scan_rate, 10)
        self.assertEqual(cfg.safety.max_runtime_hours, 8)
        self.assertTrue(cfg.ml.use_pretrained)
        # returned keys are fully-qualified
        self.assertIn("propagation.max_infections", applied)
        self.assertIn("evasion.stealth_mode", applied)
        self.assertIn("safety.max_runtime_hours", applied)
        self.assertIn("ml.use_pretrained", applied)

    def test_section_resolution_order_propagation_first(self):
        # max_infections lives in propagation (not evasion/safety/ml).
        cfg = Config()
        apply_profile(cfg, "aggressive")
        self.assertEqual(cfg.propagation.max_infections, 100)

    def test_unknown_profile_is_noop(self):
        cfg = Config()
        before = cfg.propagation.max_infections
        applied = apply_profile(cfg, "does-not-exist")
        self.assertEqual(applied, [])
        self.assertEqual(cfg.propagation.max_infections, before)

    def test_returns_empty_for_none_profile(self):
        self.assertEqual(apply_profile(Config(), None), [])

    def test_every_profile_key_lands_somewhere(self):
        # Guards against profiles silently rotting when dataclasses change.
        for name, overrides in CONFIG_PROFILES.items():
            cfg = Config()
            applied = apply_profile(cfg, name)
            self.assertEqual(
                len(applied),
                len(overrides),
                f"profile {name} has keys that no config section accepts: "
                f"{set(overrides) - {k.split('.', 1)[1] for k in applied}}",
            )

    def test_wormcore_base_delegates_to_shared_helper(self):
        from worm_core.mixin_base import WormCoreBase

        cfg = Config()
        fake_self = SimpleNamespace(config=cfg)
        WormCoreBase._apply_profile(fake_self, "lab_docker")
        self.assertEqual(cfg.propagation.max_infections, 15)
        self.assertEqual(cfg.safety.max_runtime_hours, 1)


class TestRenderShow(unittest.TestCase):
    def test_renders_all_sections_and_defaults_hint(self):
        console, patcher = _capture()
        with patcher:
            config_show.render_show(Config(), Config(), [], _args())
        out = console.file.getvalue()
        for section in (
            "Network",
            "Propagation & safety",
            "Evasion & stealth",
            "Command & control",
            "ML",
        ):
            self.assertIn(section, out)
        self.assertIn("No profile applied", out)

    def test_profile_values_carry_the_marker(self):
        effective = Config()
        applied = apply_profile(effective, "stealth")
        console, patcher = _capture()
        with patcher:
            config_show.render_show(Config(), effective, applied, _args(profile="stealth"))
        out = console.file.getvalue()
        self.assertIn("[profile]", out)
        self.assertIn("stealth", out)

    def test_kill_switch_code_is_visible(self):
        # The operator needs the code to actually use the kill switch.
        console, patcher = _capture()
        with patcher:
            config_show.render_show(Config(), Config(), [], _args())
        out = console.file.getvalue()
        self.assertIn("Kill switch code", out)
        self.assertIn(Config().safety.kill_switch_code, out)

    def test_target_override_is_rendered(self):
        effective = Config()
        effective.network.target_ranges = ["10.0.0.0/24"]
        console, patcher = _capture()
        with patcher:
            config_show.render_show(Config(), effective, [], _args(target=["10.0.0.0/24"]))
        self.assertIn("10.0.0.0/24", console.file.getvalue())

    def test_booleans_render_on_off(self):
        self.assertEqual(config_show._fmt(True), "on")
        self.assertEqual(config_show._fmt(False), "off")
        self.assertEqual(config_show._fmt(None), "—")
        self.assertEqual(config_show._fmt([1, 2]), "1, 2")
        self.assertEqual(config_show._fmt([]), "—")


class TestCmdConfig(unittest.TestCase):
    def test_cmd_show_ok(self):
        console, patcher = _capture()
        with patcher:
            rc = config_show.cmd_config(_args())
        self.assertEqual(rc, config_show.EXIT_OK)
        self.assertIn("effective configuration", console.file.getvalue())

    def test_cmd_show_with_profile(self):
        console, patcher = _capture()
        with patcher:
            rc = config_show.cmd_config(_args(profile="audit"))
        self.assertEqual(rc, config_show.EXIT_OK)
        out = console.file.getvalue()
        self.assertIn("[profile]", out)
        self.assertIn("audit", out)

    def test_cmd_show_json_shape(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = config_show.cmd_config(_args(profile="lab_docker", json=True))
        self.assertEqual(rc, config_show.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["propagation"]["max_infections"], 15)
        self.assertEqual(payload["safety"]["max_runtime_hours"], 1)
        self.assertIn("propagation.max_infections", payload["_meta"]["profile_overrides"])
        self.assertEqual(payload["_meta"]["profile"], "lab_docker")

    def test_cmd_show_json_without_profile(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = config_show.cmd_config(_args(json=True))
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["_meta"]["profile"], None)
        self.assertEqual(payload["_meta"]["profile_overrides"], [])
        self.assertIn("network", payload)

    def test_cmd_show_target_override_preview(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = config_show.cmd_config(_args(target=["127.0.0.0/24"], json=True))
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["network"]["target_ranges"], ["127.0.0.0/24"])

    def test_cmd_invalid_config_file_is_error(self):
        rc = config_show.cmd_config(_args(config="/nonexistent/config.yaml"))
        self.assertEqual(rc, config_show.EXIT_ERROR)

    def test_cmd_unknown_action_is_usage_error(self):
        rc = config_show.cmd_config(_args(action="mutate"))
        self.assertEqual(rc, 2)


class TestEndToEndThroughCli(unittest.TestCase):
    """The `wormy config` subcommand routes to config_show.cmd_config."""

    def test_cli_config_show_invokes_impl(self):
        from worm_core import cli

        args = cli.build_parser().parse_args(["config", "show", "--profile", "stealth"])
        rc = cli.cmd_config(args)
        self.assertEqual(rc, cli.EXIT_OK)

    def test_cli_config_rejects_unknown_profile_at_parse_time(self):
        from worm_core import cli

        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["config", "show", "--profile", "nope"])


if __name__ == "__main__":
    unittest.main()
