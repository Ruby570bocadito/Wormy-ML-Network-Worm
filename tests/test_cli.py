"""Tests for the professional CLI (worm_core/cli.py).

Covers: parser construction, target validation, authorization gate,
version output (text + json), lab compose resolution and the doctor
command contract.
"""

import argparse
import io
import json
import os
import sys
import unittest
from unittest import mock

from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from worm_core import cli


def _ns(**kw):
    base = {"dry_run": True, "scan_only": False, "yes_i_am_authorized": False}
    base.update(kw)
    return argparse.Namespace(**base)


class TestBuildParser(unittest.TestCase):
    def test_builds_without_error(self):
        parser = cli.build_parser()
        self.assertIsNotNone(parser)

    def test_parse_run_defaults(self):
        args = cli.build_parser().parse_args(["run"])
        # --dry-run is opt-in; live mode is blocked by the authorization gate
        self.assertFalse(args.dry_run)
        self.assertFalse(args.scan_only)

    def test_parse_scan_json(self):
        args = cli.build_parser().parse_args(["scan", "--json"])
        self.assertTrue(args.json)

    def test_parse_lab_up_expanded(self):
        args = cli.build_parser().parse_args(["lab", "up", "--expanded"])
        self.assertEqual(args.action, "up")
        self.assertTrue(args.expanded)

    def test_parse_version_json(self):
        args = cli.build_parser().parse_args(["version", "--json"])
        self.assertTrue(args.json)

    def test_parse_run_target_override(self):
        args = cli.build_parser().parse_args(["run", "--target", "10.0.0.0/24"])
        self.assertEqual(args.target, ["10.0.0.0/24"])


class TestValidateTargets(unittest.TestCase):
    def test_valid_cidr(self):
        self.assertIsNone(cli._validate_targets(["10.0.0.0/24"]))

    def test_valid_single_ip(self):
        self.assertIsNone(cli._validate_targets(["192.168.1.10"]))

    def test_invalid_string_rejected(self):
        err = cli._validate_targets(["not-a-network"])
        self.assertIsNotNone(err)
        self.assertIn("invalid target", err)

    def test_mixed_list_reports_offender(self):
        err = cli._validate_targets(["10.0.0.0/24", "bad!!"])
        self.assertIsNotNone(err)
        self.assertIn("bad!!", err)


class TestAuthorizationGate(unittest.TestCase):
    def test_dry_run_allowed(self):
        self.assertTrue(cli._authorization_gate(_ns(dry_run=True)))

    def test_scan_only_allowed(self):
        self.assertTrue(cli._authorization_gate(_ns(dry_run=False, scan_only=True)))

    def test_live_refused_without_confirmation(self):
        env = {k: v for k, v in os.environ.items() if k != cli.AUTH_ENV_VAR}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(cli._authorization_gate(_ns(dry_run=False)))

    def test_live_allowed_with_flag(self):
        env = {k: v for k, v in os.environ.items() if k != cli.AUTH_ENV_VAR}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertTrue(cli._authorization_gate(_ns(dry_run=False, yes_i_am_authorized=True)))

    def test_live_allowed_with_env_var(self):
        with mock.patch.dict(os.environ, {cli.AUTH_ENV_VAR: "1"}):
            self.assertTrue(cli._authorization_gate(_ns(dry_run=False)))


class TestCmdVersion(unittest.TestCase):
    def test_text_output_contains_version(
        self,
    ):
        from worm_core._version import __version__

        buf = _capture(lambda: cli.cmd_version(_ns(json=False)))
        self.assertIn(__version__, buf)

    def test_json_output_parses(self):
        buf = _capture(lambda: cli.cmd_version(_ns(json=True)))
        data = json.loads(buf)
        self.assertIn("wormy", data)
        self.assertIn("python", data)


class TestLabCompose(unittest.TestCase):
    def test_resolves_compose_in_repo(self):
        root = cli._find_repo_root()
        self.assertIsNotNone(root)
        path = cli._lab_compose(root)
        self.assertTrue(os.path.isfile(path))

    def test_env_override_wins(self):
        with mock.patch.dict(os.environ, {"WORMY_LAB_DIR": os.getcwd()}):
            root = cli._find_repo_root()
            self.assertIsNotNone(root)


class TestDoctorContract(unittest.TestCase):
    def test_doctor_returns_int_and_prints_summary(self):
        buf = _capture(lambda: cli.cmd_doctor(_ns()))
        self.assertTrue(
            ("Environment ready" in buf) or ("usable with warnings" in buf) or ("failed" in buf),
            "doctor must print a final summary line",
        )


class TestRunCapOverrides(unittest.TestCase):
    """--max-infections / --max-runtime: parsing, validation and application."""

    def _ns(self, **kw):
        base = {
            "dry_run": True,
            "scan_only": False,
            "yes_i_am_authorized": False,
            "max_infections": None,
            "max_runtime": None,
        }
        base.update(kw)
        return argparse.Namespace(**base)

    def _fake_worm(self):
        from types import SimpleNamespace

        from configs.config import Config

        return SimpleNamespace(config=Config())

    def test_parse_cap_flags(self):
        args = cli.build_parser().parse_args(
            ["run", "--dry-run", "--max-infections", "3", "--max-runtime", "2"]
        )
        self.assertEqual(args.max_infections, 3)
        self.assertEqual(args.max_runtime, 2)

    def test_parse_caps_default_to_none(self):
        args = cli.build_parser().parse_args(["run", "--dry-run"])
        self.assertIsNone(args.max_infections)
        self.assertIsNone(args.max_runtime)

    def test_validate_rejects_zero_infections(self):
        err = cli._validate_cap_overrides(self._ns(max_infections=0))
        self.assertIsNotNone(err)
        self.assertIn("--max-infections", err)

    def test_validate_rejects_zero_runtime(self):
        err = cli._validate_cap_overrides(self._ns(max_runtime=0))
        self.assertIsNotNone(err)
        self.assertIn("--max-runtime", err)

    def test_validate_accepts_sane_values(self):
        self.assertIsNone(cli._validate_cap_overrides(self._ns(max_infections=1, max_runtime=1)))

    def test_validate_accepts_absent_values(self):
        self.assertIsNone(cli._validate_cap_overrides(self._ns()))

    def test_apply_lowering_cap(self):
        worm = self._fake_worm()
        worm.config.propagation.max_infections = 100  # default
        cli._apply_cap_overrides(worm, self._ns(max_infections=3))
        self.assertEqual(worm.config.propagation.max_infections, 3)

    def test_apply_runtime_cap(self):
        worm = self._fake_worm()
        cli._apply_cap_overrides(worm, self._ns(max_runtime=2))
        self.assertEqual(worm.config.safety.max_runtime_hours, 2)

    def test_apply_no_flags_is_noop(self):
        worm = self._fake_worm()
        before_inf = worm.config.propagation.max_infections
        before_rt = worm.config.safety.max_runtime_hours
        cli._apply_cap_overrides(worm, self._ns())
        self.assertEqual(worm.config.propagation.max_infections, before_inf)
        self.assertEqual(worm.config.safety.max_runtime_hours, before_rt)

    def test_raising_cap_in_dry_run_does_not_warn(self):
        # Dry-run/scan-only are simulation surfaces: raising a cap there
        # must NOT trigger the live-mode safety warning.
        worm = self._fake_worm()
        err_buf = io.StringIO()
        with mock.patch.object(cli, "err_console", Console(file=err_buf, force_terminal=False)):
            cli._apply_cap_overrides(worm, self._ns(dry_run=True, max_infections=500))
        self.assertEqual(worm.config.propagation.max_infections, 500)
        self.assertNotIn("raising", err_buf.getvalue().lower())

    def test_raising_cap_in_live_mode_warns(self):
        worm = self._fake_worm()
        err_buf = io.StringIO()
        with mock.patch.object(
            cli, "err_console", Console(file=err_buf, force_terminal=False, width=100)
        ):
            cli._apply_cap_overrides(worm, self._ns(dry_run=False, max_infections=500))
        self.assertEqual(worm.config.propagation.max_infections, 500)
        self.assertIn("Safety cap raised", err_buf.getvalue())

    def test_raising_runtime_in_live_mode_warns(self):
        worm = self._fake_worm()
        err_buf = io.StringIO()
        with mock.patch.object(
            cli, "err_console", Console(file=err_buf, force_terminal=False, width=100)
        ):
            cli._apply_cap_overrides(worm, self._ns(dry_run=False, max_runtime=48))
        self.assertEqual(worm.config.safety.max_runtime_hours, 48)
        self.assertIn("Safety cap raised", err_buf.getvalue())


class TestReportSubcommand(unittest.TestCase):
    def test_parse_report_defaults(self):
        args = cli.build_parser().parse_args(["report"])
        self.assertEqual(args.action, "list")
        self.assertEqual(args.report_id, "latest")
        self.assertFalse(args.json)

    def test_parse_report_show_with_id(self):
        args = cli.build_parser().parse_args(["report", "show", "20260913_142530"])
        self.assertEqual(args.action, "show")
        self.assertEqual(args.report_id, "20260913_142530")

    def test_parse_report_html_output(self):
        args = cli.build_parser().parse_args(["report", "html", "-o", "out.html"])
        self.assertEqual(args.action, "html")
        self.assertEqual(args.output, "out.html")

    def test_parse_report_rejects_unknown_action(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["report", "explode"])

    def test_parse_report_compare_defaults(self):
        args = cli.build_parser().parse_args(["report", "compare"])
        self.assertEqual(args.action, "compare")
        self.assertEqual(args.report_id, "latest")
        self.assertIsNone(args.report_id2)

    def test_parse_report_compare_single_id(self):
        args = cli.build_parser().parse_args(["report", "compare", "20260913_1"])
        self.assertEqual(args.action, "compare")
        self.assertEqual(args.report_id, "20260913_1")
        self.assertIsNone(args.report_id2)

    def test_parse_report_compare_pair(self):
        args = cli.build_parser().parse_args(["report", "compare", "20260913_1", "20260913_2"])
        self.assertEqual(args.report_id, "20260913_1")
        self.assertEqual(args.report_id2, "20260913_2")

    def test_parse_report_compare_json(self):
        args = cli.build_parser().parse_args(["report", "compare", "--json"])
        self.assertTrue(args.json)
        self.assertEqual(args.action, "compare")


class TestShellCapFlags(unittest.TestCase):
    """--max-infections / --max-runtime parity for `wormy shell`."""

    def test_parse_shell_cap_flags(self):
        args = cli.build_parser().parse_args(
            ["shell", "--dry-run", "--max-infections", "2", "--max-runtime", "3"]
        )
        self.assertEqual(args.max_infections, 2)
        self.assertEqual(args.max_runtime, 3)
        self.assertTrue(args.dry_run)

    def test_parse_shell_caps_default_to_none(self):
        args = cli.build_parser().parse_args(["shell"])
        self.assertIsNone(args.max_infections)
        self.assertIsNone(args.max_runtime)

    def test_shell_parser_keeps_common_flags(self):
        args = cli.build_parser().parse_args(
            ["shell", "--dry-run", "--target", "127.0.0.0/30", "--profile", "audit"]
        )
        self.assertEqual(args.target, ["127.0.0.0/30"])
        self.assertEqual(args.profile, "audit")

    def test_validate_rejects_bad_shell_caps(self):
        # shell namespaces have no scan_only attribute — validation must
        # still work (getattr fallback in the warning guard).
        args = argparse.Namespace(dry_run=True, max_infections=0, max_runtime=None)
        err = cli._validate_cap_overrides(args)
        self.assertIsNotNone(err)
        self.assertIn("--max-infections", err)

    def test_apply_caps_tolerates_namespace_without_scan_only(self):
        # Regression: shell args lack scan_only; _apply_cap_overrides used
        # to crash with AttributeError on it.
        from types import SimpleNamespace

        from configs.config import Config

        worm = SimpleNamespace(config=Config())
        args = argparse.Namespace(dry_run=False, max_infections=500, max_runtime=None)
        buf = io.StringIO()
        with mock.patch.object(
            cli, "err_console", Console(file=buf, force_terminal=False, width=100)
        ):
            cli._apply_cap_overrides(worm, args)  # must not raise
        self.assertEqual(worm.config.propagation.max_infections, 500)
        self.assertIn("Safety cap raised", buf.getvalue())

    def test_cmd_shell_applies_caps_to_engine(self):
        # Wiring: cmd_shell must forward the cap flags into the engine.
        from configs.config import Config

        args = argparse.Namespace(
            config=None,
            profile=None,
            dry_run=True,
            target=None,
            max_infections=2,
            max_runtime=None,
        )
        with (
            mock.patch("worm_core.WormCore") as wc,
            mock.patch("worm_core.shell.InteractiveCLI") as icli,
        ):
            worm = wc.return_value
            worm.config = Config()
            rc = cli.cmd_shell(args)
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertEqual(worm.config.propagation.max_infections, 2)
        icli.assert_called_once_with(worm)
        icli.return_value.cmdloop.assert_called_once()
        worm.shutdown.assert_called_once()

    def test_cmd_shell_rejects_invalid_caps_before_boot(self):
        args = argparse.Namespace(
            config=None,
            profile=None,
            dry_run=True,
            target=None,
            max_infections=0,
            max_runtime=None,
        )
        buf = io.StringIO()
        with (
            mock.patch("worm_core.WormCore") as wc,
            mock.patch("worm_core.shell.InteractiveCLI") as icli,
            mock.patch.object(
                cli, "err_console", Console(file=buf, force_terminal=False, width=100)
            ),
        ):
            rc = cli.cmd_shell(args)
        self.assertEqual(rc, cli.EXIT_USAGE)
        self.assertIn("--max-infections", buf.getvalue())
        wc.assert_not_called()
        icli.assert_not_called()


class TestConfigSubcommand(unittest.TestCase):
    def test_parse_config_defaults_to_show(self):
        args = cli.build_parser().parse_args(["config"])
        self.assertEqual(args.action, "show")

    def test_parse_config_with_profile(self):
        args = cli.build_parser().parse_args(["config", "show", "--profile", "stealth"])
        self.assertEqual(args.profile, "stealth")


def _capture(fn):
    """Run fn() capturing stdout; return what was printed."""
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        fn()
    return buf.getvalue()


if __name__ == "__main__":
    unittest.main()
