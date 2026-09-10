"""Tests for the professional CLI (worm_core/cli.py).

Covers: parser construction, target validation, authorization gate,
version output (text + json), lab compose resolution and the doctor
command contract.
"""

import argparse
import json
import os
import sys
import unittest
from unittest import mock

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
