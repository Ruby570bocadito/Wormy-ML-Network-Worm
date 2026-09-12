"""Tests for the REPL `report` command (worm_core/shell.py).

The REPL integrates with the read-only report hub: `report` (or
`report new`) keeps generating a fresh report for the live session, while
`report list|show|compare|html` operate on the historical engagement
reports. These tests use a fake worm (no engine) and real report files.

Covers: backwards compatibility, subcommand dispatch, html arg parsing
(-o/id), error containment (a failing hub call must never crash the
cmd.Cmd loop), and the help table entry.
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_report_cli import _make_hosts, _make_stats
from utils.audit_report import AuditReportGenerator
from worm_core import report_cli, shell


def _fake_worm(calls):
    return SimpleNamespace(
        infected_hosts=[],
        scan_results=[],
        running=False,
        stats={},
        print_final_report=lambda: calls.append("new"),
    )


def _capture_shell_console():
    """Capture output on BOTH surfaces: the REPL console and the hub consoles.

    The shell prints its own messages on ``shell.console`` while the hub
    (report_cli) renders tables/errors on ``report_cli.console`` /
    ``report_cli.err_console``. A REPL command can write to any of them,
    so all three are captured and concatenated for assertions. Usage:

        combined, ctx = _capture_shell_console()
        with ctx:
            repl.onecmd("report list")
        out = combined.file.getvalue()
    """
    shell_console = Console(file=io.StringIO(), force_terminal=False, width=120)
    hub_console = Console(file=io.StringIO(), force_terminal=False, width=120)
    hub_err = Console(file=io.StringIO(), force_terminal=False, width=120)

    class _Combined:
        @property
        def file(self):
            text = (
                shell_console.file.getvalue()
                + hub_console.file.getvalue()
                + hub_err.file.getvalue()
            )
            return SimpleNamespace(getvalue=lambda: text)

    @contextlib.contextmanager
    def _ctx():
        with (
            mock.patch.object(shell, "console", shell_console),
            mock.patch.object(report_cli, "console", hub_console),
            mock.patch.object(report_cli, "err_console", hub_err),
        ):
            yield _Combined()

    return _Combined(), _ctx()


class ShellReportTestBase(unittest.TestCase):
    """One real generated report in a temp dir, plus a fake-worm REPL."""

    def setUp(self):
        self.reports_dir = tempfile.mkdtemp(prefix="wormy_test_shellreport_")
        gen = AuditReportGenerator()
        files = gen.generate(
            worm_stats=_make_stats(),
            scan_results=_make_hosts(),
            infected_hosts={"10.0.0.5"},
            failed_targets={"10.0.0.6"},
            output_dir=self.reports_dir,
        )
        self.json_path = files["json"]
        calls = []
        self.repl = shell.InteractiveCLI(_fake_worm(calls))
        self.calls = calls
        # Point the hub at the fixture dir regardless of CWD.
        patcher = mock.patch.object(
            report_cli, "resolve_reports_dir", return_value=self.reports_dir
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for name in os.listdir(self.reports_dir):
            os.remove(os.path.join(self.reports_dir, name))
        os.rmdir(self.reports_dir)


class TestReportGenerationCompat(ShellReportTestBase):
    def test_bare_report_still_generates(self):
        self.repl.onecmd("report")
        self.assertEqual(self.calls, ["new"])

    def test_report_new_generates(self):
        self.repl.onecmd("report new")
        self.assertEqual(self.calls, ["new"])

    def test_generation_does_not_touch_history(self):
        before = os.listdir(self.reports_dir)
        self.repl.onecmd("report")
        self.assertEqual(os.listdir(self.reports_dir), before)


class TestReportHubSubcommands(ShellReportTestBase):
    def test_report_list_shows_inventory(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report list")
        out = console.file.getvalue()
        self.assertIn("Wormy engagements", out)
        self.assertIn("report(s)", out)

    def test_report_show_renders_latest(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report show")
        out = console.file.getvalue()
        self.assertIn("engagement report", out)
        self.assertIn("Executive summary", out)

    def test_report_show_explicit_id(self):
        import re as _re

        rid = _re.search(r"audit_report_(\d{8}_\d{6})", self.json_path).group(1)
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd(f"report show {rid}")
        self.assertIn(rid, console.file.getvalue())

    def test_report_show_unknown_id_prints_error_not_crash(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report show 19990101_000000")
        out = console.file.getvalue()
        self.assertIn("Report not found", out)

    def test_report_compare_renders_deltas(self):
        # Second report so `compare` has a pair. The first one is renamed to
        # a forced id FIRST: two generate() calls within the same second
        # would otherwise collide (known second-granularity filename bug).
        forced_a = "20260101_090000"
        current = report_cli.discover_reports(self.reports_dir)[0]
        os.replace(current["path"], os.path.join(self.reports_dir, f"audit_report_{forced_a}.json"))
        gen = AuditReportGenerator()
        gen.generate(
            worm_stats=_make_stats(infections=3),
            scan_results=_make_hosts(),
            infected_hosts={"10.0.0.5", "10.0.0.6", "10.0.0.7"},
            failed_targets=set(),
            output_dir=self.reports_dir,
        )
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report compare")
        out = console.file.getvalue()
        self.assertIn("engagement comparison", out)
        self.assertIn("Metric deltas", out)

    def test_report_compare_single_report_is_error_not_crash(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report compare")
        self.assertIn("No earlier report", console.file.getvalue())

    def test_report_html_writes_default_file(self):
        default_out = os.path.join(self.reports_dir, os.path.basename(self.json_path))
        default_out = default_out[: -len(".json")] + ".html"
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report html")
        self.assertIn("HTML report written", console.file.getvalue())
        self.assertTrue(os.path.isfile(default_out))

    def test_report_html_with_id_and_output(self):
        import re as _re

        rid = _re.search(r"audit_report_(\d{8}_\d{6})", self.json_path).group(1)
        out_path = os.path.join(self.reports_dir, "entrega.html")
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd(f"report html {rid} -o {out_path}")
        self.assertTrue(os.path.isfile(out_path))
        with open(out_path, encoding="utf-8") as fh:
            self.assertIn("<!DOCTYPE html>", fh.read(200))

    def test_unknown_subcommand_prints_usage(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report bogus")
        out = console.file.getvalue()
        self.assertIn("Unknown report subcommand", out)
        self.assertIn("Usage:", out)


class TestReportHtmlArgParsing(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(shell.InteractiveCLI._parse_report_html_args([]), (None, None))

    def test_id_only(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_html_args(["20260101"]), (None, "20260101")
        )

    def test_output_only(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_html_args(["-o", "out.html"]),
            ("out.html", None),
        )

    def test_id_then_output(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_html_args(["20260101", "-o", "out.html"]),
            ("out.html", "20260101"),
        )

    def test_output_then_id(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_html_args(["--output", "out.html", "2026"]),
            ("out.html", "2026"),
        )

    def test_output_without_path_raises(self):
        with self.assertRaises(ValueError):
            shell.InteractiveCLI._parse_report_html_args(["-o"])

    def test_two_ids_raise(self):
        with self.assertRaises(ValueError):
            shell.InteractiveCLI._parse_report_html_args(["a", "b"])


class TestReplErrorContainment(ShellReportTestBase):
    def test_hub_failure_never_crashes_the_loop(self):
        with mock.patch.object(report_cli, "compare_flow", side_effect=RuntimeError("boom")):
            console, patch = _capture_shell_console()
            with patch:
                self.repl.onecmd("report compare")  # must not raise
        self.assertIn("Report command failed", console.file.getvalue())

    def test_html_missing_output_path_prints_error_not_crash(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report html -o")
        self.assertIn("Report command failed", console.file.getvalue())


class TestHelpMentionsReportSubcommands(unittest.TestCase):
    def test_help_table_documents_report_usage(self):
        console = Console(file=io.StringIO(), force_terminal=False, width=120)
        calls = []
        repl = shell.InteractiveCLI(_fake_worm(calls))
        with mock.patch.object(shell, "console", console):
            repl.onecmd("help")
        out = console.file.getvalue()
        self.assertIn("report [new|list|show|compare|html]", out)


if __name__ == "__main__":
    unittest.main()
