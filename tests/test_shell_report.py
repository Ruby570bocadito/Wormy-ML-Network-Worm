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


class TestReportCompareArgParsing(unittest.TestCase):
    def test_no_tokens(self):
        self.assertEqual(shell.InteractiveCLI._parse_report_compare_args([]), (None, None, None))

    def test_single_id(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_compare_args(["20260101"]),
            ("20260101", None, None),
        )

    def test_two_ids(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_compare_args(["a", "b"]),
            ("a", "b", None),
        )

    def test_short_metrics_flag(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_compare_args(["-m", "infected"]),
            (None, None, "infected"),
        )

    def test_long_metrics_flag_with_ids(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_compare_args(
                ["20260101", "20260102", "--metrics", "infected,failed"]
            ),
            ("20260101", "20260102", "infected,failed"),
        )

    def test_metrics_without_value_raises(self):
        with self.assertRaises(ValueError):
            shell.InteractiveCLI._parse_report_compare_args(["--metrics"])

    def test_three_ids_raise(self):
        with self.assertRaises(ValueError):
            shell.InteractiveCLI._parse_report_compare_args(["a", "b", "c"])


class TestReportPruneArgParsing(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(shell.InteractiveCLI._parse_report_prune_args([]), (None, False, False))

    def test_bare_number(self):
        self.assertEqual(shell.InteractiveCLI._parse_report_prune_args(["5"]), (5, False, False))

    def test_keep_flag(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_prune_args(["--keep", "5"]),
            (5, False, False),
        )

    def test_short_keep_flag(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_prune_args(["-k", "7"]), (7, False, False)
        )

    def test_yes_and_dry_run(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_prune_args(["3", "--yes", "--dry-run"]),
            (3, True, True),
        )

    def test_short_yes(self):
        self.assertEqual(shell.InteractiveCLI._parse_report_prune_args(["-y"]), (None, True, False))

    def test_keep_without_number_raises(self):
        with self.assertRaises(ValueError):
            shell.InteractiveCLI._parse_report_prune_args(["--keep"])

    def test_garbage_token_raises(self):
        with self.assertRaises(ValueError):
            shell.InteractiveCLI._parse_report_prune_args(["banana"])

    def test_negative_number_is_forwarded_not_crash(self):
        # hub validates it (usage error message) — parsing must not explode
        self.assertEqual(
            shell.InteractiveCLI._parse_report_prune_args(["-2"]),
            (-2, False, False),
        )


class TestReportPruneInRepl(ShellReportTestBase):
    """Two engagements; prune keeps the newest one."""

    def _seed_second_report(self):
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

    def test_prune_dry_run_deletes_nothing(self):
        self._seed_second_report()
        before = sorted(os.listdir(self.reports_dir))
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report prune 1 --dry-run")
        out = console.file.getvalue()
        self.assertIn("dry-run", out)
        self.assertIn("Nothing was touched", out)
        self.assertEqual(sorted(os.listdir(self.reports_dir)), before)

    def test_prune_with_yes_deletes_oldest(self):
        self._seed_second_report()
        ids = [r["id"] for r in report_cli.discover_reports(self.reports_dir)]
        self.assertEqual(len(ids), 2)
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report prune 1 --yes")
        out = console.file.getvalue()
        self.assertIn("Deleted", out)
        remaining = [r["id"] for r in report_cli.discover_reports(self.reports_dir)]
        self.assertEqual(remaining, [ids[-1]])  # newest survives
        self.assertFalse(
            os.path.exists(os.path.join(self.reports_dir, f"audit_report_{ids[0]}.json"))
        )

    def test_prune_declined_keeps_everything(self):
        self._seed_second_report()
        before = sorted(os.listdir(self.reports_dir))
        with mock.patch("builtins.input", return_value="n"):
            console, patch = _capture_shell_console()
            with patch:
                self.repl.onecmd("report prune 1")
        self.assertIn("Aborted", console.file.getvalue())
        self.assertEqual(sorted(os.listdir(self.reports_dir)), before)

    def test_prune_confirmed_via_prompt_deletes(self):
        self._seed_second_report()
        ids = [r["id"] for r in report_cli.discover_reports(self.reports_dir)]
        with mock.patch("builtins.input", return_value="y"):
            console, patch = _capture_shell_console()
            with patch:
                self.repl.onecmd("report prune 1")
        self.assertIn("Deleted", console.file.getvalue())
        remaining = [r["id"] for r in report_cli.discover_reports(self.reports_dir)]
        self.assertEqual(remaining, [ids[-1]])

    def test_prune_bad_token_prints_error_not_crash(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report prune banana")
        self.assertIn("Report command failed", console.file.getvalue())

    def test_prune_nothing_to_do_is_friendly(self):
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report prune 5 --yes")
        self.assertIn("Nothing to prune", console.file.getvalue())


class TestReportCompareMetricsInRepl(ShellReportTestBase):
    def _seed_pair(self):
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

    def test_compare_metrics_renders_only_requested(self):
        self._seed_pair()
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report compare --metrics infected,success_rate")
        out = console.file.getvalue()
        self.assertIn("engagement comparison", out)
        self.assertIn("Infected", out)
        self.assertIn("Success rate", out)
        self.assertNotIn("Credentials discovered", out)

    def test_compare_unknown_metric_prints_error_not_crash(self):
        self._seed_pair()
        console, patch = _capture_shell_console()
        with patch:
            self.repl.onecmd("report compare --metrics bogus")
        self.assertIn("Unknown metric", console.file.getvalue())


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
        self.assertIn("report [new|list|show|compare|html|prune]", out)


if __name__ == "__main__":
    unittest.main()


class TestSplitReportTokens(unittest.TestCase):
    """The shared `flag VALUE` tokenizer behind the html/compare parsers."""

    SPEC = {"output": (("-o", "--output"), "-o/--output needs a file path")}

    def test_positionals_keep_typed_order(self):
        ids, flags = shell._split_report_tokens(["a", "-o", "f.html", "b"], self.SPEC)
        self.assertEqual(ids, ["a", "b"])
        self.assertEqual(flags, {"output": "f.html"})

    def test_repeated_flag_last_value_wins_across_aliases(self):
        ids, flags = shell._split_report_tokens(
            ["--output", "first.html", "-o", "second.html"], self.SPEC
        )
        self.assertEqual(ids, [])
        self.assertEqual(flags, {"output": "second.html"})

    def test_flag_as_last_token_raises(self):
        with self.assertRaises(ValueError) as ctx:
            shell._split_report_tokens(["id", "--output"], self.SPEC)
        self.assertIn("file path", str(ctx.exception))

    def test_empty_tokens(self):
        self.assertEqual(shell._split_report_tokens([], self.SPEC), ([], {}))

    def test_unknown_tokens_are_positionals(self):
        ids, flags = shell._split_report_tokens(["-x", "id"], self.SPEC)
        self.assertEqual(ids, ["-x", "id"])
        self.assertEqual(flags, {})


class TestReportHtmlParsingAliases(unittest.TestCase):
    def test_mixed_alias_spellings_last_wins(self):
        self.assertEqual(
            shell.InteractiveCLI._parse_report_html_args(
                ["--output", "first.html", "-o", "second.html"]
            ),
            ("second.html", None),
        )
