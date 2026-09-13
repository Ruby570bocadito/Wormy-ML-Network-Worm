"""Tests for the round-5 REPL/UX polish (shell, reports, scanner, CLI).

User-reported issues fixed in this round:
- the REPL prompt rendered raw rich markup ("[dim]○ IDLE[/]...")
- the scan progress bar printed one line per host (spinner conflict)
- `wormy shell` drowned the terminal in ~90 engine INFO lines
- `exit` printed the whole final report twice + a negative duration
- `wormy --help` never showed how to launch the web dashboard

These tests pin each behaviour so it cannot regress.
"""

import io
import os
import sys
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

from rich.console import Console
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import professional_scanner
from worm_core import mixin_base, mixin_reporting, shell
from worm_core.cli import build_parser


def _fake_worm(**overrides):
    """A REPL-shaped worm: only what InteractiveCLI touches."""
    base = dict(
        infected_hosts=[],
        scan_results=[],
        failed_targets=[],
        running=False,
        stats={},
        print_final_report=lambda: None,
        shutdown=lambda: None,
        scan_network=lambda use_professional=True: [],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _plain_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=False, width=100)


def _ansi_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=True, width=100)


# ── prompt ─────────────────────────────────────────────────────────


class TestPromptRendering(unittest.TestCase):
    """cmd.Cmd writes the prompt through input()/stdout, so it must be a
    plain string (rich markup shows up literally otherwise)."""

    def _prompt(self, worm, console) -> str:
        with mock.patch.object(shell, "console", console):
            repl = shell.InteractiveCLI(worm)
            return repl.prompt

    def test_plain_prompt_has_no_raw_markup(self):
        p = self._prompt(_fake_worm(), _plain_console())
        self.assertNotIn("[dim]", p)
        self.assertNotIn("[bold", p)
        self.assertIn("○ IDLE", p)
        self.assertIn("wormy", p)

    def test_plain_prompt_shows_live_counts(self):
        worm = _fake_worm(infected_hosts=["10.0.0.1"], scan_results=[{"ip": "10.0.0.1"}])
        p = self._prompt(worm, _plain_console())
        self.assertIn("1 infected", p)
        self.assertIn("1 hosts", p)

    def test_terminal_prompt_uses_ansi_not_markup(self):
        p = self._prompt(_fake_worm(), _ansi_console())
        self.assertIn("\x1b[", p)  # real escape codes
        self.assertNotIn("[dim]", p)
        self.assertNotIn("[bold", p)
        self.assertIn("○ IDLE", p)

    def test_running_state_reflected(self):
        p = self._prompt(_fake_worm(running=True), _plain_console())
        self.assertIn("● RUNNING", p)
        self.assertNotIn("○ IDLE", p)


# ── help table ──────────────────────────────────────────────────────


class TestHelpTable(unittest.TestCase):
    def _render_help(self, console) -> str:
        with mock.patch.object(shell, "console", console):
            repl = shell.InteractiveCLI(_fake_worm())
            repl.do_help("")
            return console.file.getvalue()

    def test_usage_hints_survive(self):
        out = self._render_help(_plain_console())
        self.assertIn("pro|basic", out)
        self.assertIn("<ip>", out)
        self.assertIn("new|list|show|compare|html|prune", out)

    def test_all_core_commands_listed(self):
        out = self._render_help(_plain_console())
        for name in ("scan", "exploit", "report", "run", "exit", "status", "topo"):
            self.assertIn(name, out)

    def test_command_cell_two_tone(self):
        cell = shell.InteractiveCLI._command_cell("scan [pro|basic]")
        self.assertEqual(cell.plain, "scan [pro|basic]")
        # the command word is the base style, the hint span is dim italic
        self.assertEqual(cell.style, "bold cyan")
        self.assertEqual(len(cell.spans), 1)
        span = cell.spans[0]
        self.assertEqual((span.start, span.end), (4, len(cell.plain)))
        self.assertEqual(span.style, "dim italic")

    def test_command_cell_plain_word_only(self):
        cell = shell.InteractiveCLI._command_cell("exit")
        self.assertEqual(cell.plain, "exit")
        self.assertEqual(cell.style, "bold cyan")
        self.assertEqual(cell.spans, [])


# ── final report ────────────────────────────────────────────────────


def _reporting_worm(**overrides):
    base = dict(
        stats={
            "infections": 3,
            "failed_exploits": 1,
            "scans": 2,
            "total_hosts_discovered": 3,
            "vulnerabilities_found": 1,
            "exploit_chains_built": 1,
            "lateral_movements": 0,
            "lateral_success": 0,
            "brute_force_attempts": 0,
            "brute_force_successes": 0,
            "credentials_discovered": 0,
            "c2_beacons": 0,
            "polymorphic_mutations": 0,
        },
        start_time=datetime.now() - timedelta(seconds=95),
        infected_hosts=[f"10.0.0.{i}" for i in range(1, 11)],
        failed_targets=["10.0.0.99"],
        scan_results=[{"ip": "10.0.0.1"}],
        cred_manager=None,
        lateral_movement=None,
        knowledge_graph=None,
        polymorphic_engine=None,
        exploit_manager=None,
        audit_generator=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestFinalReport(unittest.TestCase):
    def _render(self, worm) -> str:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=100)
        with mock.patch.object(mixin_reporting, "_report_console", console):
            mixin_reporting.WormCoreReporting.print_final_report(worm)
        return buf.getvalue()

    def test_no_negative_duration_when_start_time_unset(self):
        worm = _reporting_worm()
        worm.stats.pop("start_time", None)
        worm.start_time = None
        out = self._render(worm)
        self.assertNotIn("-1 day", out)
        # normalized: end_time persisted and >= start_time
        self.assertLessEqual(worm.stats["start_time"], worm.stats["end_time"])

    def test_duration_humanized_from_engine_start_time(self):
        out = self._render(_reporting_worm())
        self.assertIn("1.6m", out)

    def test_duration_fmt_units(self):
        fmt = mixin_reporting._fmt_duration
        self.assertEqual(fmt(0.42), "0.42s")
        self.assertEqual(fmt(59.9), "59.90s")
        self.assertEqual(fmt(95.0), "1.6m")
        self.assertEqual(fmt(5400.0), "1.5h")

    def test_host_lists_truncated_with_overflow_note(self):
        out = self._render(_reporting_worm())
        self.assertIn("and 2 more", out)
        self.assertIn("10.0.0.99", out)

    def test_report_paths_footer(self):
        worm = _reporting_worm(
            audit_generator=SimpleNamespace(
                generate=lambda **kw: {
                    "json": "reports/audit_report_20260914_120000.json",
                    "csv": "reports/audit_report_20260914_120000.csv",
                }
            )
        )
        out = self._render(worm)
        self.assertIn("Reports written:", out)
        self.assertIn("audit_report_20260914_120000.json", out)

    def test_empty_session_has_no_subsection_noise(self):
        worm = _reporting_worm(
            infected_hosts=[], failed_targets=[], scan_results=[]
        )
        worm.stats.update(infections=0, failed_exploits=0)
        out = self._render(worm)
        # zero-value sub-sections must not print (section marker, not the
        # always-present "Lateral Movements" KPI row)
        self.assertNotIn("By technique", out)
        self.assertNotIn("CREDENTIAL INTELLIGENCE", out)
        self.assertNotIn("Infected Hosts", out)
        self.assertIn("Duration", out)

    def test_success_rate_only_when_attempts_exist(self):
        worm = _reporting_worm()
        worm.stats.update(infections=0, failed_exploits=0)
        self.assertNotIn("Success Rate", self._render(worm))
        worm.stats.update(infections=3, failed_exploits=1)
        self.assertIn("75.0%", self._render(worm))


# ── shutdown idempotency ────────────────────────────────────────────


class TestShutdownIdempotency(unittest.TestCase):
    class _Dummy(mixin_base.WormCoreBase, mixin_reporting.WormCoreReporting):
        """shutdown() (base) and print_final_report() (reporting) together,
        like the real WormCore composition."""

    def _instance(self, report_calls=None):
        from threading import Event

        inst = object.__new__(self._Dummy)
        inst.running = True
        inst.stop_event = Event()
        inst.config = SimpleNamespace(ml=SimpleNamespace(online_learning=False))
        inst._stoppable_components = []
        inst.mitre_mapper = None
        if report_calls is not None:
            inst.print_final_report = lambda: report_calls.append(1)
        return inst

    def test_final_report_printed_once_across_repeated_calls(self):
        calls = []
        inst = self._instance(report_calls=calls)
        inst.shutdown()
        inst.shutdown()
        inst.shutdown()
        self.assertEqual(len(calls), 1)

    def test_components_stopped_exactly_once(self):
        inst = self._instance(report_calls=[])
        stopped = []
        inst._stoppable_components = [SimpleNamespace(stop=lambda: stopped.append(1))]
        inst.shutdown()
        inst.shutdown()
        self.assertEqual(len(stopped), 1)


# ── quiet shell / logger level ──────────────────────────────────────


class TestConsoleLogLevel(unittest.TestCase):
    def test_set_console_level_silences_info_not_file(self):
        import logging

        from utils.logger import logger

        with mock.patch.object(logger._console_handler, "stream", io.StringIO()):
            logger.set_console_level(logging.WARNING)
            try:
                logger.info("should not appear on console")
                logger.warning("should appear")
            finally:
                logger.set_console_level(logging.INFO)
            out = logger._console_handler.stream.getvalue()
        self.assertNotIn("should not appear", out)
        self.assertIn("should appear", out)

    def test_shell_parser_has_verbose_flag(self):
        args = build_parser().parse_args(["shell"])
        self.assertFalse(args.verbose)
        args = build_parser().parse_args(["shell", "--verbose"])
        self.assertTrue(args.verbose)


class TestCmdShellQuietWiring(unittest.TestCase):
    """cmd_shell must mute the console before booting the engine (so the
    ~90 component-init INFO lines never hit the terminal) and restore
    default verbosity when the REPL exits."""

    def _args(self, verbose=False):
        return SimpleNamespace(
            config=None,
            profile=None,
            dry_run=True,
            target=None,
            max_infections=None,
            max_runtime=None,
            verbose=verbose,
        )

    def _run_cmd_shell(self, args):
        from worm_core import cli

        with (
            mock.patch("worm_core.WormCore") as wc,
            mock.patch("worm_core.shell.InteractiveCLI") as icli,
        ):
            worm = wc.return_value
            levels = []
            from utils.logger import logger

            real_set = logger.set_console_level

            def spy(level):
                levels.append(level)
                real_set(level)

            with mock.patch.object(logger, "set_console_level", side_effect=spy):
                rc = cli.cmd_shell(args)
        return rc, levels, icli

    def test_quiet_by_default_and_restored_on_exit(self):
        import logging

        rc, levels, _ = self._run_cmd_shell(self._args(verbose=False))
        self.assertEqual(rc, 0)
        self.assertIn(logging.WARNING, levels)
        self.assertEqual(levels[-1], logging.INFO)  # restored in finally

    def test_verbose_keeps_info_level(self):
        import logging

        rc, levels, _ = self._run_cmd_shell(self._args(verbose=True))
        self.assertEqual(rc, 0)
        self.assertNotIn(logging.WARNING, levels)
        self.assertEqual(levels[-1], logging.INFO)

    def test_missing_verbose_attribute_is_tolerated(self):
        # embedders/tests may build args without the new flag
        import logging

        args = self._args()
        del args.verbose
        rc, levels, _ = self._run_cmd_shell(args)
        self.assertEqual(rc, 0)
        self.assertIn(logging.WARNING, levels)


# ── CLI help: web dashboard example ─────────────────────────────────


class TestCliEpilogWebExample(unittest.TestCase):
    def test_root_help_mentions_web_dashboard(self):
        help_text = build_parser().format_help()
        self.assertIn("run --dry-run --web", help_text)
        self.assertIn("127.0.0.1:5000", help_text)

    def test_shell_help_mentions_verbose(self):
        parser = build_parser()
        sub = next(a for a in parser._subparsers._group_actions[0].choices.items()
                   if a[0] == "shell")[1]
        self.assertIn("--verbose", sub.format_help())


# ── scanner progress bar ────────────────────────────────────────────


class _FakeTty(io.StringIO):
    def isatty(self):
        return True


class TestScanProgressBar(unittest.TestCase):
    def _scanner(self):
        return object.__new__(professional_scanner.ProfessionalScanner)

    def test_tty_rewrites_single_line(self):
        scanner = self._scanner()
        tty = _FakeTty()
        with mock.patch.object(professional_scanner.sys, "stdout", tty):
            for i in range(1, 11):
                scanner._print_progress(i, 10, 0)
        written = tty.getvalue()
        self.assertNotIn("\n", written)  # one line, no newlines
        self.assertEqual(written.count("\r"), 10)  # every repaint resets the line
        self.assertIn("10/10", written)

    def test_pipe_prints_bounded_milestones_only(self):
        scanner = self._scanner()
        sink = io.StringIO()
        with mock.patch.object(professional_scanner.sys, "stdout", sink):
            for i in range(1, 101):
                scanner._print_progress(i, 100, 2)
        lines = [l for l in sink.getvalue().splitlines() if l.strip()]
        self.assertLessEqual(len(lines), 12)  # ~10% steps + final
        self.assertTrue(any("100/100" in l for l in lines))
        self.assertTrue(any("Found: 2" in l for l in lines))

    def test_bar_shape_advances(self):
        scanner = self._scanner()
        sink = _FakeTty()
        with mock.patch.object(professional_scanner.sys, "stdout", sink):
            scanner._print_progress(1, 10, 0)
            early = sink.getvalue()
            scanner._print_progress(10, 10, 0)
            late = sink.getvalue()
        self.assertGreater(late.count("█"), early.count("█"))
        self.assertIn("100.0%", late)


# ── REPL scan command (no spinner/progress conflict) ────────────────


class TestDoScanWithoutSpinner(unittest.TestCase):
    def test_do_scan_calls_worm_and_renders_hosts(self):
        calls = {}

        def fake_scan(use_professional=True):
            calls["use_pro"] = use_professional
            return [
                {
                    "ip": "10.0.0.5",
                    "os_guess": "Linux",
                    "open_ports": [22, 80],
                    "vulnerabilities": [],
                    "exploit_chain": [],
                }
            ]

        worm = _fake_worm(scan_network=fake_scan)
        console = _plain_console()
        with mock.patch.object(shell, "console", console):
            repl = shell.InteractiveCLI(worm)
            repl.do_scan("")
        out = console.file.getvalue()
        self.assertTrue(calls["use_pro"])
        self.assertIn("Scanning network", out)
        self.assertIn("10.0.0.5", out)
        self.assertIn("hosts discovered", out)

    def test_do_scan_basic_flag_propagates(self):
        calls = {}

        def fake_scan(use_professional=True):
            calls["use_pro"] = use_professional
            return []

        worm = _fake_worm(scan_network=fake_scan)
        with mock.patch.object(shell, "console", _plain_console()):
            repl = shell.InteractiveCLI(worm)
            repl.do_scan("basic")
        self.assertFalse(calls["use_pro"])

    def test_do_scan_empty_results_is_graceful(self):
        worm = _fake_worm(scan_network=lambda use_professional=True: [])
        console = _plain_console()
        with mock.patch.object(shell, "console", console):
            repl = shell.InteractiveCLI(worm)
            repl.do_scan("")
        self.assertIn("No hosts discovered", console.file.getvalue())


# ── REPL exit ───────────────────────────────────────────────────────


class TestExitCommand(unittest.TestCase):
    def test_exit_shuts_down_once_and_stops_loop(self):
        calls = []
        worm = _fake_worm(shutdown=lambda: calls.append(1))
        console = _plain_console()
        with mock.patch.object(shell, "console", console):
            repl = shell.InteractiveCLI(worm)
            stop = repl.do_exit("")
        self.assertTrue(stop)  # cmd.Cmd contract: True ends the loop
        self.assertEqual(len(calls), 1)
        self.assertIn("Exiting", console.file.getvalue())


if __name__ == "__main__":
    unittest.main()
