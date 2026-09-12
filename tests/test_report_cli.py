"""Tests for the report hub (worm_core/report_cli.py, `wormy report`).

Covers: discovery/chronological ordering, id resolution (latest /
timestamp / prefix / path), KPI summarization, list & show rendering,
--json output, HTML export (including XSS escaping of hostile report
data), and error exit codes for missing/corrupt reports.
"""

import io
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.audit_report import AuditReportGenerator
from worm_core import report_cli


def _capture(module_attr: str):
    """Replace report_cli.<module_attr> console with a recording one."""
    console = Console(file=io.StringIO(), force_terminal=False, width=120)
    return console, mock.patch.object(report_cli, module_attr, console)


def _make_stats(infections: int = 2, failures: int = 1, hosts: int = 3):
    start = datetime(2026, 9, 13, 14, 25, 0)
    return {
        "start_time": start,
        "end_time": start + timedelta(minutes=4),
        "scans": 3,
        "total_hosts_discovered": hosts,
        "vulnerabilities_found": 7,
        "exploit_chains_built": 2,
        "lateral_movements": 2,
        "lateral_success": 1,
        "brute_force_attempts": 5,
        "brute_force_successes": 2,
        "credentials_discovered": 4,
        "c2_beacons": 12,
        "polymorphic_mutations": 3,
        "infections": infections,
        "failed_exploits": failures,
    }


def _make_hosts():
    return [
        {
            "ip": "10.0.0.5",
            "os_guess": "Linux",
            "open_ports": [22, 8080],
            "vulnerability_score": 78,
            "services": {"22": "ssh"},
        },
        {
            "ip": "10.0.0.6",
            "os_guess": "Windows",
            "open_ports": [445, 3389],
            "vulnerability_score": 91,
            "services": {},
        },
        {
            "ip": "10.0.0.7",
            "os_guess": "Linux",
            "open_ports": [5432],
            "vulnerability_score": 55,
            "services": {},
        },
    ]


class ReportHubTestBase(unittest.TestCase):
    """Shared fixture: a temp reports dir with one real generated report."""

    def setUp(self):
        self.reports_dir = tempfile.mkdtemp(prefix="wormy_test_reports_")
        gen = AuditReportGenerator()
        self.files = gen.generate(
            worm_stats=_make_stats(),
            scan_results=_make_hosts(),
            infected_hosts={"10.0.0.5", "10.0.0.6"},
            failed_targets={"10.0.0.7"},
            output_dir=self.reports_dir,
        )
        self.json_path = self.files["json"]
        m = re.search(r"audit_report_(\d{8}_\d{6})", self.json_path)
        self.report_id = m.group(1)

    def tearDown(self):
        for name in os.listdir(self.reports_dir):
            os.remove(os.path.join(self.reports_dir, name))
        os.rmdir(self.reports_dir)


class TestDiscovery(ReportHubTestBase):
    def test_discover_finds_the_json_report(self):
        refs = report_cli.discover_reports(self.reports_dir)
        ids = [r["id"] for r in refs]
        self.assertIn(self.report_id, ids)
        self.assertTrue(all(r["path"].endswith(".json") for r in refs))

    def test_discover_is_chronological(self):
        # Synthetic second report with a controlled (later) id: the real
        # generator has second-granularity timestamps and would collide.
        data = report_cli.load_report(self.json_path)
        later = os.path.join(self.reports_dir, "audit_report_20991231_235959.json")
        with open(later, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        refs = report_cli.discover_reports(self.reports_dir)
        self.assertEqual(len(refs), 2)
        self.assertEqual(refs[0]["id"], self.report_id)
        self.assertEqual(refs[1]["id"], "20991231_235959")
        self.assertLessEqual(refs[0]["id"], refs[1]["id"])
        os.remove(later)

    def test_discover_ignores_non_report_json(self):
        with open(os.path.join(self.reports_dir, "final_report.json"), "w") as fh:
            fh.write("{}")
        refs = report_cli.discover_reports(self.reports_dir)
        ids = [r["id"] for r in refs]
        self.assertEqual(len(ids), 1)

    def test_resolve_latest(self):
        self.assertEqual(report_cli.resolve_report_path(self.reports_dir, "latest"), self.json_path)
        self.assertEqual(report_cli.resolve_report_path(self.reports_dir, ""), self.json_path)

    def test_resolve_by_timestamp_id(self):
        self.assertEqual(
            report_cli.resolve_report_path(self.reports_dir, self.report_id), self.json_path
        )

    def test_resolve_by_filename(self):
        self.assertEqual(
            report_cli.resolve_report_path(self.reports_dir, os.path.basename(self.json_path)),
            self.json_path,
        )

    def test_resolve_by_direct_path(self):
        self.assertEqual(
            report_cli.resolve_report_path(self.reports_dir, self.json_path), self.json_path
        )

    def test_resolve_unknown_id_returns_none(self):
        self.assertIsNone(report_cli.resolve_report_path(self.reports_dir, "19990101_000000"))

    def test_resolve_missing_dir_returns_none(self):
        self.assertIsNone(report_cli.resolve_report_path("/nonexistent-dir-xyz", "latest"))


class TestSummarize(ReportHubTestBase):
    def test_summary_kpis(self):
        data = report_cli.load_report(self.json_path)
        s = report_cli.summarize(data)
        self.assertEqual(s["hosts_discovered"], 3)
        self.assertEqual(s["infected"], 2)
        self.assertEqual(s["failed"], 1)
        self.assertEqual(s["success_rate"], "66.7%")
        self.assertEqual(s["duration"], "0:04:00")
        self.assertEqual(s["vulnerabilities"], 7)
        self.assertEqual(s["credentials"], 4)
        self.assertGreaterEqual(s["recommendations"], 1)

    def test_summarize_empty_report(self):
        s = report_cli.summarize({})
        self.assertEqual(s["infected"], 0)
        self.assertEqual(s["failed"], 0)
        self.assertEqual(s["success_rate"], "0.0%")


class TestRenderList(ReportHubTestBase):
    def test_list_renders_table_and_returns_rows(self):
        console, patcher = _capture("console")
        with patcher:
            rows = report_cli.render_list(self.reports_dir)
        out = console.file.getvalue()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], self.report_id)
        self.assertEqual(rows[0]["infected"], 2)
        self.assertIn("engagements", out)
        self.assertIn(self.report_id, out)

    def test_list_empty_dir_returns_empty(self):
        empty = tempfile.mkdtemp()
        console, patcher = _capture("console")
        with patcher:
            rows = report_cli.render_list(empty)
        self.assertEqual(rows, [])
        self.assertIn("No reports found", console.file.getvalue())
        os.rmdir(empty)


class TestRenderShow(ReportHubTestBase):
    def test_show_renders_kpis_and_recommendations(self):
        data = report_cli.load_report(self.json_path)
        console, patcher = _capture("console")
        with patcher:
            report_cli.render_show(data, self.json_path)
        out = console.file.getvalue()
        self.assertIn("engagement report", out)
        self.assertIn("Executive summary", out)
        self.assertIn("66.7%", out)
        self.assertIn("Infected hosts (2)", out)
        self.assertIn("10.0.0.5", out)
        self.assertIn("Failed targets (1)", out)
        self.assertIn("Recommendations", out)
        self.assertIn("HIGH", out)

    def test_show_without_infected_hosts(self):
        data = report_cli.load_report(self.json_path)
        data["infected_hosts"] = []
        console, patcher = _capture("console")
        with patcher:
            report_cli.render_show(data, self.json_path)
        self.assertIn("No infected hosts", console.file.getvalue())


class TestRenderHtml(ReportHubTestBase):
    def test_html_contains_kpis_and_escaped_data(self):
        data = report_cli.load_report(self.json_path)
        doc = report_cli.render_html(data, self.json_path)
        self.assertIn("Wormy engagement report", doc)
        self.assertIn("66.7%", doc)
        self.assertIn("10.0.0.5", doc)
        self.assertIn("badge HIGH", doc)
        self.assertNotIn("<script>alert", doc)

    def test_html_escapes_hostile_report_values(self):
        data = report_cli.load_report(self.json_path)
        data["scan_results"][0]["os_guess"] = "</td><script>alert(1)</script>"
        data["recommendations"][0]["category"] = '<img src=x onerror="steal()">'
        doc = report_cli.render_html(data, self.json_path)
        self.assertNotIn("<script>alert(1)</script>", doc)
        self.assertNotIn("<img src=x", doc)
        self.assertIn("&lt;script&gt;", doc)
        self.assertIn("&lt;img src=x", doc)

    def test_html_with_empty_report(self):
        doc = report_cli.render_html({}, None)
        self.assertIn("Wormy engagement report", doc)
        self.assertNotIn("<table><thead><tr><th>IP", doc)


class TestCmdReport(ReportHubTestBase):
    def _args(self, **kw):
        base = {
            "action": "list",
            "report_id": "latest",
            "reports_dir": self.reports_dir,
            "json": False,
            "output": None,
        }
        base.update(kw)
        return type("A", (), base)()

    def test_cmd_list_ok(self):
        console, patcher = _capture("console")
        with patcher:
            rc = report_cli.cmd_report(self._args())
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn(self.report_id, console.file.getvalue())

    def test_cmd_list_missing_dir_is_error(self):
        rc = report_cli.cmd_report(self._args(reports_dir="/nonexistent-xyz"))
        self.assertEqual(rc, report_cli.EXIT_ERROR)

    def test_cmd_show_ok(self):
        console, patcher = _capture("console")
        with patcher:
            rc = report_cli.cmd_report(self._args(action="show"))
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn("Executive summary", console.file.getvalue())

    def test_cmd_show_missing_report_is_error(self):
        rc = report_cli.cmd_report(self._args(action="show", report_id="19990101_000000"))
        self.assertEqual(rc, report_cli.EXIT_ERROR)

    def test_cmd_show_corrupt_report_is_error(self):
        corrupt = os.path.join(self.reports_dir, "audit_report_19990101_000000.json")
        with open(corrupt, "w") as fh:
            fh.write("{not json")
        rc = report_cli.cmd_report(self._args(action="show", report_id="19990101_000000"))
        self.assertEqual(rc, report_cli.EXIT_ERROR)
        os.remove(corrupt)

    def test_cmd_show_json_prints_valid_payload(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = report_cli.cmd_report(self._args(action="show", json=True))
        self.assertEqual(rc, report_cli.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertIn("executive_summary", payload)

    def test_cmd_list_json_prints_valid_payload(self):
        console, patcher = _capture("console")
        with patcher, mock.patch("sys.stdout", io.StringIO()) as buf:
            rc = report_cli.cmd_report(self._args(json=True))
        self.assertEqual(rc, report_cli.EXIT_OK)

    def test_cmd_html_writes_file(self):
        out = os.path.join(self.reports_dir, "export.html")
        console, patcher = _capture("console")
        with patcher:
            rc = report_cli.cmd_report(self._args(action="html", output=out))
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertTrue(os.path.isfile(out))
        content = open(out, encoding="utf-8").read()
        self.assertIn("Wormy engagement report", content)
        self.assertIn("HTML report written", console.file.getvalue())

    def test_cmd_html_default_output_name(self):
        args = self._args(action="html", output=None)
        console, patcher = _capture("console")
        with patcher:
            rc = report_cli.cmd_report(args)
        self.assertEqual(rc, report_cli.EXIT_OK)
        expected = f"audit_report_{self.report_id}.html"
        self.assertTrue(os.path.isfile(os.path.join(self.reports_dir, expected)))

    def test_cmd_html_escapes_hostile_data(self):
        data = report_cli.load_report(self.json_path)
        data["scan_results"][0]["os_guess"] = "<script>alert(1)</script>"
        out = os.path.join(self.reports_dir, "x.html")
        with open(self.json_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        console, patcher = _capture("console")
        with patcher:
            rc = report_cli.cmd_report(self._args(action="html", output=out))
        self.assertEqual(rc, report_cli.EXIT_OK)
        content = open(out, encoding="utf-8").read()
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_cmd_unknown_action_is_usage_error(self):
        rc = report_cli.cmd_report(self._args(action="explode"))
        self.assertEqual(rc, report_cli.EXIT_USAGE)


class TestReportsDirResolution(unittest.TestCase):
    def test_explicit_flag_wins_even_when_missing(self):
        # Deterministic: user input beats any heuristic, even if the dir
        # does not exist (error messages then point where the user asked).
        self.assertEqual(report_cli.resolve_reports_dir("/custom/missing"), "/custom/missing")

    def test_env_var_used_when_no_flag(self):
        with mock.patch.dict(os.environ, {report_cli.REPORTS_DIR_ENV: "/env/reports"}):
            self.assertEqual(report_cli.resolve_reports_dir(None), "/env/reports")

    def test_flag_beats_env(self):
        with mock.patch.dict(os.environ, {report_cli.REPORTS_DIR_ENV: "/env/reports"}):
            self.assertEqual(report_cli.resolve_reports_dir("/flag/reports"), "/flag/reports")

    def test_cwd_reports_preferred_over_repo_root(self):
        with mock.patch.object(report_cli, "_repo_root", return_value="/repo"):
            with mock.patch("os.path.isdir", side_effect=lambda p: p == "reports"):
                self.assertEqual(report_cli.resolve_reports_dir(None), "reports")

    def test_repo_root_used_when_cwd_has_none(self):
        with mock.patch.object(report_cli, "_repo_root", return_value="/repo"):
            with mock.patch(
                "os.path.isdir", side_effect=lambda p: p == os.path.join("/repo", "reports")
            ):
                self.assertEqual(
                    report_cli.resolve_reports_dir(None), os.path.join("/repo", "reports")
                )

    def test_falls_back_to_default_when_nothing_exists(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(report_cli.REPORTS_DIR_ENV, None)
            with mock.patch.object(report_cli, "_repo_root", return_value=None):
                with mock.patch("os.path.isdir", return_value=False):
                    self.assertEqual(
                        report_cli.resolve_reports_dir(None), report_cli.DEFAULT_REPORTS_DIR
                    )


if __name__ == "__main__":
    unittest.main()
