"""Tests for the report hub (worm_core/report_cli.py, `wormy report`).

Covers: discovery/chronological ordering, id resolution (latest /
timestamp / prefix / path), KPI summarization, list & show rendering,
--json output, HTML export (including XSS escaping of hostile report
data), and error exit codes for missing/corrupt reports.
"""

import argparse
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

    def test_report_id_from_valid_path(self):
        self.assertEqual(report_cli._report_id_from_path(self.json_path), self.report_id)

    def test_report_id_from_full_path_uses_basename(self):
        prefixed = os.path.join("/elsewhere", f"audit_report_{self.report_id}.json")
        self.assertEqual(report_cli._report_id_from_path(prefixed), self.report_id)

    def test_report_id_from_non_report_path_is_none(self):
        self.assertIsNone(report_cli._report_id_from_path("/tmp/final_report.json"))
        self.assertIsNone(report_cli._report_id_from_path("audit_report.json"))
        self.assertIsNone(report_cli._report_id_from_path(None))
        self.assertIsNone(report_cli._report_id_from_path(""))

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


class CompareFixtureBase(unittest.TestCase):
    """Two engagements with distinct forced ids: a weak baseline, a strong candidate."""

    ID_A = "20260101_090000"  # baseline (older)
    ID_B = "20260102_100000"  # candidate (newer)

    def setUp(self):
        self.reports_dir = tempfile.mkdtemp(prefix="wormy_test_compare_")
        gen = AuditReportGenerator()
        files_a = gen.generate(
            worm_stats=_make_stats(infections=1, failures=3, hosts=5),
            scan_results=_make_hosts(),
            infected_hosts={"10.0.0.5"},
            failed_targets={"10.0.0.6", "10.0.0.7"},
            output_dir=self.reports_dir,
        )
        os.replace(
            files_a["json"], os.path.join(self.reports_dir, f"audit_report_{self.ID_A}.json")
        )
        files_b = gen.generate(
            worm_stats=_make_stats(infections=3, failures=0, hosts=7),
            scan_results=_make_hosts(),
            infected_hosts={"10.0.0.5", "10.0.0.6", "10.0.0.7"},
            failed_targets=set(),
            output_dir=self.reports_dir,
        )
        os.replace(
            files_b["json"], os.path.join(self.reports_dir, f"audit_report_{self.ID_B}.json")
        )

    def tearDown(self):
        for name in os.listdir(self.reports_dir):
            os.remove(os.path.join(self.reports_dir, name))
        os.rmdir(self.reports_dir)


class TestDurationAndRateParsing(unittest.TestCase):
    def test_parse_timedelta_string(self):
        self.assertAlmostEqual(report_cli._parse_duration("0:00:02.044012"), 2.044012)

    def test_parse_timedelta_with_days(self):
        self.assertAlmostEqual(report_cli._parse_duration("1 day, 0:00:02"), 86402)

    def test_parse_plain_seconds(self):
        self.assertAlmostEqual(report_cli._parse_duration("45.2"), 45.2)

    def test_parse_na_returns_none(self):
        self.assertIsNone(report_cli._parse_duration("N/A"))
        self.assertIsNone(report_cli._parse_duration(None))
        self.assertIsNone(report_cli._parse_duration(""))

    def test_parse_garbage_returns_none(self):
        self.assertIsNone(report_cli._parse_duration("soon"))
        self.assertIsNone(report_cli._parse_duration("a:b:c"))

    def test_parse_rate(self):
        self.assertAlmostEqual(report_cli._parse_rate("12.5%"), 12.5)
        self.assertIsNone(report_cli._parse_rate("n/a"))


class TestCompareMetrics(CompareFixtureBase):
    def _rows(self):
        a = report_cli.load_report(os.path.join(self.reports_dir, f"audit_report_{self.ID_A}.json"))
        b = report_cli.load_report(os.path.join(self.reports_dir, f"audit_report_{self.ID_B}.json"))
        return report_cli.compare_metrics(a, b)

    def test_model_covers_all_ten_metrics(self):
        self.assertEqual(len(self._rows()), len(report_cli._METRICS))

    def test_infected_up_is_better(self):
        row = next(r for r in self._rows() if r["metric"] == "Infected")
        self.assertEqual(row["baseline"], 1)
        self.assertEqual(row["candidate"], 3)
        self.assertEqual(row["delta"], 2)
        self.assertEqual(row["trend"], "better")

    def test_failed_down_is_better(self):
        row = next(r for r in self._rows() if r["metric"] == "Failed")
        self.assertEqual(row["candidate"], 0)
        self.assertEqual(row["delta"], -2)
        self.assertEqual(row["trend"], "better")

    def test_success_rate_delta_in_points(self):
        row = next(r for r in self._rows() if r["metric"] == "Success rate")
        self.assertEqual(row["trend"], "better")
        # A: 1/3 attempts = 33.3% · B: 3/3 = 100% → +66.7 points
        self.assertAlmostEqual(row["delta"], 66.7, places=1)

    def test_equal_metric_is_neutral(self):
        row = next(r for r in self._rows() if r["metric"] == "Scans")
        self.assertEqual(row["delta"], 0)
        self.assertEqual(row["trend"], "neutral")

    def test_unknown_duration_is_neutral_without_delta(self):
        row = next(r for r in self._rows() if r["metric"] == "Duration")
        # both fixtures carry start/end times → numeric comparison
        self.assertIsNotNone(row["delta"])
        self.assertEqual(row["trend"], "neutral")

    def test_half_unknown_duration_degrades_gracefully(self):
        data_a = {"executive_summary": {}, "worm_statistics": {}, "report_metadata": {}}
        data_b = report_cli.load_report(
            os.path.join(self.reports_dir, f"audit_report_{self.ID_B}.json")
        )
        rows = report_cli.compare_metrics(data_a, data_b)
        row = next(r for r in rows if r["metric"] == "Duration")
        self.assertIsNone(row["delta"])
        self.assertEqual(row["trend"], "neutral")


class TestCompareFlow(CompareFixtureBase):
    def test_default_compares_last_two(self):
        _, patch = _capture("console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, None, None)
        self.assertEqual(rc, report_cli.EXIT_OK)

    def test_single_id_uses_its_predecessor(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, self.ID_B, None)
        self.assertEqual(rc, report_cli.EXIT_OK)
        out = console.file.getvalue()
        self.assertIn(self.ID_A, out)  # baseline = predecessor of B
        self.assertIn(self.ID_B, out)

    def test_two_ids_any_order_older_is_baseline(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, self.ID_B, self.ID_A)
        self.assertEqual(rc, report_cli.EXIT_OK)
        out = console.file.getvalue()
        self.assertIn("baseline  20260101_090000", out)
        self.assertIn("candidate 20260102_100000", out)

    def test_same_report_twice_is_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, self.ID_A, self.ID_A)
        self.assertEqual(rc, report_cli.EXIT_ERROR)

    def test_unknown_id_is_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, "19990101_000000", self.ID_B)
        self.assertEqual(rc, report_cli.EXIT_ERROR)

    def test_oldest_without_predecessor_is_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, self.ID_A, None)
        self.assertEqual(rc, report_cli.EXIT_ERROR)

    def test_prefix_ids_resolve(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, "20260101", "20260102")
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn(self.ID_A, console.file.getvalue())

    def test_json_output_structure(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = report_cli.compare_flow(self.reports_dir, None, None, as_json=True)
        self.assertEqual(rc, report_cli.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["baseline"]["id"], self.ID_A)
        self.assertEqual(payload["candidate"]["id"], self.ID_B)
        self.assertEqual(len(payload["metrics"]), len(report_cli._METRICS))
        infected = next(m for m in payload["metrics"] if m["metric"] == "Infected")
        self.assertEqual(infected["delta"], 2)
        self.assertEqual(infected["trend"], "better")

    def test_corrupt_report_is_error(self):
        with open(os.path.join(self.reports_dir, f"audit_report_{self.ID_A}.json"), "w") as fh:
            fh.write("{broken json")
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, self.ID_A, self.ID_B)
        self.assertEqual(rc, report_cli.EXIT_ERROR)


class TestCmdReportCompare(CompareFixtureBase):
    def _args(self, **kw):
        base = {
            "action": "compare",
            "report_id": "latest",
            "report_id2": None,
            "reports_dir": self.reports_dir,
            "json": False,
            "output": None,
        }
        base.update(kw)
        return argparse.Namespace(**base)

    def test_cmd_compare_ok(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.cmd_report(self._args())
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn("engagement comparison", console.file.getvalue())

    def test_cmd_compare_json(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = report_cli.cmd_report(self._args(json=True))
        self.assertEqual(rc, report_cli.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertIn("metrics", payload)

    def test_cmd_compare_explicit_pair(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.cmd_report(self._args(report_id=self.ID_A, report_id2=self.ID_B))
        self.assertEqual(rc, report_cli.EXIT_OK)
        out = console.file.getvalue()
        self.assertIn("baseline  20260101_090000", out)

    def test_cmd_compare_missing_dir_is_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.cmd_report(self._args(reports_dir="/nonexistent/xx"))
        self.assertEqual(rc, report_cli.EXIT_ERROR)


# ─────────────────── prune (retention policy) ────────────────────


def _seed_engagements(reports_dir: str, ids: list[str]) -> None:
    """Seed N engagements with forced ids, each with json+csv+txt siblings.

    One real generation, then copies — fast and immune to the known
    second-granularity filename collision (reported to Bugs).
    """
    gen = AuditReportGenerator()
    files = gen.generate(
        worm_stats=_make_stats(),
        scan_results=_make_hosts(),
        infected_hosts={"10.0.0.5"},
        failed_targets={"10.0.0.6"},
        output_dir=reports_dir,
    )
    for ext, key in (("json", "json"), ("csv", "csv"), ("txt", "text")):
        src = files[key]
        for rid in ids:
            dst = os.path.join(reports_dir, f"audit_report_{rid}.{ext}")
            if os.path.abspath(src) == os.path.abspath(dst):
                continue
            with open(src, "rb") as fh_in, open(dst, "wb") as fh_out:
                fh_out.write(fh_in.read())
    # drop the original (collision-prone) files, keep only forced ids
    for path in files.values():
        if all(
            os.path.basename(path) != f"audit_report_{rid}.{os.path.splitext(path)[1][1:]}"
            for rid in ids
        ):
            os.remove(path)


class PruneFixtureBase(unittest.TestCase):
    """Five engagements: 20260101_000000 .. 20260105_000000 (oldest first)."""

    IDS = [f"2026010{i}_000000" for i in range(1, 6)]

    def setUp(self):
        self.reports_dir = tempfile.mkdtemp(prefix="wormy_test_prune_")
        _seed_engagements(self.reports_dir, self.IDS)

    def tearDown(self):
        for name in os.listdir(self.reports_dir):
            os.remove(os.path.join(self.reports_dir, name))
        os.rmdir(self.reports_dir)

    def _ids_left(self) -> list[str]:
        return [r["id"] for r in report_cli.discover_reports(self.reports_dir)]


class TestPruneValidation(PruneFixtureBase):
    def test_keep_zero_is_usage_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.prune_flow(self.reports_dir, keep=0, assume_yes=True)
        self.assertEqual(rc, report_cli.EXIT_USAGE)

    def test_keep_negative_is_usage_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.prune_flow(self.reports_dir, keep=-3, assume_yes=True)
        self.assertEqual(rc, report_cli.EXIT_USAGE)

    def test_json_without_yes_is_usage_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.prune_flow(self.reports_dir, keep=2, as_json=True)
        self.assertEqual(rc, report_cli.EXIT_USAGE)

    def test_missing_dir_is_error(self):
        _, patch = _capture("err_console")
        with patch:
            rc = report_cli.prune_flow("/nonexistent/xx", keep=2, assume_yes=True)
        self.assertEqual(rc, report_cli.EXIT_ERROR)


class TestPruneFlow(PruneFixtureBase):
    def test_nothing_to_prune_when_fewer_than_keep(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.prune_flow(self.reports_dir, keep=10, assume_yes=True)
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn("Nothing to prune", console.file.getvalue())
        self.assertEqual(len(self._ids_left()), 5)

    def test_empty_dir_is_ok_nothing_to_prune(self):
        empty = tempfile.mkdtemp(prefix="wormy_test_prune_empty_")
        try:
            console, patch = _capture("console")
            with patch:
                rc = report_cli.prune_flow(empty, keep=5, assume_yes=True)
            self.assertEqual(rc, report_cli.EXIT_OK)
            self.assertIn("nothing to prune", console.file.getvalue())
        finally:
            os.rmdir(empty)

    def test_dry_run_deletes_nothing(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.prune_flow(self.reports_dir, keep=3, assume_yes=True, dry_run=True)
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn("dry-run", console.file.getvalue())
        self.assertIn("Nothing was touched", console.file.getvalue())
        self.assertEqual(len(self._ids_left()), 5)

    def test_confirmed_prune_removes_oldest_and_siblings(self):
        rc = report_cli.prune_flow(
            self.reports_dir, keep=3, assume_yes=True, confirm=lambda q: True
        )
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertEqual(self._ids_left(), self.IDS[2:])  # newest 3 kept
        # every sibling file of the pruned ids is gone
        for rid in self.IDS[:2]:
            for ext in ("json", "csv", "txt"):
                self.assertFalse(
                    os.path.exists(os.path.join(self.reports_dir, f"audit_report_{rid}.{ext}"))
                )

    def test_declined_confirmation_keeps_everything(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.prune_flow(self.reports_dir, keep=3, confirm=lambda q: False)
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertIn("Aborted", console.file.getvalue())
        self.assertEqual(len(self._ids_left()), 5)

    def test_yes_skips_the_prompt_entirely(self):
        def fail(q):
            raise AssertionError("prompt must not be called with --yes")

        rc = report_cli.prune_flow(self.reports_dir, keep=4, assume_yes=True, confirm=fail)
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertEqual(len(self._ids_left()), 4)

    def test_prune_plan_preview_lists_dropped_ids(self):
        console, patch = _capture("console")
        with patch:
            # decline via confirm so nothing is actually deleted
            report_cli.prune_flow(self.reports_dir, keep=3, confirm=lambda q: False)
        out = console.file.getvalue()
        self.assertIn("Prune plan", out)
        for rid in self.IDS[:2]:
            self.assertIn(rid, out)

    def test_json_output_structure(self):
        import contextlib
        import io as _io

        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = report_cli.prune_flow(self.reports_dir, keep=4, assume_yes=True, as_json=True)
        self.assertEqual(rc, report_cli.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["pruned"], self.IDS[:1])
        self.assertEqual(payload["kept"], self.IDS[1:])
        self.assertEqual(payload["errors"], [])
        self.assertTrue(
            any(
                name.startswith("audit_report_20260101_000000") for name in payload["deleted_files"]
            )
        )

    def test_deletion_failure_is_reported_as_error(self):
        with mock.patch.object(report_cli.os, "remove", side_effect=OSError("locked")):
            _, patch = _capture("err_console")
            with patch:
                rc = report_cli.prune_flow(
                    self.reports_dir, keep=3, assume_yes=True, confirm=lambda q: True
                )
        self.assertEqual(rc, report_cli.EXIT_ERROR)


class TestPruneCmdReport(unittest.TestCase):
    def _args(self, **kw):
        base = {
            "action": "prune",
            "reports_dir": None,
            "keep": None,
            "yes": False,
            "dry_run": False,
            "json": False,
            "report_id": "latest",
            "report_id2": None,
            "output": None,
            "metrics": None,
        }
        base.update(kw)
        return argparse.Namespace(**base)

    def test_cmd_report_defaults_keep_to_20(self):
        with mock.patch.object(report_cli, "prune_flow", return_value=report_cli.EXIT_OK) as flow:
            rc = report_cli.cmd_report(self._args())
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertEqual(flow.call_args.kwargs["keep"], report_cli.PRUNE_DEFAULT_KEEP)

    def test_cmd_report_forwards_explicit_keep(self):
        with mock.patch.object(report_cli, "prune_flow", return_value=report_cli.EXIT_OK) as flow:
            rc = report_cli.cmd_report(self._args(keep=2, yes=True, dry_run=True))
        self.assertEqual(rc, report_cli.EXIT_OK)
        self.assertEqual(flow.call_args.kwargs["keep"], 2)
        self.assertTrue(flow.call_args.kwargs["assume_yes"])
        self.assertTrue(flow.call_args.kwargs["dry_run"])

    def test_cmd_report_keep_zero_stays_zero_not_default(self):
        # explicit --keep 0 must reach validation, not be replaced by 20
        with mock.patch.object(
            report_cli, "prune_flow", return_value=report_cli.EXIT_USAGE
        ) as flow:
            rc = report_cli.cmd_report(self._args(keep=0))
        self.assertEqual(rc, report_cli.EXIT_USAGE)
        self.assertEqual(flow.call_args.kwargs["keep"], 0)


# ─────────────────── compare --metrics filter ────────────────────


class TestFilterMetricRows(CompareFixtureBase):
    def _rows(self):
        data_a = report_cli.load_report(
            os.path.join(self.reports_dir, f"audit_report_{self.ID_A}.json")
        )
        data_b = report_cli.load_report(
            os.path.join(self.reports_dir, f"audit_report_{self.ID_B}.json")
        )
        return report_cli.compare_metrics(data_a, data_b)

    def test_filter_by_machine_key(self):
        picked, unknown = report_cli._filter_metric_rows(self._rows(), "infected")
        self.assertEqual(unknown, [])
        self.assertEqual([r["key"] for r in picked], ["infected"])

    def test_filter_by_human_label_case_insensitive(self):
        picked, unknown = report_cli._filter_metric_rows(self._rows(), "Success Rate")
        self.assertEqual(unknown, [])
        self.assertEqual([r["key"] for r in picked], ["success_rate"])

    def test_filter_mixed_keys_and_labels(self):
        picked, unknown = report_cli._filter_metric_rows(
            self._rows(), "infected, Success rate ,failed"
        )
        self.assertEqual(unknown, [])
        self.assertEqual([r["key"] for r in picked], ["infected", "success_rate", "failed"])

    def test_unknown_metric_is_reported(self):
        picked, unknown = report_cli._filter_metric_rows(self._rows(), "infected,bogus")
        self.assertEqual(unknown, ["bogus"])

    def test_blank_entries_are_ignored(self):
        picked, unknown = report_cli._filter_metric_rows(self._rows(), "infected,, ")
        self.assertEqual(unknown, [])
        self.assertEqual(len(picked), 1)


class TestCompareMetricsFilter(CompareFixtureBase):
    def test_flow_renders_only_requested_metrics(self):
        console, patch = _capture("console")
        with patch:
            rc = report_cli.compare_flow(
                self.reports_dir, None, None, metrics="infected,success_rate"
            )
        self.assertEqual(rc, report_cli.EXIT_OK)
        out = console.file.getvalue()
        self.assertIn("Infected", out)
        self.assertIn("Success rate", out)
        self.assertNotIn("Credentials discovered", out)

    def test_flow_json_respects_the_filter(self):
        import contextlib
        import io as _io

        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = report_cli.compare_flow(
                self.reports_dir, None, None, as_json=True, metrics="infected"
            )
        self.assertEqual(rc, report_cli.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertEqual([m["key"] for m in payload["metrics"]], ["infected"])

    def test_flow_unknown_metric_is_usage_error_listing_valid(self):
        console, patch = _capture("err_console")
        with patch:
            rc = report_cli.compare_flow(self.reports_dir, None, None, metrics="bogus")
        self.assertEqual(rc, report_cli.EXIT_USAGE)
        out = console.file.getvalue()
        self.assertIn("bogus", out)
        self.assertIn("success_rate", out)

    def test_rows_carry_the_key_field(self):
        data_a = report_cli.load_report(
            os.path.join(self.reports_dir, f"audit_report_{self.ID_A}.json")
        )
        data_b = report_cli.load_report(
            os.path.join(self.reports_dir, f"audit_report_{self.ID_B}.json")
        )
        rows = report_cli.compare_metrics(data_a, data_b)
        self.assertEqual(rows[0]["key"], "hosts_discovered")
        self.assertEqual(rows[0]["metric"], "Hosts discovered")


if __name__ == "__main__":
    unittest.main()
