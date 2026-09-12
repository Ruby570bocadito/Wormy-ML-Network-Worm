"""
Wormy — post-engagement report hub (``wormy report``).

The engine (``wormy run`` and the REPL ``report`` command) writes
timestamped audit reports — ``reports/audit_report_<ts>.json|csv|txt`` —
at the end of every engagement. Until now the only way to consume those
artifacts was opening the raw files by hand. This module adds four
read-only operations on top of that directory:

    list    engagement inventory (date, hosts, infections, success rate)
    show    terminal rendering of one report (summary, hosts, findings)
    html    standalone self-contained HTML export for sharing/delivering
    compare side-by-side comparison of two engagements with deltas

plus exactly one mutating operation:

    prune   retention policy: keep the newest N engagements, delete the
            rest (always previewed, confirmed unless ``--yes``)

Reports are never modified or deleted by any other operation — everything
except ``prune`` is a pure consumer of the audit trail, and ``prune``
only removes whole engagement file sets (``audit_report_<id>.*``) after
an explicit confirmation. Resolution order for the reports directory:
``--reports-dir`` flag → ``$WORMY_REPORTS_DIR`` → ``./reports`` →
``<repo root>/reports``.

Exit codes mirror the CLI contract: 0 ok · 1 error · 2 usage.
"""

from __future__ import annotations

import glob
import html
import json
import os
import re
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ._version import __version__

console = Console()
err_console = Console(stderr=True)

# Mirror of worm_core.cli exit codes (imported lazily there to avoid a cycle).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

REPORTS_DIR_ENV = "WORMY_REPORTS_DIR"
DEFAULT_REPORTS_DIR = "reports"
REPORT_GLOB = "audit_report_*.json"
_ID_RE = re.compile(r"audit_report_(\d{8}_\d{6})\.json$")

LATEST = "latest"

# Retention default: `report prune` keeps the newest N engagements.
PRUNE_DEFAULT_KEEP = 20

# Severity → rich style for recommendations.
_SEVERITY_STYLES = {
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


def _report_id_from_path(path: str | None) -> str | None:
    """Timestamp id embedded in a report filename, or ``None``."""
    if not path:
        return None
    m = _ID_RE.search(os.path.basename(path))
    return m.group(1) if m else None


# ─────────────────────────── discovery ────────────────────────────


def _repo_root() -> str | None:
    """Package parent directory (source checkout), like cli._find_repo_root."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_reports_dir(explicit: str | None) -> str:
    """Resolve the reports directory.

    Explicit user input always wins, even when the directory does not
    exist yet, so error messages point where the user asked:
    ``--reports-dir`` flag → ``$WORMY_REPORTS_DIR``. Without explicit
    input the heuristic kicks in: ``./reports`` → ``<repo root>/reports``
    → ``reports`` (default, used for the error message).
    """
    if explicit:
        return explicit
    env = os.environ.get(REPORTS_DIR_ENV)
    if env:
        return env
    if os.path.isdir(DEFAULT_REPORTS_DIR):
        return DEFAULT_REPORTS_DIR
    root = _repo_root()
    if root:
        candidate = os.path.join(root, DEFAULT_REPORTS_DIR)
        if os.path.isdir(candidate):
            return candidate
    return DEFAULT_REPORTS_DIR


def discover_reports(reports_dir: str) -> list[dict]:
    """Inventory of report refs sorted chronologically (oldest first).

    Each ref: {"id": ts, "path": path, "mtime": float}.
    """
    refs = []
    for path in glob.glob(os.path.join(reports_dir, REPORT_GLOB)):
        rid = _report_id_from_path(path)
        if rid is None:
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        refs.append({"id": rid, "path": path, "mtime": mtime})
    refs.sort(key=lambda r: (r["id"], r["mtime"]))
    return refs


def resolve_report_path(reports_dir: str, report_id: str) -> str | None:
    """Map a report id (timestamp, filename, path or ``latest``) → path."""
    rid = (report_id or LATEST).strip()
    if not os.path.isdir(reports_dir):
        return None
    if rid == LATEST or rid == "":
        refs = discover_reports(reports_dir)
        return refs[-1]["path"] if refs else None
    # Direct path / relative path
    if os.path.isfile(rid):
        return rid
    # Bare timestamp id
    candidate = os.path.join(reports_dir, f"audit_report_{rid}.json")
    if os.path.isfile(candidate):
        return candidate
    # Full filename
    candidate = os.path.join(reports_dir, rid)
    if os.path.isfile(candidate):
        return candidate
    # Prefix match (first ids that start with the given prefix)
    refs = [r for r in discover_reports(reports_dir) if r["id"].startswith(rid)]
    if len(refs) == 1:
        return refs[0]["path"]
    return None


def load_report(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _report_not_found(rid: str, reports_dir: str) -> None:
    """The shared "Report not found" error — points the operator at `report list`."""
    err_console.print(
        f"[red]Report not found:[/] '{rid}' in {reports_dir}\n"
        "List available engagements with [cyan]report list[/]."
    )


def _load_or_error(path: str, context: str = "") -> tuple[dict | None, int]:
    """Load a report JSON, or print one consistent error and fail.

    Returns ``(data, EXIT_OK)`` on success and ``(None, EXIT_ERROR)`` on
    failure — the caller returns the code. ``context`` optionally names
    the flow (``" for comparison"``) so the message stays actionable;
    the failing path is always included.
    """
    try:
        return load_report(path), EXIT_OK
    except (json.JSONDecodeError, OSError) as exc:
        err_console.print(f"[red]Cannot read report{context}[/] {path}: {exc}")
        return None, EXIT_ERROR


# ─────────────────────────── summaries ────────────────────────────


def _fmt_ts(report_id: str) -> str:
    try:
        return datetime.strptime(report_id, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return report_id


def summarize(data: dict) -> dict:
    """Flatten a report JSON into the KPIs used by `list` and `show`."""
    summary = data.get("executive_summary", {}) or {}
    stats = data.get("worm_statistics", {}) or {}
    infected = data.get("infected_hosts", []) or []
    failed = data.get("failed_targets", []) or []
    recommendations = data.get("recommendations", []) or []
    scan_results = data.get("scan_results", []) or []
    total_attempts = len(infected) + len(failed)
    success_rate = len(infected) / total_attempts * 100 if total_attempts else 0.0
    return {
        "generated_at": (data.get("report_metadata", {}) or {}).get("generated_at", "N/A"),
        "tool": (data.get("report_metadata", {}) or {}).get("tool", "Wormy"),
        "version": (data.get("report_metadata", {}) or {}).get("version", "—"),
        "hosts_discovered": summary.get("total_hosts_discovered", 0),
        "infected": len(infected),
        "failed": len(failed),
        "success_rate": f"{success_rate:.1f}%",
        "duration": summary.get("duration", "N/A"),
        "scans": stats.get("scans", 0),
        "vulnerabilities": stats.get("vulnerabilities_found", 0),
        "credentials": stats.get("credentials_discovered", 0),
        "lateral": stats.get("lateral_movements", 0),
        "recommendations": len(recommendations),
        "scan_results": scan_results,
        "infected_ips": infected,
        "failed_ips": failed,
        "recommendation_list": recommendations,
    }


# ─────────────────────────── rendering: list ──────────────────────


def render_list(reports_dir: str) -> list[dict]:
    """Render the engagement inventory. Returns the summary rows (for --json)."""
    refs = discover_reports(reports_dir)
    if not refs:
        console.print(
            f"[yellow]No reports found in[/] [cyan]{reports_dir}[/].\n"
            "Run an engagement first: [cyan]wormy run --dry-run[/] writes "
            f"timestamped reports into {DEFAULT_REPORTS_DIR}/ at the end."
        )
        return []

    rows = []
    t = Table(
        title=f"Wormy engagements — {reports_dir} (oldest first)",
        border_style="bright_blue",
    )
    t.add_column("Report ID", style="cyan")
    t.add_column("Generated", style="white")
    t.add_column("Hosts", justify="right")
    t.add_column("Infected", justify="right", style="green")
    t.add_column("Failed", justify="right", style="red")
    t.add_column("Success", justify="right")
    t.add_column("Duration", style="dim")
    for ref in refs:
        try:
            data = load_report(ref["path"])
            s = summarize(data)
            row = {
                "id": ref["id"],
                "generated": s["generated_at"],
                "hosts": s["hosts_discovered"],
                "infected": s["infected"],
                "failed": s["failed"],
                "success_rate": s["success_rate"],
                "duration": s["duration"],
            }
            rows.append(row)
            t.add_row(
                ref["id"],
                str(row["generated"]),
                str(row["hosts"]),
                str(row["infected"]),
                str(row["failed"]),
                row["success_rate"],
                str(row["duration"]),
            )
        except (json.JSONDecodeError, OSError) as e:
            rows.append({"id": ref["id"], "error": str(e)})
            t.add_row(ref["id"], "[red]unreadable[/]", "-", "-", "-", "-", "-")
    console.print(t)
    console.print(
        f"[dim]{len(rows)} report(s). Inspect one with:[/] "
        f"[cyan]wormy report show {refs[-1]['id']}[/]"
    )
    return rows


# ─────────────────────────── rendering: show ──────────────────────


def _sev_style(severity: str) -> str:
    return _SEVERITY_STYLES.get((severity or "").upper(), "dim")


def render_show(data: dict, source: str) -> None:
    """Terminal rendering of a single report."""
    s = summarize(data)
    meta = data.get("report_metadata", {}) or {}
    infected_set = set(s["infected_ips"])
    hosts = [h for h in s["scan_results"] if isinstance(h, dict)]

    console.print(
        Panel(
            f"[bold]tool[/]      {meta.get('tool', 'Wormy')} v{meta.get('version', '—')} "
            f"(CLI {__version__})\n"
            f"[bold]generated[/] {s['generated_at']}\n"
            f"[bold]purpose[/]   {meta.get('purpose', '—')}\n"
            f"[bold]source[/]    {source}",
            title="Wormy — engagement report",
            border_style="bright_blue",
        )
    )

    kpi = Table(title="Executive summary", border_style="green", show_header=False)
    kpi.add_column("metric", style="cyan")
    kpi.add_column("value", justify="right")
    kpi.add_row("Hosts discovered", str(s["hosts_discovered"]))
    kpi.add_row("Infected", f"[green]{s['infected']}[/]")
    kpi.add_row("Failed", f"[red]{s['failed']}[/]")
    kpi.add_row("Success rate", s["success_rate"])
    kpi.add_row("Duration", str(s["duration"]))
    kpi.add_row("Scans", str(s["scans"]))
    kpi.add_row("Vulnerabilities found", str(s["vulnerabilities"]))
    kpi.add_row("Credentials discovered", str(s["credentials"]))
    kpi.add_row("Lateral movements", str(s["lateral"]))
    console.print(kpi)

    if s["infected_ips"]:
        t = Table(title=f"Infected hosts ({len(s['infected_ips'])})", border_style="red")
        t.add_column("IP", style="bold red")
        t.add_column("OS")
        t.add_column("Open ports")
        t.add_column("Vuln score", justify="right")
        by_ip = {h.get("ip"): h for h in hosts}
        for ip in s["infected_ips"]:
            host = by_ip.get(ip, {})
            t.add_row(
                str(ip),
                str(host.get("os_guess", "—")),
                ", ".join(str(p) for p in (host.get("open_ports") or [])) or "—",
                str(host.get("vulnerability_score", "—")),
            )
        console.print(t)
    else:
        console.print("[dim]No infected hosts in this engagement.[/]")

    if s["failed_ips"]:
        console.print(
            f"[red]Failed targets ({len(s['failed_ips'])}):[/] "
            + ", ".join(str(ip) for ip in s["failed_ips"])
        )

    top = sorted(
        hosts,
        key=lambda h: h.get("vulnerability_score", 0),
        reverse=True,
    )[:10]
    if top:
        t = Table(title="Most vulnerable hosts (top 10)", border_style="yellow")
        t.add_column("IP", style="cyan")
        t.add_column("OS")
        t.add_column("Open ports")
        t.add_column("Vuln score", justify="right")
        t.add_column("Status")
        for host in top:
            status = "INFECTED" if host.get("ip") in infected_set else "DISCOVERED"
            t.add_row(
                str(host.get("ip", "—")),
                str(host.get("os_guess", "—")),
                ", ".join(str(p) for p in (host.get("open_ports") or [])) or "—",
                str(host.get("vulnerability_score", 0)),
                f"[red]{status}[/]" if status == "INFECTED" else f"[dim]{status}[/]",
            )
        console.print(t)

    if s["recommendation_list"]:
        t = Table(
            title=f"Recommendations ({len(s['recommendation_list'])})", border_style="bright_blue"
        )
        t.add_column("#", justify="right")
        t.add_column("Severity")
        t.add_column("Category", style="cyan")
        t.add_column("Finding", max_width=44)
        t.add_column("Remediation", max_width=44)
        for i, rec in enumerate(s["recommendation_list"], 1):
            if not isinstance(rec, dict):
                continue
            sev = str(rec.get("severity", "INFO"))
            t.add_row(
                str(i),
                f"[{_sev_style(sev)}]{sev}[/]",
                str(rec.get("category", "—")),
                str(rec.get("finding", "—")),
                str(rec.get("remediation", "—")),
            )
        console.print(t)


# ─────────────────────────── rendering: html ──────────────────────


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Wormy engagement report {REPORT_ID}</title>
<style>
:root {{ --red:#b91c1c; --green:#15803d; --yellow:#a16207; --blue:#1d4ed8;
         --ink:#111827; --dim:#6b7280; --line:#e5e7eb; --bg:#f9fafb; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; background: var(--bg); color: var(--ink); line-height: 1.55; }}
.wrap {{ max-width: 1000px; margin: 2rem auto; padding: 0 1rem; }}
header {{ border: 1px solid var(--line); background: #fff; border-radius: 10px;
          padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }}
header h1 {{ margin: 0 0 .25rem; font-size: 1.35rem; }}
header p {{ margin: .15rem 0; color: var(--dim); font-size: .9rem; }}
.kpis {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.25rem; }}
.kpi {{ flex: 1 1 130px; background: #fff; border: 1px solid var(--line);
        border-radius: 10px; padding: .8rem 1rem; }}
.kpi .n {{ font-size: 1.6rem; font-weight: 700; }}
.kpi .l {{ color: var(--dim); font-size: .8rem; text-transform: uppercase;
           letter-spacing: .04em; }}
.kpi.bad .n {{ color: var(--red); }} .kpi.good .n {{ color: var(--green); }}
section {{ background: #fff; border: 1px solid var(--line); border-radius: 10px;
           padding: 1rem 1.5rem; margin-bottom: 1.25rem; }}
section h2 {{ margin: .1rem 0 .8rem; font-size: 1.05rem;
              border-bottom: 1px solid var(--line); padding-bottom: .45rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); }}
th {{ background: #f3f4f6; font-size: .78rem; text-transform: uppercase;
      letter-spacing: .03em; color: var(--dim); }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.badge {{ display: inline-block; padding: .1rem .5rem; border-radius: 999px;
          font-size: .72rem; font-weight: 700; }}
.badge.HIGH {{ background: #fee2e2; color: var(--red); }}
.badge.MEDIUM {{ background: #fef3c7; color: var(--yellow); }}
.badge.LOW {{ background: #e0f2fe; color: var(--blue); }}
.inf {{ color: var(--red); font-weight: 600; }}
.chips {{ display: flex; flex-wrap: wrap; gap: .35rem; }}
.chip {{ background: #fee2e2; color: var(--red); border-radius: 6px;
         padding: .15rem .5rem; font-size: .8rem; }}
.chip.fail {{ background: #fde8e8; }}
footer {{ color: var(--dim); font-size: .8rem; text-align: center; padding: 1rem 0 2rem; }}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Wormy engagement report</h1>
  <p><strong>Tool:</strong> {TOOL} (report v{VERSION}, CLI {CLI_VERSION})</p>
  <p><strong>Generated:</strong> {GENERATED} &nbsp;·&nbsp; <strong>Purpose:</strong> {PURPOSE}</p>
  <p><strong>Source:</strong> {SOURCE}</p>
</header>
{KPIS}
{HOSTS}
{FINDINGS}
<footer>Generated by <code>wormy report html</code> — authorized security testing only.</footer>
</div>
</body>
</html>
"""


def render_html(data: dict, source: str) -> str:
    """Build a standalone HTML document from a report dict (all values escaped)."""
    s = summarize(data)
    meta = data.get("report_metadata", {}) or {}
    report_id = _report_id_from_path(source) or "—"

    e = html.escape  # every dynamic string goes through this

    def kpi(value: str, label: str, cls: str = "") -> str:
        return (
            f'<div class="kpi {cls}"><div class="n">{value}</div><div class="l">{label}</div></div>'
        )

    kpis = (
        '<div class="kpis">'
        + "".join(
            [
                kpi(e(str(s["hosts_discovered"])), "hosts discovered"),
                kpi(e(str(s["infected"])), "infected", "good"),
                kpi(e(str(s["failed"])), "failed", "bad"),
                kpi(e(s["success_rate"]), "success rate"),
                kpi(e(str(s["duration"])), "duration"),
                kpi(e(str(s["vulnerabilities"])), "vulnerabilities"),
                kpi(e(str(s["credentials"])), "credentials"),
            ]
        )
        + "</div>"
    )

    # Hosts table
    infected_set = set(s["infected_ips"])
    host_rows = []
    for host in s["scan_results"]:
        if not isinstance(host, dict):
            continue
        ip = e(str(host.get("ip", "—")))
        status = "INFECTED" if host.get("ip") in infected_set else "discovered"
        status_html = f'<span class="inf">{status}</span>' if status == "INFECTED" else status
        host_rows.append(
            "<tr>"
            f"<td>{ip}</td>"
            f"<td>{e(str(host.get('os_guess', '—')))}</td>"
            f"<td>{e(', '.join(str(p) for p in (host.get('open_ports') or [])) or '—')}</td>"
            f'<td class="num">{e(str(host.get("vulnerability_score", 0)))}</td>'
            f"<td>{status_html}</td>"
            "</tr>"
        )
    hosts_section = (
        f'<section><h2>Hosts ({e(str(len(s["scan_results"])))})</h2>'
        "<table><thead><tr><th>IP</th><th>OS</th><th>Open ports</th>"
        "<th>Vuln score</th><th>Status</th></tr></thead><tbody>"
        + "".join(host_rows)
        + "</tbody></table></section>"
        if host_rows
        else ""
    )

    # Infected / failed chips
    chips = ""
    if s["infected_ips"]:
        chips += (
            "<section><h2>Infected hosts</h2><div class='chips'>"
            + "".join(f"<span class='chip'>{e(str(ip))}</span>" for ip in s["infected_ips"])
            + "</div></section>"
        )
    if s["failed_ips"]:
        chips += (
            "<section><h2>Failed targets</h2><div class='chips'>"
            + "".join(f"<span class='chip fail'>{e(str(ip))}</span>" for ip in s["failed_ips"])
            + "</div></section>"
        )

    # Recommendations
    rec_rows = []
    for i, rec in enumerate(s["recommendation_list"], 1):
        if not isinstance(rec, dict):
            continue
        sev = str(rec.get("severity", "INFO")).upper()
        rec_rows.append(
            "<tr>"
            f'<td class="num">{i}</td>'
            f'<td><span class="badge {e(sev)}">{e(sev)}</span></td>'
            f"<td>{e(str(rec.get('category', '—')))}</td>"
            f"<td>{e(str(rec.get('finding', '—')))}</td>"
            f"<td>{e(str(rec.get('remediation', '—')))}</td>"
            "</tr>"
        )
    recs_section = (
        "<section><h2>Recommendations</h2>"
        "<table><thead><tr><th>#</th><th>Severity</th><th>Category</th>"
        "<th>Finding</th><th>Remediation</th></tr></thead><tbody>"
        + "".join(rec_rows)
        + "</tbody></table></section>"
        if rec_rows
        else ""
    )

    return _HTML_TEMPLATE.format(
        REPORT_ID=e(report_id),
        TOOL=e(str(meta.get("tool", "Wormy"))),
        VERSION=e(str(meta.get("version", "—"))),
        CLI_VERSION=e(__version__),
        GENERATED=e(str(s["generated_at"])),
        PURPOSE=e(str(meta.get("purpose", "—"))),
        SOURCE=e(str(source or "—")),
        KPIS=kpis,
        HOSTS=(hosts_section + chips),
        FINDINGS=recs_section,
    )


# ─────────────────────────── compare ──────────────────────────────


def _parse_duration(value) -> float | None:
    """Parse a report duration into seconds (None when unknown).

    The engine writes durations as ``str(timedelta)`` ("0:00:02.044012",
    "1 day, 0:00:02") or the literal "N/A" when an engagement had no
    start time (e.g. scan-only or interrupted runs).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.upper() == "N/A":
        return None
    try:
        if ":" in text:
            days = 0.0
            if " day" in text:  # "1 day, 0:00:02" / "2 days, ..."
                day_part, _, rest = text.partition(",")
                days = float(day_part.split()[0])
                text = rest.strip()
            parts = text.split(":")
            if len(parts) != 3:
                return None
            h, m, s = parts
            return days * 86400 + int(h) * 3600 + int(m) * 60 + float(s)
        return float(text)
    except (ValueError, IndexError):
        return None


def _parse_rate(value) -> float | None:
    """Parse a success rate ("12.5%") into a float (None when unknown)."""
    if value is None:
        return None
    text = str(value).strip().rstrip("%")
    try:
        return float(text)
    except ValueError:
        return None


# (summarize key, label, direction, formatter)
#   direction: "up" → higher is better · "down" → lower is better ·
#              "neutral" → no value judgement is implied.
_METRICS = (
    ("hosts_discovered", "Hosts discovered", "up", "int"),
    ("infected", "Infected", "up", "int"),
    ("failed", "Failed", "down", "int"),
    ("success_rate", "Success rate", "up", "rate"),
    ("duration", "Duration", "neutral", "dur"),
    ("scans", "Scans", "neutral", "int"),
    ("vulnerabilities", "Vulnerabilities found", "up", "int"),
    ("credentials", "Credentials discovered", "up", "int"),
    ("lateral", "Lateral movements", "up", "int"),
    ("recommendations", "Recommendations", "neutral", "int"),
)


def _fmt_dur(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    if seconds >= 3600:
        return f"{seconds / 3600:.2f}h"
    if seconds >= 60:
        return f"{seconds / 60:.2f}m"
    return f"{seconds:.2f}s"


def _pass_through(value):
    """Identity parse/format — ``int`` metrics are already numeric."""
    return value


def _fmt_rate(value: float | None):
    """Rate cell: ``12.5%`` (None stays None — caller falls back to raw)."""
    return None if value is None else f"{value:.1f}%"


# Metric value pipeline, keyed by the ``kind`` column of _METRICS: parse
# turns the raw summarize value into a number (None = unknown), fmt renders
# a parsed value back into a table cell.
_METRIC_PARSERS = {
    "rate": _parse_rate,
    "dur": _parse_duration,
    "int": _pass_through,
}
_METRIC_FORMATTERS = {
    "rate": _fmt_rate,
    "dur": _fmt_dur,  # None-safe: renders "N/A"
    "int": _pass_through,
}


def compare_metrics(data_a: dict, data_b: dict) -> list[dict]:
    """Build the side-by-side metric model for two report dicts.

    ``data_a`` is the baseline (older engagement), ``data_b`` the candidate
    (newer). Each metric row: {"key", "metric", "baseline", "candidate",
    "delta", "trend"} — ``key`` is the summarize field (usable with
    ``--metrics``), ``metric`` the human label; numeric values when
    parseable, the raw string otherwise, ``delta``/``trend`` are
    None/"neutral" when no numeric comparison is possible.
    """
    s_a, s_b = summarize(data_a), summarize(data_b)
    rows = []
    for key, label, direction, kind in _METRICS:
        raw_a, raw_b = s_a[key], s_b[key]
        parse, fmt = _METRIC_PARSERS[kind], _METRIC_FORMATTERS[kind]
        va, vb = parse(raw_a), parse(raw_b)

        if va is not None and vb is not None:
            delta = vb - va
            if direction == "neutral" or delta == 0:
                trend = "neutral"
            elif (delta > 0) == (direction == "up"):
                trend = "better"
            else:
                trend = "worse"
            rows.append(
                {
                    "key": key,
                    "metric": label,
                    "baseline": fmt(va),
                    "candidate": fmt(vb),
                    "delta": round(delta, 3),
                    "trend": trend,
                }
            )
        else:
            rows.append(
                {
                    "key": key,
                    "metric": label,
                    "baseline": fmt(va) if va is not None else str(raw_a),
                    "candidate": fmt(vb) if vb is not None else str(raw_b),
                    "delta": None,
                    "trend": "neutral",
                }
            )
    return rows


def _filter_metric_rows(rows: list[dict], metrics: str) -> tuple[list[dict], list[str]]:
    """Filter compare rows by a comma-separated metric spec.

    Each name matches either the machine key (``infected``,
    ``success_rate``) or the human label (``"Infected"``, ``"Success
    rate"``), case-insensitively. Returns ``(filtered_rows, unknown_names)``
    — the caller turns a non-empty ``unknown_names`` into a usage error.
    """
    wanted = [name.strip().lower() for name in metrics.split(",") if name.strip()]
    unknown = []
    picked = []
    for name in wanted:
        matches = [
            r for r in rows if r["key"].lower() == name or r["metric"].strip().lower() == name
        ]
        if matches:
            picked.extend(matches)
        else:
            unknown.append(name)
    return picked, unknown


def _trend_cell(trend: str, delta) -> str:
    """Render the delta column: colored +/- value with a trend arrow."""
    if delta is None:
        return "[dim]—[/]"
    sign = "+" if delta > 0 else "" if delta < 0 else "±"
    text = f"{sign}{delta:g}"
    if trend == "better":
        return f"[green]▲ {text}[/]"
    if trend == "worse":
        return f"[red]▼ {text}[/]"
    return f"[dim]{text}[/]"


def render_compare(
    data_a: dict, data_b: dict, id_a: str, id_b: str, rows: list[dict] | None = None
) -> None:
    """Terminal rendering of a two-engagement comparison.

    ``rows`` lets the caller pass pre-filtered metric rows (``--metrics``);
    when omitted the full model is built from the two report dicts.
    """
    if rows is None:
        rows = compare_metrics(data_a, data_b)
    s_a, s_b = summarize(data_a), summarize(data_b)
    console.print(
        Panel(
            f"[bold]baseline[/]  {id_a}  ·  {s_a['generated_at']}\n"
            f"[bold]candidate[/] {id_b}  ·  {s_b['generated_at']}",
            title="Wormy — engagement comparison",
            border_style="bright_blue",
        )
    )
    t = Table(title="Metric deltas (baseline → candidate)", border_style="bright_blue")
    t.add_column("Metric", style="cyan")
    t.add_column(f"Baseline {id_a}", justify="right")
    t.add_column(f"Candidate {id_b}", justify="right")
    t.add_column("Δ", justify="right")
    for row in rows:
        t.add_row(
            row["metric"],
            str(row["baseline"]),
            str(row["candidate"]),
            _trend_cell(row["trend"], row["delta"]),
        )
    console.print(t)
    console.print(
        "[dim]▲ higher is better · ▼ lower is better · plain delta = no value "
        "judgement. The older report is always the baseline.[/]"
    )


def _resolve_ref(refs: list[dict], reports_dir: str, rid: str) -> dict | None:
    """Resolve a report id to a ref entry (path + id + mtime)."""
    path = resolve_report_path(reports_dir, rid)
    if path is None:
        return None
    for r in refs:
        if os.path.abspath(r["path"]) == os.path.abspath(path):
            return r
    # Direct file path outside the inventory (e.g. /tmp/other.json).
    derived_id = _report_id_from_path(path)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0.0
    return {
        "id": derived_id or os.path.splitext(os.path.basename(path))[0],
        "path": path,
        "mtime": mtime,
    }


def _ref_index(refs: list[dict], ref: dict) -> int | None:
    for i, r in enumerate(refs):
        if r["id"] == ref["id"]:
            return i
    return None


def compare_flow(
    reports_dir: str,
    id1: str | None,
    id2: str | None,
    as_json: bool = False,
    metrics: str | None = None,
) -> int:
    """Resolve two engagements, compare them, render. Used by CLI and REPL.

    Resolution semantics (the newer report is always the candidate):
      - ``compare`` (no ids)        → latest vs. its predecessor
      - ``compare A``               → A vs. the report right before A
      - ``compare A B``             → both resolved; the older is baseline

    ``metrics`` ("infected,success_rate") restricts the comparison to
    those KPIs, matched by key or human label; an unknown name is a
    usage error that lists the valid ones.
    """
    refs = discover_reports(reports_dir) if os.path.isdir(reports_dir) else []

    if id2 is None:
        cand = _resolve_ref(refs, reports_dir, id1 or LATEST)
        if cand is None:
            _report_not_found(id1 or LATEST, reports_dir)
            return EXIT_ERROR
        idx = _ref_index(refs, cand)
        if idx is None or idx == 0:
            err_console.print(
                f"[red]No earlier report before '{cand['id']}' in {reports_dir}.[/]\n"
                "Compare needs a predecessor — pass two ids explicitly: "
                f"[cyan]report compare <id> {cand['id']}[/]."
            )
            return EXIT_ERROR
        base_ref, cand_ref = refs[idx - 1], cand
    else:
        a = _resolve_ref(refs, reports_dir, id1 or LATEST)
        b = _resolve_ref(refs, reports_dir, id2)
        if a is None or b is None:
            # An omitted id1 implies ``latest`` — name that in the error
            # instead of a literal ``None``.
            missing = (id1 or LATEST) if a is None else id2
            _report_not_found(missing, reports_dir)
            return EXIT_ERROR
        if os.path.abspath(a["path"]) == os.path.abspath(b["path"]):
            err_console.print("[red]Cannot compare a report with itself.[/]")
            return EXIT_ERROR
        base_ref, cand_ref = sorted((a, b), key=lambda r: (r["id"], r["mtime"]))

    data_a, code = _load_or_error(base_ref["path"], " for comparison")
    if data_a is None:
        return code
    data_b, code = _load_or_error(cand_ref["path"], " for comparison")
    if data_b is None:
        return code

    rows = compare_metrics(data_a, data_b)
    if metrics:
        rows, unknown = _filter_metric_rows(rows, metrics)
        if unknown:
            valid = ", ".join(f"{key} ({label.lower()})" for key, label, _d, _k in _METRICS)
            err_console.print(
                f"[red]Unknown metric(s):[/] {', '.join(unknown)}\n" f"Valid metrics: {valid}"
            )
            return EXIT_USAGE

    if as_json:
        print(
            json.dumps(
                {
                    "baseline": {"id": base_ref["id"], "path": base_ref["path"]},
                    "candidate": {"id": cand_ref["id"], "path": cand_ref["path"]},
                    "metrics": rows,
                },
                indent=2,
                default=str,
            )
        )
    else:
        render_compare(data_a, data_b, base_ref["id"], cand_ref["id"], rows)
    return EXIT_OK


# ─────────────────────────── single-report flows ──────────────────
# Shared by the CLI (`wormy report …`) and the REPL (`report …`) so both
# surfaces behave identically.


def show_report(reports_dir: str, report_id: str | None, as_json: bool = False) -> int:
    """Resolve + load + render one report. Returns an exit code."""
    rid = report_id or LATEST
    path = resolve_report_path(reports_dir, rid)
    if path is None:
        _report_not_found(rid, reports_dir)
        return EXIT_ERROR
    data, code = _load_or_error(path)
    if data is None:
        return code
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        render_show(data, path)
    return EXIT_OK


def export_html(reports_dir: str, report_id: str | None, output: str | None = None) -> int:
    """Resolve a report and write a standalone HTML export next to it."""
    rid = report_id or LATEST
    path = resolve_report_path(reports_dir, rid)
    if path is None:
        _report_not_found(rid, reports_dir)
        return EXIT_ERROR
    data, code = _load_or_error(path)
    if data is None:
        return code
    out = output
    if not out:
        rid = _report_id_from_path(path)
        stem = f"audit_report_{rid}" if rid else "audit_report"
        out = os.path.join(os.path.dirname(path) or ".", f"{stem}.html")
    doc = render_html(data, path)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    console.print(f"[green]HTML report written to[/] [cyan]{out}[/]")
    return EXIT_OK


# ─────────────────────────── prune ────────────────────────────────
# The single mutating operation of the hub: a retention policy over the
# engagement trail. Kept deliberately conservative — preview always,
# confirm by default, delete only whole `audit_report_<id>.*` sets.


def _engagement_files(reports_dir: str, ref: dict) -> list[str]:
    """Every artifact of one engagement (json/csv/txt/html siblings)."""
    pattern = os.path.join(reports_dir, f"audit_report_{ref['id']}.*")
    return sorted(glob.glob(pattern))


def _file_size(path: str) -> int:
    """File size in bytes, 0 when unreadable (vanished between scan and plan)."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _confirm_prune(question: str) -> bool:
    """Ask the operator; EOF/Ctrl-D or anything but y/yes aborts."""
    try:
        answer = input(f"{question} ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def prune_flow(
    reports_dir: str,
    keep: int = PRUNE_DEFAULT_KEEP,
    assume_yes: bool = False,
    dry_run: bool = False,
    as_json: bool = False,
    confirm=None,
) -> int:
    """Keep the newest ``keep`` engagements, delete the rest.

    Used by the CLI (``report prune --keep N [--yes] [--dry-run]``) and
    the REPL (``report prune [N]``). The plan is always previewed before
    anything is touched; without ``--yes`` the operator confirms via a
    y/N prompt (an EOF or a "no" aborts with exit 0 — the audit trail is
    the safer default). ``--json`` requires ``--yes`` so scripts never
    hang on a prompt.
    """
    if keep is None or keep < 1:
        err_console.print(
            f"[red]--keep must be >= 1 (got {keep})[/] — pruning to zero would "
            "erase the whole audit trail."
        )
        return EXIT_USAGE
    if as_json and not assume_yes:
        err_console.print(
            "[red]report prune --json requires --yes[/] — machine output never "
            "prompts for confirmation."
        )
        return EXIT_USAGE
    if not os.path.isdir(reports_dir):
        err_console.print(f"[red]Reports directory not found:[/] {reports_dir}")
        return EXIT_ERROR

    refs = discover_reports(reports_dir)
    if len(refs) <= keep:
        msg = (
            f"Nothing to prune — {len(refs)} report(s) present, keeping {keep}."
            if refs
            else f"No reports in {reports_dir} — nothing to prune."
        )
        if as_json:
            print(json.dumps({"pruned": [], "kept": [r["id"] for r in refs], "errors": []}))
        else:
            console.print(f"[yellow]{msg}[/]")
        return EXIT_OK

    keep_refs, drop_refs = refs[-keep:], refs[:-keep]
    # plan: [{id, files: [path, ...]}]
    plan = [{"id": ref["id"], "files": _engagement_files(reports_dir, ref)} for ref in drop_refs]
    n_files = sum(len(entry["files"]) for entry in plan)

    # Machine mode skips the preview table and goes straight to deletion.
    if not as_json:
        t = Table(
            title=f"Prune plan — keep {len(keep_refs)} newest, delete {len(drop_refs)} oldest",
            border_style="yellow",
        )
        t.add_column("Report ID", style="cyan")
        t.add_column("Files", justify="right")
        t.add_column("Size", justify="right")
        for entry in plan:
            size = sum(_file_size(path) for path in entry["files"])
            t.add_row(entry["id"], str(len(entry["files"])), f"{size / 1024:.1f} KiB")
        console.print(t)

    if dry_run:
        console.print(
            f"[yellow]dry-run:[/] {n_files} file(s) would be deleted. Nothing was touched."
        )
        return EXIT_OK

    if not assume_yes:
        ask = confirm or _confirm_prune
        if not ask(
            f"Delete {n_files} file(s) from {len(drop_refs)} old report(s) in {reports_dir}? [y/N]"
        ):
            console.print("[yellow]Aborted — nothing was deleted.[/]")
            return EXIT_OK

    deleted: list[str] = []
    errors: list[dict] = []
    for entry in plan:
        for path in entry["files"]:
            try:
                os.remove(path)
                deleted.append(os.path.basename(path))
            except OSError as exc:
                errors.append({"file": os.path.basename(path), "error": str(exc)})
                err_console.print(f"[red]Could not delete[/] {path}: {exc}")

    if as_json:
        print(
            json.dumps(
                {
                    "pruned": [e["id"] for e in plan],
                    "deleted_files": sorted(deleted),
                    "kept": [r["id"] for r in keep_refs],
                    "errors": errors,
                },
                indent=2,
            )
        )
    else:
        console.print(
            f"[green]Deleted {len(deleted)} file(s)[/] from {len(drop_refs)} old report(s); "
            f"{len(keep_refs)} engagement(s) kept."
            + (f" [red]{len(errors)} error(s).[/]" if errors else "")
        )
    return EXIT_ERROR if errors else EXIT_OK


# ─────────────────────────── command ──────────────────────────────


def cmd_report(args) -> int:
    """CLI entrypoint for `wormy report`."""
    action = (getattr(args, "action", None) or "list").lower()
    reports_dir = resolve_reports_dir(getattr(args, "reports_dir", None))

    if action == "list":
        if not os.path.isdir(reports_dir):
            err_console.print(
                f"[red]Reports directory not found:[/] {reports_dir}\n"
                "Run an engagement first (e.g. [cyan]wormy run --dry-run[/]) or point "
                f"at one with [cyan]--reports-dir[/] / [cyan]${REPORTS_DIR_ENV}[/]."
            )
            return EXIT_ERROR
        rows = render_list(reports_dir)
        if getattr(args, "json", False):
            print(json.dumps(rows, indent=2, default=str))
        return EXIT_OK if rows else EXIT_ERROR

    if action == "compare":
        if not os.path.isdir(reports_dir):
            err_console.print(
                f"[red]Reports directory not found:[/] {reports_dir}\n"
                "Run at least two engagements first (e.g. [cyan]wormy run --dry-run[/])."
            )
            return EXIT_ERROR
        return compare_flow(
            reports_dir,
            getattr(args, "report_id", None),
            getattr(args, "report_id2", None),
            as_json=getattr(args, "json", False),
            metrics=getattr(args, "metrics", None),
        )

    if action == "prune":
        keep = getattr(args, "keep", None)
        if keep is None:
            keep = PRUNE_DEFAULT_KEEP
        return prune_flow(
            reports_dir,
            keep=keep,
            assume_yes=getattr(args, "yes", False),
            dry_run=getattr(args, "dry_run", False),
            as_json=getattr(args, "json", False),
        )

    # show / html operate on one report
    report_id = getattr(args, "report_id", None) or LATEST

    if action == "show":
        return show_report(reports_dir, report_id, as_json=getattr(args, "json", False))

    if action == "html":
        return export_html(reports_dir, report_id, getattr(args, "output", None))

    err_console.print(f"[red]Unknown report action:[/] {action}")
    return EXIT_USAGE
