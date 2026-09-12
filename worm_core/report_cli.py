"""
Wormy — post-engagement report hub (``wormy report``).

The engine (``wormy run`` and the REPL ``report`` command) writes
timestamped audit reports — ``reports/audit_report_<ts>.json|csv|txt`` —
at the end of every engagement. Until now the only way to consume those
artifacts was opening the raw files by hand. This module adds three
read-only operations on top of that directory:

    list    engagement inventory (date, hosts, infections, success rate)
    show    terminal rendering of one report (summary, hosts, findings)
    html    standalone self-contained HTML export for sharing/delivering

Reports are never modified or deleted by this command — it is a pure
consumer of the audit trail. Resolution order for the reports directory:
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

# Severity → rich style for recommendations.
_SEVERITY_STYLES = {
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


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
        m = _ID_RE.search(os.path.basename(path))
        if not m:
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        refs.append({"id": m.group(1), "path": path, "mtime": mtime})
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
        infected_set = set(s["infected_ips"])
        t = Table(title=f"Infected hosts ({len(s['infected_ips'])})", border_style="red")
        t.add_column("IP", style="bold red")
        t.add_column("OS")
        t.add_column("Open ports")
        t.add_column("Vuln score", justify="right")
        by_ip = {h.get("ip"): h for h in s["scan_results"] if isinstance(h, dict)}
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
        (h for h in s["scan_results"] if isinstance(h, dict)),
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
        infected_set = set(s["infected_ips"])
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
    report_id = "—"
    if source:
        m = _ID_RE.search(os.path.basename(source))
        if m:
            report_id = m.group(1)

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

    # show / html operate on one report
    report_id = getattr(args, "report_id", None) or LATEST
    path = resolve_report_path(reports_dir, report_id)
    if path is None:
        err_console.print(
            f"[red]Report not found:[/] '{report_id}' in {reports_dir}\n"
            "List available engagements with [cyan]wormy report list[/]."
        )
        return EXIT_ERROR
    try:
        data = load_report(path)
    except (json.JSONDecodeError, OSError) as exc:
        err_console.print(f"[red]Cannot read report[/] {path}: {exc}")
        return EXIT_ERROR

    if action == "show":
        if getattr(args, "json", False):
            print(json.dumps(data, indent=2, default=str))
        else:
            render_show(data, path)
        return EXIT_OK

    if action == "html":
        out = getattr(args, "output", None)
        if not out:
            m = _ID_RE.search(os.path.basename(path))
            stem = f"audit_report_{m.group(1)}" if m else "audit_report"
            out = os.path.join(os.path.dirname(path) or ".", f"{stem}.html")
        doc = render_html(data, path)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(doc)
        console.print(f"[green]HTML report written to[/] [cyan]{out}[/]")
        return EXIT_OK

    err_console.print(f"[red]Unknown report action:[/] {action}")
    return EXIT_USAGE
