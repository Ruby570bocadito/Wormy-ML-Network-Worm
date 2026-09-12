"""
Wormy — professional command-line interface.

Subcommands
-----------
    run       Launch the propagation engine (full pipeline).
    scan      Network reconnaissance only (no exploitation).
    report    Inspect & export engagement reports (list/show/html/compare/prune).
    config    Inspect the effective configuration (config show).
    lab       Manage the Docker vulnerability lab.
    train     Train the ML models (RL agent / classifier / evasion).
    doctor    Environment health check.
    shell     Interactive REPL with live status.
    version   Print version information.

Exit codes: 0 ok | 1 runtime error | 2 usage error | 130 interrupted.

Live (non dry-run) runs require explicit authorization: pass
``--yes-i-am-authorized`` or set the ``WORMY_AUTHORIZED=1`` environment
variable. This is a deliberate safety gate, not friction.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import subprocess
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ._version import __version__
from .config_profiles import CONFIG_PROFILES

PROFILE_NAMES = tuple(CONFIG_PROFILES.keys())

console = Console()
err_console = Console(stderr=True)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

LAB_COMPOSE_FILE = "docker-compose-lab.yml"
EXPANDED_COMPOSE_FILE = "docker-compose-lab-expanded.yml"
AUTH_ENV_VAR = "WORMY_AUTHORIZED"

PROGRAM = "wormy"

EPILOG_EXAMPLES = """\
examples:
  %(prog)s doctor                       # verify the environment
  %(prog)s lab up                       # start the vulnerable Docker lab
  %(prog)s scan --json -o scan.json     # reconnaissance only
  %(prog)s scan --csv hosts.csv         # reconnaissance to a spreadsheet
  %(prog)s run --dry-run                # full pipeline, simulation only
  %(prog)s run --profile stealth        # authorized engagement (asks gate)
  %(prog)s shell                        # interactive REPL
"""

REPORT_EPILOG = """\
examples:
  %(prog)s report list                  # engagement inventory (KPIs)
  %(prog)s report show                  # render the latest report
  %(prog)s report show 20260913_142530  # render a specific report
  %(prog)s report show --json           # raw report JSON to stdout
  %(prog)s report html                  # standalone HTML export (latest)
  %(prog)s report html -o report.html   # HTML export to a given path
  %(prog)s report compare               # last two engagements, side by side
  %(prog)s report compare 20260913_1 20260913_2   # explicit pair
  %(prog)s report compare --metrics infected,success_rate   # 2 KPIs only
  %(prog)s report prune                 # keep the newest 20, preview + ask
  %(prog)s report prune --keep 5 --yes  # keep 5, no prompt (scripts)
  %(prog)s report prune --dry-run       # preview only, nothing deleted
"""

CONFIG_EPILOG = """\
examples:
  %(prog)s config show                            # effective config
  %(prog)s config show --profile stealth          # + profile overrides
  %(prog)s config show --profile audit --json     # machine-readable
  %(prog)s config show --target 10.0.0.0/24       # preview a target override
"""


# ─────────────────────────── helpers ────────────────────────────


def _find_repo_root() -> str | None:
    """Locate the project root (where the compose files live).

    Resolution order: $WORMY_LAB_DIR → cwd → parent of the package
    (source checkout). Returns None when nothing matches.
    """
    candidates: list[str] = []
    env = os.environ.get("WORMY_LAB_DIR")
    if env:
        candidates.append(env)
    candidates.append(os.getcwd())
    candidates.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, LAB_COMPOSE_FILE)):
            return c
    return None


def _validate_targets(targets: list[str]) -> str | None:
    """Return an error string when any target is not a valid CIDR/IP."""
    import ipaddress

    for t in targets:
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            return f"invalid target '{t}' (expected CIDR like 10.0.0.0/24 or an IP)"
    return None


def _apply_target_override(worm, targets: list[str]) -> None:
    worm.config.network.target_ranges = list(targets)
    from .module_imports import logger

    logger.info(f"Target override from CLI: {', '.join(targets)}")


def _authorization_gate(args) -> bool:
    """True when a live (exploiting) run may proceed."""
    if args.dry_run or args.scan_only:
        return True
    if args.yes_i_am_authorized:
        return True
    if os.environ.get(AUTH_ENV_VAR, "").strip().lower() in ("1", "yes", "true"):
        return True
    err_console.print(
        Panel(
            "[bold red]Live mode is gated.[/]\n\n"
            "You are about to run the engine [bold]without[/] --dry-run and without\n"
            "--scan-only: it will actively exploit targets.\n\n"
            f"Confirm you own the network or have written authorization:\n"
            f"  [cyan]{PROGRAM} run --yes-i-am-authorized ...[/]\n"
            f"  or  [cyan]export {AUTH_ENV_VAR}=1[/]\n\n"
            "For a safe simulation use [cyan]--dry-run[/]; for reconnaissance "
            "only use [cyan]scan[/].",
            title="Authorization required",
            border_style="red",
        )
    )
    return False


def _validate_cap_overrides(args) -> str | None:
    """Return an error string for invalid --max-infections/--max-runtime values."""
    if args.max_infections is not None and args.max_infections < 1:
        return f"--max-infections must be >= 1 (got {args.max_infections})"
    if args.max_runtime is not None and args.max_runtime < 1:
        return f"--max-runtime must be >= 1 hour (got {args.max_runtime})"
    return None


def _apply_cap_overrides(worm, args) -> None:
    """Apply per-run safety-cap overrides and log/warn about them.

    Raising a cap above its effective value in live (non dry-run) mode is
    surfaced with a prominent warning: safety caps are a deliberate
    containment boundary, not friction.
    """
    from .module_imports import logger

    if args.max_infections is not None:
        prop = worm.config.propagation
        old = prop.max_infections
        prop.max_infections = args.max_infections
        logger.info(f"max_infections override: {old} -> {args.max_infections}")
        if args.max_infections > old and not (args.dry_run or getattr(args, "scan_only", False)):
            err_console.print(
                Panel(
                    f"You are [bold]raising[/] the infection cap from {old} to "
                    f"{args.max_infections} in [bold red]LIVE mode[/].\n"
                    "Ensure this stays within your authorized scope.",
                    title="Safety cap raised",
                    border_style="yellow",
                )
            )

    if args.max_runtime is not None:
        safety = worm.config.safety
        old = safety.max_runtime_hours
        safety.max_runtime_hours = args.max_runtime
        logger.info(f"max_runtime_hours override: {old} -> {args.max_runtime}")
        if args.max_runtime > old and not (args.dry_run or getattr(args, "scan_only", False)):
            err_console.print(
                Panel(
                    f"You are [bold]raising[/] the runtime cap from {old}h to "
                    f"{args.max_runtime}h in [bold red]LIVE mode[/].\n"
                    "Ensure this stays within your authorized scope.",
                    title="Safety cap raised",
                    border_style="yellow",
                )
            )


def _pre_flight_banner(worm, args) -> None:
    mode = (
        "DRY-RUN (simulation)"
        if args.dry_run
        else ("SCAN-ONLY" if args.scan_only else "LIVE (authorized)")
    )
    ranges = ", ".join(getattr(worm.config.network, "target_ranges", []) or ["<config>"])
    console.print(
        Panel(
            f"[bold]mode[/]      {mode}\n"
            f"[bold]profile[/]   {args.profile or 'default'}\n"
            f"[bold]targets[/]   {ranges}",
            title=f"{PROGRAM} v{__version__} — run",
            border_style="green" if (args.dry_run or args.scan_only) else "red",
        )
    )


# ─────────────────────────── run ────────────────────────────────


def cmd_run(args) -> int:
    if not _authorization_gate(args):
        return EXIT_USAGE

    from . import WormCore  # heavy import kept lazy for fast CLI startup

    if args.target:
        err = _validate_targets(args.target)
        if err:
            err_console.print(f"[red]{err}[/]")
            return EXIT_USAGE

    err = _validate_cap_overrides(args)
    if err:
        err_console.print(f"[red]{err}[/]")
        return EXIT_USAGE

    worm = WormCore(
        config_file=args.config,
        use_cli_monitor=not args.no_monitor and not args.interactive,
        profile=args.profile,
        dry_run=args.dry_run,
        interactive=args.interactive,
        target_ranges=args.target,
    )

    if args.max_infections is not None or args.max_runtime is not None:
        _apply_cap_overrides(worm, args)

    if args.no_geofence:
        worm.config.safety.geofence_enabled = False
        from .module_imports import logger

        logger.info("Geofence disabled via --no-geofence flag")

    if args.kill_switch:
        worm.activate_kill_switch(args.kill_switch)
        return EXIT_OK

    if args.web:
        try:
            from monitoring.web_dashboard import WebDashboard
        except ImportError:
            err_console.print("[red]Flask is required for --web (pip install flask)[/]")
            return EXIT_ERROR
        dash = WebDashboard(worm, port=args.web_port)
        dash.run_background()
        console.print(f"[green]Web dashboard:[/] http://127.0.0.1:{args.web_port}")

    if args.scan_only:
        from .module_imports import logger

        logger.info("SCAN-ONLY MODE")
        worm.scan_network()
        worm.scanner.print_summary()
        return EXIT_OK

    if args.interactive:
        from .shell import InteractiveCLI

        try:
            InteractiveCLI(worm).cmdloop()
        except KeyboardInterrupt:
            worm.shutdown()
        return EXIT_OK

    _pre_flight_banner(worm, args)
    try:
        worm.propagate()
    except KeyboardInterrupt:
        from .module_imports import logger

        logger.warning("\nInterrupted by user")
        worm.shutdown()
        return EXIT_INTERRUPTED
    except Exception as e:  # noqa: BLE001 — top-level guard, message already logged
        from .module_imports import logger

        logger.error(f"Fatal error: {e}")
        worm.shutdown()
        return EXIT_ERROR
    return EXIT_OK


# ─────────────────────────── scan ───────────────────────────────

_CSV_COLUMNS = (
    "ip",
    "hostname",
    "os_guess",
    "open_ports",
    "services",
    "vulnerability_score",
    "scan_time",
)


def _fmt_services(services) -> str:
    """Flatten scanner ``services`` (list or port→name dict) into one cell."""
    if not services:
        return ""
    if isinstance(services, dict):
        return ";".join(f"{port}:{name}" for port, name in sorted(services.items(), key=str))
    return ";".join(str(s) for s in services)


def _write_scan_csv(results: list, path: str) -> int:
    """Write reconnaissance results as CSV. Returns the host-row count.

    One row per discovered host, one column per scanner field (``-`` as
    path writes to stdout for piping). ``open_ports`` and ``services``
    are flattened with ';' separators so spreadsheets keep each host in
    a single row; dict services render as ``22:ssh;80:http``.
    """
    out = sys.stdout if path == "-" else open(path, "w", encoding="utf-8", newline="")
    try:
        writer = csv.writer(out)
        writer.writerow(_CSV_COLUMNS)
        count = 0
        for host in results:
            if not isinstance(host, dict):
                continue
            writer.writerow(
                [
                    host.get("ip", ""),
                    host.get("hostname", "") or "",
                    host.get("os_guess", "") or "",
                    ";".join(str(p) for p in (host.get("open_ports") or [])),
                    _fmt_services(host.get("services")),
                    host.get("vulnerability_score", 0),
                    host.get("scan_time", "") or "",
                ]
            )
            count += 1
    finally:
        if out is not sys.stdout:
            out.close()
    return count


def cmd_scan(args) -> int:
    from . import WormCore

    worm = WormCore(
        config_file=args.config,
        use_cli_monitor=False,
        profile=args.profile,
        dry_run=True,
        interactive=False,
    )

    if args.target:
        err = _validate_targets(args.target)
        if err:
            err_console.print(f"[red]{err}[/]")
            return EXIT_USAGE
        _apply_target_override(worm, args.target)

    results = worm.scan_network(use_professional=not args.basic)
    worm.scanner.print_summary()

    if getattr(args, "csv", None):
        n_hosts = _write_scan_csv(results, args.csv)
        console.print(f"[green]CSV written to[/] [cyan]{args.csv}[/] ({n_hosts} host(s))")

    payload = json.dumps(results, indent=2, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        console.print(f"[green]Results written to[/] {args.output}")
    if args.json:
        console.print_json(payload)
    return EXIT_OK


# ─────────────────────────── report ────────────────────────────


def cmd_report(args) -> int:
    from .report_cli import cmd_report as _impl

    return _impl(args)


# ─────────────────────────── config ─────────────────────────────


def cmd_config(args) -> int:
    from .config_show import cmd_config as _impl

    return _impl(args)


LAB_SERVICE_URLS = [
    ("SSH (weak creds)", "ssh://127.0.0.1:2222", "root / labpass123"),
    ("Tomcat manager", "http://127.0.0.1:8080/manager/html", "tomcat / tomcat"),
    ("Weblogic (7001)", "http://127.0.0.1:7001/console", "—"),
    ("Struts2 demo", "http://127.0.0.1:8081/", "—"),
    ("Postgres", "postgresql://127.0.0.1:5432", "postgres / postgres"),
    ("Redis", "redis://127.0.0.1:6379", "no auth (lab)"),
    ("Web dashboard", "http://127.0.0.1:5000", "after `wormy run --web`"),
]


def _lab_compose(root: str, expanded: bool = False) -> str:
    return os.path.join(root, EXPANDED_COMPOSE_FILE if expanded else LAB_COMPOSE_FILE)


def _print_lab_urls() -> int:
    """Print the lab services cheat-sheet (works with or without the lab up)."""
    t = Table(title="Lab services (bound to 127.0.0.1)", border_style="bright_blue")
    t.add_column("Service", style="cyan")
    t.add_column("URL", style="white")
    t.add_column("Credentials", style="yellow")
    for name, url, creds in LAB_SERVICE_URLS:
        t.add_row(name, url, creds)
    console.print(t)
    return EXIT_OK


def _docker(args: list[str], root: str, expanded: bool = False) -> int:
    compose = _lab_compose(root, expanded)
    if not shutil.which("docker"):
        err_console.print("[red]docker CLI not found.[/] Install Docker and retry.")
        return EXIT_ERROR
    if not os.path.isfile(compose):
        err_console.print(f"[red]Compose file not found:[/] {compose}")
        return EXIT_ERROR
    cmd = ["docker", "compose", "-f", compose] + args
    console.print(f"[dim]$ {' '.join(cmd)}[/]")
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


def cmd_lab(args) -> int:
    root = _find_repo_root()
    if args.action != "urls":
        if root is None:
            err_console.print(
                f"[red]'{LAB_COMPOSE_FILE}' not found.[/] Run from the project root "
                "or set WORMY_LAB_DIR."
            )
            return EXIT_ERROR
        expanded = args.expanded
        if args.action == "up":
            console.print(f"[green]Starting lab[/] ({'expanded' if expanded else 'standard'})...")
            rc = _docker(["up", "-d", "--build"], root, expanded)
            if rc == EXIT_OK:
                _print_lab_urls()
            return rc
        if args.action == "down":
            console.print("[green]Stopping lab...[/]")
            return _docker(["down", "-v", "--remove-orphans"], root, expanded)
        if args.action == "rebuild":
            console.print("[green]Rebuilding lab from scratch...[/]")
            _docker(["down", "-v", "--remove-orphans"], root, expanded)
            return _docker(["up", "-d", "--build", "--force-recreate"], root, expanded)
        if args.action == "status":
            return _docker(
                ["ps", "--format", "table {{.Name}}\t{{.Service}}\t{{.Status}}\t{{.Ports}}"],
                root,
                expanded,
            )

    return _print_lab_urls()


# ─────────────────────────── train ──────────────────────────────


def cmd_train(args) -> int:
    kinds = ["rl", "classifier", "evasion"] if args.kind == "all" else [args.kind]

    if args.kind == "rl" or args.kind == "all":
        if args.list_scenarios or args.status:
            cmd = [sys.executable, "-m", "training.realistic_training"]
            if args.list_scenarios:
                cmd.append("--list-scenarios")
            if args.status:
                cmd.append("--status")
            return subprocess.call(cmd)
        cmd = [
            sys.executable,
            "-m",
            "training.realistic_training",
            "--save-dir",
            args.save_dir,
        ]
        if args.scenarios:
            cmd += ["--scenarios"] + args.scenarios
        if args.episodes:
            cmd += ["--episodes", str(args.episodes)]
        console.print("[green]Training RL agent (curriculum)...[/]")
        return subprocess.call(cmd)

    trained = []
    for kind in kinds:
        try:
            if kind == "classifier":
                console.print("\n[cyan]Training Host Classifier...[/]")
                from ml_models.train_host_classifier import main as fn
            else:
                console.print("\n[cyan]Training Evasion Model...[/]")
                from ml_models.train_evasion_model import main as fn
            fn()
            trained.append(kind)
        except Exception as e:  # noqa: BLE001 — report and continue with other models
            err_console.print(f"[red]{kind} training failed:[/] {e}")
    console.print(
        f"\n[green]Trained:[/] {', '.join(trained)}" if trained else "[yellow]Nothing trained.[/]"
    )
    return EXIT_OK if trained else EXIT_ERROR


# ─────────────────────────── doctor ─────────────────────────────


def cmd_doctor(args) -> int:
    checks: list[tuple] = []  # (critical, name, ok, detail, hint)

    # Python version
    ok = sys.version_info >= (3, 10)
    checks.append(
        (True, "Python >= 3.10", ok, platform.python_version(), "upgrade to Python 3.10+")
    )

    # Core dependencies
    for mod, name in (
        ("rich", "rich (CLI output)"),
        ("yaml", "pyyaml (config)"),
        ("paramiko", "paramiko (SSH)"),
        ("requests", "requests (HTTP)"),
        ("psutil", "psutil (host stats)"),
        ("flask", "flask (web dashboard)"),
        ("scapy", "scapy (network)"),
        ("networkx", "networkx (topology)"),
    ):
        import importlib.util

        spec = importlib.util.find_spec(mod)
        checks.append(
            (
                False,
                name,
                spec is not None,
                "installed" if spec else "missing",
                f"pip install {mod}",
            )
        )

    # torch
    try:
        import torch

        checks.append((False, "torch (RL engine)", True, torch.__version__, ""))
        checks.append(
            (
                False,
                "CUDA (optional)",
                torch.cuda.is_available(),
                "available" if torch.cuda.is_available() else "CPU only",
                "",
            )
        )
    except Exception as e:  # noqa: BLE001
        checks.append((False, "torch (RL engine)", False, str(e)[:60], "pip install torch"))

    # feature geometry (training == inference)
    try:
        from rl_engine.features import FEATURES_PER_HOST

        checks.append(
            (
                True,
                "Feature geometry (15/host)",
                FEATURES_PER_HOST == 15,
                f"{FEATURES_PER_HOST} features/host",
                "reinstall rl_engine",
            )
        )
    except Exception as e:  # noqa: BLE001
        checks.append((True, "Feature geometry (15/host)", False, str(e)[:60], "check rl_engine"))

    # Docker
    docker_ok = shutil.which("docker") is not None
    checks.append(
        (False, "Docker CLI", docker_ok, shutil.which("docker") or "not found", "install docker")
    )
    if docker_ok:
        try:
            out = subprocess.run(
                ["docker", "compose", "version"], capture_output=True, text=True, timeout=20
            )
            checks.append(
                (
                    False,
                    "Docker compose v2",
                    out.returncode == EXIT_OK,
                    (out.stdout or "unavailable").strip().splitlines()[0][:60],
                    "install docker-compose-plugin",
                )
            )
        except Exception:  # noqa: BLE001
            checks.append((False, "Docker compose v2", False, "call failed", ""))

    # Lab compose file
    root = _find_repo_root()
    checks.append(
        (
            False,
            "Lab compose file",
            root is not None,
            root or "not found",
            "run from project root or set WORMY_LAB_DIR",
        )
    )

    # Default config loads & validates
    try:
        from configs.config import Config

        cfg = Config()
        checks.append((True, "Default config", bool(cfg.validate()), "valid", ""))
    except Exception as e:  # noqa: BLE001
        checks.append((True, "Default config", False, str(e)[:60], "check configs/"))

    # Writable runtime dirs
    for d in ("logs", "reports"):
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".doctor_probe")
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            checks.append((False, f"'{d}/' writable", True, "ok", ""))
        except Exception as e:  # noqa: BLE001
            checks.append((False, f"'{d}/' writable", False, str(e)[:40], "check permissions"))

    # Report
    t = Table(title=f"{PROGRAM} doctor — environment check", border_style="bright_blue")
    t.add_column("")
    t.add_column("Check", style="cyan")
    t.add_column("Status")
    t.add_column("Detail", max_width=48)
    t.add_column("Hint", style="dim", max_width=32)
    failed_critical = 0
    failed_optional = 0
    for critical, name, ok, detail, hint in checks:
        if ok:
            mark, style = "✓", "green"
        elif critical:
            mark, style = "✗", "red"
        else:
            mark, style = "!", "yellow"
        if not ok and critical:
            failed_critical += 1
        elif not ok:
            failed_optional += 1
        if ok:
            status_txt = "[green]ok[/]"
        elif critical:
            status_txt = "[red]FAIL[/]"
        else:
            status_txt = "[yellow]warn[/]"
        t.add_row(
            f"[{style}]{mark}[/]",
            name,
            status_txt,
            detail,
            hint if not ok else "",
        )
    console.print(t)

    ok_count = len(checks) - failed_critical - failed_optional
    if failed_critical:
        err_console.print(
            f"[red]{failed_critical} critical check(s) failed "
            f"({ok_count}/{len(checks)} passed).[/]"
        )
        return EXIT_ERROR
    if failed_optional:
        console.print(
            f"[yellow]Environment usable with warnings:[/] "
            f"{failed_optional} optional check(s) failed "
            f"({ok_count}/{len(checks)} passed). See hints above."
        )
        return EXIT_OK
    console.print(f"[green]Environment ready.[/] ({ok_count}/{len(checks)} checks passed)")
    return EXIT_OK


# ─────────────────────────── shell ──────────────────────────────


def cmd_shell(args) -> int:
    from . import WormCore
    from .shell import InteractiveCLI

    # Fail fast: reject invalid cap values BEFORE booting the engine
    # (same contract as `wormy run`).
    err = _validate_cap_overrides(args)
    if err:
        err_console.print(f"[red]{err}[/]")
        return EXIT_USAGE

    worm = WormCore(
        config_file=args.config,
        use_cli_monitor=False,
        profile=args.profile,
        dry_run=args.dry_run,
        interactive=True,
    )
    if args.target:
        err = _validate_targets(args.target)
        if err:
            err_console.print(f"[red]{err}[/]")
            return EXIT_USAGE
        _apply_target_override(worm, args.target)
    if args.max_infections is not None or args.max_runtime is not None:
        _apply_cap_overrides(worm, args)
    try:
        InteractiveCLI(worm).cmdloop()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        worm.shutdown()
    return EXIT_OK


# ─────────────────────────── version ────────────────────────────


def cmd_version(args) -> int:
    if args.json:
        print(
            json.dumps(
                {
                    "wormy": __version__,
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                }
            )
        )
    else:
        print(
            f"{PROGRAM} {__version__} (python {platform.python_version()} on {platform.system().lower()})"
        )
    return EXIT_OK


# ─────────────────────────── parser ─────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=f"Wormy v{__version__} — ML-driven network propagation platform "
        "for authorized security labs.",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def common(p, with_profile=True):
        p.add_argument("--config", type=str, help="path to a YAML config file")
        if with_profile:
            p.add_argument(
                "--profile",
                type=str,
                choices=["stealth", "aggressive", "audit", "lab_docker"],
                help="configuration profile",
            )
        p.add_argument(
            "--target",
            nargs="+",
            metavar="CIDR",
            help="override config target ranges (e.g. 10.0.0.0/24)",
        )

    # run
    p = sub.add_parser(
        "run",
        help="launch the propagation engine",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    common(p)
    p.add_argument("--dry-run", action="store_true", help="simulate; no real exploits are executed")
    p.add_argument("--scan-only", action="store_true", help="reconnaissance only, then exit")
    p.add_argument(
        "--max-infections",
        type=int,
        metavar="N",
        help="per-run override of the propagation.max_infections safety cap",
    )
    p.add_argument(
        "--max-runtime",
        type=int,
        metavar="HOURS",
        help="per-run override of the safety.max_runtime_hours cap",
    )
    p.add_argument("--kill-switch", metavar="CODE", help="activate kill switch with CODE and exit")
    p.add_argument("--no-monitor", action="store_true", help="disable the live CLI monitor")
    p.add_argument("--no-geofence", action="store_true", help="disable geofence check (labs only)")
    p.add_argument("--interactive", "-i", action="store_true", help="enter the REPL after startup")
    p.add_argument("--web", action="store_true", help="start the web dashboard in the background")
    p.add_argument(
        "--web-port", type=int, default=5000, metavar="PORT", help="dashboard port (default 5000)"
    )
    p.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help=f"confirm written authorization for live mode (or set {AUTH_ENV_VAR}=1)",
    )
    p.set_defaults(func=cmd_run)

    # scan
    p = sub.add_parser(
        "scan",
        help="reconnaissance only (no exploitation)",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    common(p)
    p.add_argument(
        "--basic", action="store_true", help="use the basic scanner instead of the professional one"
    )
    p.add_argument("--json", action="store_true", help="print results as JSON to stdout")
    p.add_argument("--output", "-o", metavar="FILE", help="write results to a JSON file")
    p.add_argument(
        "--csv",
        metavar="FILE",
        help="write results as CSV for spreadsheets (use '-' for stdout)",
    )
    p.set_defaults(func=cmd_scan)

    # report
    p = sub.add_parser(
        "report",
        help="inspect & export engagement reports",
        epilog=REPORT_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list", "show", "html", "compare", "prune"],
        help="report operation (default: list)",
    )
    p.add_argument(
        "report_id",
        nargs="?",
        default="latest",
        metavar="ID1",
        help="report id (timestamp), file, or 'latest' (default)",
    )
    p.add_argument(
        "report_id2",
        nargs="?",
        default=None,
        metavar="ID2",
        help="second id for 'compare' (the older report is the baseline)",
    )
    p.add_argument(
        "--reports-dir",
        metavar="DIR",
        help="reports directory (default: ./reports, $WORMY_REPORTS_DIR)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="machine-readable output (list/show/compare/prune)",
    )
    p.add_argument("--output", "-o", metavar="FILE", help="output path for the HTML export")
    p.add_argument(
        "--metrics",
        metavar="K1,K2",
        help="compare only these metrics — keys (infected, success_rate, ...) or labels",
    )
    p.add_argument(
        "--keep",
        type=int,
        metavar="N",
        default=None,
        help="prune: keep the newest N reports (default: 20)",
    )
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="prune: delete without the confirmation prompt (scripts)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="prune: preview the deletion plan without touching anything",
    )
    p.set_defaults(func=cmd_report)

    # config
    p = sub.add_parser(
        "config",
        help="inspect the effective configuration",
        epilog=CONFIG_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("action", nargs="?", default="show", choices=["show"], help="config operation")
    p.add_argument("--config", type=str, help="path to a YAML config file")
    p.add_argument(
        "--profile",
        type=str,
        choices=sorted(PROFILE_NAMES),
        help="configuration profile to apply before rendering",
    )
    p.add_argument(
        "--target",
        nargs="+",
        metavar="CIDR",
        help="target override, to preview what the engine would scan",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_config)

    # lab
    p = sub.add_parser(
        "lab",
        help="manage the Docker vulnerability lab",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "action",
        choices=["up", "down", "status", "rebuild", "urls"],
        help="lab action (urls: print service cheat-sheet)",
    )
    p.add_argument(
        "--expanded", action="store_true", help="use the expanded 15-service compose file"
    )
    p.set_defaults(func=cmd_lab)

    # train
    p = sub.add_parser(
        "train",
        help="train ML models",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "kind",
        nargs="?",
        default="all",
        choices=["rl", "classifier", "evasion", "all"],
        help="model to train (default: all)",
    )
    p.add_argument("--scenarios", nargs="+", help="RL scenario names (curriculum order by default)")
    p.add_argument("--episodes", type=int, help="episodes per RL scenario")
    p.add_argument("--save-dir", default="saved/rl_agent", help="RL checkpoint directory")
    p.add_argument("--list-scenarios", action="store_true", help="list RL scenarios and exit")
    p.add_argument("--status", action="store_true", help="show RL training status and exit")
    p.set_defaults(func=cmd_train)

    # doctor
    p = sub.add_parser(
        "doctor",
        help="environment health check",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.set_defaults(func=cmd_doctor)

    # shell
    p = sub.add_parser(
        "shell",
        help="interactive REPL with live status",
        epilog=EPILOG_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    common(p)
    p.add_argument("--dry-run", action="store_true", help="simulate; no real exploits are executed")
    p.add_argument(
        "--max-infections",
        type=int,
        metavar="N",
        help="override propagation.max_infections for this session",
    )
    p.add_argument(
        "--max-runtime",
        type=int,
        metavar="HOURS",
        help="override safety.max_runtime_hours for this session",
    )
    p.set_defaults(func=cmd_shell)

    # version
    p = sub.add_parser("version", help="print version information")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "func", None) is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/]")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
