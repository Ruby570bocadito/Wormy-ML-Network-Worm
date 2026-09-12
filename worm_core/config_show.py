"""
Wormy — effective configuration inspection (``wormy config show``).

Profiles (``stealth`` / ``aggressive`` / ``audit`` / ``lab_docker``)
silently change safety-relevant parameters — infection caps, delays,
runtime limits. Until now there was no product surface to answer "what
exactly will the engine use for THIS invocation?": operators had to
read YAML + source code and mentally replay the override order.

``wormy config show`` builds the configuration exactly the way the
engine would (config file → profile overrides → CLI target override)
and renders it, marking every value changed by the profile. The kill
switch code is shown on purpose: the operator needs it to stop the
engine. ``--json`` emits the effective configuration as a nested dict.

Read-only: nothing is written, no engine is started.

Exit codes mirror the CLI contract: 0 ok · 1 error · 2 usage.
"""

from __future__ import annotations

import dataclasses
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ._version import __version__
from .config_profiles import CONFIG_PROFILES, apply_profile

console = Console()
err_console = Console(stderr=True)

# Mirror of worm_core.cli exit codes.
EXIT_OK = 0
EXIT_ERROR = 1

# (section, field, human label) rows rendered per group. Curated instead
# of dumping every dataclass field: shows what operators actually tune.
_GROUPS = {
    "Network": (
        ("network", "target_ranges", "Target ranges"),
        ("network", "scan_timeout", "Scan timeout (s)"),
        ("network", "max_threads", "Max threads"),
        ("network", "excluded_ips", "Excluded IPs"),
    ),
    "Propagation & safety": (
        ("propagation", "max_infections", "Max infections (cap)"),
        ("propagation", "propagation_delay", "Propagation delay (s)"),
        ("propagation", "persistence_enabled", "Persistence"),
        ("propagation", "mutation_enabled", "Polymorphic mutation"),
        ("safety", "max_runtime_hours", "Max runtime (hours)"),
        ("safety", "geofence_enabled", "Geofence"),
        ("safety", "allowed_networks", "Allowed networks"),
        ("safety", "kill_switch_enabled", "Kill switch"),
        ("safety", "kill_switch_code", "Kill switch code"),
    ),
    "Evasion & stealth": (
        ("evasion", "stealth_mode", "Stealth mode"),
        ("evasion", "randomize_timing", "Randomize timing"),
        ("evasion", "max_scan_rate", "Max scan rate (pps)"),
        ("evasion", "detect_ids", "Detect IDS"),
        ("evasion", "detect_honeypots", "Detect honeypots"),
        ("evasion", "encrypt_traffic", "Encrypt traffic"),
    ),
    "Command & control": (
        ("c2", "c2_server", "C2 server"),
        ("c2", "c2_port", "C2 port"),
        ("c2", "c2_protocol", "C2 protocol"),
        ("c2", "beacon_interval", "Beacon interval (s)"),
    ),
    "ML": (
        ("ml", "use_pretrained", "Use pretrained models"),
        ("ml", "online_learning", "Online learning"),
        ("ml", "use_thompson_sampling", "Thompson Sampling ensemble"),
        ("ml", "rl_agent_path", "RL agent path"),
    ),
}


def _build_effective_config(args):
    """Build the Config exactly like the engine would for this invocation."""
    # Lazy like cli.py: the configs.config machinery (yaml, logger) loads
    # only when `wormy config` actually runs, not at CLI startup.
    from configs.config import Config

    config_file = getattr(args, "config", None)
    profile = getattr(args, "profile", None)
    targets = getattr(args, "target", None)

    # Base snapshot (before profile) to compute the diff markers.
    base = Config(config_file)
    effective = Config(config_file)

    applied: list[str] = []
    if profile:
        applied = apply_profile(effective, profile)

    if targets:
        effective.network.target_ranges = list(targets)

    return base, effective, applied


def _fmt(value) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "—"
    if value is None:
        return "—"
    return str(value)


def _effective_dict(config) -> dict:
    """Nested plain-dict view of a Config (dataclasses → dicts)."""
    out = {}
    for section in (
        "network",
        "exploit",
        "propagation",
        "evasion",
        "c2",
        "ml",
        "safety",
        "metasploit",
    ):
        obj = getattr(config, section, None)
        if obj is None:
            continue
        if dataclasses.is_dataclass(obj):
            out[section] = dataclasses.asdict(obj)
        else:
            out[section] = {k: getattr(obj, k) for k in dir(obj) if not k.startswith("_")}
    return out


def render_show(base, effective, applied: list[str], args) -> None:
    profile = getattr(args, "profile", None)
    config_file = getattr(args, "config", None)
    targets = getattr(args, "target", None)

    subtitle = []
    if config_file:
        subtitle.append(f"config file: {config_file}")
    else:
        subtitle.append("config file: defaults")
    if profile:
        subtitle.append(f"profile: {profile}")
    if targets:
        subtitle.append(f"targets: {', '.join(targets)}")

    console.print(
        Panel(
            "\n".join(subtitle),
            title=f"{__version__} — effective configuration",
            border_style="bright_blue",
        )
    )

    applied_set = set(applied)
    for group, rows in _GROUPS.items():
        t = Table(title=group, border_style="bright_blue", show_header=False)
        t.add_column("setting", style="cyan")
        t.add_column("value")
        for section, field, label in rows:
            eff_obj = getattr(effective, section, None)
            base_obj = getattr(base, section, None)
            if eff_obj is None or not hasattr(eff_obj, field):
                continue
            value = _fmt(getattr(eff_obj, field))
            changed = f"{section}.{field}" in applied_set
            # Values overridden by the profile carry the (profile) marker.
            if changed:
                t.add_row(label, f"[bold yellow]{value}[/] [dim]\\[profile][/]")
            else:
                t.add_row(label, value)
        if t.row_count:
            console.print(t)

    if not applied:
        console.print(
            "[dim]No profile applied — values come from the config file or "
            "defaults. Try [cyan]wormy config show --profile stealth[/].[/]"
        )
    console.print(
        "[dim]Read-only view. Launch with [cyan]wormy run --dry-run[/] "
        "to use this configuration in simulation.[/]"
    )


def cmd_config(args) -> int:
    """CLI entrypoint for `wormy config`."""
    action = (getattr(args, "action", None) or "show").lower()
    if action != "show":
        err_console.print(f"[red]Unknown config action:[/] {action}")
        return 2

    try:
        base, effective, applied = _build_effective_config(args)
    except Exception as e:  # noqa: BLE001 — invalid config file must fail loudly
        err_console.print(f"[red]Cannot load configuration:[/] {e}")
        return EXIT_ERROR

    profile = getattr(args, "profile", None)
    if profile and profile not in CONFIG_PROFILES:
        # argparse already restricts choices; guard programmatic callers.
        err_console.print(f"[red]Unknown profile:[/] {profile}")
        return EXIT_ERROR

    if getattr(args, "json", False):
        payload = _effective_dict(effective)
        payload["_meta"] = {
            "cli_version": __version__,
            "config_file": getattr(args, "config", None),
            "profile": profile,
            "profile_overrides": applied,
        }
        print(json.dumps(payload, indent=2, default=str))
        return EXIT_OK

    render_show(base, effective, applied, args)
    return EXIT_OK
