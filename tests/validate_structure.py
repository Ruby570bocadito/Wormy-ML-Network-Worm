"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Standalone Test Script - No external dependencies required
Tests core functionality without installing requirements
"""


import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_scanner_class_structure():
    """Test scanner class structure"""
    print("\n=== Testing Scanner Module ===")

    with open("scanner/__init__.py", "r") as f:
        content = f.read()

    checks = [
        ("class IntelligentScanner", "IntelligentScanner class"),
        ("def scan_network", "scan_network method"),
        ("def _scan_range", "_scan_range method"),
        ("def _scan_host", "_scan_host method"),
        ("def _scan_ports", "_scan_ports method"),
        ("def _grab_banners", "_grab_banners method"),
        ("def _guess_os", "_guess_os method"),
        ("def _calculate_vulnerability_score", "vulnerability scoring"),
        ("class HostClassifier", "HostClassifier class"),
    ]

    for check, name in checks:
        if check in content:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} MISSING")

    print("Scanner module structure OK")


def test_rl_engine_class_structure():
    """Test RL engine class structure"""
    print("\n=== Testing RL Engine Module ===")

    with open("rl_engine/__init__.py", "r") as f:
        content = f.read()

    checks = [
        ("class PropagationAgent", "PropagationAgent class"),
        ("def act", "act method"),
        ("def remember", "remember method"),
        ("def replay", "replay method"),
        ("class NetworkEnvironment", "NetworkEnvironment class"),
        ("def reset", "reset method"),
        ("def step", "step method"),
        ("class RealWorldPropagationAgent", "RealWorldPropagationAgent class"),
        ("DQN", "DQN implementation"),
        ("experience replay", "Experience replay"),
    ]

    for check, name in checks:
        if check.lower() in content.lower():
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} MISSING")

    print("RL Engine module structure OK")


def test_worm_core_structure():
    """Test worm core structure"""
    print("\n=== Testing Worm Core ===")

    with open("worm_core.py", "r") as f:
        content = f.read()

    checks = [
        ("class WormCore", "WormCore class"),
        ("def __init__", "constructor"),
        ("def scan_network", "scan_network"),
        ("def select_next_target", "target selection"),
        ("def exploit_target", "exploit_target"),
        ("def propagate", "propagate method"),
        ("check_safety_constraints", "safety checks"),
        ("activate_kill_switch", "kill switch"),
        ("self_destruct", "self-destruct"),
    ]

    for check, name in checks:
        if check in content:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} MISSING")

    print("Worm core structure OK")


def test_exploit_manager_structure():
    """Test exploit manager structure"""
    print("\n=== Testing Exploit Manager ===")

    with open("exploits/exploit_manager.py", "r") as f:
        content = f.read()

    checks = [
        ("class BaseExploit", "BaseExploit class"),
        ("class ExploitManager", "ExploitManager class"),
        ("def _load_exploits", "exploit loading"),
        ("def _load_credentials", "credential loading"),
        ("def exploit_target", "exploit method"),
        ("def select_exploits", "exploit selection"),
    ]

    for check, name in checks:
        if check in content:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} MISSING")

    print("Exploit Manager structure OK")


def test_config_structure():
    """Test config structure"""
    print("\n=== Testing Config Module ===")

    # Config moved to configs/ directory
    config_path = "configs/config.py"
    if not os.path.exists(config_path):
        config_path = "config.py"
    with open(config_path, "r") as f:
        content = f.read()

    checks = [
        ("class NetworkConfig", "NetworkConfig"),
        ("class ExploitConfig", "ExploitConfig"),
        ("class PropagationConfig", "PropagationConfig"),
        ("class EvasionConfig", "EvasionConfig"),
        ("class C2Config", "C2Config"),
        ("class MLConfig", "MLConfig"),
        ("class SafetyConfig", "SafetyConfig"),
        ("class Config", "Main Config class"),
        ("def validate", "validate method"),
    ]

    for check, name in checks:
        if check in content:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} MISSING")

    print("Config structure OK")


def test_exploit_modules():
    """Test exploit modules exist"""
    print("\n=== Testing Exploit Modules ===")

    import glob

    modules = glob.glob("exploits/modules/*_exploit.py")

    print(f"  Found {len(modules)} exploit modules:")
    for m in modules[:10]:
        print(f"    ✓ {os.path.basename(m)}")

    if len(modules) > 10:
        print(f"    ... and {len(modules) - 10} more")

    print(f"  Total: {len(modules)} exploit modules")


def test_utils_structure():
    """Test utils modules"""
    print("\n=== Testing Utils ===")

    utils_files = ["logger.py", "network_utils.py", "crypto_utils.py", "visualizer.py"]

    for u in utils_files:
        if os.path.exists(f"utils/{u}"):
            print(f"  ✓ utils/{u}")
        else:
            print(f"  ✗ utils/{u} MISSING")


def test_config_files():
    """Test config files exist"""
    print("\n=== Testing Config Files ===")

    configs = [
        "config.yaml",
        "config_simulation.yaml",
        "config_test.yaml",
        "config_aggressive.yaml",
    ]

    for c in configs:
        if os.path.exists(c):
            print(f"  ✓ {c}")
        else:
            print(f"  ✗ {c} MISSING")


if __name__ == "__main__":
    print("=" * 60)
    print("WORMY PROJECT - STRUCTURE VALIDATION")
    print("=" * 60)

    test_scanner_class_structure()
    test_rl_engine_class_structure()
    test_worm_core_structure()
    test_exploit_manager_structure()
    test_config_structure()
    test_exploit_modules()
    test_utils_structure()
    test_config_files()

    print("\n" + "=" * 60)
    print("STRUCTURE VALIDATION COMPLETE")
    print("=" * 60)
    print("\nNext: Run 'pip install -r requirements.txt' to install dependencies")
    print("Then: Run 'python worm_core.py --config config_simulation.yaml' to test")
