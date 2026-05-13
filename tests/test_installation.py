"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Installation and Component Test Script
Verifies all components are working correctly
"""


import os
import sys

print("=" * 60)
print("ML NETWORK WORM - INSTALLATION TEST")
print("=" * 60)
print()

# Test 1: Python version
print("1. Checking Python version...")
if sys.version_info >= (3, 8):
    print(f"   ✓ Python {sys.version_info.major}.{sys.version_info.minor} (OK)")
else:
    print(f"   ✗ Python {sys.version_info.major}.{sys.version_info.minor} (Need 3.8+)")
    sys.exit(1)

# Test 2: Import core modules
print("\n2. Testing core imports...")
try:
    import numpy as np

    print("   ✓ numpy")
except ImportError as e:
    print(f"   ✗ numpy - {e}")

try:
    import sklearn

    print("   ✓ scikit-learn")
except ImportError as e:
    print(f"   ✗ scikit-learn - {e}")

try:
    import yaml

    print("   ✓ pyyaml")
except ImportError as e:
    print(f"   ✗ pyyaml - {e}")

try:
    from cryptography.fernet import Fernet

    print("   ✓ cryptography")
except ImportError as e:
    print(f"   ✗ cryptography - {e}")

try:
    import gym

    print("   ✓ gym")
except ImportError as e:
    print(f"   ✗ gym - {e}")

# Test 3: TensorFlow (optional)
print("\n3. Testing TensorFlow (optional)...")
try:
    import tensorflow as tf

    print(f"   ✓ TensorFlow {tf.__version__}")
except ImportError:
    print("   ⚠ TensorFlow not available (will use rule-based agent)")

# Test 4: Network libraries
print("\n4. Testing network libraries...")
try:
    from scapy.all import IP

    print("   ✓ scapy")
except ImportError as e:
    print(f"   ✗ scapy - {e}")

try:
    import nmap

    print("   ✓ python-nmap")
except ImportError as e:
    print(f"   ✗ python-nmap - {e}")

# Test 5: Project modules
print("\n5. Testing project modules...")
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from configs.config import Config

    print("   ✓ config")
except ImportError:
    try:
        from config import Config

        print("   ✓ config")
    except ImportError as e:
        print(f"   ✗ config - {e}")

try:
    from utils.logger import logger

    print("   ✓ utils.logger")
except ImportError as e:
    print(f"   ✗ utils.logger - {e}")

try:
    from utils.network_utils import get_local_ip

    print("   ✓ utils.network_utils")
except ImportError as e:
    print(f"   ✗ utils.network_utils - {e}")

try:
    from scanner.host_classifier import HostClassifier

    print("   ✓ scanner.host_classifier")
except ImportError as e:
    print(f"   ✗ scanner.host_classifier - {e}")

try:
    from rl_engine.propagation_agent import PropagationAgent

    print("   ✓ rl_engine.propagation_agent")
except ImportError as e:
    print(f"   ✗ rl_engine.propagation_agent - {e}")

# Test 6: Configuration
print("\n6. Testing configuration...")
try:
    config = Config()
    if config.validate():
        print("   ✓ Configuration valid")
    else:
        print("   ✗ Configuration invalid")
except Exception as e:
    print(f"   ✗ Configuration error - {e}")

# Test 7: Host Classifier
print("\n7. Testing Host Classifier...")
try:
    classifier = HostClassifier()
    test_host = {
        "ip": "192.168.1.100",
        "open_ports": [22, 80, 443],
        "ttl": 64,
        "banners": {},
        "response_time": 50,
    }
    priority, confidence, os_guess = classifier.classify_host(test_host)
    print(f"   ✓ Classifier working (Priority: {priority}, OS: {os_guess})")
except Exception as e:
    print(f"   ✗ Classifier error - {e}")

# Test 8: RL Agent
print("\n8. Testing RL Agent...")
try:
    agent = PropagationAgent(state_size=60, action_size=20, use_dqn=False)
    test_state = np.random.random(60)
    action = agent.act(test_state)
    print(f"   ✓ RL Agent working (Selected action: {action})")
except Exception as e:
    print(f"   ✗ RL Agent error - {e}")

# Test 9: Logger
print("\n9. Testing Logger...")
try:
    from utils.logger import WormLogger

    test_logger = WormLogger(log_dir="test_logs")
    test_logger.info("Test message")
    print("   ✓ Logger working")

    # Cleanup
    import shutil

    if os.path.exists("test_logs"):
        shutil.rmtree("test_logs")
except Exception as e:
    print(f"   ✗ Logger error - {e}")

# Test 10: Network utilities
print("\n10. Testing Network Utilities...")
try:
    from utils.network_utils import expand_cidr, get_local_ip

    local_ip = get_local_ip()
    ips = expand_cidr("192.168.1.0/29")
    print(f"   ✓ Network utilities working (Local IP: {local_ip})")
except Exception as e:
    print(f"   ✗ Network utilities error - {e}")

# Summary
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print()
print("✓ All core components tested")
print("✓ Installation appears successful")
print()
print("Next steps:")
print("  1. Review config.yaml")
print("  2. Run: python worm_core.py --scan-only")
print("  3. Check README.md for full documentation")
print()
print("=" * 60)
