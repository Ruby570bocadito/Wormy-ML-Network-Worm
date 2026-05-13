"""
Integration Tests - End-to-end tests against Docker lab
Tests the complete worm propagation flow
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDockerLabIntegration(unittest.TestCase):
    """Integration tests for Docker lab environment"""

    def test_docker_compose_exists(self):
        """Test Docker Compose file exists"""
        self.assertTrue(os.path.exists("docker-lab/docker-compose.yml"))

    def test_docker_lab_services(self):
        """Test Docker lab has expected services"""
        with open("docker-lab/docker-compose.yml") as f:
            content = f.read()
        expected_services = ["metasploitable", "dvwa", "mysql", "postgres", "redis", "mongodb"]
        for svc in expected_services:
            self.assertIn(svc, content.lower(), f"Missing service: {svc}")

    def test_config_files_exist(self):
        """Test all configuration files exist"""
        configs = [
            "configs/config.py",
            "configs/config.yaml",
            "configs/config_simulation.yaml",
            "configs/config_msf.yaml",
        ]
        for cfg in configs:
            self.assertTrue(os.path.exists(cfg), f"Missing config: {cfg}")

    def test_wordlists_loaded(self):
        """Test wordlists can be loaded"""
        from exploits.credential_manager import CredentialManager

        cm = CredentialManager(wordlist_dir="wordlists")
        self.assertGreater(cm.stats["total_loaded"], 0)

    def test_exploit_manager_init(self):
        """Test exploit manager initializes"""
        from configs.config import Config
        from exploits.exploit_manager import ExploitManager

        config = Config()
        em = ExploitManager(config)
        self.assertGreater(len(em.exploits), 0)

    def test_scanner_init(self):
        """Test scanner initializes"""
        from configs.config import Config
        from scanner import IntelligentScanner

        config = Config()
        scanner = IntelligentScanner(config)
        self.assertIsNotNone(scanner)

    def test_rl_agent_init(self):
        """Test RL agent initializes"""
        from rl_engine import PropagationAgent

        agent = PropagationAgent(state_size=300, action_size=50, use_dqn=True)
        self.assertIsNotNone(agent)

    def test_knowledge_graph_init(self):
        """Test knowledge graph initializes"""
        from core.knowledge_graph import NetworkKnowledgeGraph

        kg = NetworkKnowledgeGraph()
        self.assertIsNotNone(kg)

    def test_host_monitor_init(self):
        """Test host monitor initializes"""
        from monitoring.host_monitor import HostMonitor

        hm = HostMonitor()
        self.assertIsNotNone(hm)

    def test_credential_pivoting(self):
        """Test credential pivoting workflow"""
        from exploits.credential_manager import CredentialManager

        cm = CredentialManager(wordlist_dir="wordlists")

        # Add discovered credential
        cm.add_discovered_credential("admin", "P@ssw0rd", source="test")

        # Should be available for pivoting
        discovered = cm.get_discovered_credentials()
        self.assertTrue(any(u == "admin" and p == "P@ssw0rd" for u, p in discovered))

    def test_exploit_chain_building(self):
        """Test exploit chain building"""
        from exploits.exploit_engine import ExploitChain, VulnerabilityScanner

        vs = VulnerabilityScanner()
        ec = ExploitChain(vs)

        target = {
            "ip": "10.0.0.1",
            "open_ports": [6379, 445, 22],
            "banners": {},
            "services": {"445": "SMB"},
            "os_guess": "Windows Server 2019",
        }

        chain = ec.build_chain(target)
        self.assertGreater(len(chain), 0)
        self.assertEqual(chain[0]["phase"], "initial_access")

    def test_lateral_movement_technique_selection(self):
        """Test lateral movement technique selection"""
        from post_exploit.lateral_movement import LateralMovementEngine

        lm = LateralMovementEngine()

        # SSH with password
        t1 = lm._select_best_technique([22], "Linux", {"username": "root", "password": "toor"})
        self.assertEqual(t1, "ssh_pivot")

        # WinRM
        t2 = lm._select_best_technique([5985], "Windows", {"username": "admin", "password": "pass"})
        self.assertEqual(t2, "winrm")

        # Pass-the-Hash
        t3 = lm._select_best_technique([445], "Windows", {"username": "admin", "hash": "abc"})
        self.assertEqual(t3, "pass_the_hash")

    def test_ids_evasion(self):
        """Test IDS evasion techniques"""
        from evasion.ids_evasion import IDSEvasionEngine

        ie = IDSEvasionEngine()

        # Test evasion
        payload = b"GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
        evaded, info = ie.evade_ids("10.0.0.1", 80, payload, "http")
        self.assertGreater(len(info["techniques_applied"]), 0)

        # Test decoy generation
        decoys = ie.generate_decoy_traffic("10.0.0.1", count=5)
        self.assertEqual(len(decoys), 5)

        # Test adaptive evasion
        strategy = ie.adaptive_evasion("10.0.0.1", [])
        self.assertIn("strategy", strategy)
        self.assertIn("risk_level", strategy)


class TestRealisticScenarios(unittest.TestCase):
    """Test realistic training scenarios"""

    def test_small_office_scenario(self):
        """Test Small Office scenario"""
        from training.scenarios import get_scenario

        s = get_scenario("small_office")
        hosts = s.generate()
        self.assertEqual(len(hosts), 10)
        self.assertGreater(s.get_expected_infections(), 0)

    def test_enterprise_scenario(self):
        """Test Enterprise scenario"""
        from training.scenarios import get_scenario

        s = get_scenario("enterprise")
        hosts = s.generate()
        self.assertEqual(len(hosts), 30)
        self.assertGreater(s.get_expected_infections(), 0)

    def test_datacenter_scenario(self):
        """Test Datacenter scenario"""
        from training.scenarios import get_scenario

        s = get_scenario("datacenter")
        hosts = s.generate()
        self.assertEqual(len(hosts), 50)
        self.assertGreater(s.get_expected_infections(), 0)

    def test_cloud_scenario(self):
        """Test Cloud scenario"""
        from training.scenarios import get_scenario

        s = get_scenario("cloud")
        hosts = s.generate()
        self.assertEqual(len(hosts), 40)
        self.assertGreater(s.get_expected_infections(), 0)

    def test_iot_scenario(self):
        """Test IoT scenario"""
        from training.scenarios import get_scenario

        s = get_scenario("iot")
        hosts = s.generate()
        self.assertEqual(len(hosts), 25)
        self.assertGreater(s.get_expected_infections(), 0)


class TestDashboards(unittest.TestCase):
    """Test web dashboards"""

    def test_armitage_dashboard_init(self):
        """Test Armitage Dashboard initializes"""
        from monitoring.armitage_dashboard import ArmitageDashboard

        ad = ArmitageDashboard()
        self.assertIsNotNone(ad)

    def test_web_dashboard_init(self):
        """Test Web Dashboard initializes"""
        from monitoring.web_dashboard import WebDashboard

        wd = WebDashboard()
        self.assertIsNotNone(wd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
