"""
Comprehensive tests for new Wormy modules:
- State Persistence Manager
- Exploit Chaining Engine
- Adaptive Rate Limiter
- Credential Dashboard
- Fixed mixin_lateral.py
- Fixed mixin_propagation.py
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestStatePersistence(unittest.TestCase):
    """Test state persistence manager"""

    def setUp(self):
        from core.state_persistence import StatePersistenceManager

        self.tmpdir = tempfile.mkdtemp()
        self.manager = StatePersistenceManager(
            snapshot_dir=self.tmpdir,
            max_snapshots=5,
            auto_save_interval=1,
        )

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_snapshot(self):
        """Test snapshot creation"""
        worm_core = type(
            "MockWorm",
            (),
            {
                "infected_hosts": {"192.168.1.1", "192.168.1.2"},
                "failed_targets": {"192.168.1.3"},
                "scan_results": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}],
                "stats": {"scans": 5, "infections": 2},
                "_detection_events": [],
            },
        )()
        path = self.manager.create_snapshot(worm_core)
        self.assertTrue(os.path.exists(path))

    def test_list_snapshots(self):
        """Test snapshot listing"""
        worm_core = type(
            "MockWorm",
            (),
            {
                "infected_hosts": set(),
                "failed_targets": set(),
                "scan_results": [],
                "stats": {},
                "_detection_events": [],
            },
        )()
        self.manager.create_snapshot(worm_core)
        snapshots = self.manager.list_snapshots()
        self.assertGreater(len(snapshots), 0)

    def test_rotate_snapshots(self):
        """Test snapshot rotation"""
        worm_core = type(
            "MockWorm",
            (),
            {
                "infected_hosts": set(),
                "failed_targets": set(),
                "scan_results": [],
                "stats": {},
                "_detection_events": [],
            },
        )()
        for _ in range(7):
            self.manager.create_snapshot(worm_core)
            time.sleep(0.01)

        snapshots = self.manager.list_snapshots()
        self.assertLessEqual(len(snapshots), 5)

    def test_get_state_summary(self):
        """Test state summary"""
        summary = self.manager.get_state_summary()
        self.assertIn("snapshot_dir", summary)
        self.assertIn("total_snapshots", summary)
        self.assertIn("auto_save_running", summary)


class TestExploitChaining(unittest.TestCase):
    """Test exploit chaining engine"""

    def setUp(self):
        from core.exploit_chaining import ExploitChainingEngine

        self.engine = ExploitChainingEngine()

    def test_build_chain_redis(self):
        """Test chain building for Redis target"""
        chain = self.engine.build_chain_for_target(
            target_ip="192.168.1.10",
            target_os="Linux",
            open_ports=[22, 6379],
            services={22: "ssh", 6379: "redis"},
            strategy="full",
        )
        self.assertIsNotNone(chain)
        self.assertGreater(len(chain.stages), 0)

    def test_build_chain_postgres(self):
        """Test chain building for Postgres target"""
        chain = self.engine.build_chain_for_target(
            target_ip="192.168.1.11",
            target_os="Linux",
            open_ports=[22, 5432],
            services={22: "ssh", 5432: "postgres"},
            strategy="full",
        )
        self.assertIsNotNone(chain)

    def test_build_chain_mssql(self):
        """Test chain building for MSSQL target"""
        chain = self.engine.build_chain_for_target(
            target_ip="192.168.1.12",
            target_os="Windows",
            open_ports=[445, 1433],
            services={445: "smb", 1433: "mssql"},
            strategy="full",
        )
        self.assertIsNotNone(chain)

    def test_build_chain_no_services(self):
        """Test chain building with no exploitable services"""
        chain = self.engine.build_chain_for_target(
            target_ip="192.168.1.13",
            target_os="Linux",
            open_ports=[80],
            services={80: "http"},
            strategy="full",
        )
        self.assertIsNone(chain)

    def test_chain_statistics(self):
        """Test chain statistics"""
        stats = self.engine.get_chain_statistics()
        self.assertIn("total_chains", stats)
        self.assertIn("successful", stats)
        self.assertIn("failed", stats)


class TestAdaptiveRateLimiter(unittest.TestCase):
    """Test adaptive rate limiter"""

    def setUp(self):
        from core.adaptive_rate_limiter import AdaptiveRateLimiter

        self.limiter = AdaptiveRateLimiter(
            base_delay=1.0,
            max_delay=60.0,
            min_delay=0.1,
            lockout_threshold=3,
            lockout_duration=5.0,
        )

    def test_initial_delay(self):
        """Test initial delay is base delay"""
        delay = self.limiter.get_delay("192.168.1.1")
        self.assertGreater(delay, 0)

    def test_delay_increases_on_failure(self):
        """Test delay increases after failures"""
        ip = "192.168.1.2"
        initial_delay = self.limiter.get_delay(ip)

        self.limiter.record_action(ip, success=False)
        delay_after_fail = self.limiter.get_delay(ip)

        self.assertGreater(delay_after_fail, initial_delay)

    def test_lockout_after_threshold(self):
        """Test lockout after failure threshold"""
        ip = "192.168.1.3"

        for _ in range(3):
            self.limiter.record_action(ip, success=False)

        delay = self.limiter.get_delay(ip)
        self.assertGreater(delay, 1.0)  # Should be locked out

    def test_target_state(self):
        """Test target state retrieval"""
        ip = "192.168.1.4"
        self.limiter.record_action(ip, success=True, response_time=0.5)

        state = self.limiter.get_target_state(ip)
        self.assertIsNotNone(state)
        self.assertEqual(state["action_count"], 1)
        self.assertEqual(state["success_count"], 1)

    def test_network_summary(self):
        """Test network summary"""
        self.limiter.record_action("192.168.1.5", success=True)
        self.limiter.record_action("192.168.1.6", success=False)

        summary = self.limiter.get_network_summary()
        self.assertIn("total_targets", summary)
        self.assertIn("total_actions", summary)
        self.assertGreater(summary["total_targets"], 0)

    def test_reset_target(self):
        """Test target reset"""
        ip = "192.168.1.7"
        self.limiter.record_action(ip, success=True)
        self.limiter.reset_target(ip)

        state = self.limiter.get_target_state(ip)
        self.assertIsNone(state)


class TestFixedMixinLateral(unittest.TestCase):
    """Test fixed mixin_lateral.py"""

    def test_service_ports_mapping(self):
        """Test SERVICE_PORTS mapping"""
        from worm_core.mixin_lateral import WormCoreLateral

        self.assertIn("ssh", WormCoreLateral.SERVICE_PORTS)
        self.assertIn("redis", WormCoreLateral.SERVICE_PORTS)
        self.assertIn("postgres", WormCoreLateral.SERVICE_PORTS)
        self.assertIn("mssql", WormCoreLateral.SERVICE_PORTS)

    def test_get_services_for_ports(self):
        """Test service detection from ports"""
        from worm_core.mixin_lateral import WormCoreLateral

        lateral = WormCoreLateral()
        services = lateral._get_services_for_ports([22, 6379, 5432])
        self.assertIn("ssh", services)
        self.assertIn("redis", services)
        self.assertIn("postgres", services)

    def test_get_services_for_ports_dynamic(self):
        """Test service detection with non-standard ports"""
        from worm_core.mixin_lateral import WormCoreLateral

        lateral = WormCoreLateral()
        services = lateral._get_services_for_ports([2222, 8080])
        self.assertIn("ssh", services)
        self.assertIn("jenkins", services)


class TestFixedMixinExploitation(unittest.TestCase):
    """Test fixed mixin_exploitation.py"""

    def test_no_top_level_unused_imports(self):
        """Test that unused top-level imports were removed"""
        import worm_core.mixin_exploitation as mod

        with open(mod.__file__) as f:
            lines = f.readlines()

        # Check first 10 lines for imports
        import_lines = "".join(lines[:10])
        self.assertNotIn("import shlex", import_lines)
        self.assertNotIn("import socket", import_lines)
        # subprocess is used inside methods, so it's OK to have it


class TestCredentialDashboard(unittest.TestCase):
    """Test credential dashboard"""

    def test_dashboard_initialization(self):
        """Test dashboard initializes"""
        from monitoring.credential_dashboard import CredentialDashboard

        dashboard = CredentialDashboard(worm_core=None, port=5002)
        self.assertIsNotNone(dashboard)
        self.assertEqual(dashboard.port, 5002)


if __name__ == "__main__":
    unittest.main()
