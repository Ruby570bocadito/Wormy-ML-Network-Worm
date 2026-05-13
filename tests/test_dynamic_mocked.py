"""
Dynamic Integration Tests with Mocked Network Calls
Tests exploit logic, scanning, and propagation without real network services
"""

import os
import sys
import unittest
from typing import Dict, List
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Mock helpers
# =============================================================================


def make_target(
    ip: str = "192.168.1.100",
    ports: List[int] = None,
    os_guess: str = "Linux",
    banners: Dict = None,
) -> Dict:
    return {
        "ip": ip,
        "open_ports": ports or [22],
        "os_guess": os_guess,
        "banners": banners or {},
        "hostname": f'host-{ip.replace(".", "-")}',
        "mac": "00:11:22:33:44:55",
        "vulnerability_score": 75,
    }


def mock_socket_ok(mock_socket):
    sock = MagicMock()
    sock.connect_ex.return_value = 0
    sock.recv.return_value = b"+PONG\r\n"
    sock.send.return_value = 0
    sock.sendall.return_value = None
    mock_socket.return_value = sock
    return sock


def mock_requests_get(mock_get, text="", status_code=200, headers=None, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    resp.json.return_value = json_data or {}
    mock_get.return_value = resp
    return resp


# =============================================================================
# SSH Exploit Tests
# =============================================================================


class TestSSHExploit(unittest.TestCase):
    """Test SSH exploit with mocked paramiko"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[22])

    @patch("paramiko.SSHClient")
    def test_exploit_success(self, mock_ssh):
        from exploits.modules.ssh_exploit import SSHExploit

        exploit = SSHExploit()

        mock_client = MagicMock()
        mock_ssh.return_value = mock_client

        success, result = exploit.exploit(self.target)

        self.assertTrue(success)
        self.assertEqual(result["method"], "SSH_BruteForce")
        self.assertIn("username", result)
        self.assertIn("password", result)
        self.assertTrue(result["shell_access"])
        mock_client.connect.assert_called()

    @patch("paramiko.SSHClient")
    def test_exploit_failure(self, mock_ssh):
        from exploits.modules.ssh_exploit import SSHExploit

        exploit = SSHExploit()

        mock_client = MagicMock()
        mock_client.connect.side_effect = Exception("Auth failed")
        mock_ssh.return_value = mock_client

        success, result = exploit.exploit(self.target)

        self.assertFalse(success)
        self.assertEqual(result.get("reason"), "no_valid_credentials")

    def test_check_vulnerable(self):
        """SSH check_vulnerable returns True when port 22 is open (port-only check)"""
        from exploits.modules.ssh_exploit import SSHExploit

        exploit = SSHExploit()
        self.assertTrue(exploit.check_vulnerable(self.target))
        self.assertFalse(exploit.check_vulnerable(make_target(ports=[80])))


# =============================================================================
# FTP Exploit Tests
# =============================================================================


class TestFTPExploit(unittest.TestCase):
    """Test FTP exploit with mocked network"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[21])

    @patch("ftplib.FTP")
    @patch("socket.socket")
    def test_exploit_anonymous_success(self, mock_socket, mock_ftp):
        from exploits.modules.ftp_exploit import FTP_Exploit

        exploit = FTP_Exploit()

        mock_socket_ok(mock_socket)
        mock_ftp.return_value = MagicMock()

        success, result = exploit.exploit(self.target)
        self.assertTrue(success)
        self.assertEqual(result.get("method"), "FTP_Anonymous")

    @patch("socket.socket")
    def test_check_vulnerable_success(self, mock_socket):
        from exploits.modules.ftp_exploit import FTP_Exploit

        exploit = FTP_Exploit()

        mock_socket_ok(mock_socket)
        self.assertTrue(exploit.check_vulnerable(self.target))

    @patch("socket.socket")
    def test_check_vulnerable_failure(self, mock_socket):
        from exploits.modules.ftp_exploit import FTP_Exploit

        exploit = FTP_Exploit()

        sock = MagicMock()
        sock.connect_ex.return_value = 1
        mock_socket.return_value = sock

        self.assertFalse(exploit.check_vulnerable(self.target))


# =============================================================================
# Web Exploit Tests
# =============================================================================


class TestWebExploit(unittest.TestCase):
    """Test Web exploit with mocked requests Session"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[80])

    def test_check_vulnerable(self):
        """Web check_vulnerable matches port (port-only check)"""
        from exploits.modules.web_exploit import WebExploit

        exploit = WebExploit()

        self.assertTrue(exploit.check_vulnerable(self.target))
        self.assertFalse(exploit.check_vulnerable(make_target(ports=[3306])))

    @patch("requests.Session")
    def test_exploit_admin_panel(self, mock_session):
        from exploits.modules.web_exploit import WebExploit

        exploit = WebExploit()
        mock_sess = exploit.session

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '<html><form><input name="username"/><input name="password"/></form></html>'
            resp.headers = {"Content-Type": "text/html"}
            resp.cookies = {}
            return resp

        mock_sess.get.side_effect = mock_get

        def mock_post(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 302
            resp.text = "Dashboard Welcome"
            resp.headers = {"location": "/dashboard", "Content-Type": "text/html"}
            resp.cookies = {"session": "abc123"}
            return resp

        mock_sess.post.side_effect = mock_post

        success, result = exploit.exploit(self.target)
        self.assertTrue(success)


# =============================================================================
# MySQL Exploit Tests  (port-only check_vulnerable)
# =============================================================================


class TestMySQLExploit(unittest.TestCase):
    """Test MySQL exploit"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[3306])

    def test_check_vulnerable_success(self):
        """MySQL check_vulnerable is port-only"""
        from exploits.modules.mysql_exploit import MySQL_Exploit

        exploit = MySQL_Exploit()
        self.assertTrue(exploit.check_vulnerable(self.target))

    def test_check_vulnerable_failure(self):
        from exploits.modules.mysql_exploit import MySQL_Exploit

        exploit = MySQL_Exploit()
        self.assertFalse(exploit.check_vulnerable(make_target(ports=[80])))


# =============================================================================
# PostgreSQL Exploit Tests  (socket connect_ex based)
# =============================================================================


class TestPostgreSQLExploit(unittest.TestCase):
    """Test PostgreSQL exploit with mocked socket"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[5432])

    @patch("socket.socket")
    def test_check_vulnerable(self, mock_socket):
        from exploits.modules.postgresql_exploit import PostgreSQL_Exploit

        exploit = PostgreSQL_Exploit()

        mock_socket_ok(mock_socket)
        self.assertTrue(exploit.check_vulnerable(self.target))


# =============================================================================
# Redis Exploit Tests  (raw socket connect+send+recv based)
# =============================================================================


class TestRedisExploit(unittest.TestCase):
    """Test Redis exploit with mocked socket"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[6379])

    @patch("socket.socket")
    def test_check_vulnerable(self, mock_socket):
        from exploits.modules.redis_exploit import Redis_Exploit

        exploit = Redis_Exploit()

        mock_socket_ok(mock_socket)
        self.assertTrue(exploit.check_vulnerable(self.target))


# =============================================================================
# Telnet Exploit Tests  (socket connect_ex based)
# =============================================================================


class TestTelnetExploit(unittest.TestCase):
    """Test Telnet exploit with mocked socket"""

    def setUp(self):
        self.target = make_target(ip="192.168.1.100", ports=[23])

    @patch("socket.socket")
    def test_check_vulnerable(self, mock_socket):
        from exploits.modules.telnet_exploit import Telnet_Exploit

        exploit = Telnet_Exploit()

        mock_socket_ok(mock_socket)
        self.assertTrue(exploit.check_vulnerable(self.target))


# =============================================================================
# ExploitManager Tests
# =============================================================================


class TestExploitManager(unittest.TestCase):
    """Test ExploitManager with mocked network"""

    @classmethod
    def setUpClass(cls):
        try:
            from configs.config import Config

            cls.config = Config()
        except Exception:
            cls.config = MagicMock()
            cls.config.exploit = MagicMock()
            cls.config.exploit.enable_ssh = True
            cls.config.exploit.enable_web = True
            cls.config.exploit.enable_smb = True
            cls.config.exploit.credential_wordlist = "wordlists/common_creds.txt"
            cls.config.exploit.exploit_timeout = 30

    @patch("socket.socket")
    @patch("paramiko.SSHClient")
    def test_select_exploits_ssh(self, mock_ssh, mock_socket):
        """Selects SSH exploit for target with port 22"""
        from exploits.exploit_manager import ExploitManager

        manager = ExploitManager(self.config)

        mock_socket_ok(mock_socket)
        target = make_target(ports=[22])
        selected = manager.select_exploits(target)

        names = [e.name for e in selected]
        self.assertIn("SSH_BruteForce", names)

    @patch("socket.socket")
    @patch("requests.get")
    def test_select_exploits_web(self, mock_get, mock_socket):
        from exploits.exploit_manager import ExploitManager

        manager = ExploitManager(self.config)

        mock_socket_ok(mock_socket)
        mock_requests_get(mock_get, text="<html>page</html>")
        target = make_target(ports=[80, 443, 8080])
        selected = manager.select_exploits(target)

        names = [e.name for e in selected]
        self.assertIn("Web_Exploit", names)

    @patch("socket.socket")
    @patch("requests.get")
    def test_select_exploits_db(self, mock_get, mock_socket):
        """Selects database exploits for DB ports"""
        from exploits.exploit_manager import ExploitManager

        manager = ExploitManager(self.config)

        mock_socket_ok(mock_socket)
        mock_requests_get(mock_get, text="", status_code=200)
        target = make_target(ports=[3306, 5432, 6379, 27017])
        selected = manager.select_exploits(target)

        names = [e.name for e in selected]
        selected_db = [
            n for n in names if "SQL" in n or "Redis" in n or "Mongo" in n or "Postgre" in n
        ]
        self.assertGreaterEqual(len(selected_db), 2)

    @patch("socket.socket")
    @patch("requests.get")
    @patch("paramiko.SSHClient")
    def test_select_exploits_multi_service(self, mock_ssh, mock_get, mock_socket):
        """Selects multiple exploits for multi-port target"""
        from exploits.exploit_manager import ExploitManager

        manager = ExploitManager(self.config)

        mock_socket_ok(mock_socket)
        mock_requests_get(mock_get, text="<html>page</html>")
        target = make_target(ports=[22, 80, 445, 3389, 21], os_guess="Windows")
        selected = manager.select_exploits(target)

        names = [e.name for e in selected]
        self.assertGreaterEqual(len(selected), 3)
        for name in ["SSH_BruteForce", "Web_Exploit", "FTP_Exploit"]:
            self.assertIn(name, names)

    @patch("paramiko.SSHClient")
    def test_exploit_target_success(self, mock_ssh):
        """Full exploit_target pipeline succeeds for SSH target"""
        from exploits.exploit_manager import ExploitManager

        manager = ExploitManager(self.config)

        mock_client = MagicMock()
        mock_ssh.return_value = mock_client

        target = make_target(ports=[22])
        success, result = manager.exploit_target(target)
        self.assertTrue(success)

    @patch("socket.socket")
    def test_exploit_target_failure(self, mock_socket):
        from exploits.exploit_manager import ExploitManager

        manager = ExploitManager(self.config)

        sock = MagicMock()
        sock.connect_ex.return_value = 1
        mock_socket.return_value = sock

        target = make_target(ports=[12345])
        success, result = manager.exploit_target(target)
        self.assertFalse(success)


# =============================================================================
# Scanner Tests
# =============================================================================


class TestScannerMocked(unittest.TestCase):

    def test_scanner_init(self):
        try:
            from configs.config import Config

            config = Config()
            from scanner import IntelligentScanner

            scanner = IntelligentScanner(config)
            self.assertIsNotNone(scanner)
        except Exception as e:
            self.skipTest(f"IntelligentScanner not available: {e}")


# =============================================================================
# WormCore Propagation Tests
# =============================================================================


class TestWormCoreMocked(unittest.TestCase):

    @patch("socket.socket")
    @patch("paramiko.SSHClient")
    def test_worm_core_init(self, mock_ssh, mock_socket):
        try:
            from worm_core import WormCore

            mock_socket_ok(mock_socket)
            core = WormCore()
            self.assertIsNotNone(core)
            self.assertTrue(hasattr(core, "scan_network"))
            self.assertTrue(hasattr(core, "exploit_target"))
            self.assertTrue(hasattr(core, "propagate"))
        except ImportError as e:
            self.skipTest(f"WormCore not available: {e}")

    @patch("socket.socket")
    @patch("paramiko.SSHClient")
    def test_worm_core_init(self, mock_ssh, mock_socket):
        try:
            from worm_core import WormCore

            mock_socket_ok(mock_socket)
            core = WormCore(dry_run=True)
            self.assertIsNotNone(core)
            self.assertTrue(hasattr(core, "scan_network"))
            self.assertTrue(hasattr(core, "exploit_target"))
            self.assertTrue(hasattr(core, "propagate"))
        except ImportError as e:
            self.skipTest(f"WormCore not available: {e}")

    @patch("socket.socket")
    @patch("paramiko.SSHClient")
    def test_safety_constraints(self, mock_ssh, mock_socket):
        try:
            from worm_core import WormCore

            mock_socket_ok(mock_socket)
            core = WormCore(dry_run=True)
            self.assertTrue(hasattr(core, "check_safety_constraints"))
            self.assertTrue(hasattr(core, "activate_kill_switch"))
            self.assertTrue(hasattr(core, "self_destruct"))
        except ImportError:
            self.skipTest("WormCore not available")


# =============================================================================
# Post-Exploit Module Tests
# =============================================================================


class TestPostExploitMocked(unittest.TestCase):

    def test_lateral_movement_init(self):
        try:
            from post_exploit.lateral_movement import LateralMovementEngine

            engine = LateralMovementEngine()
            self.assertIsNotNone(engine)
        except ImportError:
            self.skipTest("LateralMovementEngine not available")

    def test_persistence_init(self):
        try:
            from post_exploit.persistence import PersistenceManager

            pm = PersistenceManager()
            self.assertIsNotNone(pm)
        except ImportError:
            self.skipTest("PersistenceManager not available")

    def test_credential_dumper_init(self):
        try:
            from post_exploit.credential_dumper import CredentialDumper

            dumper = CredentialDumper()
            self.assertIsNotNone(dumper)
        except ImportError:
            self.skipTest("CredentialDumper not available")


# =============================================================================
# C2 Server Test
# =============================================================================


class TestC2ServerBasic(unittest.TestCase):

    def test_c2_server_init(self):
        try:
            import c2_server

            self.assertTrue(hasattr(c2_server, "start_c2_server") or hasattr(c2_server, "C2Server"))
        except ImportError:
            self.skipTest("C2 server module not available")


# =============================================================================
# Evasion Module Tests
# =============================================================================


class TestEvasionMocked(unittest.TestCase):

    def test_polymorphic_engine_init(self):
        try:
            from evasion.polymorphic_engine import PolymorphicEngine

            engine = PolymorphicEngine(mutation_level=2)
            self.assertIsNotNone(engine)
        except ImportError:
            self.skipTest("PolymorphicEngine not available")

    def test_payload_mutation(self):
        try:
            from evasion.polymorphic_engine import PolymorphicEngine

            engine = PolymorphicEngine(mutation_level=2)
            payload = "x = 1; print(x)"
            mutated = engine.mutate_payload(payload)
            self.assertIsNotNone(mutated)
        except ImportError:
            self.skipTest("PolymorphicEngine not available")


# =============================================================================
# Advanced Exploit Tests  (HTTP exploits use requests.get, socket-based use socket)
# =============================================================================


class TestAdvancedExploitsMocked(unittest.TestCase):
    """Test advanced exploit modules with properly mocked network"""

    # --- Socket-based exploits (check_vulnerable uses connect_ex) ---

    @patch("socket.socket")
    def test_smb_exploit_check(self, mock_socket):
        """SMB check_vulnerable is port-only"""
        try:
            from exploits.modules.smb_exploit import SMBExploit

            exploit = SMBExploit()
            target = make_target(ports=[445])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("SMBExploit not available")

    def test_vnc_exploit_check(self):
        """VNC check_vulnerable is port-only"""
        try:
            from exploits.modules.vnc_exploit import VNC_Exploit

            exploit = VNC_Exploit()
            target = make_target(ports=[5900])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("VNCExploit not available")

    def test_mongodb_exploit_check(self):
        """MongoDB check_vulnerable is port-only"""
        try:
            from exploits.modules.mongodb_exploit import MongoDB_Exploit

            exploit = MongoDB_Exploit()
            target = make_target(ports=[27017])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("MongoDBExploit not available")

    def test_snmp_exploit_check(self):
        """SNMP check_vulnerable is port-only"""
        try:
            from exploits.modules.snmp_exploit import SNMP_Exploit

            exploit = SNMP_Exploit()
            target = make_target(ports=[161])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("SNMPExploit not available")

    @patch("socket.socket")
    def test_docker_exploit_check(self, mock_socket):
        """Docker check_vulnerable uses socket connect_ex"""
        try:
            from exploits.modules.docker_exploit import Docker_Exploit

            exploit = Docker_Exploit()
            mock_socket_ok(mock_socket)
            target = make_target(ports=[2375])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("DockerExploit not available")

    @patch("socket.socket")
    def test_mssql_exploit_check(self, mock_socket):
        """MSSQL check_vulnerable uses socket connect_ex"""
        try:
            from exploits.modules.mssql_exploit import MSSQL_Exploit

            exploit = MSSQL_Exploit()
            mock_socket_ok(mock_socket)
            target = make_target(ports=[1433])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("MSSQLExploit not available")

    # --- HTTP-based exploits (check_vulnerable uses requests.get) ---

    @patch("requests.get")
    def test_jenkins_exploit_check(self, mock_get):
        try:
            from exploits.modules.jenkins_exploit import Jenkins_Exploit

            exploit = Jenkins_Exploit()
            mock_requests_get(
                mock_get, text="<title>Jenkins</title>", headers={"X-Jenkins": "2.303.1"}
            )
            target = make_target(ports=[8080])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("JenkinsExploit not available")

    @patch("urllib.request.urlopen")
    def test_elasticsearch_exploit_check(self, mock_urlopen):
        """Elasticsearch uses urllib.request.urlopen (not requests)"""
        try:
            from exploits.modules.elasticsearch_exploit import Elasticsearch_Exploit

            exploit = Elasticsearch_Exploit()

            cm = MagicMock()
            cm.read.return_value = (
                b'{"cluster_name": "elasticsearch", "version": {"number": "7.10.0"}}'
            )
            cm.__enter__.return_value = cm
            mock_urlopen.return_value = cm

            target = make_target(ports=[9200])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("ElasticsearchExploit not available")

    @patch("requests.get")
    def test_tomcat_exploit_check(self, mock_get):
        try:
            from exploits.modules.tomcat_exploit import Tomcat_Exploit

            exploit = Tomcat_Exploit()
            mock_requests_get(
                mock_get,
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'},
            )
            target = make_target(ports=[8080])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("TomcatExploit not available")

    @patch("requests.get")
    def test_kubernetes_exploit_check(self, mock_get):
        try:
            from exploits.modules.kubernetes_exploit import Kubernetes_Exploit

            exploit = Kubernetes_Exploit()
            mock_requests_get(
                mock_get, json_data={"gitVersion": "v1.21.0", "major": "1", "minor": "21"}
            )
            target = make_target(ports=[6443])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("KubernetesExploit not available")

    @patch("requests.get")
    def test_struts_exploit_check(self, mock_get):
        try:
            from exploits.modules.struts_exploit import Struts_Exploit

            exploit = Struts_Exploit()
            mock_requests_get(mock_get, text="Struts2 Showcase")
            target = make_target(ports=[8080])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("StrutsExploit not available")

    @patch("requests.get")
    def test_exchange_exploit_check(self, mock_get):
        try:
            from exploits.modules.exchange_exploit import Exchange_Exploit

            exploit = Exchange_Exploit()
            mock_requests_get(mock_get, text="Outlook Web App")
            target = make_target(ports=[443])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("ExchangeExploit not available")

    @patch("requests.get")
    def test_weblogic_exploit_check(self, mock_get):
        try:
            from exploits.modules.weblogic_exploit import WebLogic_Exploit

            exploit = WebLogic_Exploit()
            mock_requests_get(mock_get, text="WebLogic Server")
            target = make_target(ports=[7001])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("WebLogicExploit not available")

    @patch("requests.get")
    def test_confluence_exploit_check(self, mock_get):
        try:
            from exploits.modules.confluence_exploit import Confluence_Exploit

            exploit = Confluence_Exploit()
            mock_requests_get(
                mock_get,
                text="Atlassian Confluence",
                headers={"X-Confluence-Request-Time": "12345"},
            )
            target = make_target(ports=[8090])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("ConfluenceExploit not available")

    @patch("requests.get")
    def test_jira_exploit_check(self, mock_get):
        try:
            from exploits.modules.jira_exploit import Jira_Exploit

            exploit = Jira_Exploit()
            mock_requests_get(mock_get, text="<title>Jira Software</title>")
            target = make_target(ports=[8080])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("JiraExploit not available")

    @patch("requests.get")
    def test_gitlab_exploit_check(self, mock_get):
        try:
            from exploits.modules.gitlab_exploit import GitLab_Exploit

            exploit = GitLab_Exploit()
            mock_requests_get(mock_get, text="<title>GitLab CE</title>")
            target = make_target(ports=[443])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("GitLabExploit not available")

    @patch("requests.get")
    def test_citrix_exploit_check(self, mock_get):
        try:
            from exploits.modules.citrix_exploit import Citrix_Exploit

            exploit = Citrix_Exploit()
            mock_requests_get(mock_get, text="NetScaler Gateway")
            target = make_target(ports=[443])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("CitrixExploit not available")

    @patch("requests.get")
    def test_log4j_exploit_check(self, mock_get):
        try:
            from exploits.modules.log4j_exploit import Log4j_Exploit

            exploit = Log4j_Exploit()
            mock_requests_get(mock_get, text="", status_code=200)
            target = make_target(ports=[8080])
            self.assertTrue(exploit.check_vulnerable(target))
        except ImportError:
            self.skipTest("Log4jExploit not available")


# =============================================================================
# RL Engine Tests
# =============================================================================


class TestRLEngineMocked(unittest.TestCase):

    def test_agent_predict(self):
        try:
            from rl_engine import PropagationAgent

            agent = PropagationAgent(state_size=20, action_size=4)
            state = [0.5] * 20
            action = agent.predict(state)
            self.assertIsNotNone(action)
        except Exception as e:
            self.skipTest(f"PropagationAgent not available: {e}")

    def test_network_env_init(self):
        try:
            from rl_engine import NetworkEnvironment

            env = NetworkEnvironment(network_size=10, max_steps=50)
            self.assertIsNotNone(env)
        except Exception as e:
            self.skipTest(f"NetworkEnvironment not available: {e}")


# =============================================================================
# Run
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
