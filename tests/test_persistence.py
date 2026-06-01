"""Tests for persistence modules: local_persistence and remote_persistence"""

import os
import platform
import sys
import unittest
from unittest.mock import MagicMock, PropertyMock, call, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPersistenceManager(unittest.TestCase):
    """PersistenceManager (local_persistence) tests"""

    @patch("platform.system", return_value="Windows")
    def test_windows_methods_loaded(self, mock_platform):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        names = [m.__name__ for m in pm.methods]
        self.assertEqual(len(names), 4)
        self.assertIn("_windows_registry_run", names)
        self.assertIn("_windows_scheduled_task", names)
        self.assertIn("_windows_startup_folder", names)
        self.assertIn("_windows_service", names)

    @patch("platform.system", return_value="Linux")
    def test_linux_methods_loaded(self, mock_platform):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        names = [m.__name__ for m in pm.methods]
        self.assertEqual(len(names), 4)
        self.assertIn("_linux_cron_job", names)
        self.assertIn("_linux_systemd_service", names)
        self.assertIn("_linux_bashrc", names)
        self.assertIn("_linux_init_script", names)

    def test_establish_persistence_returns_first_success(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        mock_success = MagicMock(return_value=(True, {"method": "Mocked_Success"}))
        mock_fail = MagicMock(return_value=(False, {}))
        pm.methods = [mock_fail, mock_fail, mock_success, mock_fail]

        success, details = pm.establish_persistence("/tmp/payload.exe")
        self.assertTrue(success)
        self.assertEqual(details["method"], "Mocked_Success")
        self.assertEqual(mock_success.call_count, 1)
        self.assertEqual(mock_fail.call_count, 2)

    def test_establish_persistence_all_fail(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        mock_fail = MagicMock(return_value=(False, {}))
        pm.methods = [mock_fail, mock_fail]

        success, details = pm.establish_persistence("/tmp/payload.exe")
        self.assertFalse(success)
        self.assertEqual(details, {})

    def test_windows_registry_run(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        mock_winreg = MagicMock()
        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            success, details = pm._windows_registry_run("/tmp/payload.exe")
            self.assertTrue(success)
            self.assertEqual(details["method"], "Registry_Run_Key")

    def test_windows_scheduled_task(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            success, details = pm._windows_scheduled_task("/tmp/payload.exe")
            self.assertTrue(success)
            self.assertEqual(details["method"], "Scheduled_Task")

    def test_windows_service(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            success, details = pm._windows_service("/tmp/payload.exe")
            self.assertTrue(success)
            self.assertEqual(details["method"], "Windows_Service")

    def test_windows_startup_folder(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("os.path.exists", return_value=True):
            with patch("shutil.copy2"):
                with patch.dict(os.environ, {"APPDATA": "C:\\Users\\test\\AppData\\Roaming"}):
                    success, details = pm._windows_startup_folder("/tmp/payload.exe")
                    self.assertTrue(success)
                    self.assertEqual(details["method"], "Startup_Folder")

    def test_linux_cron_job(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            with patch("subprocess.Popen") as mock_popen:
                proc = MagicMock()
                proc.returncode = 0
                mock_popen.return_value = proc
                success, details = pm._linux_cron_job("/tmp/payload")
                self.assertTrue(success)
                self.assertEqual(details["method"], "Cron_Job")

    def test_linux_systemd_service(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("builtins.open", unittest.mock.mock_open()):
            with patch("os.makedirs"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value.returncode = 0
                    success, details = pm._linux_systemd_service("/tmp/payload")
                    self.assertTrue(success)
                    self.assertEqual(details["method"], "Systemd_Service")

    def test_linux_bashrc(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", unittest.mock.mock_open()) as mock_file:
                success, details = pm._linux_bashrc("/tmp/payload")
                self.assertTrue(success)
                self.assertEqual(details["method"], "Bashrc")

    def test_linux_init_script(self):
        from post_exploit.local_persistence import PersistenceManager

        pm = PersistenceManager()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            with patch("builtins.open", unittest.mock.mock_open()):
                with patch("os.makedirs"):
                    with patch("os.chmod"):
                        success, details = pm._linux_init_script("/tmp/payload")
                        self.assertTrue(success)
                        self.assertEqual(details["method"], "Init_Script")


class TestAdvancedPersistence(unittest.TestCase):
    """AdvancedPersistence (local_persistence) tests"""

    @patch("platform.system", return_value="Windows")
    def test_install_all_windows(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch.object(ap, "registry_run_key", return_value=True):
            with patch.object(ap, "scheduled_task", return_value=True):
                with patch.object(ap, "wmi_event_subscription", return_value=True):
                    with patch.object(ap, "startup_folder", return_value=True):
                        with patch.object(ap, "com_hijacking", return_value=True):
                            with patch.object(ap, "dll_search_order_hijack", return_value=True):
                                with patch.object(ap, "accessibility_features", return_value=True):
                                    with patch.object(ap, "logon_script", return_value=True):
                                        results = ap.install_all("/tmp/payload.exe")
        self.assertEqual(len(results), 8)
        self.assertTrue(all(results.values()))

    @patch("platform.system", return_value="Linux")
    def test_install_all_linux(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch.object(ap, "cron_job", return_value=True):
            with patch.object(ap, "systemd_service", return_value=True):
                with patch.object(ap, "bashrc_profile", return_value=True):
                    with patch.object(ap, "ssh_authorized_keys", return_value=True):
                        with patch.object(ap, "ld_preload_hijack", return_value=True):
                            results = ap.install_all("/tmp/payload.so")
        self.assertEqual(len(results), 5)
        self.assertTrue(all(results.values()))

    def test_wmi_event_subscription_wrong_os(self):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        ap.os_type = "Linux"
        self.assertFalse(ap.wmi_event_subscription("/tmp/payload.exe"))

    def test_com_hijacking_wrong_os(self):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        ap.os_type = "Linux"
        self.assertFalse(ap.com_hijacking("/tmp/payload.exe"))

    @patch("platform.system", return_value="Windows")
    def test_com_hijacking_success(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        mock_winreg = MagicMock()
        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            success = ap.com_hijacking("C:\\payload.exe")
            self.assertTrue(success)
            self.assertIn("COM_Hijack", ap.installed)

    @patch("platform.system", return_value="Windows")
    def test_logon_script_success(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        mock_winreg = MagicMock()
        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            success = ap.logon_script("C:\\payload.exe")
            self.assertTrue(success)
            self.assertIn("Logon_Script", ap.installed)

    def test_ssh_authorized_keys_not_linux(self):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        ap.os_type = "Windows"
        self.assertFalse(ap.ssh_authorized_keys("/tmp/key.pub"))

    @patch("platform.system", return_value="Linux")
    def test_ssh_authorized_keys_valid_key(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("os.makedirs"), patch("os.chmod"), patch("os.path.exists", return_value=True):
            with patch("builtins.open", unittest.mock.mock_open(read_data="")):
                success = ap.ssh_authorized_keys(
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ wormy@test"
                )
                self.assertTrue(success)
                self.assertIn("SSH_Keys", ap.installed)

    @patch("platform.system", return_value="Linux")
    def test_ssh_authorized_keys_invalid_key(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        success = ap.ssh_authorized_keys("not-a-valid-key")
        self.assertFalse(success)

    @patch("platform.system", return_value="Linux")
    def test_ld_preload_hijack(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("os.path.isfile", return_value=False):
            with patch("builtins.open", unittest.mock.mock_open()):
                with patch("subprocess.run"):
                    success = ap.ld_preload_hijack("/tmp/malicious.so")
                    self.assertTrue(success)
                    self.assertIn("LD_PRELOAD", ap.installed)

    @patch("platform.system", return_value="Linux")
    def test_ld_preload_hijack_already_present(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("os.path.isfile", return_value=True):
            existing = "/tmp/malicious.so\n"
            with patch("builtins.open", unittest.mock.mock_open(read_data=existing)):
                with patch.dict("sys.modules", {"subprocess": MagicMock()}):
                    success = ap.ld_preload_hijack("/tmp/malicious.so")
                    self.assertTrue(success)
                    self.assertIn("LD_PRELOAD", ap.installed)

    @patch("platform.system", return_value="Windows")
    def test_dll_search_order_hijack(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("os.path.exists", side_effect=[False, True, True]):
            with patch("builtins.open", unittest.mock.mock_open()):
                with patch("os.remove"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        with patch("os.path.isabs", return_value=True):
                            success = ap.dll_search_order_hijack("C:\\payload.exe")
                            self.assertTrue(success)
                            self.assertIn("DLL_Hijack", ap.installed)

    def test_get_statistics(self):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        ap.installed = ["Registry_Run", "Cron_Job"]
        stats = ap.get_statistics()
        self.assertEqual(stats["os_type"], platform.system())
        self.assertEqual(stats["methods_installed"], 2)
        self.assertEqual(stats["installed_methods"], ["Registry_Run", "Cron_Job"])

    @patch("platform.system", return_value="Linux")
    def test_bashrc_profile(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("builtins.open", unittest.mock.mock_open()) as mock_file:
            success = ap.bashrc_profile("/tmp/payload")
            self.assertTrue(success)
            self.assertIn("Bashrc", ap.installed)

    @patch("platform.system", return_value="Linux")
    def test_cron_job(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            with patch("subprocess.Popen") as mock_popen:
                proc = MagicMock()
                proc.returncode = 0
                mock_popen.return_value = proc
                success = ap.cron_job("/tmp/payload")
                self.assertTrue(success)
                self.assertIn("Cron_Job", ap.installed)

    @patch("platform.system", return_value="Linux")
    def test_systemd_service(self, mock_platform):
        from post_exploit.local_persistence import AdvancedPersistence

        ap = AdvancedPersistence()
        with patch("builtins.open", unittest.mock.mock_open()):
            with patch("os.makedirs"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value.returncode = 0
                    success = ap.systemd_service("/tmp/payload")
                    self.assertTrue(success)
                    self.assertIn("Systemd_Service", ap.installed)


class TestPersistenceEngine(unittest.TestCase):
    """PersistenceEngine (remote_persistence) tests"""

    def test_establish_linux_runs_all_methods(self):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        with patch.object(pe, "_persist_linux", return_value=(True, {"method": "cron"})):
            results = pe.establish(
                "10.0.0.1",
                os_type="Linux",
                username="root",
                password="toor",
                payload_path="/tmp/payload",
            )
            self.assertGreaterEqual(len(results), 1)

    def test_establish_windows_runs_all_methods(self):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        with patch.object(pe, "_persist_windows", return_value=(True, {"method": "registry"})):
            results = pe.establish(
                "10.0.0.2",
                os_type="Windows",
                username="admin",
                password="pass",
                payload_path="C:\\payload.exe",
            )
            self.assertGreaterEqual(len(results), 1)

    def test_establish_unknown_os(self):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        with patch.object(pe, "_persist_linux", return_value=(True, {"method": "cron"})):
            with patch.object(pe, "_persist_windows", return_value=(True, {"method": "registry"})):
                results = pe.establish(
                    "10.0.0.3",
                    os_type="Unknown",
                    username="user",
                    password="pass",
                    payload_path="/tmp/pay",
                )
                self.assertGreater(len(results), 0)

    @patch("paramiko.SSHClient")
    def test_persist_linux_via_ssh(self, mock_ssh):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        client = mock_ssh.return_value
        with patch.object(pe, "_persist_cron", return_value=(True, {"method": "cron"})):
            success, result = pe._persist_linux("10.0.0.1", "cron", "root", "toor", "/tmp/payload")
            self.assertTrue(success)
            client.connect.assert_called_once()
            client.close.assert_called_once()

    def test_persist_linux_import_error(self):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        with patch.dict("sys.modules", {"paramiko": None}):
            success, result = pe._persist_linux("10.0.0.1", "cron", "root", "toor", "/tmp/payload")
            self.assertFalse(success)
            self.assertEqual(result["error"], "paramiko not available")

    def test_persist_windows_import_error(self):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        with patch.dict("sys.modules", {"impacket": None}):
            success, result = pe._persist_windows(
                "10.0.0.2", "registry", "admin", "pass", "C:\\p.exe"
            )
            self.assertFalse(success)
            self.assertEqual(result["error"], "impacket not available")

    def test_get_statistics(self):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        pe.stats["attempts"] = 10
        pe.stats["successful"] = 7
        pe.stats["failed"] = 3
        stats = pe.get_statistics()
        self.assertEqual(stats["attempts"], 10)
        self.assertEqual(stats["successful"], 7)
        self.assertEqual(stats["success_rate"], 70.0)

    @patch("paramiko.SSHClient")
    def test_persist_cron(self, mock_ssh):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        client = mock_ssh.return_value
        channel = MagicMock()
        channel.recv_exit_status.return_value = 0
        stdout = MagicMock()
        stdout.channel = channel
        stdout.read.return_value = b"*/5 * * * * /tmp/.w_beacon # system-update\n"
        client.exec_command.return_value = (None, stdout, None)

        success, result = pe._persist_cron(client, "10.0.0.1", "/tmp/.w_beacon")
        self.assertTrue(success)
        self.assertEqual(result["method"], "cron")

    @patch("paramiko.SSHClient")
    def test_persist_ssh_keys(self, mock_ssh):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        client = mock_ssh.return_value
        channel = MagicMock()
        channel.recv_exit_status.return_value = 0
        stdout = MagicMock()
        stdout.channel = channel
        client.exec_command.return_value = (None, stdout, None)

        os.makedirs("persistence_keys", exist_ok=True)
        try:
            pe.stats = {"attempts": 0, "successful": 0, "failed": 0, "by_method": {}}
            success, result = pe._persist_ssh_keys(client, "10.0.0.1", "root")
            self.assertTrue(success)
            self.assertEqual(result["method"], "ssh_keys")
        finally:
            import shutil

            shutil.rmtree("persistence_keys", ignore_errors=True)

    @patch("paramiko.SSHClient")
    def test_persist_systemd(self, mock_ssh):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        client = mock_ssh.return_value
        channel = MagicMock()
        channel.recv_exit_status.return_value = 0
        stdout = MagicMock()
        stdout.channel = channel
        client.exec_command.return_value = (None, stdout, None)

        success, result = pe._persist_systemd(client, "10.0.0.1", "/tmp/payload")
        self.assertTrue(success)
        self.assertEqual(result["method"], "systemd")

    @patch("paramiko.SSHClient")
    def test_persist_bashrc(self, mock_ssh):
        from post_exploit.remote_persistence import PersistenceEngine

        pe = PersistenceEngine()
        client = mock_ssh.return_value
        channel = MagicMock()
        channel.recv_exit_status.return_value = 0
        stdout = MagicMock()
        stdout.channel = channel
        client.exec_command.return_value = (None, stdout, None)

        success, result = pe._persist_bashrc(client, "10.0.0.1", "/tmp/payload")
        self.assertTrue(success)
        self.assertEqual(result["method"], "bashrc")


class TestWindowsPersistence(unittest.TestCase):
    """WindowsPersistence (remote_persistence) tests"""

    @patch("platform.system", return_value="Linux")
    def test_registry_run_key_wrong_os(self, mock_platform):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        success, _ = wp.registry_run_key("C:\\payload.exe")
        self.assertFalse(success)

    def test_random_name_format(self):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        name = wp._random_name()
        self.assertGreater(len(name), 4)
        name_ext = wp._random_name(ext=".exe")
        self.assertTrue(name_ext.endswith(".exe"))

    @patch("platform.system", return_value="Windows")
    def test_registry_run_key_success(self, mock_platform):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        mock_winreg = MagicMock()
        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            success, details = wp.registry_run_key("C:\\payload.exe")
            self.assertTrue(success)
            self.assertEqual(details["method"], "registry_run")

    @patch("platform.system", return_value="Windows")
    def test_scheduled_task_success(self, mock_platform):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            success, details = wp.scheduled_task("C:\\payload.exe")
            self.assertTrue(success)
            self.assertEqual(details["method"], "scheduled_task")

    @patch("platform.system", return_value="Windows")
    def test_wmi_event_subscription_success(self, mock_platform):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            success, details = wp.wmi_event_subscription("C:\\payload.exe")
            self.assertTrue(success)
            self.assertEqual(details["method"], "wmi_subscription")
            self.assertTrue(details["stealthy"])

    @patch("platform.system", return_value="Linux")
    def test_wmi_event_subscription_wrong_os(self, mock_platform):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        success, _ = wp.wmi_event_subscription("C:\\payload.exe")
        self.assertFalse(success)

    @patch("platform.system", return_value="Windows")
    def test_startup_folder_success(self, mock_platform):
        from post_exploit.remote_persistence import WindowsPersistence

        wp = WindowsPersistence()
        with patch("os.path.exists", return_value=True):
            with patch("shutil.copy2"):
                with patch.object(wp, "_random_name", return_value="svchost1234.exe"):
                    with patch.dict(os.environ, {"APPDATA": "C:\\Users\\test\\AppData\\Roaming"}):
                        success, details = wp.startup_folder("C:\\payload.exe")
                        self.assertTrue(success)
                        self.assertEqual(details["method"], "startup_folder")


class TestLinuxPersistence(unittest.TestCase):
    """LinuxPersistence (remote_persistence) tests"""

    def test_cron_user_already_present(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "/tmp/payload\n"
            mock_run.return_value.returncode = 0
            success, details = lp.cron_user("/tmp/payload")
            self.assertTrue(success)
            self.assertEqual(details["status"], "already_present")

    def test_cron_user_success(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            with patch("subprocess.Popen") as mock_popen:
                proc = MagicMock()
                proc.returncode = 0
                mock_popen.return_value = proc
                success, details = lp.cron_user("/tmp/payload")
                self.assertTrue(success)
                self.assertEqual(details["method"], "cron_user")

    def test_cron_system_permission_error(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("builtins.open") as mock_open:
            mock_open.side_effect = PermissionError("Permission denied")
            success, details = lp.cron_system("/tmp/payload")
            self.assertFalse(success)

    def test_cron_system_success(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("builtins.open", unittest.mock.mock_open()):
            with patch("os.chmod"):
                with patch.object(lp, "_random_name", return_value="sys-kworker42"):
                    success, details = lp.cron_system("/tmp/payload")
                    self.assertTrue(success)
                    self.assertEqual(details["method"], "cron_system")

    def test_systemd_service(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("builtins.open", unittest.mock.mock_open()):
            with patch("os.makedirs"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value.returncode = 0
                    with patch.object(lp, "_random_name", return_value="sys-kworker42"):
                        success, details = lp.systemd_service("/tmp/payload")
                        self.assertTrue(success)
                        self.assertEqual(details["method"], "systemd_user")

    def test_bashrc_injection(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("os.path.expanduser", return_value="/home/user/.bashrc"):
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", unittest.mock.mock_open(read_data="")):
                    success, details = lp.bashrc_injection("/tmp/payload")
                    self.assertTrue(success)
                    self.assertEqual(details["method"], "bashrc_injection")

    def test_bashrc_injection_already_present(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("os.path.expanduser", return_value="/home/user/.bashrc"):
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", unittest.mock.mock_open(read_data="/tmp/payload\n")):
                    success, details = lp.bashrc_injection("/tmp/payload")
                    self.assertFalse(success)

    def test_ld_preload_success(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("builtins.open", unittest.mock.mock_open()):
            success, details = lp.ld_preload("/tmp/malicious.so")
            self.assertTrue(success)
            self.assertEqual(details["method"], "ld_preload")

    def test_ld_preload_permission_error(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        with patch("builtins.open") as mock_open:
            mock_open.side_effect = PermissionError("nope")
            success, details = lp.ld_preload("/tmp/malicious.so")
            self.assertFalse(success)

    def test_random_name(self):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        name = lp._random_name()
        self.assertGreater(len(name), 4)

    @patch("paramiko.SSHClient")
    def test_ssh_authorized_keys(self, mock_ssh):
        from post_exploit.remote_persistence import LinuxPersistence

        lp = LinuxPersistence()
        client = mock_ssh.return_value
        stdout = MagicMock()
        stdout.read.return_value = b""
        client.exec_command.return_value = (None, stdout, None)

        success, details = lp.ssh_authorized_keys(
            "10.0.0.1",
            "root",
            "ssh-rsa AAAA...",
            creds=("root", "toor"),
        )
        self.assertTrue(success)
        self.assertEqual(details["method"], "ssh_authorized_keys")


class TestEnterprisePersistenceEngine(unittest.TestCase):
    """EnterprisePersistenceEngine tests"""

    @patch("platform.system", return_value="Windows")
    def test_establish_windows_calls_all_methods(self, mock_platform):
        from post_exploit.remote_persistence import EnterprisePersistenceEngine

        epe = EnterprisePersistenceEngine()
        with patch.object(
            epe.win, "registry_run_key", return_value=(True, {"method": "registry_run"})
        ):
            with patch.object(
                epe.win, "scheduled_task", return_value=(True, {"method": "scheduled_task"})
            ):
                with patch.object(
                    epe.win, "startup_folder", return_value=(True, {"method": "startup_folder"})
                ):
                    with patch.object(
                        epe.win,
                        "wmi_event_subscription",
                        return_value=(True, {"method": "wmi_subscription"}),
                    ):
                        results = epe.establish("C:\\payload.exe")
        self.assertEqual(len(results), 4)

    @patch("platform.system", return_value="Linux")
    def test_establish_linux_calls_all_methods(self, mock_platform):
        from post_exploit.remote_persistence import EnterprisePersistenceEngine

        epe = EnterprisePersistenceEngine()
        with patch.object(epe.lin, "cron_user", return_value=(True, {"method": "cron_user"})):
            with patch.object(
                epe.lin, "systemd_service", return_value=(True, {"method": "systemd_user"})
            ):
                with patch.object(
                    epe.lin, "bashrc_injection", return_value=(True, {"method": "bashrc_injection"})
                ):
                    with patch.object(
                        epe.lin, "cron_system", return_value=(True, {"method": "cron_system"})
                    ):
                        results = epe.establish("/tmp/payload")
        self.assertEqual(len(results), 4)

    @patch("platform.system", return_value="Linux")
    def test_establish_linux_no_methods_succeed(self, mock_platform):
        from post_exploit.remote_persistence import EnterprisePersistenceEngine

        epe = EnterprisePersistenceEngine()
        with patch.object(epe.lin, "cron_user", return_value=(False, {})):
            with patch.object(epe.lin, "systemd_service", return_value=(False, {})):
                with patch.object(epe.lin, "bashrc_injection", return_value=(False, {})):
                    with patch.object(epe.lin, "cron_system", return_value=(False, {})):
                        results = epe.establish("/tmp/payload")
        self.assertEqual(len(results), 0)

    def test_get_report_empty(self):
        from post_exploit.remote_persistence import EnterprisePersistenceEngine

        epe = EnterprisePersistenceEngine()
        report = epe.get_report()
        self.assertEqual(report["total"], 0)
        self.assertEqual(report["mechanisms"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
