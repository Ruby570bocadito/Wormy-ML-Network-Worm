"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Input Validation and Sanitization
Validates IPs, ports, CIDRs, file paths, and user input
"""


import ipaddress
import os
import re
from typing import List, Optional, Tuple


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def validate_port(port) -> bool:
    """Validate port number"""
    try:
        p = int(port)
        return 0 < p < 65536
    except (ValueError, TypeError):
        return False


def validate_ports(ports) -> List[int]:
    """Validate and return list of valid ports"""
    valid = []
    for p in ports:
        if validate_port(p):
            valid.append(int(p))
    return sorted(set(valid))


def validate_target_ranges(ranges: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validate target ranges, return (valid, invalid)
    """
    valid = []
    invalid = []
    for target in ranges:
        if validate_ip(target) or validate_cidr(target):
            valid.append(target)
        else:
            invalid.append(target)
    return valid, invalid


def validate_file_path(path: str, must_exist: bool = False) -> bool:
    """Validate file path and optionally check existence"""
    if not path or not isinstance(path, str):
        return False

    # Check for path traversal
    if ".." in path or path.startswith("/"):
        # Allow absolute paths but check they're safe
        pass

    if must_exist:
        return os.path.isfile(path)

    return True


def validate_kill_switch_code(code: str) -> bool:
    """Validate kill switch code format"""
    if not code or not isinstance(code, str):
        return False
    if len(code) < 4 or len(code) > 128:
        return False
    # Only allow alphanumeric and underscores
    return bool(re.match(r"^[A-Za-z0-9_]+$", code))


def sanitize_ip(ip: str) -> Optional[str]:
    """Sanitize and normalize IP address"""
    if validate_ip(ip):
        return str(ipaddress.ip_address(ip))
    return None


def sanitize_cidr(cidr: str) -> Optional[str]:
    """Sanitize and normalize CIDR"""
    if validate_cidr(cidr):
        return str(ipaddress.ip_network(cidr, strict=False))
    return None


def sanitize_hostname(hostname: str) -> Optional[str]:
    """Sanitize hostname"""
    if not hostname or not isinstance(hostname, str):
        return None
    if len(hostname) > 253:
        return None
    # RFC 1123 hostname pattern
    if re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
        hostname,
    ):
        return hostname
    return None


def validate_config_value(key: str, value) -> bool:
    """Validate common config value types"""
    validators = {
        "max_infections": lambda v: isinstance(v, int) and 0 < v < 100000,
        "max_runtime_hours": lambda v: isinstance(v, (int, float)) and 0 <= v <= 168,
        "propagation_delay": lambda v: isinstance(v, (int, float)) and 0 <= v <= 3600,
        "scan_timeout": lambda v: isinstance(v, (int, float)) and 0.1 <= v <= 60,
        "max_threads": lambda v: isinstance(v, int) and 1 <= v <= 1000,
        "max_scan_rate": lambda v: isinstance(v, (int, float)) and 1 <= v <= 10000,
        "beacon_interval": lambda v: isinstance(v, int) and 5 <= v <= 86400,
        "auto_destruct_time": lambda v: isinstance(v, (int, float)) and 0 <= v <= 168,
    }

    if key in validators:
        return validators[key](value)
    return True


def expand_target_ranges(ranges: List[str], max_hosts: int = 65536) -> List[str]:
    """
    Safely expand target ranges to individual IPs with limit
    """
    valid_ranges, invalid = validate_target_ranges(ranges)

    if invalid:
        raise ValueError(f"Invalid target ranges: {invalid}")

    all_ips = []
    for target in valid_ranges:
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
                if len(hosts) > max_hosts:
                    raise ValueError(
                        f"Network {target} has {len(hosts)} hosts, " f"exceeds limit of {max_hosts}"
                    )
                all_ips.extend(hosts)
            else:
                all_ips.append(target)
        except ValueError as e:
            raise ValueError(f"Failed to expand {target}: {e}")

    return all_ips
