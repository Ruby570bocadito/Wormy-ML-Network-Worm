"""
Wormy ML Network Worm v3.0 - MITRE ATT&CK Mapper
Maps Wormy techniques to ATT&CK IDs and exports JSON reports.
"""

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

# ── ATT&CK technique catalog (Enterprise v14) ─────────────────────────────────

ATTACK_TECHNIQUES: Dict[str, Dict] = {
    # Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190",
    },
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    # Execution
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1055.001": {"name": "Dynamic-link Library Injection", "tactic": "Defense Evasion"},
    "T1055.002": {"name": "Portable Executable Injection", "tactic": "Defense Evasion"},
    "T1055.012": {"name": "Process Hollowing", "tactic": "Defense Evasion"},
    # Persistence
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1134.001": {"name": "Token Impersonation/Theft", "tactic": "Privilege Escalation"},
    # Defense Evasion
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    "T1562.006": {"name": "Indicator Blocking (ETW)", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1027.002": {"name": "Software Packing", "tactic": "Defense Evasion"},
    "T1036.004": {"name": "Masquerade Task or Service", "tactic": "Defense Evasion"},
    "T1036.005": {"name": "Match Legitimate Name or Location", "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion"},
    "T1134.004": {"name": "Parent PID Spoofing", "tactic": "Defense Evasion"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
    "T1620": {"name": "Reflective Code Loading", "tactic": "Defense Evasion"},
    # Credential Access
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1003.003": {"name": "NTDS", "tactic": "Credential Access"},
    "T1003.005": {"name": "Cached Domain Credentials", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.002": {"name": "Password Cracking", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access"},
    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": "Discovery"},
    "T1069.002": {"name": "Domain Groups", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    # Lateral Movement
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "Lateral Movement"},
    "T1175": {"name": "DCOM Lateral Movement", "tactic": "Lateral Movement"},
    "T1072": {"name": "Software Deployment Tools", "tactic": "Lateral Movement"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1056.001": {"name": "Keylogging", "tactic": "Collection"},
    "T1113": {"name": "Screen Capture", "tactic": "Collection"},
    # Command and Control
    "T1071.001": {"name": "Web Protocols (HTTPS)", "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control"},
    "T1090.004": {"name": "Domain Fronting", "tactic": "Command and Control"},
    "T1095": {"name": "Non-Application Layer Protocol (ICMP)", "tactic": "Command and Control"},
    "T1092": {"name": "Communication Through Removable Media", "tactic": "Command and Control"},
    "T1104": {"name": "Multi-Stage Channels", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1132.001": {"name": "Standard Encoding (Base64)", "tactic": "Command and Control"},
    "T1573.001": {"name": "Symmetric Cryptography", "tactic": "Command and Control"},
    "T1573.002": {"name": "Asymmetric Cryptography", "tactic": "Command and Control"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048.003": {"name": "Exfil Over Unencrypted Protocol", "tactic": "Exfiltration"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1489": {"name": "Service Stop", "tactic": "Impact"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
}

# ── Wormy technique → ATT&CK mapping ─────────────────────────────────────────

WORMY_MAPPING: Dict[str, List[str]] = {
    # Evasion
    "AMSI_Patch": ["T1562.001"],
    "AMSI_HW_Breakpoint": ["T1562.001"],
    "ETW_Disabled": ["T1562.006"],
    "DLL_Unhooking": ["T1562.001", "T1620"],
    "Module_Stomping": ["T1218", "T1620"],
    "PPID_Spoofing": ["T1134.004"],
    "Process_Hollowing": ["T1055.012"],
    "Reflective_DLL": ["T1055.001"],
    "Polymorphic_Engine": ["T1027", "T1027.002"],
    "Memory_Execution": ["T1620"],
    "JA3_Spoofing": ["T1071.001"],
    "Sleep_Obfuscation": ["T1497"],
    "Direct_Syscalls": ["T1562.001"],
    # C2
    "HTTPS_C2": ["T1071.001", "T1573.001"],
    "DNS_C2": ["T1071.004"],
    "DoH_C2": ["T1071.004", "T1132.001"],
    "ICMP_C2": ["T1095"],
    "Domain_Fronting": ["T1090.004"],
    "P2P_Gossip": ["T1104"],
    "DGA": ["T1568.002"],
    "Telegram_C2": ["T1102"],
    "Cloud_C2": ["T1102"],
    "PFS_Crypto": ["T1573.002"],
    # Credential Access
    "LSASS_Dump": ["T1003.001"],
    "SAM_Dump": ["T1003.002"],
    "NTDS_VSS": ["T1003.003"],
    "Kerberoasting": ["T1558.003"],
    "Pass_The_Hash": ["T1550.002"],
    "Password_Spray": ["T1110.003"],
    "Brute_Force": ["T1110.001"],
    "Credential_Files": ["T1552.001"],
    # Discovery
    "Network_Scan": ["T1046"],
    "Host_Discovery": ["T1018"],
    "Process_Discovery": ["T1057"],
    "AD_Enumeration": ["T1087.002", "T1069.002"],
    # Lateral Movement
    "SSH_Pivot": ["T1021.004"],
    "WinRM": ["T1021.006"],
    "RDP": ["T1021.001"],
    "PSExec": ["T1021.002"],
    "WMI_Exec": ["T1047"],
    "DCOM_ShellWindows": ["T1175"],
    "DCOM_MMC20": ["T1175"],
    "DCOM_WMI": ["T1047", "T1175"],
    # Persistence
    "Registry_Run_Key": ["T1547.001"],
    "Scheduled_Task": ["T1053.005"],
    "Service_Install": ["T1543.003"],
    # Cloud
    "AWS_IMDSv2": ["T1552.005"],
    "Azure_IMDS": ["T1552.005"],
    "GCP_Metadata": ["T1552.005"],
    "K8s_ServiceAccount": ["T1552.005"],
    # Exfiltration
    "Data_Exfil_C2": ["T1041"],
}


# ── Mapper class ──────────────────────────────────────────────────────────────


@dataclass
class TechniqueEvent:
    wormy_name: str
    attack_ids: List[str]
    timestamp: float
    target_host: Optional[str] = None
    operator: Optional[str] = None
    success: bool = True
    details: Dict = field(default_factory=dict)


class MITREMapper:
    """
    Records Wormy technique usage and exports ATT&CK-formatted reports.

    Usage:
        mapper = MITREMapper()
        mapper.record("AMSI_Patch", target="192.168.1.10", operator="op1")
        mapper.record("SSH_Pivot",  target="192.168.1.20")
        report = mapper.export_json()
        mapper.save_report("operation_report.json")
    """

    def __init__(self, operation_name: str = "Wormy Operation"):
        self.operation_name = operation_name
        self.start_time = time.time()
        self._events: List[TechniqueEvent] = []
        self._targets: Dict[str, List[str]] = {}  # host -> [technique_names]

    # ─── recording ───────────────────────────────────────────────────────────

    def record(
        self,
        wormy_technique: str,
        target: str = None,
        operator: str = None,
        success: bool = True,
        details: Dict = None,
    ) -> List[str]:
        """
        Record usage of a Wormy technique.
        Returns list of ATT&CK IDs mapped to.
        """
        attack_ids = WORMY_MAPPING.get(wormy_technique, [])
        if not attack_ids:
            logger.debug(f"MITRE: no mapping for '{wormy_technique}'")

        event = TechniqueEvent(
            wormy_name=wormy_technique,
            attack_ids=attack_ids,
            timestamp=time.time(),
            target_host=target,
            operator=operator,
            success=success,
            details=details or {},
        )
        self._events.append(event)

        if target:
            self._targets.setdefault(target, []).append(wormy_technique)

        logger.debug(f"MITRE record: {wormy_technique} → {attack_ids}")
        return attack_ids

    def record_from_bypass_list(self, bypass_techniques: List[str], target: str = None):
        """Bulk-record from EDRBypass.bypass_techniques list."""
        for t in bypass_techniques:
            self.record(t, target=target)

    # ─── export ──────────────────────────────────────────────────────────────

    def export_json(self) -> str:
        """Export full ATT&CK navigator layer + event log as JSON."""
        used_ids = set()
        for e in self._events:
            used_ids.update(e.attack_ids)

        # ATT&CK Navigator layer format
        navigator_layer = {
            "name": self.operation_name,
            "versions": {"attack": "14", "navigator": "4.9.1"},
            "domain": "enterprise-attack",
            "description": f"Auto-generated by Wormy ML | {time.ctime(self.start_time)}",
            "techniques": [
                {
                    "techniqueID": tid,
                    "tactic": ATTACK_TECHNIQUES.get(tid, {})
                    .get("tactic", "")
                    .lower()
                    .replace(" ", "-"),
                    "score": len([e for e in self._events if tid in e.attack_ids]),
                    "enabled": True,
                    "metadata": [],
                    "comment": ATTACK_TECHNIQUES.get(tid, {}).get("name", ""),
                }
                for tid in sorted(used_ids)
                if tid in ATTACK_TECHNIQUES
            ],
            "gradient": {
                "colors": ["#ff6666", "#ff0000"],
                "minValue": 0,
                "maxValue": max(
                    (len([e for e in self._events if tid in e.attack_ids]) for tid in used_ids),
                    default=1,
                ),
            },
        }

        # Event log
        event_log = [
            {
                "wormy_technique": e.wormy_name,
                "attack_ids": e.attack_ids,
                "attack_names": [ATTACK_TECHNIQUES.get(t, {}).get("name", t) for t in e.attack_ids],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e.timestamp)),
                "target": e.target_host,
                "operator": e.operator,
                "success": e.success,
                "details": e.details,
            }
            for e in self._events
        ]

        # Summary statistics
        summary = {
            "operation": self.operation_name,
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.start_time)),
            "total_events": len(self._events),
            "unique_techniques": len(used_ids),
            "targets_compromised": len(self._targets),
            "tactics_covered": list(
                {ATTACK_TECHNIQUES.get(tid, {}).get("tactic", "Unknown") for tid in used_ids}
            ),
            "technique_ids": sorted(used_ids),
        }

        full_report = {
            "summary": summary,
            "navigator_layer": navigator_layer,
            "event_log": event_log,
            "target_map": self._targets,
        }
        return json.dumps(full_report, indent=2)

    def save_report(self, path: str = None) -> str:
        """Save JSON report to file."""
        if not path:
            ts = time.strftime("%Y%m%d_%H%M%S")
            path = f"wormy_attack_report_{ts}.json"
        with open(path, "w") as f:
            f.write(self.export_json())
        logger.success(f"ATT&CK report saved: {path}")
        return path

    def print_summary(self):
        """Print a human-readable summary to the logger."""
        used = set()
        for e in self._events:
            used.update(e.attack_ids)

        tactic_map: Dict[str, List[str]] = {}
        for tid in sorted(used):
            tactic = ATTACK_TECHNIQUES.get(tid, {}).get("tactic", "Unknown")
            name = ATTACK_TECHNIQUES.get(tid, {}).get("name", tid)
            tactic_map.setdefault(tactic, []).append(f"{tid}: {name}")

        logger.info(f"=== MITRE ATT&CK Summary — {self.operation_name} ===")
        for tactic, techniques in sorted(tactic_map.items()):
            logger.info(f"  [{tactic}]")
            for t in techniques:
                logger.info(f"    {t}")
        logger.info(
            f"  Total: {len(self._events)} events, "
            f"{len(used)} unique techniques, "
            f"{len(self._targets)} targets"
        )

    def get_status(self) -> Dict:
        return {
            "operation": self.operation_name,
            "events": len(self._events),
            "techniques": len({t for e in self._events for t in e.attack_ids}),
            "targets": len(self._targets),
        }
