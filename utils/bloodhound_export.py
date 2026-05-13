# -*- coding: utf-8 -*-
"""
Wormy v3.0 — BloodHound Data Exporter
Developed by Ruby570bocadito

Converts worm's AD enumeration data into BloodHound-compatible JSON format.
Import the output files into BloodHound to visualize attack paths:
  - Computers.json
  - Users.json
  - Groups.json
  - Domains.json
  - GPOs.json

Usage:
  python3 utils/bloodhound_export.py --input data/ad_intel.json --out-dir /tmp/bh_data/
  Then in BloodHound: Upload Data -> select all JSON files
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from utils.logger import logger
except ImportError:

    class _L:
        info = warning = debug = success = print

    logger = _L()


# BloodHound timestamps are Unix epoch in seconds
_now = int(datetime.utcnow().timestamp())


def _sid(prefix: str, rid: int) -> str:
    """Generate a fake SID for offline data."""
    return f"S-1-5-21-{abs(hash(prefix)) % 2**32}-{abs(hash(prefix+'x')) % 2**32}-{abs(hash(prefix+'xx')) % 2**32}-{rid}"


def _guid() -> str:
    return str(uuid.uuid4()).upper()


# ─────────────────────────────────────────────────────────────────────────────
# BloodHound JSON builders
# ─────────────────────────────────────────────────────────────────────────────
class BloodHoundExporter:
    """
    Converts worm intel into BloodHound 4.x JSON format.
    Supports: Computers, Users, Groups, Domains, Sessions, ACLs
    """

    def __init__(self, domain: str, domain_sid: str = None):
        self.domain = domain.upper()
        self.domain_sid = domain_sid or _sid(domain, 512)
        self.computers = []
        self.users = []
        self.groups = []
        self.ous = []
        self.gpos = []

    # ── Computers ─────────────────────────────────────────────────────────────
    def add_computer(
        self,
        hostname: str,
        ip: str,
        os_type: str = "Windows Server",
        os_version: str = "2019",
        is_dc: bool = False,
        services: List[str] = None,
        pwned: bool = False,
        sessions: List[str] = None,
    ):
        """Add a computer object (host discovered by the worm)."""
        fqdn = f"{hostname.upper()}.{self.domain}"
        comp_id = _sid(hostname, 1000 + len(self.computers))
        obj = {
            "Properties": {
                "name": fqdn,
                "domain": self.domain,
                "distinguishedname": f"CN={hostname.upper()},CN=Computers,DC={'DC='.join(self.domain.split('.'))}",
                "domainsid": self.domain_sid,
                "highvalue": is_dc,
                "unconstraineddelegation": is_dc,
                "enabled": True,
                "objectid": comp_id,
                "operatingsystem": f"{os_type} {os_version}",
                "pwdlastset": _now - 86400 * 30,
                "lastlogontimestamp": _now - 3600,
                "serviceprincipalnames": services or [],
                "description": f"IP: {ip} | Pwned: {pwned}",
            },
            "ObjectIdentifier": comp_id,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "Sessions": {
                "Results": [{"UserSID": s, "ComputerSID": comp_id} for s in (sessions or [])],
                "Collected": True,
                "FailureReason": None,
            },
            "LocalAdmins": {"Results": [], "Collected": True, "FailureReason": None},
            "RemoteDesktopUsers": {"Results": [], "Collected": True, "FailureReason": None},
            "DcomUsers": {"Results": [], "Collected": True, "FailureReason": None},
            "PSRemoteUsers": {"Results": [], "Collected": True, "FailureReason": None},
        }
        if is_dc:
            obj["Properties"]["unconstraineddelegation"] = True
        self.computers.append(obj)
        return comp_id

    # ── Users ──────────────────────────────────────────────────────────────────
    def add_user(
        self,
        username: str,
        display_name: str = None,
        email: str = None,
        is_admin: bool = False,
        has_spn: bool = False,
        no_preauth: bool = False,
        password: str = None,
        groups: List[str] = None,
        rid: int = None,
    ):
        """Add a user object (discovered via LDAP enum)."""
        rid = rid or (1100 + len(self.users))
        user_id = _sid(username, rid)
        obj = {
            "Properties": {
                "name": f"{username.upper()}@{self.domain}",
                "domain": self.domain,
                "distinguishedname": f"CN={display_name or username},CN=Users,DC={'DC='.join(self.domain.split('.'))}",
                "domainsid": self.domain_sid,
                "objectid": user_id,
                "highvalue": is_admin,
                "enabled": True,
                "pwdlastset": _now - 86400 * 90,
                "lastlogon": _now - 86400 * 7,
                "displayname": display_name or username,
                "email": email or f"{username}@{self.domain.lower()}",
                "title": "Administrator" if is_admin else "User",
                "admincount": is_admin,
                "dontreqpreauth": no_preauth,
                "hasspn": has_spn,
                "description": f"{'SPN: kerberoastable | ' if has_spn else ''}{'No preauth: ASREProastable | ' if no_preauth else ''}{'Pwd: ' + password if password else ''}".strip(
                    " |"
                ),
            },
            "ObjectIdentifier": user_id,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "PrimaryGroupSID": _sid(self.domain, 513),  # Domain Users
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "SPNTargets": (
                [{"ComputerSID": _guid(), "Port": 0, "Service": "krbtgt"}] if has_spn else []
            ),
        }
        self.users.append(obj)
        return user_id

    # ── Groups ─────────────────────────────────────────────────────────────────
    def add_group(
        self, name: str, members: List[str] = None, is_admin_group: bool = False, rid: int = None
    ) -> str:
        """Add a group object."""
        rid = rid or (500 + len(self.groups))
        group_id = _sid(name, rid)
        obj = {
            "Properties": {
                "name": f"{name.upper()}@{self.domain}",
                "domain": self.domain,
                "distinguishedname": f"CN={name},CN=Users,DC={'DC='.join(self.domain.split('.'))}",
                "domainsid": self.domain_sid,
                "objectid": group_id,
                "highvalue": is_admin_group,
                "admincount": is_admin_group,
                "description": f"Worm-discovered group",
            },
            "ObjectIdentifier": group_id,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "Members": [{"ObjectIdentifier": m, "ObjectType": "User"} for m in (members or [])],
        }
        self.groups.append(obj)
        return group_id

    # ── Domain ─────────────────────────────────────────────────────────────────
    def build_domain(
        self, dc_computer_id: str, admin_group_id: str, functional_level: str = "2016"
    ) -> Dict:
        """Build the domain object."""
        return {
            "Properties": {
                "name": self.domain,
                "domain": self.domain,
                "distinguishedname": f"DC={'DC='.join(self.domain.split('.'))}",
                "domainsid": self.domain_sid,
                "objectid": self.domain_sid,
                "highvalue": True,
                "functionallevel": functional_level,
                "description": "Domain discovered by Wormy v3.0",
            },
            "ObjectIdentifier": self.domain_sid,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "Links": [],
            "ChildObjects": [],
            "Trusts": [],
        }

    # ── Export ─────────────────────────────────────────────────────────────────
    def export(self, out_dir: str) -> List[str]:
        """Write all BloodHound JSON files to out_dir."""
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        files = []
        meta = {
            "methods": 46,
            "type": "unknown",
            "count": 0,
            "version": 5,
            "timestamp": datetime.utcnow().isoformat(),
        }

        datasets = [
            ("computers", self.computers),
            ("users", self.users),
            ("groups", self.groups),
        ]

        # Add built-in groups
        da_id = self.add_group("Domain Admins", is_admin_group=True, rid=512)
        ea_id = self.add_group("Enterprise Admins", is_admin_group=True, rid=519)
        bu_id = self.add_group("Domain Users", is_admin_group=False, rid=513)

        for name, data in datasets:
            path = os.path.join(out_dir, f"{ts}_{name}.json")
            obj = {
                "data": data,
                "meta": {**meta, "type": name, "count": len(data)},
            }
            with open(path, "w") as f:
                json.dump(obj, f, indent=2)
            files.append(path)
            logger.info(f"BloodHound export: {path} ({len(data)} {name})")

        return files


# ─────────────────────────────────────────────────────────────────────────────
# Convert worm AD intel to BloodHound
# ─────────────────────────────────────────────────────────────────────────────
def convert_worm_intel(intel: Dict, exporter: BloodHoundExporter):
    """
    Convert the intel dict from ActiveDirectoryAttacker into BloodHound objects.
    Intel format from exploits/active_directory.py:
    {
      'domain': 'empresa.local',
      'dc': {'ip': '...', 'hostname': '...'},
      'users': [{'username': ..., 'has_spn': ..., 'no_preauth': ...}],
      'computers': [{'hostname': ..., 'ip': ..., 'os': ...}],
      'hashes': {'asrep': [...], 'kerberoast': [...]},
      'credentials': [{'username': ..., 'password': ...}],
    }
    """
    # Domain Controller
    dc = intel.get("dc", {})
    if dc:
        dc_id = exporter.add_computer(
            hostname=dc.get("hostname", "DC01"),
            ip=dc.get("ip", "0.0.0.0"),
            os_type="Windows Server",
            os_version=dc.get("os_version", "2019"),
            is_dc=True,
            services=["ldap", "kerberos", "dns"],
        )
    else:
        dc_id = None

    # Computers
    comp_ids = {}
    for comp in intel.get("computers", []):
        cid = exporter.add_computer(
            hostname=comp.get("hostname", comp.get("ip", "UNKNOWN")),
            ip=comp.get("ip", ""),
            os_type=comp.get("os", "Windows"),
            pwned=comp.get("pwned", False),
            services=comp.get("services", []),
        )
        comp_ids[comp.get("ip", "")] = cid

    # Users
    user_ids = {}
    for user in intel.get("users", []):
        uname = user.get("username", "")
        uid = exporter.add_user(
            username=uname,
            display_name=user.get("display_name", uname),
            email=user.get("email"),
            is_admin=user.get("is_admin", False),
            has_spn=user.get("has_spn", False),
            no_preauth=user.get("no_preauth", False),
            password=user.get("password"),
        )
        user_ids[uname] = uid

    # Credentials found → mark admin
    for cred in intel.get("credentials", []):
        uname = cred.get("username", "")
        if uname in user_ids:
            # Already added — update description only
            pass
        else:
            exporter.add_user(uname, password=cred.get("password"), is_admin=True)

    # Domain Admins group with discovered admin users
    admin_users = [
        uid
        for uname, uid in user_ids.items()
        if any(u.get("username") == uname and u.get("is_admin") for u in intel.get("users", []))
    ]
    exporter.add_group("Domain Admins", members=admin_users, is_admin_group=True, rid=512)

    return dc_id


# ─────────────────────────────────────────────────────────────────────────────
# Build from live AgentController data
# ─────────────────────────────────────────────────────────────────────────────
def build_from_agent_intel(agents: List[Dict], domain: str, out_dir: str) -> List[str]:
    """
    Build BloodHound data directly from agent intel dicts
    collected by AgentController.QuickIntelCollector.
    """
    exp = BloodHoundExporter(domain)
    dc_added = False

    for agent in agents:
        ip = agent.get("ip", "unknown")
        hostname = agent.get("hostname", ip.replace(".", "-"))
        is_dc = agent.get("is_dc", False) or "domain" in agent.get("processes", "").lower()

        comp_id = exp.add_computer(
            hostname=hostname,
            ip=ip,
            os_type=agent.get("os_type", "Linux"),
            is_dc=is_dc,
            pwned=True,  # all agents are already compromised
            services=[str(p) for p in agent.get("open_ports", [])],
        )

        # Users found in env_vars / sudo output
        for line in agent.get("env_vars", "").splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                if any(k in key.upper() for k in ["USER", "LOGNAME"]):
                    exp.add_user(val.strip(), is_admin="root" in val.lower())

    return exp.export(out_dir)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Wormy BloodHound Exporter")
    parser.add_argument(
        "--input", required=False, help="AD intel JSON file from active_directory.py"
    )
    parser.add_argument("--domain", default="EMPRESA.LOCAL", help="Active Directory domain name")
    parser.add_argument(
        "--out-dir", default="/tmp/bloodhound_data", help="Output directory for JSON files"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Generate demo data without real AD intel"
    )
    args = parser.parse_args()

    exp = BloodHoundExporter(args.domain)

    if args.demo:
        # Build realistic demo data
        dc_id = exp.add_computer(
            "DC01",
            "10.0.0.1",
            "Windows Server",
            "2019",
            is_dc=True,
            services=["ldap", "kerberos", "dns", "rpc"],
        )
        srv_id = exp.add_computer(
            "FILESERVER", "10.0.0.10", "Windows Server", "2016", services=["smb", "rdp"], pwned=True
        )
        ws_id = exp.add_computer("PC-FINANCE", "10.0.0.50", "Windows 10", services=["smb", "rdp"])

        admin_id = exp.add_user("administrator", is_admin=True, rid=500, password="Admin123!")
        svc_id = exp.add_user(
            "svc_backup", has_spn=True, rid=1105, display_name="Backup Service Account"
        )
        hr_id = exp.add_user(
            "jsmith",
            no_preauth=True,
            rid=1110,
            display_name="John Smith",
            email="jsmith@empresa.local",
        )
        it_id = exp.add_user("itadmin", is_admin=True, rid=1111, password="Summer2024!")

        exp.add_group("Domain Admins", [admin_id, it_id], is_admin_group=True, rid=512)
        exp.add_group("Domain Users", [admin_id, svc_id, hr_id, it_id], rid=513)
        exp.add_group("IT Department", [it_id], rid=1200)
        exp.add_group("HR Department", [hr_id], rid=1201)

        print("  [DEMO] Generated demo AD data")

    elif args.input and os.path.exists(args.input):
        input_path = os.path.realpath(args.input)
        with open(input_path) as f:
            intel = json.load(f)
        convert_worm_intel(intel, exp)
        print(f"  Loaded intel from {input_path}")

    else:
        print("  No --input specified — use --demo to generate demo data")
        print("  Or point --input at the JSON from exploits/active_directory.py output")
        sys.exit(1)

    files = exp.export(args.out_dir)

    print(f"\n  BloodHound files written to: {args.out_dir}")
    for f in files:
        print(f"    {os.path.basename(f)}")
    print(f"\n  Import into BloodHound:")
    print(f"    BloodHound UI -> Upload Data -> select all files in {args.out_dir}")
    print(f"    Then run queries: 'Find All Domain Admins', 'Shortest Path to DA'")


if __name__ == "__main__":
    main()
