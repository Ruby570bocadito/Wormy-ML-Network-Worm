"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Audit Report Generator
Generates comprehensive reports in JSON, CSV, and text formats
"""


import csv
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class AuditReportGenerator:
    """
    Generates audit reports from worm operation data

    Formats: JSON, CSV, Text
    """

    def __init__(self):
        self.report_data = {}

    def generate(
        self,
        worm_stats: Dict,
        scan_results: List[Dict],
        infected_hosts: set,
        failed_targets: set,
        exploit_stats: Dict = None,
        credential_stats: Dict = None,
        lateral_movement_stats: Dict = None,
        output_dir: str = "reports",
    ) -> Dict[str, str]:
        """
        Generate comprehensive audit report

        Returns:
            Dict of format -> filepath
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Wormy ML Network Worm",
                "version": "2.0",
                "purpose": "Security Audit - Authorized Testing",
            },
            "executive_summary": self._build_executive_summary(
                worm_stats, infected_hosts, failed_targets
            ),
            "scan_results": scan_results,
            "infected_hosts": sorted(list(infected_hosts)),
            "failed_targets": sorted(list(failed_targets)),
            "exploitation": exploit_stats or {},
            "credentials": credential_stats or {},
            "lateral_movement": lateral_movement_stats or {},
            "worm_statistics": worm_stats,
            "recommendations": self._generate_recommendations(
                scan_results, infected_hosts, exploit_stats
            ),
        }

        output_files = {}

        # JSON report
        json_path = os.path.join(output_dir, f"audit_report_{timestamp}.json")
        with open(json_path, "w") as f:
            json.dump(self.report_data, f, indent=2, default=str)
        output_files["json"] = json_path

        # CSV report
        csv_path = os.path.join(output_dir, f"audit_report_{timestamp}.csv")
        self._write_csv(csv_path, scan_results, infected_hosts)
        output_files["csv"] = csv_path

        # Text report
        txt_path = os.path.join(output_dir, f"audit_report_{timestamp}.txt")
        self._write_text(txt_path)
        output_files["text"] = txt_path

        logger.info(f"Audit reports generated: {output_files}")
        return output_files

    def _build_executive_summary(
        self, worm_stats: Dict, infected_hosts: set, failed_targets: set
    ) -> Dict:
        """Build executive summary"""
        total_attempts = len(infected_hosts) + len(failed_targets)
        success_rate = len(infected_hosts) / max(total_attempts, 1) * 100

        return {
            "total_hosts_discovered": worm_stats.get("total_hosts_discovered", 0),
            "total_infected": len(infected_hosts),
            "total_failed": len(failed_targets),
            "success_rate": f"{success_rate:.1f}%",
            "total_scans": worm_stats.get("scans", 0),
            "duration": (
                str(
                    (worm_stats.get("end_time") or datetime.now())
                    - (worm_stats.get("start_time") or datetime.now())
                )
                if worm_stats.get("start_time")
                else "N/A"
            ),
        }

    def _generate_recommendations(
        self, scan_results: List[Dict], infected_hosts: set, exploit_stats: Dict = None
    ) -> List[Dict]:
        """Generate security recommendations based on findings"""
        recommendations = []

        # Check for default credentials
        default_cred_hosts = []
        for host in scan_results:
            if host.get("vulnerability_score", 0) > 50:
                default_cred_hosts.append(host["ip"])

        if default_cred_hosts:
            recommendations.append(
                {
                    "severity": "HIGH",
                    "category": "Default Credentials",
                    "finding": f"{len(default_cred_hosts)} hosts with high vulnerability scores",
                    "affected_hosts": default_cred_hosts[:10],
                    "remediation": "Change all default credentials immediately. Implement strong password policy.",
                }
            )

        # Check for unnecessary services
        high_risk_ports = {21, 23, 445, 3389, 3306, 5432, 6379, 27017}
        exposed_services = []
        for host in scan_results:
            risky = set(host.get("open_ports", [])) & high_risk_ports
            if risky:
                exposed_services.append(
                    {
                        "ip": host["ip"],
                        "risky_ports": sorted(list(risky)),
                    }
                )

        if exposed_services:
            recommendations.append(
                {
                    "severity": "MEDIUM",
                    "category": "Unnecessary Services",
                    "finding": f"{len(exposed_services)} hosts with high-risk services exposed",
                    "affected_hosts": [s["ip"] for s in exposed_services[:10]],
                    "remediation": "Disable unnecessary services. Use firewalls to restrict access.",
                }
            )

        # General recommendations
        recommendations.extend(
            [
                {
                    "severity": "HIGH",
                    "category": "Network Segmentation",
                    "finding": "Flat network topology detected",
                    "remediation": "Implement network segmentation with VLANs. Isolate critical systems.",
                },
                {
                    "severity": "MEDIUM",
                    "category": "Monitoring",
                    "finding": "Automated scanning detected hosts without alerting",
                    "remediation": "Deploy IDS/IPS. Configure alerting for scanning activity.",
                },
                {
                    "severity": "HIGH",
                    "category": "Patch Management",
                    "finding": "Outdated service versions detected",
                    "remediation": "Implement automated patch management. Regularly update all services.",
                },
                {
                    "severity": "MEDIUM",
                    "category": "Access Control",
                    "finding": "Excessive network reachability between hosts",
                    "remediation": "Implement zero-trust architecture. Use micro-segmentation.",
                },
            ]
        )

        return recommendations

    def _write_csv(self, filepath: str, scan_results: List[Dict], infected_hosts: set):
        """Write CSV report"""
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "IP Address",
                    "OS",
                    "Open Ports",
                    "Vulnerability Score",
                    "Services",
                    "Status",
                    "Services Detail",
                ]
            )

            for host in scan_results:
                ip = host.get("ip", "")
                status = "INFECTED" if ip in infected_hosts else "DISCOVERED"
                services = host.get("services", {})
                services_str = (
                    ", ".join(f"{p}:{s}" for p, s in services.items()) if services else ""
                )

                writer.writerow(
                    [
                        ip,
                        host.get("os_guess", "Unknown"),
                        ", ".join(str(p) for p in host.get("open_ports", [])),
                        host.get("vulnerability_score", 0),
                        services_str,
                        status,
                        host.get("banners", {}),
                    ]
                )

    def _write_text(self, filepath: str):
        """Write human-readable text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("WORMY ML NETWORK WORM - SECURITY AUDIT REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Metadata
        meta = self.report_data.get("report_metadata", {})
        lines.append(f"Generated: {meta.get('generated_at', 'N/A')}")
        lines.append(f"Tool: {meta.get('tool', 'N/A')}")
        lines.append(f"Purpose: {meta.get('purpose', 'N/A')}")
        lines.append("")

        # Executive Summary
        lines.append("-" * 80)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        summary = self.report_data.get("executive_summary", {})
        for key, value in summary.items():
            lines.append(f"  {key.replace('_', ' ').title()}: {value}")
        lines.append("")

        # Infected Hosts
        lines.append("-" * 80)
        lines.append("INFECTED HOSTS")
        lines.append("-" * 80)
        for ip in self.report_data.get("infected_hosts", []):
            lines.append(f"  [INFECTED] {ip}")
        lines.append("")

        # Failed Targets
        lines.append("-" * 80)
        lines.append("FAILED TARGETS")
        lines.append("-" * 80)
        for ip in self.report_data.get("failed_targets", []):
            lines.append(f"  [FAILED] {ip}")
        lines.append("")

        # Scan Results
        lines.append("-" * 80)
        lines.append("SCAN RESULTS")
        lines.append("-" * 80)
        for host in self.report_data.get("scan_results", []):
            ip = host.get("ip", "Unknown")
            os_guess = host.get("os_guess", "Unknown")
            ports = host.get("open_ports", [])
            vuln = host.get("vulnerability_score", 0)
            status = (
                "INFECTED" if ip in self.report_data.get("infected_hosts", []) else "DISCOVERED"
            )

            lines.append(f"\n  [{status}] {ip}")
            lines.append(f"    OS: {os_guess}")
            lines.append(f"    Ports: {', '.join(str(p) for p in ports)}")
            lines.append(f"    Vulnerability Score: {vuln}/100")

            services = host.get("services", {})
            if services:
                lines.append(f"    Services:")
                for port, service in services.items():
                    lines.append(f"      - {port}: {service}")
        lines.append("")

        # Recommendations
        lines.append("-" * 80)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 80)
        for i, rec in enumerate(self.report_data.get("recommendations", []), 1):
            severity = rec.get("severity", "INFO")
            category = rec.get("category", "Unknown")
            finding = rec.get("finding", "")
            remediation = rec.get("remediation", "")

            lines.append(f"\n  {i}. [{severity}] {category}")
            lines.append(f"     Finding: {finding}")
            lines.append(f"     Remediation: {remediation}")
        lines.append("")

        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        with open(filepath, "w") as f:
            f.write("\n".join(lines))
