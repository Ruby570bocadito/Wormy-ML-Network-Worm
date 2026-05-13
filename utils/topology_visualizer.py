"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Network Topology Visualization
Generates visual network maps showing infection spread, host relationships,
and propagation paths using graphviz and pyvis.
"""


import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class TopologyVisualizer:
    """
    Network topology visualization

    Generates:
    - Static PNG/SVG maps (graphviz)
    - Interactive HTML maps (pyvis)
    - Text-based ASCII maps
    """

    def __init__(self):
        self.graphviz_available = False
        self.pyvis_available = False

        try:
            import graphviz

            self.graphviz_available = True
        except ImportError:
            pass

        try:
            from pyvis.network import Network

            self.pyvis_available = True
        except ImportError:
            pass

    def generate_text_map(self, hosts: Dict[str, Dict], infected: set, failed: set) -> str:
        """Generate ASCII text-based network map"""
        lines = []
        lines.append("=" * 80)
        lines.append("NETWORK TOPOLOGY MAP")
        lines.append("=" * 80)
        lines.append("")

        # Group by subnet
        subnets = {}
        for ip, info in hosts.items():
            parts = ip.split(".")
            subnet = ".".join(parts[:3])
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append((ip, info))

        for subnet, hosts_in_subnet in sorted(subnets.items()):
            lines.append(f"  Subnet: {subnet}.0/24")
            lines.append(f"  {'─' * 76}")

            for ip, info in hosts_in_subnet:
                if ip in infected:
                    status = "[INFECTED]"
                    symbol = "●"
                elif ip in failed:
                    status = "[FAILED]"
                    symbol = "✗"
                else:
                    status = "[DISCOVERED]"
                    symbol = "○"

                os_info = info.get("os_guess", "Unknown")
                ports = info.get("open_ports", [])
                ports_str = ",".join(str(p) for p in ports[:5])
                if len(ports) > 5:
                    ports_str += f"+{len(ports)-5}"

                lines.append(f"    {symbol} {ip:<18} {status:<14} {os_info:<12} Ports: {ports_str}")

                # Show lateral movements
                if "lateral_movements" in info:
                    for lm in info["lateral_movements"]:
                        target = lm.get("target", "?")
                        technique = lm.get("technique", "?")
                        success = lm.get("success", False)
                        arrow = "→" if success else "✗"
                        lines.append(f"      {arrow} {target} ({technique})")

            lines.append("")

        lines.append(f"  Legend: ● = Infected  ○ = Discovered  ✗ = Failed")
        lines.append("=" * 80)

        return "\n".join(lines)

    def generate_html_map(
        self,
        hosts: Dict[str, Dict],
        infected: set,
        failed: set,
        lateral_movements: List[Dict],
        output_path: str = "reports/topology.html",
    ) -> str:
        """Generate interactive HTML network map using pyvis"""
        if not self.pyvis_available:
            logger.warning("pyvis not available for HTML topology map")
            return ""

        try:
            from pyvis.network import Network

            net = Network(
                height="800px", width="100%", bgcolor="#1a1a2e", font_color="white", directed=True
            )

            # Set physics
            net.barnes_hut(
                gravity=-8000,
                central_gravity=0.3,
                spring_length=250,
                spring_strength=0.001,
                damping=0.09,
                overlap=0,
            )

            # Add hosts as nodes
            for ip, info in hosts.items():
                if ip in infected:
                    color = "#00ff88"
                    size = 30
                elif ip in failed:
                    color = "#ff4444"
                    size = 20
                else:
                    color = "#4488ff"
                    size = 25

                title = f"<b>{ip}</b><br>OS: {info.get('os_guess', 'Unknown')}<br>"
                title += f"Ports: {info.get('open_ports', [])}<br>"
                title += f"Status: {'Infected' if ip in infected else 'Failed' if ip in failed else 'Discovered'}"

                net.add_node(ip, label=ip, color=color, size=size, title=title)

            # Add lateral movement edges
            for lm in lateral_movements:
                source = lm.get("source", lm.get("ip", ""))
                target = lm.get("target", "")
                technique = lm.get("technique", "")
                success = lm.get("success", False)

                if source and target:
                    color = "#00ff88" if success else "#ff4444"
                    net.add_edge(
                        source,
                        target,
                        color=color,
                        title=f"{technique} ({'OK' if success else 'FAIL'})",
                        width=2,
                    )

            os.makedirs(
                os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True
            )
            net.save_graph(output_path)
            logger.info(f"Topology map saved to {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate HTML topology map: {e}")
            return ""

    def generate_graphviz_map(
        self,
        hosts: Dict[str, Dict],
        infected: set,
        failed: set,
        lateral_movements: List[Dict],
        output_path: str = "reports/topology.png",
    ) -> str:
        """Generate static topology map using graphviz"""
        if not self.graphviz_available:
            logger.warning("graphviz not available for static topology map")
            return ""

        try:
            import graphviz

            dot = graphviz.Digraph("WormyTopology", format="png")
            dot.attr(bgcolor="#1a1a2e")
            dot.attr("node", style="filled", fontname="Helvetica")

            # Group by subnet
            subnets = {}
            for ip in hosts:
                parts = ip.split(".")
                subnet = ".".join(parts[:3])
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(ip)

            for subnet, ips in subnets.items():
                with dot.subgraph(name=f'cluster_{subnet.replace(".", "_")}') as c:
                    c.attr(label=f"{subnet}.0/24", style="dashed", color="#444466")

                    for ip in ips:
                        if ip in infected:
                            color = "#00ff88"
                            fontcolor = "black"
                        elif ip in failed:
                            color = "#ff4444"
                            fontcolor = "white"
                        else:
                            color = "#4488ff"
                            fontcolor = "white"

                        c.node(ip, label=ip, fillcolor=color, fontcolor=fontcolor)

            # Add edges
            for lm in lateral_movements:
                source = lm.get("source", lm.get("ip", ""))
                target = lm.get("target", "")
                success = lm.get("success", False)
                technique = lm.get("technique", "")

                if source and target:
                    color = "#00ff88" if success else "#ff4444"
                    dot.edge(source, target, color=color, label=technique, fontcolor=color)

            os.makedirs(
                os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True
            )
            dot.render(output_path, cleanup=True)
            logger.info(f"Topology map saved to {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate graphviz topology map: {e}")
            return ""

    def generate_all(
        self,
        hosts: Dict[str, Dict],
        infected: set,
        failed: set,
        lateral_movements: List[Dict],
        output_dir: str = "reports",
    ) -> Dict[str, str]:
        """Generate all topology map formats"""
        os.makedirs(output_dir, exist_ok=True)
        results = {}

        # Text map
        text_map = self.generate_text_map(hosts, infected, failed)
        text_path = os.path.join(output_dir, "topology.txt")
        with open(text_path, "w") as f:
            f.write(text_map)
        results["text"] = text_path

        # HTML map
        html_path = self.generate_html_map(
            hosts, infected, failed, lateral_movements, os.path.join(output_dir, "topology.html")
        )
        if html_path:
            results["html"] = html_path

        # Graphviz map
        gv_path = self.generate_graphviz_map(
            hosts, infected, failed, lateral_movements, os.path.join(output_dir, "topology")
        )
        if gv_path:
            results["graphviz"] = gv_path

        return results
