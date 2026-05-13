"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Real-time Worm Visualization
Displays network topology and infection progress
"""


import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Set

try:
    import matplotlib.pyplot as plt
    import networkx as nx
    from matplotlib.animation import FuncAnimation

    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print(
        "Visualization libraries not available. Install networkx and matplotlib for visualization."
    )


class WormVisualizer:
    """Visualizes worm propagation in real-time"""

    def __init__(self, output_dir: str = "visualizations"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.network_graph = nx.Graph()
        self.infected_nodes = set()
        self.failed_nodes = set()
        self.scan_history = []

        if not VISUALIZATION_AVAILABLE:
            print("Warning: Visualization disabled (missing dependencies)")

    def add_host(self, ip: str, properties: Dict = None):
        """Add host to network graph"""
        if not VISUALIZATION_AVAILABLE:
            return

        self.network_graph.add_node(ip, **(properties or {}))

    def add_connection(self, source: str, target: str):
        """Add connection between hosts"""
        if not VISUALIZATION_AVAILABLE:
            return

        self.network_graph.add_edge(source, target)

    def mark_infected(self, ip: str):
        """Mark host as infected"""
        self.infected_nodes.add(ip)
        self.scan_history.append(
            {"timestamp": datetime.now().isoformat(), "event": "infection", "target": ip}
        )

    def mark_failed(self, ip: str):
        """Mark host as failed"""
        self.failed_nodes.add(ip)
        self.scan_history.append(
            {"timestamp": datetime.now().isoformat(), "event": "failed", "target": ip}
        )

    def plot_network(self, filename: str = "network_topology.png"):
        """Generate static network topology plot"""
        if not VISUALIZATION_AVAILABLE:
            print("Visualization not available")
            return

        plt.figure(figsize=(15, 10))

        # Layout
        pos = nx.spring_layout(self.network_graph, k=2, iterations=50)

        # Draw nodes
        node_colors = []
        for node in self.network_graph.nodes():
            if node in self.infected_nodes:
                node_colors.append("red")
            elif node in self.failed_nodes:
                node_colors.append("gray")
            else:
                node_colors.append("lightblue")

        nx.draw_networkx_nodes(
            self.network_graph, pos, node_color=node_colors, node_size=500, alpha=0.9
        )

        # Draw edges
        nx.draw_networkx_edges(self.network_graph, pos, alpha=0.3, width=1)

        # Draw labels
        nx.draw_networkx_labels(self.network_graph, pos, font_size=8)

        # Legend
        from matplotlib.patches import Patch

        legend_elements = [
            Patch(facecolor="red", label="Infected"),
            Patch(facecolor="lightblue", label="Discovered"),
            Patch(facecolor="gray", label="Failed"),
        ]
        plt.legend(handles=legend_elements, loc="upper right")

        plt.title(f"Network Topology - {len(self.infected_nodes)} Infected", fontsize=16)
        plt.axis("off")
        plt.tight_layout()

        # Save
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"Network topology saved to: {filepath}")

    def plot_infection_timeline(self, filename: str = "infection_timeline.png"):
        """Plot infection timeline"""
        if not VISUALIZATION_AVAILABLE or not self.scan_history:
            return

        # Extract infection events
        infections = [e for e in self.scan_history if e["event"] == "infection"]

        if not infections:
            return

        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in infections]
        infection_count = list(range(1, len(infections) + 1))

        plt.figure(figsize=(12, 6))
        plt.plot(timestamps, infection_count, marker="o", linestyle="-", linewidth=2, markersize=6)
        plt.xlabel("Time", fontsize=12)
        plt.ylabel("Cumulative Infections", fontsize=12)
        plt.title("Infection Timeline", fontsize=14)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"Infection timeline saved to: {filepath}")

    def generate_report(self, filename: str = "worm_report.html"):
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ML Network Worm Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-box h3 {{
            margin: 0;
            font-size: 36px;
        }}
        .stat-box p {{
            margin: 5px 0 0 0;
            opacity: 0.9;
        }}
        .timeline {{
            margin: 30px 0;
        }}
        .event {{
            padding: 10px;
            margin: 5px 0;
            border-left: 4px solid #4CAF50;
            background-color: #f9f9f9;
        }}
        .event.failed {{
            border-left-color: #f44336;
        }}
        img {{
            max-width: 100%;
            height: auto;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 ML Network Worm - Execution Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-box">
                <h3>{len(self.infected_nodes)}</h3>
                <p>Infected Hosts</p>
            </div>
            <div class="stat-box">
                <h3>{len(self.failed_nodes)}</h3>
                <p>Failed Attempts</p>
            </div>
            <div class="stat-box">
                <h3>{len(self.network_graph.nodes())}</h3>
                <p>Total Discovered</p>
            </div>
            <div class="stat-box">
                <h3>{len(self.infected_nodes) / max(len(self.network_graph.nodes()), 1) * 100:.1f}%</h3>
                <p>Success Rate</p>
            </div>
        </div>
        
        <h2>📊 Network Topology</h2>
        <img src="network_topology.png" alt="Network Topology">
        
        <h2>📈 Infection Timeline</h2>
        <img src="infection_timeline.png" alt="Infection Timeline">
        
        <h2>📝 Event Timeline</h2>
        <div class="timeline">
"""

        for event in self.scan_history[-50:]:  # Last 50 events
            event_class = "event failed" if event["event"] == "failed" else "event"
            html += f"""
            <div class="{event_class}">
                <strong>{event['timestamp']}</strong> - 
                {event['event'].upper()}: {event['target']}
            </div>
"""

        html += """
        </div>
        
        <h2>🎯 Infected Hosts</h2>
        <ul>
"""

        for ip in sorted(self.infected_nodes):
            html += f"            <li>{ip}</li>\n"

        html += """
        </ul>
    </div>
</body>
</html>
"""

        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            f.write(html)

        print(f"HTML report saved to: {filepath}")

    def export_data(self, filename: str = "worm_data.json"):
        """Export all data to JSON"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "infected_nodes": list(self.infected_nodes),
            "failed_nodes": list(self.failed_nodes),
            "total_nodes": len(self.network_graph.nodes()),
            "scan_history": self.scan_history,
            "network_edges": list(self.network_graph.edges()),
        }

        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        print(f"Data exported to: {filepath}")

    def generate_all_visualizations(self):
        """Generate all visualizations and reports"""
        print("\nGenerating visualizations...")

        if VISUALIZATION_AVAILABLE:
            self.plot_network()
            self.plot_infection_timeline()

        self.generate_report()
        self.export_data()

        print(f"\nAll visualizations saved to: {self.output_dir}/")


if __name__ == "__main__":
    # Test visualizer
    viz = WormVisualizer()

    # Add some test data
    viz.add_host("192.168.1.1")
    viz.add_host("192.168.1.100")
    viz.add_host("192.168.1.101")
    viz.add_host("192.168.1.102")

    viz.add_connection("192.168.1.1", "192.168.1.100")
    viz.add_connection("192.168.1.100", "192.168.1.101")
    viz.add_connection("192.168.1.100", "192.168.1.102")

    viz.mark_infected("192.168.1.1")
    viz.mark_infected("192.168.1.100")
    viz.mark_infected("192.168.1.101")
    viz.mark_failed("192.168.1.102")

    viz.generate_all_visualizations()
    print("\nTest visualizations generated!")
