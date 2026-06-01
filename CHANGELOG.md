# Changelog

## v4.1.0 (2026-06-01)

### Fixed
- Critical: missing `Optional` import in mixin_exploitation.py (package was unimportable)
- Missing `Optional`/`Dict` imports in evasion/direct_syscalls.py
- test_config_structure path resolution (config.py -> configs/config.py)
- All 194 Python files validated for syntax and typing imports

### Added
- C2: SMTP/Email channel for stealthy command & control
- C2: SSH Tunnel channel with multi-jump host support
- Exploit: RabbitMQ module (auth bypass + management RCE)
- Core: Adaptive rate limiter for intelligent scan throttling
- Core: Exploit chaining engine (multi-vuln dependency chains)
- Core: State persistence (snapshot/restore worm state across restarts)
- Monitoring: Credential dashboard for real-time cred visibility
- Docker Lab: Log4j and Struts2 vulnerable containers
- Kernel module stub for future LKM capabilities
- Wordlists: 13 per-service credential dictionaries
- Tests: 6 new test modules (C2, expanded lab, new modules, persistence, worm vs lab)

### Improved
- CI: bandit + semgrep security scanning integrated
- CI: pytest-cov with 30% coverage threshold
- Reproducible builds: requirements-lock.txt added
- Run lab script (run_lab.sh) with safety checks
- Config lab profile (config_lab.yaml) for isolated testing

### Changed
- 117 files changed, 10,547 insertions, 1,672 deletions

## v4.0.0 (2026-05-13)

### Added
- 44 exploit modules (12 new: EternalBlue, Zerologon, PrintNightmare, BlueKeep, WordPress, Apache, CloudFormation, Terraform, GCP IAM, Siemens S7, MQTT, OPC UA)
- worm_core/ package: refactored from 3079-line monolithic into 10 mixin modules
- CI pipeline with lint, security scan, and test jobs
- Pre-commit hooks configuration
- CHANGELOG, CONTRIBUTING, SECURITY.md

### Security
- Fixed shell=True -> shlex.split() in payload_deployer.py
- Fixed exec() -> subprocess.call(shlex.split()) in worm_core.py
- Fixed SQLi f-string -> escaped quotes in enterprise_password_engine.py
- Redacted 13 password leak lines across all exploits
- Replaced 2 bare except: with except Exception: in payload_deployer.py
- Moved 4 hardcoded credentials to env vars (JWT secret, MSF password, SSL verify)
- Added pickle.load() validation guards in scanner and evasion models

### Changed
- All 160 files reformatted with black + isort
- C2 fallback errors demoted from error to warning (normal in standalone mode)
- MultiProtocolC2.stop() added for clean shutdown
- README rewritten with Mermaid diagrams, exploit tables, and detailed architecture
- Requirements.txt synced with pyproject.toml

### Removed
- Junk files: worm_core.py.bak, _test_train.py, _train_output.txt, __pycache__/, .pytest_cache/, logs/, reports/
- Duplicate ML models in worm_core/ml_models/saved/

## v3.0.0 (Previous)

- Initial enterprise release with 32 exploit modules
- RL engine with DQN + Thompson Sampling
- Multi-protocol C2 (HTTPS, DoH, ICMP, cloud relay)
- Enterprise evasion engine (AMSI, ETW, DLL unhooking)
- Active Directory attack chain (LDAP, AS-REP, Kerberoast)
- Web dashboards (Armitage + Web)
