<p align="center">
  <h1 align="center">Wormy -- ML Network Worm v4.0</h1>
  <p align="center">
    <strong>ML-Driven Autonomous Network Propagation Platform</strong>
  </p>
  <p align="center">
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/version-4.0.0-blue.svg" alt="Version"></a>
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python"></a>
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License"></a>
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/exploits-44-blue.svg" alt="Exploits"></a>
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/evasion-enterprise-purple.svg" alt="Evasion"></a>
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/AD-kerberoast-darkred.svg" alt="AD"></a>
    <a href="https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm"><img src="https://img.shields.io/badge/tests-35%2F39-brightgreen.svg" alt="Tests"></a>
  </p>
</p>

---

> **EDUCATIONAL & AUDIT PURPOSE ONLY** -- Only use on systems you own or have explicit written authorization for. Unauthorized access is illegal.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm
cd Wormy-ML-Network-Worm

# 2. Install all dependencies
pip install -r requirements.txt

# 3. Dry-run (safe simulation, no real exploits)
python3 -m worm_core --dry-run

# 4. Against Docker lab
docker compose -f docker-compose-lab.yml up -d
python3 tests/run_worm_vs_lab.py

# 5. Full scan + exploit mode (authorized environment only)
sudo ./scripts/deploy_kali.sh --live --target 192.168.1.0/24
```

---

## Usage

```bash
# Interactive mode with full CLI (recommended)
python3 -m worm_core --dry-run --interactive

# Profiles
python3 -m worm_core --profile stealth       # Slow, full evasion
python3 -m worm_core --profile aggressive    # Fast, maximum spread
python3 -m worm_core --profile audit         # Medium, logging

# Scan only
python3 -m worm_core --scan-only

# With Metasploit
python3 -m worm_core --config configs/config_msf.yaml

# One-command automation (Kali)
sudo ./scripts/deploy_kali.sh --live --target 10.0.1.0/24
```

### Arguments

| Argument | Description |
|---|---|
| `--config <file>` | Configuration file |
| `--scan-only` | Scan network and exit |
| `--kill-switch <code>` | Activate kill switch |
| `--profile <name>` | stealth, aggressive, audit |
| `--dry-run` | Simulate without real exploits |
| `--no-monitor` | Disable CLI monitor |
| `--interactive` | Interactive CLI mode |

---

## Project Structure

```
wormy/
├── worm_core/                        # Main orchestrator package
│   ├── __init__.py                   # Re-exports WormCore from mixins
│   ├── __main__.py                   # Entry point (python3 -m worm_core)
│   ├── config_profiles.py
│   ├── module_imports.py
│   ├── mixin_base.py                 # __init__, safety, shutdown
│   ├── mixin_scanning.py
│   ├── mixin_exploitation.py
│   ├── mixin_lateral.py
│   ├── mixin_propagation.py
│   ├── mixin_reporting.py
│   └── standalone.py                 # get_local_ip(), main()
├── configs/                          # YAML configuration files
├── scanner/                          # Enterprise + Professional scanners
├── exploits/                         # Exploit manager + 44 exploit modules
├── evasion/                          # AMSI/ETW/DLL, polymorphic, IDS evasion
├── post_exploit/                     # Lateral movement, persistence, payloads
├── c2/                               # Multi-protocol C2, ICMP tunnel, PFS crypto
├── rl_engine/                        # DQN + Thompson Sampling RL agent
├── core/                             # Adaptive cycle, wave propagation, agent controller
├── monitoring/                       # Web dashboard, Armitage dashboard, multi-operator
├── swarm/                            # Multi-agent swarm coordinator
├── payloads/                         # Payload generation and management
├── ml_models/                        # Trained ML models
├── training/                         # RL training pipeline + scenarios
├── tests/                            # Unit + integration tests (35 pass, 4 known failures)
└── docker-compose-lab.yml            # Vulnerable lab environment
```

---

## Requirements

```bash
pip install -r requirements.txt
```

### Core
- torch>=2.0.0, impacket>=0.11.0, paramiko>=3.4.0, requests>=2.31.0
- rich>=13.0.0, psutil>=5.9.0, pyyaml>=6.0.1, networkx>=3.0

### Enterprise
- pymysql, pymongo, psycopg2-binary, ldap3, dnspython

### Optional
- scapy, python-nmap, gymnasium

---

## License

MIT License -- for authorized security research and penetration testing only.

**2024 Ruby570bocadito** -- [GitHub](https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm)
