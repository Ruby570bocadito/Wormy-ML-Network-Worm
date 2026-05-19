<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=8B0000&height=100&section=header&text=Wormy&fontSize=40&fontColor=ffffff&fontAlign=50&fontAlignY=50&animation=fadeIn" alt="header"/>
</p>

<p align="center">
  <strong>ML-Powered Polymorphic Network Worm</strong><br/>
  <em>Self-replicating payload with dynamic encryption, multi-vector propagation, and adversarial evasion.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white" alt="PyTorch"/>
  <img src="https://img.shields.io/badge/version-4.0.0-blue?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/exploits-44%20modules-blue?style=for-the-badge" alt="Exploits"/>
  <img src="https://img.shields.io/badge/evasion-AMSI%20%7C%20ETW%20%7C%20DLL-purple?style=for-the-badge" alt="Evasion"/>
  <img src="https://img.shields.io/badge/AD-Kerberoast%20%7C%20AS--REP%20Roast-darkred?style=for-the-badge" alt="AD"/>
  <img src="https://img.shields.io/badge/tests-35%2F39%20PASS-brightgreen?style=for-the-badge" alt="Tests"/>
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=Ruby570bocadito&label=Downloads&color=8B0000&style=flat" alt="downloads"/>
</p>

---

## 🎯 What is Wormy?

**Wormy** is an **ML-driven network propagation framework** for authorized red team operations and security research. It combines reinforcement learning-based decision making with enterprise-grade exploitation techniques to simulate advanced persistent threats (APTs) in controlled environments.

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Wormy Core v4                                 │
│                                                                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │
│  │  Scanner   │  │  RL Brain  │  │  Exploit   │  │  Knowledge     │  │
│  │  CIDR/TCP  │─▶│  DQN+TS    │─▶│  Manager   │─▶│  Graph         │  │
│  └────────────┘  └────────────┘  └──────┬─────┘  └────────────────┘  │
│                                         │                              │
│  ┌──────────────────────────────────────┼──────────────────────────┐  │
│  │  Enterprise Engines                   │                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┴──────┐ ┌──────────────┐  │  │
│  │  │ Password │ │ Evasion  │ │ AD Attacker   │ │ Persistence  │  │  │
│  │  │ Engine   │ │ AMSI/ETW │ │ LDAP+Kerb     │ │ WMI+SSH+Cron │  │  │
│  │  └──────────┘ └──────────┘ └───────────────┘ └──────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │  44 Exploit Modules                                            │   │
│  │  Windows(7) │ WebApp(12) │ Cloud(6) │ SCADA(3) │ Network(16)  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│                    ┌──────────────────────────┐                        │
│                    │  Multi-Protocol C2 + OTA │                        │
│                    │  HTTPS │ DoH │ ICMP │ P2P │                        │
│                    └────────────┬─────────────┘                        │
│                                 │                                      │
│              ┌──────────────────┼──────────────────┐                   │
│              │                  │                  │                    │
│        ┌─────┴─────┐    ┌──────┴──────┐    ┌──────┴──────┐             │
│        │ Armitage  │    │ Web Dash    │    │ Rich CLI    │             │
│        │ :5001     │    │ :5000       │    │ Interactive │             │
│        └───────────┘    └─────────────┘    └─────────────┘             │
└───────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Features

| Feature | Description | Category |
|---------|-------------|----------|
| **RL Brain** | DQN + Thompson Sampling learns target priority (DC=100, DB=70, WS=10) | ML |
| **44 Exploit Modules** | Windows, WebApp, Cloud, SCADA, IoT, Network services | Exploitation |
| **AMSI/ETW/DLL Unhooking** | Real memory patching, not stubs | Evasion |
| **Active Directory** | LDAP enum → AS-REP Roast → Kerberoast (no creds needed) | AD |
| **Multi-Protocol C2** | HTTPS, DoH, ICMP tunneling, P2P gossip mesh | C2 |
| **OTA Brain Updates** | Hot-swap model weights via C2 without restart | ML |
| **Password Engine** | Spray + mutation (35 variants) + credential stuffing | Credentials |
| **Polymorphic Engine** | AST metamorphism, semantic NOP injection, hash verification | Evasion |
| **Web Dashboards** | Armitage-style (:5001) + professional (:5000) | Monitoring |
| **Docker Lab** | 11-container vulnerable network for safe testing | Testing |
| **MITRE ATT&CK** | Automatic technique mapping and reporting | Reporting |
| **Kill Switch** | Remote propagation termination with auth code | Safety |

---

## 🚀 Quick Start

### Installation

```bash
# Clone
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm.git
cd Wormy-ML-Network-Worm

# Install dependencies
pip install -r requirements.txt
```

### Dry-Run (Safe Simulation)

```bash
# Interactive mode — no real exploits
python3 -m worm_core --dry-run --interactive

# Scan only
python3 -m worm_core --scan-only
```

### Docker Lab (Safe Testing)

```bash
# Start 11-container vulnerable network
docker compose -f docker-compose-lab.yml up -d

# Run worm against lab
python3 tests/run_worm_vs_lab.py
```

### Live Mode (Authorized Only)

```bash
# Stealth profile — slow, full evasion
python3 -m worm_core --profile stealth --target 192.168.1.0/24

# Aggressive profile — fast, maximum spread
python3 -m worm_core --profile aggressive --target 10.0.1.0/24

# With Metasploit integration
python3 -m worm_core --config configs/config_msf.yaml

# One-command automation (Kali)
sudo ./scripts/deploy_kali.sh --live --target 10.0.1.0/24
```

---

## 🎬 Demo

### Interactive CLI Session

```
$ python3 -m worm_core --dry-run --interactive

  ╔══════════════════════════════════════════════════╗
  ║         Wormy v4.0 — ML Network Worm             ║
  ║         Ruby570bocadito (c) 2024                 ║
  ╚══════════════════════════════════════════════════╝

  [DRY-RUN MODE] No real exploits will be executed

wormy > scan professional
  Scanning 192.168.1.0/24...
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:12
  [+] Discovered 23 hosts (5 classified)

wormy > targets
  +----------------+----------------+--------+-------+
  | IP             | OS             | Type   | Value |
  +----------------+----------------+--------+-------+
  | 192.168.1.10   | Windows 2019   | DC     | 100   |
  | 192.168.1.20   | Ubuntu 22.04   | DB     | 70    |
  | 192.168.1.30   | Windows 2016   | Exchange| 80   |
  | 192.168.1.50   | Windows 11     | WS     | 10    |
  | 192.168.1.60   | CentOS 8       | Web    | 30    |
  +----------------+----------------+--------+-------+

wormy > vulns 192.168.1.10
  [!] CVE-2020-1472  Zerologon        — Netlogon privilege escalation
  [!] CVE-2021-34527 PrintNightmare    — Spooler RCE/LPE
  [~] MS17-010       EternalBlue      — SMBv1 buffer overflow

wormy > run 5
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 5/5 iterations
  [+] Propagation complete
      Infected: 8  |  Discovered: 23  |  Failed: 3
      Credentials: 12  |  Lateral moves: 5

wormy > report
  [+] Audit report saved to reports/audit_20240115.json
  [+] MITRE ATT&CK mapping saved to reports/mitre_mapping.json
```

### All Commands

```bash
# Core
python3 -m worm_core --dry-run                    # Safe simulation
python3 -m worm_core --dry-run --interactive       # Interactive CLI
python3 -m worm_core --scan-only                   # Scan and exit
python3 -m worm_core --profile stealth             # Slow, full evasion
python3 -m worm_core --profile aggressive          # Fast, max spread
python3 -m worm_core --profile audit               # Medium, logging

# With config
python3 -m worm_core --config configs/config_msf.yaml

# Kill switch
python3 -m worm_core --kill-switch <code>

# Testing
make test                                          # Run test suite
python3 tests/run_worm_vs_lab.py                   # Docker lab test
```

---

## 🏗️ Architecture

### Propagation Flow

```
  ┌─────────┐     ┌──────────────┐     ┌──────────────┐
  │  Worm   │────▶│  Scanner     │────▶│  Hosts       │
  │  Core   │     │  CIDR/TCP    │     │  Sorted by   │
  │         │     │  Probe       │     │  Asset Value │
  └────┬────┘     └──────────────┘     └──────┬───────┘
       │                                      │
       │         ┌──────────────┐             │
       │         │  AD Attacker │◀────────────┘
       │         │  LDAP+AS-REP │
       │         └──────┬───────┘
       │                │
       │         ┌──────▼───────┐
       │         │  RL Brain    │  ← Thompson Sampling
       │         │  DQN+TS      │     selects best exploit
       │         └──────┬───────┘
       │                │
       │         ┌──────▼───────┐
       │         │  Evasion     │  ← AMSI + ETW + DLL
       │         │  Engine      │     + Sandbox detection
       │         └──────┬───────┘
       │                │
       │         ┌──────▼───────┐
       │         │  Exploit     │  ← 44 modules
       │         │  Manager     │     contextual bandit
       │         └──────┬───────┘
       │                │
       │         ┌──────▼───────┐
       │         │  Persistence │  ← WMI + SSH + Cron
       │         │  Engine      │
       │         └──────┬───────┘
       │                │
       │         ┌──────▼───────┐
       │         │  Feedback    │  ← reward = asset_value
       │         │  to RL       │     * stealth_bonus
       │         └──────────────┘
       │
       ▼
  ┌─────────────────┐
  │  C2 + Dashboards│
  │  HTTPS/DoH/ICMP │
  │  :5000/:5001    │
  └─────────────────┘
```

### Project Structure

```
wormy/
├── worm_core/                  # Main orchestrator (700+ lines)
│   ├── mixin_base.py           # Init, safety, shutdown
│   ├── mixin_scanning.py       # CIDR discovery, host classification
│   ├── mixin_exploitation.py   # Exploit target, brute force
│   ├── mixin_lateral.py        # Pivot, spread, pass-the-hash
│   ├── mixin_propagation.py    # Adaptive cycles, online learning
│   └── mixin_reporting.py      # Audit trail, session logging
├── scanner/                    # Enterprise + professional scanners
├── exploits/                   # 44 exploit modules + manager
│   ├── exploit_manager.py      # Contextual bandit selector
│   ├── modules/                # All exploit implementations
│   ├── enterprise_password_engine.py
│   └── active_directory.py
├── evasion/                    # AMSI/ETW/DLL, polymorphic, IDS
├── post_exploit/               # Lateral movement, persistence
├── c2/                         # Multi-protocol C2 + OTA
│   ├── multi_protocol_c2.py    # HTTPS/DoH/ICMP/P2P
│   ├── pfs_crypto.py           # X25519 + AES-256-GCM
│   └── resilient_c2.py         # DoH + Domain Fronting
├── rl_engine/                  # DQN + Thompson Sampling
├── core/                       # Wave propagation, agent controller
├── monitoring/                 # Web + Armitage dashboards
├── swarm/                      # Multi-agent coordinator
├── payloads/                   # Payload generation
├── ml_models/                  # Trained models
├── training/                   # RL training pipeline
├── tests/                      # 35/39 passing
├── docker-compose-lab.yml      # Vulnerable lab (11 containers)
└── configs/                    # YAML configurations
```

### Network Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  wormy-c2       │────▶│  wormy-network   │◀────│  vulnerable-win  │
│  172.20.0.10    │     │  172.20.0.0/16   │     │  172.20.0.20     │
│  :5000,:5001    │     │                  │     │  DC + Exchange   │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                │
                       ┌────────┴─────────┐
                       │  vulnerable-db   │     ┌──────────────────┐
                       │  172.20.0.21     │     │  test-runner     │
                       │  MySQL+Postgres  │     │  172.20.0.100    │
                       └──────────────────┘     └──────────────────┘
```

---

## 💥 Exploit Modules (44)

### Windows Critical (7)

| Module | CVE | Technique |
|--------|-----|-----------|
| EternalBlue | MS17-010 | SMBv1 buffer overflow |
| BlueKeep | CVE-2019-0708 | RDP pre-auth RCE |
| Zerologon | CVE-2020-1472 | Netlogon privilege escalation |
| PrintNightmare | CVE-2021-34527 | Spooler RCE/LPE |
| ProxyShell | CVE-2021-34473 | Exchange pre-auth RCE chain |
| Docker daemon | 2375/tcp | Unauthenticated API abuse |
| Kubernetes | 6443/tcp | Kubelet API / dashboard RCE |

### Web Application (12)

| Module | CVE | Technique |
|--------|-----|-----------|
| Log4j | CVE-2021-44228 | JNDI injection |
| Struts | CVE-2017-5638 | OGNL injection RCE |
| WebLogic | CVE-2020-14882/14883 | Console RCE |
| Jenkins | Script Console | Groovy RCE |
| Jira | Velocity | SSTI template injection |
| Confluence | OGNL | ProcessBuilder payload |
| Citrix | CVE-2019-19781 | Path traversal + webshell |
| GitLab | DjVu/ExifTool | File upload payload |
| WordPress | Various | Plugin/admin RCE |
| Apache | Path traversal | LFI/RFI + RCE chain |
| Tomcat | AJP/manager | Ghostcat + manager deploy |
| Elasticsearch | 9200/tcp | Painless script RCE |

### Cloud & Infrastructure (6)

| Module | Target | Technique |
|--------|--------|-----------|
| AWS CloudFormation | Stack creation | IAM escalation via templates |
| Terraform | State files | Backend state manipulation |
| GCP IAM | Service accounts | Privilege escalation |
| Kubernetes | K8s API | Pod exec + service account |
| Docker | Docker API | Container escape |
| VMware vCenter | VCSA | CVE-based RCE |

### SCADA & IoT (3)

| Module | Target | Technique |
|--------|--------|-----------|
| Siemens S7 | S7comm | PLC read/write, stop CPU |
| MQTT | 1883/tcp | Subscribe + inject messages |
| OPC UA | 4840/tcp | Read/write tags |

### Network Services (16)

SSH, FTP, Telnet, SMB, MySQL, MSSQL, PostgreSQL, MongoDB, Redis, Active Directory, SNMP, VNC, Elasticsearch, Docker, Kubernetes, VPN (IKE/IPSEC)

---

## 🧠 ML Brain

### Adaptive Exploit Selection

The exploit selector uses a **contextual bandit** with Thompson Sampling to rank exploits per target:

```
  State Space (15 features/host)
  ┌─────────────────────────────────────┐
  │ Vulnerability Score │ Port Count    │
  │ OS Encoding         │ Asset Value   │
  │ Credential Count    │ Exploit Hist  │
  │ Detection Risk      │ Hop Distance  │
  └──────────────────┬──────────────────┘
                     │
              ┌──────▼──────┐
              │  DQN Network│
              │  15→256→256 │
              │  →128→N     │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │  Thompson   │
              │  Sampling   │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │  Best Exploit│
              │  for Target  │
              └─────────────┘
```

### Reward Function

```python
ASSET_VALUES = {
    'domain_controller': 100,    'container_host': 90,
    'exchange_server':    80,    'database_server':  70,
    'file_server':        60,    'web_server':       30,
    'workstation':        10,
}

reward = asset_value * stealth_bonus * technique_multiplier
```

### RL Engine

- Double DQN with prioritized replay memory
- Gradient clipping + soft target updates (tau=0.005)
- Automatic model save/load with fallback to training
- OTA model updates via C2 without restart

---

## 🛡️ Evasion Engine

| Technique | Description |
|-----------|-------------|
| **AMSI Bypass** | Patches `AmsiScanBuffer` → returns `AMSI_RESULT_CLEAN` |
| **ETW Silencing** | Patches `EtwEventWrite` → blocks kernel telemetry |
| **DLL Unhooking** | Restores clean ntdll.dll from disk, removes EDR hooks |
| **Sandbox Detection** | VM artifacts, process list, RAM, username analysis |
| **Sleep Jitter** | Log-normal distribution timing, evades beacon detection |
| **JA3 Spoofing** | Mimics Chrome 120 TLS fingerprints |
| **Polymorphic Engine** | AST metamorphism, semantic NOP injection, hash verification |
| **Direct Syscalls** | Dynamic SSN resolution, bypasses user-land hooks |
| **Sleep Obfuscation** | Heap encryption + stack spoofing during idle |

---

## 🔑 Password Engine

| Feature | Description |
|---------|-------------|
| **Password Spray** | 1 password × N targets per window (lockout-safe) |
| **Mutation Engine** | 35+ variants per base word (`Admin` → `4dm1n!`, `Admin@2024`, ...) |
| **Company-Based** | Generates passwords from company name + season + year |
| **Credential Stuffing** | Uses breach lists for known credential reuse |
| **Parallel Execution** | Configurable thread pool for speed |
| **Protocols** | SSH, FTP, MySQL, Postgres, MSSQL, MongoDB, HTTP |

---

## 🏢 Active Directory Module

- **DC discovery** — port signature (88+389) + DNS SRV records
- **LDAP enumeration** — null session or authenticated
- **AS-REP Roasting** — crackable hashes without credentials (`hashcat -m 18200`)
- **Kerberoasting** — TGS ticket extraction (`hashcat -m 13100`)
- **BloodHound export** — JSON for attack path visualization

---

## 📡 Multi-Protocol C2

| Protocol | Description |
|----------|-------------|
| **HTTPS/HTTP** | Beaconing with configurable jitter |
| **DNS-over-HTTPS** | Covert channel via Cloudflare/Google TXT records |
| **ICMP Tunneling** | Bi-directional C2 over raw ICMP Echo |
| **P2P Gossip** | Agents share intel without central C2 |
| **Domain Fronting** | CDN Host header override |
| **Cloud Relay** | Telegram Bot API, Slack Webhooks, Google Sheets |
| **OTA Updates** | Send .pth model weights, hot-swap without restart |
| **PFS** | X25519 ECDH + AES-256-GCM per session |

---

## 📊 Dashboards

### Web Dashboard — `http://localhost:5000`

8 stat cards (Infected, Discovered, Vulns, Exploit Chains, Lateral Movement, Credentials, C2 Beacons, Mutations) + Hosts table + 8 REST API endpoints.

### Armitage Dashboard — `http://localhost:5001`

Visual network map with color-coded host status, real-time statistics, activity feed, and context menu (Exploit, Scan, Vulnerabilities).

### REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | Propagation status |
| `GET /api/hosts` | Discovered hosts |
| `GET /api/activity` | Activity feed |
| `GET /api/vulnerabilities` | Found vulnerabilities |
| `GET /api/credentials` | Captured credentials |
| `GET /api/topology` | Network topology |
| `GET /api/stats` | Statistics |
| `POST /api/command` | Send command |

---

## 🖥️ Interactive CLI

| Command | Description |
|---------|-------------|
| `scan [professional\|basic]` | Scan network with progress bar |
| `targets` | List discovered hosts |
| `vulns <ip>` | Show vulnerabilities for target |
| `topo` | Network topology visualization |
| `exploit <ip>` | Exploit specific target |
| `chain <ip>` | Show exploit chain |
| `bruteforce <ip> [service]` | Brute force credentials |
| `deploy <ip> [type]` | Deploy payload |
| `exec <ip> <command>` | Execute command on host |
| `persist <ip> [methods]` | Establish persistence |
| `pivot <source_ip>` | Lateral movement options |
| `run [iterations]` | Start propagation |
| `stop` | Stop propagation |
| `report` | Generate audit report |

---

## 🧪 Testing

```bash
# Unit tests
make test

# Docker lab (11 containers)
docker compose -f docker-compose-lab.yml up -d
python3 tests/run_worm_vs_lab.py

# Cleanup
docker compose -f docker-compose-lab.yml down
./scripts/cleanup_engagement.py
```

---

## 🗺️ Roadmap

- [ ] Full ICMP tunneling implementation
- [ ] Windows agent with native evasion suite
- [ ] Real-time collaborative multi-operator mode
- [ ] Automated exploit chain generation
- [ ] Integration with peekaboo for PrivEsc chaining
- [ ] Integration with BTY for post-exploitation modules
- [ ] GPT-assisted exploit selection

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing**, **red team operations**, and **educational purposes** only.

- Use only on systems you own or have explicit written permission to test
- Misuse may violate local and international laws
- The author is not responsible for any misuse or damage caused by this tool

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/Ruby570bocadito">Ruby570bocadito</a></sub>
</p>
