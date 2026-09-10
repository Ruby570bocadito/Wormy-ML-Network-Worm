# Usage Guide

Complete reference for every command, flag and interactive command, plus
step-by-step walkthroughs.

---

## 1. Installation

```bash
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm.git
cd Wormy-ML-Network-Worm

pip install -r requirements.txt     # or: pip install .
```

Python 3.10+ is required. For the RL engine you also need `torch` (the CPU
build is enough for the lab scale). Then verify the environment:

```bash
wormy doctor
```

`doctor` checks: Python version, core dependencies, torch (+ CUDA
availability), Docker CLI and compose v2, lab compose file, default config
validity, RL feature geometry (15 features/host), and writable runtime
directories. Critical failures set exit code `1`.

---

## 2. The `wormy` CLI

Exit codes: `0` ok · `1` runtime error · `2` usage/refusal · `130`
interrupted.

### `wormy run` — the engine

```bash
wormy run [flags]
```

| Flag | Effect |
|---|---|
| `--dry-run` | simulate every exploit (recommended default) |
| `--scan-only` | recon and print a summary, then exit |
| `--profile NAME` | `stealth` · `aggressive` · `audit` · `lab_docker` |
| `--target CIDR…` | override `network.target_ranges` from the config |
| `--config FILE` | custom YAML config |
| `--web` | start the web dashboard in the background |
| `--web-port PORT` | dashboard port (default 5000) |
| `--interactive, -i` | enter the REPL after startup |
| `--no-monitor` | disable the rich CLI monitor |
| `--no-geofence` | disable the geofence (labs only) |
| `--kill-switch CODE` | activate the kill switch with CODE and exit |
| `--yes-i-am-authorized` | required for live mode (or `WORMY_AUTHORIZED=1`) |

Examples:

```bash
wormy run --dry-run --target 127.0.0.0/24        # safe simulation
wormy run --scan-only --profile audit            # recon pass
wormy run --profile stealth --yes-i-am-authorized # live (authorized)
wormy run --dry-run --web --web-port 5001        # + dashboard
```

### `wormy scan` — reconnaissance only

```bash
wormy scan --target 10.0.0.0/24 --output scan.json
wormy scan --target 10.0.0.0/24 --json      # machine-readable stdout
wormy scan --basic                           # basic scanner instead of pro
```

Logs go to **stderr**, so `wormy scan --json | jq .` works cleanly.

### `wormy lab` — Docker lab manager

```bash
wormy lab up            # start (builds images the first time)
wormy lab up --expanded # the 15-service variant
wormy lab urls          # service cheat-sheet (URLs + credentials)
wormy lab status        # docker compose ps
wormy lab down          # stop + remove volumes
wormy lab rebuild       # from scratch
```

The compose file is resolved from `$WORMY_LAB_DIR`, the current directory, or
the project root — in that order.

### `wormy train` — ML training

```bash
wormy train --list-scenarios        # curriculum contents
wormy train --status                # trained? best reward? episodes?
wormy train rl --episodes 50        # RL curriculum (subset)
wormy train classifier              # host classifier (sklearn)
wormy train evasion                 # evasion model
wormy train all                     # everything
```

RL checkpoints are written atomically and validated on load; a geometry
mismatch fails loudly.

### `wormy shell` — interactive REPL

```bash
wormy shell --dry-run
```

### `wormy version`

```bash
wormy version            # wormy 4.3.0 (python 3.12.x on linux)
wormy version --json     # {"wormy": "4.3.0", ...}
```

---

## 3. The REPL

Every command has a short alias (shown in parentheses):

| Command | Description |
|---|---|
| `scan [pro\|basic]` (`s`) | discover hosts, build exploit chains |
| `targets` (`t`) | table of discovered targets and status |
| `vulns <ip>` (`v`) | vulnerabilities for one host |
| `chain <ip>` | exploit chain steps for one host |
| `exploit <ip>` (`x`) | run the chain against one host |
| `bruteforce <ip>` | credential brute force |
| `deploy <ip> [type]` | deploy payload (beacon/webshell/reverse_shell) via SSH/SMB/web |
| `persist <ip> [methods]` | remote persistence (cron, systemd, registry…) |
| `exec <ip> <cmd>` (`e`) | run a command through the registered agent |
| `creds` (`c`) | discovered credentials |
| `hosts` / `host <ip>` (`h`) | host monitor dashboard / one host detail |
| `activity [n]` | last n events |
| `pivot <ip>` | reachable hosts from an infected node |
| `topo` | generate topology maps (files) |
| `evasion` | evasion statistics |
| `run [iterations]` (`r`) | start the propagation loop |
| `stop` | cooperative stop |
| `train [model]` | train ML models from the REPL |
| `report` | final audit report |
| `status` | banner + status |
| `exit` (`q`) | shutdown and leave |

Walkthrough against the lab:

```
> scan                    # discover
> targets                 # pick a target
> vulns 10.0.0.5          # inspect
> exploit 10.0.0.5        # compromise
> creds                   # harvest
> run                     # autonomous propagation
> report                  # evidence
```

---

## 4. Web dashboard

```bash
wormy run --dry-run --web
# open http://127.0.0.1:5000
```

- **KPIs** — infected, discovered, failed, vulnerabilities, chains, lateral
  moves, credentials, beacons
- **Charts** — propagation timeline, host status, severity distribution
- **Topology** — SVG graph; node color = status, edges = lateral movement
  (solid success / dashed failed), hover for OS + ports
- **Hosts** — click a row for the detail dialog
- **Activity** — live feed (XSS-escaped)
- **Stop engine** — cooperative stop; **Pause** suspends auto-refresh

The dashboard binds to `127.0.0.1`. Command execution over HTTP is disabled
unless `WORMY_DASHBOARD_COMMANDS=1`. REST reference: [API.md](API.md).

---

## 5. Configuration

`configs/config.yaml` is the source of truth; the `Config` loader fails hard
on invalid values instead of silently defaulting.

```yaml
network:
  target_ranges: ["192.168.100.0/24"]   # keep this as tight as the engagement scope
  excluded_ips: ["192.168.100.1"]
  max_threads: 50

propagation:
  max_infections: 25
  propagation_delay: 2.0

safety:
  allowed_networks: ["192.168.100.0/24", "127.0.0.0/8"]
  max_runtime_hours: 4
  geofence_enabled: true
  kill_switch_file: "STOP_WORMY_NOW"
```

Profiles (`--profile`) override tuned values on top of the config:
`stealth` (slow, evasive), `aggressive` (fast, loud), `audit` (balanced,
heavy logging), `lab_docker` (tuned for the Docker lab).

---

## 6. Testing

```bash
make test           # full pytest suite (unit)
make test-cov       # with coverage report
pytest -m "not slow" tests/
wormy lab up && wormy lab down    # lab lifecycle smoke
```

Tests marked `integration` need the Docker lab; CI skips them by default.

---

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `wormy: command not found` | use `python3 -m worm_core` or `pip install .` |
| Live run refused with red banner | that's the gate — add `--yes-i-am-authorized` |
| `torch` missing warning in doctor | `pip install torch` (CPU build fine) |
| Dashboard unreachable | started without `--web`, or bound to another host (`WORMY_DASHBOARD_HOST`) |
| Checkpoint load refuses geometry | the feature/action space changed — retrain (`wormy train rl`) |
| Scan finds nothing in the lab | `wormy lab up` first; targets are `127.0.0.1` ranges only |
| Logs flood stdout | they don't anymore — logs go to stderr; files live in `logs/` |
