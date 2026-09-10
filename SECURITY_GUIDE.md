# Safety & Control Guide

> **Who this is for:** operators running Wormy inside an isolated,
> authorized lab (Docker lab, CTF range, or a written-authorization
> engagement). If you do not have explicit permission for every host you
> intend to touch, **stop here** — running this tool against systems you do
> not own or are not authorized to test is illegal in most jurisdictions.

---

## Safety controls (and what they actually do)

| Control | Mechanism | Enforced where |
|---------|-----------|----------------|
| **Kill switch** | `python3 -m worm_core --kill-switch <code>` sets `kill_switch_activated` + a process-wide `threading.Event` that is checked on **every** path into `exploit_target()` (main loop, wave threads, lateral movement, manual CLI commands) | `worm_core/mixin_base.py`, `worm_core/mixin_exploitation.py` |
| **Signal file** | Creating a file named `STOP_WORMY_NOW` in the repo root stops the propagation loop | checked in the propagation loop |
| **Geofencing** | Every **target IP** is validated against `safety.allowed_networks` before any packet is sent. Default allows RFC1918 ranges only; your local subnet is *not* auto-whitelisted anymore — configure it explicitly | `WormCoreBase.is_target_allowed()` |
| **Max infections** | Atomic (`check_and_add_infected`) admission under the data lock — concurrent wave threads cannot overshoot the cap | `worm_core/mixin_base.py` |
| **Auto-destruct** | Stops the run after `safety.auto_destruct_time` hours (disabled by default: `0`) | `check_safety_constraints()` |
| **Dry run** | `--dry-run` / `--scan-only` perform discovery and ML decisions only: no AD roasting traffic, no decoy/fuzzing traffic, no persistence installation, no exploit payloads | gates at the top of `exploit_target()`, `scan_network()`, `propagate()` |
| **Runtime cap** | `safety.max_runtime_hours` hard-stops long-running propagations | `check_safety_constraints()` |

### Emergency stop

```bash
# 1. Stop the propagation loop
python3 -m worm_core --kill-switch EMERGENCY_STOP_2024

# 2. Or drop a signal file
touch STOP_WORMY_NOW

# 3. Verify nothing is listening anymore
ss -tlnp | grep -E "5000|5001|8443" || echo "clean"
```

The kill-switch code is configured per profile in `configs/config.yaml`
(`safety.kill_switch_code`). Note it in your engagement notes **before**
starting a run — and prefer the signal file in shared environments, since a
command-line switch ends up in shell history and process listings.

---

## What the worm does on a compromised host (honest list)

Wormy is a **red-team automation framework**, not a benign simulator. When an
exploit succeeds against a lab or authorized target it can, depending on the
enabled modules:

1. Record the infection (logs, knowledge graph, dashboards)
2. Register the host with the agent controller (SSH task channel)
3. Attempt credential discovery (brute force / spraying — this is real
   authentication traffic)
4. Collect AD intelligence (LDAP enumeration, Kerberoast / AS-REP hashes)
5. Attempt lateral movement and propagation using harvested credentials
6. Install persistence **only if** `propagation.self_replicate` /
   persistence modules are explicitly enabled — persistence is **off** in the
   default and lab profiles

It does **not** ship destructive payloads: no file encryption, no destructive
wipe routines, no ransomware logic.

### Residual risk you must accept before running

- Successful exploits execute **real exploitation code** against real
  services. Fragile targets can crash even with a "clean" exploit.
- Credential attacks generate authentication failures that can lock out
  accounts (`enterprise_password_engine` is lockout-aware, but only if you
  keep the spray windows configured).
- Captured credentials and hashes are written to local logs/reports. Encrypt
  your working directory and delete reports after the engagement.

---

## Lab hygiene

```bash
# Start the isolated lab (all ports bound to 127.0.0.1 on the host)
docker compose -f docker-compose-lab.yml up -d

# Run the worm against the lab range only
python3 -m worm_core --profile lab_docker --target 192.168.100.0/24

# Full cleanup
docker compose -f docker-compose-lab.yml down -v
python3 scripts/cleanup_engagement.py
```

The lab's host-side port bindings are `127.0.0.1`-only: the vulnerable
services are reachable from your LAN **only** through the worm's process,
never directly.

---

## Before / during / after an engagement

**Before**

1. Written authorization for every host/range (or your own lab)
2. Isolated network segment or the Docker lab
3. Note the kill-switch code and the signal-file location
4. Snapshot/backup anything you cannot afford to break

**During**

1. Watch the dashboards (`:5000` / `:5001`) and the log stream
2. Verify that discovered hosts stay inside `allowed_networks`
3. Stop immediately if you see out-of-scope IPs in the target list

**After**

1. Kill switch + signal file
2. `scripts/cleanup_engagement.py` for automated cleanup
3. Review and then delete credential reports; keep only the engagement
   findings you need for the write-up
4. Reboot or revert lab hosts that received persistence

---

## Incident procedure

If anything behaves unexpectedly (out-of-scope hosts, crash loops, runaway
traffic):

```bash
touch STOP_WORMY_NOW                 # stop the loop
python3 -m worm_core --kill-switch EMERGENCY_STOP_2024
pkill -f "python3 -m worm_core"      # last resort, kills the process
docker compose -f docker-compose-lab.yml down -v
```

Then investigate before re-running: check `reports/` and the logs for what
the worm targeted, and correct `allowed_networks` / `target_ranges` so it
cannot happen again.
