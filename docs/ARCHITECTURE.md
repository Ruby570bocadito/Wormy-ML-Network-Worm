# Architecture

Wormy is a modular Python framework. This document explains how the pieces fit
together, how data flows through the engine, and what the RL subsystem actually
does — the level of detail expected in a TFG defense or a technical interview.

---

## 1. High-level view

```
            ┌────────────────────────────────────────────┐
            │                 wormy CLI                  │
            │  (argparse subcommands + rich output)      │
            └───────────────────┬────────────────────────┘
                                │ builds
                                ▼
┌──────────────────────── WormCore ─────────────────────────┐
│  Composed from mixins, one per lifecycle phase:           │
│                                                           │
│  WormCoreBase          wiring, config, safety, shutdown   │
│  WormCoreScanning      recon, target selection            │
│  WormCoreExploitation  exploit execution, brute force     │
│  WormCoreLateral       SMB/WMI/pivots, AD attacks         │
│  WormCorePropagation   main loop, waves, dormant cells    │
│  WormCoreReporting     status, final audit report         │
└───────┬──────────────┬──────────────┬─────────────┬──────┘
        │              │              │             │
        ▼              ▼              ▼             ▼
   rl_engine/      exploits/      c2/          monitoring/
   (policy)        (actions)      (beacons)    (dashboards)
```

The engine never blocks on a dashboard: `monitoring/` components are optional,
registered in `_stoppable_components` and shut down by `shutdown()`.

---

## 2. Component map

| Path | Responsibility |
|---|---|
| `worm_core/cli.py` | subcommand CLI: `run`, `scan`, `lab`, `train`, `doctor`, `shell`, `version`; authorization gate; exit codes |
| `worm_core/shell.py` | interactive REPL (cmd.Cmd + rich): scan/exploit/creds/report… |
| `worm_core/mixin_base.py` | config load/validate, component wiring, safety constraints, kill switch, shutdown |
| `worm_core/mixin_scanning.py` | professional scanner orchestration, `select_next_target()` |
| `worm_core/mixin_exploitation.py` | `exploit_target(target) -> (bool, dict)` — the single exploit entry point |
| `worm_core/mixin_lateral.py` | credential reuse, SMB/WMI lateral movement, AD module |
| `worm_core/mixin_propagation.py` | `propagate()` loop, wave propagation, dormant cells, OTA brain updates |
| `worm_core/mixin_reporting.py` | status printing, MITRE ATT&CK mapping, final report |
| `rl_engine/` | DQN agent, PER memory, feature contract, inference wrapper |
| `scanner/` | port/CIDR scanning, OS fingerprinting, host classifier (sklearn) |
| `exploits/` | 44 exploit modules + credential manager + adaptive selector |
| `evasion/` | AMSI/ETW patching, DLL unhooking, JA3 spoofing, polymorphic engine |
| `attacks/` | AD attacks (AS-REP, Kerberoast), password engine |
| `c2/` | HTTPS, DoH, ICMP, MQTT, P2P gossip C2 channels |
| `post_exploit/` | local/remote persistence, agent controller |
| `monitoring/` | web dashboard (Flask), Armitage-style dashboard, CLI monitor, host monitor |
| `core/wave_propagation.py` | wave planner: coordinate multi-host attempts per wave |
| `training/` | curriculum scenarios (`scenarios.py`) + realistic training loop |
| `configs/` | `Config` loader (fail-hard on invalid YAML), defaults |
| `utils/` | logging (file + JSON + stderr), rate limiter, topology visualizer |

---

## 3. The propagation loop

`propagate()` (in `WormCorePropagation`) executes this cycle until a stop
condition fires:

1. **Scan** — `scan_network()` discovers hosts and builds exploit chains per host.
2. **Select** — `select_next_target()` asks the RL policy to rank candidates.
3. **Check safety** — `check_safety_constraints()` and the geofence
   (`is_target_allowed`) decide whether the target may be touched at all.
4. **Exploit** — `exploit_target()` consults the global `stop_event`, executes
   one module from the chain, and returns `(success: bool, evidence: dict)`.
5. **Propagate** — infected hosts feed `wave_propagation`, which schedules the
   next wave using discovered credentials.
6. **Learn** — every attempt is a transition `(state, action, reward, next_state)`
   pushed into PER; online learning steps run every N iterations.

Stop conditions: `max_infections` reached, `max_runtime_hours` elapsed, kill
switch file/code, `stop_event.set()` from any dashboard or the REPL, or an
empty target list.

---

## 4. The RL subsystem

### 4.1 Feature contract

`rl_engine/features.py` is the **only** place where host state becomes model
input:

- `FEATURES_PER_HOST = 15` (vulnerability score, port count, OS encoding,
  asset value, credential count, exploit history, detection risk, hop
  distance, …)
- `build_host_features(host) -> np.ndarray(15)`
- `build_state(hosts) -> np.ndarray(300)` — 20 hosts × 15, fixed geometry.

Training (`training/`) and inference (`rl_engine/wrapper.py`) both import this
module, so the feature order and semantics are identical at both ends. A
checkpoint whose geometry does not match is rejected on load.

### 4.2 Agent

`rl_engine/dqn_agent.py` implements:

- **Double DQN** (van Hasselt et al., 2015): the online network selects the
  next action, the target network evaluates it — `argmax`/`eval` split, not
  the vanilla `max(next_q)` shortcut.
- **Prioritized Experience Replay**: sum-tree, proportional sampling,
  importance-sampling weights folded into the loss. Rewards are
  Welford-normalized and the normalizer is frozen at observation time so the
  replay buffer is stationary.
- **Bootstrapped Thompson Sampling ensemble**: 5 heads, each with its own
  optimizer and a bounded bootstrap memory; head selection per episode
  implements Thompson sampling over Q-value uncertainty.
- **Stability**: gradient clipping, soft target update (τ = 0.005), target
  network in `eval()` mode during bootstrap computation.

### 4.3 Adaptive exploit selection

`exploits/adaptive_exploit_selector.py` models each exploit as a Beta-Bernoulli
bandit conditioned on the target context (service, OS, port). Success/failure
feedback updates `(α, β)`; selection samples from the posterior. It is a
complement to the DQN: the DQN chooses *targets*, the bandit chooses *which
exploit* per context.

### 4.4 Reward

```
reward = asset_value(target) × stealth_bonus × technique_multiplier
         − detection_penalty − failed_attempt_penalty
```

`asset_value`: domain controller 100, container host 90, exchange 80, database
70, file server 60, web server 30, workstation 10.

### 4.5 Training

`training/realistic_training.py` runs a curriculum of scenarios
(`training/scenarios.py`), each with a different network topology and
defensive posture. Per episode: ε decays, PER grows, checkpoints are written
atomically (`tmp` + `os.replace`) with geometry validation. `wormy train rl`
runs the curriculum; `wormy train --status` reports progress.

---

## 5. Safety architecture

Safety is layered so that no single component failure can cause runaway
propagation:

| Layer | Mechanism |
|---|---|
| **Intent** | CLI authorization gate (`--yes-i-am-authorized` / `WORMY_AUTHORIZED`) |
| **Simulation** | `dry_run` flag — exploit paths check it before acting |
| **Scope** | geofence evaluates *target* IPs against `safety.allowed_networks` |
| **Volume** | `max_infections`, `max_scan_rate`, `propagation_delay` |
| **Time** | `max_runtime_hours`, auto-destruct |
| **Halt** | kill switch (code or `STOP_WORMY_NOW` file), cooperative `stop_event` checked at every exploit boundary, dashboards stoppable via `shutdown()` |

The `stop_event` is created before any component and passed down; every
exploit, scan and wave iteration checks it. This is why the web dashboard's
"Stop engine" button and the REPL's `stop` command take effect immediately,
even mid-wave.

Details and the threat model: [SAFETY.md](SAFETY.md).

---

## 6. Dashboards and observability

- **Web dashboard** (`monitoring/web_dashboard.py`, port 5000, `127.0.0.1`):
  read-only KPIs/charts/topology; emergency stop; command execution disabled
  unless `WORMY_DASHBOARD_COMMANDS=1`.
- **Armitage-style dashboard** (port 5001): operator-oriented monitor.
- **CLI monitor**: rich live panel refreshed from the activity bridge.
- **Logging**: rotating file + JSON lines under `logs/`; console output goes to
  **stderr** so stdout stays clean for machine-readable output.

Every host transition, exploit attempt, credential discovery and safety
violation is logged — the framework is designed to be *observable* first, which
is exactly what makes it useful for studying detection.

---

## 7. Design decisions worth defending

1. **Mixins over inheritance** — each lifecycle phase is independently
   testable; `WormCore` is a composition, not a god class.
2. **`(bool, dict)` exploit contract** — success plus structured evidence
   (module, technique, timestamp) instead of a bare boolean, so reporting and
   RL rewards share the same source of truth.
3. **Fail-hard config** — invalid YAML aborts startup with a specific error,
   rather than falling back to defaults that mask mistakes.
4. **Geometry-validated checkpoints** — an RL checkpoint that doesn't match
   the current feature/action space refuses to load. Silent random-weight
   agents are worse than crashes.
5. **stderr/stdout separation** — `wormy scan --json | jq` works because logs
   never touch stdout.
6. **localhost by default** — every listener (dashboards, lab services) binds
   to `127.0.0.1` unless explicitly overridden.
