# Safety Guide

Wormy is an active exploitation framework. This document describes exactly what
prevents it from doing damage outside its intended scope, and what is expected
from you as the operator.

---

## 1. Authorization model

| Mode | Requirement | Behavior |
|---|---|---|
| `wormy run --dry-run` | none | full pipeline, all exploit paths simulated |
| `wormy scan` | none | reconnaissance only (port scan, fingerprint) |
| `wormy run --yes-i-am-authorized` | explicit flag | live exploitation |
| `WORMY_AUTHORIZED=1 wormy run` | environment opt-in | live exploitation |
| `wormy run` (no flag) | — | **refused** (exit code 2, red banner) |

The gate exists so that a careless command cannot start a live engagement.
It is not DRM — it is a deliberate pause that forces you to state intent.

**Your responsibility**: keep written authorization for any network you test,
restrict `safety.allowed_networks` to that scope, and prefer `--dry-run`
whenever possible.

---

## 2. Layered controls

### 2.1 Scope — geofence

- Target **IPs** are evaluated against `safety.allowed_networks`
  (RFC 1918 by default) before any packet is sent.
- The local subnet is **not** auto-whitelisted anymore: an operator running
  from an unexpected network does not silently expand the scope.
- Excluded IPs (`safety.excluded_ips`) always win.

### 2.2 Volume — caps and pacing

- `propagation.max_infections`: hard cap on compromised hosts.
- `propagation.propagation_delay`: minimum seconds between iterations.
- `evasion.max_scan_rate`: packets/second ceiling.
- Rate limiter shares one lock across scanners to prevent thread-pool pileups.

### 2.3 Time — lifetime bounds

- `safety.max_runtime_hours`: the engine stops itself after N hours.
- Auto-destruct cleans up artifacts on exit when enabled.

### 2.4 Halt — kill switch and cooperative stop

Three ways to halt, all immediately effective:

1. **Kill switch code**: `wormy run --kill-switch <CODE>` (also accepted from
   the web dashboard's `POST /api/kill-switch`).
2. **Kill file**: `touch STOP_WORMY_NOW` in the working directory.
3. **Cooperative stop**: the web dashboard "Stop engine" button
   (`POST /api/stop`) or `stop` in the REPL. Both set the global `stop_event`,
   which is checked **at every exploit boundary, scan and wave iteration**.

`shutdown()` additionally stops every registered component (dashboards
included) — a kill switch leaves no listener behind.

### 2.5 Simulation — dry-run

`--dry-run` is not a toy toggle; it is enforced inside the exploit paths:

- no real exploit payloads are sent,
- no AD credential attacks (AS-REP roasting, Kerberoasting) run,
- no persistence (cron/systemd/registry) is written,
- the CLI monitor is disabled to keep output clean.

---

## 3. Network posture defaults

| Surface | Default | Override |
|---|---|---|
| Web dashboard bind | `127.0.0.1:5000` | `WORMY_DASHBOARD_HOST` (think twice) |
| Command execution via dashboard API | **disabled** (HTTP 403) | `WORMY_DASHBOARD_COMMANDS=1` |
| Lab services | published on `127.0.0.1` only | compose file |
| Expanded lab docker socket | `127.0.0.1` | — |

The control plane of an offensive tool is itself an attack surface; binding it
to localhost by default is the only sane default.

---

## 4. Threat model (what could go wrong, and the answer)

| Risk | Mitigation |
|---|---|
| Operator runs live mode by habit | authorization gate + red banner with explicit consent |
| Engine escapes the lab network | geofence on target IPs + RFC1918 defaults + `excluded_ips` |
| Runaway propagation loop | `max_infections`, `max_runtime_hours`, `stop_event` in every loop |
| Operator loses control mid-run | stop button / REPL stop / kill switch code / kill file |
| Dashboard exposed to LAN | localhost bind, read-only endpoints, command API opt-in |
| Stale credentials recovered by incident response | dry-run avoids real credential attacks; lab creds are documented and disposable |
| Misparsed config expands scope | fail-hard `Config.validate()`, invalid ranges abort startup |
| Leftover listeners after kill switch | `shutdown()` iterates `_stoppable_components` (dashboards included) |

---

## 5. Safe usage checklist

```bash
wormy doctor                        # environment OK before anything
wormy lab up                        # disposable targets
wormy run --dry-run --target 127.0.0.0/24
wormy scan --output scan.json       # recon evidence
wormy lab down                      # clean up when done
```

- [ ] Written authorization for the target scope (if live)
- [ ] `safety.allowed_networks` matches that scope exactly
- [ ] `--dry-run` tested first
- [ ] Kill switch code known to the whole team
- [ ] `wormy lab down` after the session
