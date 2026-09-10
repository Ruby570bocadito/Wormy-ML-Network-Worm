# Web Dashboard REST API

The Flask web dashboard (`monitoring/web_dashboard.py`) serves both the UI and
this JSON API.

- **Base URL**: `http://127.0.0.1:5000` (localhost by default; override with
  `WORMY_DASHBOARD_HOST` if you really know what you are doing)
- All read endpoints are **read-only**.
- Safety endpoints (`/api/stop`, `/api/kill-switch`) are always available.
- Command execution (`/api/command`) is **disabled** unless the dashboard was
  started with `WORMY_DASHBOARD_COMMANDS=1`.

---

## Monitoring

### `GET /api/status`

Engine status snapshot.

```json
{
  "version": "4.3.0",
  "running": true,
  "dry_run": true,
  "infected_hosts": 5,
  "failed_targets": 2,
  "total_discovered": 10,
  "vulnerabilities": 15,
  "exploit_chains": 8,
  "lateral_movements": "3/5",
  "brute_force": "2/10",
  "credentials": 12,
  "c2_beacons": 25,
  "polymorphic_mutations": 50,
  "start_time": "2026-09-10T14:22:31",
  "targets": ["127.0.0.0/24"]
}
```

### `GET /api/hosts`

Per-host state from the host monitor. Empty list when the monitor is disabled.

```json
[
  {
    "ip": "10.0.0.5",
    "os": "Linux",
    "status": "infected",
    "health": 92.0,
    "detection_risk": 14.0,
    "cpu": 31.0,
    "memory": 48.0,
    "payload_variant": "beacon-v3",
    "infected_at": "2026-09-10T14:24:02",
    "last_beacon": "2026-09-10T14:30:11",
    "activities": 22,
    "credentials_found": 3,
    "lateral_movements": 1
  }
]
```

### `GET /api/vulnerabilities`

Flattened vulnerability findings across all scanned hosts.

```json
[
  {
    "host": "10.0.0.5",
    "cve": "CVE-2021-44228",
    "name": "Apache Log4j RCE",
    "severity": "CRITICAL",
    "cvss": 10.0,
    "description": "Log4Shell JNDI lookup RCE"
  }
]
```

### `GET /api/credentials`

Discovered credentials.

```json
[{"username": "root", "password": "labpass123", "source": "discovered"}]
```

### `GET /api/topology`

Nodes (scanned hosts) and edges (lateral movements).

```json
{
  "nodes": [
    {"id": "10.0.0.5", "label": "10.0.0.5", "status": "infected",
     "os": "Linux", "ports": [22, 8080]}
  ],
  "edges": [
    {"from": "10.0.0.5", "to": "10.0.0.6", "label": "ssh_reuse", "success": true}
  ]
}
```

### `GET /api/activity?limit=50`

Activity feed, newest first. `limit` is clamped to `[1, 500]`.

### `GET /api/stats`

Raw statistics dict (superset of `/api/status` counters), including host
monitor and evasion subsystem statistics when available.

---

## Safety (always available)

### `POST /api/stop`

Cooperative stop — the same `stop_event` the CLI uses. The engine finishes the
current boundary and halts.

```json
{"ok": true, "status": "stop_requested"}
```

`503` when no engine is attached, `500` on failure.

### `POST /api/kill-switch`

Full kill switch. Requires the configured code.

```json
{"code": "EMERGENCY_STOP_2024"}
```

`400` when the code is missing, `400` on wrong code (error in payload).

---

## Command execution (opt-in)

### `POST /api/command`

Executes a command on a compromised host **through its registered agent**.
Disabled unless `WORMY_DASHBOARD_COMMANDS=1` — otherwise:

```json
{"ok": false, "error": "command execution is disabled; start the dashboard with WORMY_DASHBOARD_COMMANDS=1 to enable it"}
```

(HTTP 403)

When enabled:

```json
{"host_ip": "10.0.0.5", "command": "id"}
```

```json
{"ok": true, "host": "10.0.0.5", "agent": "10.0.0.5:root", "rc": 0, "output": "uid=0(root)"}
```

`404` when no agent is registered for the IP, `503` when the agent controller
is unavailable.

---

## Error handling

Errors return a JSON body with an `error` key and an appropriate HTTP status
(`400` bad request, `403` disabled/forbidden, `404` unknown, `500` internal,
`503` unavailable). The UI surfaces these via toast notifications instead of
breaking the dashboard.
