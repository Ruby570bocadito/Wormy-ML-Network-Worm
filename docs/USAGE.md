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
| `--max-infections N` | per-run override of the `propagation.max_infections` safety cap (raising it in live mode prints a warning) |
| `--max-runtime HOURS` | per-run override of the `safety.max_runtime_hours` cap |
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
wormy run --dry-run --target 127.0.0.0/30 --max-infections 2  # demo-friendly cap
```

### `wormy scan` — reconnaissance only

```bash
wormy scan --target 10.0.0.0/24 --output scan.json
wormy scan --target 10.0.0.0/24 --json      # machine-readable stdout
wormy scan --target 10.0.0.0/24 --csv hosts.csv   # one row per host, spreadsheet-ready
wormy scan --basic                           # basic scanner instead of pro
```

Logs go to **stderr**, so `wormy scan --json | jq .` works cleanly. The CSV
export keeps the scan order; `open_ports` and `services` are flattened with
`;` separators (`22:ssh;8080:http`) so each host stays on one row, and
`--csv -` writes to stdout for piping into other tools.

### `wormy report` — engagement reports

Every engagement writes timestamped audit reports
(`reports/audit_report_<ts>.json|csv|txt`). `wormy report` consumes that
trail: everything is read-only except `prune`, the single mutating
operation — and even that always previews the plan and asks before
deleting:

```bash
wormy report list                  # engagement inventory (date, KPIs, success rate)
wormy report show                  # render the latest report in the terminal
wormy report show 20260913_142530  # a specific engagement
wormy report show --json           # raw report JSON to stdout
wormy report html                  # standalone HTML export (latest)
wormy report html -o report.html   # HTML export to a given path
wormy report compare               # last two engagements, side by side
wormy report compare 20260913_1 20260913_2   # explicit pair
wormy report compare --json        # machine-readable deltas
wormy report compare --metrics infected,success_rate   # just 2-3 KPIs
wormy report prune                 # keep the newest 20 (preview + confirm)
wormy report prune --keep 5 --yes  # keep 5, no prompt (scripts)
wormy report prune --dry-run       # preview only, nothing is deleted
```

`show` renders the executive summary, infected/failed hosts, the most
vulnerable hosts and the recommendations (color-coded by severity). `html`
produces a single self-contained file — all dynamic values are HTML-escaped —
suitable for emailing or archiving an authorized engagement.

`compare` answers "did the engagement improve?": ten KPIs side by side with
signed deltas (`▲` green = better, `▼` red = worse, plain = neutral). The
older report is always the **baseline**. With no ids it compares the last two
engagements; with one id it compares that report against its predecessor;
with two ids it compares them in chronological order (any order accepted).
Comparing a report with itself, an unknown id, or the oldest report without
predecessor exits with code `1` and a clear message. `--json` emits
`{baseline, candidate, metrics[{metric, baseline, candidate, delta, trend}]}`.
`--metrics K1,K2` narrows the table (and the JSON) to the KPIs you care
about — names match either the machine key (`infected`, `success_rate`) or
the human label (`"Success rate"`), case-insensitive; an unknown name is a
usage error that lists the valid ones.

`prune` is the retention policy: it keeps the newest N engagements (default
20) and deletes the rest — always the **whole file set** of each pruned
engagement (`audit_report_<id>.json|csv|txt|html`). The deletion plan is
previewed (ids, file counts, sizes); without `--yes` you confirm with a y/N
prompt, and declining (or Ctrl-D) aborts without touching anything.
`--keep 0` is refused — erasing the whole audit trail is never one flag
away. `--json` requires `--yes` so scripts never hang on a prompt, and
emits `{pruned, deleted_files, kept, errors}`.

The reports directory resolution is: `--reports-dir` → `$WORMY_REPORTS_DIR`
→ `./reports` → `<repo root>/reports`. Missing or corrupt reports exit with
code `1` and a clear message.

### `wormy config` — inspect the effective configuration

Profiles change safety-relevant values (infection caps, delays, runtime
limits). `config show` answers "what exactly will the engine use for THIS
invocation?" by building the configuration the same way the engine does
(config file → profile → CLI target override) and rendering it — read-only,
no engine start:

```bash
wormy config show                            # effective config (file or defaults)
wormy config show --profile stealth          # + profile overrides, marked [profile]
wormy config show --profile audit --json     # machine-readable, with _meta block
wormy config show --target 10.0.0.0/24       # preview a target override
wormy config show --config my.yaml           # validate & inspect a custom file
```

Values changed by the profile carry a `[profile]` marker. The kill switch
code is shown deliberately — the operator needs it to stop the engine.

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
wormy shell --dry-run --max-infections 2    # demo session with a tight cap
```

`--max-infections N` / `--max-runtime HOURS` override the safety caps for the
session — same semantics as `wormy run` (validated before the engine boots,
logged, and a prominent warning is shown when raising a cap in live mode).

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
| `report [new\|list\|show\|compare\|html\|prune]` | generate a fresh report or inspect/manage the historical ones |
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
> report                  # evidence for this session
> report list             # history of past engagements
> report compare          # deltas vs. the previous engagement
> report compare --metrics infected,success_rate
> report prune 10 --dry-run   # preview a retention pass
```

---

## 4. Web dashboard

```bash
wormy run --dry-run --web
# open http://127.0.0.1:5000

# or explore the UI without any engine (synthetic, clearly-labelled data):
python -m monitoring.web_dashboard --demo --port 5000
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
heavy logging), `lab_docker` (tuned for the Docker lab). To see exactly
which values a profile changes for your invocation — before launching
anything — run `wormy config show --profile <name>`; overridden settings
are marked `[profile]`.

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
