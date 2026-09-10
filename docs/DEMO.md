# Demo walkthrough (safe — no lab required)

Two ways to see Wormy working end-to-end. Both are **simulation only**:
no real exploits are executed, nothing leaves your machine, no persistence
is installed.

| Path | What you get | Needs |
|---|---|---|
| `make demo` | Full pipeline machinery on an empty loopback: banner, engines, RL decisions, audit reports | nothing |
| `make setup` + lab dry-run | The same pipeline **with real findings** against 9 deliberately vulnerable Docker services | Docker |

---

## 1. Instant demo — `make demo`

```bash
make demo
# equivalent to:
python3 -m worm_core run --dry-run --target 127.0.0.0/30 --no-monitor
```

Real output (abridged — this is what you should see):

```text
INFO - [DRY RUN] No real exploits will be executed
INFO - ============================================================
INFO - WORMY ML NETWORK WORM v4.3.1
INFO - ============================================================
INFO - Mode: DRY RUN (simulation only)
INFO - Target Ranges: ['127.0.0.0/30']
INFO - ============================================================
INFO - Professional Scanner: enabled
INFO - SUCCESS: CredentialManager loaded: 171 credentials
INFO - SUCCESS: Loaded 45 exploit modules
INFO - Lateral Movement: enabled
INFO - Polymorphic Engine: enabled (level 2)
INFO - Initialized 5 C2 protocols
INFO - C2 client connections suppressed (dry-run)
INFO - Resilient C2 v2: enabled (DoH + DomainFronting + P2P + CommandQueue)
...
INFO - ============================================================
INFO - FINAL REPORT
INFO - ============================================================
INFO - Duration: 0:00:02
INFO - Infections: 0          (empty loopback: nothing to discover)
INFO - Knowledge graph: infection_rate 100% of the 1 known host
INFO - Audit reports generated: reports/audit_report_*.json|csv|txt
INFO - Knowledge graph exported to reports/knowledge_graph.json
INFO - Logs exported to reports/final_report.json
```

What just ran, in order:

1. **Config + safety** — dry-run mode printed before anything else.
2. **Engines** — 45 exploit modules, credential manager (171 pairs),
   brute-force, vulnerability scanner, lateral movement, polymorphic
   engine, 5 C2 protocols, host monitor, dashboards (bound to 127.0.0.1).
3. **C2 suppressed** — dry-run makes **zero** outbound C2 connections.
4. **Scan + propagate** — loopback has no listening services, so nothing
   is discovered; the worm registers the operator host as patient zero.
5. **Reporting** — audit report (JSON + CSV + TXT), knowledge-graph dump
   and final report under `reports/`.

On an empty loopback there is nothing to find — that is the point: the
machinery runs and the reports are produced. To see actual discoveries,
use the lab.

## 2. Full demo — with the vulnerable Docker lab

```bash
make setup                                   # 9 vulnerable services, 127.0.0.1 only
python3 -m worm_core run --dry-run --profile lab_docker
make cleanup                                 # when finished
```

With the lab up, the scan discovers real services (SSH, Tomcat, Redis,
Postgres…), the vulnerability scanner maps CVEs, the RL policy chooses
targets, and the reports contain per-host findings. Exploitation is still
simulated (`--dry-run`), but discovery, fingerprinting and reporting are
real — that is exactly the evidence layer a defender would want.

## 3. Dashboard demo — synthetic data, zero engine

```bash
make demo-ui
# open http://127.0.0.1:5000
```

Serves the operations UI backed by a clearly-labelled synthetic
engagement (`monitoring/demo_data.py`): KPIs, propagation timeline,
severity chart, network topology and a live-looking activity feed. The
top bar shows a **DEMO DATA** chip and the safety endpoints answer `400`
with an explanation — nothing can be stopped because nothing is running.

---

## Safety notes

- `--dry-run` gates: no real exploits, no outbound C2 connections, no
  persistence. See `docs/SAFETY.md` for the full control list.
- The demo targets `127.0.0.0/30` (loopback). Passing any other range is
  your decision — only scan networks you own or are authorized to test.
- Reports under `reports/` and logs under `logs/` are runtime artifacts
  and are git-ignored.
