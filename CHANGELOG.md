# Changelog

## v4.2.0 (2026-09-10)

The "make it actually work and tell the truth" release. Full audit: every
claim in the README is now backed by a verified implementation, and every
test in the suite runs without touching a live network.

### Fixed (critical — the project did not run before this release)
- `worm_core/mixin_propagation.py`: IndentationError broke `import worm_core`
  and every entry point; a single py_compile smoke test now guards this
- `pyproject.toml`: nonexistent build backend (`setuptools.backends._legacy`)
  broke `pip install .` and all CI jobs → `setuptools.build_meta`
- `core/wave_propagation.py`: exploit callback returned `bool` but was
  unpacked as `(bool, dict)` — every wave infection failed silently behind a
  swallowed TypeError; contract now accepts both shapes and logs at ERROR
- `worm_core/mixin_propagation.py`: DormantCell objects subscripted as dicts
  crashed the propagation loop from iteration 5

### Fixed (ML correctness — the "DQN + Thompson Sampling" story is now real)
- Double DQN implemented properly (van Hasselt et al., 2015): action
  selection with the online network, evaluation with the target network.
  Previously vanilla DQN was shipped under the Double DQN name
- PER importance-sampling weights are now applied to the torch loss
  (previously sampled but ignored)
- Reward normalization (Welford) frozen at `remember()` time — it was
  re-normalizing the same experiences inside every replay pass
- Target network runs in `eval()` mode during target computation (dropout
  made targets stochastic)
- Bootstrapped Thompson-Sampling ensemble: each member now trains with its
  own optimizer (previously frozen copies that never learned = no exploration)
- Epsilon decay per episode in the main training pipeline (epsilon was stuck
  at 1.0 — the agent trained with a purely random policy)
- Unified feature builder `rl_engine/features.py`: training and inference
  now observe identical feature order/semantics (previously 750-dim runtime
  states fed a 300-dim network AND the feature order differed)
- Checkpoints: atomic writes (tmp + os.replace), dimension validation on
  load (fail loud instead of silently running with random weights)
- Fixed training/inference geometry mismatch: one geometry (action_size=20,
  state_size=300) everywhere

### Fixed (safety controls were cosmetic — now enforced)
- Central `stop_event` checked on every path into `exploit_target`:
  wave threads, lateral movement and manual CLI commands could previously
  bypass the kill switch
- Geofence evaluates every TARGET IP against `allowed_networks` (it
  previously only checked the operator's own interface IP — it could never
  fail); the local subnet is no longer auto-whitelisted
- `check_and_add_infected()`: atomic admission closes the max_infections
  overshoot with concurrent wave threads (TOCTOU)
- `--dry-run` / `--scan-only` no longer emit real attack traffic: AD
  roasting, decoy traffic, fuzzing and local persistence installation are
  all gated
- Removed a live reverse-shell stub that executed in-memory on the
  OPERATOR's machine during post-exploitation cleanup
- `shutdown()` stops every registered component (both dashboards gained a
  working `stop()` via `make_server`); no more `sys.exit(0)` from library
  code (SystemExit in a worker thread killed only the thread)
- `--config` with a missing file now fails hard instead of silently running
  with default target ranges

### Fixed (logic bugs)
- Service logins used `ports[0]` regardless of service (SSH attempted
  against HTTP ports); correct service→port mapping now used in credential
  pivot, brute force and lateral movement
- `select_next_target` excluded failed hosts on the knowledge-graph path —
  previously the loop could spin forever on a failed high-value host
- `rate_limiter`: `Lock` → `RLock` fixes a self-deadlock in
  `get_host_stats()` (hung the test suite)
- `agent_controller`: `is_stale` property-with-parameter bug (always truthy);
  CLI `exec` resolves agents by IP via new `find_by_ip()` instead of
  guessing `md5(ip:root)`
- `mixin_lateral`: lateral movement recorded twice; early return prevented
  DCOM/VSS phases from ever running after a successful credential reuse
- `wave_propagation`: TOCTOU on infected/failed sets; blocking SSH harvest
  moved out of the hot loop path

### Testing & CI
- `tests/conftest.py` + `tests/test_smoke.py`: py_compile smoke test over
  every repo file, feature-builder contract tests, geometry-mismatch test
- Deleted fake tests (zero-assert collections, harness executed on import)
- Manual lab scripts excluded from pytest collection via `collect_ignore_glob`
  and `__test__ = False`
- Suite status: **239 passed, 7 skipped, 0 failed** (pytest, with per-test
  timeouts); the old "35/39 PASS" badge did not correspond to any real
  metric and has been removed
- CI: fixed broken workflow YAML (`branches: ain, develop]`), added syntax
  smoke job, scoped mypy, bandit `-ll`, updated test selection

### Docker lab
- `docker-compose-lab.yml`: all host ports bound to `127.0.0.1`, healthchecks
  for the heavy services, `PASSWORD_ACCESS=true` on the SSH target (the
  documented credentials were unusable without it)
- `docker-compose-lab-expanded.yml`: fixed port 5901 collision that broke
  `compose up`; docker.sock relay bound to `127.0.0.1` (was root-equivalent
  exposure on 0.0.0.0:2375)
- Removed the superseded `docker-lab/docker-compose.yml` (port conflicts)

### Removed
- `kernel/` and `stager/`: non-compiling skeleton C/Go code (documented as
  "research" but without a build chain it only subtracted credibility)
- `PLAN.md` (working notes, not documentation)
- `requirements-lock.txt` (generated with nonexistent future versions and
  consumed by nothing)
- Root `worm_core.py` shim (launchers now use `python -m worm_core`)

## v4.1.0 (2026-02-14)

### Fixed
- Critical: missing `Optional` import in mixin_exploitation.py (package was unimportable)
- Missing `Optional`/`Dict` imports in evasion/direct_syscalls.py
- test_config_structure path resolution (config.py -> configs/config.py)
- All 194 Python files validated for syntax and typing imports


### Added
- C2: SMTP/Email channel for stealthy command & control
- C2: SSH Tunnel channel with multi-jump host support
- Exploit: RabbitMQ module (auth bypass + management RCE)
- Core: Adaptive rate limiter for intelligent scan throttling
- Core: Exploit chaining engine (multi-vuln dependency chains)
- Core: State persistence (snapshot/restore worm state across restarts)
- Monitoring: Credential dashboard for real-time cred visibility
- Docker Lab: Log4j and Struts2 vulnerable containers
- Kernel module stub for future LKM capabilities
- Wordlists: 13 per-service credential dictionaries
- Tests: 6 new test modules (C2, expanded lab, new modules, persistence, worm vs lab)

### Improved
- CI: bandit + semgrep security scanning integrated
- CI: pytest-cov with 30% coverage threshold
- Reproducible builds: requirements-lock.txt added
- Run lab script (run_lab.sh) with safety checks
- Config lab profile (config_lab.yaml) for isolated testing

### Changed
- 117 files changed, 10,547 insertions, 1,672 deletions

## v4.0.0 (2026-05-13)

### Added
- 44 exploit modules (12 new: EternalBlue, Zerologon, PrintNightmare, BlueKeep, WordPress, Apache, CloudFormation, Terraform, GCP IAM, Siemens S7, MQTT, OPC UA)
- worm_core/ package: refactored from 3079-line monolithic into 10 mixin modules
- CI pipeline with lint, security scan, and test jobs
- Pre-commit hooks configuration
- CHANGELOG, CONTRIBUTING, SECURITY.md

### Security
- Fixed shell=True -> shlex.split() in payload_deployer.py
- Fixed exec() -> subprocess.call(shlex.split()) in worm_core.py
- Fixed SQLi f-string -> escaped quotes in enterprise_password_engine.py
- Redacted 13 password leak lines across all exploits
- Replaced 2 bare except: with except Exception: in payload_deployer.py
- Moved 4 hardcoded credentials to env vars (JWT secret, MSF password, SSL verify)
- Added pickle.load() validation guards in scanner and evasion models

### Changed
- All 160 files reformatted with black + isort
- C2 fallback errors demoted from error to warning (normal in standalone mode)
- MultiProtocolC2.stop() added for clean shutdown
- README rewritten with Mermaid diagrams, exploit tables, and detailed architecture
- Requirements.txt synced with pyproject.toml

### Removed
- Junk files: worm_core.py.bak, _test_train.py, _train_output.txt, __pycache__/, .pytest_cache/, logs/, reports/
- Duplicate ML models in worm_core/ml_models/saved/

## v3.0.0 (Previous)

- Initial enterprise release with 32 exploit modules
- RL engine with DQN + Thompson Sampling
- Multi-protocol C2 (HTTPS, DoH, ICMP, cloud relay)
- Enterprise evasion engine (AMSI, ETW, DLL unhooking)
- Active Directory attack chain (LDAP, AS-REP, Kerberoast)
- Web dashboards (Armitage + Web)
