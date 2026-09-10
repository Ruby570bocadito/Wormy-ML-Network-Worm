.PHONY: setup attack cleanup demo demo-ui test test-cov lint format typecheck install dev check help

# ── Installation ──────────────────────────────────────────────────────────

install:
	pip install -e ".[dev]"

dev:
	pip install -e ".[dev]"

# ── Docker Lab ────────────────────────────────────────────────────────────

setup:
	@echo "Starting vulnerable Docker lab..."
	docker compose -f docker-compose-lab.yml up -d
	@echo "Lab active. Check IPs with 'docker ps'."

attack:
	@echo "Starting Wormy C2 and propagation (interactive CLI)..."
	python3 -m worm_core --interactive

cleanup:
	@echo "Stopping Docker lab..."
	docker compose -f docker-compose-lab.yml down
	@echo "Environment cleaned."

# ── Demo (safe, no lab required) ─────────────────────────────────────────

# Full pipeline in simulation mode against loopback: scan, RL decisions,
# simulated exploitation, reports. Zero real exploits, zero lab needed.
demo:
	python3 -m worm_core run --dry-run --target 127.0.0.0/30 --no-monitor

# Web dashboard fed with synthetic demo data (no engine, no network).
demo-ui:
	python3 -m monitoring.web_dashboard --demo

# ── Testing ───────────────────────────────────────────────────────────────
# Automated suite only (no live network). Per-test timeouts come from
# pyproject.toml [tool.pytest.ini_options]. Lab harness scripts under
# tests/ that need a running lab are excluded and run manually.

test:
	python3 -m pytest tests/ -v --tb=short

test-cov:
	python3 -m pytest tests/ --cov --cov-report=term-missing -v

# Full pre-flight check: syntax, style, then tests.
check:
	python3 -m compileall -q .
	python3 -m pytest tests/ -q --tb=short

# ── Code Quality ──────────────────────────────────────────────────────────

lint:
	black --check .
	isort --check-only .
	flake8 --max-line-length=100 --exclude=.git,__pycache__,build,dist

format:
	black .
	isort .

typecheck:
	mypy worm_core/ rl_engine/ core/ utils/ configs/ --ignore-missing-imports

# ── Enterprise (simulated) ────────────────────────────────────────────────

enterprise-dry:
	sudo bash scripts/deploy_kali.sh --dry-run

# ── Help ──────────────────────────────────────────────────────────────────

help:
	@echo "Wormy v4.1 Makefile"
	@echo ""
	@echo "  make install     — Install package in dev mode"
	@echo "  make demo        — Safe end-to-end dry-run demo (no lab needed)"
	@echo "  make demo-ui     — Dashboard with synthetic demo data"
	@echo "  make setup       — Start Docker vulnerable lab"
	@echo "  make attack      — Run interactive CLI"
	@echo "  make test        — Run automated test suite"
	@echo "  make test-cov    — Run tests with coverage"
	@echo "  make check       — Syntax compile + full test suite"
	@echo "  make lint        — Check code style"
	@echo "  make format      — Auto-format code"
	@echo "  make typecheck   — mypy on core packages"
	@echo "  make cleanup     — Stop Docker lab"
