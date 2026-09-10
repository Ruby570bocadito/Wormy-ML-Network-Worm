"""Shared pytest fixtures for the Wormy test suite.

Every test module previously copied the same sys.path.insert boilerplate;
conftest.py is the single place that guarantees the repo root is importable.
"""

import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Manual lab/verification scripts: pytest must NOT import them during
# collection (several execute live harnesses at import time). They are run
# explicitly with `python tests/<name>.py` against a running lab.
collect_ignore_glob = [
    "validate_*.py",
    "test_worm_vs_lab.py",
    "test_expanded_lab.py",
    "comprehensive_test_suite.py",
    "test_docker_lab.py",
    "test_installation.py",
    "test_v2_modules.py",       # runs its harness (sys.exit) at import
    "test_enterprise_modules.py",
    "run_worm_vs_lab.py",
]


@pytest.fixture
def repo_root() -> str:
    return REPO_ROOT


@pytest.fixture
def sample_host() -> dict:
    """A host dict in the shape produced by the real scanners."""
    return {
        "ip": "192.168.100.20",
        "hostname": "lab-db",
        "os_guess": "Linux",
        "open_ports": [22, 3306],
        "vulnerability_score": 82,
        "credential_count": 0,
        "hop_distance": 1,
        "host_type": "database_server",
    }


@pytest.fixture
def sample_env_host() -> dict:
    """A host dict in the shape used by the RL training environment."""
    return {
        "id": 3,
        "ip": "192.168.1.13",
        "subnet": 1,
        "vulnerability": 76,
        "difficulty": 4,
        "reachable": True,
        "ports": [22, 80],
        "os": "Linux",
        "is_high_value": False,
        "credentials": 2,
        "hop_distance": 2,
        "infected": False,
    }
