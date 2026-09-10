"""Smoke tests: catch import-time breakages across the whole repo.

This suite exists because a single IndentationError in worm_core/
mixin_propagation.py silently broke every entry point while the old test
suite "passed" (the broken module was skipped via try/except ImportError).

- test_all_python_files_compile: py_compile over every .py file (no third
  party deps needed, catches every syntax error in the repo).
- test_core_packages_import: real imports of dependency-light packages.
- Heavy optional dependencies (torch, paramiko, impacket, flask...) are
  handled explicitly so skips are visible and justified.
"""

import compileall
import importlib
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Packages that must always import cleanly (no heavy third-party deps).
LIGHT_PACKAGES = [
    "configs.config",
    "rl_engine.features",
    "rl_engine.environment",
    "rl_engine.replay_memory",
    "core.state_persistence",
]

# Packages behind optional heavy dependencies: skipped (with visible reason)
# when the dependency is absent instead of faking a pass.
OPTIONAL_PACKAGES = {
    "rl_engine.dqn_agent": ["torch"],
    "rl_engine.wrapper": ["torch"],
    "rl_engine.propagation_agent": ["torch"],
}


def test_all_python_files_compile():
    """Every .py file in the repo must be syntactically valid."""
    ok = compileall.compile_dir(
        REPO_ROOT,
        quiet=2,
        force=True,
        rx=None,
        maxlevels=20,
    )
    assert ok, "compileall found syntax errors -- run: python -m compileall ."


@pytest.mark.parametrize("package", LIGHT_PACKAGES)
def test_core_packages_import(package):
    importlib.import_module(package)


@pytest.mark.parametrize("package,deps", sorted(OPTIONAL_PACKAGES.items()))
def test_optional_packages_import(package, deps):
    missing = []
    for dep in deps:
        try:
            importlib.import_module(dep)
        except ImportError:
            missing.append(dep)
    if missing:
        pytest.skip(f"optional dependency not installed: {', '.join(missing)}")
    importlib.import_module(package)


def test_canonical_feature_builder_shape(sample_host, sample_env_host):
    """The shared feature builder returns exactly 15 floats for both
    scanner-format and training-format host dicts."""
    from rl_engine.features import FEATURES_PER_HOST, build_host_features

    assert len(build_host_features(sample_host)) == FEATURES_PER_HOST
    assert len(build_host_features(sample_env_host)) == FEATURES_PER_HOST


def test_state_builder_alignment(sample_host, sample_env_host):
    """State slot i must describe host i (1:1 action mapping)."""
    from rl_engine.features import FEATURES_PER_HOST, build_state

    hosts = [sample_host, sample_env_host]
    state = build_state(hosts, max_hosts=5)
    assert len(state) == 5 * FEATURES_PER_HOST
    # Slot 0 == host 0 features, slot 1 == host 1 features
    from rl_engine.features import build_host_features

    assert state[:FEATURES_PER_HOST] == build_host_features(sample_host)
    assert state[FEATURES_PER_HOST : 2 * FEATURES_PER_HOST] == build_host_features(sample_env_host)
    # Slots 2-4 are zero-padded
    assert all(v == 0.0 for v in state[2 * FEATURES_PER_HOST :])


def test_wrapper_rejects_geometry_mismatch():
    """wrapper must fail fast when agent geometry != action_size * 15."""
    from rl_engine.wrapper import RealWorldPropagationAgent

    class FakeAgent:
        state_size = 300  # would need action_size == 20

    with pytest.raises(ValueError):
        RealWorldPropagationAgent(FakeAgent(), action_size=50)
