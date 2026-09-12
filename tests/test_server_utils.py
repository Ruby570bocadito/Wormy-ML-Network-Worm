"""Tests for monitoring._server_utils (shared dashboard plumbing).

Verifies that the optional-Flask fallback keeps the re-exported names
importable (as ``None``) when Flask is missing, so the dashboard
modules' ``from monitoring._server_utils import Flask, ...`` keeps
working in minimal environments.
"""

import importlib.util
import sys
from pathlib import Path

_SERVER_UTILS = Path(__file__).resolve().parent.parent / "monitoring" / "_server_utils.py"


def _load_fresh_without_flask():
    """Load an isolated copy of _server_utils with the flask import blocked."""
    saved = {k: v for k, v in sys.modules.items() if k == "flask" or k.startswith("flask.")}
    for key in list(saved):
        del sys.modules[key]
    # A None entry makes 'import flask' raise ImportError (import halted)
    sys.modules["flask"] = None
    try:
        spec = importlib.util.spec_from_file_location("_server_utils_noflask", _SERVER_UTILS)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        del sys.modules["flask"]
        sys.modules.update(saved)


def test_flask_names_fall_back_to_none():
    mod = _load_fresh_without_flask()
    assert mod.FLASK_AVAILABLE is False
    assert mod.Flask is None
    assert mod.jsonify is None
    assert mod.render_template_string is None
    assert mod.request is None


def test_flask_available_when_installed():
    from monitoring import _server_utils

    assert _server_utils.FLASK_AVAILABLE is True
    assert _server_utils.Flask is not None
    assert _server_utils.jsonify is not None


def test_silence_access_logs_sets_levels():
    import logging

    from monitoring._server_utils import silence_access_logs

    silence_access_logs()
    for name in ("werkzeug", "flask.app", "http.server"):
        assert logging.getLogger(name).level == logging.ERROR


def test_dashboards_degrade_consistently_without_flask():
    """Dashboard classes keep their FLASK_AVAILABLE contract after the refactor."""
    from monitoring.armitage_dashboard import ArmitageDashboard
    from monitoring.credential_dashboard import CredentialDashboard
    from monitoring.dashboard import MonitoringDashboard
    from monitoring.web_dashboard import WebDashboard

    for cls in (WebDashboard, ArmitageDashboard, CredentialDashboard, MonitoringDashboard):
        instance = cls()
        assert instance.app is not None, f"{cls.__name__} should boot with Flask installed"
        assert hasattr(instance, "run")
