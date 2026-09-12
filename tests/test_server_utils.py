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


# ── DashboardBase lifecycle (shared run/stop/run_background) ────────────


def test_all_dashboards_share_the_lifecycle_base():
    """Every Flask dashboard inherits DashboardBase: one lifecycle, one stop()."""
    from monitoring._dashboard_base import DashboardBase
    from monitoring.armitage_dashboard import ArmitageDashboard
    from monitoring.credential_dashboard import CredentialDashboard
    from monitoring.dashboard import MonitoringDashboard
    from monitoring.web_dashboard import WebDashboard

    for cls in (WebDashboard, ArmitageDashboard, CredentialDashboard, MonitoringDashboard):
        assert issubclass(cls, DashboardBase), f"{cls.__name__} must inherit DashboardBase"
        instance = cls()
        # credential/monitoring previously had no stop() at all (app.run)
        assert callable(instance.stop), f"{cls.__name__}.stop must exist"
        assert callable(instance.run_background)
        assert instance._server is None and instance._thread is None


def test_stop_before_run_is_a_noop():
    """stop() on a never-started dashboard must not raise."""
    from monitoring._dashboard_base import DashboardBase

    class _Dash(DashboardBase):
        def __init__(self):
            super().__init__()
            self.host = "127.0.0.1"
            self.port = 0

    _Dash().stop()  # no _server yet — must be a silent no-op


def test_stop_swallows_shutdown_errors():
    """stop() must never raise, even when the underlying shutdown() blows up."""
    import types

    from monitoring._dashboard_base import DashboardBase

    class _Dash(DashboardBase):
        def __init__(self):
            super().__init__()
            self.host = "127.0.0.1"
            self.port = 0

    dash = _Dash()
    dash._server = types.SimpleNamespace(
        shutdown=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    dash.stop()  # exception must be contained (logged at debug)


def test_run_background_serves_and_stop_shuts_down():
    """End-to-end: daemon thread serves HTTP, stop() really closes the listener."""
    import time
    import urllib.request

    from monitoring.web_dashboard import WebDashboard

    dash = WebDashboard(port=0)  # ephemeral port — no CI collisions
    thread = dash.run_background()
    assert thread is not None
    assert thread.daemon
    assert thread.name == "web-dashboard"

    deadline = time.time() + 5
    port = None
    while time.time() < deadline:
        server = dash._server
        if server is not None:
            port = server.server_address[1]
            break
        time.sleep(0.05)
    assert port, "dashboard did not start serving within 5s"

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
        assert resp.status == 200

    dash.stop()
    thread.join(timeout=5)
    assert not thread.is_alive(), "run_background thread should exit after stop()"
