"""
Shared lifecycle base for the Flask dashboards.

The four dashboards (``web``, ``armitage``, ``credential`` and the legacy
``dashboard``) each grew their own copy of the same lifecycle: optional-Flask
guard, serving loop, background thread, shutdown. Two of them served via
``app.run()`` and had no ``stop()`` at all — the listener could not be shut
down programmatically (kill switch, test teardown, operator Ctrl+C in a
combined process). This base class turns that lifecycle into a single
implementation:

- ``run()`` serves through ``werkzeug.serving.make_server`` so ``stop()``
  always has a handle. The ``debug`` flag is accepted for API compatibility
  and deliberately ignored: the Werkzeug interactive debugger is an RCE
  vector when exposed and must never be reachable (hardening rule from the
  security rounds — ``app.run``'s debug/reloader machinery is not used).
- ``run_background()`` starts a named daemon thread and returns it.
- ``stop()`` is idempotent and never raises, so it is safe to call from
  signal handlers, kill-switch paths and test teardowns.

Subclass contract: set ``host`` and ``port`` in ``__init__`` (each dashboard
keeps its own default/env-var resolution), create the ``app`` there (the
base initializes ``app``/``_server``/``_thread`` to ``None``), and define
``log_label`` for the lifecycle log lines.
"""

from __future__ import annotations

import threading

from utils.logger import logger

from ._server_utils import FLASK_AVAILABLE


class DashboardBase:
    """Lifecycle base for the monitoring dashboards.

    Provides ``run`` / ``stop`` / ``run_background`` with a single serving
    and shutdown path shared by every Flask dashboard in the package.
    """

    #: Short name used in lifecycle log lines ("Web Dashboard", ...).
    log_label = "Dashboard"
    #: Thread name for run_background() (visible in dumps and debuggers).
    thread_name = "dashboard"

    def __init__(self):
        self.app = None
        self._server = None
        self._thread = None

    def run(self, debug: bool = False):
        """Serve until ``stop()``; returns early when Flask is missing.

        ``debug`` is accepted for signature compatibility with the old
        ``app.run(debug=...)`` dashboards and intentionally ignored —
        make_server never enables the Werkzeug debugger.
        """
        if not FLASK_AVAILABLE:
            return
        from werkzeug.serving import make_server

        logger.info(f"Starting {self.log_label} on {self.host}:{self.port}")
        # make_server instead of app.run so stop() can shut the listener down
        # (app.run blocks forever with no handle).
        self._server = make_server(self.host, self.port, self.app, threaded=True)
        self._server.serve_forever()

    def stop(self):
        """Shut the serving loop down; idempotent and never raises."""
        server = self._server
        if server is not None:
            try:
                server.shutdown()
                logger.info(f"{self.log_label} stopped")
            except Exception as e:  # noqa: BLE001 — shutdown must never raise
                logger.debug(f"{self.log_label} stop error: {e}")

    def run_background(self):
        """Serve in a daemon thread; returns the thread (or ``None``)."""
        if not FLASK_AVAILABLE:
            return None
        self._thread = threading.Thread(target=self.run, daemon=True, name=self.thread_name)
        self._thread.start()
        logger.info(f"{self.log_label} running in background on {self.host}:{self.port}")
        return self._thread
