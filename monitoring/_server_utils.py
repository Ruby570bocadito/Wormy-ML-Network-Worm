"""
Shared plumbing for the monitoring package's HTTP servers.

Deduplicates two patterns that used to be copy-pasted across the
dashboard modules:

- Silencing Flask/Werkzeug/http.server access logs: those one-line
  access entries (``127.0.0.1 - - [..] "GET /api/.. 200 -``) print
  directly to stdout and break the Rich Live TUI.
- The optional Flask import: dashboards degrade gracefully when Flask
  is not installed (they check ``FLASK_AVAILABLE`` and skip startup).

Importing this module applies the log silencing (same import-time
behaviour the dashboard modules had when each one carried its own
copy of this block).
"""

import logging

from utils.logger import logger

try:
    from flask import Flask, jsonify, render_template_string, request

    FLASK_AVAILABLE = True
except ImportError:  # names must exist so 'from ... import Flask' still works
    Flask = jsonify = render_template_string = request = None
    FLASK_AVAILABLE = False
    logger.warning("Flask not installed: pip install flask")

_ACCESS_LOG_LOGGERS = ("werkzeug", "flask.app", "http.server")


def silence_access_logs() -> None:
    """Silence HTTP access logs that pollute stdout / the Rich Live TUI."""
    for logger_name in _ACCESS_LOG_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.ERROR)


silence_access_logs()
