"""Backwards-compatible entry helpers.

The real CLI lives in :mod:`worm_core.cli`. This module keeps
``get_local_ip`` (used by several mixins) and a delegating ``main`` so
older entry points keep working.
"""

import socket


def get_local_ip() -> str:
    """Return the primary outbound local IP (best effort)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    from .cli import main as cli_main

    return cli_main()
