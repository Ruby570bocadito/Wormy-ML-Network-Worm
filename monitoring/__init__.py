"""
Monitoring package — live interfaces for Wormy operations.

Exports are lazy so that CLI startup stays fast: the heavy UI modules
(Flask dashboards, Rich live monitor) are only imported when an
attribute is actually requested.
"""

__all__ = ["MonitoringDashboard", "get_dashboard", "CLIMonitor", "WormActivityBridge"]

# name -> (module, attribute)
_LAZY_IMPORTS = {
    "MonitoringDashboard": ("monitoring.dashboard", "MonitoringDashboard"),
    "get_dashboard": ("monitoring.dashboard", "get_dashboard"),
    "CLIMonitor": ("monitoring.cli_monitor", "CLIMonitor"),
    "WormActivityBridge": ("monitoring.cli_monitor", "WormActivityBridge"),
}


def __getattr__(name):
    try:
        module_name, attr = _LAZY_IMPORTS[name]
    except KeyError:
        raise AttributeError(f"module 'monitoring' has no attribute '{name}'") from None
    import importlib

    return getattr(importlib.import_module(module_name), attr)
