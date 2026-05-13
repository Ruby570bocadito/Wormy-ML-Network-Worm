"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Monitoring Module
"""


__all__ = ["MonitoringDashboard", "get_dashboard", "CLIMonitor", "WormActivityBridge"]


def __getattr__(name):
    if name == "MonitoringDashboard" or name == "get_dashboard":
        from monitoring.dashboard import MonitoringDashboard, get_dashboard

        return MonitoringDashboard if name == "MonitoringDashboard" else get_dashboard
    if name == "CLIMonitor":
        from monitoring.cli_monitor import CLIMonitor

        return CLIMonitor
    if name == "WormActivityBridge":
        from monitoring.cli_monitor import WormActivityBridge

        return WormActivityBridge
    raise AttributeError(f"module 'monitoring' has no attribute '{name}'")
