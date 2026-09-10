"""
RL Engine v2.1 - Canonical host feature builder.

Single source of truth for the 15-dimensional feature vector per host.
Used by BOTH:
  - rl_engine/environment.py   (training state construction)
  - rl_engine/wrapper.py       (inference state construction)

This guarantees that the feature ORDER and SEMANTICS the DQN learned
during training are identical to what it sees at inference time.

Canonical feature order (FEATURES_PER_HOST = 15):
  [0]  vuln            normalized vulnerability score       (0..1)
  [1]  difficulty      normalized compromise difficulty     (0..1)
  [2]  is_infected     host already infected flag           (0/1)
  [3]  port_count      normalized open service count        (0..1)
  [4]  is_windows      OS guess is Windows                  (0/1)
  [5]  is_linux        OS guess is Linux/Unix               (0/1)
  [6]  is_high_value   strategic asset                      (0/1)
  [7]  credentials     normalized credential count          (0..1)
  [8]  hop_distance    normalized topology distance         (0..1)
  [9]  subnet          normalized network locality          (0..1)
  [10] port_21         FTP open                             (0/1)
  [11] port_22         SSH open                             (0/1)
  [12] port_23         Telnet open                          (0/1)
  [13] port_25         SMTP open                            (0/1)
  [14] port_53         DNS open                             (0/1)
"""

from typing import List, Optional, Set

FEATURES_PER_HOST = 15

# Probe ports encoded as one-hot bits (indices 10-14).
PROBE_PORTS = (21, 22, 23, 25, 53)

# Asset types considered high value when host_type is available.
HIGH_VALUE_TYPES = {
    "domain_controller",
    "database",
    "database_server",
    "exchange_server",
    "container_host",
    "file_server",
}

ACTION_DIM_WARNING = (
    "state_size must equal action_size * FEATURES_PER_HOST "
    "(one 15-float block per selectable target)."
)


def _norm(value, default: float, scale: float = 1.0) -> float:
    try:
        return min(max(float(value) / scale, 0.0), 1.0)
    except (TypeError, ValueError):
        return min(max(default, 0.0), 1.0)


def build_host_features(
    host: dict,
    infected_ips: Optional[Set[str]] = None,
) -> List[float]:
    """Map one host dict (training OR real scan format) to 15 floats.

    Accepts both key conventions transparently:
      training env:  vulnerability, difficulty, ports, os, credentials,
                     subnet, hop_distance, is_high_value, infected
      real scanner:  vulnerability_score, open_ports, os_guess,
                     credential_count, ip, host_type, asset_value
    """
    open_ports = host.get("open_ports") or host.get("ports") or []
    if not isinstance(open_ports, (list, tuple, set)):
        open_ports = []

    vuln = _norm(
        host.get("vulnerability_score", host.get("vulnerability", 50)),
        default=0.5,
        scale=100.0,
    )

    # Real scan results have no explicit difficulty: use inverse of
    # vulnerability as a computable proxy with identical semantics
    # ("harder to compromise"). Training env provides its own 1-10 value.
    if "difficulty" in host:
        difficulty = _norm(host.get("difficulty"), default=0.5, scale=10.0)
    else:
        difficulty = 1.0 - vuln

    ip = host.get("ip")
    if infected_ips is not None and ip is not None:
        is_infected = 1.0 if ip in infected_ips else 0.0
    else:
        is_infected = 1.0 if host.get("infected", False) else 0.0

    port_count = _norm(len(open_ports), default=0.0, scale=10.0)

    os_guess = str(host.get("os_guess", host.get("os", ""))).lower()
    is_windows = 1.0 if "win" in os_guess else 0.0
    is_linux = 1.0 if ("linux" in os_guess or "unix" in os_guess) else 0.0

    host_type = str(host.get("host_type", "")).lower()
    is_high_value = (
        1.0
        if (
            host.get("is_high_value", False)
            or host_type in HIGH_VALUE_TYPES
            or host.get("asset_value", 0) >= 60
            or vuln >= 0.85
        )
        else 0.0
    )

    credentials = _norm(
        host.get("credential_count", host.get("credentials", 0)),
        default=0.0,
        scale=5.0,
    )

    hop_dist = _norm(host.get("hop_distance", 1), default=0.2, scale=5.0)

    subnet = host.get("subnet")
    if subnet is None:
        subnet = host.get("third_octet", 0)
        subnet_scale = 255.0
    else:
        subnet_scale = 3.0
    subnet_norm = _norm(subnet, default=0.0, scale=subnet_scale)

    port_bits = [1.0 if p in open_ports else 0.0 for p in PROBE_PORTS]

    return [
        vuln,
        difficulty,
        is_infected,
        port_count,
        is_windows,
        is_linux,
        is_high_value,
        credentials,
        hop_dist,
        subnet_norm,
        *port_bits,
    ]


def build_state(
    hosts: List[dict],
    max_hosts: int,
    infected_ips: Optional[Set[str]] = None,
) -> List[float]:
    """Build the flat state vector: one 15-float block per host slot.

    Slot i describes the i-th selectable target, so action index i maps
    1:1 onto hosts[i]. Slots beyond len(hosts) are zero-padded, matching
    the padding used during training.
    """
    state: List[float] = []
    for host in hosts[:max_hosts]:
        state.extend(build_host_features(host, infected_ips))

    target_size = max_hosts * FEATURES_PER_HOST
    while len(state) < target_size:
        state.append(0.0)
    return state[:target_size]
