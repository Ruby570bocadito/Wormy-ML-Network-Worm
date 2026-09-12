CONFIG_PROFILES = {
    "stealth": {
        "propagation_delay": 10.0,
        "max_infections": 10,
        "stealth_mode": True,
        "randomize_timing": True,
        "max_scan_rate": 10,
        "detect_ids": True,
        "detect_honeypots": True,
        "max_runtime_hours": 8,
        "use_pretrained": True,
    },
    "aggressive": {
        "propagation_delay": 0.5,
        "max_infections": 100,
        "stealth_mode": False,
        "randomize_timing": False,
        "max_scan_rate": 500,
        "detect_ids": False,
        "detect_honeypots": False,
        "max_runtime_hours": 2,
        "use_pretrained": False,
    },
    "audit": {
        "propagation_delay": 3.0,
        "max_infections": 50,
        "stealth_mode": True,
        "randomize_timing": True,
        "max_scan_rate": 50,
        "detect_ids": True,
        "detect_honeypots": True,
        "max_runtime_hours": 4,
        "use_pretrained": True,
        "enable_logging": True,
        "log_encryption": True,
    },
    # Profile used by run_lab.sh / `wormy lab` workflows. Tuned for the
    # disposable Docker lab: fast but rate-limited, capped infections,
    # no evasion overhead (targets are intentionally vulnerable).
    "lab_docker": {
        "propagation_delay": 1.0,
        "max_infections": 15,
        "stealth_mode": False,
        "randomize_timing": False,
        "max_scan_rate": 100,
        "detect_ids": False,
        "detect_honeypots": False,
        "max_runtime_hours": 1,
        "use_pretrained": False,
    },
}


def apply_profile(config, profile_name: str) -> list[str]:
    """Apply a named profile's overrides onto a ``Config`` instance.

    This is the single application path shared by the engine
    (``WormCoreBase._apply_profile``) and transparency surfaces such as
    ``wormy config show``, so both always agree on what a profile means.

    Key resolution order mirrors the engine's: ``propagation`` →
    ``evasion`` → ``safety`` → ``ml`` (first section that has the field
    wins). Unknown or empty profiles are a no-op.

    Returns the list of overridden settings as ``section.key`` strings
    (empty when nothing was applied).
    """
    overrides = CONFIG_PROFILES.get(profile_name) or {}
    applied: list[str] = []
    for key, value in overrides.items():
        for section in ("propagation", "evasion", "safety", "ml"):
            target = getattr(config, section, None)
            if target is not None and hasattr(target, key):
                setattr(target, key, value)
                applied.append(f"{section}.{key}")
                break
    return applied
