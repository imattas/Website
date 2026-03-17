#!/usr/bin/env python3
"""
Forensics Challenge: Registry Hives
Creates a simulated Windows registry dump text file with the flag
hidden in a Run key value (a common persistence mechanism).

Usage: python3 generate.py
Output: registry_dump.txt
"""

import os
import random
import string
from datetime import datetime, timedelta

FLAG = "zemi{r3g1stry_h1v3_s3cr3ts}"


def random_guid():
    hex_chars = string.hexdigits[:16]
    parts = [
        "".join(random.choices(hex_chars, k=8)),
        "".join(random.choices(hex_chars, k=4)),
        "".join(random.choices(hex_chars, k=4)),
        "".join(random.choices(hex_chars, k=4)),
        "".join(random.choices(hex_chars, k=12)),
    ]
    return "{" + "-".join(parts) + "}"


def random_timestamp():
    base = datetime(2024, 1, 1)
    delta = timedelta(days=random.randint(0, 365), seconds=random.randint(0, 86400))
    return (base + delta).strftime("%Y-%m-%d %H:%M:%S")


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry_dump.txt")
    random.seed(1337)

    lines = []
    lines.append("Windows Registry Dump")
    lines.append(f"Export Date: {datetime(2025, 3, 15).strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 72)
    lines.append("")

    # HKLM\SOFTWARE section
    lines.append("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion]")
    lines.append(f'"ProgramFilesDir"="C:\\\\Program Files"')
    lines.append(f'"CommonFilesDir"="C:\\\\Program Files\\\\Common Files"')
    lines.append(f'"ProgramFilesPath"="%ProgramFiles%"')
    lines.append(f'"DevicePath"="%SystemRoot%\\\\inf"')
    lines.append("")

    # Installed programs
    lines.append("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall]")
    programs = [
        ("Google Chrome", "120.0.6099.130", "Google LLC"),
        ("Mozilla Firefox", "121.0", "Mozilla"),
        ("7-Zip", "23.01", "Igor Pavlov"),
        ("Notepad++", "8.6.2", "Don HO"),
        ("Python 3.11.7", "3.11.7", "Python Software Foundation"),
    ]
    for name, ver, pub in programs:
        guid = random_guid()
        lines.append(f"")
        lines.append(f"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{guid}]")
        lines.append(f'"DisplayName"="{name}"')
        lines.append(f'"DisplayVersion"="{ver}"')
        lines.append(f'"Publisher"="{pub}"')
        lines.append(f'"InstallDate"="{random_timestamp()[:10].replace("-","")}"')

    lines.append("")

    # Services (noise)
    lines.append("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip]")
    lines.append('"Type"=dword:00000001')
    lines.append('"Start"=dword:00000000')
    lines.append('"DisplayName"="TCP/IP Protocol Driver"')
    lines.append('"ImagePath"="\\\\SystemRoot\\\\System32\\\\drivers\\\\tcpip.sys"')
    lines.append("")

    lines.append("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dhcp]")
    lines.append('"Type"=dword:00000020')
    lines.append('"Start"=dword:00000002')
    lines.append('"DisplayName"="DHCP Client"')
    lines.append("")

    # User profiles (noise)
    lines.append("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList]")
    lines.append('"ProfilesDirectory"="%SystemDrive%\\\\Users"')
    lines.append('"Default"="%SystemDrive%\\\\Users\\\\Default"')
    lines.append("")

    # THE FLAG IS HERE - hidden in a Run key (autostart persistence)
    lines.append("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]")
    lines.append('"SecurityHealth"="\\"C:\\\\Program Files\\\\Windows Defender\\\\MSASCuiL.exe\\""')
    lines.append('"iTunesHelper"="\\"C:\\\\Program Files\\\\iTunes\\\\iTunesHelper.exe\\""')
    lines.append(f'"SystemUpdate"="cmd.exe /c echo {FLAG} > C:\\\\Users\\\\Public\\\\debug.log"')
    lines.append('"RealTimeProtection"="C:\\\\Program Files\\\\Defender\\\\rtprot.exe"')
    lines.append("")

    # More Run keys in HKCU for noise
    lines.append("[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]")
    lines.append('"OneDrive"="\\"C:\\\\Users\\\\admin\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDrive.exe\\" /background"')
    lines.append('"Discord"="\\"C:\\\\Users\\\\admin\\\\AppData\\\\Local\\\\Discord\\\\Update.exe\\" --processStart Discord.exe"')
    lines.append('"Steam"="\\"C:\\\\Program Files (x86)\\\\Steam\\\\steam.exe\\" -silent"')
    lines.append("")

    # RunOnce (noise)
    lines.append("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce]")
    lines.append('"WExtract"="C:\\\\Users\\\\admin\\\\AppData\\\\Local\\\\Temp\\\\extract.exe"')
    lines.append("")

    # Network settings (noise)
    lines.append("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{b4c2e3f1-1234-5678-abcd-ef0123456789}]")
    lines.append('"EnableDHCP"=dword:00000001')
    lines.append(f'"DhcpIPAddress"="192.168.1.{random.randint(100,200)}"')
    lines.append('"DhcpSubnetMask"="255.255.255.0"')
    lines.append('"DhcpDefaultGateway"="192.168.1.1"')
    lines.append('"NameServer"="8.8.8.8,8.8.4.4"')
    lines.append("")

    # Recent documents (noise)
    lines.append("[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs]")
    lines.append('"MRUListEx"=hex:03,00,00,00,02,00,00,00,01,00,00,00,00,00,00,00')
    lines.append("")

    # End
    lines.append("=" * 72)
    lines.append("End of Registry Dump")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Created {output_path}")
    print(f"    Total lines: {len(lines)}")
    print()
    print("To solve:")
    print("  grep -i 'flag\\|zemi\\|suspicious' registry_dump.txt")
    print("  # Look at Run keys for persistence mechanisms")
    print("  # The flag is in an autostart entry under HKLM\\...\\Run")


if __name__ == "__main__":
    main()
