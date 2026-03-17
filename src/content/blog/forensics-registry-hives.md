---
title: "Forensics - Registry Hives"
description: "Parse Windows registry hives offline to uncover secrets hidden in registry keys and values."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                           |
|-------------|-------------------------------------------------|
| Category    | Forensics                                       |
| Points      | 300                                             |
| Difficulty  | Medium                                          |
| Flag Format | `zemi{...}`                                     |
| Files Given | `NTUSER.DAT`, `SAM`, `SYSTEM`, `SOFTWARE`       |
| Tools Used  | regipy, python-registry, regripper, strings     |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/forensics-registry-hives/flag.txt)
- [generate.py](/Website/challenges/forensics-registry-hives/generate.py)
- [registry_dump.txt](/Website/challenges/forensics-registry-hives/registry_dump.txt)

## What Are Registry Hives?

The Windows Registry is a hierarchical database that stores configuration settings for the operating system, hardware, software, and user preferences. It's organized into several **hive files** stored on disk:

| Hive File    | Location on Disk                                  | Contains                                            |
|--------------|---------------------------------------------------|-----------------------------------------------------|
| SAM          | `C:\Windows\System32\config\SAM`                  | User accounts, password hashes                      |
| SYSTEM       | `C:\Windows\System32\config\SYSTEM`               | Hardware config, services, boot settings            |
| SOFTWARE     | `C:\Windows\System32\config\SOFTWARE`             | Installed software, OS settings                     |
| SECURITY     | `C:\Windows\System32\config\SECURITY`             | Security policies, cached credentials               |
| NTUSER.DAT   | `C:\Users\<username>\NTUSER.DAT`                  | Per-user settings, recent files, typed URLs         |
| UsrClass.dat | `C:\Users\<username>\AppData\Local\...\UsrClass.dat` | User-specific file associations, shellbags       |

In forensics CTFs, you analyze these hive files offline (extracted from a disk image or memory dump) to find user activity, persistence mechanisms, hidden data, and more.

## Walkthrough

### Step 1: Initial Reconnaissance

Let's look at the provided files:

```bash
$ file NTUSER.DAT SAM SYSTEM SOFTWARE
NTUSER.DAT: MS Windows registry file, NT/2000 or above
SAM:        MS Windows registry file, NT/2000 or above
SYSTEM:     MS Windows registry file, NT/2000 or above
SOFTWARE:   MS Windows registry file, NT/2000 or above

$ ls -lh
-rw-r--r-- 1 user user 9.5M NTUSER.DAT
-rw-r--r-- 1 user user  64K SAM
-rw-r--r-- 1 user user  12M SYSTEM
-rw-r--r-- 1 user user  68M SOFTWARE
```

### Step 2: Quick Strings Check

Always start simple:

```bash
$ strings NTUSER.DAT | grep -i "zemi{"
# Nothing -- flag is likely in a registry value, not plaintext

$ strings -el NTUSER.DAT | grep -i "zemi"
# -el for little-endian 16-bit (Windows Unicode strings)
# Still nothing directly visible -- it's stored in a registry value
```

The flag isn't in plaintext strings. We need to properly parse the registry structure.

### Step 3: Parse with python-registry

The `python-registry` library lets us programmatically walk through registry hives:

```python
#!/usr/bin/env python3
"""Parse NTUSER.DAT to find interesting registry keys."""

from Registry import Registry

reg = Registry.Registry("NTUSER.DAT")

def print_key_recursive(key, depth=0):
    """Recursively print all keys and values."""
    indent = "  " * depth
    print(f"{indent}{key.name()}")

    for value in key.values():
        try:
            data = value.value()
            print(f"{indent}  [{value.name()}] = {data}")
        except Exception:
            print(f"{indent}  [{value.name()}] = <binary data>")

    for subkey in key.subkeys():
        print_key_recursive(subkey, depth + 1)

# Start from root
print_key_recursive(reg.root())
```

But that's a lot of output. Let's target specific interesting locations.

### Step 4: Check Common Forensics Locations

#### Recent Documents (RecentDocs)

```python
from Registry import Registry

reg = Registry.Registry("NTUSER.DAT")

# Recent documents
try:
    key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    print("=== Recent Documents ===")
    for value in key.values():
        data = value.value()
        if isinstance(data, bytes):
            # Decode the binary data (null-terminated UTF-16 filename)
            name = data.split(b'\x00\x00')[0].decode('utf-16-le', errors='ignore')
            print(f"  {name}")
    for subkey in key.subkeys():
        print(f"\n  Extension: {subkey.name()}")
        for value in subkey.values():
            data = value.value()
            if isinstance(data, bytes):
                name = data.split(b'\x00\x00')[0].decode('utf-16-le', errors='ignore')
                print(f"    {name}")
except Registry.RegistryKeyNotFoundException:
    print("RecentDocs key not found")
```

```
=== Recent Documents ===
  secret_project.docx
  financial_report.xlsx
  flag_backup.txt
  meeting_notes.pdf

  Extension: .txt
    flag_backup.txt
    notes.txt
```

Interesting -- there's a `flag_backup.txt` in recent documents. The user opened it at some point.

#### Run Keys (Persistence)

```python
# Check Run keys for persistence mechanisms
run_paths = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]

for path in run_paths:
    try:
        key = reg.open(path)
        print(f"\n=== {path} ===")
        for value in key.values():
            print(f"  {value.name()} = {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass
```

```
=== Software\Microsoft\Windows\CurrentVersion\Run ===
  SecurityUpdate = C:\Users\ctfuser\AppData\Local\Temp\update.exe -silent
  OneDrive = "C:\Users\ctfuser\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
```

That `SecurityUpdate` entry pointing to a temp folder is suspicious -- likely a persistence mechanism.

#### Typed URLs (Internet Explorer/Edge)

```python
try:
    key = reg.open("Software\\Microsoft\\Internet Explorer\\TypedURLs")
    print("\n=== Typed URLs ===")
    for value in key.values():
        print(f"  {value.value()}")
except Registry.RegistryKeyNotFoundException:
    pass
```

#### User Assist (Program Execution History)

```python
import codecs

try:
    key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    print("\n=== UserAssist (ROT13 encoded program names) ===")
    for guid_key in key.subkeys():
        count_key = guid_key.subkey("Count")
        for value in count_key.values():
            # UserAssist entries are ROT13 encoded
            decoded_name = codecs.decode(value.name(), 'rot_13')
            print(f"  {decoded_name}")
except Exception as e:
    print(f"Error: {e}")
```

### Step 5: Search All Values for the Flag

Let's systematically search every value in NTUSER.DAT:

```python
#!/usr/bin/env python3
"""Search all registry values for the flag."""

import re
from Registry import Registry

FLAG_PATTERN = re.compile(r"zemi\{[^}]+\}")

def search_key(key, path=""):
    """Recursively search all values in a registry key."""
    current_path = f"{path}\\{key.name()}"

    for value in key.values():
        try:
            data = value.value()
            # Check string values
            if isinstance(data, str):
                match = FLAG_PATTERN.search(data)
                if match:
                    print(f"[+] FOUND in {current_path}")
                    print(f"    Value: {value.name()}")
                    print(f"    Data:  {match.group()}")
                    return True
            # Check binary values
            elif isinstance(data, bytes):
                text = data.decode('utf-8', errors='ignore')
                match = FLAG_PATTERN.search(text)
                if match:
                    print(f"[+] FOUND in {current_path}")
                    print(f"    Value: {value.name()}")
                    print(f"    Data:  {match.group()}")
                    return True
                # Also try UTF-16
                text = data.decode('utf-16-le', errors='ignore')
                match = FLAG_PATTERN.search(text)
                if match:
                    print(f"[+] FOUND in {current_path}")
                    print(f"    Value: {value.name()}")
                    print(f"    Data:  {match.group()}")
                    return True
        except Exception:
            pass

    for subkey in key.subkeys():
        if search_key(subkey, current_path):
            return True

    return False

# Search all hive files
for hive_file in ["NTUSER.DAT", "SAM", "SYSTEM", "SOFTWARE"]:
    print(f"\n[*] Searching {hive_file}...")
    try:
        reg = Registry.Registry(hive_file)
        search_key(reg.root())
    except Exception as e:
        print(f"    Error: {e}")
```

```
[*] Searching NTUSER.DAT...
[+] FOUND in CMI-CreateHive\Software\CustomApp\Settings
    Value: SecretConfig
    Data:  zemi{r3g1stry_h1v3_s3cr3ts}
```

**Flag: `zemi{r3g1stry_h1v3_s3cr3ts}`**

The flag was hidden in `HKCU\Software\CustomApp\Settings` under a value named `SecretConfig`.

### Step 6: Using RegRipper (Alternative)

RegRipper is a Perl-based tool that runs predefined plugins to extract forensic artifacts from registry hives:

```bash
# Run all plugins against NTUSER.DAT
$ regripper -r NTUSER.DAT -f ntuser > ntuser_report.txt

# Run all plugins against SYSTEM
$ regripper -r SYSTEM -f system > system_report.txt

# Run all plugins against SAM
$ regripper -r SAM -f sam > sam_report.txt

# Run all plugins against SOFTWARE
$ regripper -r SOFTWARE -f software > software_report.txt

# Search reports for the flag
$ grep -r "zemi{" *_report.txt
ntuser_report.txt:  SecretConfig = zemi{r3g1stry_h1v3_s3cr3ts}
```

### Step 7: Using regipy (Alternative)

```python
from regipy.registry import RegistryHive

reg = RegistryHive("NTUSER.DAT")

# Iterate all entries
for entry in reg.recurse_subkeys(as_json=True):
    if entry.values:
        for value in entry.values:
            val_data = str(value.get("value", ""))
            if "zemi{" in val_data:
                print(f"Key:   {entry.path}")
                print(f"Value: {value['name']}")
                print(f"Data:  {val_data}")
```

### Bonus: Extracting User Credentials from SAM + SYSTEM

In real forensics (and some CTFs), you may need to extract password hashes:

```bash
# Using secretsdump.py from Impacket
$ secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.10.0

[*] Target system bootKey: 0x8a3c2f...
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ctfuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f39ab5c1d45cd5c3a...:::

# Crack with hashcat or john
$ hashcat -m 1000 hashes.txt rockyou.txt
```

## Solve Script

```python
#!/usr/bin/env python3
"""Registry hive forensics - search all hives for the flag."""

import re
import sys

FLAG_PATTERN = re.compile(r"zemi\{[^}]+\}")

def search_with_python_registry(hive_files):
    """Search using python-registry library."""
    from Registry import Registry

    for hive_file in hive_files:
        print(f"[*] Parsing {hive_file}...")
        try:
            reg = Registry.Registry(hive_file)
            result = search_key_recursive(reg.root(), "")
            if result:
                return result
        except Exception as e:
            print(f"    Error: {e}")
    return None

def search_key_recursive(key, path):
    """Recursively search registry keys for the flag."""
    current = f"{path}\\{key.name()}"
    for value in key.values():
        try:
            data = value.value()
            for text in get_text_representations(data):
                match = FLAG_PATTERN.search(text)
                if match:
                    return {
                        "path": current,
                        "value_name": value.name(),
                        "flag": match.group()
                    }
        except Exception:
            pass
    for subkey in key.subkeys():
        result = search_key_recursive(subkey, current)
        if result:
            return result
    return None

def get_text_representations(data):
    """Get possible text representations of registry data."""
    texts = []
    if isinstance(data, str):
        texts.append(data)
    elif isinstance(data, bytes):
        texts.append(data.decode('utf-8', errors='ignore'))
        texts.append(data.decode('utf-16-le', errors='ignore'))
    elif isinstance(data, int):
        texts.append(str(data))
    return texts

def main():
    hive_files = ["NTUSER.DAT", "SAM", "SYSTEM", "SOFTWARE"]
    existing = [f for f in hive_files if __import__('os').path.exists(f)]

    if not existing:
        print("[-] No registry hive files found in current directory.")
        sys.exit(1)

    result = search_with_python_registry(existing)
    if result:
        print(f"\n[+] FLAG FOUND!")
        print(f"    Registry Path: {result['path']}")
        print(f"    Value Name:    {result['value_name']}")
        print(f"    Flag:          {result['flag']}")
    else:
        print("\n[-] Flag not found in registry hives.")

if __name__ == "__main__":
    main()
```

## Tools Used

| Tool              | Purpose                                           |
|-------------------|---------------------------------------------------|
| python-registry   | Python library for parsing registry hive files     |
| regipy            | Alternative Python registry parser                 |
| RegRipper         | Automated registry artifact extraction             |
| strings           | Quick scan for readable text in binary files       |
| secretsdump.py    | Extract password hashes from SAM + SYSTEM          |
| file              | Identify file types                                |

## Lessons Learned

1. **The registry is a forensic treasure trove.** It records user activity, program execution, persistence mechanisms, USB history, network connections, and much more. Learning to navigate it is essential for Windows forensics.

2. **Know the key hive files.** Each hive serves a specific purpose: SAM for user accounts, SYSTEM for hardware/services, SOFTWARE for installed programs, and NTUSER.DAT for per-user settings. The challenge may only give you some of them.

3. **Parse, don't just search strings.** Registry values can be stored as strings, binary data, DWORD integers, or multi-strings. A simple `strings` search may miss values stored in non-ASCII formats. Use proper parsing libraries.

4. **Check high-value forensic locations.** Always examine Run/RunOnce keys (persistence), RecentDocs (file access history), TypedURLs (browsing history), UserAssist (program execution, ROT13 encoded), and MountedDevices (USB history).

5. **Multiple tools complement each other.** RegRipper is fast for known artifact extraction. python-registry and regipy give you full programmatic access for custom searches. Use both approaches.

6. **Unicode matters.** Windows stores many registry strings in UTF-16-LE encoding. When searching binary data, try both UTF-8 and UTF-16-LE decoding to catch all possible flags.
