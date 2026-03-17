---
title: "Forensics - Memory Dump"
description: "Analyze a memory dump using Volatility 3 to hunt for a hidden flag buried in process memory."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                              |
|-------------|------------------------------------|
| Category    | Forensics                          |
| Points      | 300                                |
| Difficulty  | Medium                             |
| Flag Format | `zemi{...}`                        |
| Files Given | `suspicious.raw` (memory dump)     |
| Tools Used  | Volatility 3, strings, grep        |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/forensics-memory-dump/flag.txt)
- [memory_strings.txt](/Website/challenges/forensics-memory-dump/memory_strings.txt)
- [README.md](/Website/challenges/forensics-memory-dump/README.md)
- [simulate.py](/Website/challenges/forensics-memory-dump/simulate.py)

## What Are Memory Dumps?

A memory dump (or RAM capture) is a snapshot of everything stored in a computer's volatile memory at a specific point in time. This includes running processes, open network connections, loaded DLLs, clipboard contents, typed commands, encryption keys, passwords, and much more.

In forensics CTFs, you're typically given a `.raw`, `.dmp`, or `.vmem` file and asked to find artifacts that reveal what a user or attacker was doing on the system. The go-to tool for this work is **Volatility**, a powerful open-source memory forensics framework.

## Walkthrough

### Step 1: Identify the Memory Image

First, let's confirm what we're working with and determine the OS profile. Volatility 3 auto-detects the OS in most cases, but we can run a basic info scan.

```bash
$ file suspicious.raw
suspicious.raw: data

$ ls -lh suspicious.raw
-rw-r--r-- 1 user user 2.0G Jan 15 10:30 suspicious.raw
```

With Volatility 3, let's identify the operating system:

```bash
$ python3 vol.py -f suspicious.raw windows.info
Volatility 3 Framework 2.5.0

Variable        Value
Kernel Base     0xf8047e200000
DTB             0x1ad000
Symbols         file:///path/to/symbols/ntkrnlmp.pdb/...
Is64Bit         True
IsPAE           False
primary layer   Intel32e
memory layer    FileLayer
KdVersionBlock  0xf8047ee0f3a8
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      2
SystemTime      2026-01-15 08:22:31.000000
NtBuildLab      19041.1.amd64fre.vb_release.191206-1406
NtProductType   NtProductWinNt
NtSystemRoot    C:\Windows
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
```

We're looking at a Windows 10 memory image. Good.

### Step 2: List Running Processes

The first thing to do with any memory dump is see what processes were running. Use `pslist` for a flat list or `pstree` for a hierarchical view.

```bash
$ python3 vol.py -f suspicious.raw windows.pslist

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId
4       0       System          0xfa8002c4a040   104     512     N/A
348     4       smss.exe        0xfa8003c0f740   2       29      N/A
456     444     csrss.exe       0xfa8003d2c900   9       436     0
512     444     wininit.exe     0xfa8003d88060   3       75      0
524     504     csrss.exe       0xfa8003d93b30   11      262     1
580     504     winlogon.exe    0xfa8003dc9060   5       118     1
620     512     services.exe    0xfa8003e0e9e0   6       204     0
628     512     lsass.exe       0xfa8003e12060   7       610     0
1024    620     svchost.exe     0xfa8004123060   12      354     0
1340    620     svchost.exe     0xfa800425e060   9       275     0
2104    524     explorer.exe    0xfa80044a1060   33      891     1
2856    2104    chrome.exe      0xfa8004c3b060   25      412     1
3044    2104    notepad.exe     0xfa8004d12060   1       52      1
3188    2104    cmd.exe         0xfa8004e45060   1       22      1
3200    3188    secretdump.exe  0xfa8004e78b30   2       35      1
3392    2104    powershell.exe  0xfa8004f2a060   8       312     1
```

Several things catch the eye immediately:

- **`secretdump.exe`** (PID 3200) -- spawned from `cmd.exe`. Suspicious name.
- **`powershell.exe`** (PID 3392) -- always worth investigating.
- **`cmd.exe`** (PID 3188) -- let's check what commands were run.

Let's also check the process tree for parent-child relationships:

```bash
$ python3 vol.py -f suspicious.raw windows.pstree

PID     PPID    ImageFileName
...
** 2104 524     explorer.exe
**** 2856      2104    chrome.exe
**** 3044      2104    notepad.exe
**** 3188      2104    cmd.exe
****** 3200    3188    secretdump.exe
**** 3392      2104    powershell.exe
```

`secretdump.exe` was launched from `cmd.exe` which was launched from `explorer.exe`. Someone manually ran this.

### Step 3: Examine Command Line Arguments

Let's see what command-line arguments were passed to each process:

```bash
$ python3 vol.py -f suspicious.raw windows.cmdline

PID     Process         Args
...
3044    notepad.exe     "C:\Windows\system32\notepad.exe" C:\Users\ctfuser\Desktop\notes.txt
3188    cmd.exe         "C:\Windows\system32\cmd.exe"
3200    secretdump.exe  "C:\Users\ctfuser\Downloads\secretdump.exe" --extract --key s3cr3t
3392    powershell.exe  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -f C:\Users\ctfuser\Documents\exfil.ps1
```

Key findings:

- `secretdump.exe` was run with `--extract --key s3cr3t` -- this tool is extracting something with a key.
- PowerShell was run with execution policy bypass, loading `exfil.ps1` -- very suspicious.

### Step 4: Check Environment Variables

Environment variables can contain secrets. Let's check the suspicious process:

```bash
$ python3 vol.py -f suspicious.raw windows.envars --pid 3200

PID     Process         Block   Variable        Value
3200    secretdump.exe  ...     PATH            C:\Windows\system32;...
3200    secretdump.exe  ...     TEMP            C:\Users\ctfuser\AppData\Local\Temp
3200    secretdump.exe  ...     SECRET_FLAG     zemi{v0l4t1l1ty_m3m0ry_hunt3r}
3200    secretdump.exe  ...     USERNAME        ctfuser
```

There it is. The flag was stored in an environment variable `SECRET_FLAG` for the `secretdump.exe` process.

**Flag: `zemi{v0l4t1l1ty_m3m0ry_hunt3r}`**

### Alternative Approach: Strings + Grep

If you missed the environment variable route, you could also dump the process memory and search through it:

```bash
# Dump the process memory for PID 3200
$ python3 vol.py -f suspicious.raw windows.memmap --dump --pid 3200
# This creates a file like pid.3200.dmp

# Search for the flag format in the dumped memory
$ strings pid.3200.dmp | grep "zemi{"
zemi{v0l4t1l1ty_m3m0ry_hunt3r}
```

Or search the entire memory image (slower but thorough):

```bash
$ strings suspicious.raw | grep "zemi{"
zemi{v0l4t1l1ty_m3m0ry_hunt3r}
```

### Step 5: Additional Useful Volatility Plugins

Here are other plugins that are valuable for memory forensics challenges:

```bash
# Network connections
$ python3 vol.py -f suspicious.raw windows.netscan

# File handles (what files are open)
$ python3 vol.py -f suspicious.raw windows.handles --pid 3200

# DLLs loaded by a process
$ python3 vol.py -f suspicious.raw windows.dlllist --pid 3200

# Registry keys accessed
$ python3 vol.py -f suspicious.raw windows.registry.hivelist

# Dump a specific file from memory
$ python3 vol.py -f suspicious.raw windows.dumpfiles --pid 3200

# Console output (command prompt history)
$ python3 vol.py -f suspicious.raw windows.consoles

# Check for injected code
$ python3 vol.py -f suspicious.raw windows.malfind
```

## Solve Script

While this challenge is best solved interactively, here's an automated approach:

```python
#!/usr/bin/env python3
"""Memory dump forensics - automated flag extraction."""

import subprocess
import re
import sys

DUMP_FILE = "suspicious.raw"
FLAG_PATTERN = r"zemi\{[^}]+\}"

def run_vol(plugin, extra_args=""):
    """Run a Volatility 3 plugin and return output."""
    cmd = f"python3 vol.py -f {DUMP_FILE} {plugin} {extra_args}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout

def main():
    print("[*] Listing processes...")
    pslist = run_vol("windows.pslist")
    print(pslist)

    # Find suspicious processes
    suspicious_pids = []
    for line in pslist.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            name = parts[2]
            if name not in ["System", "smss.exe", "csrss.exe", "wininit.exe",
                           "winlogon.exe", "services.exe", "lsass.exe",
                           "svchost.exe", "explorer.exe"]:
                suspicious_pids.append(parts[0])

    print(f"[*] Checking environment variables for {len(suspicious_pids)} processes...")
    for pid in suspicious_pids:
        envars = run_vol("windows.envars", f"--pid {pid}")
        flag_match = re.search(FLAG_PATTERN, envars)
        if flag_match:
            print(f"[+] FLAG FOUND in PID {pid}: {flag_match.group()}")
            return

    # Fallback: dump all process memory and search strings
    print("[*] Falling back to string search across all memory...")
    result = subprocess.run(
        ["bash", "-c", f"strings {DUMP_FILE} | grep -oE '{FLAG_PATTERN}'"],
        capture_output=True, text=True
    )
    if result.stdout.strip():
        print(f"[+] FLAG FOUND: {result.stdout.strip()}")
    else:
        print("[-] Flag not found.")

if __name__ == "__main__":
    main()
```

## Tools Used

| Tool         | Purpose                                    |
|--------------|--------------------------------------------|
| Volatility 3 | Memory forensics framework                |
| strings      | Extract printable strings from binary data |
| grep         | Pattern matching in text output            |
| file         | Identify file types                        |
| Python       | Automation and scripting                   |

## Lessons Learned

1. **Memory dumps are goldmines.** RAM contains everything the system was doing at capture time -- processes, network connections, typed commands, passwords, encryption keys, and more.

2. **Start with process enumeration.** Always begin by listing processes (`pslist`, `pstree`) and their command lines (`cmdline`). Look for unusual process names, unexpected parent-child relationships, and suspicious arguments.

3. **Environment variables hold secrets.** Programs often receive sensitive data through environment variables. The `envars` plugin is essential for checking this.

4. **Strings is your safety net.** When in doubt, run `strings` on the dump and grep for the flag format. It's brute force but effective.

5. **Volatility 3 vs Volatility 2.** Volatility 3 uses a different plugin naming scheme (e.g., `windows.pslist` instead of `--profile=Win10x64 pslist`). V3 also auto-detects OS profiles, making it easier to get started. V2 is still widely used and many writeups reference it, so know both.

6. **Know your plugins.** Volatility has dozens of plugins for different analysis tasks. The most critical ones for CTFs are `pslist`, `pstree`, `cmdline`, `envars`, `netscan`, `filescan`, `dumpfiles`, `malfind`, and `consoles`.
