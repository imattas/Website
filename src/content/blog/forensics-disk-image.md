---
title: "Forensics - Disk Image"
description: "Recover a deleted flag from an ext4 disk image using Sleuth Kit and file carving tools."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                      |
|-------------|--------------------------------------------|
| Category    | Forensics                                  |
| Points      | 250                                        |
| Difficulty  | Medium                                     |
| Flag Format | `zemi{...}`                                |
| Files Given | `evidence.dd` (raw disk image, 512MB)      |
| Tools Used  | Sleuth Kit, Autopsy, foremost, mount       |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/forensics-disk-image/flag.txt)
- [generate.sh](/Website/challenges/forensics-disk-image/generate.sh)
- [hint.txt](/Website/challenges/forensics-disk-image/hint.txt)

## What Are Disk Images?

A disk image is a bit-for-bit copy of a storage device -- a hard drive, USB stick, SD card, or partition. In forensics, raw images (`.dd`, `.raw`, `.img`) preserve every sector including deleted files, unallocated space, and slack space. Even when a file is "deleted," the data usually remains on disk until it's overwritten. Our job is to find and recover it.

## Walkthrough

### Step 1: Identify the Image

Start by understanding what kind of image we have:

```bash
$ file evidence.dd
evidence.dd: Linux rev 1.0 ext4 filesystem data, UUID=a1b2c3d4-..., volume name "evidence"

$ fdisk -l evidence.dd
Disk evidence.dd: 512 MiB, 536870912 bytes, 1048576 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes

Device       Boot  Start     End Sectors  Size Id  Type
evidence.dd1        2048 1048575 1046528  511M 83  Linux
```

It's an ext4 filesystem. There's one partition starting at sector 2048.

### Step 2: Mount the Image (Read-Only)

Always mount forensic images read-only to preserve evidence:

```bash
# Calculate the offset: sector 2048 * 512 bytes/sector = 1048576
$ sudo mkdir -p /mnt/evidence

$ sudo mount -o ro,loop,offset=1048576 evidence.dd /mnt/evidence

$ ls -la /mnt/evidence/
total 28
drwxr-xr-x  5 root root  4096 Jan 10 09:15 .
drwxr-xr-x  3 root root  4096 Jan 10 09:00 ..
drwxr-xr-x  2 root root  4096 Jan 10 09:12 documents
drwxr-xr-x  2 root root  4096 Jan 10 09:14 images
-rw-r--r--  1 root root   142 Jan 10 09:10 readme.txt
drwx------  2 root root 16384 Jan 10 09:00 lost+found

$ cat /mnt/evidence/readme.txt
Welcome to the forensics challenge!
The flag was here, but it's been deleted.
Can you recover it?
Good luck!

$ ls -la /mnt/evidence/documents/
total 12
drwxr-xr-x 2 root root 4096 Jan 10 09:12 .
drwxr-xr-x 5 root root 4096 Jan 10 09:15 ..
-rw-r--r-- 1 root root   45 Jan 10 09:12 notes.txt
```

No `flag.txt` visible. It's been deleted. Time to recover it.

### Step 3: Use Sleuth Kit to Find Deleted Files

Unmount first, then use `fls` to list files including deleted ones. Deleted files show up with an asterisk (`*`):

```bash
$ sudo umount /mnt/evidence

# List files in the root directory (inode 2)
# -o offset in sectors, -r recursive, -p show full path, -d deleted only
$ fls -o 2048 -r -p evidence.dd
r/r 11:    readme.txt
d/d 12:    documents
r/r 13:    documents/notes.txt
d/d 14:    images
r/r 15:    images/photo1.jpg
r/r * 16:  flag.txt
r/r * 17:  documents/secret_backup.txt
d/d 2049:  lost+found
```

There it is: **`flag.txt`** at inode 16, marked with `*` indicating it was deleted. There's also a deleted `secret_backup.txt` at inode 17.

### Step 4: Recover the Deleted File with icat

`icat` extracts file contents by inode number:

```bash
# Recover flag.txt (inode 16)
$ icat -o 2048 evidence.dd 16
zemi{d3l3t3d_but_n0t_g0n3}

# Also recover the backup file
$ icat -o 2048 evidence.dd 17
This is a backup of the flag in case I forget:
Flag: zemi{d3l3t3d_but_n0t_g0n3}
Don't tell anyone!
```

**Flag: `zemi{d3l3t3d_but_n0t_g0n3}`**

### Step 5: Examine File Metadata

We can get detailed metadata about the deleted file using `istat`:

```bash
$ istat -o 2048 evidence.dd 16

inode: 16
Allocated: No (deleted)
File type: Regular
Mode: 0644
Owner UID: 0
Group GID: 0
Size: 28
Num links: 0

Inode Times:
Created:    2026-01-10 09:11:00 (UTC)
Accessed:   2026-01-10 09:11:30 (UTC)
Modified:   2026-01-10 09:11:00 (UTC)
Deleted:    2026-01-10 09:13:45 (UTC)

Direct Blocks:
8193
```

This tells us exactly when the file was created (09:11) and deleted (09:13:45).

### Alternative: File Carving with foremost

If the filesystem metadata is corrupted and `fls`/`icat` don't work, we can carve files directly from the raw image:

```bash
$ foremost -t all -i evidence.dd -o carved_output/

Processing: evidence.dd
|*****|
1 txt files found.
2 jpg files found.

$ ls carved_output/
audit.txt  jpg/  txt/

$ cat carved_output/txt/00008193.txt
zemi{d3l3t3d_but_n0t_g0n3}

$ cat carved_output/audit.txt
Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
Audit File

Foremost started at Mon Jan 15 10:00:00 2026
Invocation: foremost -t all -i evidence.dd -o carved_output/

Output directory: carved_output/
...
```

`foremost` carves files based on their headers and footers, so it works even when filesystem structures are damaged.

### Alternative: photorec

Another powerful carving tool:

```bash
$ photorec /d recovered/ /cmd evidence.dd search
```

### Step 6: Slack Space Analysis

Sometimes flags are hidden in slack space -- the unused portion of a disk cluster after a file's data ends:

```bash
# Extract slack space using Sleuth Kit's blkls
$ blkls -o 2048 -s evidence.dd > slack_space.raw

# Search slack space for flags
$ strings slack_space.raw | grep "zemi{"
```

### Step 7: Timeline Analysis

For more complex challenges, building a filesystem timeline can reveal what happened:

```bash
# Create a body file
$ fls -o 2048 -r -m "/" evidence.dd > body.txt

# Convert to a sorted timeline
$ mactime -b body.txt > timeline.csv

# Examine the timeline around the time of interest
$ head -20 timeline.csv
Date,Size,Type,Mode,UID,GID,Meta,File Name
Mon Jan 10 2026 09:10:00,142,..b.,r/rrwxr-xr-x,0,0,11,/readme.txt
Mon Jan 10 2026 09:11:00,28,..b.,r/rrwxr-xr-x,0,0,16,/flag.txt (deleted)
Mon Jan 10 2026 09:12:00,45,..b.,r/rrwxr-xr-x,0,0,13,/documents/notes.txt
Mon Jan 10 2026 09:13:45,28,....,r/rrwxr-xr-x,0,0,16,/flag.txt (deleted)
```

## Solve Script

```python
#!/usr/bin/env python3
"""Disk image forensics - recover deleted flag.txt."""

import subprocess
import re
import sys

IMAGE = "evidence.dd"
OFFSET_SECTORS = 2048
FLAG_PATTERN = r"zemi\{[^}]+\}"

def run(cmd):
    """Run a command and return its output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def main():
    # Step 1: Find deleted files
    print("[*] Scanning for deleted files...")
    fls_output = run(f"fls -o {OFFSET_SECTORS} -r -p -d {IMAGE}")
    print(fls_output)

    # Step 2: Extract each deleted file and check for flag
    for line in fls_output.strip().split("\n"):
        if not line.strip():
            continue
        # Parse inode from fls output (format: "r/r * INODE: filename")
        match = re.search(r'\*?\s*(\d+):', line)
        if match:
            inode = match.group(1)
            content = run(f"icat -o {OFFSET_SECTORS} {IMAGE} {inode}")
            flag = re.search(FLAG_PATTERN, content)
            if flag:
                print(f"[+] FLAG FOUND in inode {inode}: {flag.group()}")
                return

    # Fallback: strings search across entire image
    print("[*] Falling back to strings search...")
    content = run(f"strings {IMAGE} | grep -oE '{FLAG_PATTERN}'")
    if content.strip():
        print(f"[+] FLAG FOUND: {content.strip()}")
    else:
        print("[-] Flag not found.")

if __name__ == "__main__":
    main()
```

## Tools Used

| Tool           | Purpose                                         |
|----------------|--------------------------------------------------|
| file / fdisk   | Identify image type and partition layout         |
| mount          | Mount disk image for browsing                    |
| fls            | List files including deleted entries (Sleuth Kit) |
| icat           | Extract file contents by inode (Sleuth Kit)      |
| istat          | Show inode metadata (Sleuth Kit)                 |
| foremost       | File carving by header/footer signatures         |
| photorec       | Advanced file recovery and carving               |
| blkls          | Extract slack space and unallocated sectors       |
| mactime        | Build filesystem timeline                        |
| Autopsy        | GUI frontend for Sleuth Kit                      |

## Lessons Learned

1. **Deleted does not mean gone.** When a file is deleted, the filesystem simply marks its inode as available. The actual data remains on disk until that space is overwritten by new data. This is why `fls` can still find it and `icat` can recover the contents.

2. **Always mount forensic images read-only.** Use the `-o ro` flag with `mount` to prevent accidentally modifying evidence. In real forensic work, you'd also use write-blockers.

3. **Know your offsets.** When a disk image contains a partition table, you need to calculate the byte offset to the partition. The formula is: `sector_start * sector_size` (typically 512 bytes per sector).

4. **File carving is your backup plan.** Tools like `foremost` and `photorec` don't rely on filesystem metadata. They scan raw bytes looking for file signatures (magic bytes). This works even when the filesystem is corrupted.

5. **Slack space can hide secrets.** Advanced challenges may hide data in filesystem slack space, which is the unused portion at the end of allocated clusters. The `blkls` tool from Sleuth Kit can extract this.

6. **Timeline analysis reveals the story.** Building a filesystem timeline with `mactime` helps you understand the sequence of events -- when files were created, modified, accessed, and deleted.
