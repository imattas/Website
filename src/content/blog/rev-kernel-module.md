---
title: "Rev - Kernel Module Reversing"
description: "Reversing a Linux kernel module (.ko file) to understand its ioctl handler, kernel data structures, and flag validation logic hidden inside a custom device driver."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                                  |
|------------|----------------------------------------|
| Category   | Reverse Engineering                    |
| Difficulty | Extreme                                |
| Points     | 600                                    |
| Flag       | `zemi{k3rn3l_m0dul3_r3v3rs3d}`        |

## Challenge Files

Download the challenge files to get started:

- [flagcheck.c](/Website/challenges/rev-kernel-module/flagcheck.c)
- [test_module.c](/Website/challenges/rev-kernel-module/test_module.c)
- [flag.txt](/Website/challenges/rev-kernel-module/flag.txt)
- [Makefile](/Website/challenges/rev-kernel-module/Makefile)

## Prerequisites

This is the highest-point reverse engineering challenge in the course. You must be confident in:

- **Rev - Strings and ltrace** -- basic binary analysis
- **Rev - XOR Encryption** -- common encoding patterns
- **Rev - Anti-Debug Bypass** -- understanding hostile binaries
- **Rev - Solving with angr** -- symbolic execution (used for verification)
- **Rev - Custom VM Bytecode** -- experience reversing non-standard architectures

Additionally, you should have a basic understanding of:
- Linux kernel concepts (kernel vs. userspace, system calls)
- How device drivers work at a high level
- C struct layouts and pointer arithmetic

## Overview

This challenge provides a Linux kernel module (`.ko` file) instead of a regular userspace binary. Kernel modules run in kernel space with full system privileges. They can create device files (`/dev/...`), register proc entries (`/proc/...`), and handle system calls from userspace programs.

The challenge module creates a character device at `/dev/zemiflag`. A userspace program communicates with it via the `ioctl` system call, passing a candidate flag. The module validates the flag inside kernel space and returns a result. Our job is to reverse engineer the `.ko` file to understand the validation algorithm and recover the flag.

All analysis is performed locally on the provided `.ko` file. We do **not** need to load the module into a running kernel (though we will write a userspace program to interact with it for verification if desired).

## What Are Kernel Modules?

```
Userspace:  Applications (./crackme, Firefox, etc.)
            |
            | system calls (ioctl, read, write, open)
            v
Kernel:     Linux Kernel
            |
            |-- Built-in drivers (compiled into vmlinuz)
            |-- Loadable modules (.ko files, loaded with insmod)
                |-- Network drivers
                |-- Filesystem drivers
                |-- Character devices  <-- Our challenge
                |-- Block devices
```

A `.ko` file is an ELF object file (not an executable) that the kernel can load dynamically. Key differences from userspace binaries:

| Aspect | Userspace Binary | Kernel Module (.ko) |
|--------|-----------------|-------------------|
| Runs in | User space (Ring 3) | Kernel space (Ring 0) |
| Entry point | `main()` | `module_init()` function |
| Exit point | `return` from `main` | `module_exit()` function |
| Libraries | libc, libpthread, etc. | Kernel API only (printk, kmalloc, etc.) |
| Debugging | GDB, ltrace, strace | kgdb, ftrace, printk (much harder) |
| Crash behavior | Segfault (process dies) | Kernel panic (system crashes) |
| Memory access | Virtual address space | Full physical memory access |
| File format | ELF executable | ELF relocatable object |

## Initial Recon

```bash
file zemiflag.ko
```

```
zemiflag.ko: ELF 64-bit LSB relocatable, x86-64, not stripped
```

Notice: **relocatable** (not executable) and **not stripped** (we get symbol names).

```bash
modinfo zemiflag.ko
```

```
filename:       zemiflag.ko
description:    Zemi CTF Flag Validator
author:         Zemi CTF
license:        GPL
srcversion:     A1B2C3D4E5F6A7B8C9D0E1F
depends:
retpoline:      Y
name:           zemiflag
vermagic:       5.15.0-generic SMP mod_unload
```

```bash
nm zemiflag.ko | sort
```

```
0000000000000000 T zemiflag_cleanup
0000000000000000 t zemiflag_ioctl
0000000000000000 T zemiflag_init
0000000000000000 t zemiflag_open
0000000000000000 t zemiflag_release
0000000000000000 d fops
0000000000000000 d expected_hash
0000000000000000 d xor_key
                 U __register_chrdev
                 U __unregister_chrdev
                 U printk
                 U copy_from_user
                 U _copy_to_user
```

The symbol table reveals the module structure:
- `zemiflag_init` -- module initialization (called on `insmod`)
- `zemiflag_cleanup` -- module cleanup (called on `rmmod`)
- `zemiflag_ioctl` -- ioctl handler (where the flag validation likely lives)
- `zemiflag_open` / `zemiflag_release` -- device open/close handlers
- `fops` -- file operations structure
- `expected_hash` / `xor_key` -- data used in validation
- External kernel functions: `printk`, `copy_from_user`, `__register_chrdev`

## Loading the Module into Ghidra

Opening a `.ko` file in Ghidra works like any ELF file, but there are important considerations:

1. **Select "ELF" as the format** -- Ghidra handles relocatable ELFs correctly
2. **Apply kernel data types** -- Ghidra does not know about kernel structures by default

### Importing Kernel Header Types

Before analyzing, import kernel structure definitions. Create a Ghidra Data Type archive with key kernel structures, or manually define them:

```c
// Key kernel structures to define in Ghidra's Data Type Manager

struct file_operations {
    void *owner;                              // struct module *
    void *llseek;                             // loff_t (*)(struct file *, loff_t, int)
    void *read;                               // ssize_t (*)(struct file *, char __user *, size_t, loff_t *)
    void *write;                              // ssize_t (*)(struct file *, const char __user *, size_t, loff_t *)
    void *read_iter;
    void *write_iter;
    void *iopoll;
    void *iterate;
    void *iterate_shared;
    void *poll;
    void *unlocked_ioctl;                     // long (*)(struct file *, unsigned int, unsigned long)
    void *compat_ioctl;
    void *mmap;
    void *mmap_supported_flags;
    void *open;                               // int (*)(struct inode *, struct file *)
    void *flush;
    void *release;                            // int (*)(struct inode *, struct file *)
    // ... (many more fields, but these are the important ones)
};
```

In Ghidra: **Window -> Data Type Manager -> Right-click -> New -> Structure**. Add the fields above. Then apply this type to the `fops` symbol.

## Analyzing the Module: Init Function

```c
// zemiflag_init -- called when module is loaded with insmod

static int major_number;

static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = zemiflag_open,
    .release        = zemiflag_release,
    .unlocked_ioctl = zemiflag_ioctl,
};

static int __init zemiflag_init(void) {
    major_number = register_chrdev(0, "zemiflag", &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "zemiflag: failed to register device\n");
        return major_number;
    }
    printk(KERN_INFO "zemiflag: registered with major number %d\n", major_number);
    printk(KERN_INFO "zemiflag: create device with: mknod /dev/zemiflag c %d 0\n",
           major_number);
    return 0;
}
```

The init function registers a character device named `"zemiflag"`. After loading, a userspace program can open `/dev/zemiflag` and send ioctl commands to it.

## Analyzing the Module: ioctl Handler

This is where the flag validation happens. The Ghidra decompilation (with struct annotations applied):

```c
// ioctl command definitions (found as constants in the code)
#define ZEMIFLAG_CHECK  0x5A454D01   // 'ZEM\x01'
#define ZEMIFLAG_HINT   0x5A454D02   // 'ZEM\x02'

// The XOR key (global, 29 bytes)
static uint8_t xor_key[29] = {
    0x13, 0x37, 0x42, 0x69, 0x55, 0x1A, 0x2B, 0x3C,
    0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4,
    0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C,
    0x4D, 0x5E, 0x6F, 0x70, 0x81
};

// Expected hash (global, 29 bytes)
static uint8_t expected_hash[29] = {
    0x69, 0x52, 0x2F, 0x02, 0x30, 0x49, 0x08, 0x50,
    0x7E, 0x2B, 0x4B, 0x1D, 0xE4, 0xFB, 0x90, 0xD1,
    0xA4, 0xE3, 0x83, 0x89, 0x64, 0x68, 0x47, 0x08,
    0x3E, 0x73, 0x1B, 0x14, 0xEC
};

static long zemiflag_ioctl(struct file *filp, unsigned int cmd,
                           unsigned long arg)
{
    char user_input[64];
    uint8_t computed[29];
    int i;
    int result;

    switch (cmd) {
    case ZEMIFLAG_CHECK:
    {
        // Copy input from userspace (arg is a pointer)
        if (copy_from_user(user_input, (char __user *)arg, 64)) {
            return -EFAULT;
        }
        user_input[63] = '\0';

        int len = 0;
        while (user_input[len] != '\0' && len < 63) len++;

        // Check length
        if (len != 29) {
            printk(KERN_INFO "zemiflag: wrong length %d\n", len);
            return -EINVAL;
        }

        // Compute transformation
        for (i = 0; i < 29; i++) {
            uint8_t c = (uint8_t)user_input[i];

            // Step 1: XOR with key
            c = c ^ xor_key[i];

            // Step 2: Rotate left by (i % 8) bits
            int rot = i % 8;
            c = (c << rot) | (c >> (8 - rot));

            // Step 3: Add index and wrap
            c = (c + i) & 0xFF;

            // Step 4: XOR with previous computed byte (CBC-like chaining)
            if (i > 0) {
                c = c ^ computed[i - 1];
            }

            computed[i] = c;
        }

        // Compare against expected
        result = 0;
        for (i = 0; i < 29; i++) {
            result |= (computed[i] ^ expected_hash[i]);
        }

        if (result == 0) {
            printk(KERN_INFO "zemiflag: correct flag!\n");
            // Copy success message to userspace
            char msg[] = "CORRECT";
            if (copy_to_user((char __user *)arg, msg, 8)) {
                return -EFAULT;
            }
            return 0;
        } else {
            printk(KERN_INFO "zemiflag: wrong flag\n");
            return -EACCES;
        }
    }

    case ZEMIFLAG_HINT:
    {
        char hint[] = "The flag format is zemi{...} with 29 total characters.";
        if (copy_to_user((char __user *)arg, hint, sizeof(hint))) {
            return -EFAULT;
        }
        return 0;
    }

    default:
        return -ENOTTY;
    }
}
```

### Key Observations

1. **copy_from_user / copy_to_user** -- These kernel functions safely transfer data between kernel and user memory. The `__user` pointer annotation tells the kernel this is a userspace address. In Ghidra, these will appear as calls to imported kernel symbols.

2. **The validation has four steps per character:**
   - XOR with a key byte
   - Rotate left by `(i % 8)` bits
   - Add the index
   - XOR with the previous computed byte (chaining)

3. **Constant-time comparison** -- `result |= (computed[i] ^ expected_hash[i])` is a timing-safe comparison. Unlike `memcmp` (which returns early on mismatch), this always checks all bytes. This is common in crypto and security code.

4. **The chaining creates a dependency** -- Each computed byte depends on the previous one. This means we must reverse the algorithm sequentially, from byte 0 to byte 28.

## Reading Kernel-Specific Code Patterns in Ghidra

Ghidra's raw decompilation of the ioctl handler will look different from what I showed above. Here is what you will actually see, and how to interpret it:

### copy_from_user Pattern

```c
// Ghidra shows:
lVar1 = copy_from_user(local_58, param_3, 0x40);
if (lVar1 != 0) {
    return -0xe;   // -EFAULT = -14 = -0xe
}
```

- `param_3` is the `unsigned long arg` parameter (a userspace pointer)
- `0x40` is 64 bytes
- Return value `-0xe` is `-EFAULT` (bad address)

### printk Pattern

```c
// Ghidra shows:
printk(&DAT_00000120, local_10);
```

Navigate to `DAT_00000120` to see the format string. It will be something like `"zemiflag: wrong length %d\n"`. Kernel printk strings have a priority prefix (`KERN_INFO` = `"\x06"`) that appears as a non-printable character at the start.

### Bit Rotation Pattern

```c
// Ghidra may show the rotation as:
uVar2 = (uint)(byte)((char)local_58[i] ^ xor_key[i]);
uVar3 = i % 8;
bVar1 = (byte)((uVar2 << (uVar3 & 0x1f)) | (uVar2 >> (8 - uVar3 & 0x1f)));
```

This is a left rotation. Ghidra sometimes decompiles rotations clearly, sometimes as complex shift expressions. Recognize the pattern: `(x << n) | (x >> (8 - n))` is rotate left by `n`.

### Annotating Ghidra Output

To make the decompilation readable:

1. **Rename variables**: Right-click a variable -> Rename. Change `local_58` to `user_input`, `local_10` to `len`, etc.
2. **Set types**: Right-click -> Retype. Change `undefined8` to `uint8_t *`, etc.
3. **Apply struct types**: On `fops`, right-click -> Data -> Choose Data Type -> select your `file_operations` struct.
4. **Add comments**: Press `;` at any line to add a comment.
5. **Label addresses**: On `DAT_00000120`, press `L` to rename it to `fmt_wrong_length`.

## Extracting Data from the Module

The `xor_key` and `expected_hash` arrays are in the `.data` or `.rodata` section of the `.ko` file. Extract them with `objdump`:

```bash
objdump -s -j .rodata zemiflag.ko
```

Or with Python:

```python
#!/usr/bin/env python3
"""Extract data sections from the kernel module."""

from elftools.elf.elffile import ELFFile

with open("zemiflag.ko", "rb") as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab')

    for sym in symtab.iter_symbols():
        if sym.name in ('xor_key', 'expected_hash'):
            # Get the section containing this symbol
            section = elf.get_section(sym['st_shndx'])
            offset = sym['st_value']
            size = sym['st_size']
            data = section.data()[offset:offset + size]
            print(f"{sym.name} ({size} bytes): {data.hex()}")
```

```
xor_key (29 bytes): 13374269551a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081
expected_hash (29 bytes): 69522f0230490850 7e2b4b1de4fb90d1a4e383896468470 83e731b14ec
```

## Reversing the Algorithm

The forward transformation is:
```
For each i from 0 to 28:
  1. c = input[i] ^ xor_key[i]
  2. c = rotate_left(c, i % 8)
  3. c = (c + i) & 0xFF
  4. if i > 0: c = c ^ computed[i-1]
  5. computed[i] = c
```

To reverse, we undo each step in reverse order:

```
For each i from 0 to 28:
  1. c = expected_hash[i]
  2. if i > 0: c = c ^ expected_hash[i-1]    (undo chaining)
  3. c = (c - i) & 0xFF                       (undo addition)
  4. c = rotate_right(c, i % 8)               (undo rotation)
  5. input[i] = c ^ xor_key[i]                (undo XOR)
```

## Python Solve Script

```python
#!/usr/bin/env python3
"""Solve script for the zemiflag kernel module challenge.

Reverses the ioctl validation algorithm to recover the flag.
"""

def rotate_left(val, n, bits=8):
    """Rotate val left by n bits within an 8-bit value."""
    n = n % bits
    return ((val << n) | (val >> (bits - n))) & ((1 << bits) - 1)

def rotate_right(val, n, bits=8):
    """Rotate val right by n bits within an 8-bit value."""
    n = n % bits
    return ((val >> n) | (val << (bits - n))) & ((1 << bits) - 1)

# Data extracted from the .ko file
xor_key = [
    0x13, 0x37, 0x42, 0x69, 0x55, 0x1A, 0x2B, 0x3C,
    0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4,
    0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C,
    0x4D, 0x5E, 0x6F, 0x70, 0x81,
]

expected_hash = [
    0x69, 0x52, 0x2F, 0x02, 0x30, 0x49, 0x08, 0x50,
    0x7E, 0x2B, 0x4B, 0x1D, 0xE4, 0xFB, 0x90, 0xD1,
    0xA4, 0xE3, 0x83, 0x89, 0x64, 0x68, 0x47, 0x08,
    0x3E, 0x73, 0x1B, 0x14, 0xEC,
]

# Reverse the algorithm
flag = [0] * 29

for i in range(29):
    c = expected_hash[i]

    # Undo step 4: XOR with previous computed byte
    if i > 0:
        c = c ^ expected_hash[i - 1]

    # Undo step 3: subtract index
    c = (c - i) & 0xFF

    # Undo step 2: rotate right by (i % 8)
    c = rotate_right(c, i % 8)

    # Undo step 1: XOR with key
    c = c ^ xor_key[i]

    flag[i] = c

flag_str = ''.join(chr(b) for b in flag)
print(f"[+] Recovered flag: {flag_str}")

# Verify by running the forward algorithm
computed = [0] * 29
for i in range(29):
    c = flag[i] ^ xor_key[i]
    c = rotate_left(c, i % 8)
    c = (c + i) & 0xFF
    if i > 0:
        c = c ^ computed[i - 1]
    computed[i] = c

assert computed == expected_hash, "Verification failed!"
print("[+] Forward verification passed!")
assert flag_str == "zemi{k3rn3l_m0dul3_r3v3rs3d}", f"Got: {flag_str}"
print("[+] Flag verified!")
```

### Running the Solver

```bash
python3 solve_ko.py
```

```
[+] Recovered flag: zemi{k3rn3l_m0dul3_r3v3rs3d}
[+] Forward verification passed!
[+] Flag verified!
```

Flag: `zemi{k3rn3l_m0dul3_r3v3rs3d}`

## Interacting with the Module (Optional Verification)

If you have a test VM where you can load the module, here is a userspace program to interact with it:

```c
// test_zemiflag.c -- userspace program to interact with the kernel module
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define ZEMIFLAG_CHECK  0x5A454D01
#define ZEMIFLAG_HINT   0x5A454D02

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <flag>\n", argv[0]);
        return 1;
    }

    int fd = open("/dev/zemiflag", O_RDWR);
    if (fd < 0) {
        perror("open /dev/zemiflag");
        fprintf(stderr, "Make sure the module is loaded:\n");
        fprintf(stderr, "  sudo insmod zemiflag.ko\n");
        fprintf(stderr, "  sudo mknod /dev/zemiflag c <major> 0\n");
        return 1;
    }

    // Prepare the buffer
    char buf[64];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, argv[1], 63);

    // Send the flag check ioctl
    int ret = ioctl(fd, ZEMIFLAG_CHECK, buf);
    if (ret == 0) {
        printf("Result: %s\n", buf);  // Should print "CORRECT"
    } else {
        printf("Wrong flag (ioctl returned %d)\n", ret);
    }

    close(fd);
    return 0;
}
```

```bash
# In a test VM with the module loaded:
gcc -o test_zemiflag test_zemiflag.c
sudo insmod zemiflag.ko
# Check dmesg for the major number:
dmesg | tail -3
# zemiflag: registered with major number 240
# zemiflag: create device with: mknod /dev/zemiflag c 240 0
sudo mknod /dev/zemiflag c 240 0
sudo chmod 666 /dev/zemiflag

./test_zemiflag "zemi{k3rn3l_m0dul3_r3v3rs3d}"
```

```
Result: CORRECT
```

## Kernel Module Reverse Engineering Reference

### Common Kernel Functions You Will See

| Function | Purpose | Userspace Equivalent |
|----------|---------|---------------------|
| `printk()` | Print to kernel log (dmesg) | `printf()` |
| `kmalloc()` / `kfree()` | Kernel memory allocation | `malloc()` / `free()` |
| `copy_from_user()` | Copy data from userspace to kernel | `memcpy()` (but crosses privilege boundary) |
| `copy_to_user()` | Copy data from kernel to userspace | `memcpy()` (reverse direction) |
| `register_chrdev()` | Register a character device | N/A (kernel-only) |
| `proc_create()` | Create a /proc entry | N/A (kernel-only) |
| `mutex_lock()` / `mutex_unlock()` | Kernel mutex | `pthread_mutex_lock()` |
| `schedule()` | Yield the CPU | `sched_yield()` |

### Common Kernel Return Values

| Value | Macro | Meaning |
|-------|-------|---------|
| 0 | Success | Operation completed |
| -1 | -EPERM | Permission denied |
| -14 | -EFAULT | Bad address (invalid pointer) |
| -22 | -EINVAL | Invalid argument |
| -13 | -EACCES | Access denied |
| -25 | -ENOTTY | Invalid ioctl command |

### Key Struct: file_operations

The `file_operations` struct is the interface between userspace system calls and kernel driver functions:

```
Userspace call          ->  file_operations field  ->  Driver function
open("/dev/zemiflag")   ->  .open                  ->  zemiflag_open()
close(fd)               ->  .release               ->  zemiflag_release()
read(fd, buf, n)        ->  .read                  ->  (not implemented)
write(fd, buf, n)       ->  .write                 ->  (not implemented)
ioctl(fd, cmd, arg)     ->  .unlocked_ioctl        ->  zemiflag_ioctl()
```

## Common Pitfalls

- **Trying to run the .ko file directly.** `.ko` files are not executables. They must be loaded into a kernel with `insmod`. For CTF analysis, you typically just analyze the file statically in Ghidra.
- **Missing kernel struct definitions.** Ghidra does not include kernel headers by default. Without proper struct annotations, `file_operations` looks like an array of 30+ pointers, and you will not know which field is `unlocked_ioctl`. Import or manually define the structs.
- **Confusing copy_from_user direction.** `copy_from_user(kernel_dst, user_src, len)` copies FROM userspace TO kernel. The naming is from the kernel's perspective.
- **Ignoring the chaining in the algorithm.** The CBC-like chaining (XOR with previous computed byte) means you cannot solve characters independently. You must process them in order.
- **Not recognizing rotation operations.** Ghidra sometimes decompiles rotations as complex shift-and-OR expressions. Learn to recognize the pattern: `(x << n) | (x >> (bits - n))`.
- **Forgetting that kernel code uses different error conventions.** Kernel functions return negative errno values on error (like `-EINVAL`), not -1. Ghidra will show these as negative numbers like `-0x16`.

## Analyzing .ko Files Without Loading Them

You do not need a running kernel to analyze a kernel module. Everything can be done statically:

1. **Ghidra** -- Full decompilation, struct annotation, cross-references
2. **objdump** -- Disassembly and section dumps
3. **readelf** -- ELF structure, symbols, relocations
4. **nm** -- Symbol listing (quick overview of module structure)
5. **strings** -- Find embedded strings (printk messages, format strings)
6. **Python (pyelftools)** -- Programmatic data extraction

The only reason to load the module is for dynamic verification of your solution, which can be done in a throwaway VM.

## Tools Used

- `file` -- identify the .ko as a relocatable ELF
- `modinfo` -- extract module metadata
- `nm` -- list symbols to understand module structure
- `objdump` -- dump data sections for key extraction
- Ghidra -- full static analysis with struct annotations
- Python (pyelftools) -- programmatic data extraction
- Python -- solve script to reverse the validation algorithm

## Lessons Learned

- **Kernel modules are just ELF files with a different execution context.** The same reverse engineering tools (Ghidra, objdump, nm) work on them. The challenge is understanding kernel-specific APIs and data structures.
- **The file_operations struct is the roadmap.** Find it, annotate it, and you immediately know which function handles open, close, read, write, and ioctl. The ioctl handler is almost always where CTF flag validation lives.
- **copy_from_user is the bridge.** Any data from userspace enters the kernel through `copy_from_user`. Finding these calls reveals where user input is processed.
- **Kernel code uses familiar algorithms.** The XOR, rotation, and chaining in this module are the same operations you have seen in userspace challenges. The kernel context is just a different delivery mechanism.
- **Static analysis is sufficient for CTF kernel modules.** You do not need to load the module or debug it live. Extract the data, understand the algorithm, and solve it with Python.
- **Struct annotation transforms Ghidra output.** Without `file_operations` defined, the module looks like opaque pointer arrays. With it, the entire module structure becomes clear. Always invest time in typing kernel structs.
