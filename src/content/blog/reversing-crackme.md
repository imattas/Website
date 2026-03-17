---
title: "Reverse Engineering - Baby Crackme"
description: "Reversing a simple Linux binary to find the correct password that unlocks the flag using Ghidra and GDB."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                |
|------------|----------------------|
| Category   | Reverse Engineering  |
| Difficulty | Medium               |
| Points     | 200                  |
| Flag       | `zemi{gh1dr4_1s_my_b3st_fr13nd}` |

## Challenge Files

Download the challenge files to get started:

- [crackme.c](/Website/challenges/reversing-crackme/crackme.c)
- [flag.txt](/Website/challenges/reversing-crackme/flag.txt)
- [Makefile](/Website/challenges/reversing-crackme/Makefile)

## Reconnaissance

We're given a Linux ELF binary called `crackme`. Let's start with basic recon:

```bash
file crackme
```

```
crackme: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Good news — it's not stripped, so we'll have symbol names. Let's run it:

```bash
chmod +x crackme
./crackme
```

```
Enter the password: test
Wrong password. Try again.
```

We need to find the correct password.

## Static Analysis with Ghidra

Load the binary into Ghidra and navigate to the `main` function. The decompiled output looks like:

```c
int main(void) {
    char input[64];
    char password[] = {0x73, 0x75, 0x70, 0x33, 0x72, 0x5f,
                       0x73, 0x33, 0x63, 0x72, 0x33, 0x74, 0x00};

    printf("Enter the password: ");
    fgets(input, 64, stdin);

    // Strip newline
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, password) == 0) {
        decrypt_flag();
    } else {
        puts("Wrong password. Try again.");
    }
    return 0;
}
```

The password is stored as hex bytes on the stack. Let's decode them:

```python
password_bytes = [0x73, 0x75, 0x70, 0x33, 0x72, 0x5f,
                  0x73, 0x33, 0x63, 0x72, 0x33, 0x74]
password = ''.join(chr(b) for b in password_bytes)
print(password)
```

```
sup3r_s3cr3t
```

## Verifying the Password

```bash
./crackme
```

```
Enter the password: sup3r_s3cr3t
Access granted!
zemi{gh1dr4_1s_my_b3st_fr13nd}
```

## Alternative Approach: Dynamic Analysis with GDB

If the static analysis was harder to read, we could use GDB to bypass the check entirely:

```bash
gdb ./crackme
```

```gdb
(gdb) disas main
   ...
   0x0000000000401234 <+100>:  call   0x401050 <strcmp@plt>
   0x0000000000401239 <+105>:  test   eax,eax
   0x000000000040123b <+107>:  jne    0x401260 <main+144>
   0x000000000040123d <+109>:  call   0x4011a0 <decrypt_flag>
   ...
```

The `jne` instruction at `0x40123b` jumps over `decrypt_flag` if the password is wrong. We can either:

**Option A:** Patch the jump to always fall through:

```gdb
(gdb) break *0x40123b
(gdb) run
Enter the password: anything
Breakpoint 1 hit
(gdb) set $eflags &= ~0x40   # Clear ZF to fake a match
                               # Actually, set ZF: set $eflags |= 0x40
(gdb) set $eflags |= 0x40
(gdb) continue
Access granted!
zemi{gh1dr4_1s_my_b3st_fr13nd}
```

**Option B:** Read the password from memory right before the `strcmp`:

```gdb
(gdb) break strcmp
(gdb) run
Enter the password: anything
Breakpoint 1 hit
(gdb) x/s $rsi
0x7fffffffe3a0: "sup3r_s3cr3t"
```

The second argument to `strcmp` (`$rsi` in x86-64 calling convention) is the expected password.

## Tools Used

- `file` — identify binary type
- Ghidra — static analysis / decompilation
- GDB — dynamic analysis / debugging
- Python — quick hex-to-ASCII conversion

## Lessons Learned

- Start reverse engineering with `file` and `strings` before opening a disassembler
- Non-stripped binaries are easier — you get function names for free
- Hardcoded passwords (even as hex bytes) are trivially extractable
- GDB lets you inspect register values at runtime, which is great for finding `strcmp` arguments
- In x86-64 Linux, function arguments go in registers: `$rdi`, `$rsi`, `$rdx`, `$rcx`, `$r8`, `$r9`
- You can always patch jumps in GDB to skip checks — useful when the check is obfuscated
