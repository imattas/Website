---
title: "Rev - Strings, ltrace, and strace"
description: "Using strings, ltrace, and strace as your first line of attack when reversing a Linux binary to extract a hidden flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                              |
|------------|------------------------------------|
| Category   | Reverse Engineering                |
| Difficulty | Easy                               |
| Points     | 75                                 |
| Flag       | `zemi{str1ngs_4r3_y0ur_fr13nd}`    |

## Challenge Files

Download the challenge files to get started:

- [easyrev.c](/Website/challenges/rev-strings-and-ltrace/easyrev.c)
- [flag.txt](/Website/challenges/rev-strings-and-ltrace/flag.txt)
- [Makefile](/Website/challenges/rev-strings-and-ltrace/Makefile)

## Overview

Before reaching for a full disassembler like Ghidra or IDA, every reverse engineer should know the "quick wins" -- lightweight command-line tools that can solve easy challenges in seconds. This writeup walks through three essential tools: `strings`, `ltrace`, and `strace`. All analysis is done locally on the provided binary.

## Initial Recon

We receive a binary called `ezcheck`. Start with the basics:

```bash
file ezcheck
```

```
ezcheck: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Dynamically linked and not stripped -- great. Let's run it to see what it does:

```bash
chmod +x ezcheck
./ezcheck
```

```
=== Secret Vault ===
Enter access code: hello
ACCESS DENIED
```

It prompts for an access code and rejects our guess. Time to dig deeper.

## Step 1: strings

The `strings` command extracts printable character sequences from a binary. By default it looks for sequences of 4 or more printable characters. This is always the first thing to try:

```bash
strings ezcheck
```

```
/lib64/ld-linux-x86-64.so.2
libc.so.6
strcmp
printf
fgets
puts
__libc_start_main
=== Secret Vault ===
Enter access code:
ACCESS GRANTED
ACCESS DENIED
s3cr3t_p4ss
```

Interesting -- we can see the strings `ACCESS GRANTED`, `ACCESS DENIED`, and what looks like a password: `s3cr3t_p4ss`. We also see that the binary uses `strcmp`, which means it probably compares our input against a hardcoded string.

Let's try it:

```bash
./ezcheck
```

```
=== Secret Vault ===
Enter access code: s3cr3t_p4ss
ACCESS GRANTED
zemi{str1ngs_4r3_y0ur_fr13nd}
```

That was it. But what if `strings` hadn't turned up the password so obviously? Let's look at the other tools.

## Step 2: ltrace -- Tracing Library Calls

`ltrace` intercepts and records dynamic library calls made by a process. This is incredibly powerful because it shows you the **arguments** to functions like `strcmp`, `strlen`, `memcmp`, etc.

```bash
ltrace ./ezcheck
```

```
printf("=== Secret Vault ===\n")                = 21
printf("Enter access code: ")                   = 19
fgets("anything\n", 64, 0x7f3a2b4c1980)         = 0x7ffd8a3e4b20
strcmp("anything", "s3cr3t_p4ss")                 = -18
puts("ACCESS DENIED")                            = 14
+++ exited (status 1) +++
```

Look at the `strcmp` call. `ltrace` shows us both arguments in plain text:
- First argument: `"anything"` (our input, with the newline already stripped)
- Second argument: `"s3cr3t_p4ss"` (the expected password)

The password is handed to us on a silver platter. This is the **key technique** for this challenge -- any binary that uses `strcmp` (or `strncmp`, `memcmp`) with a plaintext password will leak it through `ltrace`.

Let's confirm:

```bash
ltrace ./ezcheck
```

```
printf("=== Secret Vault ===\n")                = 21
printf("Enter access code: ")                   = 19
fgets("s3cr3t_p4ss\n", 64, 0x7f3a2b4c1980)      = 0x7ffd8a3e4b20
strcmp("s3cr3t_p4ss", "s3cr3t_p4ss")              = 0
puts("ACCESS GRANTED")                           = 15
printf("zemi{str1ngs_4r3_y0ur_fr13nd}\n")        = 30
+++ exited (status 0) +++
```

`strcmp` returns 0 (match), and the flag is printed.

## Step 3: strace -- Tracing System Calls

`strace` traces **system calls** rather than library calls. It operates at a lower level and is useful when a binary does file operations, network connections, or other OS-level activity.

```bash
strace ./ezcheck 2>&1 | head -30
```

```
execve("./ezcheck", ["./ezcheck"], 0x7ffd8a3e5120 /* 52 vars */) = 0
brk(NULL)                               = 0x55a7c8d41000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
...
write(1, "=== Secret Vault ===\n", 21)  = 21
write(1, "Enter access code: ", 19)     = 19
read(0, "test\n", 1024)                 = 5
write(1, "ACCESS DENIED\n", 14)         = 14
exit_group(1)                           = ?
```

For this particular challenge, `strace` is less useful than `ltrace` because the password comparison happens inside `strcmp` (a library call), not via a system call. However, `strace` would be essential if the binary were:

- Reading a key from a file (`openat`, `read`)
- Connecting to a local socket
- Checking for debuggers via `ptrace`
- Using environment variables

### When to Use Each Tool

| Tool       | Traces               | Best For                                     |
|------------|----------------------|----------------------------------------------|
| `strings`  | Static data          | Finding hardcoded passwords, URLs, file paths |
| `ltrace`   | Library calls        | Seeing strcmp/memcmp arguments, crypto calls   |
| `strace`   | System calls         | File I/O, network activity, anti-debug checks |

## A More Filtered Approach

When dealing with larger binaries, you can filter output:

```bash
# Only show strcmp calls
ltrace -e strcmp ./ezcheck <<< "test"
```

```
ezcheck->strcmp("test", "s3cr3t_p4ss")    = -1
+++ exited (status 1) +++
```

```bash
# Show only file-related syscalls
strace -e trace=openat,read,write ./ezcheck <<< "test"
```

```bash
# Find strings of minimum length 8
strings -n 8 ezcheck
```

```
=== Secret Vault ===
Enter access code:
ACCESS GRANTED
ACCESS DENIED
s3cr3t_p4ss
```

## Tools Used

- `file` -- identify binary type and architecture
- `strings` -- extract printable strings from binary data
- `ltrace` -- trace dynamic library calls and their arguments
- `strace` -- trace system calls and signals

## Lessons Learned

- **Always start with `strings`**. It takes one second and can solve easy challenges immediately. Look for passwords, URLs, flag fragments, and format strings.
- **`ltrace` is devastating against naive password checks**. Any binary that passes the expected password as a plaintext argument to `strcmp`, `strncmp`, or `memcmp` will leak it.
- **`strace` operates at the kernel level**. Use it when you need to understand file access, network behavior, or process-level anti-tamper checks.
- These three tools should be your **first step** before opening Ghidra or IDA. Many easy-to-medium CTF challenges fall to them instantly.
- If `ltrace` shows no output or errors, the binary may be statically linked (no dynamic library calls to intercept) -- in that case, fall back to `strace` and static analysis.
