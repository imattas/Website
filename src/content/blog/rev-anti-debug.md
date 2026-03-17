---
title: "Rev - Anti-Debug Bypass"
description: "Identifying and bypassing anti-debugging techniques in a Linux binary including ptrace, timing checks, and /proc/self/status inspection."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                            |
|------------|----------------------------------|
| Category   | Reverse Engineering              |
| Difficulty | Hard                             |
| Points     | 350                              |
| Flag       | `zemi{4nt1_d3bug_byp4ss3d}`      |

## Challenge Files

Download the challenge files to get started:

- [antidebug.c](/Website/challenges/rev-anti-debug/antidebug.c)
- [flag.txt](/Website/challenges/rev-anti-debug/flag.txt)
- [Makefile](/Website/challenges/rev-anti-debug/Makefile)

## Overview

Malware authors and CTF challenge designers both use anti-debugging techniques to make dynamic analysis harder. This binary employs multiple layers of anti-debug: `ptrace` self-attachment, timing checks, and `/proc/self/status` inspection. We need to identify and bypass each one to debug the binary and extract the flag. All analysis is performed locally.

## Initial Recon

We receive a binary called `fortress`:

```bash
file fortress
```

```
fortress: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

```bash
./fortress
```

```
=== FORTRESS ===
Initializing security checks...
Security checks passed.
Enter key: test
Incorrect key.
```

It runs fine standalone. But when we try to debug it:

```bash
gdb -q ./fortress -ex "run"
```

```
=== FORTRESS ===
Initializing security checks...
Debugger detected! Exiting.
```

And with ltrace:

```bash
ltrace ./fortress <<< "test"
```

```
ptrace(0, 0, 1, 0)                              = -1
puts("Debugger detected! Exiting.")              = 29
exit(1)
```

The binary detects our debugging tools and refuses to run. Let's understand each technique and bypass it.

## Static Analysis: Identifying Anti-Debug Techniques

Loading into Ghidra, we find the `main` function calls `security_init()` before doing anything useful:

```c
int main(void) {
    puts("=== FORTRESS ===");
    puts("Initializing security checks...");

    security_init();

    puts("Security checks passed.");

    char key[64];
    printf("Enter key: ");
    fgets(key, 64, stdin);
    key[strcspn(key, "\n")] = 0;

    if (validate_key(key)) {
        decrypt_flag(key);
    } else {
        puts("Incorrect key.");
    }
    return 0;
}
```

The `security_init` function contains three anti-debug checks:

```c
void security_init(void) {
    // Anti-debug technique #1: ptrace
    check_ptrace();

    // Anti-debug technique #2: timing
    check_timing();

    // Anti-debug technique #3: /proc/self/status
    check_proc_status();
}
```

Let's examine each one.

## Anti-Debug Technique #1: ptrace (PTRACE_TRACEME)

```c
void check_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        puts("Debugger detected! Exiting.");
        exit(1);
    }
}
```

**How it works:** `PTRACE_TRACEME` tells the kernel "I want to be traced by my parent process." A process can only have one tracer. When GDB (or ltrace/strace) attaches to a process, it uses ptrace. If the binary calls `PTRACE_TRACEME` first and a debugger is already attached, the call fails and returns -1.

In assembly:

```asm
check_ptrace:
  PUSH    RBP
  MOV     RBP, RSP
  XOR     ECX, ECX           ; data = 0
  MOV     EDX, 0x1           ; addr = 1
  XOR     ESI, ESI           ; pid = 0
  XOR     EDI, EDI           ; request = PTRACE_TRACEME (0)
  CALL    ptrace
  CMP     RAX, -1
  JE      .debugger_detected
  POP     RBP
  RET
.debugger_detected:
  LEA     RDI, [s_Debugger_detected]
  CALL    puts
  MOV     EDI, 1
  CALL    exit
```

### Bypass #1A: LD_PRELOAD

Create a shared library that overrides `ptrace` to always return 0:

```c
// fakeptrace.c
long ptrace(int request, ...) {
    return 0;
}
```

```bash
gcc -shared -fPIC -o fakeptrace.so fakeptrace.c
LD_PRELOAD=./fakeptrace.so ./fortress
```

```
=== FORTRESS ===
Initializing security checks...
Security checks passed.
Enter key:
```

The ptrace check is bypassed. `LD_PRELOAD` loads our library before libc, so our `ptrace` function gets called instead of the real one.

### Bypass #1B: GDB -- catch and override

```gdb
(gdb) catch syscall ptrace
Catchpoint 1 (syscall 'ptrace' [101])
(gdb) commands 1
  > set $rax = 0
  > continue
  > end
(gdb) run
```

This catches every ptrace syscall and sets the return value to 0 before continuing.

### Bypass #1C: Patch the binary

NOP out the call to `check_ptrace` or patch the `JE` after the comparison (as covered in the patching writeup).

## Anti-Debug Technique #2: Timing Check

```c
void check_timing(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Do some dummy work
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);

    // If the loop took more than 100ms, we're probably being debugged
    // (single-stepping or breakpoints add massive delays)
    if (elapsed_ns > 100000000L) {
        puts("Timing anomaly detected! Exiting.");
        exit(1);
    }
}
```

**How it works:** When you single-step through code in a debugger, each instruction takes orders of magnitude longer than normal execution. A simple loop that normally takes microseconds will take seconds under a debugger. The binary measures this and bails if it's too slow.

In assembly, the key comparison:

```asm
  CALL    clock_gettime
  ; ... compute elapsed nanoseconds ...
  MOV     RAX, [RBP-0x10]       ; elapsed_ns
  CMP     RAX, 0x5F5E100        ; 100,000,000 (100ms)
  JG      .timing_detected
```

### Bypass #2A: LD_PRELOAD (fake clock_gettime)

```c
// faketime.c
#include <time.h>

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    tp->tv_sec = 0;
    tp->tv_nsec = 0;
    return 0;
}
```

```bash
gcc -shared -fPIC -o faketime.so faketime.c
LD_PRELOAD="./fakeptrace.so:./faketime.so" ./fortress
```

Now both ptrace and timing checks are bypassed.

### Bypass #2B: GDB -- skip the function

```gdb
(gdb) break check_timing
Breakpoint 2 at 0x4011f0
(gdb) commands 2
  > return
  > continue
  > end
(gdb) run
```

When GDB hits `check_timing`, it immediately returns from the function without executing it.

### Bypass #2C: Patch the comparison

Change `JG` (jump if greater) to `JMP` past the exit, or NOP the conditional jump:

```
0x401230: 7F 15    JG   .timing_detected
                    -->
0x401230: 90 90    NOP  NOP
```

## Anti-Debug Technique #3: /proc/self/status (TracerPid)

```c
void check_proc_status(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            if (tracer_pid != 0) {
                fclose(f);
                puts("Tracer process detected! Exiting.");
                exit(1);
            }
            break;
        }
    }
    fclose(f);
}
```

**How it works:** On Linux, `/proc/self/status` contains process information. The `TracerPid` field shows the PID of the tracing process (0 if not being traced). When GDB is attached, this field is non-zero.

```bash
# Normal execution:
cat /proc/self/status | grep TracerPid
TracerPid:	0

# Under GDB:
# TracerPid:	12345
```

### Bypass #3A: LD_PRELOAD (fake fopen)

```c
// fakefopen.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

FILE *fopen(const char *path, const char *mode) {
    // Get the real fopen
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");

    // If opening /proc/self/status, redirect to /dev/null
    // or better, return a fake file
    if (strcmp(path, "/proc/self/status") == 0) {
        // Create a temp file with TracerPid: 0
        FILE *fake = tmpfile();
        fprintf(fake, "TracerPid:\t0\n");
        rewind(fake);
        return fake;
    }

    return real_fopen(path, mode);
}
```

```bash
gcc -shared -fPIC -o fakefopen.so fakefopen.c -ldl
LD_PRELOAD="./fakeptrace.so:./faketime.so:./fakefopen.so" ./fortress
```

### Bypass #3B: GDB -- modify the file read

```gdb
(gdb) break check_proc_status
Breakpoint 3 at 0x401270
(gdb) commands 3
  > return
  > continue
  > end
```

### Bypass #3C: Set TracerPid before the check

You can't modify `/proc/self/status` directly, but you can use GDB with a tricky approach -- detach GDB before the check runs, and re-attach after:

```gdb
(gdb) break *0x401270    # break at check_proc_status
(gdb) run
Breakpoint hit
(gdb) detach             # GDB is no longer attached -- TracerPid becomes 0
```

Then re-attach from another terminal after the check passes. This is fragile but demonstrates the concept.

## Combined Bypass: The All-in-One LD_PRELOAD Library

For the cleanest solution, combine all bypasses into one shared library:

```c
// bypass_all.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>

// Bypass ptrace
long ptrace(int request, ...) {
    return 0;
}

// Bypass timing
int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    int (*real_clock_gettime)(clockid_t, struct timespec *) =
        dlsym(RTLD_NEXT, "clock_gettime");
    int ret = real_clock_gettime(clk_id, tp);
    // Store a "base" time and always return it so elapsed = 0
    static struct timespec base = {0, 0};
    static int initialized = 0;
    if (!initialized) {
        base = *tp;
        initialized = 1;
    }
    *tp = base;
    return ret;
}

// Bypass /proc/self/status check
FILE *fopen(const char *path, const char *mode) {
    FILE *(*real_fopen)(const char *, const char *) =
        dlsym(RTLD_NEXT, "fopen");

    if (strcmp(path, "/proc/self/status") == 0) {
        FILE *fake = tmpfile();
        fprintf(fake, "Name:\tfortress\nTracerPid:\t0\n");
        rewind(fake);
        return fake;
    }
    return real_fopen(path, mode);
}
```

```bash
gcc -shared -fPIC -o bypass_all.so bypass_all.c -ldl
LD_PRELOAD=./bypass_all.so gdb -q ./fortress
```

Now GDB works with all anti-debug checks bypassed:

```gdb
(gdb) break validate_key
(gdb) run
=== FORTRESS ===
Initializing security checks...
Security checks passed.
Enter key: anything

Breakpoint 1, validate_key(key=0x7fffffffe3a0 "anything")
(gdb) # Now we can freely debug the key validation!
```

## Extracting the Flag

With debugging now working, we can analyze `validate_key`. It turns out to be another multi-constraint check. Using our GDB access, we set a breakpoint on the comparison and extract the expected key, or we use angr with the anti-debug functions patched out:

```bash
# Patch approach: NOP out the calls to anti-debug functions
r2 -w fortress
```

```
[0x00401080]> aaa
[0x00401080]> s sym.security_init
[0x004011a0]> pd 10
            0x004011a0    push rbp
            0x004011a1    mov rbp, rsp
            0x004011a4    call sym.check_ptrace
            0x004011a9    call sym.check_timing
            0x004011ae    call sym.check_proc_status
            0x004011b3    pop rbp
            0x004011b4    ret

; NOP out all three calls (each CALL is 5 bytes)
[0x004011a4]> wx 9090909090         ; NOP check_ptrace call
[0x004011a9]> wx 9090909090         ; NOP check_timing call
[0x004011ae]> wx 9090909090         ; NOP check_proc_status call
[0x004011a4]> pd 10
            0x004011a4    nop
            0x004011a5    nop
            0x004011a6    nop
            0x004011a7    nop
            0x004011a8    nop
            0x004011a9    nop
            0x004011aa    nop
            0x004011ab    nop
            0x004011ac    nop
            0x004011ad    nop
            0x004011ae    nop
            0x004011af    nop
            0x004011b0    nop
            0x004011b1    nop
            0x004011b2    nop
            0x004011b3    pop rbp
            0x004011b4    ret
[0x004011a4]> q
```

Now the patched binary can be freely debugged and analyzed to find the key and extract the flag:

```bash
./fortress
```

```
=== FORTRESS ===
Initializing security checks...
Security checks passed.
Enter key: s3cur3_f0rtr3ss
Correct!
zemi{4nt1_d3bug_byp4ss3d}
```

## Anti-Debug Technique Reference

| Technique | Detection Method | Bypass |
|-----------|-----------------|--------|
| `ptrace(PTRACE_TRACEME)` | Self-trace fails if already being traced | `LD_PRELOAD` fake ptrace, GDB catch syscall, NOP the call |
| Timing check (`clock_gettime`, `rdtsc`) | Measures execution delay from single-stepping | `LD_PRELOAD` fake time functions, NOP the comparison, skip the function in GDB |
| `/proc/self/status` TracerPid | Reads tracer PID from procfs | `LD_PRELOAD` fake fopen, NOP the call, detach/reattach GDB |
| `/proc/self/maps` | Checks for debugger memory mappings | Same as TracerPid bypass |
| `signal(SIGTRAP)` handler | Debuggers intercept SIGTRAP; if handler doesn't run, debugger is present | GDB: `handle SIGTRAP nostop pass` |
| `INT 3` instruction | Generates SIGTRAP; debuggers catch it | GDB: `handle SIGTRAP nostop pass` |
| Environment variable checks | Checks for `_`, `LINES`, etc. set by GDB | Sanitize env before running |

## Tools Used

- `file` -- identify binary type
- `ltrace` / GDB -- initial debugging attempts (revealed anti-debug)
- Ghidra -- static analysis of anti-debug functions
- `gcc` -- compile LD_PRELOAD bypass libraries
- Radare2 (`r2`) -- binary patching to NOP out anti-debug calls
- `LD_PRELOAD` -- runtime function hooking

## Lessons Learned

- **Anti-debug is delay, not prevention**. Every anti-debug technique has a known bypass. They exist to slow down analysts, not stop them.
- **`LD_PRELOAD` is the Swiss Army knife** for bypassing anti-debug on Linux. It lets you replace any dynamically linked function with your own implementation.
- **Patching out anti-debug calls is often the fastest approach** in CTFs. Just NOP the `CALL` instructions and move on to the real challenge.
- **Always check for anti-debug early**. If a binary behaves differently under GDB/ltrace, analyze `main` (and any init functions) in Ghidra first before trying to debug.
- **Multiple anti-debug layers are common**. Don't stop after bypassing the first one -- there are often several in sequence.
- **GDB's `catch syscall` and `commands` features** let you automate bypass at the debugger level without modifying the binary.
