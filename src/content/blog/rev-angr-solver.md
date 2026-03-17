---
title: "Rev - Solving with angr"
description: "Using angr's symbolic execution engine to automatically solve a multi-check crackme that would be tedious to reverse manually."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                            |
|------------|----------------------------------|
| Category   | Reverse Engineering              |
| Difficulty | Medium                           |
| Points     | 300                              |
| Flag       | `zemi{4ngr_s0lv3s_1t_4ll}`       |

## Challenge Files

Download the challenge files to get started:

- [angrme.c](/Website/challenges/rev-angr-solver/angrme.c)
- [flag.txt](/Website/challenges/rev-angr-solver/flag.txt)
- [Makefile](/Website/challenges/rev-angr-solver/Makefile)

## Overview

Some crackmes have so many checks, transformations, and branches that reversing them manually would take hours. That's where **angr** comes in -- a Python framework for symbolic execution that can explore all possible program paths and find inputs that reach a desired state. In this writeup, we use angr to automatically solve a binary with complex, layered input validation. All analysis is done locally.

## What is Symbolic Execution?

Instead of running a program with a concrete input like `"hello"`, symbolic execution runs it with a **symbolic variable** -- a placeholder that can be *any* value. As the program encounters branches (like `if (input[0] == 'z')`), the engine **forks** and explores both paths, building up a set of constraints on the symbolic variable. When a desired state is reached, a constraint solver (like Z3) finds a concrete value that satisfies all accumulated constraints.

```
Concrete execution:   input = "hello" -> one path -> one result
Symbolic execution:   input = ??? -> all paths explored -> constraints solved
```

## Initial Recon

We get a binary called `multilayer`:

```bash
file multilayer
```

```
multilayer: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

```bash
./multilayer
```

```
Enter the flag: test
Stage 1 failed.
```

```bash
ltrace ./multilayer <<< "zemi{test}"
```

```
printf("Enter the flag: ")                       = 16
fgets("zemi{test}\n", 128, 0x7f...)              = 0x7ffd...
strlen("zemi{test}")                             = 10
puts("Stage 1 failed.")                          = 16
+++ exited (status 1) +++
```

No `strcmp` leak -- the validation is custom. Let's look at it in Ghidra.

## Static Analysis with Ghidra

The decompiled `main` function reveals a multi-stage validator:

```c
int main(void) {
    char input[128];

    printf("Enter the flag: ");
    fgets(input, 128, stdin);
    input[strcspn(input, "\n")] = 0;

    if (strlen(input) != 25) {
        puts("Stage 1 failed.");
        return 1;
    }

    if (!check_prefix(input)) {
        puts("Stage 2 failed.");
        return 1;
    }

    if (!check_stage3(input)) {
        puts("Stage 3 failed.");
        return 1;
    }

    if (!check_stage4(input)) {
        puts("Stage 4 failed.");
        return 1;
    }

    if (!check_stage5(input)) {
        puts("Stage 5 failed.");
        return 1;
    }

    puts("Correct! You found the flag!");
    return 0;
}
```

Looking at each check function, they perform complex operations:

```c
int check_prefix(char *s) {
    return (s[0] == 'z' && s[1] == 'e' && s[2] == 'm' &&
            s[3] == 'i' && s[4] == '{' && s[24] == '}');
}

int check_stage3(char *s) {
    // XOR chain validation
    return ((s[5] ^ 0x55) == 0x61) &&
           ((s[6] ^ s[5]) == 0x44) &&
           ((s[7] ^ s[6]) == 0x5e) &&
           ((s[8] ^ 0x33) == 0x05) &&
           ((s[9] ^ s[8]) == 0x67);
    // ... more constraints
}

int check_stage4(char *s) {
    // Arithmetic validation
    int sum = 0;
    for (int i = 10; i < 18; i++) {
        sum += s[i] * (i - 9);
    }
    return (sum == 5731) && ((s[10] + s[17]) == 0xd0) &&
           ((s[13] - s[14]) == -4);
    // ... more constraints
}

int check_stage5(char *s) {
    // Matrix-style check
    int vals[6];
    for (int i = 0; i < 6; i++) {
        vals[i] = s[18 + i];
    }
    return (vals[0] * 3 + vals[1] * 7 == 1024) &&
           (vals[2] - vals[3] == 21) &&
           (vals[4] + vals[5] == 0xdd) &&
           (vals[0] ^ vals[5] == 0x42);
    // ... more constraints
}
```

We *could* solve these constraints by hand, but there are dozens of interdependent checks. This is exactly what angr excels at.

## Setting Up angr

Install angr if you haven't:

```bash
pip install angr
```

### Finding Key Addresses

We need two things from Ghidra:
1. **Find address**: where the program prints the success message
2. **Avoid addresses**: where the program prints failure messages

From the disassembly:

```asm
; Success path
  004013a0  LEA      RDI, [s_Correct!_You_found_the_flag!]
  004013a7  CALL     puts                               ; <-- FIND this address

; Failure paths (there are multiple)
  00401280  LEA      RDI, [s_Stage_1_failed.]
  00401287  CALL     puts                               ; <-- AVOID

  004012a0  LEA      RDI, [s_Stage_2_failed.]
  004012a7  CALL     puts                               ; <-- AVOID

  004012c0  LEA      RDI, [s_Stage_3_failed.]
  004012c7  CALL     puts                               ; <-- AVOID

  00401300  LEA      RDI, [s_Stage_4_failed.]
  00401307  CALL     puts                               ; <-- AVOID

  00401340  LEA      RDI, [s_Stage_5_failed.]
  00401347  CALL     puts                               ; <-- AVOID
```

## The angr Solve Script

```python
#!/usr/bin/env python3
"""angr solver for the multilayer crackme."""

import angr
import claripy
import sys

def solve():
    # Load the binary
    proj = angr.Project("./multilayer", auto_load_libs=False)

    # Create a symbolic variable for the input
    # We know the flag is 25 characters + newline from fgets
    flag_len = 25
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

    # Create the initial state at program entry
    state = proj.factory.full_init_state(
        args=["./multilayer"],
        stdin=flag,
        add_options=angr.options.unicorn,  # Use unicorn engine for speed
    )

    # Add constraints for printable ASCII characters
    for i in range(flag_len):
        state.solver.add(flag_chars[i] >= 0x20)
        state.solver.add(flag_chars[i] <= 0x7e)

    # We know the flag format, so constrain the prefix
    state.solver.add(flag_chars[0] == ord('z'))
    state.solver.add(flag_chars[1] == ord('e'))
    state.solver.add(flag_chars[2] == ord('m'))
    state.solver.add(flag_chars[3] == ord('i'))
    state.solver.add(flag_chars[4] == ord('{'))
    state.solver.add(flag_chars[24] == ord('}'))

    # Create the simulation manager
    simgr = proj.factory.simulation_manager(state)

    # Define find and avoid addresses
    find_addr = 0x004013a0    # "Correct! You found the flag!"
    avoid_addrs = [
        0x00401280,           # "Stage 1 failed."
        0x004012a0,           # "Stage 2 failed."
        0x004012c0,           # "Stage 3 failed."
        0x00401300,           # "Stage 4 failed."
        0x00401340,           # "Stage 5 failed."
    ]

    # Explore!
    print("[*] Starting symbolic execution...")
    simgr.explore(find=find_addr, avoid=avoid_addrs)

    # Check results
    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        flag_str = solution.decode("latin-1").strip()
        print(f"[+] Flag found: {flag_str}")
        return flag_str
    else:
        print("[-] No solution found!")
        print(f"    Active: {len(simgr.active)}")
        print(f"    Deadended: {len(simgr.deadended)}")
        print(f"    Avoided: {len(simgr.avoid)}")
        return None

if __name__ == "__main__":
    solve()
```

### Running the Solver

```bash
python3 solve.py
```

```
[*] Starting symbolic execution...
WARNING | ... | Unsupported syscall ...
[+] Flag found: zemi{4ngr_s0lv3s_1t_4ll}
```

It typically solves in 10-60 seconds depending on your machine.

### Verifying

```bash
./multilayer
```

```
Enter the flag: zemi{4ngr_s0lv3s_1t_4ll}
Correct! You found the flag!
```

## Understanding the Script

Let's break down each part:

### 1. Project Loading

```python
proj = angr.Project("./multilayer", auto_load_libs=False)
```

`auto_load_libs=False` tells angr not to load shared libraries (libc, etc.) -- it uses its own simplified models (SimProcedures) for common functions like `printf`, `strlen`, and `strcmp`. This dramatically speeds things up.

### 2. Symbolic Input with claripy

```python
flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])
```

- `claripy.BVS("name", 8)` creates an 8-bit **symbolic** bitvector (one character)
- `claripy.BVV(b"\n")` creates a **concrete** bitvector (the newline from fgets)
- We create one symbolic variable per character so we can add per-character constraints

### 3. State Initialization

```python
state = proj.factory.full_init_state(
    args=["./multilayer"],
    stdin=flag,
    add_options=angr.options.unicorn,
)
```

`full_init_state` creates a state that starts from the program's entry point (before `main`). The `stdin` parameter pre-loads our symbolic input so `fgets` reads from it.

### 4. Constraining the Input

```python
state.solver.add(flag_chars[i] >= 0x20)
state.solver.add(flag_chars[i] <= 0x7e)
```

Adding constraints **before** exploration prunes impossible paths early. If we know the flag is printable ASCII and starts with `zemi{`, telling angr this upfront saves enormous time.

### 5. Exploration

```python
simgr.explore(find=find_addr, avoid=avoid_addrs)
```

angr explores paths through the program. When it reaches a `find` address, it stops and reports success. When it reaches an `avoid` address, it discards that path. This guided exploration is what makes angr practical.

## Alternative: Using find/avoid with strings

If you don't want to look up addresses, you can match on output:

```python
def is_success(state):
    stdout = state.posix.dumps(sys.stdout.fileno())
    return b"Correct" in stdout

def is_failure(state):
    stdout = state.posix.dumps(sys.stdout.fileno())
    return b"failed" in stdout

simgr.explore(find=is_success, avoid=is_failure)
```

This is slower (angr must check output at every step) but requires no address hunting.

## When angr Works Well vs When It Doesn't

| Works Well | Struggles With |
|------------|----------------|
| Constraint-based checks (XOR, arithmetic, comparisons) | Complex loops with many iterations |
| Small-to-medium binaries | Binaries with heavy I/O or threading |
| Path-based validation (reach address X) | Crypto implementations (AES, SHA) |
| Known flag format to constrain | Self-modifying code |
| Statically linked or simple dynamic linking | Obfuscated control flow (VM-based protections) |

**Tips for making angr work better:**
- Add as many constraints as possible upfront (flag format, character ranges, known bytes)
- Use `auto_load_libs=False` unless you need real library behavior
- Use `angr.options.unicorn` for speed on concrete operations
- Set `avoid` addresses aggressively to prune bad paths early
- If it's too slow, try hooking expensive functions with `proj.hook()`

## Tools Used

- `file` -- identify binary type
- `ltrace` -- understand validation approach
- Ghidra -- find success/failure addresses and understand check structure
- angr -- symbolic execution to solve the constraint system
- claripy -- create symbolic variables and add constraints
- Python -- orchestrate the solve script

## Lessons Learned

- **Symbolic execution automates constraint solving**. When a binary checks your input through a series of mathematical constraints, angr can solve all of them simultaneously.
- **The core angr pattern is simple**: load binary, create symbolic input, set find/avoid addresses, explore, extract solution.
- **Constraining your input is critical for performance**. The more you tell angr about what the input looks like (printable, known prefix, exact length), the faster it converges.
- **angr is not magic**. It struggles with crypto, complex loops, and very large binaries. For those, you'll need manual analysis combined with targeted symbolic execution.
- **Use `auto_load_libs=False`** in almost all CTF scenarios. angr's SimProcedures handle common libc functions well enough, and loading real libraries massively increases complexity.
- **angr pairs well with Ghidra**. Use Ghidra to understand the binary's structure and identify key addresses, then let angr handle the tedious constraint solving.
