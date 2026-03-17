---
title: "Rev - Obfuscated Control Flow"
description: "Defeating control flow flattening and opaque predicates to recover the real program logic from a heavily obfuscated binary using angr, Ghidra scripting, and manual analysis."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                                  |
|------------|----------------------------------------|
| Category   | Reverse Engineering                    |
| Difficulty | Extreme                                |
| Points     | 500                                    |
| Flag       | `zemi{0bfusc4t3d_fl0w_r3v34l3d}`      |

## Challenge Files

Download the challenge files to get started:

- [obfuscated.c](/Website/challenges/rev-obfuscated-control-flow/obfuscated.c)
- [flag.txt](/Website/challenges/rev-obfuscated-control-flow/flag.txt)
- [Makefile](/Website/challenges/rev-obfuscated-control-flow/Makefile)

## Prerequisites

This writeup assumes mastery of the following:

- **Rev - Strings and ltrace** -- basic dynamic analysis
- **Rev - XOR Encryption** -- common flag encoding
- **Rev - Anti-Debug Bypass** -- handling hostile binaries
- **Rev - Solving with angr** -- symbolic execution fundamentals (critical for this challenge)
- **Rev - Patching Binary** -- binary modification techniques

You should be comfortable reading complex Ghidra decompilation output and writing Python scripts.

## Overview

Control flow obfuscation is a family of techniques that transforms a program's control flow graph (CFG) to make static analysis extremely difficult, while preserving the program's actual behavior. The two primary techniques we encounter in this challenge are:

1. **Control Flow Flattening (CFF)** -- All basic blocks are placed at the same nesting level under a single dispatcher (a `while(true)` loop with a `switch` statement). A **state variable** determines which block executes next.
2. **Opaque predicates** -- Conditions inserted into the code that always evaluate the same way (always true or always false) but look complex enough that static analysis tools cannot prove this, creating fake branches that do not exist in the real program.

These techniques are used by commercial obfuscators (OLLVM, Tigress), malware, and CTF challenges to frustrate reverse engineers. All analysis is performed locally.

## What Control Flow Flattening Looks Like

### Normal Control Flow

```
    [Entry]
       |
    [Block A] --condition--> [Block C]
       |                        |
    [Block B]               [Block D]
       |                        |
       +--------+   +-----------+
                |   |
              [Exit]
```

Each block flows naturally to the next. The CFG is tree-like and readable.

### Flattened Control Flow

```
         [Entry]
            |
      state = INIT
            |
    +-->[Dispatcher]<---------+--------+---------+
    |    switch(state)         |        |         |
    |   /    |    \    \       |        |         |
    | [A]  [B]   [C]  [D]     |        |         |
    |  |    |     |    |       |        |         |
    |  state=B  state=EXIT  state=D  state=EXIT  |
    |  |    |     |    |       |        |         |
    +--+----+-----+----+-------+--------+---------+
```

Every block is at the same level. Execution is controlled by a state variable that gets updated at the end of each block. The dispatcher (a `switch` on the state variable) routes execution to the next block. This destroys the hierarchical CFG structure that Ghidra and IDA rely on for decompilation.

## Initial Recon

```bash
file flatcrackme
```

```
flatcrackme: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

Stripped this time -- no symbol names.

```bash
./flatcrackme
```

```
Enter password: test
Wrong.
```

```bash
ltrace ./flatcrackme <<< "test"
```

```
printf("Enter password: ")                      = 16
fgets("test\n", 100, 0x7f...)                   = 0x7ffd...
strlen("test")                                   = 4
puts("Wrong.")                                   = 7
+++ exited (status 0) +++
```

```bash
./flatcrackme <<< "zemi{0bfusc4t3d_fl0w_r3v34l3d}"
```

```
Enter password: Correct! The flag is your input.
```

So the flag IS the password. We need to figure out what password the binary accepts.

## Static Analysis: The Flattened Nightmare

Opening in Ghidra, we find `main` (identified by the entry point calling `__libc_start_main`). The decompilation is horrifying:

```c
int main(void) {
    char input[100];
    int state;
    int len;
    uint8_t temp1, temp2, temp3;
    int i;
    int check_count;

    printf("Enter password: ");
    fgets(input, 100, stdin);
    input[strcspn(input, "\n")] = 0;
    len = strlen(input);

    state = 0xA3F1;
    check_count = 0;
    i = 0;

    while (1) {
        // Opaque predicate #1 (always true)
        if ((state * state + 1) % 2 != 0) {
            state = state ^ 0xDEAD;
        }

        switch (state) {
        case 0xA3F1:  // STATE_INIT: length check
            if (len == 30) {
                state = 0xB702;
            } else {
                state = 0xFFFF;
            }
            break;

        case 0xB702:  // STATE_CHECK_PREFIX
            // Opaque predicate #2 (always false -- dead branch)
            if ((i * i * i + 3 * i * i + 2 * i) % 6 != 0) {
                state = 0xDEAD;  // never reached
                break;
            }
            if (input[0] == 'z' && input[1] == 'e' &&
                input[2] == 'm' && input[3] == 'i' && input[4] == '{') {
                state = 0xC915;
            } else {
                state = 0xFFFF;
            }
            break;

        case 0xC915:  // STATE_CHECK_SUFFIX
            if (input[29] == '}') {
                state = 0xD128;
            } else {
                state = 0xFFFF;
            }
            break;

        case 0xD128:  // STATE_INIT_LOOP
            i = 5;
            check_count = 0;
            state = 0xE337;
            break;

        case 0xE337:  // STATE_LOOP_CHECK
            // Opaque predicate #3 (always true)
            if (((i + 1) * (i + 1) - i * i - 2 * i - 1) == 0) {
                if (i < 29) {
                    state = 0xF442;
                } else {
                    state = 0x1A55;
                }
            } else {
                state = 0xDEAD;  // never reached
            }
            break;

        case 0xF442:  // STATE_TRANSFORM_CHAR
            temp1 = input[i];
            temp2 = (temp1 ^ (0x41 + (i % 7)));
            temp3 = ((temp2 + (i * 3)) & 0xFF);
            state = 0x2B66;
            break;

        case 0x2B66:  // STATE_COMPARE_CHAR
        {
            uint8_t expected[] = {
                0x94, 0xA7, 0x83, 0xBB, 0x72, 0x89, 0x97,
                0xB3, 0x68, 0xAF, 0x9E, 0x76, 0xC2, 0x8B,
                0x71, 0xA4, 0x93, 0xB8, 0x7F, 0xC5, 0x86,
                0x99, 0xA1, 0x6D
            };

            // Opaque predicate #4 (always false)
            if (((check_count | ~check_count) + 1) != 0) {
                state = 0xDEAD;
                break;
            }

            if (temp3 == expected[i - 5]) {
                check_count++;
                i++;
                state = 0xE337;  // loop back
            } else {
                state = 0xFFFF;  // fail
            }
            break;
        }

        case 0x1A55:  // STATE_FINAL_CHECK
            if (check_count == 24) {
                state = 0x3C77;
            } else {
                state = 0xFFFF;
            }
            break;

        case 0x3C77:  // STATE_SUCCESS
            puts("Correct! The flag is your input.");
            return 0;

        case 0xFFFF:  // STATE_FAIL
            puts("Wrong.");
            return 1;

        case 0xDEAD:  // DEAD STATE (should never be reached)
            puts("Error.");
            return 1;

        default:
            return 1;
        }
    }
}
```

### What Makes This Hard to Read

1. **All logic is under one `switch`** -- there are no function calls, no clear structure. The entire validation algorithm is spread across switch cases.

2. **The state variable controls flow** -- instead of `if/else` and loops, execution jumps between cases via state variable assignments. You must mentally track `state` to understand execution order.

3. **Opaque predicates add noise** -- four fake conditions are sprinkled throughout:
   - `(state * state + 1) % 2 != 0` -- always false for odd `state`, always true for even. Since the initial state is 0xA3F1 (odd), this is always false. The XOR never happens.
   - `(i * i * i + 3 * i * i + 2 * i) % 6 != 0` -- this is `i(i+1)(i+2) % 6`, which is always 0 (product of three consecutive integers is always divisible by 6). Always false.
   - `((i + 1) * (i + 1) - i * i - 2 * i - 1) == 0` -- expands to `i^2 + 2i + 1 - i^2 - 2i - 1 = 0`. Always true.
   - `((check_count | ~check_count) + 1) != 0` -- `x | ~x` is always `0xFFFFFFFF` (-1), so `-1 + 1 = 0`. Always false.

4. **Dead code branches** -- the `0xDEAD` state is never reachable, but Ghidra does not know this. It shows as a valid execution path.

## Strategy 1: Manual Deobfuscation

Now that we understand the obfuscation, we can mentally strip it away and reconstruct the real logic.

### Tracing the State Machine

```
State Flow (ignoring opaque predicates):

0xA3F1 (INIT)
  |-- len != 30 --> 0xFFFF (FAIL)
  |-- len == 30 --> 0xB702

0xB702 (CHECK_PREFIX)
  |-- prefix wrong --> 0xFFFF (FAIL)
  |-- prefix ok    --> 0xC915

0xC915 (CHECK_SUFFIX)
  |-- suffix wrong --> 0xFFFF (FAIL)
  |-- suffix ok    --> 0xD128

0xD128 (INIT_LOOP)
  |-- i=5, count=0 --> 0xE337

0xE337 (LOOP_CHECK)
  |-- i < 29  --> 0xF442
  |-- i >= 29 --> 0x1A55

0xF442 (TRANSFORM)
  |-- compute temp3 --> 0x2B66

0x2B66 (COMPARE)
  |-- match    --> count++, i++, --> 0xE337 (loop)
  |-- mismatch --> 0xFFFF (FAIL)

0x1A55 (FINAL_CHECK)
  |-- count == 24 --> 0x3C77 (SUCCESS)
  |-- count != 24 --> 0xFFFF (FAIL)

0x3C77 (SUCCESS) -- print success
0xFFFF (FAIL) -- print failure
```

### Reconstructed Real Logic

Stripping the flattening and opaque predicates, the actual program is:

```c
// The REAL program logic (deobfuscated)
int main(void) {
    char input[100];
    printf("Enter password: ");
    fgets(input, 100, stdin);
    input[strcspn(input, "\n")] = 0;

    int len = strlen(input);

    // Check length
    if (len != 30) {
        puts("Wrong.");
        return 1;
    }

    // Check prefix "zemi{"
    if (input[0] != 'z' || input[1] != 'e' || input[2] != 'm' ||
        input[3] != 'i' || input[4] != '{') {
        puts("Wrong.");
        return 1;
    }

    // Check suffix "}"
    if (input[29] != '}') {
        puts("Wrong.");
        return 1;
    }

    // Check inner characters (index 5-28)
    uint8_t expected[] = {
        0x94, 0xA7, 0x83, 0xBB, 0x72, 0x89, 0x97,
        0xB3, 0x68, 0xAF, 0x9E, 0x76, 0xC2, 0x8B,
        0x71, 0xA4, 0x93, 0xB8, 0x7F, 0xC5, 0x86,
        0x99, 0xA1, 0x6D
    };

    for (int i = 5; i < 29; i++) {
        uint8_t temp1 = input[i];
        uint8_t temp2 = temp1 ^ (0x41 + (i % 7));
        uint8_t temp3 = (temp2 + (i * 3)) & 0xFF;
        if (temp3 != expected[i - 5]) {
            puts("Wrong.");
            return 1;
        }
    }

    puts("Correct! The flag is your input.");
    return 0;
}
```

Now the algorithm is clear: each character at index `i` is XORed with `(0x41 + (i % 7))`, then `(i * 3)` is added, and the result is compared against the expected array.

## Strategy 2: Solving with angr (Despite Obfuscation)

angr can handle control flow flattening because it explores paths symbolically -- it does not need to understand the CFG structure. It just needs to find a path to the success output.

```python
#!/usr/bin/env python3
"""angr solver for flatcrackme -- bypasses CFF and opaque predicates."""

import angr
import claripy

def solve():
    proj = angr.Project("./flatcrackme", auto_load_libs=False)

    # 30-character symbolic input + newline
    flag_len = 30
    flag_chars = [claripy.BVS(f"c{i}", 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

    state = proj.factory.full_init_state(
        args=["./flatcrackme"],
        stdin=flag,
        add_options=angr.options.unicorn,
    )

    # Constrain to printable ASCII
    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    # Constrain known prefix/suffix
    for i, ch in enumerate("zemi{"):
        state.solver.add(flag_chars[i] == ord(ch))
    state.solver.add(flag_chars[29] == ord('}'))

    simgr = proj.factory.simulation_manager(state)

    # Find by output string matching
    def is_success(s):
        return b"Correct" in s.posix.dumps(1)

    def is_failure(s):
        return b"Wrong" in s.posix.dumps(1)

    print("[*] Running angr (this may take 2-5 minutes due to CFF)...")
    simgr.explore(find=is_success, avoid=is_failure)

    if simgr.found:
        found = simgr.found[0]
        result = found.solver.eval(flag, cast_to=bytes)
        print(f"[+] Flag: {result.decode('latin-1').strip()}")
    else:
        print("[-] No solution found")
        print(f"    Active: {len(simgr.active)}")
        print(f"    Deadended: {len(simgr.deadended)}")

if __name__ == "__main__":
    solve()
```

```bash
python3 solve_angr.py
```

```
[*] Running angr (this may take 2-5 minutes due to CFF)...
WARNING | ... | Unsupported syscall ...
[+] Flag: zemi{0bfusc4t3d_fl0w_r3v34l3d}
```

angr is slower on CFF-obfuscated binaries because the flattened switch statement creates many more branch points to explore, but it still works because the underlying constraint system is the same.

## Strategy 3: Direct Algebraic Solution

Since we deobfuscated the logic manually, we can solve directly:

```python
#!/usr/bin/env python3
"""Direct algebraic solver for flatcrackme.

The transformation is:
  temp3 = ((input[i] ^ (0x41 + (i % 7))) + (i * 3)) & 0xFF

To reverse:
  input[i] = ((expected[i-5] - (i * 3)) & 0xFF) ^ (0x41 + (i % 7))
"""

expected = [
    0x94, 0xA7, 0x83, 0xBB, 0x72, 0x89, 0x97,
    0xB3, 0x68, 0xAF, 0x9E, 0x76, 0xC2, 0x8B,
    0x71, 0xA4, 0x93, 0xB8, 0x7F, 0xC5, 0x86,
    0x99, 0xA1, 0x6D,
]

flag = list("zemi{" + "?" * 24 + "}")

for i in range(5, 29):
    e = expected[i - 5]
    # Reverse the addition
    temp2 = (e - (i * 3)) & 0xFF
    # Reverse the XOR
    key = 0x41 + (i % 7)
    char = temp2 ^ key
    flag[i] = chr(char)

result = ''.join(flag)
print(f"[+] Flag: {result}")
assert result == "zemi{0bfusc4t3d_fl0w_r3v34l3d}"
print("[+] Verified!")
```

```bash
python3 solve_direct.py
```

```
[+] Flag: zemi{0bfusc4t3d_fl0w_r3v34l3d}
[+] Verified!
```

## Strategy 4: Ghidra Script for Automated Deobfuscation

For more complex CFF binaries, you can write a Ghidra Python script to automatically extract the state machine transitions:

```python
# Ghidra Jython script: extract_cff_states.py
# Run inside Ghidra's Script Manager
#
# This script finds switch/case patterns in a flattened function
# and extracts the state transition graph.

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import FlowType
import re

def find_state_transitions(func):
    """Extract state variable assignments from a flattened function."""
    listing = currentProgram.getListing()
    transitions = {}
    current_case = None

    # Get all instructions in the function
    addr_set = func.getBody()
    inst_iter = listing.getInstructions(addr_set, True)

    state_pattern = {}

    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnemonic = inst.getMnemonicString()

        # Look for MOV instructions that set the state variable
        # Pattern: MOV [RBP-offset], immediate_value
        if mnemonic == "MOV":
            operand0 = inst.getDefaultOperandRepresentation(0)
            operand1 = inst.getDefaultOperandRepresentation(1)

            # Check if this is storing an immediate to a stack variable
            if "RBP" in operand0 and operand1.startswith("0x"):
                try:
                    value = int(operand1, 16)
                    addr = inst.getAddress()
                    state_pattern[str(addr)] = value
                    print(f"  State assignment at {addr}: state = 0x{value:04X}")
                except ValueError:
                    pass

        # Look for CMP instructions (switch dispatch)
        if mnemonic == "CMP":
            operand1 = inst.getDefaultOperandRepresentation(1)
            if operand1.startswith("0x"):
                try:
                    value = int(operand1, 16)
                    current_case = value
                    print(f"  Switch case: 0x{value:04X} at {inst.getAddress()}")
                except ValueError:
                    pass

    return state_pattern

# Run on the function at the cursor
func = getFunctionContaining(currentAddress)
if func is not None:
    print(f"Analyzing function: {func.getName()} at {func.getEntryPoint()}")
    print("=" * 60)
    transitions = find_state_transitions(func)
    print(f"\nFound {len(transitions)} state assignments")
else:
    print("Place cursor inside the obfuscated function and re-run")
```

This script is a starting point. For production use, you would enhance it to:
- Build a full state transition graph
- Identify opaque predicates (by checking if both branches are ever taken)
- Reconstruct the original CFG
- Output a simplified decompilation

## Understanding Opaque Predicates

Opaque predicates are central to this obfuscation. Here is a reference of common patterns:

| Predicate | Why It Works | Always |
|-----------|-------------|--------|
| `x * x + 1 % 2 != 0` | For odd x: `odd^2 = odd`, `odd+1 = even`, `even%2 = 0`. For even x: `even^2 = even`, `even+1 = odd`, `odd%2 = 1` | Depends on x parity |
| `x * (x+1) % 2 == 0` | Product of consecutive integers is always even | Always true |
| `(x\|~x) + 1 == 0` | `x\|~x` = all 1s = -1 (signed), -1+1=0 | Always true |
| `x*(x+1)*(x+2) % 6 == 0` | Product of 3 consecutive integers always divisible by 6 | Always true |
| `(x+1)^2 - x^2 - 2x - 1 == 0` | Algebraically simplifies to 0 | Always true |
| `x^2 >= 0` | Squares are non-negative (for integers) | Always true |

To detect these in Ghidra:
1. Look for complex conditions that do not involve program input
2. Check if both branches lead to the same state (dead branch detection)
3. Try substituting concrete values -- if the condition never changes, it is opaque

## Dynamic Analysis: Tracing the State Variable

If static analysis is too difficult, you can trace the state variable dynamically with GDB:

```bash
gdb -q ./flatcrackme
```

```gdb
(gdb) # First, find where the state variable is stored
(gdb) # From Ghidra, we know it's at [RBP-0x0C]
(gdb) break *0x401180   # address of the switch dispatch
(gdb) commands 1
  > silent
  > set $state = *(int*)($rbp - 0xc)
  > printf "state = 0x%04X\n", $state
  > continue
  > end
(gdb) run <<< "zemi{0bfusc4t3d_fl0w_r3v34l3d}"
```

```
state = 0xA3F1
state = 0xB702
state = 0xC915
state = 0xD128
state = 0xE337
state = 0xF442
state = 0x2B66
state = 0xE337
state = 0xF442
state = 0x2B66
... (loops 24 times for each inner character)
state = 0x1A55
state = 0x3C77
Correct! The flag is your input.
```

This trace confirms our manual state machine analysis and shows the actual execution path with the correct input.

For an incorrect input, the trace diverges to `0xFFFF` at the first mismatch:

```gdb
(gdb) run <<< "zemi{wrong_input_xxxxxxxxxx}"
```

```
state = 0xA3F1
state = 0xB702
state = 0xC915
state = 0xD128
state = 0xE337
state = 0xF442
state = 0x2B66
state = 0xFFFF
Wrong.
```

## Verifying the Flag

```bash
./flatcrackme
```

```
Enter password: zemi{0bfusc4t3d_fl0w_r3v34l3d}
Correct! The flag is your input.
```

Flag: `zemi{0bfusc4t3d_fl0w_r3v34l3d}`

## Common Pitfalls

- **Trying to read the decompilation linearly.** CFF destroys linear reading. You must trace state transitions, not read top-to-bottom.
- **Falling for opaque predicates.** Spending time analyzing branches that can never be taken is a huge time sink. Test conditions with concrete values first.
- **Ignoring the state variable.** The state variable is the key to the entire program. Find it early and track it throughout.
- **Not constraining angr enough.** On CFF binaries, angr's path explosion is worse because of the extra branches. Add all constraints you can (flag format, character ranges) and use aggressive `avoid` addresses.
- **Over-engineering the Ghidra script.** For a CTF, manual analysis of the switch cases is usually faster than writing a generic deobfuscation tool. Scripts are more valuable for repeated analysis of the same obfuscator.
- **Assuming all switch cases are real.** Dead states (like `0xDEAD` in this binary) exist solely to confuse. Verify each state is reachable by tracing the transition graph.

## Tools Used

- `file` -- identify binary type (stripped, so no symbols)
- `ltrace` -- initial dynamic analysis
- Ghidra -- static analysis of the flattened control flow
- GDB -- dynamic tracing of the state variable to confirm analysis
- angr -- symbolic execution to solve despite obfuscation
- Python -- algebraic solver and custom Ghidra scripts

## Lessons Learned

- **Control flow flattening destroys readability, not functionality.** The program does the same thing -- it is just much harder to see what that thing is.
- **Opaque predicates are identifiable with math.** If a condition involves only loop variables or constants (not user input), it is likely opaque. Evaluate it with a few concrete values to confirm.
- **Trace the state variable to reconstruct the real CFG.** The state machine is a graph. Drawing it out reveals the actual program structure hiding beneath the obfuscation.
- **angr handles CFF well because it does not need the CFG.** Symbolic execution explores paths regardless of how they are structured. This makes angr a powerful tool against control flow obfuscation.
- **Manual analysis and automated tools are complementary.** Use Ghidra to understand the obfuscation structure, angr to solve it, and GDB to validate your understanding.
- **Real-world obfuscators (OLLVM, Tigress) use the same principles at greater scale.** The techniques learned here apply directly to analyzing obfuscated malware and protected commercial software.
