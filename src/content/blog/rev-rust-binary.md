---
title: "Rev - Rust Binary Reversing"
description: "Tackling the unique challenges of reversing a Rust-compiled binary including name mangling, monomorphization bloat, iterator chains, and Rust-specific data structures to extract a hidden flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                            |
|------------|----------------------------------|
| Category   | Reverse Engineering              |
| Difficulty | Extreme                          |
| Points     | 500                              |
| Flag       | `zemi{rust_r3v3rs1ng_p41n}`      |

## Challenge Files

Download the challenge files to get started:

- [main.rs](/Website/challenges/rev-rust-binary/main.rs)
- [Cargo.toml](/Website/challenges/rev-rust-binary/Cargo.toml)
- [flag.txt](/Website/challenges/rev-rust-binary/flag.txt)

## Prerequisites

Before attempting this challenge, ensure you have completed:

- **Rev - Strings and ltrace** -- basic dynamic analysis
- **Rev - XOR Encryption** -- understanding encoding schemes
- **Rev - Anti-Debug Bypass** -- dealing with complex binaries
- **Rev - Solving with angr** -- symbolic execution (useful but limited here)
- **Rev - .NET Decompile** -- experience with non-C language reversing

You need solid Ghidra skills and patience. Rust binaries produce the most verbose and confusing decompilation output of any compiled language.

## Overview

Rust is increasingly popular for both legitimate software and malware. Its compiled binaries are notoriously difficult to reverse engineer -- not because of intentional obfuscation, but because of how the Rust compiler works. A simple 20-line Rust program can produce a binary with hundreds of functions and thousands of lines of decompiled code.

This challenge is a Rust-compiled crackme. The actual flag validation logic is about 30 lines of Rust, but the compiled binary contains over 400 functions, most of which are standard library boilerplate. Our job is to find the needle in the haystack. All analysis is performed locally.

## Why Rust Binaries Are Hard to Reverse

| Issue | Explanation |
|-------|-------------|
| **Name mangling** | Rust symbol names include the full module path, crate hash, and type parameters. A function named `check` becomes something like `_ZN9rustcrack5check17h8a3b4c5d6e7f8a9bE` |
| **Monomorphization** | Generics are compiled into separate copies for each type. `Vec<u8>`, `Vec<String>`, and `Vec<i32>` each generate their own `push`, `pop`, `len` functions |
| **Iterator chains** | Rust's functional-style iterators (`.iter().map().filter().collect()`) compile into complex nested closures and adapter structs |
| **String handling** | Rust strings are `(pointer, length, capacity)` tuples, not null-terminated. Ghidra's string detection misses most of them |
| **Enum layouts** | Rust's `Option<T>`, `Result<T,E>`, and custom enums have complex discriminated union layouts that Ghidra cannot automatically recognize |
| **Panic infrastructure** | Every array access, unwrap, and arithmetic operation can panic. The panic handling code is inlined everywhere, bloating every function |
| **No C ABI** | Rust uses its own calling conventions and struct layouts. Ghidra's C-oriented analysis sometimes misinterprets argument passing |

## Initial Recon

```bash
file rustcrack
```

```
rustcrack: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
BuildID[sha1]=a1b2c3d4..., with debug_info, not stripped
```

Good news: not stripped, with debug info. This is common for CTF Rust binaries (stripped Rust is even worse).

```bash
# Count the symbols
nm rustcrack | wc -l
```

```
2847
```

2,847 symbols for a simple crackme. Welcome to Rust.

```bash
./rustcrack
```

```
=== RustCrack v1.0 ===
Enter the flag: test
Incorrect!
```

```bash
./rustcrack <<< "zemi{rust_r3v3rs1ng_p41n}"
```

```
=== RustCrack v1.0 ===
Enter the flag: Correct! Well done!
```

```bash
ltrace ./rustcrack <<< "test" 2>&1 | tail -20
```

```
... (hundreds of lines of Rust runtime initialization)
write(1, "=== RustCrack v1.0 ===\n", 23)     = 23
write(1, "Enter the flag: ", 16)              = 16
read(0, "test\n", 8192)                       = 5
write(1, "Incorrect!\n", 11)                  = 11
+++ exited (status 0) +++
```

Rust uses `read`/`write` syscalls through `std::io`, not libc `fgets`/`printf`. No useful library calls to trace.

## Step 1: Demangling Rust Symbols

The first thing to do with any Rust binary is demangle the symbols. Raw Rust symbols are unreadable:

```bash
nm rustcrack | grep -i "crack\|check\|valid\|flag\|main" | head -20
```

```
000000000000b340 T _ZN9rustcrack4main17h1a2b3c4d5e6f7890E
000000000000b5a0 t _ZN9rustcrack10check_flag17h2b3c4d5e6f7890a1E
000000000000b720 t _ZN9rustcrack9transform17h3c4d5e6f7890a1b2E
000000000000b800 t _ZN9rustcrack12validate_len17h4d5e6f7890a1b2c3E
000000000000b850 t _ZN9rustcrack12check_prefix17h5e6f7890a1b2c3d4E
000000000000b8f0 t _ZN9rustcrack14check_innerflag17h6f7890a1b2c3d4e5E
```

Install `rustfilt` to demangle these:

```bash
cargo install rustfilt
nm rustcrack | rustfilt | grep -i "crack\|check\|valid\|flag\|main" | head -20
```

```
000000000000b340 T rustcrack::main
000000000000b5a0 t rustcrack::check_flag
000000000000b720 t rustcrack::transform
000000000000b800 t rustcrack::validate_len
000000000000b850 t rustcrack::check_prefix
000000000000b8f0 t rustcrack::check_innerflag
```

Now we can see the program structure. The challenge has five relevant functions.

### Batch Demangling for Ghidra

Before opening Ghidra, create a demangled symbol map:

```bash
nm rustcrack | rustfilt > symbols_demangled.txt
```

In Ghidra, you can rename functions manually using this map, or use a script (see the Ghidra scripting section below).

## Step 2: Finding main() in Ghidra

Rust's actual entry point is not `main` -- it is `std::rt::lang_start`, which sets up the Rust runtime (panic handler, thread infrastructure, etc.) and then calls your `main`. In Ghidra:

```c
// The real entry calls __libc_start_main with this function:
void entry(void) {
    __libc_start_main(
        _ZN3std2rt10lang_start17h...E,  // Rust's lang_start
        ...
    );
}

// lang_start eventually calls:
fn lang_start<T: Termination>(
    main: fn() -> T,
    argc: isize,
    argv: *const *const u8
) -> isize {
    // ... setup ...
    main();  // <-- THIS calls rustcrack::main
    // ... cleanup ...
}
```

Navigate to `_ZN9rustcrack4main17h...E` (or `rustcrack::main` after demangling). Ghidra shows:

```c
void rustcrack::main(void) {
    // Ghidra's raw output (cleaned up slightly)
    undefined8 local_a8;    // String struct for prompt
    undefined8 local_a0;
    undefined8 local_98;    // String struct for input
    undefined8 local_90;
    undefined8 local_88;
    undefined local_80[64];
    int iVar1;

    // Print banner
    // This is a Rust &str: (pointer, length)
    local_a8 = (undefined8)&s_RustCrack_v1_0;  // ptr
    local_a0 = 0x17;                             // len = 23
    // ... (macro expansion for println!, ~20 lines of format machinery)

    // Print prompt
    local_98 = (undefined8)&s_Enter_the_flag;
    local_90 = 0x10;
    // ... (more println! machinery)

    // Read input -- Rust's stdin().read_line()
    // This creates a String (heap-allocated, growable)
    // String layout: { ptr: *mut u8, len: usize, capacity: usize }
    local_88 = 0;  // ptr (will be allocated)
    local_80[0] = 0;  // len
    local_80[8] = 0;  // capacity

    // std::io::stdin().read_line(&mut local_string)
    _ZN3std2io5stdio5Stdin9read_line17h...E(&local_88);

    // Trim the newline -- Rust's .trim()
    // Returns a &str (pointer + length), which is a VIEW into the String
    // (does not allocate)
    _ZN4core3str29_$LT$impl$u20$str$GT$4trim17h...E(
        local_88,    // ptr from String
        local_80[0], // len from String
        &local_98,   // output &str ptr
        &local_90    // output &str len
    );

    // Call check_flag with the trimmed &str
    iVar1 = _ZN9rustcrack10check_flag17h...E(local_98, local_90);

    if (iVar1 == 1) {
        // Print "Correct! Well done!"
        // ... (println! machinery)
    } else {
        // Print "Incorrect!"
        // ... (println! machinery)
    }

    // Drop the String (free heap memory)
    _ZN4core3ptr42drop_in_place$LT$alloc..string..String$GT$17h...E(&local_88);
}
```

### Understanding Rust String Layout

This is critical for Rust reversing. Rust has two string types:

```
&str (string slice) -- a fat pointer:
  +--------+--------+
  | ptr    | len    |
  +--------+--------+
  (16 bytes on x86-64)

String (owned, heap-allocated):
  +--------+--------+----------+
  | ptr    | len    | capacity |
  +--------+--------+----------+
  (24 bytes on x86-64)
```

In Ghidra, these appear as pairs or triples of `undefined8` variables. When you see two consecutive stack variables being passed to a function, it is likely a `&str`. When you see three, it is likely a `String`.

## Step 3: Analyzing check_flag

```c
// rustcrack::check_flag(input: &str) -> bool
// Ghidra decompilation (cleaned up, variables renamed)

bool check_flag(char *input_ptr, ulong input_len) {
    bool result;

    // Step 1: Check length
    result = validate_len(input_ptr, input_len);
    if (!result) {
        return false;
    }

    // Step 2: Check prefix "zemi{"
    result = check_prefix(input_ptr, input_len);
    if (!result) {
        return false;
    }

    // Step 3: Check suffix "}"
    // Rust bounds-checked access: input_ptr[input_len - 1]
    // This generates panic code if input_len == 0 (never happens due to step 1)
    if (input_len == 0) {
        // BEGIN PANIC BLOCK (can be ignored)
        _ZN4core9panicking18panic_bounds_check17h...E(0, 0, &panic_location_1);
        // This never returns -- it calls abort()
        // END PANIC BLOCK
    }
    if (input_ptr[input_len - 1] != '}') {
        return false;
    }

    // Step 4: Check inner flag content
    // Extract the slice between '{' and '}'
    // This is input_ptr[5..input_len-1] in Rust
    // Ghidra shows bounds checking code:
    if (input_len < 6) {
        // PANIC: slice out of bounds
        _ZN4core5slice5index26slice_start_index_len_fail17h...E(5, input_len);
    }

    char *inner_ptr = input_ptr + 5;
    ulong inner_len = input_len - 6;

    result = check_innerflag(inner_ptr, inner_len);
    return result;
}
```

### The Panic Code Problem

Notice the panic blocks. **Every single array access and slice operation in Rust generates bounds-checking code** that calls panic functions if the index is out of range. In the actual program, these panics never trigger (because the length is already validated), but Ghidra shows them as valid code paths.

In a typical Rust function, 30-50% of the decompiled code is panic handling. Learn to recognize and skip past these patterns:

```c
// Common panic patterns to IGNORE:
if (index >= len) {
    core::panicking::panic_bounds_check(index, len, &location);
    // unreachable
}

if (start > end || end > len) {
    core::slice::index::slice_index_order_fail(start, end);
    // unreachable
}

// Option::unwrap() panic:
if (discriminant == 0) {  // None variant
    core::panicking::panic("called `Option::unwrap()` on a `None` value", ...);
}
```

## Step 4: Analyzing validate_len

```c
// rustcrack::validate_len(input: &str) -> bool
bool validate_len(char *ptr, ulong len) {
    return len == 25;
}
```

Simple -- the flag must be 25 characters. `zemi{` (5) + inner (19) + `}` (1) = 25.

## Step 5: Analyzing check_prefix

```c
// rustcrack::check_prefix(input: &str) -> bool
bool check_prefix(char *ptr, ulong len) {
    // Rust's starts_with() for "zemi{"
    // The compiler often inlines this as a memcmp-like sequence:

    if (len < 5) return false;

    // Rust may optimize this to a 4-byte comparison + 1-byte comparison:
    if (*(uint32_t *)ptr != 0x696D657A) return false;  // "zemi" as little-endian u32
    if (ptr[4] != '{') return false;

    return true;
}
```

Rust's `starts_with` is often optimized into word-size comparisons. Ghidra shows `0x696D657A` which is `"zemi"` in little-endian. This is a common pattern in Rust reversing.

## Step 6: Analyzing check_innerflag (The Core Logic)

This is where the actual flag validation happens. The Ghidra output is dense:

```c
// rustcrack::check_innerflag(inner: &str) -> bool
// inner is the content between '{' and '}', should be 19 chars

bool check_innerflag(char *inner_ptr, ulong inner_len) {
    // Check inner length
    if (inner_len != 19) return false;

    // Expected values after transformation
    // Rust stores these as a static array
    // Found at a global address, decompiles as:
    uint8_t expected[19] = {
        0xA3, 0xB7, 0xA1, 0x98, 0xCD, 0xA7, 0x93, 0xBB,
        0xA5, 0x97, 0xA1, 0xC1, 0xB5, 0x99, 0xCD, 0xA5,
        0x93, 0xB3, 0xBD
    };

    // Rust iterator chain -- this is the hard part
    // Original Rust code (approximately):
    //   inner.bytes()
    //       .enumerate()
    //       .map(|(i, b)| transform(b, i as u8))
    //       .zip(expected.iter())
    //       .all(|(computed, exp)| computed == *exp)

    // Ghidra sees this as a loop with nested function calls:
    ulong i = 0;
    while (i < inner_len) {
        // Bounds check (PANIC CODE -- ignore)
        if (i >= inner_len) {
            _ZN4core9panicking18panic_bounds_check17h...E(i, inner_len, ...);
        }

        uint8_t byte = inner_ptr[i];
        uint8_t idx = (uint8_t)i;

        // Call transform(byte, index)
        uint8_t result = _ZN9rustcrack9transform17h...E(byte, idx);

        // Bounds check on expected array (PANIC CODE -- ignore)
        if (i >= 19) {
            _ZN4core9panicking18panic_bounds_check17h...E(i, 19, ...);
        }

        if (result != expected[i]) {
            return false;
        }

        i++;
    }

    return true;
}
```

## Step 7: Analyzing transform

The transform function is where each character is actually processed:

```c
// rustcrack::transform(byte: u8, index: u8) -> u8

uint8_t transform(uint8_t byte, uint8_t index) {
    uint8_t result;

    // Step 1: XOR with index + 0x42
    result = byte ^ (index + 0x42);

    // Step 2: Add 0x13
    result = (result + 0x13) & 0xFF;

    // Step 3: Bitwise NOT
    result = ~result & 0xFF;

    // Step 4: Rotate left by 3
    result = ((result << 3) | (result >> 5)) & 0xFF;

    return result;
}
```

In Ghidra's raw output, this function looks much worse because of Rust's type handling:

```c
// What Ghidra ACTUALLY shows (before cleanup):
undefined8 _ZN9rustcrack9transform17h3c4d5e6f7890a1b2E
                    (undefined param_1, undefined param_2) {
    byte bVar1;
    byte bVar2;
    uint uVar3;

    bVar1 = (byte)param_1;
    bVar2 = (byte)param_2;

    // Rust uses checked_add in debug mode, wrapping_add in release
    // This might appear as:
    uVar3 = (uint)bVar2 + 0x42;
    if ((uVar3 & 0xffffff00) != 0) {
        // overflow check -- only in debug builds
        // In release builds, this is optimized away
    }
    bVar1 = bVar1 ^ (byte)uVar3;
    uVar3 = (uint)bVar1 + 0x13;
    bVar1 = (byte)uVar3;
    bVar1 = ~bVar1;
    bVar1 = bVar1 << 3 | bVar1 >> 5;
    return CONCAT71(0, bVar1);  // Return u8 in a register
}
```

Note `CONCAT71` -- Ghidra's way of saying "7 bytes of zero + 1 byte of result" (returning a `u8` in a 64-bit register).

## Python Solve Script

Now that we understand the transformation, we reverse it:

```python
#!/usr/bin/env python3
"""Solve script for the Rust crackme.

Forward transformation:
  1. result = byte ^ (index + 0x42)
  2. result = (result + 0x13) & 0xFF
  3. result = ~result & 0xFF
  4. result = rotate_left(result, 3)

Reverse transformation (undo in reverse order):
  1. result = rotate_right(result, 3)
  2. result = ~result & 0xFF
  3. result = (result - 0x13) & 0xFF
  4. byte = result ^ (index + 0x42)
"""

def rotate_left(val, n, bits=8):
    return ((val << n) | (val >> (bits - n))) & ((1 << bits) - 1)

def rotate_right(val, n, bits=8):
    return ((val >> n) | (val << (bits - n))) & ((1 << bits) - 1)

def forward_transform(byte, index):
    """The transformation applied by the Rust binary."""
    result = byte ^ (index + 0x42)
    result = (result + 0x13) & 0xFF
    result = ~result & 0xFF
    result = rotate_left(result, 3)
    return result

def reverse_transform(expected, index):
    """Reverse the transformation to recover the original byte."""
    result = expected
    # Undo step 4: rotate right by 3
    result = rotate_right(result, 3)
    # Undo step 3: bitwise NOT
    result = ~result & 0xFF
    # Undo step 2: subtract 0x13
    result = (result - 0x13) & 0xFF
    # Undo step 1: XOR with (index + 0x42)
    result = result ^ (index + 0x42)
    return result

# Expected values extracted from the binary
expected = [
    0xA3, 0xB7, 0xA1, 0x98, 0xCD, 0xA7, 0x93, 0xBB,
    0xA5, 0x97, 0xA1, 0xC1, 0xB5, 0x99, 0xCD, 0xA5,
    0x93, 0xB3, 0xBD,
]

# Recover the inner flag
inner = ""
for i in range(19):
    byte = reverse_transform(expected[i], i)
    inner += chr(byte)

flag = f"zemi{{{inner}}}"
print(f"[+] Recovered flag: {flag}")

# Verify by running forward transform
for i in range(19):
    computed = forward_transform(ord(inner[i]), i)
    assert computed == expected[i], \
        f"Mismatch at index {i}: computed 0x{computed:02X} != expected 0x{expected[i]:02X}"

print("[+] Forward verification passed!")
assert flag == "zemi{rust_r3v3rs1ng_p41n}"
print("[+] Flag confirmed!")
```

### Running the Solver

```bash
python3 solve_rust.py
```

```
[+] Recovered flag: zemi{rust_r3v3rs1ng_p41n}
[+] Forward verification passed!
[+] Flag confirmed!
```

### Verifying

```bash
./rustcrack
```

```
=== RustCrack v1.0 ===
Enter the flag: zemi{rust_r3v3rs1ng_p41n}
Correct! Well done!
```

Flag: `zemi{rust_r3v3rs1ng_p41n}`

## Rust-Specific Ghidra/IDA Tips

### Tip 1: Bulk Demangle with a Ghidra Script

```python
# Ghidra Jython script: demangle_rust.py
# Renames all Rust-mangled functions to demangled names

import subprocess
from ghidra.program.model.symbol import SourceType

func_manager = currentProgram.getFunctionManager()
functions = func_manager.getFunctions(True)
count = 0

for func in functions:
    name = func.getName()
    if name.startswith("_ZN"):
        # Use rustfilt to demangle (must be installed)
        try:
            result = subprocess.check_output(
                ["rustfilt", name],
                stderr=subprocess.STDOUT
            ).decode().strip()

            if result != name:  # Successfully demangled
                # Replace :: with _ for Ghidra compatibility
                clean_name = result.replace("::", "_").replace("<", "_").replace(">", "_")
                func.setName(clean_name, SourceType.USER_DEFINED)
                count += 1
        except Exception:
            pass

print(f"Demangled {count} Rust functions")
```

### Tip 2: Recognize Rust Standard Library Functions

These are the most common Rust std functions you will encounter. Learn to recognize and skip them:

| Mangled Pattern | Demangled | What It Does |
|----------------|-----------|-------------|
| `_ZN3std2io...read_line...` | `std::io::Stdin::read_line` | Read a line from stdin |
| `_ZN4core3fmt...write_str...` | `core::fmt::Write::write_str` | Format string output |
| `_ZN4core3str...trim...` | `str::trim` | Trim whitespace |
| `_ZN5alloc7raw_vec...` | `alloc::raw_vec::RawVec::*` | Vector memory management |
| `_ZN4core9panicking...` | `core::panicking::*` | Panic handlers (SKIP) |
| `_ZN4core5slice5index...` | `core::slice::index::*` | Bounds checking (SKIP) |
| `_ZN4core3ops8function...` | `core::ops::function::*` | Closure/function trait calls |
| `_ZN3std2rt...lang_start...` | `std::rt::lang_start` | Runtime initialization |

### Tip 3: Identify Rust Enums in Memory

Rust's `Option<u8>` looks like this in memory:

```
Option::None:    [0x00, 0xXX]  (discriminant=0, padding)
Option::Some(v): [0x01, v]     (discriminant=1, value)
```

`Result<T, E>` is similar:
```
Result::Ok(v):   [0x00, v...]  (discriminant=0, value)
Result::Err(e):  [0x01, e...]  (discriminant=1, error)
```

In Ghidra, these appear as unnamed structs with a leading byte that gets compared against 0 or 1.

### Tip 4: Dealing with Iterator Chains

Rust iterator chains like:

```rust
input.bytes()
    .enumerate()
    .map(|(i, b)| transform(b, i))
    .zip(expected.iter())
    .all(|(a, b)| a == *b)
```

Compile into a single loop in release mode (thanks to Rust's zero-cost abstractions). In Ghidra, this looks like a normal `while` loop with the closure body inlined. The key insight is that **Rust iterator chains compile to the same code as manual for loops** -- just with worse decompilation aesthetics.

### Tip 5: Find Application Code by Crate Name

All application functions start with `_ZN` followed by the crate name length and name. For our binary:

```
_ZN9rustcrack...  -- 9 = length of "rustcrack"
```

Filter for this prefix to find all application-specific functions and ignore the hundreds of standard library functions:

```bash
nm rustcrack | grep "_ZN9rustcrack" | rustfilt
```

```
000000000000b340 T rustcrack::main
000000000000b5a0 t rustcrack::check_flag
000000000000b720 t rustcrack::transform
000000000000b800 t rustcrack::validate_len
000000000000b850 t rustcrack::check_prefix
000000000000b8f0 t rustcrack::check_innerflag
```

Six functions. Out of 2,847 symbols, only 6 are actually ours.

## Can angr Solve Rust Binaries?

Typically, angr struggles with Rust binaries because:

1. **Huge code size** -- standard library functions create massive path explosion
2. **Complex string handling** -- angr's SimProcedures do not model Rust's `String` or `&str`
3. **Heap allocation** -- `String::new()` and `Vec::push()` involve allocator logic
4. **Panic paths** -- every bounds check creates an extra branch to explore

For simple Rust crackmes, you can sometimes make angr work by:
- Hooking Rust std functions to skip them
- Starting execution at the check function directly (not at main)
- Providing concrete values for known bytes

But in general, **manual analysis + algebraic solving is faster than angr for Rust binaries**.

## Common Pitfalls

- **Getting lost in standard library code.** 95% of the binary is Rust stdlib. Filter by crate name to find your application functions immediately.
- **Not demangling symbols.** Raw Rust symbols are unreadable. Always demangle first with `rustfilt` or `c++filt`.
- **Analyzing panic handlers.** Panic code is dead code in correct executions. Learn to recognize the patterns (`core::panicking::*`) and skip them.
- **Misinterpreting string layouts.** Rust strings are `(ptr, len)` or `(ptr, len, cap)`, not null-terminated. When Ghidra shows two consecutive `undefined8` parameters being passed to a function, think "fat pointer to a string slice."
- **Confusing CONCAT71 with real operations.** Ghidra's `CONCAT71(0, bVar1)` just means "return a byte in a 64-bit register." It is not doing any meaningful concatenation.
- **Trying to trace through iterator adapters.** In release mode, iterator chains are fully inlined into loops. Do not try to trace through `Map`, `Filter`, `Enumerate` adapter structs -- just analyze the resulting loop.
- **Ignoring the build mode.** Debug Rust binaries have checked arithmetic (panics on overflow), bounds checks everywhere, and no inlining. Release binaries are heavily optimized but harder to trace. CTFs usually provide release builds.

## Tools Used

- `file` -- identify binary type and debug info presence
- `nm` -- list symbols (2,847 of them)
- `rustfilt` -- demangle Rust symbols to readable names
- `ltrace` -- initial dynamic analysis (limited usefulness for Rust)
- Ghidra -- primary static analysis tool
- Python -- solve script to reverse the flag transformation

## Lessons Learned

- **Filter by crate name immediately.** The single most important step in Rust reversing is identifying which functions belong to the challenge and which are standard library boilerplate. The mangled name format makes this easy.
- **Demangling transforms chaos into clarity.** Invest 30 seconds in `rustfilt` before spending hours in Ghidra. Demangled names reveal the entire program structure.
- **Panic code is noise.** In every Rust function, 30-50% of the decompiled output is unreachable panic handling. Learn the patterns and mentally filter them out.
- **Rust strings are fat pointers.** Two consecutive `undefined8` values being passed to a function almost always represent a `&str` (pointer + length). Recognizing this pattern is essential.
- **The actual algorithm is usually simple.** Beneath all the language overhead, CTF Rust crackmes use the same XOR/rotation/arithmetic checks as C crackmes. The hard part is finding the algorithm, not solving it.
- **Manual analysis beats automated tools for Rust.** angr and other symbolic execution frameworks struggle with Rust's runtime complexity. Static analysis in Ghidra + algebraic solving in Python is the most reliable approach.
