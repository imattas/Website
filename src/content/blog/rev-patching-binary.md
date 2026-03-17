---
title: "Rev - Patching a Binary"
description: "Learning to patch conditional jumps and NOP out checks in an ELF binary to bypass password verification and reveal the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                            |
|------------|----------------------------------|
| Category   | Reverse Engineering              |
| Difficulty | Medium                           |
| Points     | 200                              |
| Flag       | `zemi{p4tch3d_4nd_cr4ck3d}`      |

## Challenge Files

Download the challenge files to get started:

- [patchme.c](/Website/challenges/rev-patching-binary/patchme.c)
- [flag.txt](/Website/challenges/rev-patching-binary/flag.txt)
- [Makefile](/Website/challenges/rev-patching-binary/Makefile)

## Overview

Sometimes the goal isn't to find the correct password -- it's to make the binary accept *any* password. Binary patching is the art of modifying a compiled executable to change its behavior. In this writeup, we identify the conditional jump that gates the success path, then patch it so the binary always takes the "correct password" branch. All analysis is performed locally on the provided binary.

## Initial Recon

We receive a binary called `lockbox`:

```bash
file lockbox
```

```
lockbox: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

```bash
./lockbox
```

```
=== LOCKBOX v2.0 ===
Password: wrong
Verification failed.
Intruder alert logged.
```

Let's try `ltrace`:

```bash
ltrace ./lockbox <<< "test"
```

```
puts("=== LOCKBOX v2.0 ===")                    = 21
printf("Password: ")                             = 10
fgets("test\n", 128, 0x7f1a2b3c4980)             = 0x7ffd1a2b3c40
strlen("test")                                   = 4
MD5_Init(0x7ffd1a2b3c60)                         = 1
MD5_Update(0x7ffd1a2b3c60, "test", 4)            = 1
MD5_Final(0x7ffd1a2b3ca0, 0x7ffd1a2b3c60)        = 1
memcmp(0x7ffd1a2b3ca0, 0x404060, 16)             = -115
puts("Verification failed.")                     = 21
puts("Intruder alert logged.")                   = 23
+++ exited (status 1) +++
```

The binary hashes our input with MD5 and compares the digest to a stored hash using `memcmp`. We could try to crack the MD5 hash, but patching the binary is faster and more educational.

## Static Analysis with Ghidra

Loading into Ghidra and navigating to `main`:

```c
int main(void) {
    char input[128];
    unsigned char hash[16];
    MD5_CTX ctx;

    unsigned char expected_hash[16] = {
        0xa3, 0xf2, 0x91, 0x7b, 0x44, 0xde, 0x08, 0xc1,
        0x99, 0x3e, 0x67, 0x5a, 0x01, 0xbd, 0xf8, 0x72
    };

    puts("=== LOCKBOX v2.0 ===");
    printf("Password: ");
    fgets(input, 128, stdin);
    input[strcspn(input, "\n")] = 0;

    MD5_Init(&ctx);
    MD5_Update(&ctx, input, strlen(input));
    MD5_Final(hash, &ctx);

    if (memcmp(hash, expected_hash, 16) == 0) {
        puts("Access granted!");
        decrypt_and_print_flag();
    } else {
        puts("Verification failed.");
        puts("Intruder alert logged.");
    }
    return 1;
}
```

The critical point is the `if (memcmp(...) == 0)` check. In assembly, this looks like:

```asm
                     ; memcmp returns 0 if hashes match
  00401234  CALL     memcmp
  00401239  TEST     EAX, EAX
  0040123b  JNE      LAB_00401260        ; <-- jump to FAILURE if NOT equal
  0040123d  LEA      RDI, [s_Access_granted!]
  00401244  CALL     puts
  00401249  CALL     decrypt_and_print_flag
  0040124e  JMP      LAB_00401278        ; skip failure block
                     LAB_00401260:
  00401260  LEA      RDI, [s_Verification_failed.]
  00401267  CALL     puts
  0040126c  LEA      RDI, [s_Intruder_alert_logged.]
  00401273  CALL     puts
```

The `JNE` (Jump if Not Equal) at `0x0040123b` is the gatekeeper. When `memcmp` returns non-zero (hashes don't match), the Zero Flag is cleared and `JNE` jumps to the failure path. We need to change this behavior.

## Patching Strategy

We have several options:

### Option 1: Change JNE to JE

Flip the logic so the binary jumps to failure only when the password is *correct* (and falls through to success for any wrong password):

| Instruction | Opcode Bytes | Behavior |
|-------------|-------------|----------|
| `JNE rel8`  | `75 xx`     | Jump if ZF=0 (not equal) |
| `JE rel8`   | `74 xx`     | Jump if ZF=1 (equal) |

Change one byte: `0x75` to `0x74`.

### Option 2: NOP the JNE

Replace the entire jump instruction with NOPs so execution always falls through to the success path:

| Instruction | Opcode Bytes |
|-------------|-------------|
| `JNE rel8`  | `75 23`  (2 bytes) |
| `NOP; NOP`  | `90 90`  (2 bytes) |

### Option 3: NOP the entire check

Replace `TEST EAX, EAX` and `JNE` with NOPs (4 bytes total):

```
TEST EAX, EAX  ->  90 90       (2 bytes: 85 C0 -> 90 90)
JNE  rel8      ->  90 90       (2 bytes: 75 23 -> 90 90)
```

We'll demonstrate Options 1 and 2.

## Patch Method A: Hex Editor (xxd)

First, find the exact file offset of the `JNE` instruction. In Ghidra, the instruction is at virtual address `0x0040123b`. We need the file offset.

```bash
# Find the offset of the .text section
readelf -S lockbox | grep .text
```

```
  [14] .text     PROGBITS     0000000000401060  00001060  000002a5  0000  AX  0  0  16
```

The `.text` section starts at virtual address `0x401060` and file offset `0x1060`. So:

```
file_offset = virtual_address - section_vaddr + section_file_offset
file_offset = 0x40123b - 0x401060 + 0x1060
file_offset = 0x123b
```

Now patch with `xxd` and a hex editor approach:

```bash
# Make a backup
cp lockbox lockbox.bak

# View the bytes at offset 0x123b
xxd -s 0x1239 -l 8 lockbox
```

```
0000123b: 85c0 7523 488d 3d...
```

We see `85 c0` (TEST EAX, EAX) followed by `75 23` (JNE +0x23). Let's patch `75` to `74`:

```bash
# Patch JNE (0x75) to JE (0x74) at offset 0x123d
printf '\x74' | dd of=lockbox bs=1 seek=$((0x123d)) count=1 conv=notrunc
```

```
1+0 records in
1+0 records out
```

Verify the patch:

```bash
xxd -s 0x1239 -l 8 lockbox
```

```
0000123b: 85c0 7423 488d 3d...
```

The `75` is now `74`. Test it:

```bash
./lockbox
```

```
=== LOCKBOX v2.0 ===
Password: literally_anything
Access granted!
zemi{p4tch3d_4nd_cr4ck3d}
```

## Patch Method B: Radare2 (r2)

Radare2 provides a more ergonomic patching workflow:

```bash
# Restore original
cp lockbox.bak lockbox

# Open in write mode
r2 -w lockbox
```

```
[0x00401080]> aaa                    # analyze all
[0x00401080]> s 0x0040123b           # seek to the JNE
[0x0040123b]> pd 5                   # print disassembly

            0x00401239      85c0       test eax, eax
            0x0040123b      7523       jne 0x401260
            0x0040123d      488d3d..   lea rdi, str.Access_granted_
            0x00401244      e8...      call sym.imp.puts
            0x00401249      e8...      call sym.decrypt_and_print_flag
```

Now patch using the `wa` (write assembly) command:

```
[0x0040123b]> wa je 0x401260         # write assembly: change jne to je
Written 2 bytes (je 0x401260) = wx 7423

[0x0040123b]> pd 3                   # verify
            0x00401239      85c0       test eax, eax
            0x0040123b      7423       je 0x401260
            0x0040123d      488d3d..   lea rdi, str.Access_granted_

[0x0040123b]> q                      # quit
```

Alternatively, to NOP out the jump entirely:

```
[0x0040123b]> wx 9090                # write hex: two NOP bytes
```

## Patch Method C: Ghidra Patch

In Ghidra, you can patch directly:

1. Navigate to the `JNE` instruction at `0x0040123b`
2. Right-click the instruction -> **Patch Instruction**
3. Change `JNE` to `JE` (or type `NOP`)
4. File -> **Export Program** -> choose **Original File** format
5. Save as a new file

## Before/After Comparison

```bash
# Compare original and patched binaries
xxd lockbox.bak > /tmp/orig.hex
xxd lockbox > /tmp/patched.hex
diff /tmp/orig.hex /tmp/patched.hex
```

```
293c293
< 0000123b: 85c0 7523 488d 3d..   ..u#H.=.
---
> 0000123b: 85c0 7423 488d 3d..   ..t#H.=.
```

One byte changed. One byte is all it takes.

## x86 Jump Instruction Reference

Here are the common conditional jumps you'll encounter and their opcodes:

| Instruction | Opcode | Condition | Meaning |
|-------------|--------|-----------|---------|
| `JE` / `JZ`   | `74`  | ZF=1 | Jump if equal / zero |
| `JNE` / `JNZ` | `75`  | ZF=0 | Jump if not equal / not zero |
| `JA`           | `77`  | CF=0, ZF=0 | Jump if above (unsigned) |
| `JB` / `JC`   | `72`  | CF=1 | Jump if below / carry |
| `JG`           | `7F`  | ZF=0, SF=OF | Jump if greater (signed) |
| `JL`           | `7C`  | SF!=OF | Jump if less (signed) |
| `JMP rel8`     | `EB`  | (none) | Unconditional short jump |
| `NOP`          | `90`  | (none) | No operation |

**Quick patching rules:**
- Swap `74` and `75` to invert equal/not-equal logic
- Replace any 2-byte conditional jump with `90 90` (two NOPs) to remove the check
- Replace a conditional jump with `EB` (unconditional jump) to always take it

## Tools Used

- `file` -- identify binary type
- `ltrace` -- understand the verification mechanism (MD5 + memcmp)
- Ghidra -- static analysis to find the critical jump
- `readelf` -- find section offsets for file patching
- `xxd` / `dd` -- hex-level binary patching
- Radare2 (`r2`) -- interactive disassembly and patching
- `diff` -- verify the patch

## Lessons Learned

- **Any client-side check can be bypassed**. If the binary decides locally whether you passed, you can always patch it to say "yes."
- **The critical patch point is usually a conditional jump** right after a `TEST`/`CMP` instruction following a comparison function call.
- **You only need to change one byte** to flip the logic of a conditional jump (`75` to `74` or vice versa).
- **NOPping is the safest patch** when you're unsure of the logic -- it removes the check entirely and lets execution fall through.
- **Always back up before patching**. A bad patch can crash the binary or corrupt the flag decryption routine.
- **In real CTFs**, organizers sometimes check the binary's hash to prevent trivial patching. In those cases, you'd need to use GDB to patch at runtime instead (as shown in the Baby Crackme writeup).
