---
title: "Rev - .NET Decompilation"
description: "Reversing a .NET/C# application using dnSpy and ILSpy to recover source code, find hardcoded secrets, and decode obfuscated strings."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                            |
|------------|----------------------------------|
| Category   | Reverse Engineering              |
| Difficulty | Medium                           |
| Points     | 200                              |
| Flag       | `zemi{d0tn3t_1s_34sy_t0_r3v}`    |

## Challenge Files

Download the challenge files to get started:

- [CrackMe.cs](/Website/challenges/rev-dotnet-decompile/CrackMe.cs)
- [build.sh](/Website/challenges/rev-dotnet-decompile/build.sh)
- [flag.txt](/Website/challenges/rev-dotnet-decompile/flag.txt)

## Overview

.NET applications compile to Intermediate Language (IL) code rather than native machine code. This IL code retains rich metadata -- class names, method names, string literals, and type information -- making .NET binaries dramatically easier to reverse engineer than native C/C++ binaries. With the right tools, you can recover near-original source code. This writeup covers reversing a .NET crackme using dnSpy and ILSpy. All analysis is performed locally.

## Why .NET is Easy to Reverse

When you compile C# code, the compiler produces IL (Intermediate Language) bytecode that runs on the CLR (Common Language Runtime). Unlike native x86 assembly, IL retains:

| Preserved Information | Why It Helps |
|----------------------|-------------|
| Class and method names | You see `ValidatePassword()` instead of `sub_401230` |
| Variable names (in Debug builds) | Local variable names survive compilation |
| String literals | Hardcoded strings are directly visible |
| Type information | You know the types of all variables and parameters |
| Control flow structure | `if/else`, `for`, `while` decompile cleanly |
| Exception handling | `try/catch` blocks are preserved |

The result: decompiling a .NET binary often gives you code that's nearly identical to the original source.

## Initial Recon

We receive a file called `SecureVault.exe`:

```bash
file SecureVault.exe
```

```
SecureVault.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

The `Mono/.Net assembly` tag tells us this is a .NET binary. We can also confirm with:

```bash
# Check for .NET metadata
xxd SecureVault.exe | head -20
# Look for "BSJB" magic bytes (CLI metadata header)
strings SecureVault.exe | grep -i "BSJB"
```

On Linux, we can run it with Mono:

```bash
mono SecureVault.exe
```

```
╔══════════════════════╗
║    SECURE VAULT      ║
╚══════════════════════╝
Enter master password: test
[ERROR] Authentication failed.
```

## Decompilation with ILSpy (Cross-Platform)

ILSpy is available as a cross-platform command-line tool (`ilspycmd`) and as a GUI (Avalonia-based):

```bash
# Install the command-line decompiler
dotnet tool install -g ilspycmd

# Decompile the entire assembly to C#
ilspycmd SecureVault.exe
```

This dumps the full decompiled C# source. You can also use the ILSpy GUI or the VS Code ILSpy extension.

## Decompilation with dnSpy (Windows/Wine)

dnSpy is the gold standard for .NET reversing. Open `SecureVault.exe` in dnSpy and you'll see the full project structure in the left panel:

```
SecureVault (1.0.0.0)
├── {} SecureVault
│   ├── Program
│   │   ├── Main(string[]) : void
│   │   ├── ValidatePassword(string) : bool
│   │   ├── DecryptFlag(string) : string
│   │   └── ObfuscatedCheck(string) : bool
│   └── Crypto
│       ├── XorDecrypt(byte[], byte[]) : string
│       └── FromBase64(string) : byte[]
```

We can see every class, method, and their full signatures. Let's examine each one.

## Analyzing the Decompiled Code

### Main Method

```csharp
using System;
using System.Text;

namespace SecureVault
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("╔══════════════════════╗");
            Console.WriteLine("║    SECURE VAULT      ║");
            Console.WriteLine("╚══════════════════════╝");
            Console.Write("Enter master password: ");

            string input = Console.ReadLine();

            if (ValidatePassword(input))
            {
                string flag = DecryptFlag(input);
                Console.WriteLine("[SUCCESS] Flag: " + flag);
            }
            else
            {
                Console.WriteLine("[ERROR] Authentication failed.");
            }
        }
    }
}
```

### ValidatePassword -- Base64-Encoded Comparison

```csharp
static bool ValidatePassword(string password)
{
    // The expected password is base64-encoded
    string encodedExpected = "czNjdXIzX3ZhdWx0";

    byte[] expectedBytes = Convert.FromBase64String(encodedExpected);
    string expected = Encoding.UTF8.GetString(expectedBytes);

    if (password.Length != expected.Length)
        return false;

    // Character-by-character comparison with obfuscation
    return ObfuscatedCheck(password);
}
```

The password is base64-encoded. Let's decode it:

```bash
echo "czNjdXIzX3ZhdWx0" | base64 -d
```

```
s3cur3_vault
```

The expected password is `s3cur3_vault`. But wait -- there's an `ObfuscatedCheck` function too.

### ObfuscatedCheck -- XOR Comparison

```csharp
static bool ObfuscatedCheck(string input)
{
    // XOR each character with a rolling key and compare
    byte[] expected = new byte[] {
        0x10, 0x56, 0x00, 0x14, 0x07, 0x51, 0x6c, 0x15,
        0x02, 0x13, 0x0b, 0x11
    };

    byte key = 0x63;  // Starting key

    for (int i = 0; i < input.Length; i++)
    {
        byte transformed = (byte)(input[i] ^ key);
        if (transformed != expected[i])
            return false;
        key = (byte)((key + 0x07) & 0xFF);  // Rotate key
    }
    return true;
}
```

This is a XOR check with a rotating key. We can verify our password or derive it from scratch:

```python
expected = [0x10, 0x56, 0x00, 0x14, 0x07, 0x51, 0x6c, 0x15,
            0x02, 0x13, 0x0b, 0x11]

key = 0x63
password = ""
for b in expected:
    password += chr(b ^ key)
    key = (key + 0x07) & 0xFF

print(f"Password: {password}")
```

```
Password: s3cur3_vault
```

Matches the base64 decode. The obfuscation was redundant.

### DecryptFlag -- The Prize

```csharp
static string DecryptFlag(string password)
{
    // Encrypted flag bytes
    byte[] encryptedFlag = new byte[] {
        0x19, 0x00, 0x0f, 0x08, 0x58, 0x01, 0x47, 0x17,
        0x09, 0x46, 0x17, 0x32, 0x1c, 0x17, 0x3c, 0x50,
        0x00, 0x58, 0x18, 0x1a, 0x42, 0x10, 0x0c, 0x33,
        0x5a
    };

    // Derive decryption key from password
    byte[] keyBytes = Encoding.UTF8.GetBytes(password);

    return Crypto.XorDecrypt(encryptedFlag, keyBytes);
}
```

And the `Crypto.XorDecrypt` helper:

```csharp
namespace SecureVault
{
    static class Crypto
    {
        public static string XorDecrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return Encoding.UTF8.GetString(result);
        }

        public static byte[] FromBase64(string encoded)
        {
            return Convert.FromBase64String(encoded);
        }
    }
}
```

## Solve Script

We have everything. The flag is XOR-encrypted with the password as the key:

```python
#!/usr/bin/env python3
"""Solve script for SecureVault.exe"""

# Password (from base64 decode or XOR recovery)
password = b"s3cur3_vault"

# Encrypted flag bytes from DecryptFlag()
encrypted_flag = [
    0x19, 0x00, 0x0f, 0x08, 0x58, 0x01, 0x47, 0x17,
    0x09, 0x46, 0x17, 0x32, 0x1c, 0x17, 0x3c, 0x50,
    0x00, 0x58, 0x18, 0x1a, 0x42, 0x10, 0x0c, 0x33,
    0x5a
]

# XOR decrypt
flag = ""
for i in range(len(encrypted_flag)):
    flag += chr(encrypted_flag[i] ^ password[i % len(password)])

print(f"Flag: {flag}")
```

```
Flag: zemi{d0tn3t_1s_34sy_t0_r3v}
```

Or just run the binary with the correct password:

```bash
mono SecureVault.exe
```

```
╔══════════════════════╗
║    SECURE VAULT      ║
╚══════════════════════╝
Enter master password: s3cur3_vault
[SUCCESS] Flag: zemi{d0tn3t_1s_34sy_t0_r3v}
```

## Dealing with Common .NET Obfuscation

Real-world .NET binaries often use obfuscators. Here's what you'll encounter and how to handle it:

### String Encryption

Obfuscators like ConfuserEx encrypt all string literals. Instead of seeing `"s3cur3_vault"`, you'll see:

```csharp
string s = Module.DecryptString(1847293);  // runtime decryption
```

**Bypass:** Set a breakpoint in dnSpy on `Console.ReadLine()` and inspect variables at runtime. Or find the decryption method, call it with all referenced IDs, and dump all strings.

### Name Mangling

Method and variable names get replaced:

```csharp
// Before obfuscation:
static bool ValidatePassword(string password)

// After obfuscation:
static bool \u0001(string \u0002)
```

**Bypass:** dnSpy still shows the code logic -- you just need to read the control flow instead of relying on names. Rename methods as you understand them (dnSpy allows renaming).

### Control Flow Obfuscation

Switch statements and gotos are inserted to scramble the logic:

```csharp
int state = 0;
while (true) {
    switch (state) {
        case 0: /* ... */ state = 3; break;
        case 1: /* ... */ state = 5; break;
        case 2: /* ... */ return result;
        // ...
    }
}
```

**Bypass:** Use de4dot (a .NET deobfuscator) to clean up known obfuscator patterns before decompiling:

```bash
de4dot SecureVault.exe -o SecureVault-clean.exe
```

## .NET Reversing Tool Comparison

| Tool | Platform | Strengths | Weaknesses |
|------|----------|-----------|------------|
| dnSpy | Windows (Wine on Linux) | Debugging + decompilation, edit and recompile | Windows-only, no longer actively maintained |
| ILSpy | Cross-platform | Clean decompilation, actively maintained | No built-in debugger |
| dotPeek | Windows | JetBrains quality, good search | Windows-only, no editing |
| de4dot | Cross-platform | Automatic deobfuscation | Only handles known obfuscators |
| monodis | Linux | Quick IL disassembly, comes with Mono | Shows IL, not decompiled C# |

### Quick IL Disassembly with monodis

If you want a fast look without a GUI:

```bash
monodis --method SecureVault.exe
```

```
.method private static hidebysig bool ValidatePassword(string password) cil managed
{
    .maxstack 3
    .locals init (byte[] V_0, string V_1)

    IL_0000: ldstr "czNjdXIzX3ZhdWx0"
    IL_0005: call class [mscorlib]System.Convert::FromBase64String(string)
    IL_000a: stloc.0
    ...
}
```

Even raw IL reveals the base64-encoded string directly.

## Tools Used

- `file` -- identify binary as .NET assembly
- `strings` -- quick string extraction
- ILSpy / dnSpy -- full C# decompilation
- `monodis` -- quick IL disassembly on Linux
- `base64` -- decode obfuscated strings
- Python -- XOR decryption and password recovery
- Mono -- run .NET binaries on Linux

## Lessons Learned

- **.NET binaries are essentially open source**. The decompiled code is almost identical to the original, making .NET reversing a great entry point for beginners.
- **Always check for base64-encoded strings**. It's the most common "obfuscation" in easy .NET challenges -- just pipe suspicious strings through `base64 -d`.
- **dnSpy's debugger is a superpower**. You can set breakpoints, inspect variables, and even modify code and recompile without leaving the tool.
- **de4dot should be your first step** if the decompiled code looks mangled. It handles ConfuserEx, Dotfuscator, and many other obfuscators automatically.
- **The same XOR and comparison patterns** appear in .NET as in native binaries -- they're just much easier to read in decompiled C# than in x86 assembly.
- **Metadata is your friend**. Even heavily obfuscated .NET binaries preserve type information, method signatures, and inheritance hierarchies that reveal program structure.
