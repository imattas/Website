#!/bin/bash
# Build with Mono compiler
# Install mono: sudo apt install mono-mcs
#
# Alternative: dotnet build (if using .NET SDK)
# Alternative: csc CrackMe.cs (if using Roslyn compiler)

echo "[*] Building CrackMe.exe with Mono compiler..."
mcs -out:CrackMe.exe CrackMe.cs

if [ $? -eq 0 ]; then
    echo "[+] Build successful: CrackMe.exe"
    echo "[*] Run with: mono CrackMe.exe"
else
    echo "[-] Build failed. Is mono-mcs installed?"
    echo "[-] Install with: sudo apt install mono-mcs"
fi
