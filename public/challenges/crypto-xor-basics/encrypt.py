#!/usr/bin/env python3
"""
XOR Basics - Crypto CTF Challenge
Encrypts the flag using a repeating XOR key.
"""

def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """XOR each byte of plaintext with the corresponding byte of the repeating key."""
    return bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])

def main():
    flag = b"zemi{x0r_1s_r3v3rs1bl3}"
    key = b"CTF"  # 3-byte repeating key

    ciphertext = xor_encrypt(flag, key)

    # Write ciphertext as hex
    with open("ciphertext.hex", "w") as f:
        f.write(ciphertext.hex())

    print(f"[+] Flag encrypted with {len(key)}-byte XOR key")
    print(f"[+] Ciphertext (hex): {ciphertext.hex()}")
    print(f"[+] Written to ciphertext.hex")

if __name__ == "__main__":
    main()
