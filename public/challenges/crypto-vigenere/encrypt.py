#!/usr/bin/env python3
"""
Vigenere Cipher - Crypto CTF Challenge
Encrypts a message containing the flag using the Vigenere cipher.
"""

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext using the Vigenere cipher with the given key."""
    key = key.upper()
    result = []
    key_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            if ch.isupper():
                result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def main():
    plaintext = """The art of cryptography has fascinated scholars for centuries.
From the simple substitution ciphers of ancient Rome to the complex
algorithms of the modern era, the desire to communicate secretly has
driven innovation. Hidden within this message lies the flag:
zemi{v1g3n3r3_c1ph3r_cr4ck3d} which can only be recovered by those
who understand the elegant dance of shifting alphabets. The Vigenere
cipher, once called le chiffre indechiffrable, was eventually broken
by Friedrich Kasiski in the nineteenth century."""

    key = "CRYPTO"

    ciphertext = vigenere_encrypt(plaintext, key)

    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext)

    print(f"[+] Encrypted with Vigenere cipher using key: {key}")
    print(f"[+] Written to ciphertext.txt")

if __name__ == "__main__":
    main()
