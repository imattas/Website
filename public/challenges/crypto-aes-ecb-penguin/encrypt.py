#!/usr/bin/env python3
"""
AES-ECB Penguin - Crypto CTF Challenge

AES in ECB mode encrypts each 16-byte block independently.
Identical plaintext blocks produce identical ciphertext blocks.
This leaks information about the structure of the plaintext.

Can you identify the repeating patterns and extract the unique blocks?
"""

from hashlib import sha256

try:
    from Crypto.Cipher import AES
    def encrypt_ecb(key, plaintext):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def encrypt_ecb(key, plaintext):
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

def main():
    # Derive a consistent AES-128 key
    key = sha256(b"ecb_penguin_key").digest()[:16]

    # Build plaintext with repeating blocks to demonstrate ECB weakness
    # The flag is hidden among repeated filler blocks
    blocks = [
        b"AAAAAAAAAAAAAAAA",  # Block 0  - filler
        b"AAAAAAAAAAAAAAAA",  # Block 1  - same filler (identical ciphertext!)
        b"AAAAAAAAAAAAAAAA",  # Block 2  - same filler (identical ciphertext!)
        b"zemi{3cb_p3ngu1n",  # Block 3  - FLAG part 1 (unique ciphertext)
        b"_m0d3_1s_uns4f3}",  # Block 4  - FLAG part 2 (unique ciphertext)
        b"AAAAAAAAAAAAAAAA",  # Block 5  - filler again
        b"AAAAAAAAAAAAAAAA",  # Block 6  - filler again
        b"BBBBBBBBBBBBBBBB",  # Block 7  - different filler
        b"BBBBBBBBBBBBBBBB",  # Block 8  - same (identical ciphertext!)
        b"BBBBBBBBBBBBBBBB",  # Block 9  - same (identical ciphertext!)
        b"CCCCCCCCCCCCCCCC",  # Block 10 - yet another filler
        b"AAAAAAAAAAAAAAAA",  # Block 11 - back to A filler
    ]

    plaintext = b"".join(blocks)
    ciphertext = encrypt_ecb(key, plaintext)

    # Write as hex
    with open("ciphertext.bin", "w") as f:
        f.write(ciphertext.hex())

    print("[+] AES-ECB encryption complete")
    print(f"[+] Key (hex): {key.hex()}")
    print(f"[+] {len(blocks)} blocks encrypted ({len(ciphertext)} bytes)")
    print(f"[+] Written to ciphertext.bin (hex encoded)")
    print()
    print("[+] Notice the repeating ciphertext blocks:")
    for i in range(len(ciphertext) // 16):
        block = ciphertext[i * 16 : (i + 1) * 16]
        print(f"    Block {i:2d}: {block.hex()}")

if __name__ == "__main__":
    main()
