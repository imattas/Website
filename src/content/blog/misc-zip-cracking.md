---
title: "Misc - ZIP Cracking"
description: "Cracking password-protected ZIP archives using dictionary attacks, hashcat, and known-plaintext attacks with bkcrack."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Easy         |
| Points     | 150          |
| Flag       | `zemi{z1p_cr4ck3d_w1d3_0p3n}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/misc-zip-cracking/flag.txt)
- [generate.py](/Website/challenges/misc-zip-cracking/generate.py)

## Reconnaissance

We receive a password-protected ZIP file:

```bash
file challenge.zip
```

```
challenge.zip: Zip archive data, at least v2.0 to extract
```

```bash
unzip -l challenge.zip
```

```
Archive:  challenge.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       38  2026-02-05 10:00   flag.txt
    14372  2026-02-05 10:00   readme.pdf
---------                     -------
    14410                     2 files
```

```bash
unzip challenge.zip
```

```
Archive:  challenge.zip
[challenge.zip] flag.txt password:
   skipping: flag.txt                incorrect password
   skipping: readme.pdf              incorrect password
```

Both files are encrypted. We need to determine the encryption type and crack it.

## Analysis

### Identifying the encryption type

```bash
7z l -slt challenge.zip | grep -E "(Method|Path)"
```

```
Path = flag.txt
Method = ZipCrypto Deflate

Path = readme.pdf
Method = ZipCrypto Deflate
```

ZipCrypto is the legacy ZIP encryption — significantly weaker than AES. This opens up two attack vectors:

1. **Dictionary/brute-force attack** — try passwords from a wordlist
2. **Known-plaintext attack** — if we know part of the plaintext, we can recover the encryption keys without knowing the password

## Step-by-Step Walkthrough

### Method 1: Dictionary Attack with John the Ripper

#### Step 1: Extract the hash

```bash
zip2john challenge.zip > zip_hash.txt
cat zip_hash.txt
```

```
challenge.zip/flag.txt:$zip2$*0*3*0*e4b3a2c1d0f9e8d7c6b5a4*3f2e*26*0*26*8*f1e2d3c4b5a6*$/zip2$:flag.txt:challenge.zip
challenge.zip/readme.pdf:$zip2$*0*3*0*a1b2c3d4e5f6a7b8c9d0e1*f2e3*3834*0*3834*8*d4c3b2a1*$/zip2$:readme.pdf:challenge.zip
```

#### Step 2: Crack with a wordlist

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

```
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
sunshine123      (challenge.zip/flag.txt)
sunshine123      (challenge.zip/readme.pdf)
2g 0:00:00:04 DONE (2026-02-06 10:30) 0.4545g/s 52480p/s 52480c/s 52480C/s
Session completed
```

Password is `sunshine123`.

#### Step 3: Extract the flag

```bash
unzip -P "sunshine123" challenge.zip
cat flag.txt
```

```
zemi{z1p_cr4ck3d_w1d3_0p3n}
```

### Method 2: GPU Cracking with Hashcat

For larger keyspaces, hashcat's GPU acceleration is much faster:

```bash
# Extract hash in hashcat format (mode 17210 for ZipCrypto)
zip2john challenge.zip | cut -d':' -f2 > hashcat_zip.txt

# Crack with rockyou
hashcat -m 17210 hashcat_zip.txt /usr/share/wordlists/rockyou.txt
```

```
$zip2$*0*3*0*e4b3a2c1d0f9e8d7c6b5a4*3f2e*26*0*26*8*f1e2d3c4b5a6*$/zip2$:sunshine123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 17210 (PKZIP (Uncompressed))
Speed.#1.........:  2451.3 MH/s
```

### Method 3: Quick Brute Force with fcrackzip

For simple passwords, `fcrackzip` is fast and lightweight:

```bash
# Dictionary attack
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt challenge.zip
```

```
PASSWORD FOUND!!!!: pw == sunshine123
```

```bash
# Brute force (short passwords only)
fcrackzip -u -b -c aA1 -l 1-8 challenge.zip
```

The `-u` flag is critical — it tells fcrackzip to actually try unzipping, which eliminates false positives.

### Method 4: Known-Plaintext Attack with bkcrack

This is the most powerful technique for ZipCrypto. If you know at least 12 bytes of plaintext in any encrypted file, you can recover the internal keys and decrypt everything — without ever knowing the password.

#### When do we have known plaintext?

- PDF files always start with `%PDF-1.`
- PNG files start with a known 16-byte header
- ZIP files within ZIPs have a known signature
- Any file with a predictable header or known content

#### Step 1: Prepare known plaintext

The `readme.pdf` is a PDF file. PDFs always begin with a known header:

```bash
echo -n "%PDF-1.4" > known_plaintext.txt
```

#### Step 2: Recover the internal encryption keys

```bash
bkcrack -C challenge.zip -c readme.pdf -p known_plaintext.txt
```

```
bkcrack 1.5.0
[10:35:21] Z reduction using 5 bytes of known plaintext
100.0 % (5 / 5)
[10:35:21] Attack on 655362 Z values at index 6
Keys: 2a3b4c5d 6e7f8a9b 0c1d2e3f
100.0 % (655362 / 655362)
[10:36:48] Keys
2a3b4c5d 6e7f8a9b 0c1d2e3f
```

#### Step 3: Decrypt the archive using recovered keys

```bash
bkcrack -C challenge.zip -k 2a3b4c5d 6e7f8a9b 0c1d2e3f -D decrypted.zip
```

```
bkcrack 1.5.0
Wrote decrypted archive: decrypted.zip
```

```bash
unzip decrypted.zip
cat flag.txt
```

```
zemi{z1p_cr4ck3d_w1d3_0p3n}
```

No password needed — the known-plaintext attack completely bypasses it.

## Handling Nested Archives

Sometimes CTFs nest archives: a ZIP inside a ZIP inside a ZIP. Automate the extraction:

```bash
#!/bin/bash
# nested_unzip.sh - Recursively extract nested archives
file="$1"
while true; do
    ftype=$(file "$file")
    if echo "$ftype" | grep -q "Zip archive"; then
        echo "[*] Extracting ZIP: $file"
        # Try without password first
        if ! unzip -o "$file" 2>/dev/null; then
            echo "[!] Password protected, attempting crack..."
            pw=$(fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt "$file" 2>/dev/null | grep -oP 'pw == \K.*')
            unzip -P "$pw" -o "$file"
        fi
        # Find the next archive inside
        file=$(find . -newer "$file" -type f | head -1)
        [ -z "$file" ] && break
    else
        echo "[*] Final file: $file"
        cat "$file"
        break
    fi
done
```

## ZIP Encryption Comparison

| Feature | ZipCrypto | AES-128/256 |
|---------|-----------|-------------|
| Security | Weak (known-plaintext vulnerable) | Strong |
| Tool | fcrackzip, bkcrack, john | john, hashcat |
| Known-plaintext attack | Yes (bkcrack) | No |
| Speed to crack | Fast | Slow (PBKDF2) |
| Hashcat mode | 17210 | 17200/17225 |

## Tools Used

- `zip2john` (John the Ripper suite) — extract crackable hashes from ZIP files
- `john` — dictionary and brute-force password cracking
- `hashcat` — GPU-accelerated password cracking
- `fcrackzip` — lightweight ZIP password cracker
- `bkcrack` — known-plaintext attack on ZipCrypto
- `7z` — inspect archive metadata and encryption types

## Lessons Learned

- ZipCrypto is fundamentally broken — known-plaintext attacks can recover keys with just 12 bytes of known content
- Always check the encryption method first (`7z l -slt`) to choose the right attack
- The `-u` flag in fcrackzip is essential to avoid false positives
- Known-plaintext attacks do not recover the password — they recover the internal stream cipher keys, which is sufficient to decrypt all files in the archive
- For AES-encrypted ZIPs, dictionary/brute-force is the only option — no known-plaintext shortcut exists
- In real-world scenarios, always use AES-256 encryption (7z or WinZip AES) instead of ZipCrypto
