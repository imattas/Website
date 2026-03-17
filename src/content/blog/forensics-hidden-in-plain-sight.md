---
title: "Forensics - Hidden in Plain Sight"
description: "Extracting a hidden flag from an image using steganography tools and file analysis techniques."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Forensics          |
| Difficulty | Easy               |
| Points     | 150                |
| Flag       | `zemi{st3g0_1s_fr33_r34l_3st4t3}` |

## Challenge Files

Download the challenge files to get started:

- [challenge.png](/Website/challenges/forensics-hidden-in-plain-sight/challenge.png)
- [flag.txt](/Website/challenges/forensics-hidden-in-plain-sight/flag.txt)
- [generate.py](/Website/challenges/forensics-hidden-in-plain-sight/generate.py)
- [hint.txt](/Website/challenges/forensics-hidden-in-plain-sight/hint.txt)

## Reconnaissance

We're given a file called `landscape.png` — a normal-looking photo of a mountain. The challenge hint says: *"Sometimes what you see isn't all there is."*

Start with basic file analysis.

## Step 1 — File Metadata

```bash
file landscape.png
```

```
landscape.png: PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced
```

Looks like a valid PNG. Let's check for metadata:

```bash
exiftool landscape.png
```

```
File Name         : landscape.png
File Size         : 2.4 MB
Image Width       : 1920
Image Height      : 1080
Bit Depth         : 8
Comment           : Nice try, keep looking deeper...
```

A comment telling us to dig deeper. Not the flag, but confirmation we're on the right track.

## Step 2 — Strings Analysis

```bash
strings landscape.png | grep -i zemi
```

No results. The flag isn't stored as plain text in the file. Let's try other approaches.

## Step 3 — Check for Appended Data

Sometimes files have extra data appended after the official end-of-file marker. For PNG files, the file should end with the `IEND` chunk:

```bash
xxd landscape.png | tail -20
```

```
0024aff0: 0000 0000 4945 4e44 ae42 6082 504b 0304  ....IEND.B`.PK..
0024b000: 1400 0000 0800 ...
```

After the `IEND` marker, we see `PK` — that's a ZIP file signature. There's a ZIP archive appended to the image.

## Step 4 — Extract the Hidden ZIP

```bash
# Find where the ZIP starts
binwalk landscape.png
```

```
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             PNG image, 1920 x 1080
2404080       0x24AFF4        Zip archive data, name: flag.txt
2404250       0x24B09A        End of Zip archive
```

Extract the embedded files:

```bash
binwalk -e landscape.png
```

This creates a `_landscape.png.extracted/` directory containing the ZIP. Let's check:

```bash
ls _landscape.png.extracted/
```

```
24AFF4.zip
```

```bash
unzip _landscape.png.extracted/24AFF4.zip
```

```
Archive:  24AFF4.zip
  inflating: flag.txt
```

```bash
cat flag.txt
```

```
zemi{st3g0_1s_fr33_r34l_3st4t3}
```

## Alternative Approach

You could also extract the ZIP manually using `dd`:

```bash
# Skip to the ZIP offset and extract
dd if=landscape.png bs=1 skip=2404080 of=hidden.zip
unzip hidden.zip
```

Or use `foremost`:

```bash
foremost -i landscape.png -o output/
cat output/zip/00000001/flag.txt
```

## Tools Used

- `file` — identify file type
- `exiftool` — read metadata
- `strings` — search for readable text
- `xxd` — hex dump
- `binwalk` — scan for embedded files and extract them
- `foremost` — alternative carving tool

## Lessons Learned

- Always start forensics challenges with basic analysis: `file`, `strings`, `exiftool`
- Check for data appended after the file's end marker (`IEND` for PNG, `FFD9` for JPEG)
- `binwalk` is your best friend for finding embedded files — it scans for magic bytes of known file formats
- Files can contain other files — images can hide ZIPs, ZIPs can hide images, etc.
- The `PK` signature (`50 4B 03 04`) always indicates a ZIP archive
