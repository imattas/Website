---
title: "Misc - LSB Steganography"
description: "Extracting hidden data from the least significant bits of image pixels using stegsolve, zsteg, and a custom Python extraction script."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Medium       |
| Points     | 200          |
| Flag       | `zemi{lsb_p1x3l_p3rf3ct}` |

## Challenge Files

Download the challenge files to get started:

- [challenge.png](/Website/challenges/misc-steganography-lsb/challenge.png)
- [flag.txt](/Website/challenges/misc-steganography-lsb/flag.txt)
- [generate.py](/Website/challenges/misc-steganography-lsb/generate.py)

## Reconnaissance

We are given a PNG image file:

```bash
file secret_image.png
```

```
secret_image.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced
```

The image looks like a normal photograph. No visible artifacts, no obvious text. Let's check for hidden data.

```bash
# Check for appended data after the PNG end marker
binwalk secret_image.png
```

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 800 x 600, 8-bit/color RGB, non-interlaced
```

Nothing appended. Let's check metadata:

```bash
exiftool secret_image.png
```

```
File Size                       : 1.4 MB
Image Width                     : 800
Image Height                    : 600
Bit Depth                       : 8
Color Type                      : RGB
Comment                         : Nothing suspicious here :)
```

No flag in metadata either. Time to look at the pixel data itself.

## Analysis

### How LSB Steganography Works

Every pixel in an RGB image has three color channels: Red, Green, and Blue. Each channel is stored as an 8-bit value (0-255).

The **least significant bit** (bit 0) of each byte contributes minimally to the color — changing it alters the value by at most 1, which is imperceptible to the human eye.

```
Original pixel:  R=154 (10011010), G=201 (11001001), B=87 (01010111)
Modified pixel:  R=155 (10011011), G=200 (11001000), B=86 (01010110)
                                ^               ^              ^
                           LSB changed      LSB changed    LSB changed
```

The color difference is invisible, but those 3 modified bits encode data. With an 800x600 image (480,000 pixels x 3 channels), we can hide 480,000 x 3 = 1,440,000 bits = 180,000 bytes = 175 KB of data.

### Bit planes

Each channel has 8 bit planes (bit 0 through bit 7):

```
Bit 7 (MSB): Most visual impact, carries most color information
Bit 6: ...
Bit 5: ...
Bit 4: ...
Bit 3: ...
Bit 2: ...
Bit 1: Slight visual impact
Bit 0 (LSB): Least visual impact — ideal for hiding data
```

## Step-by-Step Walkthrough

### Step 1: Quick check with zsteg

`zsteg` automatically checks common LSB steganography configurations:

```bash
zsteg secret_image.png
```

```
b1,rgb,lsb,xy      .. text: "zemi{lsb_p1x3l_p3rf3ct}"
b1,r,lsb,xy        .. text: "iQ\x12wK..."
b1,g,lsb,xy        .. text: "\x03\xa8\x9f..."
b1,b,lsb,xy        .. text: "pV\x88..."
b2,rgb,lsb,xy      .. text: "U2FsdGVk..."
b1,rgb,msb,xy      .. text: "\xff\xd8\xff..."
```

The very first result gives us the flag: `zemi{lsb_p1x3l_p3rf3ct}`

The notation `b1,rgb,lsb,xy` means:
- `b1` — bit plane 1 (the least significant bit)
- `rgb` — read from all three channels in R,G,B order
- `lsb` — least significant bit first
- `xy` — read pixels left-to-right, top-to-bottom (row by row)

### Step 2: Verify with stegsolve

`stegsolve` is a Java GUI tool that lets you visually browse bit planes:

```bash
java -jar stegsolve.jar
```

1. Open `secret_image.png`
2. Use the arrow buttons to cycle through bit planes
3. On "Red plane 0" (LSB), you might see patterns or text
4. Go to `Analyse > Data Extract`
5. Select: Bit 0 for R, G, B channels, LSB first, Row order
6. Click "Preview" — the flag appears in the extracted data

### Step 3: Custom Python extraction script

For full control and understanding, write a manual extractor:

```python
#!/usr/bin/env python3
"""lsb_extract.py - Extract LSB steganography data from PNG images"""
from PIL import Image
import sys

def extract_lsb(image_path, channels='rgb', bit=0, order='xy'):
    """
    Extract data hidden in the least significant bits of an image.

    Args:
        image_path: Path to the image file
        channels: Which channels to read ('r', 'g', 'b', 'rgb', etc.)
        bit: Which bit plane (0 = LSB, 7 = MSB)
        order: 'xy' for row-by-row, 'yx' for column-by-column
    """
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    channel_map = {'r': 0, 'g': 1, 'b': 2}
    bits = []

    if order == 'xy':
        coords = [(x, y) for y in range(height) for x in range(width)]
    else:  # 'yx' — column by column
        coords = [(x, y) for x in range(width) for y in range(height)]

    for x, y in coords:
        pixel = pixels[x, y]
        for ch in channels:
            channel_idx = channel_map[ch]
            # Extract the specified bit
            extracted_bit = (pixel[channel_idx] >> bit) & 1
            bits.append(extracted_bit)

    # Convert bits to bytes
    data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data.append(byte)

        # Stop at null terminator
        if byte == 0:
            break

    return bytes(data)

if __name__ == "__main__":
    image_path = sys.argv[1] if len(sys.argv) > 1 else "secret_image.png"

    # Try common configurations
    configs = [
        ('rgb', 0, 'xy'),  # Most common: RGB channels, bit 0, row order
        ('r',   0, 'xy'),  # Red channel only
        ('g',   0, 'xy'),  # Green channel only
        ('b',   0, 'xy'),  # Blue channel only
        ('rgb', 0, 'yx'),  # Column order
        ('rgb', 1, 'xy'),  # Bit plane 1
    ]

    for channels, bit, order in configs:
        result = extract_lsb(image_path, channels, bit, order)
        # Check if result contains printable ASCII
        printable = result.decode('ascii', errors='ignore')
        if 'zemi{' in printable:
            print(f"[+] Found flag with config: channels={channels}, bit={bit}, order={order}")
            # Extract just the flag
            start = printable.index('zemi{')
            end = printable.index('}', start) + 1
            print(f"[+] Flag: {printable[start:end]}")
            break
        elif len(printable.strip()) > 10:
            preview = printable[:80].strip()
            print(f"[-] channels={channels}, bit={bit}, order={order}: {preview}...")
    else:
        print("[!] Flag not found in common configurations")
```

```bash
python3 lsb_extract.py secret_image.png
```

```
[+] Found flag with config: channels=rgb, bit=0, order=xy
[+] Flag: zemi{lsb_p1x3l_p3rf3ct}
```

### Step 4: Verify by embedding and extracting

To understand the process fully, here is how data is embedded:

```python
#!/usr/bin/env python3
"""lsb_embed.py - Embed data into image using LSB steganography"""
from PIL import Image

def embed_lsb(image_path, output_path, message):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    # Convert message to bits
    msg_bytes = message.encode() + b'\x00'  # null terminator
    bits = []
    for byte in msg_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    if len(bits) > width * height * 3:
        raise ValueError("Message too large for this image")

    bit_idx = 0
    for y in range(height):
        for x in range(width):
            if bit_idx >= len(bits):
                break
            r, g, b = pixels[x, y]
            channels = [r, g, b]
            for c in range(3):
                if bit_idx >= len(bits):
                    break
                # Clear LSB and set to message bit
                channels[c] = (channels[c] & 0xFE) | bits[bit_idx]
                bit_idx += 1
            pixels[x, y] = tuple(channels)

    img.save(output_path)
    print(f"[+] Embedded {len(msg_bytes)} bytes into {output_path}")

embed_lsb("cover_image.png", "secret_image.png", "zemi{lsb_p1x3l_p3rf3ct}")
```

## Advanced LSB Techniques

### Multi-bit embedding

Some challenges use more than just bit 0:

```python
# Extract bits 0 and 1 from red channel
for x, y in coords:
    r = pixels[x, y][0]
    bits.append((r >> 0) & 1)  # bit 0
    bits.append((r >> 1) & 1)  # bit 1
```

### Alpha channel

RGBA images have a fourth channel that may hide data:

```python
img = Image.open("image.png").convert("RGBA")
pixels = img.load()
r, g, b, a = pixels[0, 0]
# Check alpha channel LSB
hidden_bit = a & 1
```

### Detecting LSB steganography

Statistical analysis can detect LSB embedding:

```python
from PIL import Image
import numpy as np

img = np.array(Image.open("suspect.png"))

# Chi-square analysis on red channel
red = img[:,:,0].flatten()
# Count pairs of values (2k, 2k+1)
pairs = {}
for v in red:
    key = v // 2
    pairs.setdefault(key, [0, 0])
    pairs[key][v % 2] += 1

# In a natural image, pairs should be roughly equal
# In an LSB-embedded image, pairs become more equal (embedding randomizes LSBs)
```

## Quick Reference

```bash
# zsteg - automatic LSB detection (PNG/BMP only)
zsteg image.png
zsteg -a image.png              # Try all configurations
zsteg -b 1 -o xy image.png      # Specific bit plane and order

# stegsolve - GUI bit plane viewer
java -jar stegsolve.jar

# Python one-liner to check LSB
python3 -c "
from PIL import Image
p=Image.open('img.png').load()
bits=''.join(str(p[x,y][c]&1) for y in range(100) for x in range(100) for c in range(3))
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)).split(b'\x00')[0])
"
```

## Tools Used

- **zsteg** — automatic LSB steganography detector for PNG/BMP images
- **stegsolve** — Java GUI tool for visual bit plane analysis
- **Python Pillow (PIL)** — programmatic pixel manipulation and extraction
- **binwalk** — check for appended/embedded files
- **exiftool** — metadata inspection
- **NumPy** — statistical analysis of pixel values

## Lessons Learned

- LSB steganography hides data in the least significant bits of pixel values, which are imperceptible to the human eye
- `zsteg` should be your first tool for PNG/BMP images — it automatically checks dozens of configurations in seconds
- The most common configuration is `b1,rgb,lsb,xy` (bit 0, all RGB channels, LSB first, row order), but always check other combinations
- Understanding the bit/channel/order parameters lets you write custom extractors for non-standard embeddings
- PNG is the standard format for LSB stego because it uses lossless compression; JPEG's lossy compression destroys LSB data
- Do not forget to check the alpha channel in RGBA images
- The null terminator (`\x00`) typically marks the end of embedded data
- For detection without extraction, chi-square analysis can reveal whether an image has been modified
