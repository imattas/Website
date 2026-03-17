---
title: "Misc - QR Code Recovery"
description: "Reconstructing and decoding a damaged QR code by understanding its structure, error correction, and using Python to repair missing finder patterns."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Easy         |
| Points     | 100          |
| Flag       | `zemi{qr_d3c0d3_m4st3r}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/misc-qr-code/flag.txt)
- [generate.py](/Website/challenges/misc-qr-code/generate.py)

## Reconnaissance

We are given an image file `broken_qr.png`:

```bash
file broken_qr.png
```

```
broken_qr.png: PNG image data, 290 x 290, 1-bit grayscale, non-interlaced
```

Opening the image reveals a QR code with two of its three finder patterns (the large squares in the corners) obscured by black rectangles. Standard QR scanners cannot read it.

```bash
zbarimg broken_qr.png
```

```
scanned 0 barcode symbols from 1 images
```

No luck — the damage is too severe for the scanner. We need to repair it.

## Analysis

### QR Code Structure

A QR code has several key structural components:

- **Finder patterns**: Three 7x7 squares in the top-left, top-right, and bottom-left corners. These let scanners detect and orient the code.
- **Alignment patterns**: Smaller 5x5 squares that help with perspective correction (present in version 2+).
- **Timing patterns**: Alternating black/white strips connecting the finder patterns.
- **Format information**: 15 bits near the finder patterns encoding error correction level and mask pattern.
- **Data and error correction**: The actual payload, encoded with Reed-Solomon error correction.

Error correction levels:
| Level | Recovery Capacity |
|-------|-------------------|
| L     | ~7% damage        |
| M     | ~15% damage       |
| Q     | ~25% damage       |
| H     | ~30% damage       |

The finder patterns are fixed and identical on every QR code, so we can redraw them manually.

## Step-by-Step Walkthrough

### Step 1: Identify what is damaged

Looking at the image, the top-right and bottom-left finder patterns have been blacked out. The top-left finder pattern is intact.

A finder pattern is always a 7x7 module grid:

```
#######
#.....#
#.###.#
#.###.#
#.###.#
#.....#
#######
```

Where `#` is black and `.` is white. There is also a 1-module white separator border around each finder pattern.

### Step 2: Determine module size

By examining the intact top-left finder pattern, we measure that each module (smallest square unit) is 10x10 pixels. The QR code is version 2 (25x25 modules) at 290x290 pixels (25 modules * 10 pixels + borders).

### Step 3: Repair with Python

```python
from PIL import Image, ImageDraw

img = Image.open("broken_qr.png")
draw = ImageDraw.Draw(img)
module = 10  # pixels per module

def draw_finder_pattern(draw, x, y, mod):
    """Draw a 7x7 finder pattern at module coordinates (x, y)."""
    # Outer black 7x7 square
    draw.rectangle([x*mod, y*mod, (x+7)*mod-1, (y+7)*mod-1], fill="black")
    # Inner white 5x5 square
    draw.rectangle([(x+1)*mod, (y+1)*mod, (x+6)*mod-1, (y+6)*mod-1], fill="white")
    # Center black 3x3 square
    draw.rectangle([(x+2)*mod, (y+2)*mod, (x+5)*mod-1, (y+5)*mod-1], fill="black")

def draw_separator(draw, x, y, w, h, mod):
    """Draw white separator area."""
    draw.rectangle([x*mod, y*mod, (x+w)*mod-1, (y+h)*mod-1], fill="white")

# QR version 2 = 25x25 modules
size = 25

# Top-right finder pattern at module position (18, 0)
# Clear the damaged area first (including separator)
draw.rectangle([17*module, 0, 25*module-1, 8*module-1], fill="white")
draw_finder_pattern(draw, 18, 0, module)

# Bottom-left finder pattern at module position (0, 18)
draw.rectangle([0, 17*module, 8*module-1, 25*module-1], fill="white")
draw_finder_pattern(draw, 0, 18, module)

# Redraw timing patterns (row 6 and column 6, alternating black/white)
for i in range(8, 17):
    color = "black" if i % 2 == 0 else "white"
    # Horizontal timing pattern (row 6)
    draw.rectangle([i*module, 6*module, (i+1)*module-1, 7*module-1], fill=color)
    # Vertical timing pattern (column 6)
    draw.rectangle([6*module, i*module, 7*module-1, (i+1)*module-1], fill=color)

img.save("repaired_qr.png")
print("[+] Saved repaired QR code")
```

### Step 4: Decode the repaired QR code

```bash
zbarimg repaired_qr.png
```

```
QR-Code:zemi{qr_d3c0d3_m4st3r}
scanned 1 barcode symbols from 1 images
```

Alternatively, decode with Python:

```python
from pyzbar.pyzbar import decode
from PIL import Image

img = Image.open("repaired_qr.png")
results = decode(img)
for r in results:
    print(f"Type: {r.type}")
    print(f"Data: {r.data.decode()}")
```

```
Type: QRCODE
Data: zemi{qr_d3c0d3_m4st3r}
```

## Other QR Code CTF Techniques

### XOR-combined QR codes

Sometimes two QR code images must be XOR'd together:

```python
from PIL import Image
import numpy as np

img1 = np.array(Image.open("qr_part1.png"))
img2 = np.array(Image.open("qr_part2.png"))

# XOR the pixel values
result = np.bitwise_xor(img1, img2)
Image.fromarray(result).save("qr_combined.png")
```

### QR codes hidden in image channels

A QR code may be embedded in a single color channel or bit plane:

```python
from PIL import Image
import numpy as np

img = np.array(Image.open("suspicious.png"))

# Extract just the red channel
red = img[:, :, 0]

# Check the least significant bit
lsb = (red & 1) * 255
Image.fromarray(lsb.astype(np.uint8)).save("hidden_qr.png")
```

### Animated QR codes (GIF frames)

```python
from PIL import Image

gif = Image.open("animated.gif")
frame = 0
while True:
    try:
        gif.seek(frame)
        gif.save(f"frame_{frame}.png")
        frame += 1
    except EOFError:
        break

# Decode each frame
from pyzbar.pyzbar import decode
for i in range(frame):
    img = Image.open(f"frame_{i}.png")
    results = decode(img)
    for r in results:
        print(f"Frame {i}: {r.data.decode()}")
```

### Generating QR codes for testing

```python
import qrcode

qr = qrcode.QRCode(
    version=2,
    error_correction=qrcode.constants.ERROR_CORRECT_H,  # 30% recovery
    box_size=10,
    border=4,
)
qr.add_data("zemi{test_flag}")
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
img.save("test_qr.png")
```

## Tools Used

- `zbarimg` — command-line QR/barcode decoder
- Python `pyzbar` — programmatic barcode decoding
- Python `qrcode` — QR code generation
- Python `Pillow` (PIL) — image manipulation and repair
- `zxing` — alternative decoder (useful when zbar fails)

## Lessons Learned

- QR codes have a fixed structure — finder patterns, timing patterns, and alignment patterns are always in the same positions and can be reconstructed
- Error correction can recover significant damage (up to 30% at level H), but finder patterns must be intact for scanners to locate the code
- Always check for QR codes hidden in individual color channels, bit planes, or animation frames
- When manual repair fails, try rotating or mirroring the image — the scanner may expect a specific orientation
- The `pyzbar` library is more forgiving than `zbarimg` for slightly damaged codes
- XOR two QR images together when a challenge provides "two halves" of a code
