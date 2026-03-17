---
title: "Forensics - Audio Steganography"
description: "Uncover a secret message hidden in a WAV file's spectrogram using audio analysis techniques."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                      |
|-------------|--------------------------------------------|
| Category    | Forensics                                  |
| Points      | 200                                        |
| Difficulty  | Medium                                     |
| Flag Format | `zemi{...}`                                |
| Files Given | `transmission.wav` (audio file, 2.1 MB)   |
| Tools Used  | Audacity, SoX, steghide, Python            |

## Challenge Files

Download the challenge files to get started:

- [challenge.wav](/Website/challenges/forensics-audio-stego/challenge.wav)
- [flag.txt](/Website/challenges/forensics-audio-stego/flag.txt)
- [generate.py](/Website/challenges/forensics-audio-stego/generate.py)
- [hint.txt](/Website/challenges/forensics-audio-stego/hint.txt)

## Audio Steganography Overview

Audio steganography hides information within audio files. There are many techniques:

- **Spectrogram embedding** -- An image or text is drawn in the frequency domain, visible only when viewing the spectrogram
- **LSB (Least Significant Bit)** -- Data is encoded in the lowest bits of each audio sample
- **DTMF tones** -- Phone dial tones encode numbers
- **Morse code** -- Beeps and pauses represent dots and dashes
- **Steghide/OpenStego** -- Tools that embed files within audio using passphrase encryption
- **SSTV (Slow Scan TV)** -- Images transmitted as audio signals (used in ham radio and space)

## Walkthrough

### Step 1: Initial Analysis

Let's examine the audio file:

```bash
$ file transmission.wav
transmission.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo, 44100 Hz

$ soxi transmission.wav
Input File     : 'transmission.wav'
Channels       : 2
Sample Rate    : 44100
Precision      : 16-bit
Duration       : 00:00:12.50 = 551250 samples
File Size      : 2.10M
Bit Rate       : 1.41M
Sample Encoding: 16-bit Signed Integer PCM

$ exiftool transmission.wav
File Name                       : transmission.wav
File Size                       : 2.1 MB
File Type                       : WAV
MIME Type                       : audio/x-wav
Encoding                        : Microsoft PCM
Num Channels                    : 2
Sample Rate                     : 44100
Bits Per Sample                 : 16
Duration                        : 12.50 s
```

A 12.5-second stereo WAV file. Let's listen to it -- it sounds like white noise with some high-pitched tones. That's a strong hint for spectrogram analysis.

### Step 2: Check for Steghide Data

Before doing complex analysis, try the easy tools first:

```bash
# Try steghide with empty passphrase
$ steghide extract -sf transmission.wav -p ""
steghide: could not extract any data with that passphrase!

# Try common passphrases
$ steghide extract -sf transmission.wav -p "password"
steghide: could not extract any data with that passphrase!

$ steghide extract -sf transmission.wav -p "secret"
steghide: could not extract any data with that passphrase!
```

No steghide data with common passwords. Let's check the spectrogram.

### Step 3: Spectrogram Analysis with SoX

Generate a spectrogram image from the audio:

```bash
$ sox transmission.wav -n spectrogram -o spectrogram.png

$ file spectrogram.png
spectrogram.png: PNG image data, 800 x 513, 8-bit/color RGBA
```

Open `spectrogram.png` and you'll see text written in the high frequencies (typically above 15kHz):

```
The spectrogram shows:  zemi{sp3ctr0gr4m_s3cr3ts}
```

The text appears as bright patterns against the dark background in the 16-20 kHz range. This is invisible when listening (most people can't hear above 16kHz) but clearly visible in the spectrogram.

**Flag: `zemi{sp3ctr0gr4m_s3cr3ts}`**

### Step 4: Spectrogram Analysis with Audacity (GUI Method)

If you prefer a visual tool:

1. Open `transmission.wav` in Audacity
2. Click the track name dropdown (where it says "transmission") at the top-left of the waveform
3. Select **Spectrogram** from the dropdown menu
4. To see more detail, go to the dropdown again and choose **Spectrogram Settings**
5. Set the **Max Frequency** to 22050 Hz (Nyquist frequency)
6. Increase the **Window Size** to 2048 or 4096 for better frequency resolution
7. The flag text becomes clearly visible in the high-frequency bands

### Step 5: Spectrogram with Python (Matplotlib)

You can also script spectrogram generation:

```python
#!/usr/bin/env python3
"""Generate a high-resolution spectrogram from a WAV file."""

import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
from scipy import signal

# Read the WAV file
sample_rate, data = wavfile.read("transmission.wav")

# Use only one channel if stereo
if len(data.shape) > 1:
    data = data[:, 0]

# Generate spectrogram
frequencies, times, Sxx = signal.spectrogram(
    data,
    fs=sample_rate,
    nperseg=4096,       # Window size (higher = better freq resolution)
    noverlap=3072,      # Overlap between windows
    nfft=8192           # FFT size
)

# Plot
plt.figure(figsize=(16, 8))
plt.pcolormesh(times, frequencies, 10 * np.log10(Sxx + 1e-10),
               shading='gouraud', cmap='inferno')
plt.ylabel('Frequency (Hz)')
plt.xlabel('Time (s)')
plt.title('Spectrogram - transmission.wav')
plt.colorbar(label='Power (dB)')
plt.ylim(0, sample_rate // 2)  # Show up to Nyquist frequency
plt.tight_layout()
plt.savefig('spectrogram_python.png', dpi=200)
plt.show()

print("[*] Spectrogram saved to spectrogram_python.png")
print("[*] Look for text or patterns in the high-frequency region (15-22 kHz)")
```

### Other Audio Steganography Techniques

While the challenge flag was in the spectrogram, here are techniques for other audio forensics challenges:

#### DTMF Tone Decoding

DTMF (Dual-Tone Multi-Frequency) tones are the sounds phone keypads make. If you hear touch-tone sounds:

```bash
# Using multimon-ng to decode DTMF
$ multimon-ng -t wav -a DTMF transmission.wav
DTMF: 7
DTMF: 3
DTMF: 6
DTMF: 4
```

#### Morse Code

If you hear beeps with pauses:

```bash
# Use the morse2ascii tool or decode manually
# Short beep = dot, long beep = dash
# Short pause = between letters, long pause = between words
```

#### LSB Steganography

Data hidden in the least significant bits of audio samples:

```python
#!/usr/bin/env python3
"""Extract LSB-encoded data from a WAV file."""

import wave
import struct

def extract_lsb(wav_file):
    """Extract hidden data from LSB of audio samples."""
    with wave.open(wav_file, 'rb') as audio:
        n_frames = audio.getnframes()
        n_channels = audio.getnchannels()
        sample_width = audio.getsampwidth()
        frames = audio.readframes(n_frames)

    # Unpack samples (16-bit signed)
    fmt = f"<{n_frames * n_channels}h"
    samples = struct.unpack(fmt, frames)

    # Extract LSBs
    bits = []
    for sample in samples:
        bits.append(sample & 1)

    # Convert bits to bytes
    message = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        message.append(byte)
        # Stop at null terminator
        if byte == 0:
            break

    return message.decode('utf-8', errors='ignore')

result = extract_lsb("transmission.wav")
print(f"Extracted: {result}")
```

#### SSTV (Slow Scan TV)

If the audio sounds like screeching/warbling tones (similar to a fax machine):

```bash
# Install QSSTV on Linux
$ sudo apt install qsstv

# Or use the Python sstv library
$ pip install sstv
$ sstv -d transmission.wav -o sstv_output.png
```

SSTV encodes images as audio signals. The decoded image may contain the flag.

## Solve Script

```python
#!/usr/bin/env python3
"""Audio steganography solver - tries multiple extraction methods."""

import subprocess
import re
import os

WAV_FILE = "transmission.wav"
FLAG_PATTERN = r"zemi\{[^}]+\}"

def try_strings():
    """Check if flag is in raw file data."""
    result = subprocess.run(
        ["strings", WAV_FILE], capture_output=True, text=True
    )
    match = re.search(FLAG_PATTERN, result.stdout)
    if match:
        return f"strings: {match.group()}"
    return None

def try_steghide():
    """Try steghide with common passwords."""
    passwords = ["", "password", "secret", "ctf", "flag", "stego"]
    for pw in passwords:
        result = subprocess.run(
            ["steghide", "extract", "-sf", WAV_FILE, "-p", pw, "-f",
             "-xf", "/tmp/steghide_out.txt"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            with open("/tmp/steghide_out.txt") as f:
                content = f.read()
            match = re.search(FLAG_PATTERN, content)
            if match:
                return f"steghide (pw='{pw}'): {match.group()}"
    return None

def try_spectrogram():
    """Generate spectrogram image."""
    subprocess.run([
        "sox", WAV_FILE, "-n", "spectrogram",
        "-x", "1600", "-y", "513", "-z", "80",
        "-o", "spectrogram.png"
    ])
    print("[*] Spectrogram saved to spectrogram.png - check visually for text")
    return None  # Requires visual inspection

def main():
    print("[*] Audio steganography analysis")
    print(f"[*] File: {WAV_FILE}\n")

    # Try automated methods first
    for name, func in [("Strings", try_strings), ("Steghide", try_steghide)]:
        print(f"[*] Trying {name}...")
        result = func()
        if result:
            print(f"[+] FLAG FOUND via {result}")
            return

    # Generate spectrogram for visual inspection
    print("[*] Generating spectrogram for visual inspection...")
    try_spectrogram()
    print("[!] Open spectrogram.png and look for text in high frequencies")

if __name__ == "__main__":
    main()
```

## Tools Used

| Tool        | Purpose                                               |
|-------------|-------------------------------------------------------|
| SoX         | Audio processing and spectrogram generation            |
| Audacity    | GUI audio editor with spectrogram view                 |
| steghide    | Extract data embedded with steghide                    |
| exiftool    | Check audio file metadata                              |
| multimon-ng | Decode DTMF tones, Morse code, and other signals       |
| Python      | Scripted spectrogram generation and LSB extraction     |
| QSSTV       | Decode SSTV (Slow Scan TV) signals from audio          |

## Lessons Learned

1. **Listen first, then look.** Play the audio file. If it sounds like noise or has unusual high-pitched tones, it's likely a spectrogram challenge. If it has beeping patterns, think Morse code or DTMF.

2. **Spectrograms reveal hidden images.** Data can be painted into the frequency domain of audio. The human ear might not notice it (especially in ultrasonic ranges above 16kHz), but a spectrogram view makes it immediately visible.

3. **Try steghide early.** Many CTF audio challenges use `steghide` with simple or empty passwords. Always try it with common passphrases before moving to more complex analysis.

4. **SoX is the command-line Swiss Army knife.** The `sox` command can generate spectrograms, convert formats, mix channels, and manipulate audio without needing a GUI. The command `sox input.wav -n spectrogram -o output.png` is your best friend.

5. **Multiple techniques may be layered.** Advanced challenges combine techniques -- you might find a steghide passphrase in the spectrogram, or SSTV-encoded audio hidden via LSB steganography. Always check for multiple layers.

6. **Window size matters for spectrograms.** A larger FFT window size gives better frequency resolution but worse time resolution. Try different settings (1024, 2048, 4096, 8192) if text appears blurry.
