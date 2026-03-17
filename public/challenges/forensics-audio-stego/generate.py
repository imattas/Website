#!/usr/bin/env python3
"""
Forensics Challenge: Audio Steganography
Creates a WAV file with the flag text rendered as a spectrogram pattern.
When viewed in a spectrogram viewer (Audacity, Sonic Visualiser, sox),
the flag text becomes visible.

Usage: python3 generate.py
Output: challenge.wav
Dependencies: pip install numpy
"""

import struct
import os
import math

FLAG = "zemi{sp3ctr0gr4m_s3cr3ts}"

# WAV parameters
SAMPLE_RATE = 44100
DURATION = 4.0  # seconds
BITS_PER_SAMPLE = 16
NUM_CHANNELS = 1

# Spectrogram text rendering parameters
FREQ_MIN = 2000   # Hz - bottom of text band
FREQ_MAX = 8000   # Hz - top of text band
CHAR_WIDTH = 0.12  # seconds per character


# Simple 5x7 bitmap font for printable ASCII characters
FONT = {
    ' ': [0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000],
    '!': [0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00000, 0b00100],
    '{': [0b00010, 0b00100, 0b00100, 0b01000, 0b00100, 0b00100, 0b00010],
    '}': [0b01000, 0b00100, 0b00100, 0b00010, 0b00100, 0b00100, 0b01000],
    '_': [0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b11111],
    '0': [0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110],
    '1': [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
    '2': [0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111],
    '3': [0b01110, 0b10001, 0b00001, 0b00110, 0b00001, 0b10001, 0b01110],
    '4': [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010],
    '5': [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110],
    '6': [0b01110, 0b10001, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110],
    '7': [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
    '8': [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
    '9': [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b10001, 0b01110],
    'a': [0b00000, 0b00000, 0b01110, 0b00001, 0b01111, 0b10001, 0b01111],
    'b': [0b10000, 0b10000, 0b10110, 0b11001, 0b10001, 0b10001, 0b11110],
    'c': [0b00000, 0b00000, 0b01110, 0b10000, 0b10000, 0b10001, 0b01110],
    'd': [0b00001, 0b00001, 0b01101, 0b10011, 0b10001, 0b10001, 0b01111],
    'e': [0b00000, 0b00000, 0b01110, 0b10001, 0b11111, 0b10000, 0b01110],
    'f': [0b00110, 0b01001, 0b01000, 0b11100, 0b01000, 0b01000, 0b01000],
    'g': [0b00000, 0b01111, 0b10001, 0b10001, 0b01111, 0b00001, 0b01110],
    'h': [0b10000, 0b10000, 0b10110, 0b11001, 0b10001, 0b10001, 0b10001],
    'i': [0b00100, 0b00000, 0b01100, 0b00100, 0b00100, 0b00100, 0b01110],
    'j': [0b00010, 0b00000, 0b00110, 0b00010, 0b00010, 0b10010, 0b01100],
    'k': [0b10000, 0b10000, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010],
    'l': [0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
    'm': [0b00000, 0b00000, 0b11010, 0b10101, 0b10101, 0b10001, 0b10001],
    'n': [0b00000, 0b00000, 0b10110, 0b11001, 0b10001, 0b10001, 0b10001],
    'o': [0b00000, 0b00000, 0b01110, 0b10001, 0b10001, 0b10001, 0b01110],
    'p': [0b00000, 0b00000, 0b11110, 0b10001, 0b11110, 0b10000, 0b10000],
    'q': [0b00000, 0b00000, 0b01101, 0b10011, 0b01111, 0b00001, 0b00001],
    'r': [0b00000, 0b00000, 0b10110, 0b11001, 0b10000, 0b10000, 0b10000],
    's': [0b00000, 0b00000, 0b01110, 0b10000, 0b01110, 0b00001, 0b11110],
    't': [0b01000, 0b01000, 0b11100, 0b01000, 0b01000, 0b01001, 0b00110],
    'u': [0b00000, 0b00000, 0b10001, 0b10001, 0b10001, 0b10011, 0b01101],
    'v': [0b00000, 0b00000, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100],
    'w': [0b00000, 0b00000, 0b10001, 0b10001, 0b10101, 0b10101, 0b01010],
    'x': [0b00000, 0b00000, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001],
    'y': [0b00000, 0b00000, 0b10001, 0b10001, 0b01111, 0b00001, 0b01110],
    'z': [0b00000, 0b00000, 0b11111, 0b00010, 0b00100, 0b01000, 0b11111],
}


def text_to_bitmap(text):
    """Convert text to a 2D bitmap array using the font."""
    rows = 7
    bitmap = [[] for _ in range(rows)]
    for ch in text:
        glyph = FONT.get(ch, FONT.get(' '))
        for r in range(rows):
            for bit in range(4, -1, -1):
                bitmap[r].append(1 if (glyph[r] >> bit) & 1 else 0)
            bitmap[r].append(0)  # 1-pixel gap between chars
    return bitmap


def generate_wav(bitmap):
    """Generate WAV audio data where active pixels become sine tones."""
    cols = len(bitmap[0])
    rows = len(bitmap)
    total_samples = int(SAMPLE_RATE * DURATION)

    samples_per_col = total_samples // cols
    freq_step = (FREQ_MAX - FREQ_MIN) / (rows - 1)

    audio = [0.0] * total_samples

    for col_idx in range(cols):
        start_sample = col_idx * samples_per_col
        end_sample = start_sample + samples_per_col
        if end_sample > total_samples:
            end_sample = total_samples

        for row_idx in range(rows):
            if bitmap[row_idx][col_idx]:
                # Map row to frequency (top row = high freq)
                freq = FREQ_MAX - row_idx * freq_step
                amplitude = 0.3
                for s in range(start_sample, end_sample):
                    t = s / SAMPLE_RATE
                    audio[s] += amplitude * math.sin(2 * math.pi * freq * t)

    # Normalize
    max_val = max(abs(s) for s in audio) or 1.0
    scale = 32000 / max_val
    return [int(s * scale) for s in audio]


def write_wav(filepath, samples):
    """Write a 16-bit mono WAV file."""
    num_samples = len(samples)
    data_size = num_samples * 2  # 16-bit
    file_size = 36 + data_size

    with open(filepath, "wb") as f:
        # RIFF header
        f.write(b"RIFF")
        f.write(struct.pack("<I", file_size))
        f.write(b"WAVE")

        # fmt chunk
        f.write(b"fmt ")
        f.write(struct.pack("<I", 16))       # chunk size
        f.write(struct.pack("<H", 1))        # PCM format
        f.write(struct.pack("<H", NUM_CHANNELS))
        f.write(struct.pack("<I", SAMPLE_RATE))
        f.write(struct.pack("<I", SAMPLE_RATE * NUM_CHANNELS * BITS_PER_SAMPLE // 8))
        f.write(struct.pack("<H", NUM_CHANNELS * BITS_PER_SAMPLE // 8))
        f.write(struct.pack("<H", BITS_PER_SAMPLE))

        # data chunk
        f.write(b"data")
        f.write(struct.pack("<I", data_size))
        for s in samples:
            clamped = max(-32768, min(32767, s))
            f.write(struct.pack("<h", clamped))


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.wav")

    print(f"[*] Rendering flag text as spectrogram bitmap...")
    bitmap = text_to_bitmap(FLAG)
    print(f"    Bitmap: {len(bitmap)} rows x {len(bitmap[0])} cols")

    print(f"[*] Generating audio ({DURATION}s, {SAMPLE_RATE}Hz)...")
    samples = generate_wav(bitmap)

    print(f"[*] Writing WAV file...")
    write_wav(output_path, samples)

    print(f"[+] Created {output_path}")
    print()
    print("To solve:")
    print("  # Open in Audacity -> View -> Spectrogram")
    print("  # Or: sox challenge.wav -n spectrogram -o spec.png")
    print("  # The flag text appears visually in the spectrogram")


if __name__ == "__main__":
    main()
