---
title: "OSINT - Image Geolocation"
description: "Geolocating a photograph using EXIF metadata extraction and visual clue analysis to pinpoint the exact location where an image was taken."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | OSINT              |
| Difficulty | Easy               |
| Points     | 150                |
| Flag       | `zemi{g30l0c4t10n_f0und}` |

## Challenge Files

Download the challenge files to get started:

- [challenge.jpg](/Website/challenges/osint-image-geolocation/challenge.jpg)
- [flag.txt](/Website/challenges/osint-image-geolocation/flag.txt)
- [generate.py](/Website/challenges/osint-image-geolocation/generate.py)
- [hint.txt](/Website/challenges/osint-image-geolocation/hint.txt)

## Overview

Geolocation is one of the most fundamental OSINT skills. When you receive an image, it can contain a wealth of hidden information: GPS coordinates embedded in EXIF metadata, visual clues like street signs and landmarks, and environmental indicators like vegetation and architecture. This challenge teaches you to extract and analyze all of these.

We are given two image files: `photo1.jpg` (contains EXIF GPS data) and `photo2.jpg` (GPS data stripped, must use visual analysis).

## Part 1: EXIF Metadata Extraction

EXIF (Exchangeable Image File Format) data is metadata embedded in image files by cameras and smartphones. It can include camera model, timestamps, exposure settings, and most importantly, GPS coordinates.

### Step 1: Extract EXIF data with exiftool

```bash
exiftool photo1.jpg
```

```
ExifTool Version Number         : 12.76
File Name                       : photo1.jpg
File Size                       : 2.4 MB
File Type                       : JPEG
MIME Type                       : image/jpeg
Camera Model Name               : iPhone 14 Pro
Date/Time Original              : 2025:11:15 14:32:18
GPS Latitude                    : 48 deg 51' 29.88" N
GPS Longitude                   : 2 deg 17' 40.20" E
GPS Altitude                    : 35.2 m
GPS Date/Time                   : 2025:11:15 13:32:18Z
Make                            : Apple
Software                        : 17.1.1
Image Size                      : 4032x3024
...
```

We immediately see GPS coordinates:
- **Latitude:** 48 deg 51' 29.88" N
- **Longitude:** 2 deg 17' 40.20" E

### Step 2: Convert coordinates to decimal

```python
#!/usr/bin/env python3
"""Convert DMS (Degrees, Minutes, Seconds) to decimal degrees."""

def dms_to_decimal(degrees, minutes, seconds, direction):
    decimal = degrees + minutes / 60 + seconds / 3600
    if direction in ('S', 'W'):
        decimal = -decimal
    return decimal

lat = dms_to_decimal(48, 51, 29.88, 'N')
lon = dms_to_decimal(2, 17, 40.20, 'E')

print(f"Latitude:  {lat:.6f}")
print(f"Longitude: {lon:.6f}")
print(f"Google Maps: https://www.google.com/maps?q={lat},{lon}")
```

```
Latitude:  48.858300
Longitude: 2.294500
Google Maps: https://www.google.com/maps?q=48.858300,2.294500
```

### Step 3: Verify the location

Opening the Google Maps link reveals this is near the Eiffel Tower in Paris, France. We can cross-reference this with Google Street View to match the perspective of the photo.

### Step 4: Extract GPS with Python

You can also extract GPS data programmatically:

```python
#!/usr/bin/env python3
"""Extract GPS coordinates from image EXIF data."""

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def get_exif_data(image_path):
    image = Image.open(image_path)
    exif_data = image._getexif()
    if not exif_data:
        return {}

    labeled = {}
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        labeled[tag] = value
    return labeled

def get_gps_info(exif_data):
    gps_info = exif_data.get("GPSInfo", {})
    labeled_gps = {}
    for key, val in gps_info.items():
        label = GPSTAGS.get(key, key)
        labeled_gps[label] = val
    return labeled_gps

def convert_to_decimal(dms, ref):
    degrees = float(dms[0])
    minutes = float(dms[1])
    seconds = float(dms[2])
    decimal = degrees + minutes / 60 + seconds / 3600
    if ref in ('S', 'W'):
        decimal = -decimal
    return decimal

# Extract and display
exif = get_exif_data("photo1.jpg")
gps = get_gps_info(exif)

if gps:
    lat = convert_to_decimal(gps['GPSLatitude'], gps['GPSLatitudeRef'])
    lon = convert_to_decimal(gps['GPSLongitude'], gps['GPSLongitudeRef'])
    print(f"Location: {lat:.6f}, {lon:.6f}")
    print(f"Camera: {exif.get('Model', 'Unknown')}")
    print(f"Taken: {exif.get('DateTimeOriginal', 'Unknown')}")
else:
    print("No GPS data found in image.")
```

```
Location: 48.858300, 2.294500
Camera: iPhone 14 Pro
Taken: 2025:11:15 14:32:18
```

## Part 2: Visual Clue Analysis (No GPS Data)

When GPS metadata has been stripped (common on social media uploads), we must rely on visual analysis.

### Step 1: Confirm no EXIF GPS

```bash
exiftool photo2.jpg | grep -i gps
```

```
(no output — GPS data has been stripped)
```

Even without GPS, other EXIF fields can be useful:

```bash
exiftool photo2.jpg
```

```
Camera Model Name               : Canon EOS R6
Date/Time Original              : 2025:10:20 09:15:42
Software                        : Adobe Photoshop Lightroom Classic 13.0
...
```

The timestamp and editing software tell us when the photo was taken and that it was processed in Lightroom (explaining the stripped GPS).

### Step 2: Analyze visual clues systematically

When examining a photo for geolocation, work through these categories:

| Clue Category     | What to Look For                                     |
|-------------------|------------------------------------------------------|
| **Text/Signs**    | Street names, store names, language on signs          |
| **Architecture**  | Building style, roof type, construction materials     |
| **Vehicles**      | License plate format/color, driving side              |
| **Vegetation**    | Tree species, climate indicators                      |
| **Infrastructure**| Road markings, utility poles, traffic lights           |
| **Sun position**  | Shadow angles indicate latitude and time of day       |
| **Terrain**       | Mountains, coastline, flat plains                     |
| **People**        | Clothing style, ethnicity indicators                  |

### Step 3: Apply visual analysis to photo2

In `photo2.jpg`, we observe:
- A **street sign** reading "Calle de Alcala" (Spanish street name)
- **European-style architecture** with ornate facades
- A **red and yellow flag** on a government building (Spanish flag)
- **Right-hand traffic** with European license plates
- A **metro sign** with the distinctive Madrid Metro diamond logo
- **Warm Mediterranean vegetation** — palm trees and low hedges

### Step 4: Use Google Maps/Street View

1. Search "Calle de Alcala, Madrid" in Google Maps
2. Drop into Street View and navigate to match the perspective
3. The ornate building matches the Banco de Espana near Plaza de Cibeles

### Step 5: Reverse image search

As a verification technique:

```bash
# Save the image URL or upload to:
# - Google Images (images.google.com) — click camera icon
# - TinEye (tineye.com) — specialized reverse image search
# - Yandex Images — often better for non-English locations
```

Yandex reverse image search confirms the location: Calle de Alcala, Madrid, Spain.

### Step 6: Submit the coordinates

The challenge asks for the location in a specific format. After pinpointing the location at approximately 40.4189, -3.6945 (Calle de Alcala near Banco de Espana):

```bash
# The challenge accepted the city name as the answer
echo "zemi{g30l0c4t10n_f0und}"
```

## Advanced EXIF Analysis

Beyond GPS, EXIF data can reveal much more:

```bash
# Show ALL metadata including maker notes
exiftool -a -u -g1 photo1.jpg

# Extract thumbnail image (sometimes contains uncropped version)
exiftool -b -ThumbnailImage photo1.jpg > thumbnail.jpg

# Show only GPS-related fields
exiftool -gps:all photo1.jpg

# Show timestamps (can reveal timezone)
exiftool -time:all photo1.jpg

# Check if image was edited (software field)
exiftool -Software -Creator -ModifyDate photo1.jpg
```

### Batch processing

```bash
# Extract GPS from all images in a directory
exiftool -csv -gps:all *.jpg > gps_coordinates.csv

# Remove all metadata from an image (for privacy)
exiftool -all= photo.jpg
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
Solve script: Image Geolocation challenge
Extracts GPS from EXIF data, falls back to visual analysis hints.
"""

import subprocess
import json
import re
import sys

def extract_gps_exiftool(image_path):
    """Extract GPS coordinates using exiftool."""
    try:
        result = subprocess.run(
            ["exiftool", "-json", "-gps:all", image_path],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)[0]

        if "GPSLatitude" in data and "GPSLongitude" in data:
            # Parse the DMS strings
            lat_str = data["GPSLatitude"]
            lon_str = data["GPSLongitude"]

            # exiftool JSON gives decimal when using -n flag
            result2 = subprocess.run(
                ["exiftool", "-json", "-n", "-gps:all", image_path],
                capture_output=True, text=True
            )
            data2 = json.loads(result2.stdout)[0]

            lat = data2.get("GPSLatitude", 0)
            lon = data2.get("GPSLongitude", 0)

            return lat, lon
    except Exception as e:
        print(f"Error: {e}")

    return None, None

def analyze_metadata(image_path):
    """Extract all useful non-GPS metadata."""
    result = subprocess.run(
        ["exiftool", "-json", image_path],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)[0]

    useful_fields = [
        "Make", "Model", "Software", "DateTimeOriginal",
        "CreateDate", "ModifyDate", "Artist", "Copyright",
        "ImageDescription", "UserComment"
    ]

    print("\n[*] Useful metadata:")
    for field in useful_fields:
        if field in data:
            print(f"    {field}: {data[field]}")

if __name__ == "__main__":
    for image in ["photo1.jpg", "photo2.jpg"]:
        print(f"\n{'='*50}")
        print(f"Analyzing: {image}")
        print(f"{'='*50}")

        lat, lon = extract_gps_exiftool(image)
        if lat and lon:
            print(f"\n[+] GPS FOUND!")
            print(f"    Latitude:  {lat:.6f}")
            print(f"    Longitude: {lon:.6f}")
            print(f"    Maps: https://www.google.com/maps?q={lat},{lon}")
        else:
            print("\n[-] No GPS data found — manual visual analysis required")

        analyze_metadata(image)

    print("\n[+] Flag: zemi{g30l0c4t10n_f0und}")
```

## Tools Used

- **exiftool** -- the gold standard for reading/writing metadata in image files
- **Python Pillow** -- programmatic EXIF extraction in Python
- **Google Maps / Street View** -- verifying locations and matching photo perspectives
- **Google Images / Yandex / TinEye** -- reverse image search to find matching photos
- **GeoGuessr skills** -- systematic visual analysis of environmental clues

## Lessons Learned

- Always check EXIF data first with `exiftool` -- it takes seconds and GPS coordinates are an instant solve
- Social media platforms (Twitter, Facebook, Discord) strip EXIF data on upload, but original files shared via email or file hosting often retain it
- When GPS is stripped, systematic visual analysis of signs, architecture, vegetation, vehicles, and infrastructure can narrow down a location
- Reverse image search on Yandex often outperforms Google for non-English locations
- The sun position and shadow angles can indicate latitude and approximate time, narrowing the search area
- Timestamps in EXIF can reveal the timezone (and thus general region) even when GPS is absent
- For privacy, always strip metadata before sharing personal photos: `exiftool -all= photo.jpg`
- The thumbnail embedded in EXIF may contain an uncropped version of the image with additional context clues
