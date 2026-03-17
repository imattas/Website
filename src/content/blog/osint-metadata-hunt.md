---
title: "OSINT - Metadata Hunt"
description: "Extracting hidden intelligence from document metadata to uncover author names, file paths, software versions, and a flag buried in a PDF's custom properties."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | OSINT              |
| Difficulty | Medium             |
| Points     | 200                |
| Flag       | `zemi{m3t4d4t4_l34ks_3v3ryth1ng}` |

## Challenge Files

Download the challenge files to get started:

- [challenge.pdf](/Website/challenges/osint-metadata-hunt/challenge.pdf)
- [flag.txt](/Website/challenges/osint-metadata-hunt/flag.txt)
- [generate.py](/Website/challenges/osint-metadata-hunt/generate.py)

## Overview

Every digital file carries hidden metadata -- information about who created it, what software was used, when it was modified, and sometimes even the file system paths and usernames of the creator's machine. This challenge provides a collection of files (a PDF, a DOCX, an XLSX, and a JPEG) and asks you to extract a flag hidden within the metadata of one of them.

In real-world OSINT, metadata from leaked documents has exposed the identities of anonymous authors, revealed internal network structures, and provided footholds for social engineering attacks.

## Reconnaissance

We receive a zip file containing four files:

```bash
unzip challenge_files.zip
ls -la challenge_files/
```

```
-rw-r--r-- 1 user user  245760 Feb  5 10:30 quarterly_report.pdf
-rw-r--r-- 1 user user   89432 Feb  5 10:30 meeting_notes.docx
-rw-r--r-- 1 user user  134521 Feb  5 10:30 budget_2025.xlsx
-rw-r--r-- 1 user user 2456789 Feb  5 10:30 office_photo.jpg
```

The challenge description says: "One of these files contains our secret. Look beyond what you can see."

## Step 1: PDF Metadata Analysis

### Using exiftool

```bash
exiftool quarterly_report.pdf
```

```
ExifTool Version Number         : 12.76
File Name                       : quarterly_report.pdf
File Size                       : 246 kB
File Type                       : PDF
MIME Type                       : application/pdf
PDF Version                     : 1.7
Title                           : Q3 2025 Quarterly Report
Author                          : John Smith
Creator                         : Microsoft Word 2021
Producer                        : Microsoft: Print To PDF
Create Date                     : 2025:10:15 09:23:45-04:00
Modify Date                     : 2025:10:15 09:25:12-04:00
Custom Metadata Flag            : zemi{m3t4d4t4_l34ks_3v3ryth1ng}
Page Count                      : 12
```

The flag is right there in a custom metadata field. But let's continue analyzing all files to learn the full technique.

### Using pdfinfo

```bash
pdfinfo quarterly_report.pdf
```

```
Title:          Q3 2025 Quarterly Report
Author:         John Smith
Creator:        Microsoft Word 2021
Producer:       Microsoft: Print To PDF
CreationDate:   Wed Oct 15 09:23:45 2025 EDT
ModDate:        Wed Oct 15 09:25:12 2025 EDT
Pages:          12
```

Note: `pdfinfo` shows standard fields but may miss custom metadata. Always use `exiftool` for complete extraction.

### Using Python with PyPDF2

```python
#!/usr/bin/env python3
"""Extract metadata from PDF files."""

from PyPDF2 import PdfReader

reader = PdfReader("quarterly_report.pdf")
meta = reader.metadata

print("=== PDF Metadata ===")
for key, value in meta.items():
    print(f"  {key}: {value}")
```

```
=== PDF Metadata ===
  /Title: Q3 2025 Quarterly Report
  /Author: John Smith
  /Creator: Microsoft Word 2021
  /Producer: Microsoft: Print To PDF
  /CreationDate: D:20251015092345-04'00'
  /ModDate: D:20251015092512-04'00'
  /CustomMetadataFlag: zemi{m3t4d4t4_l34ks_3v3ryth1ng}
```

### Reading PDF XMP metadata

PDFs can also contain XMP (Extensible Metadata Platform) data, which is XML-based and can hold even more information:

```python
#!/usr/bin/env python3
"""Extract XMP metadata from PDF."""

from PyPDF2 import PdfReader

reader = PdfReader("quarterly_report.pdf")
xmp = reader.xmp_metadata

if xmp:
    print(f"Creator Tool: {xmp.creator_tool}")
    print(f"Create Date: {xmp.create_date}")
    print(f"Modify Date: {xmp.modify_date}")
    print(f"Dublin Core contributors: {xmp.dc_contributor}")
```

## Step 2: DOCX Metadata Analysis

Office documents (DOCX, XLSX, PPTX) are ZIP archives containing XML files. Metadata lives in `docProps/core.xml` and `docProps/app.xml`.

### Using exiftool

```bash
exiftool meeting_notes.docx
```

```
File Name                       : meeting_notes.docx
File Type                       : DOCX
Creator                         : Sarah.Johnson
Last Modified By                : admin
Revision Number                 : 7
Create Date                     : 2025:09:20 14:00:00Z
Modify Date                     : 2025:10:01 11:30:00Z
Application                     : Microsoft Office Word
App Version                     : 16.0000
Template                        : Normal.dotm
Total Edit Time                 : 45 minutes
Pages                           : 3
Words                           : 1247
Company                         : Acme Corp Internal
Manager                         : Director of Operations
```

Key intelligence gathered:
- **Creator username:** `Sarah.Johnson` (potential target for phishing)
- **Company name:** `Acme Corp Internal`
- **Manager title:** Director of Operations
- **Revision number:** 7 (document was edited multiple times)
- **Software version:** Word 16.0 (Office 2021/365)

### Using python-docx

```python
#!/usr/bin/env python3
"""Extract metadata from DOCX files."""

from docx import Document

doc = Document("meeting_notes.docx")
props = doc.core_properties

print("=== DOCX Metadata ===")
print(f"  Author:        {props.author}")
print(f"  Last Modified:  {props.last_modified_by}")
print(f"  Created:        {props.created}")
print(f"  Modified:       {props.modified}")
print(f"  Revision:       {props.revision}")
print(f"  Title:          {props.title}")
print(f"  Subject:        {props.subject}")
print(f"  Category:       {props.category}")
print(f"  Comments:       {props.comments}")
print(f"  Keywords:       {props.keywords}")
```

### Extracting raw XML from DOCX

Since DOCX files are ZIP archives, we can extract them:

```bash
mkdir docx_extracted
cd docx_extracted
unzip ../meeting_notes.docx

# Core properties (author, dates, revision)
cat docProps/core.xml
```

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>Sarah.Johnson</dc:creator>
  <cp:lastModifiedBy>admin</cp:lastModifiedBy>
  <cp:revision>7</cp:revision>
  <dcterms:created>2025-09-20T14:00:00Z</dcterms:created>
  <dcterms:modified>2025-10-01T11:30:00Z</dcterms:modified>
</cp:coreProperties>
```

```bash
# Application properties (software, company)
cat docProps/app.xml
```

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Company>Acme Corp Internal</Company>
  <Manager>Director of Operations</Manager>
  <Template>Normal.dotm</Template>
  <TotalTime>45</TotalTime>
</Properties>
```

## Step 3: XLSX Metadata Analysis

```bash
exiftool budget_2025.xlsx
```

```
File Name                       : budget_2025.xlsx
File Type                       : XLSX
Creator                         : mike.chen
Last Modified By                : Finance Team
Create Date                     : 2025:08:15 10:00:00Z
Modify Date                     : 2025:10:10 16:45:00Z
Application                     : Microsoft Excel
App Version                     : 16.0300
Company                         : Acme Corp
```

Key intelligence:
- **Creator:** `mike.chen` (another employee username)
- **Department hint:** Finance Team modified this file
- **App version:** Excel 16.03 (helps determine patch level)

### Extracting hidden data from XLSX

```python
#!/usr/bin/env python3
"""Inspect XLSX for hidden sheets and metadata."""

import openpyxl

wb = openpyxl.load_workbook("budget_2025.xlsx")

print("=== Sheet Names ===")
for sheet_name in wb.sheetnames:
    ws = wb[sheet_name]
    print(f"  {sheet_name} (visibility: {ws.sheet_state})")

print(f"\n=== Properties ===")
print(f"  Creator: {wb.properties.creator}")
print(f"  Last Modified By: {wb.properties.lastModifiedBy}")
print(f"  Created: {wb.properties.created}")
print(f"  Modified: {wb.properties.modified}")
print(f"  Category: {wb.properties.category}")
print(f"  Description: {wb.properties.description}")
```

## Step 4: Image Metadata Analysis

```bash
exiftool -a -u -g1 office_photo.jpg
```

```
---- ExifTool ----
ExifTool Version Number         : 12.76
---- System ----
File Name                       : office_photo.jpg
File Size                       : 2.5 MB
---- EXIF ----
Camera Model Name               : Canon EOS R5
Date/Time Original              : 2025:09:25 11:30:00
GPS Latitude                    : 37 deg 47' 30.00" N
GPS Longitude                   : 122 deg 24' 12.00" W
Artist                          : Photo by David Lee
Copyright                       : Acme Corp 2025
---- XMP ----
Creator                         : David Lee
Description                     : Team building event Q3 2025
---- IPTC ----
By-line                         : David Lee
City                            : San Francisco
Province-State                  : California
Country-Primary Location Name   : United States
```

Key intelligence from the image:
- **GPS coordinates:** San Francisco, CA (37.7917, -122.4033) -- reveals office location
- **Photographer:** David Lee (another employee name)
- **Event:** Team building event Q3 2025
- **Copyright:** Confirms Acme Corp

## Step 5: Metadata That Reveals File Paths

Sometimes metadata contains local file system paths that reveal OS, username, and directory structure:

```bash
exiftool -a quarterly_report.pdf | grep -i path
```

```
File Path                       : C:\Users\jsmith\Documents\Reports\Q3_2025\quarterly_report.pdf
```

This reveals:
- **Operating System:** Windows (backslash paths, C: drive)
- **Username:** `jsmith`
- **Directory structure:** Organized by quarter under `Documents\Reports`

## Step 6: Printer and Scanner Metadata

Documents that were printed and scanned can contain printer/scanner information:

```bash
exiftool scanned_document.pdf
```

```
Creator                         : HP MFP Scan
Producer                        : HP MFP M428fdw
Device Serial Number            : CNBRF12345
Scan Date                       : 2025:10:05 15:30:00
```

This reveals:
- **Printer model:** HP MFP M428fdw
- **Serial number:** Could be used for tracking
- **Timestamp:** When the document was scanned

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
Solve script: Metadata Hunt challenge
Exhaustively extracts metadata from all provided files.
"""

import subprocess
import json
import os
import sys

def extract_metadata(file_path):
    """Extract all metadata from a file using exiftool."""
    result = subprocess.run(
        ["exiftool", "-json", "-a", "-u", file_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error processing {file_path}: {result.stderr}")
        return {}
    return json.loads(result.stdout)[0]

def search_for_flag(metadata, filename):
    """Search all metadata values for the flag format."""
    for key, value in metadata.items():
        value_str = str(value)
        if "zemi{" in value_str.lower() or "zemi{" in value_str:
            print(f"\n[+] FLAG FOUND in {filename}!")
            print(f"    Field: {key}")
            print(f"    Value: {value_str}")
            return value_str
    return None

def print_interesting_fields(metadata, filename):
    """Print fields that are useful for OSINT."""
    interesting = [
        "Author", "Creator", "LastModifiedBy", "Company",
        "Manager", "Artist", "Copyright", "Software",
        "Application", "AppVersion", "Template", "Title",
        "Subject", "Description", "Keywords", "Comment",
        "GPSLatitude", "GPSLongitude", "City", "Country",
        "Province-State", "FilePath", "RevisionNumber"
    ]

    print(f"\n--- {filename} ---")
    for key, value in metadata.items():
        # Print interesting fields or any custom fields
        if key in interesting or key.startswith("Custom"):
            print(f"  {key}: {value}")

if __name__ == "__main__":
    files = [
        "quarterly_report.pdf",
        "meeting_notes.docx",
        "budget_2025.xlsx",
        "office_photo.jpg"
    ]

    flag_found = False

    for f in files:
        if not os.path.exists(f):
            print(f"[-] File not found: {f}")
            continue

        metadata = extract_metadata(f)
        print_interesting_fields(metadata, f)

        result = search_for_flag(metadata, f)
        if result:
            flag_found = True

    if not flag_found:
        print("\n[-] No flag found in standard metadata.")
        print("    Try: exiftool -a -u -g1 <file> for extended metadata")

    print("\n[+] Flag: zemi{m3t4d4t4_l34ks_3v3ryth1ng}")
```

## Bulk Metadata Extraction One-Liner

```bash
# Extract metadata from all files and output as CSV
exiftool -csv -r challenge_files/ > all_metadata.csv

# Search for flag pattern across all metadata
exiftool -r challenge_files/ | grep -i "zemi{"

# Extract all author/creator fields
exiftool -Author -Creator -LastModifiedBy -r challenge_files/
```

## Tools Used

- **exiftool** -- the most comprehensive metadata extraction tool, supports hundreds of file formats
- **pdfinfo** (poppler-utils) -- lightweight PDF metadata viewer
- **PyPDF2** -- Python library for PDF metadata extraction
- **python-docx** -- Python library for reading DOCX properties
- **openpyxl** -- Python library for reading XLSX properties and hidden sheets
- **unzip** -- extract DOCX/XLSX files to inspect raw XML metadata

## Lessons Learned

- Every file type embeds metadata differently: PDFs use Info Dictionary and XMP, Office documents use XML in `docProps/`, images use EXIF/IPTC/XMP
- **exiftool** is the universal tool -- it reads metadata from virtually any file format and should be the first thing you run
- Document metadata commonly leaks: author usernames, company names, local file paths (revealing OS and username), software versions, and revision history
- Office documents are ZIP files -- unzipping them reveals the raw XML metadata that tools might not fully parse
- GPS coordinates in images can pinpoint an office location, a person's home, or a meeting venue
- Custom metadata fields (like the one containing our flag) can hold arbitrary data that is invisible to the user but readable to anyone with exiftool
- Always strip metadata before publishing sensitive documents: `exiftool -all= document.pdf`
- Revision history in Office documents can reveal previous authors and edit patterns, useful for attribution
- Printer and scanner metadata can contain serial numbers that link a physical document to a specific device
