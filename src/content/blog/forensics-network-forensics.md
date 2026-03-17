---
title: "Forensics - Network Forensics"
description: "Detect and reconstruct DNS exfiltration from a PCAP to recover stolen data encoded in subdomain queries."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                             |
|-------------|---------------------------------------------------|
| Category    | Forensics                                         |
| Points      | 350                                               |
| Difficulty  | Hard                                              |
| Flag Format | `zemi{...}`                                       |
| Files Given | `corporate_traffic.pcap` (network capture, 15 MB) |
| Tools Used  | tshark, Wireshark, Python, base64, CyberChef      |

## Challenge Files

Download the challenge files to get started:

- [challenge.pcap](/Website/challenges/forensics-network-forensics/challenge.pcap)
- [flag.txt](/Website/challenges/forensics-network-forensics/flag.txt)
- [generate.py](/Website/challenges/forensics-network-forensics/generate.py)
- [hint.txt](/Website/challenges/forensics-network-forensics/hint.txt)

## How DNS Exfiltration Works

DNS exfiltration is a technique attackers use to sneak data out of a network by encoding it in DNS queries. Most firewalls allow DNS traffic (port 53) to pass through, making it an ideal covert channel.

The technique works like this:

1. The attacker controls a domain (e.g., `evil.com`) and its authoritative DNS server
2. Data to exfiltrate is encoded (base64, hex, etc.) and split into chunks
3. Each chunk becomes a subdomain label in a DNS query: `<encoded_chunk>.evil.com`
4. The queries traverse the network, reaching the attacker's DNS server
5. The attacker's server logs the queries and reassembles the data

For example, exfiltrating the string "SECRET DATA" as base64:
- Base64 encode: `U0VDUkVUIERBVEE=`
- Split into chunks: `U0VDUkVU`, `IERBVEE=`
- DNS queries: `U0VDUkVU.exfil.evil.com`, `IERBVEE.exfil.evil.com`

## Walkthrough

### Step 1: Initial PCAP Analysis

Let's get an overview of the traffic:

```bash
$ capinfos corporate_traffic.pcap
File name:           corporate_traffic.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
Packet size limit:   65535
Number of packets:   48230
File size:           15 MB
Data size:           14 MB
Capture duration:    3600.5 seconds
First packet time:   2026-01-10 08:00:00
Last packet time:    2026-01-10 09:00:00

# Protocol breakdown
$ tshark -r corporate_traffic.pcap -q -z io,phs
Protocol Hierarchy Statistics
  eth                          48230
    ip                         48200
      tcp                      35120
        http                   12400
        tls                    18200
        ...
      udp                      13080
        dns                     8940
        ...
```

8940 DNS packets in a one-hour capture -- that's a lot of DNS traffic. Let's investigate.

### Step 2: Identify Unusual DNS Patterns

```bash
# List all unique queried domains, sorted by frequency
$ tshark -r corporate_traffic.pcap -Y "dns.qry.name" -T fields -e dns.qry.name \
    | sort | uniq -c | sort -rn | head -20

   4200  (various subdomains).data.exfiltrate.net
    520  www.google.com
    380  clients4.google.com
    340  update.microsoft.com
    ...
```

Massive red flag: **4200 queries** to subdomains of `data.exfiltrate.net`. Normal DNS doesn't look like this.

Let's examine these queries more closely:

```bash
# Extract just the exfiltration domain queries
$ tshark -r corporate_traffic.pcap \
    -Y 'dns.qry.name contains "exfiltrate.net" and dns.flags.response == 0' \
    -T fields -e frame.number -e frame.time -e dns.qry.name \
    | head -20

1042    08:05:12.001    AGVSZ0Vm.data.exfiltrate.net
1043    08:05:12.105    aXRyNG.data.exfiltrate.net
1044    08:05:12.210    QzR1Z2.data.exfiltrate.net
1045    08:05:12.315    h0XzNI.data.exfiltrate.net
1046    08:05:12.420    ZjFsdH.data.exfiltrate.net
1047    08:05:12.525    I0dDRf.data.exfiltrate.net
1048    08:05:12.630    ZGF0YQ.data.exfiltrate.net
...
```

The subdomain labels look like base64-encoded data. The queries are evenly spaced (~100ms apart), which is characteristic of automated exfiltration.

### Step 3: Extract All Exfiltration Subdomains

```bash
# Extract all subdomain labels (the part before .data.exfiltrate.net)
$ tshark -r corporate_traffic.pcap \
    -Y 'dns.qry.name contains "exfiltrate.net" and dns.flags.response == 0' \
    -T fields -e dns.qry.name \
    | sed 's/\.data\.exfiltrate\.net//' \
    > exfil_chunks.txt

$ wc -l exfil_chunks.txt
4200 exfil_chunks.txt

$ head -10 exfil_chunks.txt
AGVSZ0Vm
aXRyNG
QzR1Z2
h0XzNI
ZjFsdH
I0dDRf
ZGF0YQ
...
```

### Step 4: Detect the Encoding

Let's look at the character set used:

```bash
# Check character set
$ cat exfil_chunks.txt | fold -w1 | sort -u | tr -d '\n'
+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=
```

This is the base64 character set (A-Z, a-z, 0-9, +, /, =). Now we need to figure out how the chunks were split.

### Step 5: Reassemble and Decode

The chunks need to be concatenated in order and then base64 decoded:

```bash
# Concatenate all chunks into one string
$ cat exfil_chunks.txt | tr -d '\n' > exfil_combined.txt

# Check the length
$ wc -c exfil_combined.txt
33600 exfil_combined.txt

# Try base64 decoding
$ cat exfil_combined.txt | base64 -d > exfil_decoded.bin 2>/dev/null

$ file exfil_decoded.bin
exfil_decoded.bin: gzip compressed data

# It's gzipped -- decompress
$ gunzip -c exfil_decoded.bin > exfil_final.txt

$ file exfil_final.txt
exfil_final.txt: ASCII text

$ head -20 exfil_final.txt
=== EXFILTRATED DATA ===
Date: 2026-01-10
Source: Corporate Database

Employee Records:
ID,Name,Department,Salary
1001,John Smith,Engineering,95000
1002,Jane Doe,Marketing,87000
1003,Bob Wilson,Finance,92000
...

$ grep "zemi{" exfil_final.txt
Secret Key: zemi{dns_3xf1ltr4t10n_c4ught}
```

**Flag: `zemi{dns_3xf1ltr4t10n_c4ught}`**

The exfiltrated data was a database dump containing employee records. The flag was embedded within the stolen data.

### Step 6: Full Python Reconstruction Script

Here's a comprehensive script that automates the entire process:

```python
#!/usr/bin/env python3
"""
DNS Exfiltration Detector and Reconstructor

Analyzes a PCAP file for DNS-based data exfiltration,
extracts the encoded data, and reconstructs the original content.
"""

import subprocess
import re
import base64
import gzip
import sys
from collections import Counter

PCAP_FILE = "corporate_traffic.pcap"
FLAG_PATTERN = r"zemi\{[^}]+\}"

def extract_dns_queries(pcap_file):
    """Extract all DNS query names from a PCAP file."""
    cmd = (
        f"tshark -r {pcap_file} "
        f"-Y 'dns.flags.response == 0' "
        f"-T fields -e dns.qry.name"
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip().split('\n')

def find_exfil_domain(queries):
    """Identify the likely exfiltration domain by finding unusual query patterns."""
    # Extract base domains (last two labels)
    base_domains = []
    for query in queries:
        parts = query.strip().split('.')
        if len(parts) >= 2:
            base = '.'.join(parts[-2:])
            base_domains.append(base)

    # Find domains with unusually high query counts
    domain_counts = Counter(base_domains)
    print("[*] Top queried domains:")
    for domain, count in domain_counts.most_common(10):
        print(f"    {count:6d}  {domain}")

    # The exfil domain likely has the highest count and long subdomain labels
    top_domain = domain_counts.most_common(1)[0][0]
    return top_domain

def extract_subdomains(queries, exfil_domain):
    """Extract the encoded subdomain labels for the exfiltration domain."""
    chunks = []
    for query in queries:
        query = query.strip()
        if query.endswith(exfil_domain):
            # Remove the base domain and any intermediate labels
            subdomain = query[:-(len(exfil_domain) + 1)]
            # Remove intermediate labels like "data."
            parts = subdomain.split('.')
            # Take only the first label (the encoded data)
            if parts[0]:
                chunks.append(parts[0])
    return chunks

def try_decode(chunks, encoding='base64'):
    """Try to decode the reassembled chunks."""
    combined = ''.join(chunks)
    print(f"[*] Combined length: {len(combined)} characters")

    if encoding == 'base64':
        try:
            # Add padding if necessary
            padding = 4 - (len(combined) % 4)
            if padding != 4:
                combined += '=' * padding

            decoded = base64.b64decode(combined)
            print(f"[*] Base64 decoded: {len(decoded)} bytes")

            # Check if it's gzip compressed
            if decoded[:2] == b'\x1f\x8b':
                print("[*] Data is gzip compressed, decompressing...")
                decoded = gzip.decompress(decoded)
                print(f"[*] Decompressed: {len(decoded)} bytes")

            return decoded

        except Exception as e:
            print(f"[-] Base64 decode failed: {e}")
            return None

    elif encoding == 'hex':
        try:
            decoded = bytes.fromhex(combined)
            print(f"[*] Hex decoded: {len(decoded)} bytes")
            return decoded
        except Exception as e:
            print(f"[-] Hex decode failed: {e}")
            return None

    return None

def main():
    print(f"[*] Analyzing {PCAP_FILE} for DNS exfiltration...\n")

    # Step 1: Extract DNS queries
    print("[*] Extracting DNS queries...")
    queries = extract_dns_queries(PCAP_FILE)
    print(f"[*] Total DNS queries: {len(queries)}\n")

    # Step 2: Identify exfiltration domain
    exfil_domain = find_exfil_domain(queries)
    print(f"\n[*] Likely exfiltration domain: {exfil_domain}\n")

    # Step 3: Extract encoded chunks
    chunks = extract_subdomains(queries, exfil_domain)
    print(f"[*] Extracted {len(chunks)} data chunks\n")

    if not chunks:
        print("[-] No data chunks found.")
        sys.exit(1)

    # Step 4: Try decoding
    for encoding in ['base64', 'hex']:
        print(f"[*] Trying {encoding} decoding...")
        decoded = try_decode(chunks, encoding)
        if decoded:
            text = decoded.decode('utf-8', errors='ignore')

            # Search for flag
            match = re.search(FLAG_PATTERN, text)
            if match:
                print(f"\n[+] FLAG FOUND: {match.group()}")

            # Save decoded data
            output_file = f"exfiltrated_data.{'txt' if text.isprintable() else 'bin'}"
            with open(output_file, 'wb') as f:
                f.write(decoded)
            print(f"[*] Decoded data saved to {output_file}")

            # Show preview
            print(f"\n[*] Data preview (first 500 chars):")
            print(text[:500])
            return

    print("[-] Could not decode the exfiltrated data.")

if __name__ == "__main__":
    main()
```

### Additional Analysis: Identifying the Source

```bash
# Who initiated the DNS exfiltration?
$ tshark -r corporate_traffic.pcap \
    -Y 'dns.qry.name contains "exfiltrate.net" and dns.flags.response == 0' \
    -T fields -e ip.src -e ip.dst \
    | sort | uniq -c | sort -rn

   4200 192.168.1.105  192.168.1.1

# All exfiltration traffic came from 192.168.1.105 to the gateway at 192.168.1.1
```

```bash
# What else was 192.168.1.105 doing?
$ tshark -r corporate_traffic.pcap \
    -Y 'ip.src == 192.168.1.105 and not dns' \
    -T fields -e frame.time -e ip.dst -e tcp.dstport \
    | head -10

08:04:55.100    10.0.0.50       3306
08:04:55.200    10.0.0.50       3306
08:04:55.300    10.0.0.50       3306
```

The attacker at 192.168.1.105 was connecting to port 3306 (MySQL) on an internal server at 10.0.0.50, then exfiltrating the data via DNS.

## Tools Used

| Tool      | Purpose                                               |
|-----------|-------------------------------------------------------|
| tshark    | Command-line packet analysis (Wireshark CLI)           |
| Wireshark | GUI packet analysis for visual inspection              |
| capinfos  | PCAP file metadata and statistics                      |
| Python    | Data reconstruction and decoding                       |
| base64    | Base64 decoding of exfiltrated data                    |
| CyberChef | Alternative decoding/decompression (web tool)         |

## Lessons Learned

1. **DNS is a covert channel.** Because DNS traffic is almost always allowed through firewalls, it's a popular exfiltration vector. If you see a high volume of DNS queries to a single domain with long subdomain labels, investigate immediately.

2. **Look for statistical anomalies.** Normal DNS queries are to well-known domains and have short, readable labels. Exfiltration DNS has encoded (base64/hex) labels, high query volume, regular timing intervals, and queries to unusual domains.

3. **tshark is essential.** While Wireshark's GUI is great for browsing, `tshark` lets you extract specific fields for programmatic analysis. The key flags are `-Y` (display filter), `-T fields` (output format), and `-e` (field extraction).

4. **Reconstruct in order.** DNS queries may arrive out of order in the PCAP. Use frame numbers or timestamps to ensure you reassemble the data in the correct sequence. In this challenge, the queries were already in order.

5. **Layer decoding.** Exfiltrated data is often compressed (gzip, zlib) after encoding (base64, hex) to minimize the number of DNS queries needed. Be prepared to peel back multiple layers.

6. **Identify the full attack story.** Don't just find the flag -- understand the whole attack. Who was the source? What internal resources did they access? When did the exfiltration start? This context matters in real forensics investigations.
