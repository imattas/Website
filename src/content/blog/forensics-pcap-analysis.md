---
title: "Forensics - Packet Capture Analysis"
description: "Analyzing a network packet capture to find credentials transmitted over an unencrypted HTTP login and extract the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Forensics          |
| Difficulty | Easy               |
| Points     | 125                |
| Flag       | `zemi{w1r3sh4rk_s33s_4ll}` |

## Challenge Files

Download the challenge files to get started:

- [challenge.pcap](/Website/challenges/forensics-pcap-analysis/challenge.pcap)
- [flag.txt](/Website/challenges/forensics-pcap-analysis/flag.txt)
- [generate.py](/Website/challenges/forensics-pcap-analysis/generate.py)
- [hint.txt](/Website/challenges/forensics-pcap-analysis/hint.txt)

## Reconnaissance

We're given a file `traffic.pcap` and the hint: *"Someone logged in without encryption. Can you find what they sent?"*

This tells us to look for unencrypted credentials — likely HTTP, FTP, or Telnet traffic.

## Step 1 — Open in Wireshark

Load `traffic.pcap` in Wireshark. Quick stats first:

```
Statistics → Protocol Hierarchy
```

```
Ethernet
  └─ IPv4
       ├─ TCP (98.2%)
       │    ├─ HTTP (12.1%)
       │    ├─ TLS (85.3%)
       │    └─ Other (0.8%)
       └─ UDP (1.8%)
            └─ DNS (1.8%)
```

There's HTTP traffic — that's unencrypted. Let's focus on that.

## Step 2 — Filter HTTP Traffic

Apply the display filter:

```
http
```

We see several HTTP requests. One stands out:

```
POST /login HTTP/1.1
Host: internal.corp.local
Content-Type: application/x-www-form-urlencoded
```

## Step 3 — Follow the HTTP Stream

Right-click the POST request → Follow → HTTP Stream:

```
POST /login HTTP/1.1
Host: internal.corp.local
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

username=admin&password=zemi{w1r3sh4rk_s33s_4ll}

HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=abc123
```

The password field contains the flag: `zemi{w1r3sh4rk_s33s_4ll}`

## Alternative Approaches

### Using tshark (Command Line)

If you prefer the command line:

```bash
# Extract all HTTP POST data
tshark -r traffic.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# Search for the flag format
tshark -r traffic.pcap -Y "http" -T fields -e http.file_data | grep -i "zemi"
```

### Using strings

Quick and dirty:

```bash
strings traffic.pcap | grep "zemi{"
```

```
username=admin&password=zemi{w1r3sh4rk_s33s_4ll}
```

This works because the traffic is unencrypted — the flag exists as plaintext in the capture.

## Common PCAP Filters

Here are useful Wireshark filters for CTF forensics:

```bash
# HTTP traffic
http

# POST requests only
http.request.method == "POST"

# FTP credentials
ftp.request.command == "USER" || ftp.request.command == "PASS"

# DNS queries
dns.qr == 0

# Find specific strings
frame contains "flag"
frame contains "zemi"

# Filter by IP
ip.addr == 192.168.1.100

# TCP streams
tcp.stream eq 5
```

## Extracting Files from PCAPs

Sometimes the flag is in a transferred file:

```
File → Export Objects → HTTP
```

This lists all files transferred over HTTP. You can save them individually and examine each one.

## Tools Used

- Wireshark — GUI packet analysis
- tshark — command-line packet analysis
- strings — quick plaintext search

## Lessons Learned

- **Never** transmit credentials over unencrypted protocols (HTTP, FTP, Telnet)
- Always use HTTPS/TLS for authentication endpoints
- Wireshark's "Follow Stream" feature is incredibly useful for reconstructing conversations
- `strings` is a quick first pass on any binary file, including PCAPs
- PCAP challenges often contain: credentials, transferred files, DNS exfiltration, or encoded data in packet payloads
- Learn Wireshark display filters — they save enormous amounts of time
