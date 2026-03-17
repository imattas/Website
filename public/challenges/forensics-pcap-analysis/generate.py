#!/usr/bin/env python3
"""
Forensics Challenge: PCAP Analysis
Creates a PCAP file containing HTTP traffic with a POST request that sends
credentials in plaintext. The password field contains the flag.

Usage: python3 generate.py
Output: challenge.pcap
Dependencies: pip install scapy
"""

import struct
import os

FLAG = "zemi{w1r3sh4rk_s33s_4ll}"

# ---------- low-level PCAP writer (no scapy dependency needed) ----------

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1


def pcap_global_header():
    return struct.pack("<IHHiIII",
                       PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
                       PCAP_THISZONE, PCAP_SIGFIGS, PCAP_SNAPLEN,
                       PCAP_LINKTYPE_ETHERNET)


def pcap_packet_header(ts_sec, ts_usec, caplen, origlen):
    return struct.pack("<IIII", ts_sec, ts_usec, caplen, origlen)


def checksum(data):
    """Compute the Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_ethernet(src_mac, dst_mac, ethertype, payload):
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def build_ipv4(src_ip, dst_ip, protocol, payload):
    version_ihl = 0x45
    dscp_ecn = 0
    total_length = 20 + len(payload)
    identification = 0x1234
    flags_offset = 0x4000  # Don't Fragment
    ttl = 64
    header = struct.pack(">BBHHHBBH4s4s",
                         version_ihl, dscp_ecn, total_length,
                         identification, flags_offset, ttl, protocol,
                         0,  # checksum placeholder
                         src_ip, dst_ip)
    cs = checksum(header)
    header = header[:10] + struct.pack(">H", cs) + header[12:]
    return header + payload


def build_tcp(src_port, dst_port, seq, ack, flags, payload):
    data_offset = 5 << 4
    window = 65535
    header = struct.pack(">HHIIBBHHH",
                         src_port, dst_port, seq, ack,
                         data_offset, flags, window,
                         0, 0)  # checksum=0, urgent=0
    return header + payload


def ip_bytes(ip_str):
    return bytes(int(x) for x in ip_str.split("."))


def mac_bytes(mac_str):
    return bytes(int(x, 16) for x in mac_str.split(":"))


def build_http_post_packet(ts_sec):
    """Build a full Ethernet/IP/TCP/HTTP POST packet with credentials."""
    src_mac = mac_bytes("aa:bb:cc:dd:ee:01")
    dst_mac = mac_bytes("aa:bb:cc:dd:ee:02")
    src_ip = ip_bytes("192.168.1.100")
    dst_ip = ip_bytes("192.168.1.1")

    http_body = f"username=admin&password={FLAG}"
    http_headers = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: 192.168.1.1\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(http_body)}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
        f"{http_body}"
    )
    http_data = http_headers.encode()

    tcp = build_tcp(54321, 80, 1000, 1, 0x18, http_data)  # PSH+ACK
    ip = build_ipv4(src_ip, dst_ip, 6, tcp)
    eth = build_ethernet(src_mac, dst_mac, 0x0800, ip)
    return eth, ts_sec


def build_dns_query_packet(ts_sec):
    """Build a benign DNS query for noise."""
    src_mac = mac_bytes("aa:bb:cc:dd:ee:01")
    dst_mac = mac_bytes("aa:bb:cc:dd:ee:ff")
    src_ip = ip_bytes("192.168.1.100")
    dst_ip = ip_bytes("8.8.8.8")

    # Minimal DNS query for example.com
    dns = (b"\x12\x34"   # Transaction ID
           b"\x01\x00"   # Standard query
           b"\x00\x01"   # 1 question
           b"\x00\x00\x00\x00\x00\x00"
           b"\x07example\x03com\x00"
           b"\x00\x01"   # Type A
           b"\x00\x01")  # Class IN

    udp = struct.pack(">HHH", 12345, 53, 8 + len(dns)) + b"\x00\x00" + dns
    ip = build_ipv4(src_ip, dst_ip, 17, udp)
    eth = build_ethernet(src_mac, dst_mac, 0x0800, ip)
    return eth, ts_sec


def build_http_get_packet(ts_sec):
    """Build a benign HTTP GET request for noise."""
    src_mac = mac_bytes("aa:bb:cc:dd:ee:01")
    dst_mac = mac_bytes("aa:bb:cc:dd:ee:02")
    src_ip = ip_bytes("192.168.1.100")
    dst_ip = ip_bytes("192.168.1.1")

    http_data = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: 192.168.1.1\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n"
    ).encode()

    tcp = build_tcp(54320, 80, 500, 1, 0x18, http_data)
    ip = build_ipv4(src_ip, dst_ip, 6, tcp)
    eth = build_ethernet(src_mac, dst_mac, 0x0800, ip)
    return eth, ts_sec


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.pcap")

    packets = []

    # Build several packets: noise + the juicy POST
    packets.append(build_dns_query_packet(1000))
    packets.append(build_http_get_packet(1001))
    packets.append(build_dns_query_packet(1002))
    packets.append(build_http_post_packet(1003))  # <-- flag is here
    packets.append(build_http_get_packet(1004))
    packets.append(build_dns_query_packet(1005))

    with open(output_path, "wb") as f:
        f.write(pcap_global_header())
        for pkt_data, ts in packets:
            hdr = pcap_packet_header(ts, 0, len(pkt_data), len(pkt_data))
            f.write(hdr + pkt_data)

    print(f"[+] Created {output_path} with {len(packets)} packets")
    print()
    print("To solve:")
    print("  wireshark challenge.pcap")
    print("  tshark -r challenge.pcap -Y 'http.request.method == POST' -T fields -e http.file_data")
    print("  strings challenge.pcap | grep 'password='")


if __name__ == "__main__":
    main()
