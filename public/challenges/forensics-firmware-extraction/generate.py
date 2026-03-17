#!/usr/bin/env python3
"""
Forensics Challenge: Firmware Extraction
Creates a fake firmware blob with an embedded SquashFS-like filesystem
containing configuration files, one of which holds the flag.

Players use binwalk, dd, or manual analysis to find and extract the
embedded filesystem.

Usage: python3 generate.py
Output: firmware.bin
"""

import struct
import os
import zlib
import random

FLAG = "zemi{f1rmw4r3_s3cr3ts_3xtr4ct3d}"


def create_firmware_header():
    """Create a realistic-looking firmware header."""
    header = b""
    # Vendor magic bytes
    header += b"\x27\x05\x19\x56"  # uImage-style magic
    # Header CRC (fake)
    header += struct.pack(">I", 0xDEADBEEF)
    # Timestamp
    header += struct.pack(">I", 1700000000)
    # Data size (placeholder, will be filled)
    header += struct.pack(">I", 0x00100000)
    # Load address
    header += struct.pack(">I", 0x80000000)
    # Entry point
    header += struct.pack(">I", 0x80000100)
    # Data CRC (fake)
    header += struct.pack(">I", 0xCAFEBABE)
    # OS (Linux=5), Arch (ARM=2), Image type (Firmware=5), Compression (gzip=1)
    header += bytes([5, 2, 5, 1])
    # Image name (32 bytes, null-padded)
    name = b"IoT-Router-v2.1.3-release"
    header += name + b"\x00" * (32 - len(name))
    return header


def create_fake_kernel():
    """Create fake kernel data (random bytes with some structure)."""
    random.seed(42)
    # Start with an ARM Linux kernel magic
    kernel = b"\x00\x00\xa0\xe1" * 4  # ARM NOP sled
    kernel += b"Linux version 5.10.92 (buildroot@factory) "
    kernel += b"(arm-linux-gnueabihf-gcc 10.3.0) #1 SMP\x00"
    # Pad with pseudo-random data to simulate compressed kernel
    kernel += bytes(random.getrandbits(8) for _ in range(4096))
    return kernel


def create_squashfs_filesystem():
    """Create a fake SquashFS filesystem containing config files with the flag."""
    # SquashFS magic: hsqs (0x73717368)
    sqsh_magic = b"hsqs"

    # Create file contents for the embedded filesystem
    files = {
        "/etc/config/system": (
            "config system\n"
            "    option hostname 'IoT-Router'\n"
            "    option timezone 'UTC'\n"
            "    option log_size '64'\n"
        ),
        "/etc/config/network": (
            "config interface 'loopback'\n"
            "    option ifname 'lo'\n"
            "    option proto 'static'\n"
            "    option ipaddr '127.0.0.1'\n"
            "\n"
            "config interface 'lan'\n"
            "    option ifname 'eth0'\n"
            "    option proto 'dhcp'\n"
        ),
        "/etc/config/wireless": (
            "config wifi-device 'radio0'\n"
            "    option type 'mac80211'\n"
            "    option channel '6'\n"
            "    option hwmode '11g'\n"
            "\n"
            "config wifi-iface\n"
            "    option device 'radio0'\n"
            "    option network 'lan'\n"
            "    option mode 'ap'\n"
            "    option ssid 'IoT-Router'\n"
            "    option encryption 'psk2'\n"
            "    option key 'changeme123'\n"
        ),
        "/etc/shadow": (
            "root:$6$fake$hash:19000:0:99999:7:::\n"
            "daemon:*:19000:0:99999:7:::\n"
            "nobody:*:19000:0:99999:7:::\n"
        ),
        "/etc/config/secret.conf": (
            "# Internal configuration - DO NOT DISTRIBUTE\n"
            f"# Debug flag: {FLAG}\n"
            "admin_password=sup3rs3cur3\n"
            "api_key=ak_12345abcde67890\n"
            "debug_mode=true\n"
        ),
        "/etc/banner": (
            "  ___ _____ _____         _\n"
            " |_ _|_   _| _ \\___ _  _| |_ ___ _ _\n"
            "  | |  | | |   / _ \\ || |  _/ -_) '_|\n"
            " |___| |_| |_|_\\___/\\_,_|\\__\\___|_|\n"
            "\n"
            " Firmware v2.1.3\n"
        ),
    }

    # Build a simple tar-like structure (custom, not real SquashFS internals)
    fs_data = b""
    for path, content in files.items():
        # File entry: path length (2 bytes) + path + content length (4 bytes) + content
        path_bytes = path.encode()
        content_bytes = content.encode()
        fs_data += struct.pack(">H", len(path_bytes))
        fs_data += path_bytes
        fs_data += struct.pack(">I", len(content_bytes))
        fs_data += content_bytes

    # Compress the filesystem data
    compressed_fs = zlib.compress(fs_data)

    # Build SquashFS-like block
    sqsh_block = sqsh_magic
    sqsh_block += struct.pack("<I", len(files))          # inode count
    sqsh_block += struct.pack("<I", len(compressed_fs))   # compressed size
    sqsh_block += struct.pack("<I", len(fs_data))         # uncompressed size
    sqsh_block += struct.pack("<H", 4)                    # block size log2
    sqsh_block += struct.pack("<H", 1)                    # compression type (gzip)
    sqsh_block += b"\x00" * 48                            # padding to 64-byte header
    sqsh_block += compressed_fs

    return sqsh_block


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware.bin")

    print("[*] Creating firmware header...")
    header = create_firmware_header()

    print("[*] Creating fake kernel section...")
    kernel = create_fake_kernel()

    print("[*] Creating embedded SquashFS filesystem...")
    filesystem = create_squashfs_filesystem()

    # Padding between sections
    padding1 = b"\xFF" * (0x1000 - len(header))  # pad header to 4KB
    padding2 = b"\xFF" * (0x1000 - (len(kernel) % 0x1000))  # align kernel

    # Assemble firmware blob
    firmware = header + padding1 + kernel + padding2 + filesystem

    # Add trailing padding
    firmware += b"\xFF" * (0x1000 - (len(firmware) % 0x1000))

    with open(output_path, "wb") as f:
        f.write(firmware)

    sqsh_offset = len(header) + len(padding1) + len(kernel) + len(padding2)

    print(f"[+] Created {output_path}")
    print(f"    Total size: {len(firmware)} bytes")
    print(f"    Header:     0x0000 - 0x{len(header):04X}")
    print(f"    Kernel:     0x1000 - 0x{0x1000 + len(kernel):04X}")
    print(f"    SquashFS:   0x{sqsh_offset:04X} (look for 'hsqs' magic)")
    print()
    print("To solve:")
    print("  binwalk firmware.bin")
    print("  binwalk -e firmware.bin")
    print("  # Or manually: find 'hsqs' offset, extract, decompress")
    print("  # The flag is in /etc/config/secret.conf inside the filesystem")
    print()
    print("Manual extraction hint:")
    print(f"  python3 -c \"")
    print(f"    import zlib, struct")
    print(f"    data = open('firmware.bin','rb').read()")
    print(f"    idx = data.find(b'hsqs')")
    print(f"    # Parse SquashFS header, then zlib decompress the data")
    print(f"  \"")


if __name__ == "__main__":
    main()
