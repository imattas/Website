# Privilege Escalation Challenge: Linux Advanced
# Ubuntu container with advanced privilege escalation vulnerabilities:
#   1. PATH hijacking via SUID binary that calls system("ls")
#   2. Shared library hijacking (LD_PRELOAD-compatible SUID)
#   3. Wildcard injection in a root cron tar command
#
# Build: docker build -t privesc-advanced .
# Run:   docker run --rm -it privesc-advanced

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    cron \
    openssh-server \
    vim \
    nano \
    curl \
    wget \
    net-tools \
    python3 \
    gcc \
    make \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Create low-privilege user
RUN useradd -m -s /bin/bash user && \
    echo "user:user" | chpasswd

# ============================================================
# VULNERABILITY 1: PATH Hijacking via SUID binary
# The binary calls system("ls") without a full path.
# Exploit: create fake "ls" in a directory, prepend to PATH.
# ============================================================
COPY vulnerable_suid.c /tmp/vulnerable_suid.c
RUN gcc -o /usr/local/bin/vuln_list /tmp/vulnerable_suid.c && \
    chmod u+s /usr/local/bin/vuln_list && \
    rm /tmp/vulnerable_suid.c

# ============================================================
# VULNERABILITY 2: Shared library hijacking
# A custom SUID program that loads a shared library from a
# user-writable location.
# ============================================================
RUN echo '#include <stdio.h>\n\
void helper_init() __attribute__((constructor));\n\
void helper_init() { printf("Helper library loaded.\\n"); }\n\
void do_work() { printf("Doing work...\\n"); }' > /tmp/helper.c && \
    gcc -shared -fPIC -o /usr/local/lib/libhelper.so /tmp/helper.c && \
    echo '#include <stdio.h>\n\
#include <stdlib.h>\n\
extern void do_work();\n\
int main() {\n\
    printf("=== Service Manager ===\\n");\n\
    do_work();\n\
    return 0;\n\
}' > /tmp/svc_mgr.c && \
    gcc -o /usr/local/bin/svc_manager /tmp/svc_mgr.c -L/usr/local/lib -lhelper -Wl,-rpath,/home/user/lib && \
    chmod u+s /usr/local/bin/svc_manager && \
    mkdir -p /home/user/lib && \
    chown user:user /home/user/lib && \
    rm /tmp/helper.c /tmp/svc_mgr.c && \
    ldconfig

# ============================================================
# VULNERABILITY 3: Wildcard injection in tar cron job
# A cron job runs: cd /home/user/backups && tar czf /tmp/backup.tar.gz *
# The wildcard * expands filenames as tar options!
# Create files named "--checkpoint=1" and "--checkpoint-action=exec=sh shell.sh"
# ============================================================
RUN mkdir -p /home/user/backups && \
    chown -R user:user /home/user/backups && \
    echo '#!/bin/bash\ncd /home/user/backups && tar czf /tmp/backup.tar.gz * 2>/dev/null' > /opt/backup.sh && \
    chmod 755 /opt/backup.sh && \
    echo "* * * * * root /opt/backup.sh" > /etc/cron.d/backup && \
    chmod 644 /etc/cron.d/backup

# Place the flag
RUN echo "zemi{4dv4nc3d_pr1v3sc_m4st3r}" > /root/flag.txt && \
    chmod 400 /root/flag.txt

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Welcome message
RUN echo '\n\
================================================\n\
  Privilege Escalation Challenge: Advanced\n\
================================================\n\
\n\
You are logged in as "user" (low privilege).\n\
The flag is in /root/flag.txt (owned by root).\n\
\n\
This challenge has MULTIPLE escalation paths.\n\
Can you find them all?\n\
\n\
Recon suggestions:\n\
  - find / -perm -4000 2>/dev/null\n\
  - cat /etc/cron.d/*\n\
  - ldd /usr/local/bin/svc_manager\n\
  - strings /usr/local/bin/vuln_list\n\
================================================\n' > /etc/motd

EXPOSE 22

CMD service cron start && /usr/sbin/sshd -D
