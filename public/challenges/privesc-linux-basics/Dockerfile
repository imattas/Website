# Privilege Escalation Challenge: Linux Basics
# Ubuntu container with intentional privilege escalation vulnerabilities:
#   1. SUID binary (find with SUID bit)
#   2. Writable cron job running as root
#   3. sudo misconfiguration (user can run vim as root)
#
# Build: docker build -t privesc-basics .
# Run:   docker run --rm -it privesc-basics
# Login: ssh user@localhost -p 2222 (password: user)

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    cron \
    openssh-server \
    vim \
    nano \
    curl \
    wget \
    net-tools \
    findutils \
    python3 \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create the low-privilege user
RUN useradd -m -s /bin/bash user && \
    echo "user:user" | chpasswd

# ============================================================
# VULNERABILITY 1: SUID binary
# The 'find' command has the SUID bit set, allowing any user
# to execute commands as root via: find . -exec /bin/bash \;
# ============================================================
RUN chmod u+s /usr/bin/find

# ============================================================
# VULNERABILITY 2: Writable cron job
# A cron job runs /opt/scripts/backup.sh as root every minute.
# The script is world-writable, so the user can modify it.
# ============================================================
RUN mkdir -p /opt/scripts && \
    echo '#!/bin/bash\ntar czf /tmp/backup.tar.gz /home/ 2>/dev/null' > /opt/scripts/backup.sh && \
    chmod 777 /opt/scripts/backup.sh && \
    echo "* * * * * root /opt/scripts/backup.sh" > /etc/cron.d/backup && \
    chmod 644 /etc/cron.d/backup

# ============================================================
# VULNERABILITY 3: sudo misconfiguration
# User can run /usr/bin/vim as root without a password.
# Escape: :!/bin/bash or :set shell=/bin/bash then :shell
# ============================================================
RUN echo "user ALL=(root) NOPASSWD: /usr/bin/vim" >> /etc/sudoers

# Place the flag readable only by root
RUN echo "zemi{l1nux_pr1v3sc_r00t3d}" > /root/flag.txt && \
    chmod 400 /root/flag.txt

# Setup SSH
RUN mkdir /var/run/sshd && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Setup welcome message
RUN echo '\n\
============================================\n\
  Privilege Escalation Challenge: Basics\n\
============================================\n\
\n\
You are logged in as "user" (low privilege).\n\
The flag is in /root/flag.txt (owned by root).\n\
\n\
Find a way to escalate your privileges!\n\
\n\
Hints:\n\
  - Check for SUID binaries: find / -perm -4000 2>/dev/null\n\
  - Check sudo rights: sudo -l\n\
  - Check for writable scripts: find / -writable 2>/dev/null\n\
  - Check cron jobs: cat /etc/cron.d/*\n\
============================================\n' > /etc/motd

EXPOSE 22

# Start SSH and cron
CMD service cron start && /usr/sbin/sshd -D
