# Forensics Challenge: Docker Forensics
# The flag is written in an early layer and then deleted in a later layer.
# Players must inspect the Docker image layers to recover the deleted flag.
#
# Build: docker build -t docker-forensics .
# Save:  docker save docker-forensics -o challenge.tar
# Solve: Extract challenge.tar, inspect each layer's tar for flag.txt

FROM ubuntu:22.04

# Layer 1: Install basic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: Add an application user
RUN useradd -m -s /bin/bash appuser

# Layer 3: Write the flag (this layer will contain it forever!)
RUN echo "zemi{d0ck3r_l4y3r_s3cr3ts}" > /root/flag.txt && \
    chmod 600 /root/flag.txt

# Layer 4: Add a decoy application
RUN mkdir -p /opt/app && \
    echo '#!/bin/bash\necho "Application running..."' > /opt/app/run.sh && \
    chmod +x /opt/app/run.sh

# Layer 5: "Clean up" by removing the flag (but it persists in layer 3!)
RUN rm -f /root/flag.txt && \
    echo "Cleanup complete" > /var/log/setup.log

# Layer 6: Set up the final environment
USER appuser
WORKDIR /home/appuser
CMD ["/opt/app/run.sh"]
