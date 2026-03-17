---
title: "Forensics - Docker Forensics"
description: "Dig through Docker image layers to recover a secret that was added and then deleted in a subsequent build step."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                          |
|-------------|-------------------------------------------------|
| Category    | Forensics                                       |
| Points      | 350                                             |
| Difficulty  | Hard                                            |
| Flag Format | `zemi{...}`                                     |
| Files Given | `challenge_app.tar` (Docker image export, 85MB) |
| Tools Used  | docker, tar, dive, jq, grep                     |

## Challenge Files

Download the challenge files to get started:

- [build.sh](/Website/challenges/forensics-docker-forensics/build.sh)
- [Dockerfile](/Website/challenges/forensics-docker-forensics/Dockerfile)
- [flag.txt](/Website/challenges/forensics-docker-forensics/flag.txt)

## Docker Image Structure

Docker images are built in layers. Each instruction in a Dockerfile creates a new layer that captures the filesystem changes made by that instruction. Understanding this layered architecture is the key to this challenge.

A Docker image export (created with `docker save`) is a tar archive containing:

- **`manifest.json`** -- Lists the image's layers in order and the config file
- **`<hash>.json`** -- Image configuration with build history, environment variables, commands
- **Layer directories** -- Each containing a `layer.tar` with that layer's filesystem changes

The critical insight: **when a file is deleted in a later layer, it's only marked as deleted (with a whiteout file). The original data still exists in the earlier layer.** This is how secrets leak.

## Walkthrough

### Step 1: Load and Inspect the Image

We have a tar file that's a Docker image export. Let's examine it:

```bash
# List the contents of the image archive
$ tar tf challenge_app.tar
manifest.json
a1b2c3d4e5f6.json
layer0/
layer0/layer.tar
layer1/
layer1/layer.tar
layer2/
layer2/layer.tar
layer3/
layer3/layer.tar
layer4/
layer4/layer.tar
repositories

# Extract the archive
$ mkdir docker_analysis && cd docker_analysis
$ tar xf ../challenge_app.tar
```

### Step 2: Examine the Manifest and Config

```bash
$ cat manifest.json | python3 -m json.tool
[
    {
        "Config": "a1b2c3d4e5f6.json",
        "RepoTags": ["challenge_app:latest"],
        "Layers": [
            "layer0/layer.tar",
            "layer1/layer.tar",
            "layer2/layer.tar",
            "layer3/layer.tar",
            "layer4/layer.tar"
        ]
    }
]
```

Five layers. Let's check the build config to understand what each layer does:

```bash
$ cat a1b2c3d4e5f6.json | python3 -m json.tool
{
    "architecture": "amd64",
    "config": {
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "APP_VERSION=1.0.3"
        ],
        "Cmd": ["/app/server"],
        "WorkingDir": "/app"
    },
    "history": [
        {
            "created": "2026-01-05T10:00:00Z",
            "created_by": "/bin/sh -c #(nop) FROM ubuntu:22.04"
        },
        {
            "created": "2026-01-05T10:00:05Z",
            "created_by": "/bin/sh -c apt-get update && apt-get install -y curl"
        },
        {
            "created": "2026-01-05T10:00:15Z",
            "created_by": "/bin/sh -c #(nop) COPY file:secret_config.txt /app/config/secret.txt"
        },
        {
            "created": "2026-01-05T10:00:20Z",
            "created_by": "/bin/sh -c rm /app/config/secret.txt && echo 'cleaned up'"
        },
        {
            "created": "2026-01-05T10:00:25Z",
            "created_by": "/bin/sh -c #(nop) COPY file:server /app/server"
        }
    ],
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:aaa...",
            "sha256:bbb...",
            "sha256:ccc...",
            "sha256:ddd...",
            "sha256:eee..."
        ]
    }
}
```

The build history tells the entire story:

1. **Layer 0**: Base image (`ubuntu:22.04`)
2. **Layer 1**: Install packages (`apt-get install curl`)
3. **Layer 2**: **Copy `secret_config.txt` to `/app/config/secret.txt`** -- This is where the secret was added!
4. **Layer 3**: **Delete `/app/config/secret.txt`** -- The developer tried to clean up!
5. **Layer 4**: Copy the server binary

The developer made a classic mistake: adding a secret file in one layer and deleting it in the next. The deletion only creates a whiteout marker; the original file is still in Layer 2.

### Step 3: Extract Each Layer

```bash
# Create directories for each layer's contents
$ for i in 0 1 2 3 4; do
    mkdir -p extracted/layer${i}
    tar xf layer${i}/layer.tar -C extracted/layer${i}
  done

# List what's in each layer
$ for i in 0 1 2 3 4; do
    echo "=== Layer $i ==="
    find extracted/layer${i} -type f | head -10
    echo ""
  done

=== Layer 0 ===
extracted/layer0/bin/bash
extracted/layer0/bin/ls
extracted/layer0/usr/bin/curl
... (base ubuntu filesystem)

=== Layer 1 ===
extracted/layer1/usr/bin/curl
extracted/layer1/var/cache/apt/...

=== Layer 2 ===
extracted/layer2/app/config/secret.txt

=== Layer 3 ===
extracted/layer3/app/config/.wh.secret.txt

=== Layer 4 ===
extracted/layer4/app/server
```

There it is:

- **Layer 2** contains `app/config/secret.txt` -- the actual secret file
- **Layer 3** contains `app/config/.wh.secret.txt` -- a **whiteout file** (the `.wh.` prefix tells Docker to hide the file from this layer onwards)

### Step 4: Read the Secret

```bash
$ cat extracted/layer2/app/config/secret.txt
# Application Secret Configuration
# DO NOT COMMIT THIS FILE

DATABASE_HOST=internal-db.corp.local
DATABASE_USER=admin
DATABASE_PASS=Sup3rS3cur3P@ss!
API_KEY=sk-live-a1b2c3d4e5f6g7h8i9j0
SECRET_FLAG=zemi{d0ck3r_l4y3r_s3cr3ts}
```

**Flag: `zemi{d0ck3r_l4y3r_s3cr3ts}`**

The file also contained database credentials and an API key -- a realistic scenario of secrets leaking through Docker layers.

### Step 5: Verify with Docker History

If you load the image into Docker, you can also inspect its history:

```bash
$ docker load -i challenge_app.tar
Loaded image: challenge_app:latest

$ docker history challenge_app:latest
IMAGE          CREATED        CREATED BY                                      SIZE
a1b2c3d4e5f6   2 weeks ago   COPY file:server /app/server                    5.2MB
<missing>      2 weeks ago   /bin/sh -c rm /app/config/secret.txt && ec...   0B
<missing>      2 weeks ago   COPY file:secret_config.txt /app/config/se...   245B
<missing>      2 weeks ago   /bin/sh -c apt-get update && apt-get insta...   45MB
<missing>      2 weeks ago   /bin/sh -c #(nop) FROM ubuntu:22.04             78MB

# Note: the rm layer is 0B because deletions don't add data, they add whiteout markers
# But the COPY layer is 245B -- the secret file is still there!
```

### Step 6: Using dive for Visual Exploration

`dive` is an excellent TUI tool for exploring Docker image layers:

```bash
$ dive challenge_app:latest
```

`dive` shows you:

- Each layer's added/modified/removed files
- Total image size and layer efficiency
- Files that were added then removed (wasted space)

In the dive UI, navigating to Layer 2 would clearly show `secret.txt` being added, and Layer 3 would show it being removed.

### Step 7: Check Environment Variables

Don't forget to check for secrets in environment variables and build args:

```bash
# Check env vars in the image config
$ cat a1b2c3d4e5f6.json | python3 -c "
import json, sys
config = json.load(sys.stdin)
env = config.get('config', {}).get('Env', [])
for e in env:
    print(e)
"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APP_VERSION=1.0.3

# Check for ARG values (these persist in image history)
$ cat a1b2c3d4e5f6.json | python3 -c "
import json, sys
config = json.load(sys.stdin)
for entry in config.get('history', []):
    cmd = entry.get('created_by', '')
    if 'ARG' in cmd or 'ENV' in cmd or 'secret' in cmd.lower():
        print(cmd)
"
/bin/sh -c #(nop) COPY file:secret_config.txt /app/config/secret.txt
/bin/sh -c rm /app/config/secret.txt && echo 'cleaned up'
```

## Solve Script

```python
#!/usr/bin/env python3
"""
Docker image forensics - extract secrets from intermediate layers.

Analyzes a Docker image export (docker save) to find files that
were added in one layer and deleted in a subsequent layer.
"""

import tarfile
import json
import re
import os
import sys
import io

IMAGE_TAR = "challenge_app.tar"
FLAG_PATTERN = re.compile(r"zemi\{[^}]+\}")

def analyze_docker_image(image_tar):
    """Analyze a Docker image tar for leaked secrets."""
    print(f"[*] Analyzing Docker image: {image_tar}\n")

    with tarfile.open(image_tar, 'r') as tar:
        # Step 1: Read manifest
        manifest_data = tar.extractfile("manifest.json").read()
        manifest = json.loads(manifest_data)
        print(f"[*] Image tags: {manifest[0].get('RepoTags', ['untagged'])}")

        # Step 2: Read config for build history
        config_file = manifest[0]["Config"]
        config_data = tar.extractfile(config_file).read()
        config = json.loads(config_data)

        print("\n[*] Build history:")
        for i, entry in enumerate(config.get("history", [])):
            cmd = entry.get("created_by", "N/A")
            print(f"    Layer {i}: {cmd[:80]}")

        # Step 3: Check environment variables
        print("\n[*] Environment variables:")
        for env in config.get("config", {}).get("Env", []):
            print(f"    {env}")
            match = FLAG_PATTERN.search(env)
            if match:
                print(f"\n[+] FLAG in env var: {match.group()}")
                return

        # Step 4: Extract and search each layer
        layers = manifest[0]["Layers"]
        print(f"\n[*] Analyzing {len(layers)} layers...\n")

        whiteout_files = set()  # Files deleted in later layers

        # First pass: find whiteout files (deletions)
        for layer_path in layers:
            layer_tar_data = tar.extractfile(layer_path).read()
            with tarfile.open(fileobj=io.BytesIO(layer_tar_data)) as layer_tar:
                for member in layer_tar.getmembers():
                    basename = os.path.basename(member.name)
                    if basename.startswith(".wh."):
                        original = member.name.replace("/.wh.", "/")
                        whiteout_files.add(original)
                        print(f"[!] Deleted file found: {original}")

        # Second pass: extract files that were later deleted
        print(f"\n[*] Searching for deleted files in earlier layers...")
        for layer_path in layers:
            layer_tar_data = tar.extractfile(layer_path).read()
            with tarfile.open(fileobj=io.BytesIO(layer_tar_data)) as layer_tar:
                for member in layer_tar.getmembers():
                    if not member.isfile():
                        continue

                    # Check if this file was deleted in a later layer
                    if member.name in whiteout_files:
                        print(f"\n[!] Recovered deleted file: {member.name}")
                        try:
                            content = layer_tar.extractfile(member).read()
                            text = content.decode('utf-8', errors='ignore')
                            print(f"    Content:\n{text}")

                            match = FLAG_PATTERN.search(text)
                            if match:
                                print(f"\n[+] FLAG FOUND: {match.group()}")
                                return
                        except Exception as e:
                            print(f"    Error reading: {e}")

                    # Also check all files for the flag pattern
                    if member.size < 1048576:  # Skip files > 1MB
                        try:
                            content = layer_tar.extractfile(member).read()
                            text = content.decode('utf-8', errors='ignore')
                            match = FLAG_PATTERN.search(text)
                            if match:
                                print(f"\n[+] FLAG in {member.name}: {match.group()}")
                                return
                        except Exception:
                            pass

    print("\n[-] Flag not found.")

if __name__ == "__main__":
    analyze_docker_image(IMAGE_TAR)
```

## Tools Used

| Tool           | Purpose                                          |
|----------------|--------------------------------------------------|
| tar            | Extract Docker image layers                      |
| docker history | View build history of an image                   |
| docker save    | Export an image to a tar archive                  |
| dive           | Interactive TUI for exploring image layers       |
| jq / python    | Parse JSON manifest and config files             |
| grep / strings | Search for flags in extracted layer contents      |

## Lessons Learned

1. **Docker layers are immutable.** Each layer captures filesystem changes as a diff. Deleting a file in a later layer does not remove it from earlier layers. The file's data persists in the image forever unless the image is rebuilt with multi-stage builds or `--squash`.

2. **Whiteout files signal deletions.** Docker uses files prefixed with `.wh.` to mark deletions. When you see `.wh.secret.txt` in a layer, you know `secret.txt` existed in an earlier layer and was explicitly removed. This is a major forensic indicator.

3. **Always check build history.** The image config file contains the full Dockerfile history. Look for COPY/ADD commands followed by RUN commands that delete the same files. This pattern is the most common way secrets leak.

4. **Environment variables and build args persist.** Even if an `ARG` is only used during build time, its value is recorded in the image metadata. Similarly, `ENV` values are visible in the config. Never put secrets in either.

5. **Use dive for quick visual analysis.** The `dive` tool provides a fast, interactive way to browse each layer's filesystem changes. It highlights added, modified, and removed files, making it easy to spot suspicious patterns.

6. **The fix: multi-stage builds.** The correct way to handle build-time secrets is to use multi-stage Dockerfiles where secrets are only in the builder stage, not the final image. Docker BuildKit also supports `--secret` mounts that never persist in layers.
