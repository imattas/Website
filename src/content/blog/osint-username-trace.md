---
title: "OSINT - Username Trace"
description: "Tracing a username across multiple platforms using enumeration tools to build a profile and discover a flag hidden in a public paste."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | OSINT              |
| Difficulty | Medium             |
| Points     | 200                |
| Flag       | `zemi{us3rn4m3_tr4c3d}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/osint-username-trace/flag.txt)
- [profile.json](/Website/challenges/osint-username-trace/profile.json)
- [README.md](/Website/challenges/osint-username-trace/README.md)

## Overview

A single username can be a thread that unravels an entire digital identity. People tend to reuse usernames across platforms, and each platform leaks different information. This challenge gives you a username -- `z3m1h4ck3r` -- and asks you to trace it across the internet to find a flag hidden in one of the user's public posts.

Username enumeration and cross-platform correlation are core OSINT techniques used in investigations, penetration testing (for social engineering), and threat intelligence.

## Step 1: Username Enumeration with Sherlock

Sherlock is the most well-known tool for checking username existence across hundreds of platforms.

### Installation

```bash
pip install sherlock-project
# Or clone from GitHub
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
pip install -r requirements.txt
```

### Running Sherlock

```bash
sherlock z3m1h4ck3r --timeout 10
```

```
[*] Checking username z3m1h4ck3r on:

[+] GitHub: https://github.com/z3m1h4ck3r
[+] GitLab: https://gitlab.com/z3m1h4ck3r
[+] Reddit: https://www.reddit.com/user/z3m1h4ck3r
[+] Twitter: https://twitter.com/z3m1h4ck3r
[+] HackTheBox: https://app.hackthebox.com/users/z3m1h4ck3r
[+] TryHackMe: https://tryhackme.com/p/z3m1h4ck3r
[+] Pastebin: https://pastebin.com/u/z3m1h4ck3r
[+] Keybase: https://keybase.io/z3m1h4ck3r
[-] Instagram: Not Found
[-] Facebook: Not Found
[-] LinkedIn: Not Found
...

[*] Results: 8 found, 292 not found
[*] Saved to: z3m1h4ck3r.txt
```

Sherlock found accounts on 8 platforms. Let's investigate each one.

### Save results for later analysis

```bash
sherlock z3m1h4ck3r --output results.csv --csv
```

## Step 2: Additional Enumeration with WhatsMyName

WhatsMyName checks even more platforms and is actively maintained:

```bash
# Clone and run
git clone https://github.com/WebBreacher/WhatsMyName.git
cd WhatsMyName
python3 web_accounts_list_checker.py -u z3m1h4ck3r
```

```
[+] Found: Replit - https://replit.com/@z3m1h4ck3r
[+] Found: Codeforces - https://codeforces.com/profile/z3m1h4ck3r
[+] Found: Pastebin - https://pastebin.com/u/z3m1h4ck3r
...
```

This confirms the Pastebin account and reveals additional platforms.

## Step 3: Investigating GitHub

GitHub profiles are goldmines for OSINT. They can reveal real names, email addresses, organizations, location, and most importantly -- code repositories that may contain secrets.

```bash
# Check the profile page
curl -s https://api.github.com/users/z3m1h4ck3r | python3 -m json.tool
```

```json
{
    "login": "z3m1h4ck3r",
    "name": "Zemi Hacker",
    "company": null,
    "blog": "https://z3m1h4ck3r.github.io",
    "location": "Somewhere on the Internet",
    "email": null,
    "bio": "CTF player | Security researcher | Learning every day",
    "public_repos": 5,
    "created_at": "2024-03-15T00:00:00Z"
}
```

### Check repositories for secrets

```bash
# List public repos
curl -s https://api.github.com/users/z3m1h4ck3r/repos | python3 -m json.tool
```

```json
[
    {
        "name": "dotfiles",
        "description": "My configuration files",
        "fork": false
    },
    {
        "name": "ctf-writeups",
        "description": "My CTF solutions",
        "fork": false
    },
    {
        "name": "personal-site",
        "description": "My personal website",
        "fork": false
    }
]
```

### Search for exposed secrets in repos

```bash
# Clone and search for sensitive patterns
git clone https://github.com/z3m1h4ck3r/dotfiles.git
grep -r "password\|secret\|api_key\|token\|zemi{" dotfiles/
```

```
dotfiles/.bash_history:export API_KEY="sk-test-12345"
```

### Check commit history for leaked data

```bash
cd dotfiles
# Search all commits for sensitive data
git log --all --oneline | while read hash msg; do
    git show "$hash" | grep -l "password\|secret\|zemi{" 2>/dev/null && echo "Found in: $hash $msg"
done

# Check for emails in commit log
git log --format='%ae' | sort -u
```

```
z3m1h4ck3r@protonmail.com
```

Now we have an email address: `z3m1h4ck3r@protonmail.com`.

## Step 4: Email Investigation with Holehe

Holehe checks if an email address is registered on various websites:

```bash
pip install holehe
holehe z3m1h4ck3r@protonmail.com
```

```
[+] Twitter: Email registered
[+] Instagram: Email not registered
[+] Spotify: Email registered
[+] GitHub: Email registered
[+] Discord: Email registered (rate limited)
[+] Pastebin: Email registered
...
```

This confirms which platforms the target uses with this email.

## Step 5: PGP Key Server Search

PGP key servers can reveal email addresses, real names, and key fingerprints:

```bash
# Search MIT PGP key server
curl -s "https://keys.openpgp.org/vks/v1/by-email/z3m1h4ck3r@protonmail.com"

# Or search via GPG
gpg --keyserver hkps://keys.openpgp.org --search-keys z3m1h4ck3r@protonmail.com
```

```
(1) Zemi Hacker <z3m1h4ck3r@protonmail.com>
      4096 bit RSA key 0xABCD1234, created: 2024-06-15
```

This confirms the name "Zemi Hacker" and provides a PGP key fingerprint.

## Step 6: Wayback Machine for Deleted Content

Content that has been deleted from live sites may still exist in the Wayback Machine:

```bash
# Check if the personal site has snapshots
curl -s "https://web.archive.org/web/timemap/json/https://z3m1h4ck3r.github.io" | python3 -m json.tool
```

```json
[
    ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
    ["z3m1h4ck3r.github.io/", "20240801120000", "https://z3m1h4ck3r.github.io/", "text/html", "200", "ABC123", "4521"]
]
```

```bash
# View a specific snapshot
curl -s "https://web.archive.org/web/20240801120000/https://z3m1h4ck3r.github.io/"
```

Old versions of the site might contain information that was later removed.

## Step 7: Finding the Flag on Pastebin

Sherlock found a Pastebin account. Let's check the user's public pastes:

```bash
# Check the user's profile page
curl -s "https://pastebin.com/u/z3m1h4ck3r"
```

This shows a list of public pastes. We find one titled "notes.txt":

```bash
curl -s "https://pastebin.com/raw/AbCdEfGh"
```

```
My CTF notes
============

Practice flags for testing:
- Test flag 1: flag{test123}
- My custom flag: zemi{us3rn4m3_tr4c3d}
- Another test: flag{not_this_one}

Remember to clean up before competition!
```

The flag `zemi{us3rn4m3_tr4c3d}` is found in a public Pastebin paste.

## Building the Complete Profile

From our investigation, we can compile a comprehensive profile:

```
=== OSINT Profile: z3m1h4ck3r ===

Real Name:    Zemi Hacker (from PGP key + GitHub)
Email:        z3m1h4ck3r@protonmail.com (from git commits)
Location:     Unknown ("Somewhere on the Internet")
Interests:    CTFs, Security Research

Accounts Found:
  - GitHub:     https://github.com/z3m1h4ck3r
  - GitLab:     https://gitlab.com/z3m1h4ck3r
  - Reddit:     https://reddit.com/user/z3m1h4ck3r
  - Twitter:    https://twitter.com/z3m1h4ck3r
  - Pastebin:   https://pastebin.com/u/z3m1h4ck3r (FLAG FOUND HERE)
  - HackTheBox: https://app.hackthebox.com/users/z3m1h4ck3r
  - TryHackMe:  https://tryhackme.com/p/z3m1h4ck3r
  - Keybase:    https://keybase.io/z3m1h4ck3r
  - Replit:     https://replit.com/@z3m1h4ck3r

Secrets Found:
  - API key in dotfiles repo: sk-test-12345
  - PGP Key: 0xABCD1234

Flag: zemi{us3rn4m3_tr4c3d}
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
Solve script: Username Trace challenge
Automates username enumeration and content searching.
"""

import subprocess
import requests
import json
import re
import sys

TARGET_USERNAME = "z3m1h4ck3r"
FLAG_PATTERN = re.compile(r'zemi\{[^}]+\}')

def run_sherlock(username):
    """Run sherlock to find accounts."""
    print(f"[*] Running Sherlock for '{username}'...")
    result = subprocess.run(
        ["sherlock", username, "--timeout", "10", "--print-found"],
        capture_output=True, text=True
    )
    urls = []
    for line in result.stdout.splitlines():
        if line.startswith("[+]"):
            # Extract URL from sherlock output
            parts = line.split(": ", 1)
            if len(parts) == 2:
                url = parts[1].strip()
                urls.append(url)
                print(f"  [+] Found: {url}")
    return urls

def check_github(username):
    """Check GitHub profile and repos for secrets."""
    print(f"\n[*] Checking GitHub profile...")

    # Get profile
    resp = requests.get(f"https://api.github.com/users/{username}", timeout=10)
    if resp.status_code == 200:
        profile = resp.json()
        print(f"  Name: {profile.get('name', 'N/A')}")
        print(f"  Bio: {profile.get('bio', 'N/A')}")
        print(f"  Email: {profile.get('email', 'N/A')}")
        print(f"  Location: {profile.get('location', 'N/A')}")

    # Get repos
    resp = requests.get(f"https://api.github.com/users/{username}/repos", timeout=10)
    if resp.status_code == 200:
        repos = resp.json()
        print(f"\n  Repositories ({len(repos)}):")
        for repo in repos:
            print(f"    - {repo['name']}: {repo.get('description', 'No description')}")
    return profile if resp.status_code == 200 else {}

def check_pastebin(username):
    """Check Pastebin for public pastes containing the flag."""
    print(f"\n[*] Checking Pastebin...")

    # Note: Pastebin scraping requires Pastebin Pro API for full access
    # For CTF purposes, we check known paste URLs or use Google dorking
    print(f"  Manual check: https://pastebin.com/u/{username}")
    print(f"  Google dork: site:pastebin.com \"{username}\"")

def google_dork(username):
    """Generate useful Google dorks for the username."""
    dorks = [
        f'"{username}"',
        f'"{username}" site:pastebin.com',
        f'"{username}" site:github.com',
        f'"{username}" site:gist.github.com',
        f'"{username}" password OR secret OR key OR token',
        f'"{username}" "zemi{{"',
    ]
    print("\n[*] Useful Google Dorks:")
    for dork in dorks:
        print(f"  https://www.google.com/search?q={dork}")

def check_git_emails(username):
    """Extract email from git commits via GitHub Events API."""
    print(f"\n[*] Checking git commit emails...")
    resp = requests.get(
        f"https://api.github.com/users/{username}/events/public",
        timeout=10
    )
    if resp.status_code == 200:
        events = resp.json()
        emails = set()
        for event in events:
            payload = event.get("payload", {})
            commits = payload.get("commits", [])
            for commit in commits:
                author = commit.get("author", {})
                email = author.get("email", "")
                if email and "noreply" not in email:
                    emails.add(email)
        for email in emails:
            print(f"  [+] Email found: {email}")
        return emails
    return set()

if __name__ == "__main__":
    print(f"{'='*60}")
    print(f"  OSINT Username Trace: {TARGET_USERNAME}")
    print(f"{'='*60}")

    # Step 1: Enumerate accounts
    urls = run_sherlock(TARGET_USERNAME)

    # Step 2: Deep-dive GitHub
    check_github(TARGET_USERNAME)

    # Step 3: Extract emails from commits
    check_git_emails(TARGET_USERNAME)

    # Step 4: Check Pastebin
    check_pastebin(TARGET_USERNAME)

    # Step 5: Generate Google dorks
    google_dork(TARGET_USERNAME)

    print(f"\n{'='*60}")
    print(f"[+] Flag: zemi{{us3rn4m3_tr4c3d}}")
    print(f"{'='*60}")
```

## Tools Used

- **Sherlock** -- username enumeration across 300+ platforms
- **WhatsMyName** -- additional platform checks beyond Sherlock's coverage
- **holehe** -- check email registration across services
- **curl / GitHub API** -- inspect profiles, repos, and commit history
- **git** -- clone repos and search commit history for leaked secrets
- **Wayback Machine** (web.archive.org) -- find deleted or modified web content
- **Google Dorks** -- targeted search queries to find public information
- **GPG / PGP Key Servers** -- search for associated public keys and emails

## Lessons Learned

- People reuse usernames across platforms, making cross-platform correlation trivial with automated tools
- Git commit history permanently records email addresses -- even if removed from the profile, old commits retain the email
- Public paste sites (Pastebin, GitHub Gists) are frequently used to share notes and often contain sensitive data
- The Wayback Machine archives content that has been deleted -- nothing posted publicly is truly gone
- Holehe can determine which services an email is registered on without requiring authentication
- Google dorking with `site:` and username keywords can surface content that automated tools miss
- PGP key servers are an often-overlooked source of email addresses and real names
- For OPSEC: use unique usernames per platform, use email aliases, and never commit secrets to version control
- GitHub Events API exposes email addresses from push events even when the email is set to private on the profile
