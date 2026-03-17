---
title: "Misc - Git Forensics"
description: "Recovering a deleted flag from git commit history by searching through diffs, deleted files, stashes, and dangling commits."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Easy         |
| Points     | 100          |
| Flag       | `zemi{g1t_h1st0ry_n3v3r_l13s}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/misc-git-forensics/flag.txt)
- [setup.sh](/Website/challenges/misc-git-forensics/setup.sh)

## Reconnaissance

We are given a tarball containing a git repository:

```bash
tar -xzf git-forensics.tar.gz
cd suspicious-repo
ls -la
```

```
total 16
drwxr-xr-x  3 user user 4096 Feb 10 12:00 .
drwxr-xr-x  5 user user 4096 Feb 10 12:00 ..
drwxr-xr-x  8 user user 4096 Feb 10 12:00 .git
-rw-r--r--  1 user user   42 Feb 10 12:00 README.md
```

Only a `README.md` in the working tree — nothing interesting:

```bash
cat README.md
```

```
# Project Alpha
Nothing to see here. Move along.
```

The flag must be hiding somewhere in the git history. Time to dig.

## Analysis

Git never truly deletes data until garbage collection runs. Even "removed" files, reverted commits, and abandoned branches leave traces in the object store. Our plan:

1. Check commit history across all branches
2. Search diffs for the flag pattern
3. Look for deleted files
4. Inspect stashes
5. Hunt for dangling/unreachable commits

## Step-by-Step Walkthrough

### Step 1: Examine the full commit log

```bash
git log --all --oneline --graph
```

```
* a3f9c21 (HEAD -> main) Remove sensitive data
* 7b2e4d8 Clean up project files
* e5c1a9f Update README
* 1d4f6b3 Add configuration
* 8a2c5e7 Initial commit
```

Five commits. The message "Remove sensitive data" is suspicious — let's look there first.

### Step 2: Diff the suspicious commit

```bash
git diff 7b2e4d8..a3f9c21
```

```diff
diff --git a/config/secrets.yml b/config/secrets.yml
deleted file mode 100644
index 3e7a1b2..0000000
--- a/config/secrets.yml
+++ /dev/null
@@ -1,5 +0,0 @@
-database:
-  host: localhost
-  user: admin
-  password: supersecret123
-  api_key: not_the_flag_sorry
```

A deleted secrets file, but no flag. Let's search more broadly.

### Step 3: Search all commits for the flag pattern

The most powerful approach — search every commit's patch for the flag format:

```bash
git log -p --all -S "zemi{" --format="%h %s"
```

```
7b2e4d8 Clean up project files
diff --git a/notes/todo.txt b/notes/todo.txt
deleted file mode 100644
index 9d1f3a2..0000000
--- a/notes/todo.txt
+++ /dev/null
@@ -1,4 +0,0 @@
-TODO:
-- Deploy to production
-- Remember to remove the flag: zemi{g1t_h1st0ry_n3v3r_l13s}
-- Update documentation
```

Found it. The flag was in `notes/todo.txt`, added in an earlier commit and deleted in `7b2e4d8` ("Clean up project files").

### Step 4: Verify by checking the file at that commit's parent

We can also recover the file directly:

```bash
git show 1d4f6b3:notes/todo.txt
```

```
TODO:
- Deploy to production
- Remember to remove the flag: zemi{g1t_h1st0ry_n3v3r_l13s}
- Update documentation
```

## Alternative Discovery Methods

### Finding deleted files

If we did not know the flag format, we could list all deleted files:

```bash
git log --diff-filter=D --summary --all
```

```
commit 7b2e4d8...
    Clean up project files
 delete mode 100644 notes/todo.txt

commit a3f9c21...
    Remove sensitive data
 delete mode 100644 config/secrets.yml
```

Then inspect each deleted file at the commit before its deletion.

### Checking stashes

Sometimes flags are hidden in stashed changes:

```bash
git stash list
```

```
stash@{0}: WIP on main: 8a2c5e7 Initial commit
```

```bash
git stash show -p stash@{0}
```

```diff
diff --git a/draft.txt b/draft.txt
new file mode 100644
+++ b/draft.txt
@@ -0,0 +1 @@
+This was a red herring stash. No flag here.
```

Nothing in the stash this time, but always check.

### Checking other branches

```bash
git branch -a
```

```
* main
  dev
```

```bash
git log dev --oneline
```

```
e5c1a9f Update README
1d4f6b3 Add configuration
8a2c5e7 Initial commit
```

The `dev` branch diverged before the flag was deleted, so the file would still exist there.

### Finding dangling commits

After force pushes or rebases, orphaned commits remain:

```bash
git fsck --unreachable --no-reflogs
```

```
unreachable commit f4a8b2c1d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9
```

```bash
git show f4a8b2c
```

```
commit f4a8b2c...
Author: dev <dev@local>
Date:   Tue Feb 10 11:30:00 2026

    Oops, committed the flag

diff --git a/flag.txt b/flag.txt
new file mode 100644
+++ b/flag.txt
@@ -0,0 +1 @@
+zemi{g1t_h1st0ry_n3v3r_l13s}
```

Dangling commits are a goldmine in CTF challenges.

## Quick Reference: Git Forensics Commands

```bash
# Full history across all branches
git log --all --oneline --graph

# Search for a string across all commits
git log -p --all -S "search_term"

# Find deleted files
git log --diff-filter=D --summary --all

# View a file at a specific commit
git show <commit>:<filepath>

# List stashes
git stash list
git stash show -p stash@{0}

# Find orphaned commits
git fsck --unreachable --no-reflogs

# Search commit messages
git log --all --grep="keyword"

# List all branches (including remote)
git branch -a
```

## Tools Used

- Git — repository history inspection
- Standard command-line tools (grep, cat)

## Lessons Learned

- Git never forgets — deleting a file only removes it from the working tree, not from the object store
- `git log -p --all -S "pattern"` is the single most useful forensics command — it searches every patch in every branch for a string
- Always check stashes, other branches, and dangling/unreachable commits
- `git fsck --unreachable` reveals commits that were rebased away or created on detached HEAD
- In real-world security, use tools like `trufflehog` or `git-secrets` to prevent committing sensitive data, and use `git filter-branch` or BFG Repo-Cleaner to truly purge secrets from history
