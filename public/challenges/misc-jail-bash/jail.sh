#!/bin/bash
# Misc Challenge: Bash Jail
# A restricted bash environment. Players must escape rbash restrictions
# to read flag.txt.
#
# Usage: bash jail.sh
#
# Intended escape vectors:
#   - vi/vim :!/bin/bash or :set shell=/bin/bash
#   - awk 'BEGIN {system("/bin/bash")}'
#   - python3 -c 'import os; os.system("/bin/bash")'
#   - find / -exec /bin/bash \;
#   - Using $() or `` in allowed commands

FLAG="zemi{b4sh_j41l_3sc4p3d}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAG_FILE="${SCRIPT_DIR}/flag.txt"

# Ensure flag file exists
echo "${FLAG}" > "${FLAG_FILE}"
chmod 444 "${FLAG_FILE}"

# Create a restricted environment
JAIL_DIR=$(mktemp -d /tmp/bash_jail.XXXXXX)
JAIL_BIN="${JAIL_DIR}/bin"
mkdir -p "${JAIL_BIN}"

# Only allow a few commands in the jail
ALLOWED_COMMANDS=(ls echo whoami id pwd date hostname uname)

for cmd in "${ALLOWED_COMMANDS[@]}"; do
    cmd_path=$(which "${cmd}" 2>/dev/null)
    if [ -n "${cmd_path}" ]; then
        cp "${cmd_path}" "${JAIL_BIN}/"
    fi
done

# Copy the flag into the jail
cp "${FLAG_FILE}" "${JAIL_DIR}/flag.txt"

cat << 'BANNER'
  ____            _          _       _ _
 | __ )  __ _ ___| |__      | | __ _(_) |
 |  _ \ / _` / __| '_ \  _ | |/ _` | | |
 | |_) | (_| \__ \ | | || || | (_| | | |
 |____/ \__,_|___/_| |_| \__/ \__,_|_|_|

 Welcome to the Bash Jail!
 You are in a restricted shell with limited commands.
 The flag is in flag.txt in the current directory.
 Can you read it?

 Available commands: ls echo whoami id pwd date hostname uname
 Type 'exit' to leave.

BANNER

echo "Allowed commands: ${ALLOWED_COMMANDS[*]}"
echo ""

# Drop into restricted shell
export PATH="${JAIL_BIN}"
export HOME="${JAIL_DIR}"
export SHELL="${JAIL_BIN}/bash" 2>/dev/null || true

cd "${JAIL_DIR}"

# Run a restricted loop (simulated rbash)
while true; do
    read -r -p "jail$ " input || { echo; break; }

    [ -z "${input}" ] && continue
    [ "${input}" = "exit" ] && break
    [ "${input}" = "quit" ] && break

    # Get the command name (first word)
    cmd_name=$(echo "${input}" | awk '{print $1}')

    # Check against blacklist
    blacklisted=0
    for blocked in cat less more head tail tac nl rev vim vi nano sed awk python python3 perl ruby bash sh zsh fish tee dd cp mv; do
        if [ "${cmd_name}" = "${blocked}" ]; then
            echo "bash: ${cmd_name}: restricted - command not allowed"
            blacklisted=1
            break
        fi
    done

    # Check for suspicious characters
    if echo "${input}" | grep -qE '[|;&><\$\`\\]'; then
        echo "bash: restricted - special characters not allowed"
        blacklisted=1
    fi

    # Check for path traversal
    if echo "${input}" | grep -qE '(\.\./|/bin/|/usr/|/etc/)'; then
        echo "bash: restricted - path traversal not allowed"
        blacklisted=1
    fi

    if [ "${blacklisted}" -eq 0 ]; then
        # Check if command exists in jail
        if [ -f "${JAIL_BIN}/${cmd_name}" ]; then
            eval "${input}" 2>&1
        else
            echo "bash: ${cmd_name}: command not found"
        fi
    fi
done

echo "Bye!"

# Cleanup
rm -rf "${JAIL_DIR}"
