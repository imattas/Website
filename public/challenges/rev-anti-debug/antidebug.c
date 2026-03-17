/*
 * CTF Challenge: Anti-Debug Bypass
 *
 * Compile: gcc -o antidebug antidebug.c
 *
 * This binary uses multiple anti-debugging techniques:
 *   1. ptrace(PTRACE_TRACEME) - detects if a debugger is attached
 *   2. Timing check - measures execution time to detect single-stepping
 *   3. /proc/self/status - checks TracerPid field for attached debugger
 *
 * To solve, bypass all anti-debug checks:
 *   - Patch ptrace calls (NOP them out or force return 0)
 *   - LD_PRELOAD a fake ptrace that always returns 0
 *   - Patch timing checks
 *   - Use `set $eax = 0` in GDB after ptrace calls
 *   - Modify /proc check or patch the branch
 *
 * VULNERABILITY: All anti-debug checks can be bypassed by patching,
 * LD_PRELOAD, or using GDB scripting. The flag is decrypted in memory
 * after all checks pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <unistd.h>

/* VULNERABILITY: Anti-debug check #1 - ptrace(PTRACE_TRACEME)
 * If a debugger is already attached, this returns -1.
 * Bypass: LD_PRELOAD a library that overrides ptrace to return 0,
 * or NOP out the call in the binary. */
int check_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        return 1;  /* Debugger detected */
    }
    return 0;
}

/* VULNERABILITY: Anti-debug check #2 - Timing check
 * Measures clock cycles. Single-stepping in a debugger will cause
 * the elapsed time to be much larger than normal execution.
 * Bypass: Patch the comparison or set a breakpoint after the check. */
int check_timing(void) {
    struct timespec start, end;
    long elapsed;

    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Dummy computation to measure */
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i * i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    elapsed = (end.tv_sec - start.tv_sec) * 1000000000L +
              (end.tv_nsec - start.tv_nsec);

    /* If loop took more than 10ms, likely being debugged */
    if (elapsed > 10000000L) {
        return 1;  /* Debugger detected */
    }
    return 0;
}

/* VULNERABILITY: Anti-debug check #3 - /proc/self/status
 * Reads TracerPid from /proc/self/status. Non-zero means a tracer
 * (debugger) is attached.
 * Bypass: Patch the fopen/fgets calls, or modify the comparison. */
int check_proc_status(void) {
    FILE *f;
    char line[256];

    f = fopen("/proc/self/status", "r");
    if (f == NULL) {
        return 0;  /* Can't check, assume OK */
    }

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            if (pid != 0) {
                return 1;  /* Debugger detected */
            }
            return 0;
        }
    }

    fclose(f);
    return 0;
}

/* Decrypt and print the flag after all checks pass */
void decrypt_flag(void) {
    /* XOR-encrypted flag with key 0xAA */
    unsigned char enc[] = {
        0xd0, 0xcf, 0xc7, 0xc9, 0xd1, 0x8e, 0xcb, 0xc4,
        0x89, 0x8e, 0xc6, 0x89, 0xc8, 0xce, 0xc5, 0xd1,
        0xd0, 0x84, 0xc8, 0xd3, 0xd8, 0x8e, 0xc2, 0xd3,
        0xd8, 0x89, 0xc2, 0xc2, 0xcf, 0xc6, 0xd1
    };
    /* ^^^ XOR 0xAA produces: zemi{4nt1_d3bug_byp4ss3d} */
    int len = sizeof(enc);
    char flag[64];

    for (int i = 0; i < len; i++) {
        flag[i] = enc[i] ^ 0xAA;
    }
    flag[len] = '\0';

    printf("[+] All anti-debug checks passed!\n");
    printf("[+] Flag: %s\n", flag);
}

int main(int argc, char *argv[]) {
    printf("=== Anti-Debug Challenge ===\n");
    printf("[*] Running integrity checks...\n");

    /* Anti-debug check #1 */
    if (check_ptrace()) {
        printf("[-] Integrity check failed. (ptrace)\n");
        printf("[-] Nice try, debugger detected!\n");
        return 1;
    }
    printf("[*] Check 1/3 passed.\n");

    /* Anti-debug check #2 */
    if (check_timing()) {
        printf("[-] Integrity check failed. (timing)\n");
        printf("[-] Execution too slow - are you single-stepping?\n");
        return 1;
    }
    printf("[*] Check 2/3 passed.\n");

    /* Anti-debug check #3 */
    if (check_proc_status()) {
        printf("[-] Integrity check failed. (proc)\n");
        printf("[-] TracerPid is non-zero!\n");
        return 1;
    }
    printf("[*] Check 3/3 passed.\n");

    decrypt_flag();

    return 0;
}
