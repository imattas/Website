/*
 * CTF Challenge: Binary Patching
 *
 * Compile: gcc -o patchme patchme.c
 *
 * This binary performs license key validation with multiple checks.
 * The final check is intentionally inverted - it rejects valid keys.
 * You need to patch the binary to flip the conditional jump:
 *   - Find the JNE (0x75) instruction after the final comparison
 *   - Patch it to JE (0x74) so valid keys are accepted
 *
 * Approach:
 *   1. Disassemble with objdump or load in Ghidra
 *   2. Find the final_check() function
 *   3. Locate the conditional jump after the comparison
 *   4. Patch JNE -> JE (change byte 0x75 to 0x74)
 *   5. Or use radare2: `r2 -w patchme` then seek and patch
 *
 * VULNERABILITY: The final validation logic is inverted. A correct key
 * will be rejected unless the binary is patched.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LICENSE_KEY_LEN 16

/* Check 1: Key must start with "ZEMI-" */
int check_prefix(const char *key) {
    return strncmp(key, "ZEMI-", 5) == 0;
}

/* Check 2: Key must be exactly LICENSE_KEY_LEN characters */
int check_length(const char *key) {
    return strlen(key) == LICENSE_KEY_LEN;
}

/* Check 3: Characters at positions 5-8 must be hex digits */
int check_hex_segment(const char *key) {
    int i;
    for (i = 5; i < 9; i++) {
        char c = key[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* Check 4: Position 9 must be '-' */
int check_separator(const char *key) {
    return key[9] == '-';
}

/* Check 5: Checksum of last 6 characters must equal 0x1F4 */
int check_checksum(const char *key) {
    int sum = 0;
    int i;
    for (i = 10; i < 16; i++) {
        sum += (unsigned char)key[i];
    }
    return sum == 0x1F4;
}

/*
 * VULNERABILITY: This is the check you need to PATCH.
 * The comparison result is intentionally INVERTED.
 * In assembly, this compiles to a JNE (jump if not equal).
 * Patch the JNE (0x75) to JE (0x74) to fix the logic.
 *
 * A valid key like "ZEMI-CAFE-rrrrrr" would pass all checks
 * but get rejected here unless patched.
 */
int final_check(const char *key) {
    int valid = 1;

    valid &= check_prefix(key);
    valid &= check_length(key);
    valid &= check_hex_segment(key);
    valid &= check_separator(key);
    valid &= check_checksum(key);

    /* BUG (intentional): Logic is inverted!
     * This should be `if (valid)` but it's `if (!valid)`.
     * In the binary, patch the JNE to JE after the test instruction. */
    if (!valid) {
        return 1;  /* Returns success when checks FAIL */
    } else {
        return 0;  /* Returns failure when checks PASS */
    }
}

void print_flag(void) {
    printf("[+] License validated!\n");
    printf("[+] Flag: zemi{p4tch3d_4nd_cr4ck3d}\n");
}

int main(int argc, char *argv[]) {
    char key[256];

    printf("=== License Validator v3.2 ===\n");
    printf("Enter license key: ");
    fflush(stdout);

    if (fgets(key, sizeof(key), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    /* Strip newline */
    key[strcspn(key, "\n")] = '\0';

    if (final_check(key)) {
        print_flag();
    } else {
        printf("[-] Invalid license key.\n");
        printf("[-] Hint: Sometimes the logic is... backwards.\n");
    }

    return 0;
}
