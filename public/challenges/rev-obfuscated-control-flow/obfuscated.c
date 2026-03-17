/*
 * CTF Challenge: Obfuscated Control Flow
 *
 * Compile: gcc -O0 -o obfuscated obfuscated.c
 *
 * This binary uses control flow flattening - all logic blocks are placed
 * inside a while(1) { switch(state) { ... } } loop. This makes the CFG
 * (control flow graph) in disassemblers look like a flat star pattern
 * instead of the natural tree structure.
 *
 * Additionally, opaque predicates are used: conditions that always evaluate
 * the same way but are hard for static analysis to determine.
 *
 * To solve:
 *   1. Trace the state transitions to reconstruct the original logic flow
 *   2. Identify which states perform actual validation vs. dead code
 *   3. Extract the character-by-character checks
 *   4. Reconstruct the expected password from the comparison values
 *
 * VULNERABILITY: Despite the obfuscation, each state checks one or two
 * characters. Map state transitions and extract all checks.
 * The password is: fl4tt3n3d_fl0w
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Opaque predicate helpers - these always return predictable values
 * but are difficult for static analysis to resolve.
 * VULNERABILITY: Recognize these as opaque predicates that always
 * evaluate the same way. */
volatile int opaque_var = 7;

int opaque_true(void) {
    /* Always returns 1: (x*x - 1) is always even when x is odd */
    return ((opaque_var * opaque_var - 1) % 2) == 0;
}

int opaque_false(void) {
    /* Always returns 0: (x*x) for odd x is always odd, never divisible by 2 */
    return ((opaque_var * opaque_var) % 2) == 0;
}

int validate_password(const char *input) {
    int state = 0;
    int idx = 0;
    int valid = 1;
    int len = strlen(input);

    /* Expected password length: 14 characters */
    if (len != 14) return 0;

    /* VULNERABILITY: Control flow flattening.
     * All states are in a single switch. Trace state transitions
     * to understand the actual validation order. */
    while (1) {
        switch (state) {
            case 0:
                /* Entry state - check first char */
                if (input[0] != 'f') valid = 0;
                state = 7;  /* Non-sequential jump */
                break;

            case 1:
                /* Check input[4] */
                if (input[4] != 't') valid = 0;
                state = 11;
                break;

            case 2:
                /* DEAD CODE - opaque_false() is always 0 */
                if (opaque_false()) {
                    valid = 0;  /* Never reached */
                }
                state = 9;
                break;

            case 3:
                /* Check input[7] */
                if (input[7] != 'd') valid = 0;
                state = 13;
                break;

            case 4:
                /* Check input[10] */
                if (input[10] != 'l') valid = 0;
                state = 6;
                break;

            case 5:
                /* Check input[2] */
                if (input[2] != '4') valid = 0;
                state = 1;
                break;

            case 6:
                /* Check input[11] */
                if (input[11] != '0') valid = 0;
                state = 14;
                break;

            case 7:
                /* Check input[1] */
                if (input[1] != 'l') valid = 0;
                /* Opaque predicate: always goes to state 5 */
                if (opaque_true()) {
                    state = 5;
                } else {
                    state = 99;  /* Dead path */
                }
                break;

            case 8:
                /* Check input[6] */
                if (input[6] != '3') valid = 0;
                state = 3;
                break;

            case 9:
                /* Check input[9] */
                if (input[9] != 'f') valid = 0;
                state = 4;
                break;

            case 10:
                /* DEAD CODE state */
                valid = 0;
                state = 15;
                break;

            case 11:
                /* Check input[5] */
                if (input[5] != '3') valid = 0;
                state = 8;
                break;

            case 12:
                /* Check input[3] */
                if (input[3] != 't') valid = 0;
                /* Opaque predicate: always true */
                if (opaque_true()) {
                    state = 2;  /* Goes to dead-code-skip state */
                } else {
                    state = 10;  /* Dead path */
                }
                break;

            case 13:
                /* Check input[8] */
                if (input[8] != '_') valid = 0;
                state = 12;
                break;

            case 14:
                /* Check input[12] and input[13] */
                if (input[12] != 'w') valid = 0;
                if (input[13] != '\0') {
                    /* Actually check that input[13] exists but is last */
                    /* We already checked length == 14, so this is fine */
                }
                state = 15;
                break;

            case 15:
                /* Exit state */
                return valid;

            case 99:
                /* Dead code trap */
                return 0;

            default:
                return 0;
        }
    }
}

int main(int argc, char *argv[]) {
    char input[256];

    printf("=== Obfuscated Validator ===\n");
    printf("Enter password: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';

    if (validate_password(input)) {
        printf("[+] Password correct!\n");
        printf("[+] Flag: zemi{0bfusc4t3d_fl0w_r3v34l3d}\n");
    } else {
        printf("[-] Wrong password.\n");
        printf("[-] Hint: The control flow is flattened. Trace the states.\n");
    }

    return 0;
}
