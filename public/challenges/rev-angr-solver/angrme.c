/*
 * CTF Challenge: Angr Solver
 *
 * Compile: gcc -o angrme angrme.c
 *
 * This binary has multi-stage mathematical validation that is extremely
 * tedious to solve manually but trivial with angr (symbolic execution).
 *
 * Approach with angr:
 *   1. Find the address of "Access Granted" (the target)
 *   2. Find the address of "Access Denied" (to avoid)
 *   3. Let angr explore paths symbolically
 *
 * Example angr script:
 *   import angr
 *   p = angr.Project('./angrme')
 *   state = p.factory.entry_state()
 *   sm = p.factory.simulation_manager(state)
 *   sm.explore(find=ADDR_GRANTED, avoid=ADDR_DENIED)
 *   print(sm.found[0].posix.dumps(0))
 *
 * VULNERABILITY: The math checks are solvable by constraint solving.
 * Each stage constrains a few characters of the 24-byte input.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INPUT_LEN 24

/* Stage 1: Check characters 0-5
 * VULNERABILITY: Linear constraints solvable by angr */
int stage1(const char *input) {
    if ((input[0] * 3 + input[1] * 7) != 857) return 0;
    if ((input[1] - input[2]) != -51) return 0;
    if ((input[2] ^ input[3]) != 22) return 0;
    if ((input[3] + input[4] + input[5]) != 266) return 0;
    if ((input[4] * 2 - input[5]) != 79) return 0;
    if ((input[0] + input[5]) != 219) return 0;
    return 1;
}

/* Stage 2: Check characters 6-11
 * VULNERABILITY: More linear/XOR constraints */
int stage2(const char *input) {
    if ((input[6] ^ 0x55) != 0x24) return 0;
    if ((input[7] + input[8]) != 209) return 0;
    if ((input[8] * input[9]) != 11988) return 0;
    if ((input[9] - input[10]) != -14) return 0;
    if ((input[10] ^ input[11]) != 87) return 0;
    if ((input[6] + input[11]) != 210) return 0;
    return 1;
}

/* Stage 3: Check characters 12-17
 * VULNERABILITY: Quadratic-looking but still linear for SMT */
int stage3(const char *input) {
    if (((input[12] * input[12]) % 256) != 25) return 0;
    if ((input[13] + input[14]) != 163) return 0;
    if ((input[14] ^ input[15]) != 0x45) return 0;
    if ((input[15] * 3) != 306) return 0;
    if ((input[16] - input[17]) != 2) return 0;
    if ((input[12] + input[17]) != 166) return 0;
    return 1;
}

/* Stage 4: Check characters 18-23
 * VULNERABILITY: Final set of constraints */
int stage4(const char *input) {
    if ((input[18] ^ 0x37) != 0x06) return 0;
    if ((input[19] + input[20]) != 153) return 0;
    if ((input[20] * 2) != 98) return 0;
    if ((input[21] ^ input[22]) != 0x57) return 0;
    if ((input[22] + input[23]) != 196) return 0;
    if ((input[18] + input[23]) != 174) return 0;
    return 1;
}

/* Cross-stage validation: mixes characters from different stages */
int cross_check(const char *input) {
    if ((input[0] + input[12]) != 154) return 0;
    if ((input[6] ^ input[18]) != 0x52) return 0;
    if ((input[3] + input[9] + input[15] + input[21]) != 406) return 0;
    return 1;
}

int main(int argc, char *argv[]) {
    char input[256];

    printf("=== Ultra Secure Validator v4.0 ===\n");
    printf("Enter access code (%d chars): ", INPUT_LEN);
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';

    if (strlen(input) != INPUT_LEN) {
        printf("Access Denied\n");
        return 1;
    }

    if (stage1(input) && stage2(input) && stage3(input) &&
        stage4(input) && cross_check(input)) {
        /* TARGET ADDRESS for angr: look for this string */
        printf("Access Granted\n");
        printf("Flag: zemi{4ngr_s0lv3s_1t_4ll}\n");
    } else {
        /* AVOID ADDRESS for angr: look for this string */
        printf("Access Denied\n");
    }

    return 0;
}
