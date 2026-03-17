/*
 * CTF Challenge: XOR Encryption Reversing
 *
 * Compile: gcc -o xorrev xorrev.c
 *
 * The flag is XOR-encrypted with a repeating key. The program XORs your
 * input with the same key and compares against the encrypted flag.
 *
 * To solve:
 *   1. Extract the encrypted flag bytes and XOR key from the binary.
 *   2. XOR the encrypted bytes with the key to recover the plaintext flag.
 *   3. Or, use a debugger to inspect memory after the XOR operation.
 *
 * VULNERABILITY: XOR encryption is its own inverse. If you know the key
 * and the ciphertext, plaintext = ciphertext ^ key.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* XOR key used for encryption */
static const char XOR_KEY[] = "DEADBEEF";
#define KEY_LEN 8

/*
 * VULNERABILITY: These are the flag bytes XOR'd with "DEADBEEF".
 * To recover: for each byte, flag[i] = encrypted_flag[i] ^ XOR_KEY[i % KEY_LEN]
 *
 * Plaintext flag: zemi{x0r_r3v3rs1ng_101}
 */
static const unsigned char encrypted_flag[] = {
    0x3e, 0x20, 0x28, 0x2d, 0x3d, 0x15, 0x55, 0x17,
    0x1e, 0x17, 0x59, 0x37, 0x1b, 0x16, 0x56, 0x36,
    0x2e, 0x22, 0x1e, 0x55, 0x54, 0x35, 0x54, 0x7c
};
#define FLAG_LEN 24

void xor_data(const char *input, char *output, int len) {
    int i;
    for (i = 0; i < len; i++) {
        output[i] = input[i] ^ XOR_KEY[i % KEY_LEN];
    }
}

int main(int argc, char *argv[]) {
    char input[256];
    char encrypted_input[256];
    int input_len;

    printf("=== XOR Reversing Challenge ===\n");
    printf("Enter the flag: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    /* Strip newline */
    input[strcspn(input, "\n")] = '\0';
    input_len = strlen(input);

    if (input_len != FLAG_LEN) {
        printf("[-] Wrong length. Expected %d characters.\n", FLAG_LEN);
        return 1;
    }

    /* XOR the user's input with the same key */
    xor_data(input, encrypted_input, input_len);

    /*
     * VULNERABILITY: Compare XOR'd input against stored encrypted flag.
     * Since XOR is reversible: flag = encrypted_flag ^ key
     */
    if (memcmp(encrypted_input, encrypted_flag, FLAG_LEN) == 0) {
        printf("[+] Correct! You found the flag: %s\n", input);
    } else {
        printf("[-] Wrong flag. Try XOR'ing the encrypted bytes with the key.\n");
    }

    return 0;
}
