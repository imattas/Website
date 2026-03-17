/*
 * CTF Challenge: Reversing CrackMe
 *
 * Compile: gcc -o crackme crackme.c
 *
 * The password is constructed on the stack using hex values to avoid
 * appearing in plaintext strings. Use Ghidra or IDA to trace the
 * stack assignments and reconstruct the password.
 *
 * Hint: Look at the hex values being moved onto the stack in the
 * check_password() function. Convert them to ASCII.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* VULNERABILITY: The flag is XOR-encrypted with a single-byte key.
 * In Ghidra, you can see the encrypted bytes and the key in decrypt_flag(). */
void decrypt_flag(void) {
    /* XOR key: 0x42 */
    unsigned char enc[] = {
        0x38, 0x27, 0x2d, 0x2b, 0x3b, 0x25, 0x30, 0x73,
        0x26, 0x34, 0x73, 0x63, 0x2b, 0x7b, 0x73, 0x31,
        0x35, 0x7b, 0x22, 0x71, 0x75, 0x31, 0x74, 0x73,
        0x24, 0x36, 0x73, 0x27, 0x76, 0x3d
    };
    /* ^^^ These bytes XOR 0x42 produce: zemi{gh1dr4_1s_my_b3st_fr13nd} */
    int len = sizeof(enc);
    char flag[64];
    int i;

    for (i = 0; i < len; i++) {
        flag[i] = enc[i] ^ 0x42;
    }
    flag[len] = '\0';

    printf("Congratulations! Flag: %s\n", flag);
}

/* VULNERABILITY: The password is built character-by-character on the stack.
 * In a disassembler, you'll see MOV instructions placing each byte.
 * Reconstruct the ASCII string from the hex values. */
int check_password(const char *input) {
    char password[16];

    /* Password constructed on stack to avoid showing in `strings` output */
    password[0]  = 0x53;  /* S */
    password[1]  = 0x33;  /* 3 */
    password[2]  = 0x63;  /* c */
    password[3]  = 0x72;  /* r */
    password[4]  = 0x33;  /* 3 */
    password[5]  = 0x74;  /* t */
    password[6]  = 0x4b;  /* K */
    password[7]  = 0x33;  /* 3 */
    password[8]  = 0x79;  /* y */
    password[9]  = 0x21;  /* ! */
    password[10] = 0x00;  /* null terminator */

    /* The actual password is: S3cr3tK3y! */
    return strcmp(input, password) == 0;
}

int main(int argc, char *argv[]) {
    char input[256];

    printf("=== CrackMe v1.0 ===\n");
    printf("Enter password: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Error reading input.\n");
        return 1;
    }

    /* Strip newline */
    input[strcspn(input, "\n")] = '\0';

    if (check_password(input)) {
        decrypt_flag();
    } else {
        printf("Wrong password. Try harder!\n");
    }

    return 0;
}
