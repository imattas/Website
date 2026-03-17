/*
 * CTF Challenge: Strings & Ltrace
 *
 * Compile: gcc -o easyrev easyrev.c
 *
 * This is an introductory reversing challenge. The password is compared
 * using strcmp(), which means two easy approaches:
 *
 *   1. Run `strings easyrev` to find the hardcoded password.
 *   2. Run `ltrace ./easyrev` and type anything - ltrace will show
 *      the strcmp() call with both arguments in plaintext.
 *
 * VULNERABILITY: The password is a plaintext string literal, and the
 * comparison uses strcmp() which ltrace can intercept.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Hardcoded password - visible via `strings` */
#define SECRET_PASSWORD "sup3r_s3cr3t_p4ssw0rd"

void print_banner(void) {
    printf("+---------------------------------+\n");
    printf("|     EasyRev Login System v2.1   |\n");
    printf("+---------------------------------+\n");
}

void grant_access(void) {
    printf("\n[+] Access Granted!\n");
    /* VULNERABILITY: Flag is also a plaintext string */
    printf("[+] Flag: zemi{str1ngs_4r3_y0ur_fr13nd}\n");
    printf("[+] Well done! Now try a harder challenge.\n");
}

void deny_access(void) {
    printf("\n[-] Access Denied.\n");
    printf("[-] Hint: Have you tried `strings` or `ltrace`?\n");
}

int main(int argc, char *argv[]) {
    char input[256];

    print_banner();
    printf("\nUsername: admin\n");
    printf("Password: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    /* Strip newline */
    input[strcspn(input, "\n")] = '\0';

    /* VULNERABILITY: strcmp is interceptable by ltrace.
     * Running `ltrace ./easyrev` will show:
     * strcmp("your_input", "sup3r_s3cr3t_p4ssw0rd") = ...
     */
    if (strcmp(input, SECRET_PASSWORD) == 0) {
        grant_access();
    } else {
        deny_access();
    }

    return 0;
}
