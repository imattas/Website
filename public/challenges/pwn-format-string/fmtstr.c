/*
 * Format String Challenge
 *
 * Vulnerability: The program passes user-controlled input directly to
 * printf() without a format specifier: printf(buffer) instead of
 * printf("%s", buffer). This allows an attacker to:
 *
 *   1. Read from the stack using %x, %p, %s format specifiers
 *   2. Write to arbitrary memory using %n
 *   3. Leak the secret value and/or overwrite it to match the target
 *
 * Goal: Overwrite the 'secret' variable to equal 'target' (0x1337)
 *       to trigger the flag printing code.
 *
 * Compile: make
 * Hint: Use %p to leak stack values, find the secret's address,
 *       then use %n to write 0x1337 to it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global secret variable -- your target for overwrite */
int secret = 0;
const int target = 0x1337;

void print_flag(void) {
    printf("\n[+] Secret matches target! Here's your flag:\n");
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("[-] flag.txt not found. Are you running this in the challenge directory?\n");
        exit(1);
    }
    char flag[128];
    fgets(flag, sizeof(flag), f);
    printf("[+] %s\n", flag);
    fclose(f);
}

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    char buffer[256];
    int i;

    setup();

    printf("=== Format String Challenge ===\n");
    printf("Leak the secret, then overwrite it!\n\n");

    printf("[*] secret is at: %p (current value: 0x%x)\n", (void *)&secret, secret);
    printf("[*] target value: 0x%x\n", target);
    printf("[*] Hint: You need to write %d (0x%x) to the secret variable\n\n",
           target, target);

    for (i = 0; i < 3; i++) {
        printf("Round %d/3 - Enter format string: ", i + 1);
        fflush(stdout);

        if (fgets(buffer, sizeof(buffer), stdin) == NULL)
            break;

        /* Remove trailing newline */
        buffer[strcspn(buffer, "\n")] = '\0';

        printf("Output: ");

        /* VULNERABILITY: User input passed directly as format string.
         * printf(buffer) instead of printf("%s", buffer) */
        printf(buffer);

        printf("\n");
        printf("[*] secret = 0x%x (need 0x%x)\n\n", secret, target);

        if (secret == target) {
            print_flag();
            return 0;
        }
    }

    if (secret != target) {
        printf("[-] secret is 0x%x, but needs to be 0x%x. Try again!\n", secret, target);
    }

    return 0;
}
