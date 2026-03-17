/*
 * Buffer Overflow Challenge
 *
 * Vulnerability: The gets() function reads unbounded input into a fixed-size
 * buffer on the stack. The 'check' variable sits directly above the buffer
 * in memory. By overflowing the buffer, an attacker can overwrite 'check'
 * with the magic value 0xdeadbeef, which triggers the win() function.
 *
 * Compile: make
 * Exploit: Provide 64 bytes of padding + 0xdeadbeef (little-endian)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
    printf("\n[+] Access granted! Here is your flag:\n");
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("[-] flag.txt not found. Are you running this in the challenge directory?\n");
        exit(1);
    }
    char flag[128];
    fgets(flag, sizeof(flag), f);
    printf("%s\n", flag);
    fclose(f);
    exit(0);
}

int main(void) {
    volatile int check = 0;
    char buffer[64];

    printf("=== Buffer Overflow Challenge ===\n");
    printf("Can you change the 'check' variable?\n\n");
    printf("check is at: %p\n", (void *)&check);
    printf("buffer is at: %p\n", (void *)buffer);
    printf("Distance: %ld bytes\n\n", (long)((char *)&check - buffer));
    printf("Enter your input: ");

    /* VULNERABILITY: gets() performs no bounds checking */
    gets(buffer);

    printf("\nbuffer contents: %s\n", buffer);
    printf("check = 0x%08x\n", check);

    if (check == 0xdeadbeef) {
        win();
    } else {
        printf("[-] Nope! check must be 0xdeadbeef, but it is 0x%08x\n", check);
        printf("[-] Try again. Remember, you need to overflow the buffer!\n");
    }

    return 0;
}
