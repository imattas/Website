/*
 * Ret2Win Challenge
 *
 * Vulnerability: The vuln() function uses gets() to read into a 64-byte
 * stack buffer. Since the binary is compiled with -fno-stack-protector and
 * -no-pie, an attacker can overflow the buffer, overwrite the saved return
 * address on the stack, and redirect execution to the win() function.
 *
 * The win() function exists in the binary but is never called normally.
 * Your goal is to find the address of win() and overwrite the return
 * address to jump there.
 *
 * Compile: make
 * Hint: Use `objdump -d ret2win | grep win` to find the address.
 *       Overflow = 64 bytes buffer + 8 bytes saved RBP + 8 bytes return address
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This function is never called in normal execution */
void win(void) {
    printf("\n[+] Congratulations! You redirected execution to win()!\n");
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("[-] flag.txt not found. Are you running this in the challenge directory?\n");
        exit(1);
    }
    char flag[128];
    fgets(flag, sizeof(flag), f);
    printf("[+] Flag: %s\n", flag);
    fclose(f);
    exit(0);
}

void vuln(void) {
    char buffer[64];

    printf("Enter your payload: ");

    /* VULNERABILITY: gets() allows writing past the buffer boundary,
     * overwriting the saved frame pointer and return address */
    gets(buffer);

    printf("You entered: %s\n", buffer);
    printf("Returning from vuln()...\n");
}

int main(void) {
    printf("=== Ret2Win Challenge ===\n");
    printf("There's a secret function in this binary. Can you call it?\n\n");

    /* Hint: print the address of win for beginners */
    printf("[DEBUG] win() is at: %p\n", (void *)win);
    printf("[DEBUG] vuln() is at: %p\n\n", (void *)vuln);

    vuln();

    printf("[-] Normal return from vuln(). Try harder!\n");
    return 0;
}
