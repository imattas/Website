/*
 * Ret2Libc Challenge
 *
 * Vulnerability: The program uses gets() in vuln(), creating a classic
 * stack buffer overflow. However, unlike ret2win, there is NO win() function
 * in this binary. The stack is also non-executable (NX enabled by default).
 *
 * To exploit this, you must use a ret2libc attack:
 *   1. Leak a libc address (puts@GOT via puts@PLT)
 *   2. Calculate libc base address
 *   3. Call system("/bin/sh") using libc gadgets
 *
 * Compile: make
 * Hint: Use puts() to leak its own GOT entry, then return to main()
 *       to send a second payload with system("/bin/sh").
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln(void) {
    char buffer[64];

    printf("Enter your payload: ");
    fflush(stdout);

    /* VULNERABILITY: gets() allows unbounded stack write.
     * No win function exists -- you need to ret2libc. */
    gets(buffer);

    printf("You said: %s\n", buffer);
}

void setup(void) {
    /* Disable buffering for clean I/O */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    setup();

    printf("=== Ret2Libc Challenge ===\n");
    printf("No win function here. You'll need libc.\n\n");

    /* Useful addresses for building your ROP chain */
    printf("[*] puts@plt: %p\n", (void *)puts);
    printf("[*] main: %p\n", (void *)main);
    printf("[*] Hint: Leak a GOT entry, calculate libc base, call system(\"/bin/sh\")\n\n");

    vuln();

    printf("[-] Returned normally. Try again!\n");
    return 0;
}
