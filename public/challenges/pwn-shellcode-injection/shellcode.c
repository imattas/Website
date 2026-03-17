/*
 * Shellcode Injection Challenge
 *
 * Vulnerability: The program allocates a buffer on the stack, reads user
 * input into it, then casts the buffer to a function pointer and calls it.
 * Because the binary is compiled with -z execstack, the stack is executable,
 * allowing injected machine code to run directly.
 *
 * Your goal is to write shellcode that reads and prints flag.txt, or
 * spawns a shell so you can cat flag.txt yourself.
 *
 * Compile: make
 * Hint: The stack is executable. Write your shellcode, pipe it in.
 *       Example shellcode: execve("/bin/sh", NULL, NULL)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define BUFSIZE 256

int main(void) {
    char shellcode[BUFSIZE];
    int n;

    printf("=== Shellcode Injection Challenge ===\n");
    printf("I'll read your shellcode and execute it.\n\n");

    printf("[*] Shellcode buffer is at: %p\n", (void *)shellcode);
    printf("[*] Buffer size: %d bytes\n", BUFSIZE);
    printf("[*] The stack is executable (compiled with -z execstack)\n\n");

    printf("Enter your shellcode (raw bytes, up to %d bytes): ", BUFSIZE);
    fflush(stdout);

    /* Read raw bytes from stdin */
    n = read(0, shellcode, BUFSIZE);

    if (n <= 0) {
        printf("[-] No input received.\n");
        return 1;
    }

    printf("[*] Received %d bytes of shellcode.\n", n);
    printf("[*] Jumping to shellcode...\n\n");

    /* VULNERABILITY: Casting user-controlled data to a function pointer
     * and calling it. With an executable stack, this runs arbitrary code. */
    void (*func)(void) = (void (*)(void))shellcode;
    func();

    /* If shellcode returns normally */
    printf("[-] Shellcode returned. Did it work?\n");
    return 0;
}
