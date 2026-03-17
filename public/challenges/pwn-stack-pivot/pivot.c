/*
 * Stack Pivot Challenge
 *
 * Vulnerability: The vuln() function has a small buffer (only 32 bytes)
 * and the overflow only allows overwriting 16 bytes past the return
 * address -- not enough for a full ROP chain. However, there is a large
 * globally-accessible buffer in the BSS section where we can stage a
 * full ROP chain.
 *
 * Strategy:
 *   1. First, write your full ROP chain into the BSS staging buffer
 *      (the program reads into it for you)
 *   2. Then, overflow the small stack buffer with a short pivot gadget
 *      that moves RSP to point at the BSS staging area
 *   3. When the function returns, it "pivots" the stack to BSS and
 *      executes your staged ROP chain
 *
 * Compile: make
 * Hint: Look for "leave; ret" or "xchg rsp, rax; ret" gadgets.
 *       Stage your payload in the bss_stage buffer, then pivot to it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Large BSS buffer for staging the ROP chain */
char bss_stage[4096] __attribute__((aligned(16)));

void win(void) {
    printf("\n[+] Stack pivot successful! Flag:\n");
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("[-] flag.txt not found. Are you running this in the challenge directory?\n");
        exit(1);
    }
    char flag[128];
    fgets(flag, sizeof(flag), f);
    printf("[+] %s\n", flag);
    fclose(f);
    exit(0);
}

/* This function exists to provide a "leave; ret" gadget in the binary */
void pivot_gadget(void) {
    __asm__ volatile (
        "nop\n"
        "nop\n"
        /* The function epilogue (leave; ret) is the gadget we need.
         * leave = mov rsp, rbp; pop rbp
         * If we control rbp, we control rsp after leave. */
    );
}

void vuln(void) {
    char small_buf[32];

    printf("[*] Enter payload for small buffer (overflow limited to 16 bytes past ret):\n");
    printf(">>> ");
    fflush(stdout);

    /* VULNERABILITY: read() allows slight overflow past return address.
     * Buffer is 32 bytes, but we read 32 + 8 (saved RBP) + 16 = 56 bytes.
     * That's only enough for saved RBP + return address + one gadget address.
     * Not enough for a full ROP chain -- must pivot! */
    read(0, small_buf, 32 + 8 + 16);

    printf("[*] Returning from vuln()...\n");
}

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    setup();

    printf("=== Stack Pivot Challenge ===\n");
    printf("Limited overflow, but a large staging area awaits.\n\n");

    printf("[*] bss_stage buffer: %p (%zu bytes)\n", (void *)bss_stage, sizeof(bss_stage));
    printf("[*] win():            %p\n", (void *)win);
    printf("[*] pivot_gadget():   %p\n\n", (void *)pivot_gadget);

    /* Phase 1: Read the staged ROP chain into BSS */
    printf("[*] Phase 1: Stage your ROP chain in BSS.\n");
    printf("[*] Enter your staged payload (up to 4096 bytes):\n");
    printf(">>> ");
    fflush(stdout);

    int n = read(0, bss_stage, sizeof(bss_stage));
    printf("[*] Staged %d bytes at %p\n\n", n, (void *)bss_stage);

    /* Phase 2: Trigger the overflow and pivot */
    printf("[*] Phase 2: Now overflow the small buffer and pivot the stack.\n");
    vuln();

    printf("[-] Normal return. Your pivot didn't work. Try again!\n");
    return 0;
}
