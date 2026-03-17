/*
 * ROP Chains Challenge
 *
 * Vulnerability: Classic stack buffer overflow via gets(). The binary has
 * NX enabled (no executable stack), so you must use Return-Oriented
 * Programming (ROP) to chain together existing code snippets ("gadgets")
 * to achieve arbitrary code execution.
 *
 * The binary provides several "helper" functions that serve as useful
 * gadgets. Chain them together to:
 *   1. Set the correct argument registers
 *   2. Open, read, and print flag.txt
 *
 * Compile: make
 * Hint: Use ROPgadget or ropper to find gadgets. Chain the helper
 *       functions in the right order to read the flag.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* Useful gadget functions -- these provide building blocks for your chain */

/* Sets the first argument register (rdi on x86_64) */
void set_arg1(void) {
    /* This function's epilogue with a pop rdi; ret gadget is useful */
    __asm__ volatile (
        "nop\n"
    );
}

/* Opens a file and returns the fd */
int open_file(const char *filename) {
    printf("[gadget] Opening file: %s\n", filename);
    return open(filename, O_RDONLY);
}

/* Reads from fd into a global buffer */
char read_buf[256];
void read_from_fd(int fd) {
    printf("[gadget] Reading from fd %d\n", fd);
    int n = read(fd, read_buf, sizeof(read_buf) - 1);
    if (n > 0) read_buf[n] = '\0';
}

/* Prints the global buffer */
void print_buf(void) {
    printf("[gadget] Buffer contents: %s\n", read_buf);
}

/* Calls system() with an argument */
void call_system(const char *cmd) {
    printf("[gadget] Executing: %s\n", cmd);
    system(cmd);
}

/* Provides a useful string in the binary */
const char *flag_path = "flag.txt";
const char *shell_cmd = "/bin/sh";
const char *cat_flag = "cat flag.txt";

void vuln(void) {
    char buffer[64];

    printf("Enter your ROP chain: ");
    fflush(stdout);

    /* VULNERABILITY: Stack buffer overflow for ROP chain injection */
    gets(buffer);

    printf("Input received.\n");
}

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    setup();

    printf("=== ROP Chains Challenge ===\n");
    printf("Chain the gadgets to read the flag!\n\n");

    printf("[*] Useful addresses:\n");
    printf("    open_file:   %p\n", (void *)open_file);
    printf("    read_from_fd:%p\n", (void *)read_from_fd);
    printf("    print_buf:   %p\n", (void *)print_buf);
    printf("    call_system: %p\n", (void *)call_system);
    printf("    flag_path:   %p -> \"%s\"\n", (void *)flag_path, flag_path);
    printf("    cat_flag:    %p -> \"%s\"\n", (void *)cat_flag, cat_flag);
    printf("    shell_cmd:   %p -> \"%s\"\n\n", (void *)shell_cmd, shell_cmd);

    vuln();

    printf("[-] Normal return. Build a better chain!\n");
    return 0;
}
