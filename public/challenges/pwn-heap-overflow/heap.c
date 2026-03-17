/*
 * Heap Overflow Challenge
 *
 * Vulnerability: Two structures are allocated on the heap adjacently.
 * The first (data_chunk) contains a buffer that can be overflowed via
 * gets(). The second (ctrl_chunk) contains a function pointer that is
 * called later. By overflowing the data buffer, an attacker can
 * overwrite the function pointer in the adjacent chunk to redirect
 * execution to win().
 *
 * Compile: make
 * Hint: The heap allocates chunks sequentially. Overflow the first
 *       chunk's data to overwrite the function pointer in the second.
 *       Use the printed addresses to calculate the exact offset.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char data[64];
} data_chunk_t;

typedef struct {
    char padding[32];
    void (*handler)(void);
} ctrl_chunk_t;

void normal_handler(void) {
    printf("[handler] Normal execution path. Nothing interesting here.\n");
}

void win(void) {
    printf("\n[+] Function pointer hijacked! You win!\n");
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

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    setup();

    printf("=== Heap Overflow Challenge ===\n");
    printf("Overflow the first chunk to hijack the function pointer!\n\n");

    /* Allocate two adjacent heap chunks */
    data_chunk_t *data = (data_chunk_t *)malloc(sizeof(data_chunk_t));
    ctrl_chunk_t *ctrl = (ctrl_chunk_t *)malloc(sizeof(ctrl_chunk_t));

    /* Initialize the control chunk with the normal handler */
    memset(ctrl->padding, 'A', sizeof(ctrl->padding));
    ctrl->handler = normal_handler;

    printf("[*] data chunk at:    %p (data buffer at %p)\n", (void *)data, (void *)data->data);
    printf("[*] ctrl chunk at:    %p (handler at %p)\n", (void *)ctrl, (void *)&ctrl->handler);
    printf("[*] Distance:         %ld bytes\n",
           (long)((char *)&ctrl->handler - (char *)data->data));
    printf("[*] normal_handler:   %p\n", (void *)normal_handler);
    printf("[*] win:              %p\n\n", (void *)win);

    printf("Enter data for the first chunk: ");

    /* VULNERABILITY: gets() writes unbounded data into the heap buffer,
     * overflowing into the adjacent control chunk */
    gets(data->data);

    printf("\n[*] Calling handler function pointer...\n");
    printf("[*] handler points to: %p\n", (void *)ctrl->handler);

    /* Call the (potentially overwritten) function pointer */
    ctrl->handler();

    printf("[-] Normal handler returned. Overwrite the pointer next time!\n");

    free(data);
    free(ctrl);

    return 0;
}
