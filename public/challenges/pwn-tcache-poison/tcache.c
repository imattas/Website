/*
 * Tcache Poisoning Challenge
 *
 * Vulnerability: This menu-driven heap program has a Use-After-Free (UAF)
 * bug. When a chunk is freed, its pointer is not NULLed, allowing the user
 * to edit and print freed chunks. This enables tcache poisoning:
 *
 * Attack strategy:
 *   1. Allocate two chunks (index 0 and 1)
 *   2. Free chunk 0 and chunk 1 (they go into the tcache free list)
 *   3. Edit the freed chunk 1 (UAF) to overwrite its fd pointer
 *      to point to win_ptr (or any target address)
 *   4. Allocate twice: first alloc returns chunk 1, second alloc
 *      returns a chunk at your controlled address
 *   5. Overwrite win_ptr with the address of win()
 *   6. Use option 5 to call win_ptr(), which now calls win()
 *
 * Compile: make
 * Hint: glibc 2.32+ has safe-linking. If your libc uses it, you'll
 *       need to XOR the fd pointer with (heap_addr >> 12).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNKS 8
#define CHUNK_SIZE 0x80

char *chunks[MAX_CHUNKS];

/* Function pointer that gets called -- initial value is lose() */
void lose(void) {
    printf("[-] Try harder! Overwrite this function pointer.\n");
}

void win(void) {
    printf("\n[+] Tcache poisoning successful!\n");
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

/* Global function pointer -- target for overwrite */
void (*win_ptr)(void) = lose;

void menu(void) {
    printf("\n=== Tcache Poison Menu ===\n");
    printf("1. Allocate chunk\n");
    printf("2. Free chunk\n");
    printf("3. Edit chunk\n");
    printf("4. Print chunk\n");
    printf("5. Call function pointer\n");
    printf("6. Quit\n");
    printf(">>> ");
}

void alloc_chunk(void) {
    int idx;
    printf("Index (0-%d): ", MAX_CHUNKS - 1);
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) {
        printf("[-] Invalid index.\n");
        return;
    }
    if (chunks[idx] != NULL) {
        printf("[-] Slot already in use.\n");
        return;
    }
    chunks[idx] = (char *)malloc(CHUNK_SIZE);
    if (chunks[idx] == NULL) {
        printf("[-] malloc failed.\n");
        return;
    }
    memset(chunks[idx], 0, CHUNK_SIZE);
    printf("[+] Allocated chunk %d at %p\n", idx, (void *)chunks[idx]);
}

void free_chunk(void) {
    int idx;
    printf("Index (0-%d): ", MAX_CHUNKS - 1);
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) {
        printf("[-] Invalid index.\n");
        return;
    }
    if (chunks[idx] == NULL) {
        printf("[-] Slot is empty.\n");
        return;
    }
    free(chunks[idx]);
    /* VULNERABILITY: Pointer is NOT set to NULL after free.
     * This creates a Use-After-Free (UAF) condition. */
    printf("[+] Freed chunk %d (pointer NOT nulled -- UAF!)\n", idx);
}

void edit_chunk(void) {
    int idx;
    printf("Index (0-%d): ", MAX_CHUNKS - 1);
    scanf("%d", &idx);
    getchar(); /* consume newline */
    if (idx < 0 || idx >= MAX_CHUNKS) {
        printf("[-] Invalid index.\n");
        return;
    }
    if (chunks[idx] == NULL) {
        printf("[-] Slot is empty.\n");
        return;
    }
    /* VULNERABILITY: Can edit freed chunks due to dangling pointer */
    printf("Enter data (up to %d bytes): ", CHUNK_SIZE);
    read(0, chunks[idx], CHUNK_SIZE);
    printf("[+] Data written to chunk %d\n", idx);
}

void print_chunk(void) {
    int idx;
    printf("Index (0-%d): ", MAX_CHUNKS - 1);
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) {
        printf("[-] Invalid index.\n");
        return;
    }
    if (chunks[idx] == NULL) {
        printf("[-] Slot is empty.\n");
        return;
    }
    /* VULNERABILITY: Can read freed chunks, leaking heap metadata */
    printf("[*] Chunk %d contents:\n", idx);
    write(1, chunks[idx], CHUNK_SIZE);
    printf("\n");
}

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    int choice;

    setup();

    printf("=== Tcache Poisoning Challenge ===\n");
    printf("[*] win():     %p\n", (void *)win);
    printf("[*] win_ptr:   %p (points to %p)\n", (void *)&win_ptr, (void *)win_ptr);
    printf("[*] Overwrite win_ptr to point to win(), then call it!\n");

    while (1) {
        menu();
        if (scanf("%d", &choice) != 1) break;

        switch (choice) {
            case 1: alloc_chunk(); break;
            case 2: free_chunk(); break;
            case 3: edit_chunk(); break;
            case 4: print_chunk(); break;
            case 5:
                printf("[*] Calling function pointer at %p -> %p\n",
                       (void *)&win_ptr, (void *)win_ptr);
                win_ptr();
                break;
            case 6:
                printf("Goodbye!\n");
                return 0;
            default:
                printf("[-] Invalid choice.\n");
        }
    }

    return 0;
}
