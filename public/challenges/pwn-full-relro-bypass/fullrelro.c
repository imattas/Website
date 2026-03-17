/*
 * Full RELRO Bypass Challenge
 *
 * This binary is compiled with Full RELRO (-Wl,-z,relro,-z,now) and PIE.
 * Full RELRO makes the GOT read-only, so GOT overwrites are impossible.
 * PIE randomizes the binary's base address.
 *
 * Vulnerability: The menu-driven heap program has:
 *   1. A heap buffer overflow in the edit function (reads more than allocated)
 *   2. A UAF in the view function (can read freed chunks to leak heap/libc)
 *
 * Since GOT is read-only, you must find alternative targets:
 *   - __free_hook / __malloc_hook (glibc < 2.34)
 *   - Overwrite function pointers in heap structures
 *   - Target libc internal structures
 *
 * Compile: make
 * Hint: Leak PIE base via UAF, leak libc via unsorted bin, then target
 *       __free_hook (or function pointer) with one_gadget or system().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 16
#define NOTE_SIZE 0x100

struct note {
    int in_use;
    size_t size;
    char *data;
    void (*print_func)(struct note *);
};

struct note notes[MAX_NOTES];

void default_print(struct note *n) {
    printf("Note contents: ");
    write(1, n->data, n->size);
    printf("\n");
}

void win(void) {
    printf("\n[+] Full RELRO bypassed! Here's your flag:\n");
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

void create_note(void) {
    int idx;
    size_t size;

    for (idx = 0; idx < MAX_NOTES; idx++) {
        if (!notes[idx].in_use) break;
    }
    if (idx == MAX_NOTES) {
        printf("[-] No free slots.\n");
        return;
    }

    printf("Size (max %d): ", NOTE_SIZE);
    scanf("%zu", &size);
    if (size > NOTE_SIZE) size = NOTE_SIZE;

    notes[idx].data = (char *)malloc(size);
    if (notes[idx].data == NULL) {
        printf("[-] malloc failed.\n");
        return;
    }
    memset(notes[idx].data, 0, size);
    notes[idx].size = size;
    notes[idx].in_use = 1;
    notes[idx].print_func = default_print;

    printf("[+] Created note %d at %p (data at %p)\n",
           idx, (void *)&notes[idx], (void *)notes[idx].data);
}

void edit_note(void) {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    getchar();
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("[-] Invalid index.\n");
        return;
    }
    /* VULNERABILITY: Does not check in_use flag -- allows editing freed notes.
     * Also, reads NOTE_SIZE bytes regardless of actual allocation size. */
    if (notes[idx].data == NULL) {
        printf("[-] No data pointer.\n");
        return;
    }
    printf("Enter data: ");
    /* VULNERABILITY: Always reads NOTE_SIZE bytes, even if chunk is smaller.
     * This enables heap overflow. */
    read(0, notes[idx].data, NOTE_SIZE);
    printf("[+] Note %d updated.\n", idx);
}

void view_note(void) {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("[-] Invalid index.\n");
        return;
    }
    /* VULNERABILITY: Does not check in_use flag -- leaks freed chunk data
     * which may contain heap pointers or libc addresses. */
    if (notes[idx].data == NULL) {
        printf("[-] No data pointer.\n");
        return;
    }
    printf("[*] Note %d (size %zu):\n", idx, notes[idx].size);
    notes[idx].print_func(&notes[idx]);
}

void delete_note(void) {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("[-] Invalid index.\n");
        return;
    }
    if (!notes[idx].in_use) {
        printf("[-] Note not in use.\n");
        return;
    }
    free(notes[idx].data);
    /* VULNERABILITY: data pointer and print_func are NOT cleared.
     * in_use is cleared but the dangling pointers remain. */
    notes[idx].in_use = 0;
    printf("[+] Note %d freed (dangling pointer remains).\n", idx);
}

void trigger(void) {
    /* Try to call win via an overwritten function pointer */
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("[-] Invalid index.\n");
        return;
    }
    if (notes[idx].print_func == NULL) {
        printf("[-] No function pointer set.\n");
        return;
    }
    printf("[*] Calling print_func for note %d (%p)...\n",
           idx, (void *)notes[idx].print_func);
    notes[idx].print_func(&notes[idx]);
}

void menu(void) {
    printf("\n=== Full RELRO Heap Challenge ===\n");
    printf("1. Create note\n");
    printf("2. Edit note\n");
    printf("3. View note\n");
    printf("4. Delete note\n");
    printf("5. Trigger function pointer\n");
    printf("6. Quit\n");
    printf(">>> ");
}

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    int choice;
    setup();

    printf("=== Full RELRO + PIE Bypass Challenge ===\n");
    printf("[*] GOT is read-only. Find another target.\n");
    printf("[*] win():          %p\n", (void *)win);
    printf("[*] default_print:  %p\n", (void *)default_print);
    printf("[*] notes array:    %p\n", (void *)notes);
    printf("[*] Hint: Overwrite a note's print_func pointer to win()\n");

    while (1) {
        menu();
        if (scanf("%d", &choice) != 1) break;

        switch (choice) {
            case 1: create_note(); break;
            case 2: edit_note(); break;
            case 3: view_note(); break;
            case 4: delete_note(); break;
            case 5: trigger(); break;
            case 6:
                printf("Goodbye!\n");
                return 0;
            default:
                printf("[-] Invalid choice.\n");
        }
    }

    return 0;
}
