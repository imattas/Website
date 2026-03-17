/*
 * Userspace test program for the flagcheck kernel module.
 *
 * Compile: gcc -o test_module test_module.c
 * Usage:   sudo ./test_module <flag>
 *
 * This program opens /dev/flagcheck and sends the user-provided flag
 * via ioctl for validation by the kernel module.
 *
 * You can also use this to brute-force the flag one character at a time
 * by observing kernel logs (dmesg) for the mismatch position.
 *
 * But the easier approach: just reverse transform_byte() from the
 * kernel module source/binary and decrypt expected_output[].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#define DEVICE_PATH "/dev/flagcheck"
#define IOCTL_CHECK_FLAG _IOW('F', 1, char *)
#define FLAG_LEN 30

/*
 * Standalone solver: reverse the transform without needing the kernel module.
 * VULNERABILITY: This shows exactly how to invert the transform.
 */
void solve_offline(void) {
    const unsigned char expected[] = {
        0x92, 0xf2, 0x1a, 0x2a, 0xda, 0x72, 0xca, 0x42,
        0x1a, 0xca, 0x22, 0x9a, 0x1a, 0x5a, 0x0a, 0x42,
        0x22, 0xca, 0x9a, 0x42, 0x32, 0xca, 0xca, 0x0a,
        0xca, 0x02, 0xca, 0x0a, 0xda, 0x00
    };
    char flag[FLAG_LEN + 1];
    int i;

    printf("[*] Solving offline (reversing transform)...\n");

    for (i = 0; i < FLAG_LEN; i++) {
        unsigned char b = expected[i];
        /* Reverse XOR */
        b ^= 0x5A;
        /* Reverse rotate-left-3 = rotate-right-3 */
        b = (b >> 3) | (b << 5);
        flag[i] = b;
    }
    flag[FLAG_LEN] = '\0';

    printf("[+] Recovered flag: %s\n", flag);
}

int main(int argc, char *argv[]) {
    int fd;
    int ret;

    if (argc < 2) {
        printf("Usage: %s <flag>     - test via kernel module\n", argv[0]);
        printf("       %s --solve    - solve offline (no module needed)\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--solve") == 0) {
        solve_offline();
        return 0;
    }

    if (strlen(argv[1]) != FLAG_LEN) {
        printf("[-] Flag must be exactly %d characters.\n", FLAG_LEN);
        return 1;
    }

    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("open " DEVICE_PATH);
        printf("[-] Is the kernel module loaded? Try: sudo insmod flagcheck.ko\n");
        return 1;
    }

    ret = ioctl(fd, IOCTL_CHECK_FLAG, argv[1]);
    close(fd);

    if (ret == 0) {
        printf("[+] Correct flag!\n");
    } else {
        printf("[-] Wrong flag. Check dmesg for details.\n");
    }

    return 0;
}
