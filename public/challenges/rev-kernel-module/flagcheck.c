/*
 * CTF Challenge: Kernel Module Reversing
 *
 * Build: make (requires kernel headers)
 *
 * This is a Linux kernel module that exposes a character device
 * /dev/flagcheck. Users interact via ioctl to validate a flag.
 *
 * The validation uses XOR + bit rotation on each character.
 *
 * To solve:
 *   1. Reverse the transform_byte() function
 *   2. Apply the inverse transform to the expected_output array
 *   3. Or, use the test_module.c userspace program to brute-force
 *      character by character
 *
 * VULNERABILITY: The transform is a simple XOR + rotate, which is
 * trivially invertible. Extract expected_output[] and reverse each byte.
 *
 * NOTE: You don't actually need to load the module to solve this.
 * Just reverse-engineer the transform from the source or disassembly.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>

#define DEVICE_NAME "flagcheck"
#define IOCTL_CHECK_FLAG _IOW('F', 1, char *)
#define FLAG_LEN 30

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Challenge");
MODULE_DESCRIPTION("Flag validation kernel module");

static dev_t dev_num;
static struct cdev c_dev;
static struct class *cl;

/* XOR key for transformation */
#define XOR_KEY 0x5A

/* VULNERABILITY: Rotate left by 3 bits + XOR with key.
 * Inverse: XOR with key, then rotate right by 3 bits.
 *
 * To reverse:
 *   byte ^= XOR_KEY;              // undo XOR
 *   byte = (byte >> 3) | (byte << 5);  // rotate right 3
 */
static unsigned char transform_byte(unsigned char b) {
    /* Rotate left by 3 bits */
    b = (b << 3) | (b >> 5);
    /* XOR with key */
    b ^= XOR_KEY;
    return b;
}

/*
 * VULNERABILITY: Expected output after transform_byte() applied to each
 * character of the flag. Reverse the transform to recover the flag.
 *
 * Flag: zemi{k3rn3l_m0dul3_r3v3rs3d}
 */
static const unsigned char expected_output[FLAG_LEN] = {
    0x92, 0xf2, 0x1a, 0x2a, 0xda, 0x72, 0xca, 0x42,
    0x1a, 0xca, 0x22, 0x9a, 0x1a, 0x5a, 0x0a, 0x42,
    0x22, 0xca, 0x9a, 0x42, 0x32, 0xca, 0xca, 0x0a,
    0xca, 0x02, 0xca, 0x0a, 0xda, 0x00
};

/* ioctl handler - validates user-provided flag */
static long flagcheck_ioctl(struct file *f, unsigned int cmd,
                            unsigned long arg) {
    char user_flag[FLAG_LEN + 1];
    int i;

    if (cmd != IOCTL_CHECK_FLAG)
        return -EINVAL;

    if (copy_from_user(user_flag, (char *)arg, FLAG_LEN))
        return -EFAULT;

    user_flag[FLAG_LEN] = '\0';

    /* Transform each byte and compare against expected */
    for (i = 0; i < FLAG_LEN; i++) {
        unsigned char transformed = transform_byte(user_flag[i]);
        if (transformed != expected_output[i]) {
            printk(KERN_INFO "flagcheck: wrong flag (mismatch at %d)\n", i);
            return -EACCES;
        }
    }

    printk(KERN_INFO "flagcheck: correct flag!\n");
    return 0;
}

static int flagcheck_open(struct inode *i, struct file *f) {
    return 0;
}

static int flagcheck_release(struct inode *i, struct file *f) {
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = flagcheck_open,
    .release = flagcheck_release,
    .unlocked_ioctl = flagcheck_ioctl,
};

static int __init flagcheck_init(void) {
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

    if ((cl = class_create(THIS_MODULE, DEVICE_NAME)) == NULL) {
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    if (device_create(cl, NULL, dev_num, NULL, DEVICE_NAME) == NULL) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    printk(KERN_INFO "flagcheck: module loaded (/dev/flagcheck)\n");
    return 0;
}

static void __exit flagcheck_exit(void) {
    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);
    printk(KERN_INFO "flagcheck: module unloaded\n");
}

module_init(flagcheck_init);
module_exit(flagcheck_exit);
