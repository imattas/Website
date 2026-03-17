/*
 * SROP (Sigreturn-Oriented Programming) Challenge
 *
 * This is a minimal binary written in x86_64 assembly. It provides only
 * a read() syscall and a syscall gadget -- almost no useful ROP gadgets.
 *
 * Vulnerability: The read() call reads more data than the stack frame
 * allows, creating a buffer overflow. With so few gadgets available,
 * traditional ROP is impossible.
 *
 * Strategy: Use SROP (Sigreturn-Oriented Programming):
 *   1. Overflow the buffer to control the return address
 *   2. Point the return address to the syscall gadget
 *   3. Set RAX to 15 (sigreturn syscall number)
 *   4. Craft a fake sigcontext frame on the stack that sets all
 *      registers to desired values (e.g., execve("/bin/sh", 0, 0))
 *   5. When sigreturn executes, the kernel restores registers from
 *      your fake frame, giving you arbitrary register control
 *
 * Compile: make
 * Hint: Use pwntools' SigreturnFrame() to build the fake signal frame.
 */

.global _start

.section .text

_start:
    /* Call vuln() */
    call vuln

    /* Exit cleanly */
    mov $60, %rax        /* sys_exit */
    xor %rdi, %rdi       /* status = 0 */
    syscall

vuln:
    /* Set up a small stack frame */
    push %rbp
    mov %rsp, %rbp
    sub $64, %rsp        /* 64-byte local buffer */

    /* Print prompt */
    mov $1, %rax         /* sys_write */
    mov $1, %rdi         /* fd = stdout */
    lea prompt(%rip), %rsi
    mov $prompt_len, %rdx
    syscall

    /* VULNERABILITY: Read up to 1024 bytes into a 64-byte buffer */
    mov $0, %rax         /* sys_read */
    mov $0, %rdi         /* fd = stdin */
    lea -64(%rbp), %rsi  /* buffer on stack */
    mov $1024, %rdx      /* way more than 64 bytes! */
    syscall

    /* Print confirmation */
    mov $1, %rax         /* sys_write */
    mov $1, %rdi         /* fd = stdout */
    lea done(%rip), %rsi
    mov $done_len, %rdx
    syscall

    leave
    ret

/* Useful gadget: a bare syscall; ret */
.global syscall_gadget
syscall_gadget:
    syscall
    ret

/* Provide /bin/sh string in the binary */
.section .rodata
binsh:
    .asciz "/bin/sh"

prompt:
    .ascii "=== SROP Challenge ===\nMinimal binary. Very few gadgets.\nSend your SROP payload: "
    .set prompt_len, . - prompt

done:
    .ascii "\nInput received. Returning...\n"
    .set done_len, . - done
