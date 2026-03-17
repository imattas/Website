/*
 * CTF Challenge: Custom VM Reversing
 *
 * Compile: gcc -o vm vm.c
 * Run: ./vm bytecode.hex
 *
 * This implements a custom virtual machine with 10 opcodes.
 * The bytecode program reads user input, XORs each character with
 * a key, and compares against expected values.
 *
 * To solve:
 *   1. Understand the VM architecture (registers, opcodes, memory)
 *   2. Disassemble the bytecode by hand or write a disassembler
 *   3. Trace the XOR key and expected ciphertext
 *   4. Reverse: plaintext[i] = expected[i] ^ key
 *
 * VM Architecture:
 *   - 8 general-purpose registers (R0-R7)
 *   - 256-byte memory
 *   - Stack (64 entries)
 *   - Flag register (for CMP results)
 *
 * Opcodes:
 *   0x01 MOV  Rd, imm8    - Load immediate into register
 *   0x02 ADD  Rd, Rs      - Rd = Rd + Rs
 *   0x03 XOR  Rd, Rs      - Rd = Rd ^ Rs
 *   0x04 CMP  Rd, Rs      - Set flag (Rd == Rs)
 *   0x05 JMP  addr        - Unconditional jump
 *   0x06 JEQ  addr        - Jump if equal (flag set)
 *   0x07 PUSH Rd          - Push register to stack
 *   0x08 POP  Rd          - Pop stack to register
 *   0x09 LOAD Rd, [addr]  - Load from memory
 *   0x0A STORE [addr], Rs - Store to memory
 *   0x0B READ Rd          - Read one byte from input into Rd
 *   0x0C PRINT Rd         - Print register as char
 *   0xFF HALT             - Stop execution
 *
 * VULNERABILITY: The bytecode is a simple XOR cipher. Disassemble it
 * to find the key and expected values, then reverse the XOR.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_REGS    8
#define MEM_SIZE    256
#define STACK_SIZE  64
#define MAX_CODE    4096

/* Opcodes */
#define OP_MOV   0x01
#define OP_ADD   0x02
#define OP_XOR   0x03
#define OP_CMP   0x04
#define OP_JMP   0x05
#define OP_JEQ   0x06
#define OP_PUSH  0x07
#define OP_POP   0x08
#define OP_LOAD  0x09
#define OP_STORE 0x0A
#define OP_READ  0x0B
#define OP_PRINT 0x0C
#define OP_HALT  0xFF

typedef struct {
    unsigned char regs[NUM_REGS];
    unsigned char memory[MEM_SIZE];
    unsigned char stack[STACK_SIZE];
    int sp;
    int pc;
    int flag;  /* comparison result */
    unsigned char *code;
    int code_len;
    const char *input;
    int input_pos;
} VM;

void vm_init(VM *vm, unsigned char *code, int code_len, const char *input) {
    memset(vm, 0, sizeof(VM));
    vm->code = code;
    vm->code_len = code_len;
    vm->sp = -1;
    vm->input = input;
    vm->input_pos = 0;
}

int vm_run(VM *vm) {
    int cycles = 0;
    int max_cycles = 10000;

    while (vm->pc < vm->code_len && cycles < max_cycles) {
        unsigned char opcode = vm->code[vm->pc++];
        cycles++;

        switch (opcode) {
            case OP_MOV: {
                unsigned char rd = vm->code[vm->pc++];
                unsigned char imm = vm->code[vm->pc++];
                if (rd < NUM_REGS) vm->regs[rd] = imm;
                break;
            }
            case OP_ADD: {
                unsigned char rd = vm->code[vm->pc++];
                unsigned char rs = vm->code[vm->pc++];
                if (rd < NUM_REGS && rs < NUM_REGS)
                    vm->regs[rd] = vm->regs[rd] + vm->regs[rs];
                break;
            }
            case OP_XOR: {
                unsigned char rd = vm->code[vm->pc++];
                unsigned char rs = vm->code[vm->pc++];
                if (rd < NUM_REGS && rs < NUM_REGS)
                    vm->regs[rd] = vm->regs[rd] ^ vm->regs[rs];
                break;
            }
            case OP_CMP: {
                unsigned char rd = vm->code[vm->pc++];
                unsigned char rs = vm->code[vm->pc++];
                if (rd < NUM_REGS && rs < NUM_REGS)
                    vm->flag = (vm->regs[rd] == vm->regs[rs]) ? 1 : 0;
                break;
            }
            case OP_JMP: {
                unsigned char addr = vm->code[vm->pc++];
                vm->pc = addr;
                break;
            }
            case OP_JEQ: {
                unsigned char addr = vm->code[vm->pc++];
                if (vm->flag) vm->pc = addr;
                break;
            }
            case OP_PUSH: {
                unsigned char rd = vm->code[vm->pc++];
                if (rd < NUM_REGS && vm->sp < STACK_SIZE - 1)
                    vm->stack[++vm->sp] = vm->regs[rd];
                break;
            }
            case OP_POP: {
                unsigned char rd = vm->code[vm->pc++];
                if (rd < NUM_REGS && vm->sp >= 0)
                    vm->regs[rd] = vm->stack[vm->sp--];
                break;
            }
            case OP_LOAD: {
                unsigned char rd = vm->code[vm->pc++];
                unsigned char addr = vm->code[vm->pc++];
                if (rd < NUM_REGS)
                    vm->regs[rd] = vm->memory[addr];
                break;
            }
            case OP_STORE: {
                unsigned char addr = vm->code[vm->pc++];
                unsigned char rs = vm->code[vm->pc++];
                if (rs < NUM_REGS)
                    vm->memory[addr] = vm->regs[rs];
                break;
            }
            case OP_READ: {
                unsigned char rd = vm->code[vm->pc++];
                if (rd < NUM_REGS) {
                    if (vm->input && vm->input[vm->input_pos]) {
                        vm->regs[rd] = vm->input[vm->input_pos++];
                    } else {
                        vm->regs[rd] = 0;
                    }
                }
                break;
            }
            case OP_PRINT: {
                unsigned char rd = vm->code[vm->pc++];
                if (rd < NUM_REGS)
                    putchar(vm->regs[rd]);
                break;
            }
            case OP_HALT:
                return vm->regs[0];  /* Return R0 as exit code */
            default:
                fprintf(stderr, "Unknown opcode: 0x%02X at PC=%d\n",
                        opcode, vm->pc - 1);
                return -1;
        }
    }

    if (cycles >= max_cycles) {
        fprintf(stderr, "Execution limit reached.\n");
        return -1;
    }

    return vm->regs[0];
}

/* Load bytecode from hex file */
int load_hex(const char *filename, unsigned char *buf, int max_len) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }

    int len = 0;
    unsigned int byte;
    while (fscanf(f, "%02x", &byte) == 1 && len < max_len) {
        buf[len++] = (unsigned char)byte;
    }

    fclose(f);
    return len;
}

int main(int argc, char *argv[]) {
    unsigned char code[MAX_CODE];
    int code_len;
    char input[256];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bytecode.hex>\n", argv[0]);
        return 1;
    }

    code_len = load_hex(argv[1], code, MAX_CODE);
    if (code_len < 0) {
        fprintf(stderr, "Failed to load bytecode.\n");
        return 1;
    }

    printf("=== Custom VM Challenge ===\n");
    printf("Loaded %d bytes of bytecode.\n", code_len);
    printf("Enter the flag: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';

    VM vm;
    vm_init(&vm, code, code_len, input);
    int result = vm_run(&vm);

    if (result == 0) {
        printf("\n[+] Correct! The flag is: %s\n", input);
    } else {
        printf("\n[-] Wrong flag.\n");
    }

    return 0;
}
