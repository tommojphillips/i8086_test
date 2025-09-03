
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "cJSON.h"
#include "i8086.h"

uint8_t memory[0x100000] = { 0 };

/* Memory Functions */
uint8_t mm_read_byte(uint20_t addr) {
	return *(uint8_t*)&memory[addr & 0xFFFFF];
}
void mm_write_byte(uint20_t addr, uint8_t value) {
    *(uint8_t*)&memory[addr & 0xFFFFF] = value;
}

/* IO Functions */
uint8_t io_read_byte(uint16_t port) {
    (void)port;
	return 0xFF;
}
void io_write_byte(uint16_t port, uint8_t value) {
    (void)port;
    (void)value;
}
uint16_t io_read_word(uint16_t port) {
    (void)port;
	return 0xFFFF;
}
void io_write_word(uint16_t port, uint16_t value) {
    (void)port;
    (void)value;
}

void cpu_set_flags_from_word(I8086* cpu, uint16_t flags_word) {
    cpu->status.word = flags_word;
}

void cpu_load_ram_list(cJSON* ram_list) {
    int n = cJSON_GetArraySize(ram_list);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(ram_list, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        uint8_t value = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
        memory[addr] = value;
    }
}

void cpu_set_regs(I8086* cpu, cJSON* regs) {
    cpu->registers[REG_AX].r16 = (uint16_t)cJSON_GetObjectItem(regs, "ax")->valueint;
    cpu->registers[REG_BX].r16 = (uint16_t)cJSON_GetObjectItem(regs, "bx")->valueint;
    cpu->registers[REG_CX].r16 = (uint16_t)cJSON_GetObjectItem(regs, "cx")->valueint;
    cpu->registers[REG_DX].r16 = (uint16_t)cJSON_GetObjectItem(regs, "dx")->valueint;
    cpu->registers[REG_SI].r16 = (uint16_t)cJSON_GetObjectItem(regs, "si")->valueint;
    cpu->registers[REG_DI].r16 = (uint16_t)cJSON_GetObjectItem(regs, "di")->valueint;
    cpu->registers[REG_SP].r16 = (uint16_t)cJSON_GetObjectItem(regs, "sp")->valueint;
    cpu->registers[REG_BP].r16 = (uint16_t)cJSON_GetObjectItem(regs, "bp")->valueint;
    cpu->segments[SEG_ES] = (uint16_t)cJSON_GetObjectItem(regs, "es")->valueint;
    cpu->segments[SEG_CS] = (uint16_t)cJSON_GetObjectItem(regs, "cs")->valueint;
    cpu->segments[SEG_SS] = (uint16_t)cJSON_GetObjectItem(regs, "ss")->valueint;
    cpu->segments[SEG_DS] = (uint16_t)cJSON_GetObjectItem(regs, "ds")->valueint;
    cpu->ip = (uint16_t)cJSON_GetObjectItem(regs, "ip")->valueint;
    cpu_set_flags_from_word(cpu, (uint16_t)cJSON_GetObjectItem(regs, "flags")->valueint);
}

int try_get_object_int(cJSON* object, const char* string, uint16_t* value) {
    cJSON* item = cJSON_GetObjectItem(object, string);
    if (item) {
        *value = (uint16_t)item->valueint;
        return 1;
    }
    else {
        return 0;
    }
}

int cpu_compare_state(I8086* cpu, cJSON* final) {
    cJSON* regs = cJSON_GetObjectItem(final, "regs");
    cJSON* ram = cJSON_GetObjectItem(final, "ram");
    uint16_t v = 0;

#define CHECK_MISMATCH(name, regidx) \
    if (try_get_object_int(regs, name, &v)) { \
        if (regidx != v) return 1; \
    }

    CHECK_MISMATCH("ax", cpu->registers[REG_AX].r16);
    CHECK_MISMATCH("bx", cpu->registers[REG_BX].r16);
    CHECK_MISMATCH("cx", cpu->registers[REG_CX].r16);
    CHECK_MISMATCH("dx", cpu->registers[REG_DX].r16);
    CHECK_MISMATCH("si", cpu->registers[REG_SI].r16);
    CHECK_MISMATCH("di", cpu->registers[REG_DI].r16);
    CHECK_MISMATCH("sp", cpu->registers[REG_SP].r16);
    CHECK_MISMATCH("bp", cpu->registers[REG_BP].r16);
    CHECK_MISMATCH("cs", cpu->segments[SEG_CS]);
    CHECK_MISMATCH("ds", cpu->segments[SEG_DS]);
    CHECK_MISMATCH("ss", cpu->segments[SEG_SS]);
    CHECK_MISMATCH("es", cpu->segments[SEG_ES]);
    CHECK_MISMATCH("ip", cpu->ip);
    CHECK_MISMATCH("flags", cpu->status.word);

#undef CHECK_MISMATCH
    
    int n = cJSON_GetArraySize(ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        uint8_t val = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
        if (memory[addr] != val) return 1;
    }

    return 0;
}

void cpu_print_reg(cJSON* initial_regs, cJSON* final_regs, const char* name, uint16_t reg_val) {
    uint16_t v1 = 0;
    uint16_t v2 = 0;
    int has_v2 = 0;

    printf("|  %s   ", name);
    if (!try_get_object_int(initial_regs, name, &v1)) {
        printf("|  ---- ");
    }
    else {
        printf("|  %04X ", v1);
    }

    if (!try_get_object_int(final_regs, name, &v2)) {
        printf("|  ---- ");
    }
    else {
        printf("|  %04X ", v2);
        has_v2 = 1;
    }

    printf("|  %04X ", reg_val);

    if (has_v2) {
        printf("|  %c  |\n", (v2 != reg_val) ? 'X' : ' ');
    }
    else {
        printf("|     |\n");
    }
}

void cpu_print_seg_reg(cJSON* initial_regs, cJSON* final_regs, const char* seg_name, uint16_t seg_val, const char* reg_name, uint16_t reg_val) {
    uint16_t seg = 0;
    uint16_t reg = 0;

    printf("| %s:%s ", seg_name, reg_name);
    if (!try_get_object_int(initial_regs, seg_name, &seg) || !try_get_object_int(initial_regs, reg_name, &reg)) {
        printf("| ----- ");
    }
    else {
        printf("| %05X ", (((uint20_t)seg << 4) + reg) & 0xFFFFF);
    }

    if (!try_get_object_int(final_regs, seg_name, &seg) || !try_get_object_int(final_regs, reg_name, &reg)) {
        printf("| ----- ");
    }
    else {
        printf("| %05X ", (((uint20_t)seg << 4) + reg) & 0xFFFFF);
    }

    printf("| %05X |     |\n", (((uint20_t)seg_val << 4) + reg_val) & 0xFFFFF);
}

void cpu_print_flags(cJSON* initial_regs, cJSON* final_regs, const char* name, I8086_PROGRAM_STATUS_WORD psw) {
    uint16_t v1 = 0;
    uint16_t v2 = 0;

    if (!try_get_object_int(initial_regs, name, &v1)) {
        return;
    }

    if (!try_get_object_int(final_regs, name, &v2)) {
        return;
    }


    printf("\n| FLAG  | INIT  | EXP   | CPU   | ERR |\n");
    printf(  "|-------|-------|-------|-------|-----|\n");
    printf(  "| flags |  %04X |  %04X |  %04X |  %c  |\n", v1, v2, psw.word, (v2 != psw.word) ? 'X' : ' ');

    I8086_PROGRAM_STATUS_WORD fv1 = { .word = v1 };
    I8086_PROGRAM_STATUS_WORD fv2 = { .word = v2 };

#define PRINT_FLAG(flag) \
        printf("|  %s   |  %d    |  %d    |  %d    |  %c  |\n", \
            #flag, fv1.flag, fv2.flag, psw.flag, (fv2.flag != psw.flag) ? 'X' : ' ')

    PRINT_FLAG(cf);
    PRINT_FLAG(r0);
    PRINT_FLAG(pf);
    PRINT_FLAG(r1);
    PRINT_FLAG(af);
    PRINT_FLAG(r2);
    PRINT_FLAG(zf);
    PRINT_FLAG(sf);
    PRINT_FLAG(tf);
    PRINT_FLAG(in);
    PRINT_FLAG(df);
    PRINT_FLAG(of);
    PRINT_FLAG(r3);
    PRINT_FLAG(r4);
    PRINT_FLAG(r5);
    PRINT_FLAG(r6);
}

void cpu_print_ram(cJSON* initial_ram, cJSON* final_ram) {

    // Collect all addresses that appear in either initial_ram or final_ram
    typedef struct {
        uint32_t addr;
    } ADDR_ENTRY;

    int n = cJSON_GetArraySize(final_ram);
    int m = cJSON_GetArraySize(initial_ram);
    int addr_count = 0;

    if (n + m < 1) {
        return;
    }

    ADDR_ENTRY* addrs = calloc(n + m, sizeof(ADDR_ENTRY));
    if (addrs == NULL) {
        perror("AddrEntry Calloc");
        exit(1);
    }

    /* collect addresses from final_ram */
    for (int i = 0; i < n; ++i) {
        cJSON* pair = cJSON_GetArrayItem(final_ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;

        int found = 0;
        for (int k = 0; k < addr_count; k++) {
            if (addrs[k].addr == addr) {
                found = 1;
                break;
            }
        }

        if (!found) {
            addrs[addr_count++].addr = addr;
        }
    }

    /* collect addresses from initial_ram */
    for (int i = 0; i < m; ++i) {
        cJSON* pair = cJSON_GetArrayItem(initial_ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;

        int found = 0;
        for (int k = 0; k < addr_count; ++k) {
            if (addrs[k].addr == addr) {
                found = 1;
                break;
            }
        }

        if (!found) {
            addrs[addr_count++].addr = addr;
        }
    }

    if (addr_count < 1) {
        return;
    }

    printf("\n| ADDR  | INIT  | EXP   | CPU   | ERR |\n");
    printf(  "|-------|-------|-------|-------|-----|\n");

    for (int i = 0; i < addr_count; ++i) {
        uint32_t addr = addrs[i].addr;

        /* Lookup init value if exists */
        int has_init = 0;
        uint8_t init_val = 0;
        for (int j = 0; j < m; ++j) {
            cJSON* pair = cJSON_GetArrayItem(initial_ram, j);
            uint32_t init_addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;

            if (init_addr == addr) {
                init_val = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
                has_init = 1;
                break;
            }
        }

        /* Lookup final value if exists */
        int has_exp = 0;
        uint8_t exp_val = 0;
        for (int j = 0; j < n; ++j) {
            cJSON* pair = cJSON_GetArrayItem(final_ram, j);
            uint32_t exp_addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;

            if (exp_addr == addr) {
                exp_val = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
                has_exp = 1;
                break;
            }
        }

        /* print address, value */

        printf("| %05X ", addr);

        if (has_init) {
            printf("|  %02X   ", init_val);
        }
        else {
            printf("|  --   ");
        }

        if (has_exp) {
            printf("|  %02X   ", exp_val);
        }
        else {
            printf("|  --   ");
        }

        printf("|  %02X   |  %c  |\n", memory[addr], has_exp && exp_val != memory[addr] ? 'X' : ' ');
    }

    free(addrs);
    addrs = NULL;
}

void cpu_print_state(cJSON* initial, cJSON* final, I8086* cpu) {
    cJSON* initial_regs = cJSON_GetObjectItem(initial, "regs");
    cJSON* final_regs = cJSON_GetObjectItem(final, "regs");
    cJSON* initial_ram = cJSON_GetObjectItem(initial, "ram");
    cJSON* final_ram = cJSON_GetObjectItem(final, "ram");

    printf("\n|  REG  | INIT  | EXP   | CPU   | ERR |\n");
    printf(  "|-------|-------|-------|-------|-----|\n");

#define PRINT_REG(name, reg_val) \
    cpu_print_reg(initial_regs, final_regs, name, reg_val)

    PRINT_REG("ax", cpu->registers[REG_AX].r16);
    PRINT_REG("bx", cpu->registers[REG_BX].r16);
    PRINT_REG("cx", cpu->registers[REG_CX].r16);
    PRINT_REG("dx", cpu->registers[REG_DX].r16);
    PRINT_REG("si", cpu->registers[REG_SI].r16);
    PRINT_REG("di", cpu->registers[REG_DI].r16);
    PRINT_REG("sp", cpu->registers[REG_SP].r16);
    PRINT_REG("bp", cpu->registers[REG_BP].r16);
    PRINT_REG("cs", cpu->segments[SEG_CS]);
    PRINT_REG("ds", cpu->segments[SEG_DS]);
    PRINT_REG("es", cpu->segments[SEG_ES]);
    PRINT_REG("ss", cpu->segments[SEG_SS]);
    PRINT_REG("ip", cpu->ip);

#define PRINT_SEG_REG(seg_name, seg_val, reg_name, reg_val) \
    cpu_print_seg_reg(initial_regs, final_regs, seg_name, seg_val, reg_name, reg_val)

    PRINT_SEG_REG("cs", cpu->segments[SEG_CS], "ip", cpu->ip);
    PRINT_SEG_REG("ss", cpu->segments[SEG_CS], "sp", cpu->registers[REG_SP].r16);

    cpu_print_flags(initial_regs, final_regs, "flags", cpu->status);

    cpu_print_ram(initial_ram, final_ram);

    printf("\n");

#undef PRINT_REG
#undef PRINT_FLAGS
}

void print_usage() {
    printf("Usage: 8086_test.exe <json_test_file> [-e] [-i<index>] [-psp] [-psf]\n" \
        "-e        Dont exit on error\n" \
        "-i<index> Start at test i\n" \
        "-t<count> End at test i+t\n" \
        "-psp      Print state on passed\n" \
        "-psf      Dont print state on failed\n");
}

typedef struct ARGS {
    int dont_exit_on_error;
    int print_state_on_pass;
    int print_state_on_fail;
    int index;
    int count;
    FILE* file;
} ARGS;

void set_default_args(ARGS* args) {
    args->index = 0;
    args->count = 0;
    args->dont_exit_on_error = 0;
    args->print_state_on_pass = 0;
    args->print_state_on_fail = 1;
    args->file = NULL;
}

int parse_args(ARGS* args, int argc, char** argv) {

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];

        if (strncmp("-e", arg, 2) == 0) {
            args->dont_exit_on_error = 1;
        }
        else if (strncmp("-psp", arg, 4) == 0) {
            args->print_state_on_pass = 1;
        }
        else if (strncmp("-psf", arg, 4) == 0) {
            args->print_state_on_fail = 0;
        }
        else if (strncmp("-i", arg, 2) == 0) {
            arg += 2;
            args->index = strtol(arg, NULL, 10);
        }
        else if (strncmp("-t", arg, 2) == 0) {
            arg += 2;
            args->count = strtol(arg, NULL, 10);
        }
        else if (strncmp("-?", arg, 2) == 0) {
            print_usage();
            return 0;
        }
        else {
            if (args->file == NULL) {
                args->file = fopen(arg, "rb");
                if (args->file == NULL) {
                    perror(arg);
                    return 0;
                }
            }
        }
    }

    return 1;
}

int main(int argc, char* argv[]) {
    int failed = 0;
    char* json_text = NULL;
    cJSON* root = NULL;
    ARGS args = { 0 };
    I8086 cpu = { 0 };
    cJSON* child = NULL;
    int test_count = 0;
    long json_text_size = 0;

    set_default_args(&args);
    if (parse_args(&args, argc, argv) == 0) {
        failed = 1;
        goto cleanup;
    }

    if (args.file == NULL) {
        print_usage();
        failed = 1;
        goto cleanup;
    }

    fseek(args.file, 0, SEEK_END);
    json_text_size = ftell(args.file);
    fseek(args.file, 0, SEEK_SET);

    json_text = (char*)malloc(json_text_size);
    if (json_text == NULL) {
        perror("JSON text malloc failed");
        failed = 1;
        goto cleanup;
    }

    fread(json_text, 1, json_text_size, args.file);

    root = cJSON_Parse(json_text);
    if (root == NULL) { 
        const char* error = cJSON_GetErrorPtr();
        printf("JSON parse error:\n%s\n", error);
        failed = 1;
        goto cleanup;
    }

    test_count = cJSON_GetArraySize(root);
    if (test_count < args.index) {
        printf("Test count was %d but index was %d\n", test_count, args.index);
        failed = 1;
        goto cleanup;
    }
    if (test_count < args.count || args.count < 1) {
        args.count = test_count;
    }

    i8086_init(&cpu);
    cpu.funcs.read_mem_byte = mm_read_byte;
    cpu.funcs.write_mem_byte = mm_write_byte;
    cpu.funcs.read_io_byte = io_read_byte;
    cpu.funcs.read_io_word = io_read_word;
    cpu.funcs.write_io_byte = io_write_byte;
    cpu.funcs.write_io_word = io_write_word;

    for (int i = args.index; i < args.count; i++) {
        child = cJSON_GetArrayItem(root, i);

        i8086_reset(&cpu);
        memset(memory, 0, 0x100000);

        cJSON* initial = cJSON_GetObjectItem(child, "initial");
        cpu_set_regs(&cpu, cJSON_GetObjectItem(initial, "regs"));
        cpu_load_ram_list(cJSON_GetObjectItem(initial, "ram"));

        // Load instruction bytes at IP
        cJSON* bytes = cJSON_GetObjectItem(child, "bytes");
        int n = cJSON_GetArraySize(bytes);
        for (uint16_t b = 0; b < n; ++b) {
            uint8_t v = (uint8_t)cJSON_GetArrayItem(bytes, b)->valueint;
            mm_write_byte(((uint20_t)cpu.segments[SEG_CS] << 4) + (uint16_t)(cpu.ip + b), v);
        }

        uint16_t start_ip = cpu.ip; 
        // stay in loop until REP finally finishes
        do {
            // Execute instruction
            if (i8086_execute(&cpu) == I8086_DECODE_UNDEFINED) {
                printf("ERROR: undef op: %02X", cpu.opcode);
                if (cpu.modrm.byte != 0) {
                    printf(" /%02X", cpu.modrm.reg);
                }
                printf("\n");
                failed = 1;
                goto cleanup;
            }
        } while (cpu.ip == start_ip && 
                (cpu.opcode == 0xA4 || cpu.opcode == 0xA5 || // movs
                 cpu.opcode == 0xA6 || cpu.opcode == 0xA7 || // cmps
                 cpu.opcode == 0xAA || cpu.opcode == 0xAB || // stos
                 cpu.opcode == 0xAC || cpu.opcode == 0xAD || // lods
                 cpu.opcode == 0xAE || cpu.opcode == 0xAF)); // scas

        // Compare final state
        cJSON* final = cJSON_GetObjectItem(child, "final");
        char* name = cJSON_GetObjectItem(child, "name")->valuestring;
        if (cpu_compare_state(&cpu, final) == 0) {
            printf("%04d) Test PASSED: %s\n", i, name);
            if (args.print_state_on_pass == 1) {
                cpu_print_state(initial, final, &cpu);
            }
        }
        else {
            printf("%04d) Test FAILED: %s\n", i, name);
            failed++;
            if (args.print_state_on_fail == 1) {
                cpu_print_state(initial, final, &cpu);
            }
            if (args.dont_exit_on_error == 0) {
                break;
            }
        }
    }

    //if (failed != 0) printf("FAILED: %d\n", failed);

cleanup:

    if (args.file != NULL) {
        fclose(args.file);
        args.file = NULL;
    }

    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }

    if (json_text != NULL) {
        free(json_text);
        json_text = NULL;
    }

    if (failed > 0) {
        return failed;
    }
    else {
        return 0;
    }
}
