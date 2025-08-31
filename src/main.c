
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "cJSON.h"
#include "i8086.h"  // Your CPU emulator header

// ------------------------ Helper Functions ------------------------

uint8_t memory[0x100000] = { 0 };

/* Memory Functions */
uint8_t read_mm_byte(uint20_t addr) {
	return *(uint8_t*)&memory[addr & 0xFFFFF];
}
void write_mm_byte(uint20_t addr, uint8_t value) {
    *(uint8_t*)&memory[addr & 0xFFFFF] = value;
}

/* IO Functions */
uint8_t read_io_byte(uint16_t port) {
    (void)port;
	return 0xFF;
}
void write_io_byte(uint16_t port, uint8_t value) {
    (void)port;
    (void)value;
}
uint16_t read_io_word(uint16_t port) {
    (void)port;
	return 0xFFFF;
}
void write_io_word(uint16_t port, uint16_t value) {
    (void)port;
    (void)value;
}

// ------------------------ Helper Functions ------------------------

// Convert 16-bit flags word to individual CPU flags
void cpu_set_flags_from_word(I8086* cpu, uint16_t flags_word) {
    cpu->status.word = flags_word;
}

// Extract flags into 16-bit word for comparison
uint16_t cpu_get_flags_word(I8086* cpu) {
    return cpu->status.word;
}

// Load RAM from JSON array of [address, value]
void cpu_load_ram_list(cJSON* ram_list) {
    int n = cJSON_GetArraySize(ram_list);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(ram_list, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        uint8_t value = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
        memory[addr] = value;
    }
}

// Set registers from JSON
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

// Compare CPU state to JSON final state
int cpu_compare_state(I8086* cpu, cJSON* final) {
    cJSON* regs = cJSON_GetObjectItem(final, "regs");
    cJSON* ram = cJSON_GetObjectItem(final, "ram");

    int mismatch = 0;
    uint16_t r = 0;
    uint16_t v = 0;

    // --- General Purpose Registers ---
    if (try_get_object_int(regs, "ax", &v)) {
        r = cpu->registers[REG_AX].r16;
        if (r != v) { mismatch++; }
    }

    if (try_get_object_int(regs, "bx", &v)) {
        r = cpu->registers[REG_BX].r16;
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "cx", &v)) {
        r = cpu->registers[REG_CX].r16;
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "dx", &v)) {
        r = cpu->registers[REG_DX].r16;
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "si", &v)) {
        r = cpu->registers[REG_SI].r16;
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "di", &v)) {
        r = cpu->registers[REG_DI].r16;
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "sp", &v)) {
        r = cpu->registers[REG_SP].r16;
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "bp", &v)) {
        r = cpu->registers[REG_BP].r16;
        if (r != v) { mismatch++; }
    }

    // --- Segment Registers ---
    if (try_get_object_int(regs, "cs", &v)) {
        r = cpu->segments[SEG_CS];
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "ds", &v)) {
        r = cpu->segments[SEG_DS];
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "es", &v)) {
        r = cpu->segments[SEG_ES];
        if (r != v) { mismatch++; }
    }
    if (try_get_object_int(regs, "ss", &v)) {
        r = cpu->segments[SEG_SS];
        if (r != v) { mismatch++; }
    }

    // --- Instruction Pointer ---
    if (try_get_object_int(regs, "ip", &v)) {
        r = cpu->ip;
        if (r != v) { mismatch++; }
    }

    // --- Flags ---
    if (try_get_object_int(regs, "flags", &v)) {
        r = cpu_get_flags_word(cpu);
        if (r != v) { mismatch++; }
    }

    // --- RAM ---
    int n = cJSON_GetArraySize(ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        uint8_t val = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
        if (memory[addr] != val) {
            mismatch++;
        }
    }

    return mismatch == 0;
}

void cpu_print_state(cJSON* initial, cJSON* final, I8086* cpu) {
    cJSON* initial_regs = cJSON_GetObjectItem(initial, "regs");
    cJSON* final_regs = cJSON_GetObjectItem(final, "regs");
    cJSON* initial_ram = cJSON_GetObjectItem(initial, "ram");
    cJSON* final_ram = cJSON_GetObjectItem(final, "ram");

    uint16_t v1 = 0;
    uint16_t v2 = 0;
    uint16_t v3 = 0;

    printf("\n|  REG  |  IN  | EXP  | CPU  | ERR |\n");
    printf("|-------|------|------|------|-----|\n");

#define PRINT_REG(name, regidx) \
        v1 = (uint16_t)cJSON_GetObjectItem(initial_regs, name)->valueint; \
        v2 = (uint16_t)cJSON_GetObjectItem(final_regs, name)->valueint; \
        v3 = regidx; \
        printf("|  %s   | %04X | %04X | %04X |  %c  |\n", \
            name, v1, v2, v3, (v2 != v3) ? 'X' : ' '); \

    // --- General Purpose Registers ---
    PRINT_REG("ax", cpu->registers[REG_AX].r16);
    PRINT_REG("bx", cpu->registers[REG_BX].r16);
    PRINT_REG("cx", cpu->registers[REG_CX].r16);
    PRINT_REG("dx", cpu->registers[REG_DX].r16);
    PRINT_REG("si", cpu->registers[REG_SI].r16);
    PRINT_REG("di", cpu->registers[REG_DI].r16);
    PRINT_REG("sp", cpu->registers[REG_SP].r16);
    PRINT_REG("bp", cpu->registers[REG_BP].r16);

    // --- Segment Registers ---
    PRINT_REG("cs", cpu->segments[SEG_CS]);
    PRINT_REG("ds", cpu->segments[SEG_DS]);
    PRINT_REG("es", cpu->segments[SEG_ES]);
    PRINT_REG("ss", cpu->segments[SEG_SS]);

    // --- Instruction Pointer ---
    PRINT_REG("ip", cpu->ip);

    // --- Flags ---
    v1 = (uint16_t)cJSON_GetObjectItem(initial_regs, "flags")->valueint;
    v2 = (uint16_t)cJSON_GetObjectItem(final_regs, "flags")->valueint;
    I8086_PROGRAM_STATUS_WORD fv1 = { .word = v1 };
    I8086_PROGRAM_STATUS_WORD fv2 = { .word = v2 };
    I8086_PROGRAM_STATUS_WORD fv3 = { .word = cpu->status.word };

#define PRINT_FLAG(flag) \
        printf("|  %s   |  %d   |  %d   |  %d   |  %c  |\n", \
            #flag, fv1.flag, fv2.flag, fv3.flag, (fv2.flag != fv3.flag) ? 'X' : ' ')

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

    // --- RAM ---
    int n = cJSON_GetArraySize(final_ram);
    printf("\n| ADDR  | INIT | EXP  | CPU  | ERR |\n");
    printf("|-------|------|------|------|-----|\n");

    for (int i = 0; i < n; i++) {
        cJSON* pair_final = cJSON_GetArrayItem(final_ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair_final, 0)->valueint;
        uint8_t exp_val = (uint8_t)cJSON_GetArrayItem(pair_final, 1)->valueint;
        uint8_t cpu_val = memory[addr];

        // --- lookup initial value by address ---
        cJSON* init_val_item = NULL;
        int m = cJSON_GetArraySize(initial_ram);
        for (int j = 0; j < m; j++) {
            cJSON* pair_init = cJSON_GetArrayItem(initial_ram, j);
            uint32_t init_addr = (uint32_t)cJSON_GetArrayItem(pair_init, 0)->valueint;
            if (init_addr == addr) {
                init_val_item = cJSON_GetArrayItem(pair_init, 1);
                break;
            }
        }

        if (init_val_item) {
            printf("| %05X | %04X | %04X | %04X |  %c  |\n",
                addr,
                (uint8_t)init_val_item->valueint,
                exp_val,
                cpu_val,
                (exp_val != cpu_val) ? 'X' : ' '
            );
        }
        else {
            printf("| %05X | ---- | %04X | %04X |  %c  |\n",
                addr,
                exp_val,
                cpu_val,
                (exp_val != cpu_val) ? 'X' : ' '
            );
        }
    }

#undef PRINT_REG
#undef PRINT_FLAG
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <json_test_file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) { 
        perror("fopen"); 
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* json_text = (char*)malloc(size);
    if (json_text == NULL) {
        printf("JSON text malloc error\n");
        fclose(f);
        return 1;
    }

    fread(json_text, 1, size, f);
    fclose(f);

    int failed = 0;

    cJSON* root = cJSON_Parse(json_text);
    if (!root) { 
        printf("JSON parse error\n");
        failed = 1;
        goto cleanup;
    }

    cJSON* child = NULL;
    int total = cJSON_GetArraySize(root);

    I8086 cpu = { 0 };
    i8086_init(&cpu);
    cpu.funcs.read_mem_byte = read_mm_byte;    
    cpu.funcs.write_mem_byte = write_mm_byte;
    cpu.funcs.read_io_byte = read_io_byte;
    cpu.funcs.read_io_word = read_io_word;
    cpu.funcs.write_io_byte = write_io_byte;
    cpu.funcs.write_io_word = write_io_word;

    for (int i = 0; i < total; i++) {
        child = cJSON_GetArrayItem(root, i);

        i8086_reset(&cpu);
        memset(memory, 0, 0x100000);

        cJSON* initial = cJSON_GetObjectItem(child, "initial");
        cpu_set_regs(&cpu, cJSON_GetObjectItem(initial, "regs"));
        cpu_load_ram_list(cJSON_GetObjectItem(initial, "ram"));

        // Load instruction bytes at IP
        cJSON* bytes = cJSON_GetObjectItem(child, "bytes");
        int n = cJSON_GetArraySize(bytes);
        for (int b = 0; b < n; b++) {
            uint8_t v = (uint8_t)cJSON_GetArrayItem(bytes, b)->valueint;
            write_mm_byte((uint20_t)(cpu.segments[SEG_CS] << 4) + (cpu.ip + b), v);
        }

        uint16_t start_ip = cpu.ip;
        do {
            // Execute instruction(s)
            if (i8086_execute(&cpu) == I8086_DECODE_UNDEFINED) {
                printf("ERROR: undef op: %02X", cpu.opcode);
                if (cpu.modrm.byte != 0) {
                    printf(" /%02X", cpu.modrm.reg);
                }
                printf("\n");
                failed = 1;
                goto cleanup;
            }
        } while (cpu.ip == start_ip); // stay in loop until REP finally finishes

        // Compare final state
        cJSON* final = cJSON_GetObjectItem(child, "final");
        char* name = cJSON_GetObjectItem(child, "name")->valuestring;
        if (cpu_compare_state(&cpu, final)) {
            printf("%04d) Test PASSED: %s\n", i, name);
        }
        else {
            printf("%04d) Test FAILED: %s\n", i, name);
            failed++;
            cpu_print_state(initial, final, &cpu);
            break;
        }
    }

    printf("FAILED: %d\n", failed);

cleanup:

    cJSON_Delete(root);
    free(json_text);
    if (failed > 0) {
        return failed;
    }
    else {
        return 0;
    }
}
