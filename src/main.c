
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "cJSON.h"
#include "i8086.h"
#include "i8086_mnem.h"

typedef struct ARGS {
    int dont_exit_on_error;
    int print_state_on_pass;
    int print_state_on_fail;
    int index;
    int count;
    FILE* file;
    FILE* metadata_file;
    char opcode_str[256];
    char subcode_str[256];
    int test_defined_flags;
    int test_mnemonics;
} ARGS;

typedef struct OPCODE_METADATA {
    const char* status_str;
    const char* flags_str;
    uint16_t mask; /* defined flags mask */
} OPCODE_METADATA;

uint8_t memory[0x100000] = { 0 };

cJSON* initial_ram = NULL;
cJSON* final_ram = NULL;
int ram_error_r = 0;
int ram_error_w = 0;

cJSON* initial_regs = NULL;
cJSON* final_regs = NULL;

/* Get 20bit address SEG:ADDR */
#define PHYS_ADDRESS(seg, offset) ((((uint20_t)seg << 4) + ((offset) & 0xFFFF)) & 0xFFFFF)

/* Memory Functions */
uint8_t mm_read_byte(uint20_t addr) {

    /* confirm we are only reading from an address in the initial or final states from the test. */

    int n = cJSON_GetArraySize(initial_ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(initial_ram, i);
        uint32_t exp_addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        if (addr == exp_addr) {
            return *(uint8_t*)&memory[addr];
        }
    }

    n = cJSON_GetArraySize(final_ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(final_ram, i);
        uint32_t exp_addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        if (addr == exp_addr) {
            return *(uint8_t*)&memory[addr];
        }
    }

    /* We didnt find an address in the test. Only addresses
    that the CPU reads from or writes to are in the test.
    If the address isn't in the test, its an error. */
    printf("ERROR: Tried to read byte at %05X\n", addr);
    ram_error_r = 1;
    return 0;
}
void mm_write_byte(uint20_t addr, uint8_t value) {

    /* confirm we are only writing to an address in the initial or final states from the test. */

    int n = cJSON_GetArraySize(initial_ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(initial_ram, i);
        uint32_t exp_addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        if (addr == exp_addr) {
            *(uint8_t*)&memory[addr] = value;
            return;
        }
    }

    n = cJSON_GetArraySize(final_ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(final_ram, i);
        uint32_t exp_addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        if (addr == exp_addr) {
            *(uint8_t*)&memory[addr] = value;
            return;
        }
    }

    /* We didnt find an address in the test. Only addresses
    that the CPU reads from or writes to are in the test.
    If the address isn't in the test, its an error. */
    printf("ERROR: Tried to write byte at %05X\n", addr);
    ram_error_w = 1;
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

void cpu_set_ram() {
    int n = cJSON_GetArraySize(initial_ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(initial_ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        uint8_t value = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
        mm_write_byte(addr, value);
    }
}

void cpu_set_regs(I8086* cpu) {
    cpu->registers[REG_AX].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "ax")->valueint;
    cpu->registers[REG_BX].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "bx")->valueint;
    cpu->registers[REG_CX].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "cx")->valueint;
    cpu->registers[REG_DX].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "dx")->valueint;
    cpu->registers[REG_SI].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "si")->valueint;
    cpu->registers[REG_DI].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "di")->valueint;
    cpu->registers[REG_SP].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "sp")->valueint;
    cpu->registers[REG_BP].r16 = (uint16_t)cJSON_GetObjectItem(initial_regs, "bp")->valueint;
    cpu->segments[SEG_ES] = (uint16_t)cJSON_GetObjectItem(initial_regs, "es")->valueint;
    cpu->segments[SEG_CS] = (uint16_t)cJSON_GetObjectItem(initial_regs, "cs")->valueint;
    cpu->segments[SEG_SS] = (uint16_t)cJSON_GetObjectItem(initial_regs, "ss")->valueint;
    cpu->segments[SEG_DS] = (uint16_t)cJSON_GetObjectItem(initial_regs, "ds")->valueint;
    cpu->ip = (uint16_t)cJSON_GetObjectItem(initial_regs, "ip")->valueint;
    cpu->status.word = (uint16_t)cJSON_GetObjectItem(initial_regs, "flags")->valueint;
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

int cpu_compare_state(I8086* cpu, cJSON* final, OPCODE_METADATA* opcode_metadata) {
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
    
#undef CHECK_MISMATCH

    if (try_get_object_int(regs, "flags", &v)) {
        if ((cpu->status.word & opcode_metadata->mask) != (v & opcode_metadata->mask)) return 1;
    };
        
    int n = cJSON_GetArraySize(ram);
    for (int i = 0; i < n; i++) {
        cJSON* pair = cJSON_GetArrayItem(ram, i);
        uint32_t addr = (uint32_t)cJSON_GetArrayItem(pair, 0)->valueint;
        uint8_t val = (uint8_t)cJSON_GetArrayItem(pair, 1)->valueint;
        if (memory[addr] != val) return 1;
    }

    if (ram_error_r || ram_error_w) {
        return 1;
    }

    return 0;
}

void cpu_print_reg(const char* name, uint16_t reg_val) {
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

void cpu_print_seg_reg(const char* seg_name, uint16_t seg_val, const char* reg_name, uint16_t reg_val) {
    uint16_t seg = 0;
    uint16_t reg = 0;

    printf("| %s:%s ", seg_name, reg_name);
    if (!try_get_object_int(initial_regs, seg_name, &seg) || !try_get_object_int(initial_regs, reg_name, &reg)) {
        printf("| ----- ");
    }
    else {
        printf("| %05X ", PHYS_ADDRESS(seg, reg));
    }

    if (!try_get_object_int(final_regs, seg_name, &seg) || !try_get_object_int(final_regs, reg_name, &reg)) {
        printf("| ----- ");
    }
    else {
        printf("| %05X ", PHYS_ADDRESS(seg, reg));
    }

    printf("| %05X |     |\n", PHYS_ADDRESS(seg_val, reg_val));
}

void cpu_print_flags(const char* name, I8086_PROGRAM_STATUS_WORD psw, OPCODE_METADATA* opcode_metadata) {
    uint16_t v1 = 0;
    uint16_t v2 = 0;

    if (!try_get_object_int(initial_regs, name, &v1)) {
        return;
    }
    v1 &= opcode_metadata->mask;

    if (!try_get_object_int(final_regs, name, &v2)) {
        return;
    }
    v2 &= opcode_metadata->mask;

    psw.word &= opcode_metadata->mask;

    printf("\n| FLAG  | INIT  | EXP   | CPU   | ERR |\n");
    printf(  "|-------|-------|-------|-------|-----|\n");
    printf(  "| flags |  %04X |  %04X |  %04X |  %c  |\n", 
        v1, v2, psw.word, (v2 != psw.word) ? 'X' : ' ');

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

void cpu_print_ram(I8086* cpu) {

    // Collect all addresses that appear in either initial_ram or final_ram
    typedef struct {
        uint32_t addr;
    } ADDR_ENTRY;

    int n_c = cJSON_GetArraySize(final_ram);
    int m_c = cJSON_GetArraySize(initial_ram);
    int addr_count = 0;

    if (n_c + m_c < 1) {
        return;
    }

    ADDR_ENTRY* addrs = calloc(n_c + m_c, sizeof(ADDR_ENTRY));
    if (addrs == NULL) {
        perror("AddrEntry Calloc");
        exit(1);
    }

    /* collect addresses from final_ram */
    for (int i = 0; i < n_c; ++i) {
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
    for (int i = 0; i < m_c; ++i) {
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
        for (int j = 0; j < m_c; ++j) {
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
        for (int j = 0; j < n_c; ++j) {
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

        printf("|  %02X   |  %c  |", memory[addr], has_exp && exp_val != memory[addr] ? 'X' : ' ');

        const char* reg16_mnem[] = {
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di"
        };

        const char* seg_mnem[] = {
            "es", "cs", "ss", "ds"
        };

        for (int j = 0; j < 3; ++j) {
            for (int k = 0; k < 7; ++k) {
                if (PHYS_ADDRESS(cpu->segments[j], cpu->registers[k].r16) == addr) {
                    printf(" (%s:%s)", seg_mnem[j], reg16_mnem[k]);
                }
            }
        }
        if (PHYS_ADDRESS(cpu->segments[SEG_CS], cpu->ip) == addr) {
            printf(" (cs:ip)");
        }
        printf("\n");
    }

    free(addrs);
    addrs = NULL;
}

void cpu_print_state(I8086* cpu, OPCODE_METADATA* opcode_metadata) {

    printf("\n|  REG  | INIT  | EXP   | CPU   | ERR |\n");
    printf(  "|-------|-------|-------|-------|-----|\n");

#define PRINT_REG(name, reg_val) \
    cpu_print_reg(name, reg_val)

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
    cpu_print_seg_reg(seg_name, seg_val, reg_name, reg_val)

    PRINT_SEG_REG("cs", cpu->segments[SEG_CS], "ip", cpu->ip);
    PRINT_SEG_REG("ss", cpu->segments[SEG_SS], "sp", cpu->registers[REG_SP].r16);

    cpu_print_flags("flags", cpu->status, opcode_metadata);

    cpu_print_ram(cpu);

    /* Check if a ram error has been flagged. */
    if (ram_error_w) {
        printf("RAM ERROR W\n");
    }
    if (ram_error_r) {
        printf("RAM ERROR R\n");
    }

    printf("\n");

#undef PRINT_REG
#undef PRINT_FLAGS
}

void print_usage() {
    printf("Usage: 8086_test.exe <test_file> [metadata_file] [extra_flags]\n" \
        "\t-e         Dont exit on error\n" \
        "\t-i<index>  Start at test i\n" \
        "\t-t<count>  End at test i+t\n" \
        "\t-psp       Print state on passed\n" \
        "\t-psf       Dont print state on failed\n" \
        "\t-defined   Ignore undefined flags in instructions. Requires metadata file\n" \
        "\t-mnemonics Test only mnemonics\n");
}

void set_default_args(ARGS* args) {
    args->index = 0;
    args->count = 0;
    args->dont_exit_on_error = 0;
    args->print_state_on_pass = 0;
    args->print_state_on_fail = 1;
    args->file = NULL;
    args->metadata_file = NULL;
    args->test_defined_flags = 0;
    args->test_mnemonics = 0;
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
        else if (strncmp("-defined", arg, 8) == 0) {
            args->test_defined_flags = 1;
        }
        else if (strncmp("-i", arg, 2) == 0) {
            arg += 2;
            args->index = strtol(arg, NULL, 10);
        }
        else if (strncmp("-t", arg, 2) == 0) {
            arg += 2;
            args->count = strtol(arg, NULL, 10);
        }
        else if (strncmp("-mnemonics", arg, 11) == 0) {
            args->test_mnemonics = 1;
        }
        else if (strncmp("-?", arg, 2) == 0) {
            print_usage();
            return 0;
        }
        else {
            /* Test file then metadata file */
            if (args->file == NULL) {
                args->file = fopen(arg, "rb");
                if (args->file == NULL) {
                    perror(arg);
                    return 0;
                }
            }
            else if (args->metadata_file == NULL) {
                args->metadata_file = fopen(arg, "rb");
                if (args->metadata_file == NULL) {
                    perror(arg);
                    return 0;
                }
            }
        }
    }

    return 1;
}

int get_opcode_metadata(cJSON* opcode, OPCODE_METADATA* opcode_metadata) {
    cJSON* tmp = cJSON_GetObjectItem(opcode, "status");
    if (tmp != NULL) {
        if (strcmp(tmp->valuestring, "prefix") == 0) {
            return 0;
        }
        opcode_metadata->status_str = tmp->valuestring;
    }

    tmp = cJSON_GetObjectItem(opcode, "flags");
    if (tmp != NULL) {
        opcode_metadata->flags_str = tmp->valuestring;
    }
    tmp = cJSON_GetObjectItem(opcode, "flags-mask");
    if (tmp != NULL) {
        opcode_metadata->mask = (uint16_t)tmp->valueint;
    }

    return 1;
}
int find_opcode_metadata(cJSON* bytes, int bytes_index, cJSON* opcodes, uint8_t byte, OPCODE_METADATA* opcode_metadata) {
    char opcode_str[3] = { 0 }; 
    sprintf(opcode_str, "%02X", byte);
    cJSON* opcode = cJSON_GetObjectItem(opcodes, opcode_str);
    if (opcode != NULL) {
        cJSON* reg = cJSON_GetObjectItem(opcode, "reg");
        if (reg != NULL) {
            char subcode_str[3] = { 0 };
            I8086_MOD_RM modrm = { 0 };
            modrm.byte = (uint8_t)cJSON_GetArrayItem(bytes, bytes_index + 1)->valueint;
            sprintf(subcode_str, "%d", modrm.reg);
            cJSON* subcode = cJSON_GetObjectItem(reg, subcode_str);
            if (subcode != NULL) {
                return get_opcode_metadata(subcode, opcode_metadata);
            }
            else {
                printf("Error: could not find opcode '%s.%s' in opcodes\n", opcode_str, subcode_str);
                return 0;
            }
        }
        else {
            return get_opcode_metadata(opcode, opcode_metadata);
        }
    }
    else {
        printf("Error: could not find opcode '%s' in opcodes\n", opcode_str);
        return 0;
    }
}

int main(int argc, char* argv[]) {
    int failed = 0;
    ARGS args = { 0 };
    I8086 cpu = { 0 };
    I8086_MNEM mnem = { 0 };
    cJSON* child = NULL;

    char* json_text = NULL;
    long json_text_size = 0;
    cJSON* test = NULL;
    int test_count = 0;
    
    char* metadata_text = NULL;
    long metadata_text_size = 0;
    cJSON* metadata = NULL;
    cJSON* metadata_opcodes = NULL;

    /* Parse Arguments */
    set_default_args(&args);
    if (parse_args(&args, argc, argv) == 0) {
        failed = 1;
        goto cleanup;
    }

    /* Read in the test file */
    if (args.file == NULL) {
        print_usage();
        failed = 1;
        goto cleanup;
    }

    fseek(args.file, 0, SEEK_END);
    json_text_size = ftell(args.file);
    fseek(args.file, 0, SEEK_SET);

    json_text = (char*)calloc(json_text_size+1, 1);
    if (json_text == NULL) {
        perror("JSON text malloc failed");
        failed = 1;
        goto cleanup;
    }

    fread(json_text, 1, json_text_size, args.file);

    test = cJSON_Parse(json_text);
    if (test == NULL) {
        const char* error = cJSON_GetErrorPtr();
        printf("JSON parse error:\n%s\n", error);
        failed = 1;
        goto cleanup;
    }

    test_count = cJSON_GetArraySize(test);
    if (test_count < args.index) {
        printf("Test count was %d but index was %d\n", test_count, args.index);
        failed = 1;
        goto cleanup;
    }
    if (test_count < args.count || args.count < 1) {
        args.count = test_count;
    }

    /* Load the metadata file */
    int has_metadata_file = 0;
    if (args.metadata_file != NULL) {
        fseek(args.metadata_file, 0, SEEK_END);
        metadata_text_size = ftell(args.metadata_file);
        fseek(args.metadata_file, 0, SEEK_SET);

        metadata_text = (char*)calloc(metadata_text_size+1, 1);
        if (metadata_text == NULL) {
            perror("JSON metadata text malloc failed");
            failed = 1;
            goto cleanup;
        }

        fread(metadata_text, 1, metadata_text_size, args.metadata_file);

        metadata = cJSON_Parse(metadata_text);
        if (metadata == NULL) {
            const char* error = cJSON_GetErrorPtr();
            printf("JSON parse error:\n%s\n", error);
            failed = 1;
            goto cleanup;
        }

        metadata_opcodes = cJSON_GetObjectItem(metadata, "opcodes");
        has_metadata_file = 1;
    }

    /* Init the CPU */
    i8086_init(&cpu);
    cpu.funcs.read_mem_byte = mm_read_byte;
    cpu.funcs.write_mem_byte = mm_write_byte;
    cpu.funcs.read_io_byte = io_read_byte;
    cpu.funcs.read_io_word = io_read_word;
    cpu.funcs.write_io_byte = io_write_byte;
    cpu.funcs.write_io_word = io_write_word;

    mnem.state = &cpu;

    for (int i = args.index; i < args.count; i++) {

        /* Reset the CPU,RAM */
        i8086_reset(&cpu);
        memset(memory, 0, 0x100000);

        child = cJSON_GetArrayItem(test, i);
        char* name = cJSON_GetObjectItem(child, "name")->valuestring;

        cJSON* initial = cJSON_GetObjectItem(child, "initial");
        initial_regs = cJSON_GetObjectItem(initial, "regs");
        initial_ram = cJSON_GetObjectItem(initial, "ram");

        cJSON* final = cJSON_GetObjectItem(child, "final");
        final_regs = cJSON_GetObjectItem(final, "regs");
        final_ram = cJSON_GetObjectItem(final, "ram");

        cJSON* bytes = cJSON_GetObjectItem(child, "bytes");
        int bytes_count = cJSON_GetArraySize(bytes);

        cpu_set_regs(&cpu);
        cpu_set_ram();

        // Load opcode bytes
        int found = 0;
        OPCODE_METADATA opcode_metadata = { .mask = 0xFFFF };
        for (uint16_t b = 0; b < bytes_count; ++b) {
            uint8_t v = (uint8_t)cJSON_GetArrayItem(bytes, b)->valueint;
            mm_write_byte(PHYS_ADDRESS(cpu.segments[SEG_CS], cpu.ip + b), v);
            if (has_metadata_file && !found) {
                found = find_opcode_metadata(bytes, b, metadata_opcodes, v, &opcode_metadata);
            }
        }

        // if we are testing the undefined flags, override the opcode metadata mask to FFFF.
        if (args.test_defined_flags == 0) {
            opcode_metadata.mask = 0xFFFF;
        }

        if (args.test_mnemonics) {
            if (i8086_mnem(&mnem) == I8086_DECODE_UNDEFINED) {
                printf("ERROR: undef op: %02X", mnem.opcode);
                if (mnem.modrm.byte != 0) {
                    printf(" /%02X", mnem.modrm.reg);
                }
                printf("\n");
                failed = 1;
                break;
            }
            if (strcmp(mnem.str, name) != 0) {
                printf("%04d) Mnemonic FAILED: '%s' != '%s'\n", i, name, mnem.str);
                failed = 1;
                break;
            }
            else {
                printf("%04d) Mnemonic PASSED: %s\n", i, name);
            }
            continue;
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
                break;
            }
        } while (cpu.ip == start_ip &&
                (cpu.opcode == 0xA4 || cpu.opcode == 0xA5 || // movs
                 cpu.opcode == 0xA6 || cpu.opcode == 0xA7 || // cmps
                 cpu.opcode == 0xAA || cpu.opcode == 0xAB || // stos
                 cpu.opcode == 0xAC || cpu.opcode == 0xAD || // lods
                 cpu.opcode == 0xAE || cpu.opcode == 0xAF)); // scas

        // Compare final state
        if (cpu_compare_state(&cpu, final, &opcode_metadata) == 0) {
            printf("%04d) Test PASSED: %s\n", i, name);
            if (args.print_state_on_pass == 1) {
                cpu_print_state(&cpu, &opcode_metadata);
            }
        }
        else {
            printf("%04d) Test FAILED: %s\n", i, name);
            failed++;
            if (args.print_state_on_fail == 1) {
                cpu_print_state(&cpu, &opcode_metadata);
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

    if (test != NULL) {
        cJSON_Delete(test);
        test = NULL;
    }

    if (json_text != NULL) {
        free(json_text);
        json_text = NULL;
    }

    if (args.metadata_file != NULL) {
        fclose(args.metadata_file);
        args.metadata_file = NULL;
    }

    if (metadata != NULL) {
        cJSON_Delete(metadata);
        metadata = NULL;
    }

    if (metadata_text != NULL) {
        free(metadata_text);
        metadata_text = NULL;
    }

    if (failed > 0) {
        return failed;
    }
    else {
        return 0;
    }
}
