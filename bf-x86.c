#define _BSD_SOURCE    // MAP_ANONYMOUS
#define _POSIX_SOURCE  // fileno
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <elf.h>

#define MEMORY_SIZE 30000

const char *program_name = "bf-x86";
#define FATAL(message)                                          \
    do {                                                        \
        fprintf(stderr, "%s: %s\n", program_name, message);     \
        exit(EXIT_FAILURE);                                     \
    } while (0)

enum ins {
    INS_MOVE,
    INS_MUTATE,
    INS_IN,
    INS_OUT,
    INS_BRANCH,
    INS_JUMP,
    INS_HALT,
    INS_CLEAR,
    INS_ADD,
    INS_NOP
};

const char *
instruction_name(enum ins ins)
{
    static const char *const names[] = {
        "MOVE", "MUTATE", "IN", "OUT", "BRANCH",
        "JUMP", "HALT", "CLEAR", "ADD", "NOP"
    };
    return names[ins];
}

int
instruction_arity(enum ins ins)
{
    static const int arity[] = {1, 1, 0 ,0, 1, 1, 0, 0, 0};
    return arity[ins];
}

struct program {
    size_t max, count;
    struct {
        enum ins ins;
        long operand;
    } *ins;
    size_t markers_max, markers_count;
    long *markers;
};

#define PROGRAM_INIT {0, 0, NULL, 0, 0, NULL}
#define PROGRAM (struct program){0}

void program_mark(struct program *);
long program_unmark(struct program *);
void program_add(struct program *, enum ins, long);
void program_free(struct program *);
void program_parse(struct program *, FILE *);
void program_optimize(struct program *, int level);
void program_strip_nops(struct program *);
void program_print(const struct program *, FILE *);

void
program_free(struct program *p)
{
    free(p->ins);
    free(p->markers);
}

void
program_add(struct program *p, enum ins ins, long operand)
{
    if (p->count == p->max) {
        if (p->max == 0)
            p->max = 256;
        else
            p->max *= 2;
        size_t size = sizeof(p->ins[0]) * p->max;
        p->ins = realloc(p->ins, size);
    }
    switch (ins) {
        case INS_BRANCH:
            program_mark(p);
            break;
        case INS_JUMP: {
            long sibling = program_unmark(p);
            if (sibling < 0)
                FATAL("unmatched ']'");
            p->ins[sibling].operand = p->count + 1;
            operand = sibling;
        } break;
        case INS_MOVE:
        case INS_MUTATE:
        case INS_IN:
        case INS_OUT:
        case INS_HALT:
        case INS_CLEAR:
        case INS_ADD:
        case INS_NOP:
            /* Nothing */
            break;
    }
    p->ins[p->count].ins = ins;
    p->ins[p->count].operand = operand;
    p->count++;
}

void
program_mark(struct program *p)
{
    if (p->markers_count == p->markers_max) {
        if (p->markers_max == 0)
            p->markers_max = 16;
        else
            p->markers_max *= 2;
        size_t size = sizeof(p->markers[0]) * p->markers_max;
        p->markers = realloc(p->markers, size);
    }
    p->markers[p->markers_count++] = p->count;
}

long
program_unmark(struct program *p)
{
    if (p->markers_count > 0)
        return p->markers[--p->markers_count];
    else
        return -1;
}

void
program_parse(struct program *p, FILE *in)
{
    int c;
    while ((c = fgetc(in)) != EOF) {
        switch (c) {
            case '+':
                program_add(p, INS_MUTATE, 1);
                break;
            case '-':
                program_add(p, INS_MUTATE, -1);
                break;
            case '>':
                program_add(p, INS_MOVE, 1);
                break;
            case '<':
                program_add(p, INS_MOVE, -1);
                break;
            case '.':
                program_add(p, INS_OUT, 0);
                break;
            case ',':
                program_add(p, INS_IN, 0);
                break;
            case '[':
                program_add(p, INS_BRANCH, 0);
                break;
            case ']':
                program_add(p, INS_JUMP, 0);
                break;
            default:
                /* Nothing */
                break;
        }
    }
    if (p->markers_count > 0)
        FATAL("unmatched '['");
    program_add(p, INS_HALT, 0);
}

void
program_strip_nops(struct program *p)
{
    struct program copy = PROGRAM_INIT;
    for (size_t i = 0; i < p->count; i++)
        if (p->ins[i].ins != INS_NOP)
            program_add(&copy, p->ins[i].ins, p->ins[i].operand);
    program_free(p);
    *p = copy;
}

enum optype {OP_ANY, OP_CONSTANT, OP_STORE, OP_LOAD, OP_LOAD_NEG};

struct pattern {
    enum ins ins;
    enum optype optype;
    long operand;
};

struct optimization {
    const char *name;
    struct pattern *sequence;
    struct pattern *replacement;
};

void
optimize_replace(struct program *p, long i, struct optimization *o, long *vars)
{
    for (long n = 0; o->sequence[n].ins != INS_NOP; n++) {
        p->ins[i + n].ins = o->replacement[n].ins;
        switch (o->replacement[n].optype) {
            case OP_CONSTANT:
                p->ins[i + n].operand = o->replacement[n].operand;
                break;
            case OP_LOAD:
                p->ins[i + n].operand = vars[o->replacement[n].operand];
                break;
            case OP_LOAD_NEG:
                p->ins[i + n].operand = -vars[o->replacement[n].operand];
                break;
            case OP_ANY:
                break;
            case OP_STORE:
                assert(!"invalid replacement");
                break;
        }
    }
}

long
optimize_apply(struct program *p, struct optimization *o)
{
    long count = 0;
    long variables[16] = {0};
    for (size_t i = 0; i < p->count; i++) {
        long length = 0;
        for (size_t n = 0;
             o->sequence[n].ins != INS_NOP && i + n < p->count;
             n++) {
            enum ins ins = p->ins[i + n].ins;
            long operand = p->ins[i + n].operand;
            if (ins != o->sequence[n].ins) {
                length = 0;
                break;
            }
            length++;
            enum optype o_type = o->sequence[n].optype;
            long o_operand = o->sequence[n].operand;
            switch (o_type) {
                case OP_CONSTANT:
                    if (operand != o_operand)
                        length = 0;
                    break;
                case OP_STORE:
                    variables[o_operand] = operand;
                    break;
                case OP_LOAD:
                    if (operand != variables[o_operand])
                        length = 0;
                    break;
                case OP_LOAD_NEG:
                    if (operand != -variables[o_operand])
                        length = 0;
                    break;
                case OP_ANY:
                    break;
            }
            if (length == 0)
                break;
        }
        if (length > 0) {
            optimize_replace(p, i, o, variables);
            i += length;
            count++;
        }
    }
    if (count > 0)
        program_strip_nops(p);
    return count;
}

/* [-] */
struct optimization optimization_clear = {
    .name = "Cell clear",
    .sequence = (struct pattern []){
        {INS_BRANCH},
        {INS_MUTATE, OP_CONSTANT, -1},
        {INS_JUMP},
        {INS_NOP}
    },
    .replacement = (struct pattern []){
        {INS_CLEAR},
        {INS_NOP},
        {INS_NOP}
    }
};

/* [->+<] */
struct optimization optimization_add = {
    .name = "Cell add",
    .sequence = (struct pattern []){
        {INS_BRANCH},
        {INS_MUTATE, OP_CONSTANT, -1},
        {INS_MOVE, OP_STORE, 0},
        {INS_MUTATE, OP_CONSTANT, 1},
        {INS_MOVE, OP_LOAD_NEG, 0},
        {INS_JUMP},
        {INS_NOP}
    },
    .replacement = (struct pattern []){
        {INS_ADD, OP_LOAD, 0},
        {INS_CLEAR},
        {INS_NOP},
        {INS_NOP},
        {INS_NOP},
        {INS_NOP}
    }
};

void
program_compress(struct program *p)
{
    for (size_t i = 0; i < p->count; i++) {
        if (p->ins[i].ins == INS_MOVE || p->ins[i].ins == INS_MUTATE) {
            size_t f = i + 1;
            while (p->ins[i].ins == p->ins[f].ins) {
                p->ins[f].ins = INS_NOP;
                p->ins[i].operand += p->ins[f].operand;
                f++;
            }
            if (p->ins[i].operand == 0)
                p->ins[i].ins = INS_NOP;
        }
    }
    program_strip_nops(p);
}

void
program_optimize(struct program *p, int level)
{
    if (level == 0)
        return;
    program_compress(p);
    long count = 0;
    do {
        count = 0;
        if (level >= 2)
            count += optimize_apply(p, &optimization_clear);
        if (level >= 3)
            count += optimize_apply(p, &optimization_add);
    } while (count > 0);
}

void
program_print(const struct program *p, FILE *out)
{
    for (size_t i = 0; i < p->count; i++) {
        long operand = p->ins[i].operand;
        enum ins ins = p->ins[i].ins;
        if (ins != INS_NOP) {
            fprintf(out, "%08ld  ", i);
            if (instruction_arity(ins) == 1)
                fprintf(out, "%-12s%ld\n", instruction_name(ins), operand);
            else
                fprintf(out, "%s\n", instruction_name(ins));
        }
    }
}

void interpret(const struct program *, FILE *);

void
interpret(const struct program *program, FILE *trace)
{
    long ip = 0;
    long dp = 0;
    uint8_t memory[MEMORY_SIZE] = {0};
    for (;;) {
        enum ins ins = program->ins[ip].ins;
        long operand = program->ins[ip].operand;
        if (trace != NULL && ins != INS_NOP) {
            const char *name = instruction_name(ins);
            fprintf(trace, "(%ld) %s %ld\n", ip, name, operand);
        }
        ip++;
        switch (ins) {
            case INS_MOVE:
                dp += operand;
                break;
            case INS_MUTATE:
                memory[dp] += operand;
                break;
            case INS_IN:
                memory[dp] = getchar();
                break;
            case INS_OUT:
                putchar(memory[dp]);
                break;
            case INS_JUMP:
                ip = operand;
                break;
            case INS_BRANCH:
                if (memory[dp] == 0)
                    ip = operand;
                break;
            case INS_CLEAR:
                memory[dp] = 0;
                break;
            case INS_ADD:
                memory[dp + operand] += memory[dp];
                break;
            case INS_NOP:
                break;
            case INS_HALT:
                return;
        }
    }
}

struct asmbuf {
    size_t size, fill;
    uint8_t code[];
};

struct asmbuf *asmbuf_create(void);
void           asmbuf_free(struct asmbuf *);
void           asmbuf_finalize(struct asmbuf *);
void           asmbuf_ins(struct asmbuf *, int, uint64_t);
void           asmbuf_immediate(struct asmbuf *, int, const void *);
void           asmbuf_syscall(struct asmbuf *, int);

struct asmbuf *
asmbuf_create(void)
{
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    size_t size = 1<<28;  // TODO: grow as needed?
    struct asmbuf *buf = mmap(NULL, size, prot, flags, -1, 0);
    buf->size = size;
    return buf;
}

void
asmbuf_free(struct asmbuf *buf)
{
    munmap(buf, buf->size);
}

void
asmbuf_finalize(struct asmbuf *buf)
{
    mprotect(buf, buf->size, PROT_READ | PROT_EXEC);
}

void
asmbuf_ins(struct asmbuf *buf, int size, uint64_t ins)
{
    for (int i = size - 1; i >= 0; i--)
        buf->code[buf->fill++] = (ins >> (i * 8)) & 0xff;
}

void
asmbuf_immediate(struct asmbuf *buf, int size, const void *value)
{
    memcpy(buf->code + buf->fill, value, size);
    buf->fill += size;
}

void
asmbuf_syscall(struct asmbuf *buf, int syscall)
{
    if (syscall == 0) {
        asmbuf_ins(buf, 2, 0x31C0); // xor  eax, eax
    } else if (syscall == 1) {
        asmbuf_ins(buf, 3, 0x4C89E0); // mov rax, r12
    } else {
        asmbuf_ins(buf, 1, 0xB8);  // mov  rax, syscall
        uint32_t n = syscall;
        asmbuf_immediate(buf, 4, &n);
    }
    asmbuf_ins(buf, 2, 0x0F05);  // syscall
}

enum mode {
    MODE_OPEN, MODE_FUNCTION, MODE_STANDALONE
};

struct asmbuf *compile(const struct program *, enum mode);

struct asmbuf *
compile(const struct program *program, enum mode mode)
{
    uint32_t memory_size = MEMORY_SIZE;
    struct asmbuf *buf = asmbuf_create();

    /* Clear zero register */
    if (mode == MODE_FUNCTION) {
        asmbuf_ins(buf, 1, 0x53); // push rbx
        asmbuf_ins(buf, 2, 0x4154); // push r12
    }
    asmbuf_ins(buf, 2, 0x31dB); // xor ebx, ebx
    asmbuf_ins(buf, 6, 0x41BC01000000); // mov r12, 1

    /* Allocate BF array on stack */
    asmbuf_ins(buf, 3, 0x4881EC); // sub  rsp, X
    asmbuf_immediate(buf, 4, &memory_size);
    asmbuf_ins(buf, 3, 0x4889E6); // mov  rsi, rsp
    asmbuf_ins(buf, 5, 0xBA01000000); // mov  edx, 0x1

    /* Clear BF array */
    asmbuf_ins(buf, 2, 0x30C0); // xor  al, al
    asmbuf_ins(buf, 3, 0x4889E7); // mov  rdi, rsp
    asmbuf_ins(buf, 1, 0xB9); // mov  rcx, X
    asmbuf_immediate(buf, 4, &memory_size);
    asmbuf_ins(buf, 2, 0xF3AA); // rep stosb

    /* rsi - data pointer
     * rdi - syscall argument
     * rax - temp
     * rbx - zero register
     * r12 - one register
     */
    uint32_t *table = malloc(sizeof(table[0]) * program->count);
    for (size_t i = 0; i < program->count; i++) {
        enum ins ins = program->ins[i].ins;
        long operand = program->ins[i].operand;
        table[i] = buf->fill;
        switch (ins) {
            case INS_MOVE:
                if (operand > -256 && operand < 256) {
                    if (operand > 0) {
                        asmbuf_ins(buf, 3, 0x4883C6); // add  rsi, byte X
                    } else {
                        operand *= -1;
                        asmbuf_ins(buf, 3, 0x4883EE); // sub  rsi, byte X
                    }
                    asmbuf_immediate(buf, 1, &operand);
                } else {
                    if (operand > 0) {
                        asmbuf_ins(buf, 3, 0x4881C6); // add  rsi, X
                    } else {
                        operand *= -1;
                        asmbuf_ins(buf, 3, 0x4881EE); // sub  rsi, X
                    }
                    asmbuf_immediate(buf, 4, &operand);
                }
                break;
            case INS_MUTATE:
                if (operand > 0) {
                    asmbuf_ins(buf, 2, 0x8006); // add  byte [rsi], X
                } else {
                    operand *= -1;
                    asmbuf_ins(buf, 2, 0x802E); // sub  byte [rsi], X
                }
                asmbuf_immediate(buf, 1, &operand);
                break;
            case INS_CLEAR:
                asmbuf_ins(buf, 2, 0x881e); // mov  [rsi], bl
                break;
            case INS_IN:
                asmbuf_ins(buf, 3, 0x4831FF); // xor  rdi, rdi
                asmbuf_syscall(buf, SYS_read);
                break;
            case INS_OUT:
                asmbuf_ins(buf, 3, 0x4C89E7); // mov  rdi, r12
                asmbuf_syscall(buf, SYS_write);
                break;
            case INS_BRANCH: {
                uint32_t delta = 0;
                asmbuf_ins(buf, 2, 0x381E); // cmp  [rsi], bl
                asmbuf_ins(buf, 2, 0x0F84); // jz
                asmbuf_immediate(buf, 4, &delta); // patched by JUMP ']'
            } break;
            case INS_JUMP: {
                uint32_t delta = table[operand];
                delta -= buf->fill + 5;
                asmbuf_ins(buf, 1, 0xE9); // jmp delta
                asmbuf_immediate(buf, 4, &delta);
                void *jz = &buf->code[table[operand] + 4];
                uint32_t patch = buf->fill - table[operand] - 8;
                memcpy(jz, &patch, 4); // patch previous branch '['
            } break;
            case INS_ADD: {
                asmbuf_ins(buf, 2, 0x8A06);  // mov  al, [rsi]
                uint32_t delta = operand;
                if (operand >= -128 && operand < 127) {
                    asmbuf_ins(buf, 2, 0x0046);  // add  [rsi+delta], al
                    asmbuf_immediate(buf, 1, &delta);
                } else {
                    asmbuf_ins(buf, 2, 0x0086);  // add  [rsi+delta], al
                    asmbuf_immediate(buf, 4, &delta);
                }
            } break;
            case INS_HALT:
                if (mode == MODE_FUNCTION) {
                    asmbuf_ins(buf, 3, 0x4881C4); // add  rsp, X
                    asmbuf_immediate(buf, 4, &memory_size);
                    asmbuf_ins(buf, 2, 0x415C); // pop r12
                    asmbuf_ins(buf, 1, 0x5B); // pop rbx
                    asmbuf_ins(buf, 1, 0xC3); // ret
                } else if (mode == MODE_STANDALONE) {
                    asmbuf_ins(buf, 3, 0x4831FF); // xor  rdi, rdi
                    asmbuf_syscall(buf, SYS_exit);
                }
                break;
            case INS_NOP:
                break;
        }
    }
    free(table);

    asmbuf_finalize(buf);
    return buf;
}

void
elf_write(struct asmbuf *buf, FILE *elf)
{
    uint64_t entry = 0x400000 + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    Elf64_Ehdr ehdr = {
        .e_ident = {
            ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
            ELFCLASS64,
            ELFDATA2LSB,
            EV_CURRENT,
            ELFOSABI_SYSV,
        },
        .e_type = ET_EXEC,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = entry,
        .e_phoff = sizeof(Elf64_Ehdr),
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = 1,
    };
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_flags = PF_X | PF_R,
        .p_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr),
        .p_vaddr = entry,
        .p_filesz = buf->fill,
        .p_memsz = buf->fill,
        .p_align = 0,
    };

    fwrite(&ehdr, sizeof(ehdr), 1, elf);
    fwrite(&phdr, sizeof(phdr), 1, elf);
    fwrite(buf->code, buf->fill, 1, elf);
}

void
print_help(const char *argv0, FILE *o)
{
    fprintf(o, "Usage: %s [-o <file>] [-i] [-e] [-h] [-O <n>]\n", argv0);
    fprintf(o, "  -o <file>    executable output file name\n");
    fprintf(o, "  -O <level>   optimization level\n");
    fprintf(o, "  -e           no output file, execute program\n");
    fprintf(o, "  -i           no output file, interpret program (slow)\n");
    fprintf(o, "  -h           print this usage information\n");
    fprintf(o, "  -D           debugging listing\n");
}

int
main(int argc, char **argv)
{
    /* Options */
    program_name = argv[0];
    char *output = NULL;
    char *input = NULL;
    bool do_exec = false;
    bool do_interpret = false;
    bool do_debug = false;
    int optimize = 3;

    /* Parse arguments */
    int option;
    while ((option = getopt(argc, argv, "o:eiDhO:")) != -1) {
        switch (option) {
            case 'o':
                output = optarg;
                break;
            case 'O':
                optimize = atoi(optarg);
                break;
            case 'e':
                do_exec = true;
                break;
            case 'i':
                do_interpret = true;
                break;
            case 'D':
                do_debug = true;
                break;
            case 'h':
                print_help(argv[0], stdout);
                break;
            default:
                print_help(argv[0], stderr);
                FATAL("invalid option");
        }
    }
    if (optind >= argc)
        FATAL("no input files");
    else if (optind != argc - 1)
        FATAL("too many input files");
    input = argv[optind];

    char output_buf[1024];
    if (!do_interpret && !do_exec && output == NULL) {
        snprintf(output_buf, sizeof(output_buf), "%s", input);
        output = output_buf;
        char *p = output + strlen(output);
        while (*p != '.' && p >= output)
            p--;
        if (p < output)
            FATAL("no output file specified");
        else
            *p = '\0';
    }

    struct program program = PROGRAM_INIT;
    FILE *source = fopen(argv[optind], "r");
    if (source == NULL)
        FATAL("could not open input file");
    program_parse(&program, source);
    program_optimize(&program, optimize);
    fclose(source);

    if (do_debug)
        program_print(&program, stderr);

    if (do_interpret) {
        interpret(&program, do_debug ? stderr : NULL);
    } else if (do_exec) {
        struct asmbuf *buf = compile(&program, MODE_FUNCTION);
        void (*run)(void) = (void *)buf->code;
        run();
        asmbuf_free(buf);
    } else {
        struct asmbuf *buf = compile(&program, MODE_STANDALONE);
        FILE *elf = fopen(output, "wb");
        if (elf == NULL)
            FATAL("could not open output file");
        elf_write(buf, elf);
        fchmod(fileno(elf), 0755);
        fclose(elf);
        asmbuf_free(buf);
    }

    program_free(&program);
    return 0;
}
