#define _BSD_SOURCE  // MAP_ANONYMOUS
#define _POSIX_SOURCE  // fileno
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#define MEMORY_SIZE 30000

#define FATAL(message)                          \
    do {                                        \
        fprintf(stderr, "%s\n", message);       \
        exit(EXIT_FAILURE);                     \
    } while (0)

enum ins {
    INS_MOVE,
    INS_MUTATE,
    INS_IN,
    INS_OUT,
    INS_JUMP,
    INS_BRANCH,
    INS_HALT,
    INS_NOP
};

const char *
instruction_name(enum ins ins)
{
    static const char *const names[] = {
        "MOVE", "MUTATE", "IN", "OUT", "JUMP", "BRANCH", "HALT", "NOP"
    };
    return names[ins];
}

int
instruction_arity(enum ins ins)
{
    static const int arity[] = {1, 1, 0 ,0, 1, 1, 0, 0};
    return arity[ins];
}

struct program {
    size_t max, count;
    struct {
        enum ins ins;
        long value;
    } *instructions;
    size_t markers_max, markers_count;
    long *markers;
};

#define PROGRAM_INIT {0}
#define PROGRAM (struct program){0}

void program_mark(struct program *);
long program_unmark(struct program *);
void program_add(struct program *, enum ins, long);
void program_free(struct program *);
void program_parse(struct program *, FILE *);
void program_optimize(struct program *);
void program_print(const struct program *);

void
program_free(struct program *p)
{
    free(p->instructions);
    free(p->markers);
}

void
program_add(struct program *p, enum ins ins, long value)
{
    if (p->count == p->max) {
        if (p->max == 0)
            p->max = 256;
        else
            p->max *= 2;
        size_t size = sizeof(p->instructions[0]) * p->max;
        p->instructions = realloc(p->instructions, size);
    }
    switch (ins) {
    case INS_JUMP:
        value = program_unmark(p);
        if (value < 0)
            FATAL("unmatched ']'");
        p->instructions[value].value = p->count + 1;
        break;
    case INS_BRANCH:
        program_mark(p);
        break;
    case INS_MUTATE:
    case INS_MOVE:
    case INS_IN:
    case INS_OUT:
    case INS_HALT:
    case INS_NOP:
        /* Nothing */
        break;
    }
    p->instructions[p->count].ins = ins;
    p->instructions[p->count].value = value;
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
program_optimize(struct program *p)
{
    for (size_t i = 0; i < p->count; i++) {
        size_t f = i + 1;
        switch (p->instructions[i].ins) {
        case INS_MUTATE:
        case INS_MOVE:
            while (p->instructions[i].ins == p->instructions[f].ins) {
                p->instructions[f].ins = INS_NOP;
                p->instructions[i].value += p->instructions[f].value;
                f++;
            }
            break;
        case INS_BRANCH:
        case INS_JUMP:
        case INS_IN:
        case INS_OUT:
        case INS_NOP:
        case INS_HALT:
            /* Nothing */
            break;
        }
    }
}

void
program_print(const struct program *p)
{
    for (size_t i = 0; i < p->count; i++) {
        printf("%08ld  ", i);
        long value = p->instructions[i].value;
        enum ins ins = p->instructions[i].ins;
        if (instruction_arity(ins) == 1)
            printf("%-12s%ld\n", instruction_name(ins), value);
        else
            printf("%s\n", instruction_name(ins));
    }
}

struct interpeter {
    long dp;
    long ip;
    uint8_t memory[MEMORY_SIZE];
};

#define INTERPRETER_INIT {0}
#define INTERPRETER (struct interpeter){0}

void interpret(struct interpeter *, const struct program *);

void
interpret(struct interpeter *machine, const struct program *program)
{
    for (;;) {
        enum ins ins = program->instructions[machine->ip].ins;
        long value = program->instructions[machine->ip].value;
        machine->ip++;
        //printf("(%ld) %s %ld\n", machine->ip, instruction_name(ins), value);
        switch (ins) {
        case INS_MOVE:
            machine->dp += value;
            break;
        case INS_MUTATE:
            machine->memory[machine->dp] += value;
            break;
        case INS_IN:
            machine->memory[machine->dp] = getchar();
            break;
        case INS_OUT:
            putchar(machine->memory[machine->dp]);
            break;
        case INS_JUMP:
            machine->ip = value;
            break;
        case INS_BRANCH:
            if (machine->memory[machine->dp] == 0)
                machine->ip = value;
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

struct asmbuf *
asmbuf_create(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    size_t size = page_size * 256;
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

enum mode {
    MODE_OPEN, MODE_FUNCTION, MODE_STANDALONE
};

struct asmbuf *compile(const struct program *, enum mode);

struct asmbuf *
compile(const struct program *program, enum mode mode)
{
    uint32_t memory_size = MEMORY_SIZE;
    struct asmbuf *buf = asmbuf_create();

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

    uint32_t table[program->count];
    for (size_t i = 0; i < program->count; i++) {
        enum ins ins = program->instructions[i].ins;
        long value = program->instructions[i].value;
        table[i] = buf->fill;
        switch (ins) {
        case INS_MOVE:
            if (value > 0) {
                asmbuf_ins(buf, 3, 0x4881C6); // add  rsi, X
            } else {
                value *= -1;
                asmbuf_ins(buf, 3, 0x4881EE); // sub  rsi, X
            }
            asmbuf_immediate(buf, 4, &value);
            break;
        case INS_MUTATE:
            if (value > 0) {
                asmbuf_ins(buf, 2, 0x8006); // add  byte [rsi], X
            } else {
                value *= -1;
                asmbuf_ins(buf, 2, 0x802E); // sub  byte [rsi], X
            }
            asmbuf_immediate(buf, 1, &value);
            break;
        case INS_IN:
            asmbuf_ins(buf, 3, 0x4831C0); // xor  rax, rax
            asmbuf_ins(buf, 3, 0x4831FF); // xor  rdi, rdi
            asmbuf_ins(buf, 2, 0x0F05);   // syscall
            break;
        case INS_OUT:
            asmbuf_ins(buf, 5, 0xB801000000); // mov  rax, 1
            asmbuf_ins(buf, 5, 0xBF01000000); // mov  rdi, 1
            asmbuf_ins(buf, 2, 0x0F05); // syscall
            break;
        case INS_BRANCH: {
            uint32_t delta = 0;
            asmbuf_ins(buf, 3, 0x803E00); // cmp  byte [rsi], 0
            asmbuf_ins(buf, 2, 0x0F84);
            asmbuf_immediate(buf, 4, &delta); // patched by return JUMP ']'
        } break;
        case INS_JUMP: {
            uint32_t delta = table[value];
            delta -= buf->fill + 5;
            asmbuf_ins(buf, 1, 0xE9); // jmp delta
            asmbuf_immediate(buf, 4, &delta);
            void *jz = &buf->code[table[value] + 5];
            uint32_t patch = buf->fill - table[value] - 9;
            memcpy(jz, &patch, 4); // patch previous branch '['
        } break;
        case INS_HALT:
            if (mode == MODE_FUNCTION) {
                asmbuf_ins(buf, 3, 0x4881C4); // add  rsp, X
                asmbuf_immediate(buf, 4, &memory_size);
                asmbuf_ins(buf, 1, 0xC3); // ret
            } else if (mode == MODE_STANDALONE) {
                asmbuf_ins(buf, 5, 0xB83C000000); // mov  rax, 1
                asmbuf_ins(buf, 3, 0x4831FF); // xor  rdi, rdi
                asmbuf_ins(buf, 2, 0x0F05); // syscall
            }
            break;
        case INS_NOP:
            break;
        }
    }

    asmbuf_finalize(buf);
    return buf;
}

void
elf_write(struct asmbuf *buf, FILE *elf)
{
    uint64_t entry = 0x400000;
    char strtab[] = ".text\0.shstrtab\0";
    Elf64_Ehdr header = {
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
        .e_shoff = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr),
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = 1,
        .e_shentsize = sizeof(Elf64_Shdr),
        .e_shnum = 2,
        .e_shstrndx = 0
    };
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_flags = PF_X | PF_R,
        .p_vaddr = entry,
        .p_paddr = entry,
        .p_filesz = buf->fill,
        .p_memsz = buf->fill,
        .p_align = 0x200000
    };
    Elf64_Shdr shdr[2] = {
        {
            .sh_name = 6,
            .sh_type = SHT_STRTAB,
            .sh_offset = sizeof(header) + sizeof(phdr) + sizeof(shdr),
            .sh_size = sizeof(strtab),
            .sh_addralign = 1
        }, {
            .sh_name = 0, // .text
            .sh_type = SHT_PROGBITS,
            .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
            .sh_addr = entry,
            .sh_offset =
              sizeof(header) + sizeof(phdr) + sizeof(shdr) + sizeof(strtab),
            .sh_size = buf->fill,
            .sh_addralign = 1
        }
    };
    header.e_entry += shdr[1].sh_offset; // why?

    fwrite(&header, sizeof(header), 1, elf);
    fwrite(&phdr, sizeof(phdr), 1, elf);
    fwrite(&shdr, sizeof(shdr), 1, elf);
    fwrite(strtab, sizeof(strtab), 1, elf);
    fwrite(buf->code, buf->fill, 1, elf);
}

void
print_help(const char *argv0, FILE *o)
{
    fprintf(o, "Usage: %s [-o <file>] [-i] [-e] [-h]\n", argv0);
    fprintf(o, "  -e           no output file, execute program\n");
    fprintf(o, "  -h           print this usage information\n");
    fprintf(o, "  -i           no output file, interpret program (slow)\n");
    fprintf(o, "  -o <file>    executable output file name\n");
    fprintf(o, "  -D           debugging listing\n");
}

int
main(int argc, char **argv)
{
    /* Options */
    const char *output = NULL;
    bool do_exec = false;
    bool do_interpret = false;
    bool do_debug = false;

    /* Parse arguments */
    int option;
    while ((option = getopt(argc, argv, "o:eiDh")) != -1) {
        switch (option) {
        case 'o':
            output = optarg;
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

    /* Validate arguments. */
    if (optind >= argc)
        FATAL("no input files");
    else if (optind != argc - 1)
        FATAL("too many input files");
    else if (!do_interpret && !do_exec && output == NULL)
        FATAL("no output file specified");

    struct program program = PROGRAM_INIT;
    FILE *source = fopen(argv[optind], "r");
    if (source == NULL)
        FATAL("could not open input file");
    program_parse(&program, source);
    program_optimize(&program);
    fclose(source);

    if (do_debug)
        program_print(&program);

    if (do_interpret) {
        interpret(&INTERPRETER, &program);
    } else if (do_exec) {
        struct asmbuf *buf = compile(&program, MODE_FUNCTION);
        void (*run)(void) = (void *)buf->code;
        run();
        asmbuf_free(buf);
    } else {
        struct asmbuf *buf = compile(&program, MODE_STANDALONE);
        FILE *elf = fopen(output, "wb");
        elf_write(buf, elf);
        fchmod(fileno(elf), 0755);
        fclose(elf);
        asmbuf_free(buf);
    }

    program_free(&program);
    return 0;
}
